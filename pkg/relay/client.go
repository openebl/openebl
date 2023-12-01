package relay

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

type NostrClientOption func(s *NostrClient)

type NostrClientOutputMsg struct {
	requestID string
	request   Request
	result    chan any
}

type NostrClient struct {
	io.Closer

	serverURL string

	mux         sync.Mutex
	closeChan   chan any
	outputChan  chan NostrClientOutputMsg
	responseMap map[string]chan any

	eventSink                EventSink
	connectionStatusCallback ClientConnectionStatusCallback
}

func NewNostrClient(opts ...NostrClientOption) *NostrClient {
	client := &NostrClient{
		closeChan:   make(chan any),
		outputChan:  make(chan NostrClientOutputMsg, 16),
		responseMap: make(map[string]chan any),
	}

	for _, opt := range opts {
		opt(client)
	}

	go client.outputWorker()

	return client
}

func (c *NostrClient) Close() error {
	c.mux.Lock()
	defer c.mux.Unlock()

	select {
	case <-c.closeChan:
		return nil
	default:
	}

	close(c.closeChan)
	return nil
}

func (c *NostrClient) outputWorker() {
	wg := sync.WaitGroup{}
	var conn *websocket.Conn
	var inputWorkerCtx context.Context
	var inputWorkerCancel context.CancelCauseFunc
	var err error

	defer func() {
		if conn != nil {
			conn.Close()
		}
		wg.Wait()
	}()

	cleanUp := func() {
		if conn != nil {
			go func() { c.connectionStatusCallback(context.Background(), c, "", false) }()
			conn.Close()
		}
		conn = nil
		inputWorkerCtx = nil
		inputWorkerCancel = nil
		wg.Wait()
		c.emptyOutputQueue()
		ShallowSleep(context.Background(), 5*time.Second, c.closeChan)
	}

	for {
		select {
		case <-c.closeChan:
			return
		default:
		}
		if conn == nil {
			inputWorkerCtx, inputWorkerCancel = context.WithCancelCause(context.Background())
			conn, err = c.prepareConnection(context.Background())
			if conn != nil {
				wg.Add(1)
				go func() {
					defer wg.Done()
					c.inputWorker(inputWorkerCancel, conn)
				}()
			}
		}
		if err != nil {
			logrus.Errorf("NostrClient: failed to prepare connection to %q: %v", c.serverURL, err)
			ShallowSleep(context.Background(), 5*time.Second, c.closeChan)
			err = nil
			continue
		}

		select {
		case <-c.closeChan:
			return
		case <-inputWorkerCtx.Done():
			// inputWorker has some error. We need to close the connection.
			cleanUp()
		case msg, ok := <-c.outputChan:
			if !ok {
				return
			}
			if msg.requestID != "" && msg.result != nil {
				c.addWaitingResponse(msg.requestID, msg.result)
			}

			jsonRaw, _ := json.Marshal(msg.request)
			if err := conn.WriteMessage(websocket.TextMessage, jsonRaw); err != nil {
				logrus.Errorf("NostrClient: failed to write message to %q: %v", c.serverURL, err)
				cleanUp()
			}
		}
	}
}

func (c *NostrClient) inputWorker(cancel context.CancelCauseFunc, conn *websocket.Conn) {
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			logrus.Errorf("NostrClient: failed to read message from %q: %v", c.serverURL, err)
			cancel(err)
			return
		}

		resp, err := ParseResponse(msg)
		if err != nil {
			logrus.Errorf("NostrClient: failed to parse message from %q: %v", c.serverURL, err)
			continue
		}

		switch resp := resp.(type) {
		case *EventPublishResponse:
			c.receivePublishResponse(resp)
		case *RelayServerIdentifyResponse:
			c.receiveServerIdentity(resp)
		case *SubscribeResponse:
			c.receiveEvent(resp)
		case *RelayServerNotice:
			c.receiveNotice(resp)
		default:
			logrus.Errorf("NostrClient: unsupported message from %q: %v", c.serverURL, err)
		}
	}
}

func (c *NostrClient) receiveEvent(resp *SubscribeResponse) {
	event := resp.Event
	if event != nil {
		_, err := c.eventSink(
			context.Background(),
			*event,
		)
		if err != nil {
			logrus.Errorf("NostrClient: failed to handle event %v: %v", resp, err)
		}
	}

	c.replyWaitingResponse(resp.SubscribeID, "OK")
}

func (c *NostrClient) receivePublishResponse(resp *EventPublishResponse) {
	if !resp.OK {
		c.replyWaitingResponse(resp.RequestID, errors.New(resp.Reason))
		return
	}

	c.replyWaitingResponse(resp.RequestID, resp.Reason)
}

func (c *NostrClient) receiveServerIdentity(resp *RelayServerIdentifyResponse) {
	go func() { c.connectionStatusCallback(context.Background(), c, resp.Identity, true) }()
}

func (c *NostrClient) receiveNotice(resp *RelayServerNotice) {
	logrus.Errorf("NostrClient: received notice from %q: %v", c.serverURL, resp.Message)
}

func (c *NostrClient) Publish(ctx context.Context, evtType int, data []byte) error {
	requestID := uuid.NewString()
	msg := NostrClientOutputMsg{
		requestID: requestID,
		request: Request{
			Publish: &EventPublishRequest{
				RequestID: requestID,
				Type:      evtType,
				Data:      data,
			},
		},
		result: make(chan any, 1),
	}

	if err := c.send(ctx, msg); err != nil {
		return err
	}

	var result any
	select {
	case <-ctx.Done():
		return ctx.Err()
	case v := <-msg.result:
		result = v
	}

	if err, ok := result.(error); ok {
		return err
	}

	reason, ok := result.(string)
	if !ok {
		logrus.Errorf("NostrClient: Get unknown result after publishing event %q: %v", requestID, result)
		return nil
	}
	logrus.Debugf("NostrClient: Get result after publishing event %q: %v", requestID, reason)
	return nil
}

func (c *NostrClient) Subscribe(ctx context.Context, offset int64) error {
	subscriptionID := uuid.NewString()
	msg := NostrClientOutputMsg{
		requestID: subscriptionID,
		request: Request{
			Subscribe: &SubscribeRequest{
				SubscribeID: subscriptionID,
				Offset:      offset,
			},
		},
		result: make(chan any, 1),
	}

	if err := c.send(ctx, msg); err != nil {
		return err
	}

	var result any
	select {
	case <-ctx.Done():
		return ctx.Err()
	case v := <-msg.result:
		result = v
	}

	if err, ok := result.(error); ok {
		return err
	}

	reason, ok := result.(string)
	if !ok {
		logrus.Errorf("NostrClient: Get unknown result after Subscribing %q: %v", subscriptionID, result)
		return nil
	}
	logrus.Debugf("NostrClient: Get result after Subscribing %q: %v", subscriptionID, reason)
	return nil
}

func (c *NostrClient) send(ctx context.Context, msg NostrClientOutputMsg) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.closeChan:
		return errors.New("closed")
	case c.outputChan <- msg:
		return nil
	}
}

func (c *NostrClient) prepareConnection(ctx context.Context) (*websocket.Conn, error) {
	serverURL, err := url.Parse(c.serverURL)
	if err != nil {
		return nil, err
	}

	conn, _, err := websocket.DefaultDialer.DialContext(ctx, serverURL.String(), nil)
	if err != nil {
		return nil, err
	}
	return conn, err
}

func (c *NostrClient) addWaitingResponse(requestID string, result chan any) {
	c.mux.Lock()
	defer c.mux.Unlock()

	c.responseMap[requestID] = result
}

func (c *NostrClient) replyWaitingResponse(requestID string, result any) {
	c.mux.Lock()
	ch, ok := c.responseMap[requestID]
	delete(c.responseMap, requestID)
	c.mux.Unlock()

	if ok && ch != nil {
		ch <- result
	}
}

func (c *NostrClient) emptyOutputQueue() {
	for {
		select {
		case msg, ok := <-c.outputChan:
			if !ok {
				return
			}
			if msg.result == nil {
				continue
			}
			msg.result <- errors.New("UNAVAILABLE")
		default:
			return
		}
	}
}

func ShallowSleep(ctx context.Context, d time.Duration, signalChan chan any) {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-signalChan:
	case <-ctx.Done():
	case <-timer.C:
	}
}
