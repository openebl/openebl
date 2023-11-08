package relay

import (
	"context"
	"errors"
	"io"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/nbd-wtf/go-nostr"
	"github.com/sirupsen/logrus"
)

type NostrClientOption func(s *NostrClient)

type NostrClientOutputMsg struct {
	requestID string
	result    chan any
	data      []byte
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
			go func() { c.connectionStatusCallback(context.Background(), c, false) }()
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
				go func() { c.connectionStatusCallback(context.Background(), c, true) }()
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

			if err := conn.WriteMessage(websocket.TextMessage, msg.data); err != nil {
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

		nostrMsg := nostr.ParseMessage(msg)
		if nostrMsg == nil {
			logrus.Errorf("NostrClient: failed to parse message from %q: %v", c.serverURL, err)
			continue
		}

		switch nostrMsg.Label() {
		case "EVENT":
			c.receiveEvent(nostrMsg.(*nostr.EventEnvelope))
		case "EOSE":
			logrus.Debugf("NostrClient: received EOS from %q", c.serverURL)
		case "OK":
			c.receiveOK(nostrMsg.(*nostr.OKEnvelope))
		default:
			logrus.Errorf("NostrClient: unsupported message from %q: %v", c.serverURL, err)
		}
	}
}

func (c *NostrClient) receiveEvent(envelope *nostr.EventEnvelope) {
	err := c.eventSink(
		context.Background(),
		Event{
			// Timestamp: envelope.Timestamp,
			// Offset:    envelope.Offset,
			Offset: int64(envelope.CreatedAt),
			Type:   envelope.Kind,
			Data:   []byte(envelope.Content),
		},
	)
	if err != nil {
		logrus.Errorf("NostrClient: failed to handle event %q: %v", envelope, err)
	}

	c.replyWaitingResponse(*envelope.SubscriptionID, "OK")
}

func (c *NostrClient) receiveOK(envelope *nostr.OKEnvelope) {
	if !envelope.OK {
		c.replyWaitingResponse(envelope.EventID, errors.New(envelope.Reason))
		return
	}

	c.replyWaitingResponse(envelope.EventID, envelope.Reason)
}

func (c *NostrClient) Publish(ctx context.Context, evtType int, msgID string, data []byte) error {
	nostrEnvelope := nostr.EventEnvelope{
		Event: nostr.Event{
			ID:      msgID,
			Kind:    evtType,
			Content: string(data),
		},
	}
	nostrRaw, _ := nostrEnvelope.MarshalJSON()
	msg := NostrClientOutputMsg{
		requestID: msgID,
		result:    make(chan any, 1),
		data:      nostrRaw,
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
		logrus.Errorf("NostrClient: Get unknown result after publishing event %q: %v", msgID, result)
		return nil
	}
	logrus.Debugf("NostrClient: Get result after publishing event %q: %v", msgID, reason)
	return nil
}

func (c *NostrClient) Subscribe(ctx context.Context, offset int64) error {
	timestamp := nostr.Timestamp(offset)
	subscriptionID := uuid.NewString()
	nostrEnvelope := nostr.ReqEnvelope{
		SubscriptionID: subscriptionID,
		Filters: []nostr.Filter{
			{
				Since: &timestamp,
			},
		},
	}

	nostrRaw, _ := nostrEnvelope.MarshalJSON()
	msg := NostrClientOutputMsg{
		requestID: subscriptionID,
		result:    make(chan any, 1),
		data:      nostrRaw,
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
