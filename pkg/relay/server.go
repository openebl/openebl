package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

type NostrServerOption func(s *NostrServer)

type NostrServer struct {
	httpServer *http.Server
	address    string
	certFile   *string
	keyFile    *string

	wsUpgrader  websocket.Upgrader
	identity    string
	eventSource EventSource
	eventSink   EventSink

	clientMux sync.Mutex
	clients   map[string]*NostrClientStub // map[remote address]*NostrClientStub
}

type NostrClientSubscription struct {
	SubscribeID string
	Type        int
	Offset      int64
	CloseChan   chan any
}

type NoStrClientSubscriptionFilter struct {
	Since  *int64
	Until  *int64
	Offset *int64
}

// NostrClientStub is a presentation of a client connection to the relay server.
type NostrClientStub struct {
	nostrServer *NostrServer
	conn        *websocket.Conn

	clientMux     sync.Mutex
	subscriptions map[string]NostrClientSubscription // map[subscription id]NostrClientSubscription

	closeChan  chan struct{}
	outputChan chan []byte
}

func NewNostrServer(opts ...NostrServerOption) *NostrServer {
	server := &NostrServer{
		clients: make(map[string]*NostrClientStub),
	}

	for _, opt := range opts {
		opt(server)
	}

	return server
}

func (s *NostrServer) ListenAndServe() error {
	if s.httpServer != nil {
		return errors.New("server already started")
	}

	serverMux := http.NewServeMux()
	serverMux.Handle("/", s)

	s.httpServer = &http.Server{
		Addr:    s.address,
		Handler: serverMux,
	}

	if s.certFile != nil && s.keyFile != nil {
		return s.httpServer.ListenAndServeTLS(*s.certFile, *s.keyFile)
	} else if !(s.certFile == nil && s.keyFile == nil) {
		return errors.New("both certFile and keyFile must be specified")
	}

	return s.httpServer.ListenAndServe()
}

func (s *NostrServer) Close() error {
	if s.httpServer == nil {
		return errors.New("server not started")
	}

	if err := s.httpServer.Shutdown(context.Background()); err != nil {
		return err
	}
	s.httpServer = nil
	return nil
}

func (s *NostrServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logrus.Debugf("Receive connection to %q.", r.RequestURI)

	// A brief checking about if the client wants to upgrade to websocket.
	// If not, just return a 200 OK.
	if r.Header.Get("Upgrade") == "" {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Nostr Relay Server is working."))
		return
	}

	c, err := s.wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		logrus.Errorf("(%q)failed to upgrade websocket: %v", r.RequestURI, err)
		return
	}

	client := &NostrClientStub{
		nostrServer:   s,
		conn:          c,
		subscriptions: make(map[string]NostrClientSubscription),
		closeChan:     make(chan struct{}),
		outputChan:    make(chan []byte, 16),
	}

	s.addClient(client)
	go client.Run()
}

func (s *NostrServer) addClient(client *NostrClientStub) {
	remoteAddr := client.conn.RemoteAddr().String()

	s.clientMux.Lock()
	defer s.clientMux.Unlock()
	s.clients[remoteAddr] = client
}

func (s *NostrServer) removeClient(client *NostrClientStub) {
	remoteAddr := client.conn.RemoteAddr().String()

	s.clientMux.Lock()
	defer s.clientMux.Unlock()
	delete(s.clients, remoteAddr)
}

func (c *NostrClientStub) Run() {
	defer c.close()

	// Send RelayServerIdentity to the client before accepting any request.
	identifyResponse := Response{
		RelayServerIdentifyResponse: &RelayServerIdentifyResponse{
			Identity: c.nostrServer.identity,
		},
	}
	identifyResponseRaw, _ := json.Marshal(identifyResponse)
	if err := c.send(identifyResponseRaw, true); err != nil {
		logrus.Errorf("failed to send identify response: %v", err)
		return
	}

	go c.outputWorker()

	for {
		_, message, err := c.conn.ReadMessage()
		if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
			return
		} else if err != nil {
			logrus.Errorf("failed to read message: %v", err)
			return
		}
		logrus.Debugf("recv: message length %d", len(message))

		request, err := ParseRequest(message)
		if err != nil {
			logrus.Errorf("failed to parse message: %v", err)
			c.sendNotice("failed to parse message")
			continue
		}

		switch req := request.(type) {
		case *EventPublishRequest:
			c.receiveEvent(req)
		case *SubscribeRequest:
			c.subscribe(req)
		default:
			c.sendNotice("unsupported request")
		}
	}
}

func (c *NostrClientStub) outputWorker() {
	for {
		select {
		case <-c.closeChan:
			return
		case msg := <-c.outputChan:
			err := c.conn.WriteMessage(websocket.TextMessage, msg)
			if err != nil {
				logrus.Errorf("failed to write message: %v", err)
				c.close()
				return
			}
		}
	}
}

func (c *NostrClientStub) close() {
	func() {
		c.clientMux.Lock()
		defer c.clientMux.Unlock()

		select {
		case <-c.closeChan:
			return
		default:
			close(c.closeChan)
			for _, subscription := range c.subscriptions {
				close(subscription.CloseChan)
			}
		}
	}()
	c.conn.Close()
	c.nostrServer.removeClient(c)
}

func (c *NostrClientStub) send(msg []byte, blocking bool) error {
	if blocking {
		select {
		case <-c.closeChan:
			return errors.New("client closed")
		case c.outputChan <- msg:
		}
	} else {
		select {
		case <-c.closeChan:
			return errors.New("client closed")
		case c.outputChan <- msg:
		default:
			return errors.New("output channel is full")
		}
	}

	return nil
}

func (c *NostrClientStub) sendNotice(msg string) error {
	resp := Response{
		Notice: &RelayServerNotice{
			Message: msg,
		},
	}
	respRaw, _ := json.Marshal(resp)
	return c.send(respRaw, true)
}

func (c *NostrClientStub) subscribe(req *SubscribeRequest) {
	subScription := NostrClientSubscription{
		SubscribeID: req.SubscribeID,
		Type:        req.Type,
		Offset:      req.Offset,
		CloseChan:   make(chan any),
	}

	c.clientMux.Lock()
	defer c.clientMux.Unlock()

	c.subscriptions[req.SubscribeID] = subScription

	go c.subscriptionPullingTask(subScription)
}

func (c *NostrClientStub) unsubscribe(subscriptionID string) {
	c.clientMux.Lock()
	defer c.clientMux.Unlock()

	subscription, ok := c.subscriptions[subscriptionID]
	if !ok {
		return
	}
	delete(c.subscriptions, subscriptionID)
	close(subscription.CloseChan)
}

func (c *NostrClientStub) subscriptionPullingTask(subscription NostrClientSubscription) {
	eventSourceRequest := EventSourcePullingRequest{
		Offset: subscription.Offset,
		Type:   subscription.Type,
		Length: 100,
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	firstBatch := true
	for {
		if firstBatch {
			select {
			case <-c.closeChan:
				return
			case <-subscription.CloseChan:
				return
			default:
			}
		} else {
			select {
			case <-c.closeChan:
				return
			case <-subscription.CloseChan:
				return
			case <-ticker.C:
			}
		}

		eventSourceResponse, err := c.nostrServer.eventSource(context.Background(), eventSourceRequest)
		if err != nil {
			logrus.Errorf("failed to pull events: %v", err)
			c.close()
			return
		}
		if len(eventSourceResponse.Events) == 0 && firstBatch {
			// All old data is consumed by the client.
			eos := Response{
				SubscribeResponse: &SubscribeResponse{
					SubscribeID: subscription.SubscribeID,
					EOS:         true,
				},
			}
			eosRaw, _ := json.Marshal(eos)
			if err := c.send(eosRaw, true); err != nil {
				logrus.Errorf("failed to send EOS: %v", err)
			}
			firstBatch = false
			continue
		} else if len(eventSourceResponse.Events) == 0 {
			continue
		}

		for _, event := range eventSourceResponse.Events {
			// TODO: EventSource should provide enough information to generate a valid nostr.Event.
			eventEnvelope := Response{
				SubscribeResponse: &SubscribeResponse{
					SubscribeID: subscription.SubscribeID,
					Event: &Event{
						Timestamp: event.Timestamp,
						Offset:    event.Offset,
						Type:      event.Type,
						Data:      event.Data,
					},
				},
			}
			eventEnvelopeRaw, _ := json.Marshal(&eventEnvelope)
			if err := c.send(eventEnvelopeRaw, false); err != nil {
				logrus.Errorf("failed to send event: %v", err)
				c.close()
				return
			}
		}
		eventSourceRequest.Offset = eventSourceResponse.MaxOffset + 1
	}
}

func (c *NostrClientStub) receiveEvent(evt *EventPublishRequest) {
	event := Event{
		Timestamp: time.Now().Unix(),
		Type:      evt.Type,
		Data:      evt.Data,
	}

	resp := EventPublishResponse{
		RequestID: evt.RequestID,
	}

	if eventID, err := c.nostrServer.eventSink(context.Background(), event); err != nil {
		logrus.Errorf("failed to sink event: %v", err)
		resp.OK = false
		resp.Reason = fmt.Sprintf("failed to sink event: %v", err)
	} else {
		resp.OK = true
		resp.EventID = eventID
	}

	respEnvelop := Response{
		EventPublishResponse: &resp,
	}
	raw, _ := json.Marshal(respEnvelop)
	if err := c.send(raw, true); err != nil {
		logrus.Errorf("failed to send OK: %v", err)
		c.close()
		return
	}
}
