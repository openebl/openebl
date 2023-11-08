package relay

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/nbd-wtf/go-nostr"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
)

type NostrServerOption func(s *NostrServer)

type NostrServer struct {
	httpServer *http.Server
	address    string
	certFile   *string
	keyFile    *string

	wsUpgrader  websocket.Upgrader
	eventSource EventSource
	eventSink   EventSink

	clientMux sync.Mutex
	clients   map[string]*NostrClientStub // map[remote address]*NostrClientStub
}

type NostrClientSubscription struct {
	ID        string
	Filters   []NoStrClientSubscriptionFilter
	CloseChan chan any
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
	c, err := s.wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		logrus.Errorf("failed to upgrade websocket: %v", err)
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

		nostrEnvelope := nostr.ParseMessage(message)
		if nostrEnvelope == nil {
			logrus.Errorf("failed to parse message: %v", err)
			c.sendNotice("failed to parse message")
			continue
		}

		switch nostrEnvelope.Label() {
		case "REQ":
			c.subscribe(nostrEnvelope.(*nostr.ReqEnvelope))
		case "EVENT":
			c.receiveEvent(nostrEnvelope.(*nostr.EventEnvelope))
		case "CLOSE":
			c.unsubscribe(string(*(nostrEnvelope.(*nostr.CloseEnvelope))))
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
	resp := nostr.NoticeEnvelope(msg)
	respRaw, _ := resp.MarshalJSON()
	return c.send(respRaw, true)
}

func (c *NostrClientStub) subscribe(req *nostr.ReqEnvelope) {
	if len(req.Filters) == 0 {
		c.sendNotice("no filters specified")
		return
	}
	if len(req.Filters) > 1 {
		c.sendNotice("multiple filters not supported")
		return
	}

	subScription := NostrClientSubscription{
		ID:        req.SubscriptionID,
		CloseChan: make(chan any),
	}
	subScription.Filters = lo.Map(req.Filters, func(f nostr.Filter, _ int) NoStrClientSubscriptionFilter {
		return NoStrClientSubscriptionFilter{
			Since: (*int64)(f.Since),
			Until: (*int64)(f.Until),
		}
	})

	c.clientMux.Lock()
	defer c.clientMux.Unlock()

	c.subscriptions[req.SubscriptionID] = subScription

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
		Offset: subscription.Filters[0].Since,
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
			eos := nostr.EOSEEnvelope(subscription.ID)
			eosRaw, _ := eos.MarshalJSON()
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
			eventEnvelope := nostr.EventEnvelope{
				SubscriptionID: &subscription.ID,
				Event: nostr.Event{
					CreatedAt: nostr.Timestamp(event.Offset),
					Kind:      event.Type,
					Content:   string(event.Data),
				},
			}
			eventEnvelopeRaw, _ := eventEnvelope.MarshalJSON()
			if err := c.send(eventEnvelopeRaw, false); err != nil {
				logrus.Errorf("failed to send event: %v", err)
				c.close()
				return
			}
		}
		newOffset := eventSourceResponse.MaxOffset + 1
		eventSourceRequest.Offset = &newOffset
	}
}

func (c *NostrClientStub) receiveEvent(evt *nostr.EventEnvelope) {
	event := Event{
		Timestamp: int64(evt.Event.CreatedAt),
		Type:      evt.Event.Kind,
		Data:      []byte(evt.Event.Content),
	}

	resp := nostr.OKEnvelope{
		EventID: evt.Event.ID,
		OK:      true,
		Reason:  "",
	}

	if err := c.nostrServer.eventSink(context.Background(), event); err != nil {
		logrus.Errorf("failed to sink event: %v", err)
		resp.OK = false
		resp.Reason = fmt.Sprintf("failed to sink event: %v", err)
	}

	raw, _ := resp.MarshalJSON()
	if err := c.send(raw, true); err != nil {
		logrus.Errorf("failed to send OK: %v", err)
		c.close()
		return
	}
}
