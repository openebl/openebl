package relay_test

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/openebl/openebl/pkg/relay"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"golang.org/x/time/rate"
)

type NostrRelayServerTestSuite struct {
	suite.Suite
}

type ServerEventSourceAndSink struct {
	events []relay.Event
}

func (s *ServerEventSourceAndSink) GetEvents() []relay.Event {
	return s.events
}

func (s *ServerEventSourceAndSink) Pull(ctx context.Context, request relay.EventSourcePullingRequest) (relay.EventSourcePullingResponse, error) {
	offset := request.Offset
	if offset >= int64(len(s.events)) {
		return relay.EventSourcePullingResponse{}, nil
	}

	end := offset + int64(request.Length)
	if end > int64(len(s.events)) {
		end = int64(len(s.events))
	}

	return relay.EventSourcePullingResponse{
		Events:    s.events[offset:end],
		MaxOffset: int64(end - 1),
	}, nil
}

func (s *ServerEventSourceAndSink) AddEvents(events ...relay.Event) {
	s.events = append(s.events, events...)
	for i := range s.events {
		s.events[i].Offset = int64(i)
	}
}

func (s *ServerEventSourceAndSink) Sink(ctx context.Context, event relay.Event) (string, error) {
	sum512Result := sha512.Sum512(event.Data)
	eventID := hex.EncodeToString(sum512Result[:])
	s.AddEvents(event)
	return eventID, nil
}

func TestNostrRelayServerTestSuite(t *testing.T) {
	suite.Run(t, new(NostrRelayServerTestSuite))
}

func (s *NostrRelayServerTestSuite) TestSubscription() {
	serverIdentity := "test-server"
	eventSource := &ServerEventSourceAndSink{}
	eventSink := &ServerEventSourceAndSink{}

	for i := 0; i < 4; i++ {
		event := relay.Event{
			Offset: int64(i),
			Type:   1001,
			Data:   []byte(fmt.Sprintf("hello %d", i)),
		}
		eventSource.AddEvents(event)
	}

	srv := relay.NewNostrServer(
		relay.NostrServerAddress("localhost:8081"),
		relay.NostrServerWithEventSource(eventSource.Pull),
		relay.NostrServerWithEventSink(eventSink.Sink),
		relay.NostrServerWithIdentity(serverIdentity),
	)
	go func() {
		srv.ListenAndServe()
	}()
	defer srv.Close()

	clientEventSink := &ServerEventSourceAndSink{}
	client := relay.NewNostrClient(
		relay.NostrClientWithServerURL("ws://localhost:8081"),
		relay.NostrClientWithEventSink(clientEventSink.Sink),
		relay.NostrClientWithConnectionStatusCallback(
			func(ctx context.Context, cancel context.CancelCauseFunc, client relay.RelayClient, remoteServerIdentity string, status bool) {
				if !status {
					return
				}
				assert.EqualValues(s.T(), serverIdentity, remoteServerIdentity, "server identity should be the same")
				client.Subscribe(context.Background(), 0)
			},
		),
	)
	defer client.Close()

	time.Sleep(2 * time.Second)
	assert.ElementsMatchf(s.T(), clientEventSink.GetEvents(), eventSource.GetEvents(), "client and server should have the same events")
}

func (s *NostrRelayServerTestSuite) TestReceiveEvent() {
	eventSource := &ServerEventSourceAndSink{}
	eventSink := &ServerEventSourceAndSink{}

	srv := relay.NewNostrServer(
		relay.NostrServerAddress("localhost:8082"),
		relay.NostrServerWithEventSource(eventSource.Pull),
		relay.NostrServerWithEventSink(eventSink.Sink),
	)
	go func() {
		srv.ListenAndServe()
	}()
	defer srv.Close()

	clientEventSink := &ServerEventSourceAndSink{}
	client := relay.NewNostrClient(
		relay.NostrClientWithServerURL("ws://localhost:8082"),
		relay.NostrClientWithEventSink(clientEventSink.Sink),
		relay.NostrClientWithConnectionStatusCallback(
			func(ctx context.Context, cancel context.CancelCauseFunc, client relay.RelayClient, serverIdentity string, status bool) {
			},
		),
	)
	defer client.Close()

	events := []relay.Event{
		{
			Type:   1001,
			Offset: 0,
			Data:   []byte("hello 1"),
		},
		{
			Type:   1001,
			Offset: 1,
			Data:   []byte("hello 2"),
		},
	}

	for _, event := range events {
		client.Publish(context.Background(), event.Type, event.Data)
	}

	time.Sleep(2 * time.Second)
	assert.Len(s.T(), eventSink.GetEvents(), 2)
	receivedEvents := eventSink.GetEvents()[:]
	for i := range receivedEvents {
		receivedEvents[i].Timestamp = 0
	}
	assert.ElementsMatchf(s.T(), receivedEvents, events, "client and server should have the same events")
}

var limiter = rate.NewLimiter(0.2, 1)

func eventSource(ctx context.Context, request relay.EventSourcePullingRequest) (relay.EventSourcePullingResponse, error) {
	if request.Offset != 0 && !limiter.Allow() {
		return relay.EventSourcePullingResponse{}, nil
	}

	return relay.EventSourcePullingResponse{
		Events: []relay.Event{
			{
				Timestamp: 999,
				Offset:    0,
				Type:      1001,
				Data:      []byte("hello"),
			},
		},
		MaxOffset: 0,
	}, nil
}

func serverEventSink(ctx context.Context, event relay.Event) (string, error) {
	// if rand.Float32() >= 0.5 {
	// 	return errors.New("not implemented")
	// }
	fmt.Printf("%s\n", string(event.Data))
	return string(event.Data), nil
}

func TestNostrRelayServer(t *testing.T) {
	t.Skip()
	srv := relay.NewNostrServer(
		relay.NostrServerAddress("localhost:8080"),
		relay.NostrServerWithEventSource(eventSource),
		relay.NostrServerWithEventSink(serverEventSink),
		relay.NostrServerWithIdentity("test-server"),
	)

	// go func() {
	// 	time.Sleep(10 * time.Second)
	// 	srv.Close()
	// }()
	err := srv.ListenAndServe()
	if err != nil {
		t.Fatal(err)
	}
}
