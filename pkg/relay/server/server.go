package server

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/openebl/openebl/pkg/relay"
	"github.com/openebl/openebl/pkg/relay/server/storage"
	"github.com/openebl/openebl/pkg/relay/server/storage/postgres"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
)

type ServerConfig struct {
	DbConfig     postgres.DatabaseConfig `yaml:"db_config"`
	LocalAddress string                  `yaml:"local_address"`
	OtherPeers   []string                `yaml:"other_peers"` // Set the server to connect to other servers to pull data from them.
}

type Server struct {
	io.Closer

	localAddress string
	dataStore    storage.RelayServerDataStore
	dataStoreID  string
	eventSink    relay.EventSink
	relayServer  *relay.NostrServer

	otherPeers map[string]*ClientCallback // map[remote address]RelayClient
}

type ClientCallback struct {
	client         *relay.NostrClient
	server         *Server
	serverIdentity string
}

func (c *ClientCallback) OnConnectionStatusChange(
	ctx context.Context,
	cancel context.CancelCauseFunc,
	client relay.RelayClient,
	remoteServerIdentity string,
	status bool,
) {
	if !status {
		return
	}

	c.serverIdentity = remoteServerIdentity
	offset, err := c.server.dataStore.GetOffset(ctx, remoteServerIdentity)
	if err != nil {
		cancel(err)
		return
	}

	if err := client.Subscribe(ctx, offset); err != nil {
		logrus.Errorf("failed to subscribe to %s: %v", remoteServerIdentity, err)
		cancel(err)
		return
	}
}

func (c *ClientCallback) EventSink(ctx context.Context, event relay.Event) (string, error) {
	evtID := GetEventID(event.Data)
	_, err := c.server.dataStore.StoreEventWithOffsetInfo(ctx, event.Timestamp, evtID, event.Type, event.Data, event.Offset, c.serverIdentity)
	if err != nil && !errors.Is(err, storage.ErrDuplicateEvent) {
		return "", err
	}
	return evtID, nil
}

func NewServer(options ...ServerOption) (*Server, error) {
	server := &Server{}
	for _, option := range options {
		option(server)
	}

	// Get data storage identity
	dataStoreID, err := server.dataStore.GetIdentity(context.Background())
	if err != nil {
		return nil, err
	}
	server.dataStoreID = dataStoreID

	// Prepare event source
	eventSource := func(ctx context.Context, request relay.EventSourcePullingRequest) (relay.EventSourcePullingResponse, error) {
		dsRequest := storage.ListEventRequest{
			Limit:  int64(request.Length),
			Offset: int64(request.Offset),
		}
		dsResult, err := server.dataStore.ListEvents(ctx, dsRequest)
		if err != nil {
			return relay.EventSourcePullingResponse{}, err
		}

		events := lo.Map(
			dsResult.Events,
			func(event storage.Event, _ int) relay.Event {
				return relay.Event{
					Timestamp: event.Timestamp,
					Offset:    event.Offset,
					Type:      event.Type,
					Data:      event.Data,
				}
			},
		)

		return relay.EventSourcePullingResponse{
			Events:    events,
			MaxOffset: dsResult.MaxOffset,
		}, nil
	}

	// Prepare EventSink
	serverEventSink := func(ctx context.Context, event relay.Event) (string, error) {
		evtID := GetEventID(event.Data)
		_, err := server.dataStore.StoreEventWithOffsetInfo(ctx, event.Timestamp, evtID, event.Type, event.Data, 0, "")
		if err != nil && !errors.Is(err, storage.ErrDuplicateEvent) {
			return "", err
		}
		return evtID, nil
	}
	server.eventSink = serverEventSink

	// Prepare NostrServer
	relayServer := relay.NewNostrServer(
		relay.NostrServerAddress(server.localAddress),
		relay.NostrServerWithEventSource(eventSource),
		relay.NostrServerWithEventSink(serverEventSink),
		relay.NostrServerWithIdentity(dataStoreID),
	)
	server.relayServer = relayServer

	return server, nil
}

func (s *Server) Run() error {
	for peerAddress := range s.otherPeers {
		peerAddress := peerAddress

		clientCallback := &ClientCallback{
			server: s,
		}

		client := relay.NewNostrClient(
			relay.NostrClientWithServerURL(peerAddress),
			relay.NostrClientWithEventSink(clientCallback.EventSink),
			relay.NostrClientWithConnectionStatusCallback(clientCallback.OnConnectionStatusChange),
		)
		clientCallback.client = client
		s.otherPeers[peerAddress] = clientCallback
	}

	err := s.relayServer.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) Close() error {
	for _, clientCallback := range s.otherPeers {
		defer clientCallback.client.Close()
	}

	return s.relayServer.Close()
}
