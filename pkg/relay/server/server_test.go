package server_test

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/openebl/openebl/pkg/relay"
	"github.com/openebl/openebl/pkg/relay/server"
	"github.com/openebl/openebl/pkg/relay/server/storage"
	"github.com/openebl/openebl/pkg/relay/server/storage/postgres"
	"github.com/openebl/openebl/pkg/util"
	mock_cert "github.com/openebl/openebl/test/mock/relay/server/cert"
	"github.com/samber/lo"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type ClientEventSink struct {
	Events []relay.Event
}

func (s *ClientEventSink) Sink(ctx context.Context, event relay.Event) (string, error) {
	sum512Result := sha512.Sum512(event.Data)
	eventID := hex.EncodeToString(sum512Result[:])
	s.Events = append(s.Events, event)
	return eventID, nil
}

// Mockup of storage.RelayServerDataStore
type ServerDataStore struct {
	mtx    sync.Mutex
	ID     string
	Events []storage.Event
	Offset map[string]int64
}

func NewServerDataStore(id string) *ServerDataStore {
	return &ServerDataStore{
		ID:     id,
		Offset: make(map[string]int64),
	}
}

func (s *ServerDataStore) GetIdentity(ctx context.Context) (string, error) {
	return s.ID, nil
}

func (s *ServerDataStore) StoreEventWithOffsetInfo(
	ctx context.Context,
	ts int64,
	eventID string,
	eventType int,
	event []byte,
	offset int64,
	peerId string,
) (int64, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	if _, dup := lo.Find(
		s.Events,
		func(e storage.Event) bool {
			return e.ID == eventID
		},
	); !dup {
		event := storage.Event{
			ID:        eventID,
			Timestamp: ts,
			Offset:    int64(len(s.Events)),
			Type:      eventType,
			Data:      event,
		}
		s.Events = append(s.Events, event)
	}

	if peerId != "" {
		s.Offset[peerId] = offset
	}

	return 0, nil
}

// ListEvents returns a list of events from the storage.
func (s *ServerDataStore) ListEvents(ctx context.Context, request storage.ListEventRequest) (storage.ListEventResult, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	if request.Offset >= int64(len(s.Events)) {
		return storage.ListEventResult{}, nil
	}
	end := request.Offset + request.Limit
	if end >= int64(len(s.Events)) {
		end = int64(len(s.Events))
	}

	eventResult := s.Events[request.Offset:end]
	return storage.ListEventResult{
		Events:    eventResult,
		MaxOffset: int64(eventResult[len(eventResult)-1].Offset),
	}, nil
}

// StoreOffset stores the offset of the peer.
func (s *ServerDataStore) StoreOffset(ctx context.Context, ts int64, peerId string, offset int64) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	s.Offset[peerId] = offset
	return nil
}

// GetOffset returns the offset of the peer.
func (s *ServerDataStore) GetOffset(ctx context.Context, peerId string) (int64, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.Offset[peerId], nil
}

func (s *ServerDataStore) GetEvents() []storage.Event {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.Events
}

type ServerTestSuite struct {
	suite.Suite

	ctrl    *gomock.Controller
	certMgr *mock_cert.MockCertManager
}

func TestServerSuite(t *testing.T) {
	suite.Run(t, new(ServerTestSuite))
}

func (s *ServerTestSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())
	s.certMgr = mock_cert.NewMockCertManager(s.ctrl)
}

func (s *ServerTestSuite) TearDownTest() {
	s.ctrl.Finish()
}

func (s *ServerTestSuite) TestClientServerServerClientInteraction() {
	ctx := context.Background()

	// The test case test with the configuration:
	// [client1] <--> [server1] <--> [server2] <--> [client2]
	// The message must be able to travel from client1 to client2.
	// The message already on the server1 and server2 must be spread to other nodes.
	storage1 := NewServerDataStore("server1")
	storage2 := NewServerDataStore("server2")

	storage1.StoreEventWithOffsetInfo(ctx, 100, server.GetEventID([]byte("event on server1")), 1001, []byte("event on server1"), 0, "")
	storage2.StoreEventWithOffsetInfo(ctx, 102, server.GetEventID([]byte("event on server2")), 1001, []byte("event on server2"), 0, "")

	srv1, err := server.NewServer(
		server.WithLocalAddress("localhost:9003"),
		server.WithStorage(storage1),
		server.WithPeers([]string{"ws://localhost:9004"}),
	)
	s.Require().NoError(err)

	srv2, err := server.NewServer(
		server.WithLocalAddress("localhost:9004"),
		server.WithStorage(storage2),
		server.WithPeers([]string{"ws://localhost:9003"}),
	)
	s.Require().NoError(err)

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		srv1.Run()
	}()
	go func() {
		defer wg.Done()
		srv2.Run()
	}()

	client1Sink := &ClientEventSink{}
	client2Sink := &ClientEventSink{}

	client1 := relay.NewNostrClient(
		relay.NostrClientWithServerURL("ws://localhost:9003"),
		relay.NostrClientWithEventSink(client1Sink.Sink),
		relay.NostrClientWithConnectionStatusCallback(
			func(ctx context.Context, cancel context.CancelCauseFunc, client relay.RelayClient, remoteServerIdentity string, status bool) {
				if !status {
					return
				}
				client.Subscribe(context.Background(), 0)
			},
		),
	)
	client2 := relay.NewNostrClient(
		relay.NostrClientWithServerURL("ws://localhost:9004"),
		relay.NostrClientWithEventSink(client2Sink.Sink),
		relay.NostrClientWithConnectionStatusCallback(
			func(ctx context.Context, cancel context.CancelCauseFunc, client relay.RelayClient, remoteServerIdentity string, status bool) {
				if !status {
					return
				}
				client.Subscribe(context.Background(), 0)
			},
		),
	)

	time.Sleep(2 * time.Second)
	client1.Publish(context.Background(), 1001, []byte("hello world from client1"))
	time.Sleep(2 * time.Second)
	client2.Publish(context.Background(), 1001, []byte("hello world from client2"))

	time.Sleep(2 * time.Second)
	srv1.Close()
	srv2.Close()
	wg.Wait()

	server1Events := lo.Map(storage1.GetEvents(), func(evt storage.Event, _ int) string { return string(evt.Data) })
	server2Events := lo.Map(storage2.GetEvents(), func(evt storage.Event, _ int) string { return string(evt.Data) })
	client1Events := lo.Map(client1Sink.Events, func(evt relay.Event, _ int) string { return string(evt.Data) })
	client2Events := lo.Map(client2Sink.Events, func(evt relay.Event, _ int) string { return string(evt.Data) })
	sort.Strings(server1Events)
	sort.Strings(server2Events)
	sort.Strings(client1Events)
	sort.Strings(client2Events)

	s.Require().Len(server1Events, 4)
	s.Assert().ElementsMatch(server1Events, server2Events)
	s.Assert().ElementsMatch(server1Events, client1Events)
	s.Assert().ElementsMatch(server1Events, client2Events)
}

func (s *ServerTestSuite) TestReceivingCRL() {
	storage1 := NewServerDataStore("server1")
	srv1, err := server.NewServer(
		server.WithLocalAddress("localhost:9011"),
		server.WithStorage(storage1),
		server.WithCertManager(s.certMgr),
	)
	s.Require().NoError(err)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv1.Run()
	}()

	client1Sink := &ClientEventSink{}
	client1 := relay.NewNostrClient(
		relay.NostrClientWithServerURL("ws://localhost:9011"),
		relay.NostrClientWithEventSink(client1Sink.Sink),
		relay.NostrClientWithConnectionStatusCallback(
			func(ctx context.Context, cancel context.CancelCauseFunc, client relay.RelayClient, remoteServerIdentity string, status bool) {
				if !status {
					return
				}
				client.Subscribe(context.Background(), 0)
			},
		),
	)

	s.certMgr.EXPECT().AddCRL(gomock.Any(), []byte("CRL message")).Return(nil)
	s.certMgr.EXPECT().SyncRootCerts(gomock.Any()).Return(nil).MinTimes(1)

	time.Sleep(2 * time.Second)
	client1.Publish(context.Background(), int(relay.X509CertificateRevocationList), []byte("CRL message"))

	time.Sleep(2 * time.Second)
	srv1.Close()
	wg.Wait()
}

func TestServer(t *testing.T) {
	t.Skip()
	dbConfig1 := util.PostgresDatabaseConfig{
		Host:     "localhost",
		Port:     5432,
		User:     "xdlai",
		Database: "relay_server_test",
		SSLMode:  "disable",
		PoolSize: 5,
	}

	dbConfig2 := util.PostgresDatabaseConfig{
		Host:     "localhost",
		Port:     5432,
		User:     "xdlai",
		Database: "relay_server_test2",
		SSLMode:  "disable",
		PoolSize: 5,
	}

	storage1, err := postgres.NewEventStorageWithConfig(dbConfig1)
	require.NoError(t, err)
	storage2, err := postgres.NewEventStorageWithConfig(dbConfig2)
	require.NoError(t, err)

	srv1, err := server.NewServer(
		server.WithLocalAddress("localhost:9001"),
		server.WithStorage(storage1),
		server.WithPeers([]string{"ws://localhost:9002"}),
	)
	require.NoError(t, err)

	srv2, err := server.NewServer(
		server.WithLocalAddress("localhost:9002"),
		server.WithStorage(storage2),
		server.WithPeers([]string{"ws://localhost:9001"}),
	)
	require.NoError(t, err)

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		srv1.Run()
	}()
	go func() {
		defer wg.Done()
		srv2.Run()
	}()
	wg.Wait()
}
