package postgres_test

import (
	"database/sql"
	"testing"

	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/bu_server/storage/postgres"
	"github.com/openebl/openebl/pkg/relay"
	"github.com/stretchr/testify/suite"
)

type RelayStorageTestSuite struct {
	BaseTestSuite
	storage storage.RelayStorage
}

func TestRelayStorage(t *testing.T) {
	suite.Run(t, new(RelayStorageTestSuite))
}

func (s *RelayStorageTestSuite) SetupTest() {
	s.BaseTestSuite.SetupTest()
	s.storage = postgres.NewStorageWithPool(s.pgPool)
}

func (s *RelayStorageTestSuite) TearDownTest() {
	s.BaseTestSuite.TearDownTest()
}

func (s *RelayStorageTestSuite) TestRelayServerOffset() {
	tx, ctx, err := s.storage.CreateTx(s.ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	s.Require().NoError(err)
	defer func() { _ = tx.Rollback(ctx) }()

	serverID := "test_relay_server"
	offset, err := s.storage.GetRelayServerOffset(s.ctx, tx, serverID)
	s.Require().EqualError(err, sql.ErrNoRows.Error())
	s.Assert().EqualValues(0, offset)

	err = s.storage.UpdateRelayServerOffset(s.ctx, tx, serverID, 999)
	s.Require().NoError(err)
	offset, err = s.storage.GetRelayServerOffset(s.ctx, tx, serverID)
	s.Require().NoError(err)
	s.Assert().EqualValues(999, offset)

	err = s.storage.UpdateRelayServerOffset(s.ctx, tx, serverID, 1999)
	s.Require().NoError(err)
	offset, err = s.storage.GetRelayServerOffset(s.ctx, tx, serverID)
	s.Require().NoError(err)
	s.Assert().EqualValues(1999, offset)

	offset, err = s.storage.GetRelayServerOffset(s.ctx, tx, "non_existent_server")
	s.Require().EqualError(err, sql.ErrNoRows.Error())
	s.Assert().EqualValues(0, offset)
}

func (s *RelayStorageTestSuite) TestStoreEvent() {
	tx, ctx, err := s.storage.CreateTx(s.ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	s.Require().NoError(err)
	defer func() { _ = tx.Rollback(ctx) }()

	serverID := "test_relay_server"
	ts := int64(1234567890)
	event := relay.Event{
		Timestamp: 12345,
		Offset:    999,
		Type:      int(relay.X509Certificate),
		Data:      []byte("test_data"),
	}
	eventID := "test_event_id"

	// Test storing a new event.
	stored, err := s.storage.StoreEvent(s.ctx, tx, ts, eventID, event, serverID)
	s.Require().NoError(err)
	s.Assert().True(stored)

	// Test storing a duplicated event.
	stored, err = s.storage.StoreEvent(s.ctx, tx, ts, eventID, event, serverID)
	s.Require().NoError(err)
	s.Assert().False(stored)

	// Verify if the offset is updated correctly.
	offset, err := s.storage.GetRelayServerOffset(s.ctx, tx, serverID)
	s.Require().NoError(err)
	s.Assert().EqualValues(event.Offset, offset)

	err = tx.Commit(ctx)
	s.Require().NoError(err)
}
