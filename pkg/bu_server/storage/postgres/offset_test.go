package postgres_test

import (
	"database/sql"
	"testing"

	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/bu_server/storage/postgres"
	"github.com/stretchr/testify/suite"
)

type OffsetStorageTestSuite struct {
	BaseTestSuite
	storage storage.OffsetStorage
}

func TestOffsetStorage(t *testing.T) {
	suite.Run(t, new(OffsetStorageTestSuite))
}

func (s *OffsetStorageTestSuite) SetupTest() {
	s.BaseTestSuite.SetupTest()
	s.storage = postgres.NewStorageWithPool(s.pgPool)
}

func (s *OffsetStorageTestSuite) TearDownTest() {
	s.BaseTestSuite.TearDownTest()
}

func (s *OffsetStorageTestSuite) TestRelayServerOffset() {
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
