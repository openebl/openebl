package postgres_test

import (
	"database/sql"
	"testing"

	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/bu_server/storage/postgres"
	"github.com/stretchr/testify/suite"
)

type OutboxStorageTestSuite struct {
	BaseTestSuite
	storage storage.TradeDocumentOutboxStorage
}

func TestOutboxStorage(t *testing.T) {
	suite.Run(t, new(OutboxStorageTestSuite))
}

func (s *OutboxStorageTestSuite) SetupTest() {
	s.BaseTestSuite.SetupTest()
	s.storage = postgres.NewStorageWithPool(s.pgPool)
}

func (s *OutboxStorageTestSuite) TearDownTest() {
	s.BaseTestSuite.TearDownTest()
}

func (s *OutboxStorageTestSuite) TestAddTradeDocumentOutbox() {
	tradeDoc := storage.TradeDocument{
		RawID:      "deadbeef",
		Kind:       1001,
		DocID:      "doc_id_1",
		DocVersion: 1,
		Doc:        []byte("%PDF-1.7 Hello world!"),
		CreatedAt:  1234567890,
		Meta:       map[string]interface{}{"meta": "data"},
	}

	tx, ctx, err := s.storage.CreateTx(s.ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	s.Require().NoError(err)
	defer func() { _ = tx.Rollback(ctx) }()

	// Add trade document to outbox
	err = s.storage.AddTradeDocumentOutbox(s.ctx, tx, tradeDoc.CreatedAt, tradeDoc.DocID, tradeDoc.Kind, tradeDoc.Doc)
	s.Require().NoError(err)

	// Get event from outbox
	messages, err := s.storage.GetTradeDocumentOutbox(s.ctx, tx, 10)
	s.Require().NoError(err)
	s.Require().NotEmpty(messages)
	s.Require().Len(messages, 1)
	s.Assert().Equal(tradeDoc.DocID, messages[0].Key)
	s.Assert().Equal(tradeDoc.Doc, messages[0].Msg)

	// Delete event from outbox
	err = s.storage.DeleteTradeDocumentOutbox(s.ctx, tx, messages[0].RecID)
	s.Require().NoError(err)

	// No more events in outbox
	messages, err = s.storage.GetTradeDocumentOutbox(s.ctx, tx, 10)
	s.Require().NoError(err)
	s.Require().Empty(messages)
}
