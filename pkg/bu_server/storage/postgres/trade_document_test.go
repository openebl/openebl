package postgres_test

import (
	"database/sql"
	"testing"

	"github.com/go-testfixtures/testfixtures/v3"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/bu_server/storage/postgres"
	"github.com/stretchr/testify/suite"
)

type TradeDocumentStorageTestSuite struct {
	BaseTestSuite
	storage storage.TradeDocumentStorage
}

func TestTradeDocumentStorage(t *testing.T) {
	suite.Run(t, new(TradeDocumentStorageTestSuite))
}

func (s *TradeDocumentStorageTestSuite) SetupTest() {
	s.BaseTestSuite.SetupTest()
	s.storage = postgres.NewStorageWithPool(s.pgPool)

	db := stdlib.OpenDBFromPool(s.pgPool)
	fixtures, err := testfixtures.New(
		testfixtures.Database(db),
		testfixtures.Dialect("postgres"),
		testfixtures.Directory("testdata/trade_document"),
	)
	s.Require().NoError(err)
	s.Require().NoError(fixtures.Load())
}

func (s *TradeDocumentStorageTestSuite) TearDownTest() {
	s.BaseTestSuite.TearDownTest()
}

func (s *TradeDocumentStorageTestSuite) TestAddTradeDocument() {
	tx, ctx, err := s.storage.CreateTx(s.ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	s.Require().NoError(err)
	defer tx.Rollback(ctx)

	tradeDocument := storage.TradeDocument{
		RawID:      "test-raw-id",
		Kind:       1001,
		DocID:      "test-doc-id",
		DocVersion: 1,
		Doc:        []byte("test-doc"),
		CreatedAt:  123,
		Meta: map[string]interface{}{
			"bu": "test-bu",
		},
	}

	err = s.storage.AddTradeDocument(ctx, tx, tradeDocument)
	s.Require().NoError(err)
	tradeDocument.DocVersion += 1
	tradeDocument.RawID = "test-raw-id-2"
	tradeDocument.Doc = []byte("test-doc version 2")
	err = s.storage.AddTradeDocument(ctx, tx, tradeDocument)
	s.Require().NoError(err)

	var dataOnDB []string
	err = tx.QueryRow(ctx, `SELECT jsonb_agg(convert_from(doc, 'utf8') ORDER BY doc_version asc) FROM trade_document td WHERE doc_id = 'test-doc-id'`).Scan(&dataOnDB)
	s.Require().NoError(err)
	s.Require().Len(dataOnDB, 2)
	s.Assert().ElementsMatch([]string{"test-doc", "test-doc version 2"}, dataOnDB)

	s.Require().NoError(tx.Commit(ctx))
}

func (s *TradeDocumentStorageTestSuite) TestListTradeDocument() {
	tx, ctx, err := s.storage.CreateTx(s.ctx)
	s.Require().NoError(err)
	defer tx.Rollback(s.ctx)

	docsOnDB := []storage.TradeDocument{
		{
			RawID:      "raw_doc_3",
			Kind:       1001,
			DocID:      "doc_2",
			DocVersion: 1,
			Doc:        []byte("doc 2"),
			CreatedAt:  1634567890,
			Meta: map[string]any{
				"visible_to_bu": []any{"did:openebl:issuer", "did:openebl:shipper", "did:openebl:consignee", "did:openebl:release_agent"},
				"archive":       []any{"did:openebl:issuer", "did:openebl:shipper", "did:openebl:consignee", "did:openebl:release_agent"},
			},
		},
		{
			RawID:      "raw_doc_2",
			Kind:       1000,
			DocID:      "doc_1",
			DocVersion: 2,
			Doc:        []byte("new binary_data"),
			CreatedAt:  1634567890,
			Meta: map[string]any{
				"visible_to_bu": []any{"did:openebl:issuer", "did:openebl:shipper", "did:openebl:consignee", "did:openebl:release_agent"},
				"sent":          []any{"did:openebl:issuer", "did:openebl:shipper"},
				"action_needed": []any{"did:openebl:consignee"},
				"upcoming":      []any{"did:openebl:release_agent"},
			},
		},
	}

	req := storage.ListTradeDocumentRequest{
		Limit: 10,
	}

	// Basic List function
	func() {
		resp, err := s.storage.ListTradeDocument(ctx, tx, req)
		s.Require().NoError(err)
		s.Assert().Equal(2, resp.Total)
		s.Assert().ElementsMatch(docsOnDB, resp.Docs)
	}()

	// List with empty result
	func() {
		newReq := req
		newReq.DocIDs = []string{"non-exist-doc-id"}
		resp, err := s.storage.ListTradeDocument(ctx, tx, newReq)
		s.Require().NoError(err)
		s.Assert().Equal(0, resp.Total)
		s.Assert().Empty(resp.Docs)
	}()

	// List with offset
	func() {
		newReq := req
		newReq.Offset = 1
		resp, err := s.storage.ListTradeDocument(ctx, tx, newReq)
		s.Require().NoError(err)
		s.Assert().Equal(2, resp.Total)
		s.Assert().ElementsMatch(docsOnDB[1:], resp.Docs)
	}()

	// List with kind filter
	func() {
		newReq := req
		newReq.Kind = 1000
		resp, err := s.storage.ListTradeDocument(ctx, tx, newReq)
		s.Require().NoError(err)
		s.Assert().Equal(1, resp.Total)
		s.Assert().ElementsMatch(docsOnDB[1:], resp.Docs)
	}()

	// List with docIDs filter
	func() {
		newReq := req
		newReq.DocIDs = []string{"doc_2"}
		resp, err := s.storage.ListTradeDocument(ctx, tx, newReq)
		s.Require().NoError(err)
		s.Assert().Equal(1, resp.Total)
		s.Assert().ElementsMatch(docsOnDB[:1], resp.Docs)
	}()

	// List with status report
	func() {
		newReq := req
		newReq.Report = true
		newReq.RequestBy = "did:openebl:issuer"
		resp, err := s.storage.ListTradeDocument(s.ctx, tx, newReq)
		s.Require().NoError(err)
		s.Assert().Equal(2, resp.Total)
		s.Assert().Equal(0, resp.Report.ActionNeeded)
		s.Assert().Equal(0, resp.Report.Upcoming)
		s.Assert().Equal(1, resp.Report.Sent)
		s.Assert().Equal(1, resp.Report.Archive)
		s.Assert().ElementsMatch(docsOnDB, resp.Docs)
	}()

	// List with meta filter: action_needed
	func() {
		newReq := req
		newReq.Report = true
		newReq.RequestBy = "did:openebl:consignee"
		newReq.Meta = map[string]any{
			"action_needed": []any{"did:openebl:consignee"},
		}
		resp, err := s.storage.ListTradeDocument(ctx, tx, newReq)
		s.Require().NoError(err)
		s.Assert().Equal(1, resp.Total)
		s.Assert().Equal(1, resp.Report.ActionNeeded)
		s.Assert().Equal(1, resp.Report.Archive)
		s.Assert().ElementsMatch(docsOnDB[1:], resp.Docs)
	}()

	// List with meta filter: upcoming
	func() {
		newReq := req
		newReq.Report = true
		newReq.RequestBy = "did:openebl:release_agent"
		newReq.Meta = map[string]any{
			"upcoming": []string{"did:openebl:release_agent"},
		}
		resp, err := s.storage.ListTradeDocument(ctx, tx, newReq)
		s.Require().NoError(err)
		s.Assert().Equal(1, resp.Total)
		s.Assert().Equal(1, resp.Report.Upcoming)
		s.Assert().Equal(1, resp.Report.Archive)
		s.Assert().ElementsMatch(docsOnDB[1:], resp.Docs)
	}()

	// List with meta filter: sent
	func() {
		newReq := req
		newReq.Report = true
		newReq.RequestBy = "did:openebl:issuer"
		newReq.Meta = map[string]any{
			"sent": []string{"did:openebl:issuer"},
		}
		resp, err := s.storage.ListTradeDocument(ctx, tx, newReq)
		s.Require().NoError(err)
		s.Assert().Equal(1, resp.Total)
		s.Assert().Equal(1, resp.Report.Sent)
		s.Assert().Equal(1, resp.Report.Archive)
		s.Assert().ElementsMatch(docsOnDB[1:], resp.Docs)
	}()

	// List with meta filter: archive
	func() {
		newReq := req
		newReq.Report = true
		newReq.RequestBy = "did:openebl:issuer"
		newReq.Meta = map[string]any{
			"archive": []string{"did:openebl:issuer"},
		}
		resp, err := s.storage.ListTradeDocument(ctx, tx, newReq)
		s.Require().NoError(err)
		s.Assert().Equal(1, resp.Total)
		s.Assert().Equal(1, resp.Report.Sent)
		s.Assert().Equal(1, resp.Report.Archive)
		s.Assert().ElementsMatch(docsOnDB[:1], resp.Docs)
	}()
}
