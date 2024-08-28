package postgres_test

import (
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-testfixtures/testfixtures/v3"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/bu_server/storage/postgres"
	"github.com/stretchr/testify/suite"
)

type WebhookStorageTestSuite struct {
	BaseTestSuite
	storage storage.WebhookStorage
}

func TestWebhookStorage(t *testing.T) {
	suite.Run(t, new(WebhookStorageTestSuite))
}

func (s *WebhookStorageTestSuite) SetupTest() {
	s.BaseTestSuite.SetupTest()
	s.storage = postgres.NewStorageWithPool(s.pgPool)

	db := stdlib.OpenDBFromPool(s.pgPool)
	fixtures, err := testfixtures.New(
		testfixtures.Database(db),
		testfixtures.Dialect("postgres"),
		testfixtures.Directory("testdata/webhook"),
	)
	s.Require().NoError(err)
	s.Require().NoError(fixtures.Load())
}

func (s *WebhookStorageTestSuite) TearDownTest() {
	s.BaseTestSuite.TearDownTest()
}

func (s *WebhookStorageTestSuite) TestAddWebhook() {
	ts := time.Now().Unix()
	webhook := model.Webhook{
		ID:            "test_webhook",
		Version:       1,
		ApplicationID: "app_1",
		Deleted:       false,
		Url:           "https://example.com/webhook",
		Events:        []model.WebhookEventType{model.WebhookEventBLAccomplished},
		Secret:        "secret",
		CreatedAt:     12345,
		CreatedBy:     "test_user",
		UpdatedAt:     12345,
		UpdatedBy:     "test_user",
	}

	tx, ctx, err := s.storage.CreateTx(s.ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	s.Require().NoError(err)
	defer func() { _ = tx.Rollback(ctx) }()

	err = s.storage.AddWebhook(ctx, tx, webhook)
	s.Require().NoError(err)

	ts += 10
	newWebhook := webhook
	newWebhook.Version = 2
	newWebhook.Url = "https://example2.com/webhook"
	newWebhook.Events = append(newWebhook.Events, model.WebhookEventBLPrintedToPaper)
	newWebhook.UpdatedAt = ts
	err = s.storage.AddWebhook(ctx, tx, newWebhook)
	s.Require().NoError(err)

	var dbData []model.Webhook
	// Verify webhook table.
	s.Require().NoError(tx.QueryRow(ctx, `SELECT JSONB_AGG(webhook ORDER BY rec_id ASC) FROM webhook WHERE id = $1`, webhook.ID).Scan(&dbData))
	s.Require().Equal(1, len(dbData))
	s.Assert().Equal(newWebhook, dbData[0])

	// Verify webhook_history table.
	s.Require().NoError(tx.QueryRow(ctx, `SELECT JSONB_AGG(webhook ORDER BY rec_id ASC) FROM webhook_history WHERE id = $1`, webhook.ID).Scan(&dbData))
	s.Require().Equal(2, len(dbData))
	s.Assert().Equal(webhook, dbData[0])
	s.Assert().Equal(newWebhook, dbData[1])

	s.Require().NoError(tx.Commit(ctx))
}

func (s *WebhookStorageTestSuite) TestListWebhook() {
	tx, ctx, err := s.storage.CreateTx(s.ctx)
	s.Require().NoError(err)
	defer func() { _ = tx.Rollback(ctx) }()

	baseReq := storage.ListWebhookRequest{
		Offset:        0,
		Limit:         10,
		ApplicationID: "app_1",
	}

	// Test Basic Function (filter by ApplicationID)
	res, err := s.storage.ListWebhook(ctx, tx, baseReq)
	s.Require().NoError(err)
	s.Assert().Equal(2, res.Total)
	s.Require().Equal(2, len(res.Records))
	s.Assert().Equal("webhook_1", res.Records[0].ID)
	s.Assert().Equal("https://example1.com/webhook", res.Records[0].Url)
	s.Assert().Equal("webhook_2", res.Records[1].ID)
	s.Assert().Equal("https://example2.com/webhook", res.Records[1].Url)
	// End of Test Basic Function

	// Test Limit and Offset
	req := baseReq
	req.Limit = 1
	req.Offset = 1
	res, err = s.storage.ListWebhook(ctx, tx, req)
	s.Require().NoError(err)
	s.Assert().Equal(2, res.Total)
	s.Require().Equal(1, len(res.Records))
	s.Assert().Equal("webhook_2", res.Records[0].ID)
	// End of Test Limit and Offset

	// Test IDs
	req = baseReq
	req.IDs = []string{"webhook_1"}
	res, err = s.storage.ListWebhook(ctx, tx, req)
	s.Require().NoError(err)
	s.Assert().Equal(1, res.Total)
	s.Require().Equal(1, len(res.Records))
	s.Assert().Equal("webhook_1", res.Records[0].ID)
	// End of Test IDs

	// Test Events
	req = baseReq
	req.Events = []string{"bu.updated"}
	res, err = s.storage.ListWebhook(ctx, tx, req)
	s.Require().NoError(err)
	s.Assert().Equal(1, res.Total)
	s.Require().Equal(1, len(res.Records))
	s.Assert().Equal("webhook_2", res.Records[0].ID)
	// End of Test Events
}

func (s *WebhookStorageTestSuite) TestWebhookEvent() {
	tx, ctx, err := s.storage.CreateTx(s.ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	s.Require().NoError(err)
	defer func() { _ = tx.Rollback(ctx) }()

	res, err := s.storage.GetWebhookEvent(s.ctx, tx, 10)
	s.Require().NoError(err)
	s.Assert().Empty(res)

	key := "some_hash_value"
	ts := time.Now().Unix()
	event := &model.WebhookEvent{
		ID:        "bl_1",
		Url:       "https://example.com/webhook",
		Type:      "bl.accomplished",
		CreatedAt: ts,
	}
	err = s.storage.AddWebhookEvent(ctx, tx, ts, key, event)
	s.Require().NoError(err)

	res, err = s.storage.GetWebhookEvent(s.ctx, tx, 20)
	s.Require().Nil(err)
	s.Require().Len(res, 1)
	s.Require().Equal(key, res[0].Key)
	var eventOnDB *model.WebhookEvent
	s.Require().NoError(json.Unmarshal(res[0].Msg, &eventOnDB))
	s.Assert().EqualValues(event, eventOnDB)

	err = s.storage.DeleteWebhookEvent(s.ctx, tx, res[0].RecID)
	s.Require().NoError(err)
	res, err = s.storage.GetWebhookEvent(s.ctx, tx, 10)
	s.Require().NoError(err)
	s.Assert().Empty(res)
}
