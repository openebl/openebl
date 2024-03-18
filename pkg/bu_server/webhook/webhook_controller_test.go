package webhook_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/bu_server/webhook"
	mock_storage "github.com/openebl/openebl/test/mock/bu_server/storage"
	"github.com/stretchr/testify/suite"
)

type WebhookControllerTestSuite struct {
	suite.Suite
	ctx         context.Context
	ctrl        *gomock.Controller
	storage     *mock_storage.MockWebhookStorage
	tx          *mock_storage.MockTx
	webhookCtrl webhook.WebhookController
}

func TestWebhookController(t *testing.T) {
	suite.Run(t, new(WebhookControllerTestSuite))
}

func (s *WebhookControllerTestSuite) SetupTest() {
	s.ctx = context.Background()
	s.ctrl = gomock.NewController(s.T())
	s.storage = mock_storage.NewMockWebhookStorage(s.ctrl)
	s.tx = mock_storage.NewMockTx(s.ctrl)
	s.webhookCtrl = webhook.NewWebhookController(s.storage)
}

func (s *WebhookControllerTestSuite) TearDownTest() {
	s.ctrl.Finish()
}

func (s *WebhookControllerTestSuite) TestCreateWebhook() {
	ts := time.Now().Unix()

	req := webhook.CreateWebhookRequest{
		Requester:     "requester",
		ApplicationID: "app_id",
		Events:        []model.WebhookEventType{model.WebhookEventBLAccomplished, model.WebhookEventBLPrintedToPaper},
		Url:           "https://example.com/notify",
		Secret:        "secret_key",
	}

	expectedWebhook := model.Webhook{
		Version:       1,
		ApplicationID: "app_id",
		Events:        []model.WebhookEventType{model.WebhookEventBLAccomplished, model.WebhookEventBLPrintedToPaper},
		Url:           "https://example.com/notify",
		Secret:        "secret_key",
		CreatedAt:     ts,
		CreatedBy:     "requester",
		UpdatedAt:     ts,
		UpdatedBy:     "requester",
		Deleted:       false,
	}

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().AddWebhook(gomock.Any(), s.tx, gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, webhook model.Webhook) error {
				expectedWebhook.ID = webhook.ID
				s.Assert().Equal(expectedWebhook, webhook)
				return nil
			},
		),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	res, err := s.webhookCtrl.Create(s.ctx, ts, req)
	s.NoError(err)
	s.Require().Empty(res.Secret)
	res.Secret = expectedWebhook.Secret
	s.Assert().Equal(expectedWebhook, res)
}

func (s *WebhookControllerTestSuite) TestListWebhook() {
	req := webhook.ListWebhookRequest{
		Offset:        0,
		Limit:         10,
		ApplicationID: "app_1",
	}

	expectedWebhook := model.Webhook{
		ID:            "webhook_1",
		Version:       1,
		ApplicationID: "app_1",
		Url:           "https://example.com/notify",
		Events:        []model.WebhookEventType{model.WebhookEventBLAccomplished, model.WebhookEventBLPrintedToPaper},
		Secret:        "secret_key",
		CreatedAt:     12345,
		CreatedBy:     "requester",
		UpdatedAt:     12346,
		UpdatedBy:     "requester",
		Deleted:       false,
	}

	listReq := storage.ListWebhookRequest{
		Offset:        0,
		Limit:         10,
		ApplicationID: "app_1",
	}
	listResult := storage.ListWebhookResult{
		Total:   1,
		Records: []model.Webhook{expectedWebhook},
	}

	expectedListResp := webhook.ListWebhookResponse{
		Total:   1,
		Records: []model.Webhook{expectedWebhook},
	}

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any()).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().ListWebhook(gomock.Any(), s.tx, listReq).Return(listResult, nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	res, err := s.webhookCtrl.List(s.ctx, req)
	s.NoError(err)
	s.Assert().Equal(expectedListResp, res)
}

func (s *WebhookControllerTestSuite) TestGetWebhook() {
	const (
		appID     = "app_1"
		webhookID = "webhook_1"
	)

	expectedWebhook := model.Webhook{
		ID:            "webhook_1",
		Version:       1,
		ApplicationID: "app_1",
		Url:           "https://example.com/notify",
		Events:        []model.WebhookEventType{model.WebhookEventBLAccomplished, model.WebhookEventBLPrintedToPaper},
		Secret:        "secret_key",
		CreatedAt:     12345,
		CreatedBy:     "requester",
		UpdatedAt:     12346,
		UpdatedBy:     "requester",
		Deleted:       false,
	}

	listReq := storage.ListWebhookRequest{
		Offset:        0,
		Limit:         1,
		ApplicationID: appID,
		IDs:           []string{webhookID},
	}
	listResult := storage.ListWebhookResult{
		Total:   1,
		Records: []model.Webhook{expectedWebhook},
	}

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any()).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().ListWebhook(gomock.Any(), s.tx, listReq).Return(listResult, nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	res, err := s.webhookCtrl.Get(s.ctx, appID, webhookID)
	s.NoError(err)
	s.Assert().Equal(expectedWebhook, res)
}

func (s *WebhookControllerTestSuite) TestUpdateWebhook() {
	ts := time.Now().Unix()

	req := webhook.UpdateWebhookRequest{
		ID:            "webhook_1",
		Requester:     "requester",
		ApplicationID: "app_id",
		Events:        []model.WebhookEventType{model.WebhookEventBLIssued, model.WebhookEventBLAccomplished, model.WebhookEventBLPrintedToPaper},
		Url:           "https://example2.com/notify",
		Secret:        "new_secret_key",
	}

	webhook := model.Webhook{
		Version:       1,
		ApplicationID: "app_id",
		Events:        []model.WebhookEventType{model.WebhookEventBLAccomplished, model.WebhookEventBLPrintedToPaper},
		Url:           "https://example.com/notify",
		Secret:        "secret_key",
		CreatedAt:     12345,
		CreatedBy:     "requester",
		UpdatedAt:     12345,
		UpdatedBy:     "requester",
		Deleted:       false,
	}
	expectedListReq := storage.ListWebhookRequest{
		Offset:        0,
		Limit:         1,
		ApplicationID: "app_id",
		IDs:           []string{"webhook_1"},
	}
	expectedListResp := storage.ListWebhookResult{
		Total:   1,
		Records: []model.Webhook{webhook},
	}

	expectedWebhook := model.Webhook{
		Version:       2,
		ApplicationID: "app_id",
		Events:        []model.WebhookEventType{model.WebhookEventBLIssued, model.WebhookEventBLAccomplished, model.WebhookEventBLPrintedToPaper},
		Url:           "https://example2.com/notify",
		Secret:        "new_secret_key",
		CreatedAt:     12345,
		CreatedBy:     "requester",
		UpdatedAt:     ts,
		UpdatedBy:     "requester",
		Deleted:       false,
	}

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().ListWebhook(gomock.Any(), s.tx, expectedListReq).Return(expectedListResp, nil),
		s.storage.EXPECT().AddWebhook(gomock.Any(), s.tx, expectedWebhook).Return(nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	res, err := s.webhookCtrl.Update(s.ctx, ts, req)
	s.NoError(err)
	s.Require().Empty(res.Secret)
	res.Secret = expectedWebhook.Secret
	s.Assert().Equal(expectedWebhook, res)
}

func (s *WebhookControllerTestSuite) TestDeleteWebhook() {
	ts := time.Now().Unix()

	req := webhook.DeleteWebhookRequest{
		ID:            "webhook_1",
		Requester:     "requester",
		ApplicationID: "app_id",
	}

	webhook := model.Webhook{
		Version:       1,
		ApplicationID: "app_id",
		Events:        []model.WebhookEventType{model.WebhookEventBLAccomplished, model.WebhookEventBLPrintedToPaper},
		Url:           "https://example.com/notify",
		Secret:        "secret_key",
		CreatedAt:     12345,
		CreatedBy:     "requester",
		UpdatedAt:     12345,
		UpdatedBy:     "requester",
		Deleted:       false,
	}
	expectedListReq := storage.ListWebhookRequest{
		Offset:        0,
		Limit:         1,
		ApplicationID: "app_id",
		IDs:           []string{"webhook_1"},
	}
	expectedListResp := storage.ListWebhookResult{
		Total:   1,
		Records: []model.Webhook{webhook},
	}

	expectedWebhook := model.Webhook{
		Version:       2,
		ApplicationID: "app_id",
		Events:        []model.WebhookEventType{model.WebhookEventBLAccomplished, model.WebhookEventBLPrintedToPaper},
		Url:           "https://example.com/notify",
		Secret:        "secret_key",
		CreatedAt:     12345,
		CreatedBy:     "requester",
		UpdatedAt:     ts,
		UpdatedBy:     "requester",
		Deleted:       true,
	}

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().ListWebhook(gomock.Any(), s.tx, expectedListReq).Return(expectedListResp, nil),
		s.storage.EXPECT().AddWebhook(gomock.Any(), s.tx, expectedWebhook).Return(nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	res, err := s.webhookCtrl.Delete(s.ctx, ts, req)
	s.NoError(err)
	s.Require().Empty(res.Secret)
	res.Secret = expectedWebhook.Secret
	s.Assert().Equal(expectedWebhook, res)
}

func (s *WebhookControllerTestSuite) TestSendWebhookEvent() {
	const (
		id    = "subject_id"
		appID = "app_id"
	)
	ts := time.Now().Unix()

	expectedWebhook := model.Webhook{
		ID:            "webhook_1",
		Version:       1,
		ApplicationID: appID,
		Url:           "https://example.com/notify",
		Events:        []model.WebhookEventType{model.WebhookEventBLAccomplished, model.WebhookEventBLPrintedToPaper},
		Secret:        "secret_key",
		CreatedAt:     12345,
		CreatedBy:     "requester",
		UpdatedAt:     12345,
		UpdatedBy:     "requester",
		Deleted:       false,
	}
	expectedListReq := storage.ListWebhookRequest{
		Offset:        0,
		Limit:         1,
		ApplicationID: appID,
		Events:        []string{"bl.accomplished"},
	}
	expectedListResp := storage.ListWebhookResult{
		Total:   1,
		Records: []model.Webhook{expectedWebhook},
	}

	expectedEvent := &model.WebhookEvent{
		ID:        id,
		Url:       "https://example.com/notify",
		Type:      model.WebhookEventBLAccomplished,
		CreatedAt: ts,
	}

	gomock.InOrder(
		s.storage.EXPECT().ListWebhook(gomock.Any(), s.tx, expectedListReq).Return(expectedListResp, nil),
		s.storage.EXPECT().AddWebhookEvent(gomock.Any(), s.tx, ts, gomock.Any(), expectedEvent).Return(nil),
	)

	err := s.webhookCtrl.SendWebhookEvent(s.ctx, s.tx, ts, appID, id, model.WebhookEventBLAccomplished)
	s.Require().NoError(err)
}
