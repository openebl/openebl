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
