package webhook

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/storage"
)

type WebhookController interface {
	Create(ctx context.Context, ts int64, req CreateWebhookRequest) (model.Webhook, error)
}

type CreateWebhookRequest struct {
	Requester     string                   `json:"requester"`
	ApplicationID string                   `json:"application_id"`
	Events        []model.WebhookEventType `json:"events"`
	Url           string                   `json:"url"`
	Secret        string                   `json:"secret"`
}

type _WebhookController struct {
	storage storage.WebhookStorage
}

func NewWebhookController(storage storage.WebhookStorage) WebhookController {
	return &_WebhookController{
		storage: storage,
	}
}

func (c *_WebhookController) Create(ctx context.Context, ts int64, req CreateWebhookRequest) (model.Webhook, error) {
	err := ValidateCreateWebhookRequest(req)
	if err != nil {
		return model.Webhook{}, err
	}

	webhook := model.Webhook{
		ID:            uuid.NewString(),
		Version:       1,
		ApplicationID: req.ApplicationID,
		Url:           req.Url,
		Events:        req.Events,
		Secret:        req.Secret,
		CreatedAt:     ts,
		CreatedBy:     req.Requester,
		UpdatedAt:     ts,
		UpdatedBy:     req.Requester,
		Deleted:       false,
	}

	tx, ctx, err := c.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return model.Webhook{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	err = c.storage.AddWebhook(ctx, tx, webhook)
	if err != nil {
		return model.Webhook{}, err
	}

	err = tx.Commit(ctx)
	if err != nil {
		return model.Webhook{}, err
	}

	webhook.Secret = ""
	return webhook, nil
}
