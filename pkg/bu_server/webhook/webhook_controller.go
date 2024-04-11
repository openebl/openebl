package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/samber/lo"
)

type WebhookController interface {
	Create(ctx context.Context, ts int64, req CreateWebhookRequest) (model.Webhook, error)
	List(ctx context.Context, req ListWebhookRequest) (ListWebhookResponse, error)
	Get(ctx context.Context, applicationID string, id string) (model.Webhook, error)
	Update(ctx context.Context, ts int64, req UpdateWebhookRequest) (model.Webhook, error)
	Delete(ctx context.Context, ts int64, req DeleteWebhookRequest) (model.Webhook, error)
	SendWebhookEvent(ctx context.Context, tx storage.Tx, ts int64, applicationID string, id string, eventType model.WebhookEventType) error
}

type ListWebhookRequest struct {
	Offset        int    `json:"offset"`
	Limit         int    `json:"limit"`
	ApplicationID string `json:"application_id"`
}

type ListWebhookResponse struct {
	Total   int             `json:"total"`
	Records []model.Webhook `json:"records"`
}

type CreateWebhookRequest struct {
	Requester     string                   `json:"requester"`
	ApplicationID string                   `json:"application_id"`
	Events        []model.WebhookEventType `json:"events"`
	Url           string                   `json:"url"`
	Secret        string                   `json:"secret"`
}

type UpdateWebhookRequest struct {
	ID            string                   `json:"id"`
	Requester     string                   `json:"requester"`
	ApplicationID string                   `json:"application_id"`
	Events        []model.WebhookEventType `json:"events"`
	Url           string                   `json:"url"`
	Secret        string                   `json:"secret"`
}

type DeleteWebhookRequest struct {
	ID            string `json:"id"`
	Requester     string `json:"requester"`
	ApplicationID string `json:"application_id"`
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

	// Conceal secret in the response
	webhook.Secret = ""
	return webhook, nil
}

func (c *_WebhookController) List(ctx context.Context, req ListWebhookRequest) (ListWebhookResponse, error) {
	err := ValidateListWebhookRequest(req)
	if err != nil {
		return ListWebhookResponse{}, err
	}

	listReq := storage.ListWebhookRequest{
		Offset:        req.Offset,
		Limit:         req.Limit,
		ApplicationID: req.ApplicationID,
	}

	tx, ctx, err := c.storage.CreateTx(ctx)
	if err != nil {
		return ListWebhookResponse{}, nil
	}
	defer func() { _ = tx.Rollback(ctx) }()

	result, err := c.storage.ListWebhook(ctx, tx, listReq)
	if err != nil {
		return ListWebhookResponse{}, err
	}

	// Conceal secrets in the response
	lo.ForEach(result.Records, func(webhook model.Webhook, i int) {
		result.Records[i].Secret = ""
	})

	res := ListWebhookResponse{
		Total:   result.Total,
		Records: result.Records,
	}

	return res, nil
}

func (c *_WebhookController) Get(ctx context.Context, applicationID string, id string) (model.Webhook, error) {
	if applicationID == "" {
		return model.Webhook{}, errors.New("empty application id")
	}
	if id == "" {
		return model.Webhook{}, errors.New("empty webhook id")
	}
	listReq := storage.ListWebhookRequest{
		Offset:        0,
		Limit:         1,
		ApplicationID: applicationID,
		IDs:           []string{id},
	}

	tx, ctx, err := c.storage.CreateTx(ctx)
	if err != nil {
		return model.Webhook{}, nil
	}
	defer func() { _ = tx.Rollback(ctx) }()

	result, err := c.storage.ListWebhook(ctx, tx, listReq)
	if err != nil {
		return model.Webhook{}, err
	}

	if len(result.Records) < 1 {
		return model.Webhook{}, model.ErrWebhookNotFound
	}

	// Conceal secret in the response
	result.Records[0].Secret = ""
	return result.Records[0], nil
}

func (c *_WebhookController) Update(ctx context.Context, ts int64, req UpdateWebhookRequest) (model.Webhook, error) {
	err := ValidateUpdateWebhookRequest(req)
	if err != nil {
		return model.Webhook{}, err
	}

	tx, ctx, err := c.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return model.Webhook{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	listReq := storage.ListWebhookRequest{
		Offset:        0,
		Limit:         1,
		ApplicationID: req.ApplicationID,
		IDs:           []string{req.ID},
	}
	listResp, err := c.storage.ListWebhook(ctx, tx, listReq)
	if len(listResp.Records) < 1 {
		return model.Webhook{}, model.ErrWebhookNotFound
	}

	updatedWebhook := listResp.Records[0]
	updatedWebhook.Version += 1
	updatedWebhook.UpdatedAt = ts
	updatedWebhook.UpdatedBy = req.Requester
	updatedWebhook.Url = req.Url
	updatedWebhook.Events = req.Events
	updatedWebhook.Secret = req.Secret

	err = c.storage.AddWebhook(ctx, tx, updatedWebhook)
	if err != nil {
		return model.Webhook{}, err
	}

	err = tx.Commit(ctx)
	if err != nil {
		return model.Webhook{}, err
	}

	// Conceal secret in the response
	updatedWebhook.Secret = ""
	return updatedWebhook, nil
}

func (c *_WebhookController) Delete(ctx context.Context, ts int64, req DeleteWebhookRequest) (model.Webhook, error) {
	err := ValidateDeleteWebhookRequest(req)
	if err != nil {
		return model.Webhook{}, err
	}

	tx, ctx, err := c.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return model.Webhook{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	listReq := storage.ListWebhookRequest{
		Offset:        0,
		Limit:         1,
		ApplicationID: req.ApplicationID,
		IDs:           []string{req.ID},
	}
	listResp, err := c.storage.ListWebhook(ctx, tx, listReq)
	if len(listResp.Records) < 1 {
		return model.Webhook{}, model.ErrWebhookNotFound
	}

	updatedWebhook := listResp.Records[0]
	updatedWebhook.Version += 1
	updatedWebhook.UpdatedAt = ts
	updatedWebhook.UpdatedBy = req.Requester
	updatedWebhook.Deleted = true

	err = c.storage.AddWebhook(ctx, tx, updatedWebhook)
	if err != nil {
		return model.Webhook{}, err
	}

	err = tx.Commit(ctx)
	if err != nil {
		return model.Webhook{}, err
	}

	// Conceal secret in the response
	updatedWebhook.Secret = ""
	return updatedWebhook, nil
}

func (c *_WebhookController) SendWebhookEvent(ctx context.Context, tx storage.Tx, ts int64, applicationID string, id string, eventType model.WebhookEventType) error {
	req := storage.ListWebhookRequest{
		Offset:        0,
		Limit:         1,
		ApplicationID: applicationID,
		Events:        []string{string(eventType)},
	}

	res, err := c.storage.ListWebhook(ctx, tx, req)
	if err != nil {
		return err
	}
	if len(res.Records) < 1 {
		return nil
	}

	webhook := res.Records[0]
	if webhook.Deleted {
		return nil
	}

	event := &model.WebhookEvent{
		ID:        id,
		Url:       webhook.Url,
		Type:      eventType,
		CreatedAt: ts,
	}

	signature, err := eventHash(event, webhook.Secret)
	if err != nil {
		return err
	}

	err = c.storage.AddWebhookEvent(ctx, tx, ts, signature, event)
	if err != nil {
		return err
	}

	return nil
}

func eventHash(event *model.WebhookEvent, key string) (string, error) {
	if key == "" {
		return "", errors.New("empty secret key")
	}
	eventBytes, err := json.Marshal(event)
	if err != nil {
		return "", err
	}

	h := hmac.New(sha1.New, []byte(key))
	h.Write(eventBytes)

	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}
