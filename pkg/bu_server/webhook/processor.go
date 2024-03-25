package webhook

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/avast/retry-go/v4"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/bu_server/storage/postgres"
	"github.com/openebl/openebl/pkg/util"
	"github.com/sirupsen/logrus"
)

type Config struct {
	Database      util.PostgresDatabaseConfig
	CheckInterval int
	BatchSize     int
	Timeout       int
	MaxRetry      int
}

type ProcessorOption func(p *Processor)

func WithStorage(storage storage.WebhookStorage) ProcessorOption {
	return func(p *Processor) {
		p.storage = storage
	}
}

type Processor struct {
	retry         int
	batchSize     int
	checkInterval time.Duration
	timeout       time.Duration
	storage       storage.WebhookStorage
}

func NewProcessorWithConfig(cfg Config, opts ...ProcessorOption) (*Processor, error) {
	res := &Processor{
		retry:         cfg.MaxRetry,
		batchSize:     cfg.BatchSize,
		checkInterval: time.Second * time.Duration(cfg.CheckInterval),
		timeout:       time.Second * time.Duration(cfg.Timeout),
	}

	for _, opt := range opts {
		opt(res)
	}
	if res.storage == nil {
		webhookStorage, err := postgres.NewStorageWithConfig(cfg.Database)
		if err != nil {
			return nil, fmt.Errorf("create storage: %w", err)
		}
		res.storage = webhookStorage
	}

	return res, nil
}

func (p *Processor) Run(ctx context.Context) {
	logrus.Info("WebhookEvent processor is now running")

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(p.checkInterval):
			p._Proc(ctx)
		}
	}
}

func (p *Processor) _Proc(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msgs, err := p.getEvent(ctx)
		if err != nil {
			logrus.Errorf("failed to get WebhookEvent: %v", err)
			return
		}
		if len(msgs) == 0 {
			return
		}

		logrus.Debugf("Got %d WebhookEvents", len(msgs))
		ids := make([]int64, 0, len(msgs))
		for i := range msgs {
			err = p.postEvent(ctx, msgs[i])
			if err != nil {
				logrus.Warnf("failed to post WebhookEvent: %v", err)
				if !errors.Is(err, model.ErrWebhookUnreachable) {
					continue
				}
			}

			ids = append(ids, msgs[i].RecID)
		}

		if len(ids) == 0 {
			return
		}

		err = p.deleteEvent(ctx, ids...)
		if err != nil {
			logrus.Errorf("failed to delete WebhookEvent: %v", err)
		}

		logrus.Debugf("POSTed %d WebhookEvents", len(ids))
	}
}

func (p *Processor) postEvent(ctx context.Context, msg storage.OutboxMsg) error {
	var event model.WebhookEvent
	err := json.Unmarshal(msg.Msg, &event)
	if err != nil {
		return fmt.Errorf("json unmarshal event: %v", err)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableKeepAlives = true
	transport.MaxIdleConnsPerHost = -1
	client := http.Client{Timeout: p.timeout, Transport: transport}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, event.Url, util.StructToJSONReader(event))
	if err != nil {
		return fmt.Errorf("create http request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Payload-Signature", msg.Key)

	err = retry.Do(
		func() error {
			resp, err := client.Do(req)
			if err != nil {
				logrus.Debugf("send http request: %v", err)
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				logrus.Debugf("%s returned %v: %s", event.Url, resp.StatusCode, string(body))
				return fmt.Errorf("unexpected status code: %v", resp.StatusCode)
			}

			return nil
		},
		retry.Attempts(uint(p.retry)),
		retry.Context(ctx),
	)

	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return fmt.Errorf("exceed maximum retries posting webhook event. %w", model.ErrWebhookUnreachable)
	}
	return nil
}

func (p *Processor) getEvent(ctx context.Context) ([]storage.OutboxMsg, error) {
	tx, ctx, err := p.storage.CreateTx(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	outboxMsgs, err := p.storage.GetWebhookEvent(ctx, tx, p.batchSize)
	if err != nil {
		return nil, err
	}

	if len(outboxMsgs) == 0 {
		return nil, nil
	}

	return outboxMsgs, nil
}

func (p *Processor) deleteEvent(ctx context.Context, recIDs ...int64) error {
	tx, ctx, err := p.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	err = p.storage.DeleteWebhookEvent(ctx, tx, recIDs...)
	if err != nil {
		return err
	}
	err = tx.Commit(ctx)
	if err != nil {
		return err
	}

	return nil
}
