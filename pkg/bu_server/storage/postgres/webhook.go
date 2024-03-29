package postgres

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/storage"
)

func (s *_Storage) AddWebhook(ctx context.Context, tx storage.Tx, webhook model.Webhook) error {
	query := `
WITH new_data AS (
	INSERT INTO webhook (id, "version", deleted, application_id, events, webhook, created_at, updated_at)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
	ON CONFLICT (id) DO UPDATE SET
		"version" = excluded."version",
		application_id = excluded.application_id,
		deleted = excluded.deleted,
		events = excluded.events,
		webhook = excluded.webhook,
		updated_at = excluded.updated_at
	RETURNING id, "version", webhook, updated_at
)
INSERT INTO webhook_history (id, "version", webhook, created_at)
SELECT * FROM new_data
`
	_, err := tx.Exec(
		ctx,
		query,
		webhook.ID,
		webhook.Version,
		webhook.Deleted,
		webhook.ApplicationID,
		webhook.Events,
		webhook,
		webhook.UpdatedAt,
	)
	if err != nil {
		return err
	}

	return nil
}

func (s *_Storage) ListWebhook(ctx context.Context, tx storage.Tx, req storage.ListWebhookRequest) (storage.ListWebhookResult, error) {
	query := `
	WITH filtered_record AS (
		SELECT
			rec_id,
			webhook
		FROM webhook w
		WHERE
			NOT deleted AND
			($3 = '' OR application_id = $3) AND
			(COALESCE(array_length($4::TEXT[], 1), 0) = 0 OR id = ANY($4)) AND
			(COALESCE(array_length($5::TEXT[], 1), 0) = 0 OR events @> $5)
	)
	SELECT
		total,
		webhook
	FROM (SELECT COUNT(*) AS total FROM filtered_record) AS report
	FULL OUTER JOIN (SELECT webhook FROM filtered_record ORDER BY rec_id ASC OFFSET $1 LIMIT $2) AS record ON FALSE
	`
	rows, err := tx.Query(ctx, query, req.Offset, req.Limit, req.ApplicationID, req.IDs, req.Events)
	if err != nil {
		return storage.ListWebhookResult{}, err
	}
	defer rows.Close()

	var res storage.ListWebhookResult
	for rows.Next() {
		var total *int
		var webhook *model.Webhook

		if err := rows.Scan(&total, &webhook); err != nil {
			return storage.ListWebhookResult{}, err
		}
		if total != nil {
			res.Total = *total
		}
		if webhook != nil {
			res.Records = append(res.Records, *webhook)
		}
	}
	if err := rows.Err(); err != nil {
		return storage.ListWebhookResult{}, err
	}

	return res, nil
}

func (s *_Storage) AddWebhookEvent(ctx context.Context, tx storage.Tx, ts int64, key string, event *model.WebhookEvent) error {
	if event == nil {
		return nil
	}
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	query := `INSERT INTO webhook_outbox(created_at, key, event) VALUES ($1, $2, $3)`
	_, err = tx.Exec(
		ctx,
		query,
		ts,
		key,
		data,
	)
	if err != nil {
		return err
	}

	return nil
}

func (s *_Storage) GetWebhookEvent(ctx context.Context, tx storage.Tx, batchSize int) ([]storage.OutboxMsg, error) {
	query := `SELECT rec_id, key, event FROM webhook_outbox ORDER BY rec_id ASC LIMIT $1`
	rows, err := tx.Query(ctx, query, batchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make([]storage.OutboxMsg, 0, batchSize)
	for rows.Next() {
		var recID sql.NullInt64
		var key sql.NullString
		data := make([]byte, 0)
		if err := rows.Scan(&recID, &key, &data); err != nil {
			return nil, err
		}
		record := storage.OutboxMsg{
			RecID: recID.Int64,
			Key:   key.String,
			Msg:   data,
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return records, nil
}

func (s *_Storage) DeleteWebhookEvent(ctx context.Context, tx storage.Tx, recIDs ...int64) error {
	if len(recIDs) == 0 {
		return nil
	}

	query := `DELETE FROM webhook_outbox WHERE rec_id = ANY($1)`
	_, err := tx.Exec(ctx, query, recIDs)
	if err != nil {
		return err
	}
	return nil
}
