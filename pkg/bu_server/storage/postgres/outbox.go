package postgres

import (
	"context"

	"github.com/openebl/openebl/pkg/bu_server/storage"
)

func (s *_Storage) AddTradeDocumentOutbox(ctx context.Context, tx storage.Tx, ts int64, key string, payload []byte) error {
	const query string = `INSERT INTO trade_document_outbox (key, payload, created_at) VALUES ($1, $2, $3)`
	_, err := tx.Exec(ctx, query, key, payload, ts)
	if err != nil {
		return err
	}
	return nil
}

func (s *_Storage) GetTradeDocumentOutbox(ctx context.Context, tx storage.Tx, batchSize int) ([]storage.OutboxMsg, error) {
	const query string = `SELECT rec_id, key, payload FROM trade_document_outbox ORDER BY rec_id ASC LIMIT $1`
	rows, err := tx.Query(ctx, query, batchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make([]storage.OutboxMsg, 0, batchSize)
	for rows.Next() {
		var recID int64
		var key string
		var payload []byte
		if err := rows.Scan(&recID, &key, &payload); err != nil {
			return nil, err
		}
		record := storage.OutboxMsg{
			RecID: recID,
			Key:   key,
			Msg:   payload,
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return records, nil
}

func (s *_Storage) DeleteTradeDocumentOutbox(ctx context.Context, tx storage.Tx, recIDs ...int64) error {
	if len(recIDs) == 0 {
		return nil
	}

	const query string = `DELETE FROM trade_document_outbox WHERE rec_id = ANY($1)`
	_, err := tx.Exec(ctx, query, recIDs)
	if err != nil {
		return err
	}
	return nil
}
