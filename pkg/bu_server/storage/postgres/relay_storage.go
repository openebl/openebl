package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/relay"
)

func (s *_Storage) GetRelayServerOffset(ctx context.Context, tx storage.Tx, serverID string) (int64, error) {
	const query string = `SELECT comsumed_offset FROM relay_server_offset WHERE server_id = $1`
	row := tx.QueryRow(ctx, query, serverID)
	var offset int64
	if err := row.Scan(&offset); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, sql.ErrNoRows
		}
		return 0, err
	}
	return offset, nil
}

func (s *_Storage) UpdateRelayServerOffset(ctx context.Context, tx storage.Tx, serverID string, offset int64) error {
	const query string = `
INSERT INTO relay_server_offset (server_id, comsumed_offset, updated_at) VALUES ($1, $2, EXTRACT(EPOCH FROM NOW()))
ON CONFLICT (server_id) DO UPDATE SET
	comsumed_offset = EXCLUDED.comsumed_offset,
	updated_at = EXCLUDED.updated_at
`
	_, err := tx.Exec(ctx, query, serverID, offset)
	if err != nil {
		return err
	}
	return nil
}

func (s *_Storage) StoreEvent(ctx context.Context, tx storage.Tx, ts int64, eventID string, event relay.Event, serverID string) (bool, error) {
	const query string = `
WITH insert_offset AS (
	INSERT INTO relay_server_offset (server_id, comsumed_offset, updated_at) VALUES ($1, $2, $3)
	ON CONFLICT (server_id) DO UPDATE SET
		comsumed_offset = EXCLUDED.comsumed_offset,
		updated_at = EXCLUDED.updated_at
	RETURNING comsumed_offset
)
INSERT INTO relay_event (id, "type", created_at, "event", stored_at) VALUES ($4, $5, $6, $7, $3)
ON CONFLICT (id) DO NOTHING
RETURNING id`

	row := tx.QueryRow(
		ctx,
		query,
		serverID,
		event.Offset,
		ts,
		eventID,
		event.Type,
		event.Timestamp,
		event.Data,
	)

	insertedID := sql.NullString{}
	if err := row.Scan(&insertedID); errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	} else if err != nil {
		return false, err
	}

	return true, nil
}
