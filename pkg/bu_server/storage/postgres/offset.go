package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/openebl/openebl/pkg/bu_server/storage"
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
