package postgres

import (
	"context"
	"fmt"
	"net/url"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openebl/openebl/pkg/relay/server/storage"
)

type DatabaseConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	Database string `yaml:"database"`
	SSLMode  string `yaml:"sslmode"`
	PoolSize int    `yaml:"pool"`
}

func NewDBPool(config DatabaseConfig) (*pgxpool.Pool, error) {
	connString := fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s&pool_max_conns=%d",
		url.PathEscape(config.User),
		url.PathEscape(config.Password),
		url.PathEscape(config.Host),
		config.Port,
		url.PathEscape(config.Database),
		url.QueryEscape(config.SSLMode),
		config.PoolSize,
	)

	dbPool, err := pgxpool.New(
		context.Background(),
		connString,
	)

	if err != nil {
		return nil, fmt.Errorf("open connection to database: %w", err)
	}

	err = dbPool.Ping(context.Background())
	if err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return dbPool, nil
}

// EventStorage implements RelayServerDataStore interface.
type EventStorage struct {
	dbPool *pgxpool.Pool
}

func NewEventStorage(dbPool *pgxpool.Pool) *EventStorage {
	return &EventStorage{
		dbPool: dbPool,
	}
}

func (s *EventStorage) GetIdentity(ctx context.Context) (string, error) {
	txOption := pgx.TxOptions{
		AccessMode: pgx.ReadOnly,
	}
	tx, err := s.dbPool.BeginTx(ctx, txOption)
	if err != nil {
		return "", fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	query := `SELECT id FROM storage_identify`
	row := tx.QueryRow(ctx, query)
	var id string
	if err := row.Scan(&id); err != nil {
		return "", fmt.Errorf("scan: %w", err)
	}

	return id, nil
}

func (s *EventStorage) StoreEventWithOffsetInfo(
	ctx context.Context,
	ts int64,
	eventID string,
	eventType int,
	event []byte,
	offset int64,
	peerId string,
) (int64, error) {
	txOption := pgx.TxOptions{
		IsoLevel:   pgx.Serializable,
		AccessMode: pgx.ReadWrite,
	}
	tx, err := s.dbPool.BeginTx(ctx, txOption)
	if err != nil {
		return 0, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Store Offset information when it's available
	if peerId != "" {
		if err := s.storeOffset(ctx, tx, ts, peerId, offset); err != nil {
			return 0, err
		}
	}

	// Check if the event is already stored
	query := `SELECT id FROM "event" WHERE id = $1`
	row := tx.QueryRow(ctx, query, eventID)
	var oldID string
	err = row.Scan(&oldID)
	if err != nil && err != pgx.ErrNoRows {
		return 0, fmt.Errorf("scan for old event ID: %w", err)
	} else if err == nil {
		err = storage.ErrDuplicateEvent
	} else if err == pgx.ErrNoRows {
		err = nil
	}

	if peerId != "" && err == storage.ErrDuplicateEvent {
		// Commit the transaction if the offset is already stored.
		if err := tx.Commit(ctx); err != nil {
			return 0, fmt.Errorf("commit transaction: %w", err)
		}
		return 0, err
	}
	if err != nil {
		return 0, err
	}

	// Store Event
	var newOffset int64
	query = `INSERT INTO "event" (id, "type", created_at, "event") VALUES ($1, $2, $3, $4) RETURNING "offset"`
	row = tx.QueryRow(ctx, query, eventID, eventType, ts, event)
	if err := row.Scan(&newOffset); err != nil {
		return 0, fmt.Errorf("scan offset: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit transaction: %w", err)
	}

	return newOffset, nil
}

func (s *EventStorage) ListEvents(ctx context.Context, request storage.ListEventRequest) (storage.ListEventResult, error) {
	txOption := pgx.TxOptions{
		AccessMode: pgx.ReadOnly,
	}
	tx, err := s.dbPool.BeginTx(ctx, txOption)
	if err != nil {
		return storage.ListEventResult{}, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	query := `
	SELECT 
		id,
		created_at,
		"offset",
		"type",
		"event"
	FROM "event"
	WHERE
		($2 = 0 OR "offset" >= $2) AND
		($3 = 0 OR "type" = $3)
	ORDER BY "offset" ASC
	LIMIT $1`

	rows, err := tx.Query(ctx, query, request.Limit, request.Offset, request.EventType)
	if err != nil {
		return storage.ListEventResult{}, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	var result storage.ListEventResult
	for rows.Next() {
		event := storage.Event{}
		if err := rows.Scan(
			&event.ID,
			&event.Timestamp,
			&event.Offset,
			&event.Type,
			&event.Data,
		); err != nil {
			return storage.ListEventResult{}, fmt.Errorf("scan: %w", err)
		}
		result.Events = append(result.Events, event)
		if result.MaxOffset < event.Offset {
			result.MaxOffset = event.Offset
		}
	}

	if err := rows.Err(); err != nil {
		return storage.ListEventResult{}, fmt.Errorf("rows: %w", err)
	}

	return result, nil
}

func (s *EventStorage) StoreOffset(ctx context.Context, ts int64, peerAddress string, offset int64) error {
	txOption := pgx.TxOptions{
		IsoLevel:   pgx.Serializable,
		AccessMode: pgx.ReadWrite,
	}
	tx, err := s.dbPool.BeginTx(ctx, txOption)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	if err := s.storeOffset(ctx, tx, ts, peerAddress, offset); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

func (s *EventStorage) storeOffset(ctx context.Context, tx pgx.Tx, ts int64, peerAddress string, offset int64) error {
	query := `
	INSERT INTO "offset" (peer, "offset", created_at, updated_at) VALUES(
		$1,
		$2,
		$3,
		$3
	) ON CONFLICT (peer)
	DO UPDATE
	SET 
		"offset" = excluded."offset",
		updated_at = excluded.updated_at`

	if _, err := tx.Exec(ctx, query, peerAddress, offset, ts); err != nil {
		return fmt.Errorf("exec: %w", err)
	}

	return nil
}

func (s *EventStorage) GetOffset(ctx context.Context, peerAddress string) (int64, error) {
	txOption := pgx.TxOptions{
		AccessMode: pgx.ReadOnly,
	}
	tx, err := s.dbPool.BeginTx(ctx, txOption)
	if err != nil {
		return 0, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	query := `SELECT "offset" FROM "offset" WHERE peer = $1`
	row := tx.QueryRow(ctx, query, peerAddress)
	var offset int64
	if err := row.Scan(&offset); err != nil && err != pgx.ErrNoRows {
		return 0, fmt.Errorf("scan: %w", err)
	}

	return offset, nil
}

func (s *EventStorage) Close() error {
	s.dbPool.Close()
	return nil
}
