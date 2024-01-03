package postgres

import (
	"context"
	"database/sql"

	"github.com/jackc/pgx/v5"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/sirupsen/logrus"
)

func (tx *_TxWrapper) Commit(ctx context.Context) error {
	return tx.tx.Commit(ctx)
}

func (tx *_TxWrapper) Rollback(ctx context.Context) error {
	return tx.tx.Rollback(ctx)
}

func (tx *_TxWrapper) Exec(ctx context.Context, sql string, args ...any) (storage.Result, error) {
	result, err := tx.tx.Exec(ctx, sql, args...)
	if err != nil {
		logrus.Errorf("Fail to exec. %v", err)
		return nil, err
	}
	return &_ResultWrapper{result}, nil
}

func (tx *_TxWrapper) Query(ctx context.Context, sql string, args ...any) (storage.Rows, error) {
	rows, err := tx.tx.Query(ctx, sql, args...)
	if err != nil {
		logrus.Errorf("Fail to query. %v", err)
		return nil, err
	}
	return &_RowsWrapper{rows}, nil
}

func (tx *_TxWrapper) QueryRow(ctx context.Context, sql string, args ...any) storage.Row {
	row := tx.tx.QueryRow(ctx, sql, args...)
	return &_RowWrapper{row}
}

func (r *_ResultWrapper) RowsAffected() (int64, error) {
	return r.result.RowsAffected(), nil
}

func (r *_RowsWrapper) Close() {
	r.rows.Close()
}

func (r *_RowsWrapper) Err() error {
	return r.rows.Err()
}

func (r *_RowsWrapper) Next() bool {
	return r.rows.Next()
}

func (r *_RowsWrapper) Scan(dest ...any) error {
	return r.rows.Scan(dest...)
}

func (r *_RowWrapper) Scan(dest ...any) error {
	return r.row.Scan(dest...)
}

func (p *_Storage) CreateTx(ctx context.Context, options ...storage.CreateTxOption) (storage.Tx, error) {
	option := storage.TxWrapperOption{}
	for _, opt := range options {
		opt(&option)
	}

	connPool := p.dbPool
	sqlTxOption := sql.TxOptions{}
	for _, opt := range options {
		opt(&option)
	}

	txOption := pgx.TxOptions{}
	if sqlTxOption.ReadOnly {
		txOption.AccessMode = pgx.ReadOnly
	} else {
		txOption.AccessMode = pgx.ReadWrite
	}
	switch sqlTxOption.Isolation {
	case sql.LevelDefault:
		txOption.IsoLevel = pgx.ReadCommitted
	case sql.LevelReadUncommitted:
		txOption.IsoLevel = pgx.ReadUncommitted
	case sql.LevelReadCommitted:
		txOption.IsoLevel = pgx.ReadCommitted
	case sql.LevelRepeatableRead:
		txOption.IsoLevel = pgx.RepeatableRead
	case sql.LevelSerializable:
		txOption.IsoLevel = pgx.Serializable
	case sql.LevelLinearizable:
		txOption.IsoLevel = pgx.Serializable
	default:
		txOption.IsoLevel = pgx.ReadCommitted
	}

	tx, err := connPool.BeginTx(ctx, txOption)
	if err != nil {
		logrus.Errorf("Fail to create transaction. %v", err)
		return nil, err
	}
	return &_TxWrapper{tx}, nil
}
