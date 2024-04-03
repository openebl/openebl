package postgres

import (
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openebl/openebl/pkg/util"
)

type _Storage struct {
	dbPool *pgxpool.Pool
}
type _TxWrapper struct {
	tx pgx.Tx
}

type _RowWrapper struct {
	row pgx.Row
}

type _RowsWrapper struct {
	rows pgx.Rows
}

type _ResultWrapper struct {
	result pgconn.CommandTag
}

func NewStorageWithPool(dbPool *pgxpool.Pool) *_Storage {
	return &_Storage{
		dbPool: dbPool,
	}
}

func NewStorageWithConfig(config util.PostgresDatabaseConfig) (*_Storage, error) {
	dbPool, err := util.NewPostgresDBPool(config)
	if err != nil {
		return nil, err
	}

	return NewStorageWithPool(dbPool), nil
}
