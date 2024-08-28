package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// _Storage implements RelayServerDataStore interface.
type _Storage struct {
	dbPool *pgxpool.Pool
}

func (s *_Storage) CreateTX(ctx context.Context, readOnly bool) (pgx.Tx, error) {
	var txOption pgx.TxOptions

	if readOnly {
		txOption = pgx.TxOptions{
			AccessMode: pgx.ReadOnly,
		}
	} else {
		txOption = pgx.TxOptions{
			IsoLevel:   pgx.Serializable,
			AccessMode: pgx.ReadWrite,
		}
	}

	tx, err := s.dbPool.BeginTx(ctx, txOption)
	if err != nil {
		return nil, err
	}
	return tx, nil
}
