package storage

import (
	"context"
	"database/sql"
)

type TxWrapperOption struct {
	write bool
	level sql.IsolationLevel
}

type TxWrapper interface {
	Commit() error
	Rollback() error
	GetTx() *sql.Tx
}

type CreateTxOption func(*TxWrapperOption)

type TransactionInterface interface {
	CreateTx(ctx context.Context, options ...CreateTxOption) (TxWrapper, error)
}

func TxOptionWithWrite(write bool) CreateTxOption {
	return func(option *TxWrapperOption) {
		option.write = write
	}
}

func TxOptionWithIsolationLevel(level sql.IsolationLevel) CreateTxOption {
	return func(option *TxWrapperOption) {
		option.level = level
	}
}
