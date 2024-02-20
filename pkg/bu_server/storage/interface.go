package storage

import (
	"context"
	"database/sql"
)

type TxWrapperOption struct {
	write bool
	level sql.IsolationLevel
}

type Tx interface {
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
	Exec(ctx context.Context, sql string, arguments ...any) (Result, error)
	Query(ctx context.Context, sql string, args ...any) (Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) Row
}

type Rows interface {
	Close()
	Err() error
	Next() bool
	Scan(dest ...any) error
}

type Row interface {
	Scan(dest ...any) error
}

type Result interface {
	// RowsAffected returns the number of rows affected by an
	// update, insert, or delete. Not every database or database
	// driver may support this.
	RowsAffected() (int64, error)
}

type CreateTxOption func(*TxWrapperOption)

type TransactionInterface interface {
	CreateTx(ctx context.Context, options ...CreateTxOption) (Tx, error)
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

type TradeDocument struct {
	RawID      string         // The Raw ID of the envelope of the document.
	Kind       int            // The kind of the document. It provides the hint of how to process the document.
	DocID      string         // The ID of the trade document.
	DocVersion int64          // The version of the trade document.
	Doc        []byte         // The trade document to be stored.
	CreatedAt  int64          // When the trade document is created.
	Meta       map[string]any // Indexing Data for search or list operations.
}
type ListTradeDocumentRequest struct {
	Offset int
	Limit  int

	// The filter of the trade document.
	Kind   int
	DocIDs []string
	Meta   map[string]any
}
type ListTradeDocumentResponse struct {
	Total int
	Docs  []TradeDocument
}
type TradeDocumentStorage interface {
	CreateTx(ctx context.Context, options ...CreateTxOption) (Tx, error)
	AddTradeDocument(ctx context.Context, tx Tx, tradeDoc TradeDocument) error
	ListTradeDocument(ctx context.Context, tx Tx, req ListTradeDocumentRequest) (ListTradeDocumentResponse, error)
}
