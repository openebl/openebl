package storage

import (
	"context"
	"database/sql"

	"github.com/openebl/openebl/pkg/bu_server/model"
)

type StorageContextKey string

const (
	TRANSACTION StorageContextKey = "transaction"
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
	CreateTx(ctx context.Context, options ...CreateTxOption) (Tx, context.Context, error)
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

	// generate the status report by business unit.
	Report    bool
	RequestBy string
}

type ListTradeDocumentReport struct {
	ActionNeeded int `json:"action_needed"`
	Upcoming     int `json:"upcoming"`
	Sent         int `json:"sent"`
	Archive      int `json:"archive"`
}

type ListTradeDocumentResponse struct {
	Total  int
	Docs   []TradeDocument
	Report *ListTradeDocumentReport
}

type TradeDocumentStorage interface {
	CreateTx(ctx context.Context, options ...CreateTxOption) (Tx, context.Context, error)
	AddTradeDocument(ctx context.Context, tx Tx, tradeDoc TradeDocument) error
	ListTradeDocument(ctx context.Context, tx Tx, req ListTradeDocumentRequest) (ListTradeDocumentResponse, error)
}

type ListWebhookRequest struct {
	Offset int `json:"offset"` // Offset of the webhooks to be listed.
	Limit  int `json:"limit"`  // Limit of the webhooks to be listed.

	// Filters
	ApplicationID string   `json:"application_id"` // The ID of the application this webhook belongs to.
	IDs           []string `json:"ids"`            // The IDs of the webhook.
	Events        []string `json:"events"`         // The Events the webhook is interested in.
}

type ListWebhookResult struct {
	Total   int             `json:"total"`   // Total number of webhooks.
	Records []model.Webhook `json:"records"` // Records of webhook.
}

type OutboxMsg struct {
	RecID int64
	Key   string
	Msg   []byte
}

type WebhookStorage interface {
	CreateTx(ctx context.Context, options ...CreateTxOption) (Tx, context.Context, error)
	AddWebhook(ctx context.Context, tx Tx, webhook model.Webhook) error
	ListWebhook(ctx context.Context, tx Tx, req ListWebhookRequest) (ListWebhookResult, error)
	AddWebhookEvent(ctx context.Context, tx Tx, ts int64, key string, event *model.WebhookEvent) error
	GetWebhookEvent(ctx context.Context, tx Tx, batchSize int) ([]OutboxMsg, error)
	DeleteWebhookEvent(ctx context.Context, tx Tx, recIDs ...int64) error
}
