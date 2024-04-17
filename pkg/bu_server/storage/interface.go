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

type CreateTxOption func(*sql.TxOptions)

type TransactionInterface interface {
	CreateTx(ctx context.Context, options ...CreateTxOption) (Tx, context.Context, error)
}

func TxOptionWithWrite(write bool) CreateTxOption {
	return func(option *sql.TxOptions) {
		option.ReadOnly = !write
	}
}

func TxOptionWithIsolationLevel(level sql.IsolationLevel) CreateTxOption {
	return func(option *sql.TxOptions) {
		option.Isolation = level
	}
}

// ListBusinessUnitsRequest is the request to list business units.
type ListBusinessUnitsRequest struct {
	Offset int `json:"offset"` // Offset of the business units to be listed.
	Limit  int `json:"limit"`  // Limit of the business units to be listed.

	// Filters
	ApplicationID   string   `json:"application_id"`    // The ID of the application this BusinessUnit belongs to.
	BusinessUnitIDs []string `json:"business_unit_ids"` // The IDs of the business units.
}

// ListBusinessUnitsResult is the result of listing business units.
type ListBusinessUnitsResult struct {
	Total   int                       `json:"total"`   // Total number of business units.
	Records []ListBusinessUnitsRecord `json:"records"` // Records of business units.
}

// ListAuthenticationRequest is the request to list authentications.
type ListAuthenticationRequest struct {
	Offset int `json:"offset"` // Offset of the authentications to be listed.
	Limit  int `json:"limit"`  // Limit of the authentications to be listed.

	// Filters
	ApplicationID     string   `json:"application_id"`     // The ID of the application this BusinessUnit belongs to.
	BusinessUnitID    string   `json:"id"`                 // Unique DID of a BusinessUnit.
	AuthenticationIDs []string `json:"authentication_ids"` // Unique IDs of the authentications.
}

// ListAuthenticationResult is the result of listing authentications.
type ListAuthenticationResult struct {
	Total   int                                `json:"total"`   // Total number of authentications.
	Records []model.BusinessUnitAuthentication `json:"records"` // Records of authentications.
}

// ListBusinessUnitsRecord is the record of a business unit.
type ListBusinessUnitsRecord struct {
	BusinessUnit    model.BusinessUnit                 `json:"business_unit"`   // The business unit.
	Authentications []model.BusinessUnitAuthentication `json:"authentications"` // The authentications of the business unit.
}

type BusinessUnitStorage interface {
	CreateTx(ctx context.Context, options ...CreateTxOption) (Tx, context.Context, error)
	StoreBusinessUnit(ctx context.Context, tx Tx, bu model.BusinessUnit) error
	ListBusinessUnits(ctx context.Context, tx Tx, req ListBusinessUnitsRequest) (ListBusinessUnitsResult, error)
	StoreAuthentication(ctx context.Context, tx Tx, auth model.BusinessUnitAuthentication) error
	ListAuthentication(ctx context.Context, tx Tx, req ListAuthenticationRequest) (ListAuthenticationResult, error)
}

type TradeDocument struct {
	RawID        string         // The Raw ID of the envelope of the document.
	Kind         int            // The kind of the document. It provides the hint of how to process the document.
	DocID        string         // The ID of the trade document.
	DocVersion   int64          // The version of the trade document.
	DocReference string         // The reference identifier(e.g., bl_number) of the trade document.
	Doc          []byte         // The trade document to be stored.
	DecryptedDoc []byte         // The decrypted trade document to be stored.
	CreatedAt    int64          // When the trade document is created.
	Meta         map[string]any // Indexing Data for search or list operations.
}

type ListTradeDocumentRequest struct {
	Offset int
	Limit  int

	// The filter of the trade document.
	Kinds        []int
	DocReference string
	From         string
	DocIDs       []string
	Meta         map[string]any

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
	AddTradeDocumentOutbox(ctx context.Context, tx Tx, ts int64, key string, kind int, payload []byte) error
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
	Kind  int
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

type OffsetStorage interface {
	CreateTx(ctx context.Context, options ...CreateTxOption) (Tx, context.Context, error)
	GetRelayServerOffset(ctx context.Context, tx Tx, serverID string) (int64, error)
	UpdateRelayServerOffset(ctx context.Context, tx Tx, serverID string, offset int64) error
}

type TradeDocumentInboxStorage interface {
	CreateTx(ctx context.Context, options ...CreateTxOption) (Tx, context.Context, error)
	ListAuthentication(ctx context.Context, tx Tx, req ListAuthenticationRequest) (ListAuthenticationResult, error)
	AddTradeDocument(ctx context.Context, tx Tx, tradeDoc TradeDocument) error
	GetRelayServerOffset(ctx context.Context, tx Tx, serverID string) (int64, error)
	UpdateRelayServerOffset(ctx context.Context, tx Tx, serverID string, offset int64) error
}

type TradeDocumentOutboxStorage interface {
	CreateTx(ctx context.Context, options ...CreateTxOption) (Tx, context.Context, error)
	AddTradeDocumentOutbox(ctx context.Context, tx Tx, ts int64, key string, kind int, payload []byte) error
	GetTradeDocumentOutbox(ctx context.Context, tx Tx, batchSize int) ([]OutboxMsg, error)
	DeleteTradeDocumentOutbox(ctx context.Context, tx Tx, recIDs ...int64) error
}
