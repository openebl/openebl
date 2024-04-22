package storage

import (
	"context"
	"database/sql"

	"github.com/openebl/openebl/pkg/cert_server/model"
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

type CertStorage interface {
	CreateTx(ctx context.Context, options ...CreateTxOption) (Tx, context.Context, error)

	AddCertificate(ctx context.Context, tx Tx, cert model.Cert) error
	ListCertificates(ctx context.Context, tx Tx, req ListCertificatesRequest) (ListCertificatesResponse, error)

	AddCertificateRevocationList(ctx context.Context, tx Tx, crl model.CertRevocationList) error

	// CertificateOutbox functions.
	// GetCertificateOutboxMsg and DeleteCertificateOutboxMsg relies on "SELECT FOR UPDATE" query, so it should be called inside a transaction.
	// The transaction isolation level MUST NOT be sql.LevelSerializable, or the query will fail.
	// AddCertificateOutboxMsg doesn't have the isolation level limitation.
	AddCertificateOutboxMsg(ctx context.Context, tx Tx, ts int64, key string, kind int, payload []byte) error
	GetCertificateOutboxMsg(ctx context.Context, tx Tx, batchSize int) ([]CertificateOutboxMsg, error)
	DeleteCertificateOutboxMsg(ctx context.Context, tx Tx, recIDs ...int64) error
}

type ListCertificatesRequest struct {
	Offset int `json:"offset"` // Offset of the list.
	Limit  int `json:"limit"`  // Limit of the list.

	// Filter by type of the certificate.
	IDs          []string           `json:"ids"`            // List of IDs of the certificates to be listed.
	Statuses     []model.CertStatus `json:"statuses"`       // List of statuses of the certificates to be listed.
	Types        []model.CertType   `json:"types"`          // List of types of the certificates to be listed.
	PublicKeyIDs []string           `json:"public_key_ids"` // List of public key IDs of the certificates to be listed.
}

type ListCertificatesResponse struct {
	Total int64        `json:"total"` // Total number of certificates.
	Certs []model.Cert `json:"certs"` // List of certificates.
}

type CertificateOutboxMsg struct {
	RecID int64
	Key   string
	Kind  int
	Msg   []byte
}
