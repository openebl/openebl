package storage

import (
	"context"
	"errors"
)

var ErrDuplicateEvent = errors.New("duplicate event")

type ListEventRequest struct {
	Offset    int64
	EventType int
	Limit     int64
}

type ListEventResult struct {
	Events    []Event
	MaxOffset int64
}

type Event struct {
	ID        string
	Timestamp int64
	Offset    int64
	Type      int
	Data      []byte
}

type RelayServerDataStore interface {
	// GetIdentity returns the identity of the data storage.
	GetIdentity(ctx context.Context) (string, error)

	// StoreEventWithOffsetInfo returns the offset of the event in the storage.
	// If peerId is empty, the offset will be ignored.
	StoreEventWithOffsetInfo(
		ctx context.Context,
		ts int64,
		eventID string,
		eventType int,
		event []byte,
		offset int64,
		peerId string,
	) (int64, error)

	// ListEvents returns a list of events from the storage.
	ListEvents(ctx context.Context, request ListEventRequest) (ListEventResult, error)

	// StoreOffset stores the offset of the peer.
	StoreOffset(ctx context.Context, ts int64, peerId string, offset int64) error

	// GetOffset returns the offset of the peer.
	GetOffset(ctx context.Context, peerId string) (int64, error)
}

type IssuerKeyAndCertSerialNumber struct {
	IssuerKeyID       string `json:"issuer_key_id"`
	CertificateSerial string `json:"cert_serial_number"`
}
type GetCRLRequest struct {
	RevokedAt                      int64                          // The time when the certificate is revoked. Only CRLs that are revoked before this time will be retrieved.
	IssuerKeysAndCertSerialNumbers []IssuerKeyAndCertSerialNumber // The issuer key ID and certificate serial number of the CRLs to be retrieved.
}

type GetCRLResult struct {
	CRLs map[IssuerKeyAndCertSerialNumber][]byte
}

type CertDataStore interface {
	AddRootCert(ctx context.Context, ts int64, fingerPrint string, cert []byte) error
	RevokeRootCert(ctx context.Context, ts int64, fingerPrinter string) error
	GetActiveRootCert(ctx context.Context) ([][]byte, error)
	AddCRL(ctx context.Context, ts int64, issuerKeyID string, certSerialNumber string, revokedAt int64, crl []byte) error
	GetCRL(ctx context.Context, req GetCRLRequest) (GetCRLResult, error)
}
