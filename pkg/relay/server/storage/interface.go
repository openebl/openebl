package storage

import "context"

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
	// StoreEvent returns the offset of the event in the storage.
	StoreEvent(ctx context.Context, ts int64, eventID string, eventType int, event []byte) (int64, error)

	// ListEvents returns a list of events from the storage.
	ListEvents(ctx context.Context, request ListEventRequest) (ListEventResult, error)

	// StoreOffset stores the offset of the peer.
	StoreOffset(ctx context.Context, ts int64, peerAddress string, offset int64) error

	// GetOffset returns the offset of the peer.
	GetOffset(ctx context.Context, peerAddress string) (int64, error)
}
