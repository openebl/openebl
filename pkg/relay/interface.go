package relay

import (
	"context"
	"io"
)

type Event struct {
	Timestamp int64
	Offset    int64
	Type      int
	Data      []byte
}

type EventSink func(ctx context.Context, event Event) error
type ClientConnectionStatusCallback func(ctx context.Context, client RelayClient, status bool)

type RelayClient interface {
	io.Closer

	// Send sends a message to the relay server.
	Publish(ctx context.Context, evtType int, msgID string, data []byte) error

	// Subscribe event.
	Subscribe(ctx context.Context, offset int64) error
}

type EventSourcePullingRequest struct {
	Offset *int64
	Length int
}
type EventSourcePullingResponse struct {
	Events    []Event
	MaxOffset int64
}
type EventSource func(ctx context.Context, request EventSourcePullingRequest) (EventSourcePullingResponse, error)

type RelayServer interface {
	io.Closer
	ListenAndServe() error
}
