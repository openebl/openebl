package relay

import (
	"context"
	"io"
)

type Event struct {
	Offset int64
	Type   int
	Data   []byte
}

type EventSink func(ctx context.Context, event Event) error

type RelayClient interface {
	io.Closer

	// Send sends a message to the relay server.
	Publish(ctx context.Context, evtType int, data []byte) error

	// Subscribe event.
	Subscribe(ctx context.Context, offset int64, sink EventSink) error
}

type EventSource func(ctx context.Context, offset int64) (Event, error)
