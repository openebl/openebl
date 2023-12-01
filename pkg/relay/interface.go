package relay

import (
	"context"
	"io"
)

// Request is a request to the relay server.
type Request struct {
	Publish   *EventPublishRequest `json:"publish,omitempty"`
	Subscribe *SubscribeRequest    `json:"subscribe,omitempty"`
}

// EventPublishRequest is a request from the client to publish an event to the relay server.
type EventPublishRequest struct {
	RequestID string `json:"request_id,omitempty"`
	Type      int    `json:"type"`
	Data      []byte `json:"data"`
}

// SubscribeRequest is a request from the client to subscribe an event from the relay server.
type SubscribeRequest struct {
	SubscribeID string `json:"subscribe_id,omitempty"`
	Type        int    `json:"type"`
	Offset      int64  `json:"offset"`
}

// Response is a message from the relay server.
type Response struct {
	RelayServerIdentifyResponse *RelayServerIdentifyResponse `json:"identify_response,omitempty"`
	SubscribeResponse           *SubscribeResponse           `json:"subscribe_response,omitempty"`
	EventPublishResponse        *EventPublishResponse        `json:"publish_response,omitempty"`
	Notice                      *RelayServerNotice           `json:"notice,omitempty"`
}

type EventPublishResponse struct {
	// RequestID is the request ID of the EventPublishRequest.
	RequestID string `json:"request_id,omitempty"`
	OK        bool   `json:"ok"`
	EventID   string `json:"event_id"`
	Reason    string `json:"reason,omitempty"`
}

type Event struct {
	Timestamp int64
	Offset    int64
	Type      int
	Data      []byte
}

type SubscribeResponse struct {
	SubscribeID string `json:"subscribe_id,omitempty"`
	Event       *Event `json:"event,omitempty"`
	EOS         bool   `json:"eos"`
}

type RelayServerIdentifyResponse struct {
	Identity string `json:"identify"`
}

type RelayServerNotice struct {
	Message string `json:"message"`
}

type EventSink func(ctx context.Context, event Event) (string, error)

// ClientConnectionStatusCallback is a callback function that is called when the connection status of the client changes.
// The implementation note:
//  1. The callback function is called in a goroutine.
//  2. Use *cancelFunc* to notify the caller there is something wrong of the callback. The caller should handle it.
//  3. cancelFunc can be nil.
type ClientConnectionStatusCallback func(ctx context.Context, cancelFunc context.CancelCauseFunc, client RelayClient, serverIdentity string, status bool)

type RelayClient interface {
	io.Closer

	// Send sends a message to the relay server.
	Publish(ctx context.Context, evtType int, data []byte) error

	// Subscribe event.
	Subscribe(ctx context.Context, offset int64) error
}

type EventSourcePullingRequest struct {
	Offset int64
	Type   int
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
