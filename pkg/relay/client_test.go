package relay_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/openebl/openebl/pkg/relay"
)

func clientEventSink(ctx context.Context, event relay.Event) (string, error) {
	fmt.Printf("%s\n", string(event.Data))
	return "", nil
}

func TestNostrRelayClient(t *testing.T) {
	t.Skip("skip test")
	clientConnectionStatusCallback := func(ctx context.Context, client relay.RelayClient, serverIdentity string, status bool) {
		fmt.Printf("connection status: %v\n", status)
		if client != nil && status {
			err := client.Subscribe(context.Background(), 0)
			if err != nil {
				t.Fatal(err)
			} else {
				fmt.Printf("subscribed\n")
			}
		}
	}

	client := relay.NewNostrClient(
		relay.NostrClientWithServerURL("ws://localhost:8080"),
		relay.NostrClientWithEventSink(clientEventSink),
		relay.NostrClientWithConnectionStatusCallback(clientConnectionStatusCallback),
	)

	var count int64
	for {
		time.Sleep(1 * time.Second)
		msg := fmt.Sprintf("hello %d", count)
		count++
		client.Publish(context.Background(), 1001, []byte(msg))
	}
}
