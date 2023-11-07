package relay_test

import (
	"testing"

	"github.com/openebl/openebl/pkg/relay"
)

func TestNostrRelayServer(t *testing.T) {
	srv := relay.NewNostrServer(
		relay.NostrServerAddress("localhost:8080"),
	)

	err := srv.ListenAndServe()
	if err != nil {
		t.Fatal(err)
	}
}
