package broker

import (
	"crypto/tls"
	"time"

	"github.com/openebl/openebl/pkg/bu_server/business_unit"
	"github.com/openebl/openebl/pkg/bu_server/cert"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/relay"
)

type OptionFunc func(broker *Broker)

// WithTLSConfig sets the TLS config for the broker
func WithTLSConfig(tlsConfig *tls.Config) OptionFunc {
	return func(b *Broker) {
		b.tlsConfig = tlsConfig
	}
}

// WithRelayClient sets the relay client for the broker
func WithRelayClient(client relay.RelayClient) OptionFunc {
	return func(b *Broker) {
		b.client = client
	}
}

// WithRelayServer sets the relay server URL for the broker
func WithRelayServer(server string) OptionFunc {
	return func(b *Broker) {
		b.relayServer = server
	}
}

// WithOutboxStore sets the outbox storage for the broker
func WithOutboxStore(store storage.TradeDocumentOutboxStorage) OptionFunc {
	return func(b *Broker) {
		b.outboxStore = store
	}
}

// WithInboxStore sets the inbox storage for the broker
func WithInboxStore(store storage.TradeDocumentInboxStorage) OptionFunc {
	return func(b *Broker) {
		b.inboxStore = store
	}
}

// WithClientID sets the client ID for the broker
func WithClientID(clientID string) OptionFunc {
	return func(b *Broker) {
		b.clientID = clientID
	}
}

// WithCheckInterval sets the check interval for the broker
func WithCheckInterval(interval int) OptionFunc {
	return func(b *Broker) {
		b.checkInterval = time.Duration(interval) * time.Second
	}
}

// WithBatchSize sets the batch size for the broker
func WithBatchSize(size int) OptionFunc {
	return func(b *Broker) {
		b.batchSize = size
	}
}

func WithBUManager(ctrl business_unit.BusinessUnitManager) OptionFunc {
	return func(b *Broker) {
		b.buMgr = ctrl
	}
}

func WithCertManager(ctrl cert.CertManager) OptionFunc {
	return func(b *Broker) {
		b.certMgr = ctrl
	}
}
