package broker

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	otlp_util "github.com/bluexlab/otlp-util-go"
	"github.com/openebl/openebl/pkg/bu_server/business_unit"
	"github.com/openebl/openebl/pkg/bu_server/cert"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/model/trade_document/bill_of_lading"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/bu_server/trade_document"
	"github.com/openebl/openebl/pkg/envelope"
	"github.com/openebl/openebl/pkg/pkix"
	"github.com/openebl/openebl/pkg/relay"
	"github.com/openebl/openebl/pkg/relay/server"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Broker represents the broker instance
type Broker struct {
	tlsConfig             *tls.Config
	relayServer           string
	relayServerID         string
	client                relay.RelayClient
	clientID              string
	checkInterval         time.Duration
	batchSize             int
	outboxStore           storage.TradeDocumentOutboxStorage
	inboxStore            storage.TradeDocumentInboxStorage
	buMgr                 business_unit.BusinessUnitManager
	certMgr               cert.CertManager
	rootCertCheckInterval time.Duration
	done                  chan struct{}
	closed                bool
	closeErr              error
	mu                    sync.Mutex
	receivedCount         metric.Int64Counter
	sentCount             metric.Int64Counter
}

func NewBroker(opts ...OptionFunc) (*Broker, error) {
	s := &Broker{
		checkInterval:         30 * time.Second, // Default check interval
		batchSize:             10,               // Default batch size
		rootCertCheckInterval: time.Hour,        // Default root cert check interval
		done:                  make(chan struct{}),
		receivedCount:         otlp_util.NewInt64Counter("broker.received.count", metric.WithDescription("Number of received messages")),
		sentCount:             otlp_util.NewInt64Counter("broker.sent.count", metric.WithDescription("Number of sent messages")),
	}
	for _, opt := range opts {
		opt(s)
	}

	return s, nil
}

// Run starts the broker
func (b *Broker) Run(ctx context.Context) error {
	if b.client == nil {
		client := relay.NewNostrClient(
			relay.NostrClientWithServerURL(b.relayServer),
			relay.NostrClientWithEventSink(b.eventSink),
			relay.NostrClientWithConnectionStatusCallback(b.connectionStatusCallback),
			relay.NostrClientWithTLSConfig(b.tlsConfig),
		)
		b.client = client
	}

	go b.syncRootCerts(ctx)
	go b.tradeDocumentOutboxWorker(ctx)

	select {
	case <-ctx.Done():
		return nil
	case <-b.done:
		return b.closeErr
	}
}

// Close closes the broker
func (b *Broker) Close(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}

	b.closed = true
	close(b.done)

	return nil
}

func (b *Broker) closeWithError(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return
	}

	b.closeErr = err
	b.closed = true
	close(b.done)
}

func (b *Broker) eventSink(ctx context.Context, event relay.Event) (string, error) {
	log := logrus.WithFields(logrus.Fields{"timestamp": event.Timestamp, "offset": event.Offset, "type": event.Type})
	log.Debugf("Received event")

	if len(event.Data) == 0 {
		log.Warn("Empty event data")
		return "", nil
	}

	ts := time.Now().Unix()
	rawID := server.GetEventID(event.Data)
	tx, ctx, err := b.inboxStore.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		log.Warnf("Failed to create transaction: %v", err)
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	storeTradeDocument := func(ctx context.Context, td storage.TradeDocument) error {
		tx, ctx, err := b.inboxStore.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
		if err != nil {
			return fmt.Errorf("failed to create transaction: %w", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()

		if err := b.inboxStore.AddTradeDocument(ctx, tx, td); err != nil {
			return fmt.Errorf("failed to store trade document: %w", err)
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("failed to commit transaction: %w", err)
		}
		return nil
	}

	storeCertificate := func(ctx context.Context, certRaw []byte) error {
		_, err := b.buMgr.ActivateAuthentication(ctx, ts, certRaw)
		if errors.Is(err, model.ErrAuthenticationNotFound) {
			return nil
		}
		if errors.Is(err, model.ErrInvalidParameter) || errors.Is(err, model.ErrAuthenticationNotPending) {
			logrus.Warnf("Failed to activate authentication: %v", err)
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to activate authentication: %w", err)
		}
		return nil
	}

	storeCertificateRevocation := func(ctx context.Context, crl []byte) error {
		err := b.certMgr.AddCRL(ctx, crl)
		if errors.Is(err, model.ErrInvalidParameter) {
			logrus.Warnf("Failed to add CRL: %v", err)
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to add CRL: %w", err)
		}
		return nil
	}
	deDuplicateEvent := func(ctx context.Context, serverID string) (bool, error) {
		isNew, err := b.inboxStore.StoreEvent(ctx, tx, ts, rawID, event, serverID)
		if err != nil {
			return false, err
		}
		return isNew, err
	}
	processEvent := func(ctx context.Context, event relay.Event) error {
		switch relay.EventType(event.Type) {
		case relay.FileBasedBillOfLading:
			td, err := tradeDocumentFromEvent(event.Data)
			if err != nil {
				log.Warnf("Failed to parse trade document: %v", err)
				return nil
			}
			if err := storeTradeDocument(ctx, td); err != nil {
				return fmt.Errorf("failed to store trade document: %w", err)
			}
		case relay.EncryptedFileBasedBillOfLading:
			td, err := b.decryptTradeDocument(ctx, event.Data)
			if err != nil {
				log.Warnf("Failed to decrypt trade document: %v", err)
				return nil
			}
			td.RawID = rawID
			td.Kind = int(relay.EncryptedFileBasedBillOfLading)
			td.DecryptedDoc, td.Doc = td.Doc, event.Data
			if err := storeTradeDocument(ctx, td); err != nil {
				return fmt.Errorf("failed to store trade document: %w", err)
			}
		case relay.X509Certificate:
			if err := storeCertificate(ctx, event.Data); err != nil {
				return fmt.Errorf("failed to store certificate: %w", err)
			}
		case relay.X509CertificateRevocationList:
			if err := storeCertificateRevocation(ctx, event.Data); err != nil {
				return fmt.Errorf("failed to store certificate revocation: %w", err)
			}
		case relay.BusinessUnit:
			jwsEvent, err := jwsFromEvent(event.Data)
			if err != nil {
				return err
			}
			if err := b.buMgr.UpdateBusinessUnitByExternalEvent(ctx, ts, jwsEvent); errors.Is(err, model.ErrInvalidParameter) {
				logrus.Warnf("Failed to update business unit: %v", err)
				return nil
			} else if err != nil {
				return fmt.Errorf("failed to store business unit: %w", err)
			}
		case relay.BusinessUnitAuthentication:
			jwsEvent, err := jwsFromEvent(event.Data)
			if err != nil {
				return err
			}
			if err := b.buMgr.UpdateAuthenticationByExternalEvent(ctx, ts, jwsEvent); errors.Is(err, model.ErrInvalidParameter) {
				logrus.Warnf("Failed to update business unit authentication: %v", err)
				return nil
			} else if err != nil {
				return fmt.Errorf("failed to store business unit authentication: %w", err)
			}
		default:
			log.Debugf("Unwanted event type: %d", event.Type)
		}
		return nil
	}

	b.receivedCount.Add(ctx, 1, metric.WithAttributes(attribute.Int("kind", event.Type)))

	if isNew, err := deDuplicateEvent(ctx, b.relayServerID); err != nil {
		log.Warnf("Failed to store event: %v", err)
		return "", err
	} else if !isNew {
		log.Debugf("Event already exists")
		if err := tx.Commit(ctx); err != nil {
			log.Warnf("Failed to commit transaction: %v", err)
		}
		return "", nil
	}

	if err := processEvent(ctx, event); err != nil {
		log.Warnf("Failed to process event: %v", err)
		return "", err
	}

	if err := tx.Commit(ctx); err != nil {
		log.Warnf("Failed to commit transaction: %v", err)
	}
	return "", nil
}

func tradeDocumentFromEvent(data []byte) (storage.TradeDocument, error) {
	doc, err := jwsFromEvent(data)
	if err != nil {
		return storage.TradeDocument{}, err
	}
	if err := doc.VerifySignature(); err != nil {
		return storage.TradeDocument{}, fmt.Errorf("failed to verify signature: %w", err)
	}
	rawPack, err := doc.GetPayload()
	if err != nil {
		return storage.TradeDocument{}, fmt.Errorf("failed to get payload: %w", err)
	}

	blPack := bill_of_lading.BillOfLadingPack{}
	err = json.Unmarshal(rawPack, &blPack)
	if err != nil {
		return storage.TradeDocument{}, fmt.Errorf("failed to unmarshal BL pack: %w", err)
	}
	meta, err := trade_document.GetBillOfLadingPackMeta(&blPack)
	if err != nil {
		return storage.TradeDocument{}, fmt.Errorf("failed to get BL pack meta: %w", err)
	}

	ts := time.Now().Unix()
	td := storage.TradeDocument{
		RawID:        server.GetEventID(data),
		Kind:         int(relay.FileBasedBillOfLading),
		DocID:        blPack.ID,
		DocVersion:   blPack.Version,
		DocReference: "",
		Doc:          data,
		CreatedAt:    ts,
		Meta:         meta,
	}
	if mbl := trade_document.GetLastBillOfLading(&blPack).GetBillOfLadingV3(); mbl != nil {
		td.DocReference = mbl.TransportDocumentReference
	}
	return td, nil
}

func jwsFromEvent(data []byte) (envelope.JWS, error) {
	doc := envelope.JWS{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return envelope.JWS{}, fmt.Errorf("failed to unmarshal JWS: %w", err)
	}
	return doc, nil
}

func (b *Broker) decryptTradeDocument(ctx context.Context, data []byte) (storage.TradeDocument, error) {
	doc := envelope.JWE{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return storage.TradeDocument{}, fmt.Errorf("failed to unmarshal JWE: %w", err)
	}

	// Decrypt the data using multiple workers
	const numWorkers = 10

	// Fetch all authentications to decrypt the data
	authentications := make(chan model.BusinessUnitAuthentication, numWorkers*2)
	fetchError := make(chan error, 1)
	defer close(fetchError)
	go b.fetchAuthentications(ctx, authentications, fetchError)

	// decryptedTradeDocument is used to store the decrypted trade document
	decryptedTradeDocument := make(chan storage.TradeDocument, numWorkers)

	stopWorkers := make(chan struct{})
	workersDone := make(chan struct{})
	go func() {
		wg := &sync.WaitGroup{}
		wg.Add(numWorkers)

		for i := 0; i < numWorkers; i++ {
			go b.decryptData(ctx, doc, authentications, decryptedTradeDocument, stopWorkers, wg)
		}

		wg.Wait()
		close(workersDone)
		close(decryptedTradeDocument)
	}()

	// Wait for the first successful decryption
	select {
	case err := <-fetchError:
		close(stopWorkers)
		<-workersDone
		return storage.TradeDocument{}, fmt.Errorf("failed to fetch authentications: %w", err)
	case td := <-decryptedTradeDocument:
		close(stopWorkers)
		<-workersDone
		return td, nil
	case <-workersDone:
		return storage.TradeDocument{}, errors.New("no valid authentication found")
	}
}

func (b *Broker) fetchAuthentications(
	ctx context.Context,
	authentications chan<- model.BusinessUnitAuthentication,
	fetchError chan<- error,
) {
	defer close(authentications)

	tx, ctx, err := b.inboxStore.CreateTx(ctx)
	if err != nil {
		fetchError <- err
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	req := storage.ListAuthenticationRequest{Offset: 0, Limit: 100}
	for {
		result, err := b.inboxStore.ListAuthentication(ctx, tx, req)
		if err != nil {
			fetchError <- err
			return
		}
		for _, auth := range result.Records {
			select {
			case authentications <- auth:
			case <-ctx.Done():
				return
			case <-b.done:
				return
			}
		}
		if len(result.Records) < req.Limit {
			break
		}
		req.Offset += req.Limit
	}
}

func (b *Broker) decryptData(
	ctx context.Context,
	doc envelope.JWE,
	authentications <-chan model.BusinessUnitAuthentication,
	decrypted chan<- storage.TradeDocument,
	stop <-chan struct{},
	wg *sync.WaitGroup,
) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-b.done:
			return
		case <-stop:
			return
		case auth, ok := <-authentications:
			if !ok {
				return
			}
			privateKey, err := pkix.ParsePrivateKey([]byte(auth.PrivateKey))
			if err != nil {
				logrus.Warnf("Failed to decode private key %s: %v", auth.ID, err)
				continue
			}
			decryptedData, err := envelope.Decrypt(doc, []any{privateKey})
			if err != nil {
				logrus.Tracef("Failed to decrypt data: %v", err)
				continue
			}
			tradeDoc, err := tradeDocumentFromEvent(decryptedData)
			if err != nil {
				logrus.Debugf("Failed to parse trade document: %v", err)
				continue
			}
			select {
			case decrypted <- tradeDoc:
			default: // channel is full or closed
			}
			return
		}
	}
}

func (b *Broker) connectionStatusCallback(ctx context.Context, cancel context.CancelCauseFunc, client relay.RelayClient, serverIdentity string, status bool) {
	logrus.Infof("Connection status for %s: %v", serverIdentity, status)
	if client == nil || !status {
		return
	}

	tx, ctx, err := b.inboxStore.CreateTx(ctx)
	if err != nil {
		logrus.Errorf("Broker::connectionStatusCallback() failed to create transaction: %v", err)
		if cancel != nil {
			cancel(err)
		}
		b.closeWithError(err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	offset, err := b.inboxStore.GetRelayServerOffset(ctx, tx, serverIdentity)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		logrus.Errorf("Broker::connectionStatusCallback() failed to get offset: %v", err)
		if cancel != nil {
			cancel(err)
		}
		b.closeWithError(err)
		return
	}
	if err == nil {
		// consume from the next offset
		offset++
	}

	logrus.Infof("Subscribed to %s with offset %d", serverIdentity, offset)
	b.relayServerID = serverIdentity
	if err := client.Subscribe(context.Background(), offset); err != nil {
		logrus.Errorf("Failed to subscribe: %v", err)
		b.closeWithError(err)
		return
	}
}

func (b *Broker) tradeDocumentOutboxWorker(ctx context.Context) {
	fetchMessages := func(ctx context.Context) ([]storage.OutboxMsg, error) {
		tx, ctx, err := b.outboxStore.CreateTx(ctx)
		if err != nil {
			return nil, err
		}
		defer func() { _ = tx.Rollback(ctx) }()

		return b.outboxStore.GetTradeDocumentOutbox(ctx, tx, b.batchSize)
	}
	markAsSent := func(ctx context.Context, ids []int64) error {
		tx, ctx, err := b.outboxStore.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(ctx) }()

		err = b.outboxStore.DeleteTradeDocumentOutbox(ctx, tx, ids...)
		if err != nil {
			return err
		}

		return tx.Commit(ctx)
	}

	errOutboxEmpty := errors.New("outbox is empty")
	processOutbox := func(ctx context.Context) error {
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-b.done:
				return nil
			default:
				messages, err := fetchMessages(ctx)
				if err != nil {
					return fmt.Errorf("failed to fetch messages: %w", err)
				}
				if len(messages) == 0 {
					return errOutboxEmpty
				}
				logrus.Debugf("Fetched %d messages", len(messages))

				var ids []int64
				for _, msg := range messages {
					b.sentCount.Add(ctx, 1, metric.WithAttributes(attribute.Int("kind", msg.Kind)))
					if err := b.client.Publish(ctx, msg.Kind, msg.Msg); err != nil {
						return fmt.Errorf("failed to publish message: %w", err)
					}
					ids = append(ids, msg.RecID)
				}

				if err := markAsSent(ctx, ids); err != nil {
					return fmt.Errorf("failed to mark messages as sent: %w", err)
				}

				logrus.Debugf("Sent %d messages", len(ids))
				return nil
			}
		}
	}

	ticker := time.NewTicker(b.checkInterval)
	defer ticker.Stop()
	for {
		// Check if the context is done or the broker is closed
		select {
		case <-ctx.Done():
			return
		case <-b.done:
			return
		default:
		}

		// Process the outbox to send messages
		err := processOutbox(ctx)
		if errors.Is(err, errOutboxEmpty) {
			// Wait for the next check interval or done signal if the outbox is empty
			select {
			case <-ctx.Done():
				return
			case <-b.done:
				return
			case <-ticker.C:
				continue
			}
		}
		if err != nil {
			logrus.Errorf("Failed to process outbox: %v", err)
			b.closeWithError(err)
			return
		}
	}
}

func (b *Broker) syncRootCerts(ctx context.Context) {
	if b.certMgr == nil {
		return
	}

	fastTicker := time.NewTicker(3 * time.Second)
	defer fastTicker.Stop()

	normalTicker := time.NewTicker(b.rootCertCheckInterval)
	defer normalTicker.Stop()

	err := b.certMgr.SyncRootCerts(ctx)
	if err != nil {
		logrus.Errorf("Failed to sync root certs: %v", err)
	} else {
		fastTicker.Stop()
		logrus.Info("Root certs synced")
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-b.done:
			return
		case <-fastTicker.C:
		case <-normalTicker.C:
		}

		err := b.certMgr.SyncRootCerts(ctx)
		if err != nil {
			logrus.Errorf("Failed to sync root certs: %v", err)
		} else {
			fastTicker.Stop()
			logrus.Info("Root certs synced")
		}
	}
}
