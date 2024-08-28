package publisher

import (
	"context"
	"sync"
	"time"

	"github.com/openebl/openebl/pkg/cert_server/storage"
	"github.com/openebl/openebl/pkg/relay"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
)

type PublisherOption func(*Publisher)

func PublisherWithBatchSize(batchSize int) PublisherOption {
	return func(p *Publisher) {
		p.batchSize = batchSize
	}
}

func PublisherWithInterval(interval time.Duration) PublisherOption {
	return func(p *Publisher) {
		p.interval = interval
	}
}

func PublisherWithOutboxStorage(outbox storage.CertStorage) PublisherOption {
	return func(p *Publisher) {
		p.outbox = outbox
	}
}

func PublisherWithRelayClient(relayClient relay.RelayClient) PublisherOption {
	return func(p *Publisher) {
		p.relayClient = relayClient
	}
}

type Publisher struct {
	stopChan chan struct{}
	wg       sync.WaitGroup

	batchSize   int
	interval    time.Duration
	outbox      storage.CertStorage
	relayClient relay.RelayClient
}

func NewPublisher(options ...PublisherOption) *Publisher {
	p := &Publisher{
		stopChan:  make(chan struct{}),
		batchSize: 10,
		interval:  5 * time.Second,
	}

	for _, opt := range options {
		opt(p)
	}

	return p
}

func (p *Publisher) Start() {
	p.wg.Add(1)
	go p.loop()
}

func (p *Publisher) Stop() {
	close(p.stopChan)
	p.wg.Wait()
}

func (p *Publisher) loop() {
	logrus.Info("Publisher loop started")
	defer p.wg.Done()
	defer logrus.Info("Publisher loop stopped")

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	skipTicker := true

	for {
		if skipTicker {
			select {
			case <-p.stopChan:
				return
			default:
				skipTicker = p.worker()
			}
		} else {
			select {
			case <-p.stopChan:
				return
			case <-ticker.C:
				skipTicker = p.worker()
			}
		}
	}
}

func (p *Publisher) worker() bool {
	ctx := context.Background()
	tx, ctx, err := p.outbox.CreateTx(ctx, storage.TxOptionWithWrite(true))
	if err != nil {
		logrus.Errorf("Publisher: Failed to create transaction: %v", err)
		return false
	}
	defer tx.Rollback(ctx)

	msgs, err := p.outbox.GetCertificateOutboxMsg(ctx, tx, p.batchSize)
	if err != nil {
		logrus.Errorf("Publisher: Failed to get outbox messages: %v", err)
		return false
	}
	if len(msgs) == 0 {
		return false
	}

	for _, msg := range msgs {
		err := p.relayClient.Publish(ctx, msg.Kind, msg.Msg)
		if err != nil {
			logrus.Errorf("Publisher: Failed to publish message: %v", err)
			return false
		}
	}

	recIDs := lo.Map(msgs, func(msg storage.CertificateOutboxMsg, _ int) int64 { return msg.RecID })
	if err := p.outbox.DeleteCertificateOutboxMsg(ctx, tx, recIDs...); err != nil {
		logrus.Errorf("Publisher: Failed to delete outbox messages: %v", err)
		return false
	}
	if err := tx.Commit(ctx); err != nil {
		logrus.Errorf("Publisher: Failed to commit transaction: %v", err)
		return false
	}
	return true
}
