package publisher_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/openebl/openebl/pkg/cert_server/publisher"
	"github.com/openebl/openebl/pkg/cert_server/storage"
	"github.com/openebl/openebl/pkg/relay"
	mock_storage "github.com/openebl/openebl/test/mock/cert_server/storage"
	mock_relay "github.com/openebl/openebl/test/mock/relay"
	"github.com/stretchr/testify/suite"
)

type PublisherTestSuite struct {
	suite.Suite

	ctx  context.Context
	ctrl *gomock.Controller

	outbox      *mock_storage.MockCertStorage
	tx          *mock_storage.MockTx
	relayClient *mock_relay.MockRelayClient
}

func TestPublisher(t *testing.T) {
	suite.Run(t, new(PublisherTestSuite))
}

func (s *PublisherTestSuite) SetupTest() {
	s.ctx = context.Background()
	s.ctrl = gomock.NewController(s.T())
	s.outbox = mock_storage.NewMockCertStorage(s.ctrl)
	s.tx = mock_storage.NewMockTx(s.ctrl)
	s.relayClient = mock_relay.NewMockRelayClient(s.ctrl)
}

func (s *PublisherTestSuite) TearDownTest() {
	s.ctrl.Finish()
}

func (s *PublisherTestSuite) TestPublisher() {
	outboxMsgs := []storage.CertificateOutboxMsg{
		{
			RecID: 1,
			Key:   "ca1",
			Kind:  int(relay.X509Certificate),
			Msg:   []byte("cert1"),
		},
		{
			RecID: 2,
			Key:   "ca2",
			Kind:  int(relay.X509CertificateRevocationList),
			Msg:   []byte("crl"),
		},
	}

	batchSize := 10
	publisher := publisher.NewPublisher(
		publisher.PublisherWithBatchSize(batchSize),
		publisher.PublisherWithOutboxStorage(s.outbox),
		publisher.PublisherWithRelayClient(s.relayClient),
	)

	gomock.InOrder(
		s.outbox.EXPECT().CreateTx(s.ctx, gomock.Len(1)).Return(s.tx, s.ctx, nil),
		s.outbox.EXPECT().GetCertificateOutboxMsg(gomock.Any(), s.tx, batchSize).Return(outboxMsgs[:], nil),
		s.relayClient.EXPECT().Publish(gomock.Any(), int(outboxMsgs[0].Kind), outboxMsgs[0].Msg).Return(nil),
		s.relayClient.EXPECT().Publish(gomock.Any(), int(outboxMsgs[1].Kind), outboxMsgs[1].Msg).Return(nil),
		s.outbox.EXPECT().DeleteCertificateOutboxMsg(gomock.Any(), s.tx, int64(1), int64(2)).Return(nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
		s.outbox.EXPECT().CreateTx(s.ctx, gomock.Len(1)).Return(s.tx, s.ctx, nil),
		s.outbox.EXPECT().GetCertificateOutboxMsg(gomock.Any(), s.tx, batchSize).Return(nil, nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	publisher.Start()
	time.Sleep(2 * time.Second)
	publisher.Stop()
}
