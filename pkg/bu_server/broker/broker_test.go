package broker_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
	_ "unsafe"

	"github.com/golang/mock/gomock"
	"github.com/openebl/openebl/pkg/bu_server/broker"
	"github.com/openebl/openebl/pkg/bu_server/model/trade_document/bill_of_lading"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/bu_server/trade_document"
	"github.com/openebl/openebl/pkg/envelope"
	"github.com/openebl/openebl/pkg/relay"
	"github.com/openebl/openebl/pkg/relay/server"
	mock_storage "github.com/openebl/openebl/test/mock/bu_server/storage"
	mock_relay "github.com/openebl/openebl/test/mock/relay"
	"github.com/stretchr/testify/suite"
)

//go:linkname eventSink github.com/openebl/openebl/pkg/bu_server/broker.(*Broker).eventSink
func eventSink(b *broker.Broker, ctx context.Context, event relay.Event) (string, error)

//go:linkname connectionStatusCallback github.com/openebl/openebl/pkg/bu_server/broker.(*Broker).connectionStatusCallback
func connectionStatusCallback(b *broker.Broker, ctx context.Context, cancel context.CancelCauseFunc, client relay.RelayClient, serverIdentity string, status bool)

//go:linkname tradeDocumentOutboxWorker github.com/openebl/openebl/pkg/bu_server/broker.(*Broker).tradeDocumentOutboxWorker
func tradeDocumentOutboxWorker(b *broker.Broker, ctx context.Context)

type BrokerTestSuite struct {
	suite.Suite
	ctx           context.Context
	ctrl          *gomock.Controller
	tx            *mock_storage.MockTx
	relayClient   *mock_relay.MockRelayClient
	inboxStorage  *mock_storage.MockTradeDocumentInboxStorage
	outboxStorage *mock_storage.MockTradeDocumentOutboxStorage
}

func TestBrokerTestSuite(t *testing.T) {
	suite.Run(t, new(BrokerTestSuite))
}

func (s *BrokerTestSuite) SetupTest() {
	s.ctx = context.TODO()
	s.ctrl = gomock.NewController(s.T())
	s.tx = mock_storage.NewMockTx(s.ctrl)
	s.relayClient = mock_relay.NewMockRelayClient(s.ctrl)
	s.inboxStorage = mock_storage.NewMockTradeDocumentInboxStorage(s.ctrl)
	s.outboxStorage = mock_storage.NewMockTradeDocumentOutboxStorage(s.ctrl)
}

func (s *BrokerTestSuite) TearDownTest() {
	s.ctrl.Finish()
}

func (s *BrokerTestSuite) TestBrokerConnectionStatusCallback() {
	gomock.InOrder(
		s.inboxStorage.EXPECT().CreateTx(gomock.Any()).Return(s.tx, s.ctx, nil),
		s.inboxStorage.EXPECT().GetRelayServerOffset(gomock.Any(), s.tx, "serverIdentity").Return(int64(123), nil),
		s.relayClient.EXPECT().Subscribe(gomock.Any(), int64(124)).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	config := broker.Config{}
	b, err := broker.NewFromConfig(
		config,
		broker.WithRelayClient(s.relayClient),
		broker.WithInboxStore(s.inboxStorage),
		broker.WithOutboxStore(s.outboxStorage),
	)
	s.Require().NoError(err)
	connectionStatusCallback(b, s.ctx, nil, s.relayClient, "serverIdentity", true)
}

func (s *BrokerTestSuite) TestBrokerEventSink() {
	receivedTD := storage.TradeDocument{}
	gomock.InOrder(
		s.inboxStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.inboxStorage.EXPECT().AddTradeDocument(gomock.Any(), s.tx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, tx storage.Tx, tradeDoc storage.TradeDocument) error {
				receivedTD = tradeDoc
				return nil
			}),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),

		s.inboxStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.inboxStorage.EXPECT().UpdateRelayServerOffset(gomock.Any(), s.tx, "", int64(101)).Return(nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	config := broker.Config{}
	b, err := broker.NewFromConfig(
		config,
		broker.WithRelayClient(s.relayClient),
		broker.WithInboxStore(s.inboxStorage),
		broker.WithOutboxStore(s.outboxStorage),
	)
	s.Require().NoError(err)

	td := loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/shipper_issued_ebl_jws.json")
	event := relay.Event{
		Timestamp: 1234567890,
		Offset:    101,
		Type:      int(relay.FileBasedBillOfLading),
		Data:      td.Doc,
	}
	_, err = eventSink(b, s.ctx, event)
	s.Require().NoError(err)

	s.Assert().True(receivedTD.CreatedAt > 0 && receivedTD.CreatedAt <= time.Now().Unix())
	td.CreatedAt = receivedTD.CreatedAt
	s.Assert().EqualValues(td, receivedTD)
}

func (s *BrokerTestSuite) TestBrokerPublish() {
	td := loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/shipper_issued_ebl_jws.json")
	message := storage.OutboxMsg{
		RecID: 111,
		Key:   "ebl.001",
		Msg:   td.Doc,
	}
	var receivedData []byte
	gomock.InOrder(
		s.outboxStorage.EXPECT().CreateTx(gomock.Any()).Return(s.tx, s.ctx, nil),
		s.outboxStorage.EXPECT().GetTradeDocumentOutbox(gomock.Any(), s.tx, 100).Return([]storage.OutboxMsg{message}, nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),

		s.relayClient.EXPECT().Publish(gomock.Any(), int(relay.FileBasedBillOfLading), gomock.Any()).
			DoAndReturn(func(ctx context.Context, evtType int, data []byte) error {
				receivedData = data
				return nil
			}),

		s.outboxStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.outboxStorage.EXPECT().DeleteTradeDocumentOutbox(gomock.Any(), s.tx, []int64{111}).Return(nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),

		s.outboxStorage.EXPECT().CreateTx(gomock.Any()).Return(s.tx, s.ctx, nil),
		s.outboxStorage.EXPECT().GetTradeDocumentOutbox(gomock.Any(), s.tx, 100).Return(nil, nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	config := broker.Config{}
	b, err := broker.NewFromConfig(
		config,
		broker.WithRelayClient(s.relayClient),
		broker.WithInboxStore(s.inboxStorage),
		broker.WithOutboxStore(s.outboxStorage),
		broker.WithBatchSize(100),
		broker.WithCheckInterval(10),
	)
	s.Require().NoError(err)

	go func() {
		time.Sleep(500 * time.Millisecond)
		_ = b.Close(s.ctx)
	}()
	tradeDocumentOutboxWorker(b, s.ctx)
	s.Assert().Equal(td.Doc, receivedData)
}

func loadTradeDocument(datafile string) storage.TradeDocument {
	_, file, _, _ := runtime.Caller(1)
	content, err := os.ReadFile(filepath.Clean(filepath.Join(filepath.Dir(file), datafile)))
	if err != nil {
		panic(err)
	}
	rawDoc := envelope.JWS{}
	if err := json.Unmarshal(content, &rawDoc); err != nil {
		panic(err)
	}
	blPack := bill_of_lading.BillOfLadingPack{}
	rawBlPack, err := rawDoc.GetPayload()
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(rawBlPack, &blPack); err != nil {
		panic(err)
	}
	meta, err := trade_document.GetBillOfLadingPackMeta(&blPack)
	if err != nil {
		panic(err)
	}
	docReference := ""
	if bl := trade_document.GetLastBillOfLading(&blPack); bl != nil {
		docReference = bl.BillOfLading.TransportDocumentReference
	}

	return storage.TradeDocument{
		RawID:        server.GetEventID(content),
		Kind:         int(relay.FileBasedBillOfLading),
		DocID:        blPack.ID,
		DocVersion:   blPack.Version,
		DocReference: docReference,
		Doc:          content,
		CreatedAt:    1234567890,
		Meta:         meta,
	}
}
