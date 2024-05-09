package broker_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
	_ "unsafe"

	"github.com/golang/mock/gomock"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openebl/openebl/pkg/bu_server/broker"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/model/trade_document/bill_of_lading"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/bu_server/trade_document"
	"github.com/openebl/openebl/pkg/envelope"
	"github.com/openebl/openebl/pkg/pkix"
	"github.com/openebl/openebl/pkg/relay"
	"github.com/openebl/openebl/pkg/relay/server"
	mock_business_unit "github.com/openebl/openebl/test/mock/bu_server/business_unit"
	mock_cert "github.com/openebl/openebl/test/mock/bu_server/cert"
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
	buMgr         *mock_business_unit.MockBusinessUnitManager
	certMgr       *mock_cert.MockCertManager
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
	s.buMgr = mock_business_unit.NewMockBusinessUnitManager(s.ctrl)
	s.certMgr = mock_cert.NewMockCertManager(s.ctrl)
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

	b, err := broker.NewBroker(
		broker.WithRelayClient(s.relayClient),
		broker.WithInboxStore(s.inboxStorage),
		broker.WithOutboxStore(s.outboxStorage),
	)
	s.Require().NoError(err)
	connectionStatusCallback(b, s.ctx, nil, s.relayClient, "serverIdentity", true)
}

func (s *BrokerTestSuite) TestBrokerEventSinkPlain() {
	td := loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/shipper_issued_ebl_jws.json")
	event := relay.Event{
		Timestamp: 1234567890,
		Offset:    101,
		Type:      int(relay.FileBasedBillOfLading),
		Data:      td.Doc,
	}
	eventID := server.GetEventID(td.Doc)

	receivedTD := storage.TradeDocument{}
	gomock.InOrder(
		s.inboxStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil), // CreateTx for StoreEvent.
		s.inboxStorage.EXPECT().StoreEvent(gomock.Any(), s.tx, gomock.Any(), eventID, event, "").Return(true, nil),
		s.inboxStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil), // CreateTx for AddTradeDocument.
		s.inboxStorage.EXPECT().AddTradeDocument(gomock.Any(), s.tx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, tx storage.Tx, tradeDoc storage.TradeDocument) error {
				receivedTD = tradeDoc
				return nil
			}),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),   // Commit for AddTradeDocument.
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil), // Rollback for AddTradeDocument.
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),   // Commit for StoreEvent.
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil), // Rollback for StoreEvent.
	)

	b, err := broker.NewBroker(
		broker.WithRelayClient(s.relayClient),
		broker.WithInboxStore(s.inboxStorage),
		broker.WithOutboxStore(s.outboxStorage),
	)
	s.Require().NoError(err)

	_, err = eventSink(b, s.ctx, event)
	s.Require().NoError(err)

	s.Assert().True(receivedTD.CreatedAt > 0 && receivedTD.CreatedAt <= time.Now().Unix())
	td.CreatedAt = receivedTD.CreatedAt
	s.Assert().EqualValues(td, receivedTD)
}

func (s *BrokerTestSuite) TestBrokerEventSinkEncrypted() {
	aliceCred := loadPrivateKey("../../../credential/alice_ecc.pem")
	aliceAuth, _ := pkix.MarshalPrivateKey(aliceCred)
	clairCred := loadPrivateKey("../../../credential/claire_rsa.pem")
	clairAuth, _ := pkix.MarshalPrivateKey(clairCred)
	listAuthenticationRequest := storage.ListAuthenticationRequest{Limit: 100}
	listAuthenticationResult := storage.ListAuthenticationResult{
		Total: 2,
		Records: []model.BusinessUnitAuthentication{
			{PrivateKey: aliceAuth},
			{PrivateKey: clairAuth},
		},
	}

	td := loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/shipper_issued_ebl_jws.json")
	result, err := envelope.Encrypt(
		td.Doc,
		envelope.ContentEncryptionAlgorithm(jwa.A256GCM),
		[]envelope.KeyEncryptionSetting{
			{
				PublicKey: &aliceCred.(*ecdsa.PrivateKey).PublicKey,
				Algorithm: envelope.KeyEncryptionAlgorithm(jwa.ECDH_ES_A256KW),
			},
			{
				PublicKey: &clairCred.(*rsa.PrivateKey).PublicKey,
				Algorithm: envelope.KeyEncryptionAlgorithm(jwa.RSA_OAEP_256),
			},
		},
	)
	s.Require().NoError(err)
	encrypted, err := json.Marshal(result)
	s.T().Logf("Encrypted: %s", string(encrypted))
	s.Require().NoError(err)

	event := relay.Event{
		Timestamp: 1234567890,
		Offset:    101,
		Type:      int(relay.EncryptedFileBasedBillOfLading),
		Data:      encrypted,
	}
	eventID := server.GetEventID(encrypted)

	receivedTD := storage.TradeDocument{}
	gomock.InOrder(
		s.inboxStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil), // CreateTx for StoreEvent.
		s.inboxStorage.EXPECT().StoreEvent(gomock.Any(), s.tx, gomock.Any(), eventID, event, "").Return(true, nil),

		s.inboxStorage.EXPECT().CreateTx(gomock.Any()).Return(s.tx, s.ctx, nil), // CreateTx for ListAuthentication.
		s.inboxStorage.EXPECT().ListAuthentication(gomock.Any(), s.tx, listAuthenticationRequest).Return(listAuthenticationResult, nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil), // Rollback for ListAuthentication.

		s.inboxStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil), // CreateTx for AddTradeDocument.
		s.inboxStorage.EXPECT().AddTradeDocument(gomock.Any(), s.tx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, tx storage.Tx, tradeDoc storage.TradeDocument) error {
				receivedTD = tradeDoc
				return nil
			}),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),   // Commit for AddTradeDocument.
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil), // Rollback for AddTradeDocument.

		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),   // Commit for StoreEvent.
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil), // Rollback for StoreEvent.
	)

	b, err := broker.NewBroker(
		broker.WithRelayClient(s.relayClient),
		broker.WithInboxStore(s.inboxStorage),
		broker.WithOutboxStore(s.outboxStorage),
	)
	s.Require().NoError(err)

	_, err = eventSink(b, s.ctx, event)
	s.Require().NoError(err)

	s.Assert().Equal(receivedTD.RawID, server.GetEventID(encrypted))
	s.Assert().True(receivedTD.CreatedAt > 0 && receivedTD.CreatedAt <= time.Now().Unix())
	td.RawID = receivedTD.RawID
	td.CreatedAt = receivedTD.CreatedAt
	td.Kind = int(relay.EncryptedFileBasedBillOfLading)
	td.DecryptedDoc, td.Doc = td.Doc, receivedTD.Doc
	s.Assert().EqualValues(td, receivedTD)
}

func (s *BrokerTestSuite) TestBrokerEventSinkCert() {
	ts := time.Now().Unix()
	buCertRaw, err := os.ReadFile("../../../testdata/cert_server/cert_authority/bu_cert.crt")
	s.Require().NoError(err)
	b, err := broker.NewBroker(
		broker.WithRelayClient(s.relayClient),
		broker.WithInboxStore(s.inboxStorage),
		broker.WithOutboxStore(s.outboxStorage),
		broker.WithCertManager(s.certMgr),
		broker.WithBUManager(s.buMgr),
	)
	s.Require().NoError(err)

	evt := relay.Event{
		Timestamp: ts,
		Type:      int(relay.X509Certificate),
		Offset:    12345,
		Data:      buCertRaw,
	}
	eventID := server.GetEventID(buCertRaw)

	gomock.InOrder(
		s.inboxStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil), // CreateTx for StoreEvent.
		s.inboxStorage.EXPECT().StoreEvent(gomock.Any(), s.tx, gomock.Any(), eventID, evt, "").Return(true, nil),

		s.buMgr.EXPECT().ActivateAuthentication(gomock.Any(), ts, buCertRaw).Return(model.BusinessUnitAuthentication{}, nil),

		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),   // Commit for StoreEvent.
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil), // Rollback for StoreEvent.
	)

	_, err = eventSink(b, s.ctx, evt)
	s.Require().NoError(err)
}

func (s *BrokerTestSuite) TestBrokerEventSinkCRL() {
	ts := time.Now().Unix()
	crlRaw, err := os.ReadFile("../../../testdata/cert_server/cert_authority/ca_cert.crl")
	s.Require().NoError(err)
	b, err := broker.NewBroker(
		broker.WithRelayClient(s.relayClient),
		broker.WithInboxStore(s.inboxStorage),
		broker.WithOutboxStore(s.outboxStorage),
		broker.WithCertManager(s.certMgr),
		broker.WithBUManager(s.buMgr),
	)
	s.Require().NoError(err)

	evt := relay.Event{
		Timestamp: ts,
		Type:      int(relay.X509CertificateRevocationList),
		Offset:    12345,
		Data:      crlRaw,
	}
	eventID := server.GetEventID(crlRaw)

	gomock.InOrder(
		s.inboxStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil), // CreateTx for StoreEvent.
		s.inboxStorage.EXPECT().StoreEvent(gomock.Any(), s.tx, gomock.Any(), eventID, evt, "").Return(true, nil),

		s.certMgr.EXPECT().AddCRL(gomock.Any(), crlRaw).Return(nil),

		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),   // Commit for StoreEvent.
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil), // Rollback for StoreEvent.
	)

	_, err = eventSink(b, s.ctx, evt)
	s.Require().NoError(err)
}

func (s *BrokerTestSuite) TestBrokerEventSinkDuplicated() {
	ts := time.Now().Unix()
	event := relay.Event{
		Timestamp: ts,
		Offset:    654321,
		Type:      int(relay.X509Certificate),
		Data:      []byte("fake cert"),
	}
	eventID := server.GetEventID(event.Data)

	gomock.InOrder(
		s.inboxStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil), // CreateTx for StoreEvent.
		s.inboxStorage.EXPECT().StoreEvent(gomock.Any(), s.tx, gomock.Any(), eventID, event, "").Return(false, nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),   // Commit for StoreEvent.
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil), // Rollback for StoreEvent.
	)

	b, err := broker.NewBroker(
		broker.WithRelayClient(s.relayClient),
		broker.WithInboxStore(s.inboxStorage),
		broker.WithOutboxStore(s.outboxStorage),
	)
	s.Require().NoError(err)

	_, err = eventSink(b, s.ctx, event)
	s.Require().NoError(err)
}

func (s *BrokerTestSuite) TestBrokerPublish() {
	td := loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/shipper_issued_ebl_jws.json")
	message := storage.OutboxMsg{
		RecID: 111,
		Key:   "ebl.001",
		Kind:  int(relay.EncryptedFileBasedBillOfLading),
		Msg:   td.Doc,
	}
	var receivedData []byte
	gomock.InOrder(
		s.outboxStorage.EXPECT().CreateTx(gomock.Any()).Return(s.tx, s.ctx, nil),
		s.outboxStorage.EXPECT().GetTradeDocumentOutbox(gomock.Any(), s.tx, 100).Return([]storage.OutboxMsg{message}, nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),

		s.relayClient.EXPECT().Publish(gomock.Any(), 1002, gomock.Any()).
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

	b, err := broker.NewBroker(
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

func loadPrivateKey(datafile string) any {
	_, file, _, _ := runtime.Caller(1)
	content, err := os.ReadFile(filepath.Clean(filepath.Join(filepath.Dir(file), datafile)))
	if err != nil {
		panic(err)
	}
	key, err := pkix.ParsePrivateKey(content)
	if err != nil {
		panic(err)
	}
	return key
}
