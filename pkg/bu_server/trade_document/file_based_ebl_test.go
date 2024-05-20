package trade_document_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/openebl/openebl/pkg/bu_server/business_unit"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/model/trade_document/bill_of_lading"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/bu_server/trade_document"
	"github.com/openebl/openebl/pkg/did"
	"github.com/openebl/openebl/pkg/envelope"
	"github.com/openebl/openebl/pkg/pkix"
	"github.com/openebl/openebl/pkg/relay"
	"github.com/openebl/openebl/pkg/relay/server"
	"github.com/openebl/openebl/pkg/util"
	mock_business_unit "github.com/openebl/openebl/test/mock/bu_server/business_unit"
	mock_storage "github.com/openebl/openebl/test/mock/bu_server/storage"
	mock_webhook "github.com/openebl/openebl/test/mock/bu_server/webhook"
	"github.com/samber/lo"
	"github.com/stretchr/testify/suite"
)

type FileBasedEBLTestSuite struct {
	suite.Suite

	ctx         context.Context
	ctrl        *gomock.Controller
	tdStorage   *mock_storage.MockTradeDocumentStorage
	tx          *mock_storage.MockTx
	buMgr       *mock_business_unit.MockBusinessUnitManager
	webhookCtrl *mock_webhook.MockWebhookController
	eblCtrl     trade_document.FileBaseEBLController

	issuer          model.BusinessUnit
	issuerAuth      model.BusinessUnitAuthentication
	issuerSigner    business_unit.JWSSigner
	shipper         model.BusinessUnit
	shipperAuth     model.BusinessUnitAuthentication
	shipperSigner   business_unit.JWSSigner
	consignee       model.BusinessUnit
	consigneeAuth   model.BusinessUnitAuthentication
	consigneeSigner business_unit.JWSSigner
	releaseAgent    model.BusinessUnit
	releaseAuth     model.BusinessUnitAuthentication
	releaseSigner   business_unit.JWSSigner
	encryptors      []business_unit.JWEEncryptor

	draftEbl                    storage.TradeDocument
	shipperEbl                  storage.TradeDocument
	consigneeEbl                storage.TradeDocument
	releaseAgentEbl             storage.TradeDocument
	issuerEblAmendmentRequested storage.TradeDocument
	issuerReturnedEbl           storage.TradeDocument
	accomplishedEbl             storage.TradeDocument
	consigneePrintedEbl         storage.TradeDocument
}

const id = "316f5f2d-eb10-4563-a0d2-45858a57ad5e"
const kind = int(relay.FileBasedBillOfLading)

func TestFileBasedEBL(t *testing.T) {
	suite.Run(t, new(FileBasedEBLTestSuite))
}

func (s *FileBasedEBLTestSuite) SetupSuite() {
	s.issuer = s.loadBU("../../../testdata/bu_server/trade_document/file_based_ebl/issuer.json")
	s.shipper = s.loadBU("../../../testdata/bu_server/trade_document/file_based_ebl/shipper.json")
	s.consignee = s.loadBU("../../../testdata/bu_server/trade_document/file_based_ebl/consignee.json")
	s.releaseAgent = s.loadBU("../../../testdata/bu_server/trade_document/file_based_ebl/release_agent.json")

	s.issuerAuth = s.loadBuAuth("../../../testdata/bu_server/trade_document/file_based_ebl/issuer_auth.json")
	s.shipperAuth = s.loadBuAuth("../../../testdata/bu_server/trade_document/file_based_ebl/shipper_auth.json")
	s.consigneeAuth = s.loadBuAuth("../../../testdata/bu_server/trade_document/file_based_ebl/consignee_auth.json")
	s.releaseAuth = s.loadBuAuth("../../../testdata/bu_server/trade_document/file_based_ebl/release_agent_auth.json")

	s.draftEbl = s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/draft_ebl_jws.json")
	s.shipperEbl = s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/shipper_issued_ebl_jws.json")
	s.consigneeEbl = s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/consignee_ebl_jws.json")
	s.releaseAgentEbl = s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/release_agent_ebl_jws.json")
	s.issuerEblAmendmentRequested = s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/issuer_ebl_amendment_request_by_consignee_jws.json")
	s.issuerReturnedEbl = s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/issuer_ebl_returned_by_shipper_jws.json")
	s.accomplishedEbl = s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/release_agent_accomplished_ebl_jws.json")
	s.consigneePrintedEbl = s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/consignee_printed_ebl_jws.json")

	s.issuerSigner, _ = business_unit.DefaultJWTFactory.NewJWSSigner(s.issuerAuth)
	s.shipperSigner, _ = business_unit.DefaultJWTFactory.NewJWSSigner(s.shipperAuth)
	s.consigneeSigner, _ = business_unit.DefaultJWTFactory.NewJWSSigner(s.consigneeAuth)
	s.releaseSigner, _ = business_unit.DefaultJWTFactory.NewJWSSigner(s.releaseAuth)

	s.encryptors = func() []business_unit.JWEEncryptor {
		issuer, _ := business_unit.DefaultJWTFactory.NewJWEEncryptor(s.issuerAuth)
		shipper, _ := business_unit.DefaultJWTFactory.NewJWEEncryptor(s.shipperAuth)
		consignee, _ := business_unit.DefaultJWTFactory.NewJWEEncryptor(s.consigneeAuth)
		releaseAgent, _ := business_unit.DefaultJWTFactory.NewJWEEncryptor(s.releaseAuth)
		return []business_unit.JWEEncryptor{issuer, shipper, consignee, releaseAgent}
	}()
}

func (s *FileBasedEBLTestSuite) SetupTest() {
	s.ctx = context.Background()
	s.ctrl = gomock.NewController(s.T())
	s.tdStorage = mock_storage.NewMockTradeDocumentStorage(s.ctrl)
	s.tx = mock_storage.NewMockTx(s.ctrl)
	s.webhookCtrl = mock_webhook.NewMockWebhookController(s.ctrl)
	s.buMgr = mock_business_unit.NewMockBusinessUnitManager(s.ctrl)
	s.eblCtrl = trade_document.NewFileBaseEBLController(s.tdStorage, s.buMgr, s.webhookCtrl)
}

func (s *FileBasedEBLTestSuite) TearDownTest() {
	s.ctrl.Finish()
}

func (s *FileBasedEBLTestSuite) loadBU(fileName string) model.BusinessUnit {
	f, err := os.Open(fileName)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	var bu model.BusinessUnit
	if err := json.NewDecoder(f).Decode(&bu); err != nil {
		panic(err)
	}
	return bu
}

func (s *FileBasedEBLTestSuite) loadBuAuth(fileName string) model.BusinessUnitAuthentication {
	f, err := os.Open(fileName)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	var auth model.BusinessUnitAuthentication
	if err := json.NewDecoder(f).Decode(&auth); err != nil {
		panic(err)
	}
	return auth
}

func (s *FileBasedEBLTestSuite) loadTradeDocument(fileName string) storage.TradeDocument {
	raw, err := os.ReadFile(fileName)
	if err != nil {
		panic(err)
	}

	rawDoc := envelope.JWS{}
	if err := json.Unmarshal(raw, &rawDoc); err != nil {
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

	result := storage.TradeDocument{
		Kind:       kind,
		DocID:      blPack.ID,
		DocVersion: blPack.Version,
		Doc:        raw,
	}

	return result
}

func (s *FileBasedEBLTestSuite) TestExtractBLPackFromEncryptedTradeDocument() {
	type TestCase struct {
		Name string
		Doc  storage.TradeDocument
	}

	encryptedEBL := func(td storage.TradeDocument) storage.TradeDocument {
		encryptedEBL := td
		encryptedEBL.Kind = int(relay.EncryptedFileBasedBillOfLading)
		encryptedEBL.DecryptedDoc, encryptedEBL.Doc = encryptedEBL.Doc, []byte("dont care")
		return encryptedEBL
	}

	testCases := []TestCase{
		{
			Name: "Normal EBL",
			Doc:  encryptedEBL(s.draftEbl),
		},
		{
			Name: "Shipper EBL",
			Doc:  encryptedEBL(s.shipperEbl),
		},
		{
			Name: "Consignee EBL",
			Doc:  encryptedEBL(s.consigneeEbl),
		},
		{
			Name: "Release Agent EBL",
			Doc:  encryptedEBL(s.releaseAgentEbl),
		},
		{
			Name: "Issuer EBL Amendment Requested",
			Doc:  encryptedEBL(s.issuerEblAmendmentRequested),
		},
		{
			Name: "Issuer Returned EBL by Shipper",
			Doc:  encryptedEBL(s.issuerReturnedEbl),
		},
		{
			Name: "Accomplished EBL",
			Doc:  encryptedEBL(s.accomplishedEbl),
		},
		{
			Name: "Printed EBL",
			Doc:  encryptedEBL(s.consigneePrintedEbl),
		},
	}

	for _, tc := range testCases {
		blPack, err := trade_document.ExtractBLPackFromTradeDocument(tc.Doc)
		s.Require().NoError(err)
		s.Assert().Equal(tc.Doc.DocID, blPack.ID, tc.Name)
		s.Assert().Equal(tc.Doc.DocVersion, blPack.Version, tc.Name)
	}
}

func (s *FileBasedEBLTestSuite) TestEBLAllowActions() {
	type TestCase struct {
		Name                     string
		Doc                      storage.TradeDocument
		IssuerAllowActions       []trade_document.FileBasedEBLAction
		ShipperAllowActions      []trade_document.FileBasedEBLAction
		ConsigneeAllowActions    []trade_document.FileBasedEBLAction
		ReleaseAgentAllowActions []trade_document.FileBasedEBLAction
	}

	testCases := []TestCase{
		{
			Name: "Draft EBL",
			Doc:  s.draftEbl,
			IssuerAllowActions: []trade_document.FileBasedEBLAction{
				trade_document.FILE_EBL_UPDATE_DRAFT,
				trade_document.FILE_EBL_DELETE,
			},
			ShipperAllowActions:      []trade_document.FileBasedEBLAction{},
			ConsigneeAllowActions:    []trade_document.FileBasedEBLAction{},
			ReleaseAgentAllowActions: []trade_document.FileBasedEBLAction{},
		},
		{
			Name:               "Shipper EBL",
			Doc:                s.shipperEbl,
			IssuerAllowActions: []trade_document.FileBasedEBLAction{},
			ShipperAllowActions: []trade_document.FileBasedEBLAction{
				trade_document.FILE_EBL_REQUEST_AMEND,
				trade_document.FILE_EBL_PRINT,
				trade_document.FILE_EBL_TRANSFER,
				trade_document.FILE_EBL_RETURN,
			},
			ConsigneeAllowActions:    []trade_document.FileBasedEBLAction{},
			ReleaseAgentAllowActions: []trade_document.FileBasedEBLAction{},
		},
		{
			Name:                "Consignee EBL",
			Doc:                 s.consigneeEbl,
			IssuerAllowActions:  []trade_document.FileBasedEBLAction{},
			ShipperAllowActions: []trade_document.FileBasedEBLAction{},
			ConsigneeAllowActions: []trade_document.FileBasedEBLAction{
				trade_document.FILE_EBL_REQUEST_AMEND,
				trade_document.FILE_EBL_PRINT,
				trade_document.FILE_EBL_RETURN,
				trade_document.FILE_EBL_SURRENDER,
			},
			ReleaseAgentAllowActions: []trade_document.FileBasedEBLAction{},
		},
		{
			Name:                  "Release Agent EBL",
			Doc:                   s.releaseAgentEbl,
			IssuerAllowActions:    []trade_document.FileBasedEBLAction{},
			ShipperAllowActions:   []trade_document.FileBasedEBLAction{},
			ConsigneeAllowActions: []trade_document.FileBasedEBLAction{},
			ReleaseAgentAllowActions: []trade_document.FileBasedEBLAction{
				trade_document.FILE_EBL_REQUEST_AMEND,
				trade_document.FILE_EBL_PRINT,
				trade_document.FILE_EBL_RETURN,
				trade_document.FILE_EBL_ACCOMPLISH,
			},
		},
		{
			Name: "Issuer EBL Amendment Requested",
			Doc:  s.issuerEblAmendmentRequested,
			IssuerAllowActions: []trade_document.FileBasedEBLAction{
				trade_document.FILE_EBL_AMEND,
				trade_document.FILE_EBL_PRINT,
				trade_document.FILE_EBL_RETURN,
			},
			ShipperAllowActions:      []trade_document.FileBasedEBLAction{},
			ConsigneeAllowActions:    []trade_document.FileBasedEBLAction{},
			ReleaseAgentAllowActions: []trade_document.FileBasedEBLAction{},
		},
		{
			Name: "Issuer Returned EBL by Shipper",
			Doc:  s.issuerReturnedEbl,
			IssuerAllowActions: []trade_document.FileBasedEBLAction{
				trade_document.FILE_EBL_AMEND,
				trade_document.FILE_EBL_PRINT,
				trade_document.FILE_EBL_TRANSFER,
			},
			ShipperAllowActions:      []trade_document.FileBasedEBLAction{},
			ConsigneeAllowActions:    []trade_document.FileBasedEBLAction{},
			ReleaseAgentAllowActions: []trade_document.FileBasedEBLAction{},
		},
		{
			Name:                     "Accomplished EBL",
			Doc:                      s.accomplishedEbl,
			IssuerAllowActions:       []trade_document.FileBasedEBLAction{},
			ShipperAllowActions:      []trade_document.FileBasedEBLAction{},
			ConsigneeAllowActions:    []trade_document.FileBasedEBLAction{},
			ReleaseAgentAllowActions: []trade_document.FileBasedEBLAction{},
		},
		{
			Name:                     "Printed EBL",
			Doc:                      s.consigneePrintedEbl,
			IssuerAllowActions:       []trade_document.FileBasedEBLAction{},
			ShipperAllowActions:      []trade_document.FileBasedEBLAction{},
			ConsigneeAllowActions:    []trade_document.FileBasedEBLAction{},
			ReleaseAgentAllowActions: []trade_document.FileBasedEBLAction{},
		},
	}

	for _, tc := range testCases {
		blPack, _ := trade_document.ExtractBLPackFromTradeDocument(tc.Doc)
		s.Assert().EqualValues(tc.IssuerAllowActions, trade_document.GetFileBasedEBLAllowActions(&blPack, s.issuer.ID.String()), tc.Name)
		s.Assert().EqualValues(tc.ShipperAllowActions, trade_document.GetFileBasedEBLAllowActions(&blPack, s.shipper.ID.String()), tc.Name)
		s.Assert().EqualValues(tc.ConsigneeAllowActions, trade_document.GetFileBasedEBLAllowActions(&blPack, s.consignee.ID.String()), tc.Name)
		s.Assert().EqualValues(tc.ReleaseAgentAllowActions, trade_document.GetFileBasedEBLAllowActions(&blPack, s.releaseAgent.ID.String()), tc.Name)
	}
}

func (s *FileBasedEBLTestSuite) TestCreateEBL() {
	ts := int64(1708676399)
	eta, err := model.NewDateTimeFromString("2022-01-01T00:00:00Z")
	s.Require().NoError(err)

	req := trade_document.IssueFileBasedEBLRequest{
		MetaData:         bill_of_lading.ApplicationMetaData{"requester": json.RawMessage(`"application user"`)},
		Application:      "appid",
		Issuer:           "did:openebl:issuer",
		AuthenticationID: "bu_auth_id",
		File: trade_document.File{
			Name:    "test.txt",
			Type:    "text/plain",
			Content: []byte("test content"),
		},
		BLNumber:  "bl_number",
		BLDocType: bill_of_lading.BillOfLadingDocumentTypeHouseBillOfLading,
		ToOrder:   false,
		POL: trade_document.Location{
			LocationName: "Port of Loading",
			UNLocCode:    "POL",
		},
		POD: trade_document.Location{
			LocationName: "Port of Discharge",
			UNLocCode:    "POD",
		},
		ETA:          &eta,
		Shipper:      "did:openebl:shipper",
		Consignee:    "did:openebl:consignee",
		ReleaseAgent: "did:openebl:release_agent",
		Note:         "note",
		Draft:        util.Ptr(false),
	}

	var tdOnDB storage.TradeDocument
	var receivedOutboxPayload []byte
	var receivedOutboxKey string
	var receivedOutboxKind int
	gomock.InOrder(
		s.buMgr.EXPECT().ListBusinessUnits(
			gomock.Any(),
			storage.ListBusinessUnitsRequest{
				Limit:           4,
				ApplicationID:   "appid",
				BusinessUnitIDs: []string{"did:openebl:issuer", "did:openebl:shipper", "did:openebl:consignee", "did:openebl:release_agent"},
			},
		).Return(
			storage.ListBusinessUnitsResult{
				Total: 4,
				Records: []storage.ListBusinessUnitsRecord{
					{
						BusinessUnit: model.BusinessUnit{
							ID:            did.MustParse("did:openebl:issuer"),
							Version:       1,
							ApplicationID: "appid",
							Status:        model.BusinessUnitStatusActive,
						},
					},
					{
						BusinessUnit: model.BusinessUnit{
							ID:            did.MustParse("did:openebl:shipper"),
							Version:       1,
							ApplicationID: "appid",
							Status:        model.BusinessUnitStatusActive,
						},
					},
					{
						BusinessUnit: model.BusinessUnit{
							ID:            did.MustParse("did:openebl:consignee"),
							Version:       1,
							ApplicationID: "appid",
							Status:        model.BusinessUnitStatusActive,
						},
					},
					{
						BusinessUnit: model.BusinessUnit{
							ID:            did.MustParse("did:openebl:release_agent"),
							Version:       1,
							ApplicationID: "appid",
							Status:        model.BusinessUnitStatusActive,
						},
					},
				},
			},
			nil,
		),
		s.buMgr.EXPECT().GetJWSSigner(
			gomock.Any(),
			business_unit.GetJWSSignerRequest{
				ApplicationID:    "appid",
				BusinessUnitID:   did.MustParse("did:openebl:issuer"),
				AuthenticationID: "bu_auth_id",
			},
		).Return(s.issuerSigner, nil),
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.tdStorage.EXPECT().AddTradeDocument(gomock.Any(), s.tx, gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, tdoc storage.TradeDocument) error {
				tdOnDB = tdoc
				return nil
			},
		).Return(nil),
		s.tdStorage.EXPECT().AddTradeDocumentOutbox(gomock.Any(), s.tx, gomock.Eq(ts), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, ts int64, docID string, kind int, payload []byte) error {
				receivedOutboxKey = docID
				receivedOutboxKind = kind
				receivedOutboxPayload = payload
				return nil
			}),
		s.webhookCtrl.EXPECT().SendWebhookEvent(gomock.Any(), s.tx, ts, "appid", gomock.Any(), model.WebhookEventBLIssued).Return(nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	result, err := s.eblCtrl.Create(s.ctx, ts, req)
	s.Require().NoError(err)
	s.Assert().Equal(tdOnDB.DocID, result.BL.ID)
	s.Assert().EqualValues(relay.FileBasedBillOfLading, tdOnDB.Kind)
	s.Assert().EqualValues(tdOnDB.DocVersion, result.BL.Version)
	s.Assert().EqualValues([]string{"did:openebl:issuer", "did:openebl:shipper", "did:openebl:consignee", "did:openebl:release_agent"}, tdOnDB.Meta["visible_to_bu"])
	s.Assert().EqualValues([]string{"did:openebl:shipper"}, tdOnDB.Meta["action_needed"])
	s.Assert().EqualValues([]string{"did:openebl:issuer"}, tdOnDB.Meta["sent"])
	s.Assert().EqualValues([]string{"did:openebl:consignee", "did:openebl:release_agent"}, tdOnDB.Meta["upcoming"])
	s.Assert().Empty(tdOnDB.Meta["archive"])

	// Validate if tdOnDB and result are the same except the file content of result is empty.
	jws := envelope.JWS{}
	s.Require().NoError(json.Unmarshal(tdOnDB.Doc, &jws))
	payload, err := jws.GetPayload()
	s.Require().NoError(err)
	blPackOnDB := bill_of_lading.BillOfLadingPack{}
	s.Require().NoError(json.Unmarshal(payload, &blPackOnDB))

	s.Assert().Empty(result.BL.Events[0].BillOfLading.File.Content)
	result.BL.Events[0].BillOfLading.File.Content = blPackOnDB.Events[0].BillOfLading.File.Content
	s.Assert().Equal(util.StructToJSON(result.BL), util.StructToJSON(blPackOnDB))

	// Validate the content of result (BillOfLadingPack).
	expectedBLPackJson := `{"id":"316f5f2d-eb10-4563-a0d2-45858a57ad5e","version":1,"parent_hash":"","events":[{"bill_of_lading":{"bill_of_lading":{"transportDocumentReference":"bl_number","carrierCode":"","carrierCodeListProvider":"","issuingParty":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":"did:openebl:issuer"}]},"shipmentLocations":[{"location":{"locationName":"Port of Loading","address":null,"UNLocationCode":"POL","facilityCode":"","facilityCodeListProvider":""},"shipmentLocationTypeCode":"POL"},{"location":{"locationName":"Port of Discharge","address":null,"UNLocationCode":"POD","facilityCode":"","facilityCodeListProvider":""},"shipmentLocationTypeCode":"POD","eventDateTime":"2022-01-01T00:00:00Z"}],"shippingInstruction":{"shippingInstructionReference":"","documentStatus":"ISSU","transportDocumentTypeCode":"","consignmentItems":null,"utilizedTransportEquipments":null,"documentParties":[{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":"did:openebl:issuer"}]},"partyFunction":"DDR","isToBeNotified":false},{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":"did:openebl:shipper"}]},"partyFunction":"OS","isToBeNotified":false},{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":"did:openebl:consignee"}]},"partyFunction":"CN","isToBeNotified":false},{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":"did:openebl:release_agent"}]},"partyFunction":"DDS","isToBeNotified":false}]}},"file":{"name":"test.txt","file_type":"text/plain","content":"dGVzdCBjb250ZW50","created_date":"2024-02-23T08:19:59Z"},"doc_type":"HouseBillOfLading","created_by":"did:openebl:issuer","created_at":"2024-02-23T08:19:59Z","note":"note", "metadata":{"requester":"application user"}}},{"transfer":{"transfer_by":"did:openebl:issuer","transfer_to":"did:openebl:shipper","transfer_at":"2024-02-23T08:19:59Z","metadata":{"requester":"application user"}}}],"current_owner":"did:openebl:shipper"}`
	expectedBLPack := bill_of_lading.BillOfLadingPack{}
	json.Unmarshal([]byte(expectedBLPackJson), &expectedBLPack)
	expectedBLPack.ID = result.BL.ID
	s.Assert().NotEmpty(result.BL.ID)
	s.Assert().Equal(util.StructToJSON(expectedBLPack), util.StructToJSON(result.BL))
	s.Assert().EqualValues(tdOnDB.DocID, receivedOutboxKey)
	s.Assert().EqualValues(tdOnDB.Kind, receivedOutboxKind)
	s.Assert().EqualValues(tdOnDB.Doc, receivedOutboxPayload)
}

func (s *FileBasedEBLTestSuite) TestCreateDraftEBL() {
	ts := int64(1708676399)

	req := trade_document.IssueFileBasedEBLRequest{
		MetaData:         bill_of_lading.ApplicationMetaData{"requester": json.RawMessage(`"application user"`)},
		Application:      "appid",
		Issuer:           "did:openebl:issuer",
		AuthenticationID: "bu_auth_id",
		File: trade_document.File{
			Name:    "test.txt",
			Type:    "text/plain",
			Content: []byte("test content"),
		},
		BLNumber:  "bl_number",
		BLDocType: bill_of_lading.BillOfLadingDocumentTypeHouseBillOfLading,
		ToOrder:   false,
		Draft:     util.Ptr(true),
	}

	var tdOnDB storage.TradeDocument
	gomock.InOrder(
		s.buMgr.EXPECT().ListBusinessUnits(
			gomock.Any(),
			storage.ListBusinessUnitsRequest{
				Limit:           1,
				ApplicationID:   "appid",
				BusinessUnitIDs: []string{"did:openebl:issuer"},
			},
		).Return(
			storage.ListBusinessUnitsResult{
				Total: 4,
				Records: []storage.ListBusinessUnitsRecord{
					{
						BusinessUnit: model.BusinessUnit{
							ID:            did.MustParse("did:openebl:issuer"),
							Version:       1,
							ApplicationID: "appid",
							Status:        model.BusinessUnitStatusActive,
						},
					},
				},
			},
			nil,
		),
		s.buMgr.EXPECT().GetJWSSigner(
			gomock.Any(),
			business_unit.GetJWSSignerRequest{
				ApplicationID:    "appid",
				BusinessUnitID:   did.MustParse("did:openebl:issuer"),
				AuthenticationID: "bu_auth_id",
			},
		).Return(s.issuerSigner, nil),
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.tdStorage.EXPECT().AddTradeDocument(gomock.Any(), s.tx, gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, tdoc storage.TradeDocument) error {
				tdOnDB = tdoc
				return nil
			},
		).Return(nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	result, err := s.eblCtrl.Create(s.ctx, ts, req)
	s.Require().NoError(err)
	s.Assert().Equal(tdOnDB.DocID, result.BL.ID)
	s.Assert().EqualValues(relay.FileBasedBillOfLading, tdOnDB.Kind)
	s.Assert().EqualValues(tdOnDB.DocVersion, result.BL.Version)
	s.Assert().EqualValues([]string{"did:openebl:issuer"}, tdOnDB.Meta["visible_to_bu"])
	s.Assert().EqualValues([]string{"did:openebl:issuer"}, tdOnDB.Meta["action_needed"])
	s.Assert().EqualValues(nil, tdOnDB.Meta["sent"])
	s.Assert().EqualValues(nil, tdOnDB.Meta["upcoming"])
	s.Assert().Empty(tdOnDB.Meta["archive"])

	// Validate if tdOnDB and result are the same except the file content of result is empty.
	jws := envelope.JWS{}
	s.Require().NoError(json.Unmarshal(tdOnDB.Doc, &jws))
	payload, err := jws.GetPayload()
	s.Require().NoError(err)
	blPackOnDB := bill_of_lading.BillOfLadingPack{}
	s.Require().NoError(json.Unmarshal(payload, &blPackOnDB))

	s.Assert().Empty(result.BL.Events[0].BillOfLading.File.Content)
	result.BL.Events[0].BillOfLading.File.Content = blPackOnDB.Events[0].BillOfLading.File.Content
	s.Assert().Equal(util.StructToJSON(result.BL), util.StructToJSON(blPackOnDB))

	// Validate the content of result (BillOfLadingPack).
	expectedBLPackJson := `{"id":"48a23c9f-0307-4467-a0cd-63197443a3f1","version":1,"parent_hash":"","events":[{"bill_of_lading":{"bill_of_lading":{"transportDocumentReference":"bl_number","carrierCode":"","carrierCodeListProvider":"","issuingParty":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":"did:openebl:issuer"}]},"shipmentLocations":[{"location":{"locationName":"","address":null,"UNLocationCode":"","facilityCode":"","facilityCodeListProvider":""},"shipmentLocationTypeCode":"POL"},{"location":{"locationName":"","address":null,"UNLocationCode":"","facilityCode":"","facilityCodeListProvider":""},"shipmentLocationTypeCode":"POD"}],"shippingInstruction":{"shippingInstructionReference":"","documentStatus":"DRFT","transportDocumentTypeCode":"","consignmentItems":null,"utilizedTransportEquipments":null,"documentParties":[{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":"did:openebl:issuer"}]},"partyFunction":"DDR","isToBeNotified":false},{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":""}]},"partyFunction":"OS","isToBeNotified":false},{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":""}]},"partyFunction":"CN","isToBeNotified":false},{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":""}]},"partyFunction":"DDS","isToBeNotified":false}]}},"file":{"name":"test.txt","file_type":"text/plain","content":"dGVzdCBjb250ZW50","created_date":"2024-02-23T08:19:59Z"},"doc_type":"HouseBillOfLading","created_by":"did:openebl:issuer","created_at":"2024-02-23T08:19:59Z","metadata":{"requester":"application user"}}}],"current_owner":"did:openebl:issuer"}`
	expectedBLPack := bill_of_lading.BillOfLadingPack{}
	json.Unmarshal([]byte(expectedBLPackJson), &expectedBLPack)
	expectedBLPack.ID = result.BL.ID
	s.Assert().NotEmpty(result.BL.ID)
	s.Assert().Equal(util.StructToJSON(expectedBLPack), util.StructToJSON(result.BL))
}

func (s *FileBasedEBLTestSuite) TestUpdateDraftEBLToNonDraftEBL() {
	ts := int64(1708762799)
	eta, err := model.NewDateTimeFromString("2022-01-01T00:00:00Z")
	s.Require().NoError(err)

	req := trade_document.UpdateFileBasedEBLDraftRequest{
		ID: id,
		IssueFileBasedEBLRequest: trade_document.IssueFileBasedEBLRequest{
			MetaData:         bill_of_lading.ApplicationMetaData{"requester": json.RawMessage(`"application user"`)},
			Application:      "app_id",
			Issuer:           "did:openebl:issuer",
			AuthenticationID: "issuer_auth1",
			File: trade_document.File{
				Name:    "test.txt",
				Type:    "text/plain",
				Content: []byte("real content"),
			},
			BLNumber:  "bl_number",
			BLDocType: bill_of_lading.BillOfLadingDocumentTypeHouseBillOfLading,
			ToOrder:   false,
			POL: trade_document.Location{
				LocationName: "Real Port of Loading",
				UNLocCode:    "POL",
			},
			POD: trade_document.Location{
				LocationName: "Real Port of Discharge",
				UNLocCode:    "POD",
			},
			ETA:          &eta,
			Shipper:      "did:openebl:shipper",
			Consignee:    "did:openebl:consignee",
			ReleaseAgent: "did:openebl:release_agent",
			Note:         "note",
			Draft:        util.Ptr(false),
		},
	}

	receivedTD := storage.TradeDocument{}
	var receivedOutboxPayload []byte

	gomock.InOrder(
		s.buMgr.EXPECT().ListBusinessUnits(
			gomock.Any(),
			storage.ListBusinessUnitsRequest{
				Limit:           4,
				ApplicationID:   "app_id",
				BusinessUnitIDs: []string{"did:openebl:issuer", "did:openebl:shipper", "did:openebl:consignee", "did:openebl:release_agent"},
			},
		).Return(
			storage.ListBusinessUnitsResult{
				Total: 4,
				Records: []storage.ListBusinessUnitsRecord{
					{
						BusinessUnit: s.issuer,
					},
					{
						BusinessUnit: s.shipper,
					},
					{
						BusinessUnit: s.consignee,
					},
					{
						BusinessUnit: s.releaseAgent,
					},
				},
			},
			nil,
		),
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.tdStorage.EXPECT().ListTradeDocument(
			gomock.Any(),
			s.tx,
			storage.ListTradeDocumentRequest{
				Limit:  1,
				DocIDs: []string{req.ID},
			},
		).Return(
			storage.ListTradeDocumentResponse{
				Total: 1,
				Docs:  []storage.TradeDocument{s.draftEbl},
			},
			nil,
		),
		s.buMgr.EXPECT().GetJWSSigner(
			gomock.Any(),
			business_unit.GetJWSSignerRequest{
				ApplicationID:    "app_id",
				BusinessUnitID:   did.MustParse(req.Issuer),
				AuthenticationID: req.AuthenticationID,
			},
		).Return(s.issuerSigner, nil),
		s.tdStorage.EXPECT().AddTradeDocument(gomock.Any(), s.tx, gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, td storage.TradeDocument) error {
				receivedTD = td
				return nil
			},
		),
		s.tdStorage.EXPECT().AddTradeDocumentOutbox(gomock.Any(), s.tx, gomock.Eq(ts), gomock.Eq(id), gomock.Eq(kind), gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, ts int64, docID string, kind int, payload []byte) error {
				receivedOutboxPayload = payload
				return nil
			}),
		s.webhookCtrl.EXPECT().SendWebhookEvent(gomock.Any(), s.tx, ts, "app_id", gomock.Any(), model.WebhookEventBLIssued).Return(nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	expectedBlPack := func() bill_of_lading.BillOfLadingPack {
		td := s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/shipper_issued_ebl_jws.json")
		res, err := trade_document.ExtractBLPackFromTradeDocument(td)
		s.Require().NoError(err)
		return res
	}()
	blPack, err := s.eblCtrl.UpdateDraft(s.ctx, ts, req)
	s.Require().NoError(err)
	receivedBLPack, err := trade_document.ExtractBLPackFromTradeDocument(receivedTD)
	s.Require().NoError(err)
	s.Assert().Empty(blPack.BL.Events[0].BillOfLading.File.Content)
	blPack.BL.Events[0].BillOfLading.File.Content = receivedBLPack.Events[0].BillOfLading.File.Content
	s.Assert().EqualValues(util.StructToJSON(receivedBLPack), util.StructToJSON(blPack.BL))
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(receivedBLPack))
	s.Assert().EqualValues(receivedTD.Doc, receivedOutboxPayload)

	// os.WriteFile("../../../testdata/bu_server/trade_document/file_based_ebl/shipper_issued_ebl_jws.json", receivedTD.Doc, 0644)
	// os.WriteFile("../../../testdata/bu_server/trade_document/file_based_ebl/shipper_issued_ebl.json", []byte(util.StructToJSON(expectedBlPack)), 0644)
}

func (s *FileBasedEBLTestSuite) TestUpdateDraftEBLToDraftEBL() {
	ts := int64(1708762799)
	eta, err := model.NewDateTimeFromString("2022-01-01T00:00:00Z")
	s.Require().NoError(err)

	req := trade_document.UpdateFileBasedEBLDraftRequest{
		ID: id,
		IssueFileBasedEBLRequest: trade_document.IssueFileBasedEBLRequest{
			MetaData:         bill_of_lading.ApplicationMetaData{"requester": json.RawMessage(`"application user"`)},
			Application:      "app_id",
			Issuer:           "did:openebl:issuer",
			AuthenticationID: "issuer_auth1",
			File: trade_document.File{
				Name:    "test.txt",
				Type:    "text/plain",
				Content: []byte("real content"),
			},
			BLNumber:  "bl_number",
			BLDocType: bill_of_lading.BillOfLadingDocumentTypeHouseBillOfLading,
			ToOrder:   false,
			ETA:       &eta,
			Note:      "note",
			Draft:     util.Ptr(true),
		},
	}

	receivedTD := storage.TradeDocument{}

	gomock.InOrder(
		s.buMgr.EXPECT().ListBusinessUnits(
			gomock.Any(),
			storage.ListBusinessUnitsRequest{
				Limit:           1,
				ApplicationID:   "app_id",
				BusinessUnitIDs: []string{"did:openebl:issuer"},
			},
		).Return(
			storage.ListBusinessUnitsResult{
				Total: 4,
				Records: []storage.ListBusinessUnitsRecord{
					{
						BusinessUnit: s.issuer,
					},
				},
			},
			nil,
		),
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.tdStorage.EXPECT().ListTradeDocument(
			gomock.Any(),
			s.tx,
			storage.ListTradeDocumentRequest{
				Limit:  1,
				DocIDs: []string{req.ID},
			},
		).Return(
			storage.ListTradeDocumentResponse{
				Total: 1,
				Docs:  []storage.TradeDocument{s.draftEbl},
			},
			nil,
		),
		s.buMgr.EXPECT().GetJWSSigner(
			gomock.Any(),
			business_unit.GetJWSSignerRequest{
				ApplicationID:    "app_id",
				BusinessUnitID:   did.MustParse(req.Issuer),
				AuthenticationID: req.AuthenticationID,
			},
		).Return(s.issuerSigner, nil),
		s.tdStorage.EXPECT().AddTradeDocument(gomock.Any(), s.tx, gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, td storage.TradeDocument) error {
				receivedTD = td
				return nil
			},
		),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	expectedBLPackJson := `{"id":"316f5f2d-eb10-4563-a0d2-45858a57ad5e","version":2,"parent_hash":"3da2e77f4a0f93946b2cabbe83ee49ea20e2261b148e335b3c09c0f6cbb7446f62202a39f3decc817c920be400a180a54884c3457eb605abe677704f843b4486","events":[{"bill_of_lading":{"bill_of_lading":{"transportDocumentReference":"bl_number","carrierCode":"","carrierCodeListProvider":"","issuingParty":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":"did:openebl:issuer"}]},"shipmentLocations":[{"location":{"locationName":"","address":null,"UNLocationCode":"","facilityCode":"","facilityCodeListProvider":""},"shipmentLocationTypeCode":"POL"},{"location":{"locationName":"","address":null,"UNLocationCode":"","facilityCode":"","facilityCodeListProvider":""},"shipmentLocationTypeCode":"POD","eventDateTime":"2022-01-01T00:00:00Z"}],"shippingInstruction":{"shippingInstructionReference":"","documentStatus":"DRFT","transportDocumentTypeCode":"","consignmentItems":null,"utilizedTransportEquipments":null,"documentParties":[{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":"did:openebl:issuer"}]},"partyFunction":"DDR","isToBeNotified":false},{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":""}]},"partyFunction":"OS","isToBeNotified":false},{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":""}]},"partyFunction":"CN","isToBeNotified":false},{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":""}]},"partyFunction":"DDS","isToBeNotified":false}]}},"file":{"name":"test.txt","file_type":"text/plain","content":"cmVhbCBjb250ZW50","created_date":"2024-02-24T08:19:59Z"},"doc_type":"HouseBillOfLading","created_by":"did:openebl:issuer","created_at":"2024-02-24T08:19:59Z","note":"note","metadata":{"requester":"application user"}}}],"current_owner":"did:openebl:issuer"}`
	expectedBLPack := bill_of_lading.BillOfLadingPack{}
	json.Unmarshal([]byte(expectedBLPackJson), &expectedBLPack)

	blPack, err := s.eblCtrl.UpdateDraft(s.ctx, ts, req)
	s.Require().NoError(err)
	receivedBLPack, err := trade_document.ExtractBLPackFromTradeDocument(receivedTD)
	s.Require().NoError(err)
	s.Assert().Empty(blPack.BL.Events[0].BillOfLading.File.Content)
	blPack.BL.Events[0].BillOfLading.File.Content = receivedBLPack.Events[0].BillOfLading.File.Content
	s.Assert().EqualValues(util.StructToJSON(receivedBLPack), util.StructToJSON(blPack.BL))
	s.Assert().EqualValues(util.StructToJSON(expectedBLPack), util.StructToJSON(receivedBLPack))
}

func (s *FileBasedEBLTestSuite) TestUpdateDraftEBL_FileNotChange() {
	ts := int64(1708762799)
	eta, err := model.NewDateTimeFromString("2022-01-01T00:00:00Z")
	s.Require().NoError(err)

	req := trade_document.UpdateFileBasedEBLDraftRequest{
		ID: id,
		IssueFileBasedEBLRequest: trade_document.IssueFileBasedEBLRequest{
			MetaData:         bill_of_lading.ApplicationMetaData{"requester": json.RawMessage(`"application user"`)},
			Application:      "app_id",
			Issuer:           "did:openebl:issuer",
			AuthenticationID: "issuer_auth1",
			File: trade_document.File{
				Name: "test.txt",
				Type: "text/plain",
			},
			BLNumber:  "new_bl_number",
			BLDocType: bill_of_lading.BillOfLadingDocumentTypeHouseBillOfLading,
			ToOrder:   false,
			ETA:       &eta,
			Note:      "note",
			Draft:     util.Ptr(true),
		},
	}

	receivedTD := storage.TradeDocument{}

	gomock.InOrder(
		s.buMgr.EXPECT().ListBusinessUnits(
			gomock.Any(),
			storage.ListBusinessUnitsRequest{
				Limit:           1,
				ApplicationID:   "app_id",
				BusinessUnitIDs: []string{"did:openebl:issuer"},
			},
		).Return(
			storage.ListBusinessUnitsResult{
				Total: 4,
				Records: []storage.ListBusinessUnitsRecord{
					{
						BusinessUnit: s.issuer,
					},
				},
			},
			nil,
		),
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.tdStorage.EXPECT().ListTradeDocument(
			gomock.Any(),
			s.tx,
			storage.ListTradeDocumentRequest{
				Limit:  1,
				DocIDs: []string{req.ID},
			},
		).Return(
			storage.ListTradeDocumentResponse{
				Total: 1,
				Docs:  []storage.TradeDocument{s.draftEbl},
			},
			nil,
		),
		s.buMgr.EXPECT().GetJWSSigner(
			gomock.Any(),
			business_unit.GetJWSSignerRequest{
				ApplicationID:    "app_id",
				BusinessUnitID:   did.MustParse(req.Issuer),
				AuthenticationID: req.AuthenticationID,
			},
		).Return(s.issuerSigner, nil),
		s.tdStorage.EXPECT().AddTradeDocument(gomock.Any(), s.tx, gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, td storage.TradeDocument) error {
				receivedTD = td
				return nil
			},
		),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	expectedBLPackJson := `{"id":"316f5f2d-eb10-4563-a0d2-45858a57ad5e","version":2,"parent_hash":"3da2e77f4a0f93946b2cabbe83ee49ea20e2261b148e335b3c09c0f6cbb7446f62202a39f3decc817c920be400a180a54884c3457eb605abe677704f843b4486","events":[{"bill_of_lading":{"bill_of_lading":{"transportDocumentReference":"new_bl_number","carrierCode":"","carrierCodeListProvider":"","issuingParty":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":"did:openebl:issuer"}]},"shipmentLocations":[{"location":{"locationName":"","address":null,"UNLocationCode":"","facilityCode":"","facilityCodeListProvider":""},"shipmentLocationTypeCode":"POL"},{"location":{"locationName":"","address":null,"UNLocationCode":"","facilityCode":"","facilityCodeListProvider":""},"shipmentLocationTypeCode":"POD","eventDateTime":"2022-01-01T00:00:00Z"}],"shippingInstruction":{"shippingInstructionReference":"","documentStatus":"DRFT","transportDocumentTypeCode":"","consignmentItems":null,"utilizedTransportEquipments":null,"documentParties":[{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":"did:openebl:issuer"}]},"partyFunction":"DDR","isToBeNotified":false},{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":""}]},"partyFunction":"OS","isToBeNotified":false},{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":""}]},"partyFunction":"CN","isToBeNotified":false},{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":""}]},"partyFunction":"DDS","isToBeNotified":false}]}},"file":{"name":"test.txt","file_type":"text/plain","content":"dGVzdCBjb250ZW50","created_date":"2024-02-24T08:19:59Z"},"doc_type":"HouseBillOfLading","created_by":"did:openebl:issuer","created_at":"2024-02-24T08:19:59Z","note":"note","metadata":{"requester":"application user"}}}],"current_owner":"did:openebl:issuer"}`
	expectedBLPack := bill_of_lading.BillOfLadingPack{}
	json.Unmarshal([]byte(expectedBLPackJson), &expectedBLPack)

	blPack, err := s.eblCtrl.UpdateDraft(s.ctx, ts, req)
	s.Require().NoError(err)
	receivedBLPack, err := trade_document.ExtractBLPackFromTradeDocument(receivedTD)
	s.Require().NoError(err)
	s.Assert().Empty(blPack.BL.Events[0].BillOfLading.File.Content)
	blPack.BL.Events[0].BillOfLading.File.Content = receivedBLPack.Events[0].BillOfLading.File.Content
	s.Assert().EqualValues(util.StructToJSON(receivedBLPack), util.StructToJSON(blPack.BL))
	s.Assert().EqualValues(util.StructToJSON(expectedBLPack), util.StructToJSON(receivedBLPack))
}

func (s *FileBasedEBLTestSuite) TestListEBL() {
	req := trade_document.ListFileBasedEBLRequest{
		Application: "appid",
		RequestBy:   "did:openebl:issuer",
		Offset:      0,
		Limit:       20,
		Status:      "action_needed",
	}

	listResp := storage.ListTradeDocumentResponse{
		Total: 1,
		Docs:  []storage.TradeDocument{s.draftEbl},
	}

	gomock.InOrder(
		s.buMgr.EXPECT().ListBusinessUnits(
			gomock.Any(),
			storage.ListBusinessUnitsRequest{
				Limit:           1,
				ApplicationID:   "appid",
				BusinessUnitIDs: []string{"did:openebl:issuer"},
			},
		).Return(
			storage.ListBusinessUnitsResult{
				Total: 1,
				Records: []storage.ListBusinessUnitsRecord{
					{
						BusinessUnit: model.BusinessUnit{
							ID:            did.MustParse("did:openebl:issuer"),
							Version:       1,
							ApplicationID: "appid",
							Status:        model.BusinessUnitStatusActive,
						},
					},
				},
			},
			nil,
		),
		s.tdStorage.EXPECT().CreateTx(gomock.Any()).Return(s.tx, s.ctx, nil),
		s.tdStorage.EXPECT().ListTradeDocument(gomock.Any(), s.tx, gomock.Any()).Return(listResp, nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	expectedBlPack := func() bill_of_lading.BillOfLadingPack {
		td := s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/draft_ebl_jws.json")
		res, err := trade_document.ExtractBLPackFromTradeDocument(td)
		s.Require().NoError(err)
		res.Events[0].BillOfLading.File.Content = nil
		return res
	}()

	result, err := s.eblCtrl.List(s.ctx, req)
	s.Require().NoError(err)
	s.Require().Len(result.Records, 1)
	s.Assert().Empty(result.Records[0].BL.Events[0].BillOfLading.File.Content)
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(result.Records[0].BL))
	s.Assert().EqualValues([]trade_document.FileBasedEBLAction{trade_document.FILE_EBL_UPDATE_DRAFT, trade_document.FILE_EBL_DELETE}, result.Records[0].AllowActions)
}

func (s *FileBasedEBLTestSuite) TestShipperTransferEBL() {
	ts := int64(1709529502)

	req := trade_document.TransferEBLRequest{
		MetaData:         bill_of_lading.ApplicationMetaData{"requester": json.RawMessage(`"application user"`)},
		Application:      "app_id",
		TransferBy:       "did:openebl:shipper",
		AuthenticationID: "shipper_auth1",
		ID:               id,
		Note:             "note",
	}

	receivedTD := storage.TradeDocument{}
	var receivedOutboxPayload []byte

	gomock.InOrder(
		s.buMgr.EXPECT().ListBusinessUnits(
			gomock.Any(),
			storage.ListBusinessUnitsRequest{
				Limit:           1,
				ApplicationID:   "app_id",
				BusinessUnitIDs: []string{"did:openebl:shipper"},
			},
		).Return(
			storage.ListBusinessUnitsResult{
				Total:   1,
				Records: []storage.ListBusinessUnitsRecord{{BusinessUnit: s.shipper}},
			}, nil,
		),
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.tdStorage.EXPECT().ListTradeDocument(
			gomock.Any(),
			s.tx,
			storage.ListTradeDocumentRequest{
				Limit:  1,
				DocIDs: []string{req.ID},
			},
		).Return(
			storage.ListTradeDocumentResponse{
				Total: 1,
				Docs:  []storage.TradeDocument{s.shipperEbl},
			},
			nil,
		),
		s.buMgr.EXPECT().GetJWSSigner(
			gomock.Any(),
			business_unit.GetJWSSignerRequest{
				ApplicationID:    "app_id",
				BusinessUnitID:   did.MustParse("did:openebl:shipper"),
				AuthenticationID: "shipper_auth1",
			},
		).Return(s.shipperSigner, nil),
		s.tdStorage.EXPECT().AddTradeDocument(gomock.Any(), s.tx, gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, td storage.TradeDocument) error {
				receivedTD = td
				return nil
			},
		),
		s.tdStorage.EXPECT().AddTradeDocumentOutbox(gomock.Any(), s.tx, gomock.Eq(ts), gomock.Eq(id), gomock.Eq(kind), gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, ts int64, docID string, kind int, payload []byte) error {
				receivedOutboxPayload = payload
				return nil
			}),
		s.webhookCtrl.EXPECT().SendWebhookEvent(gomock.Any(), s.tx, ts, "app_id", id, model.WebhookEventBLTransferred).Return(nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	expectedBlPack := func() bill_of_lading.BillOfLadingPack {
		td := s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/consignee_ebl_jws.json")
		res, err := trade_document.ExtractBLPackFromTradeDocument(td)
		s.Require().NoError(err)
		return res
	}()

	blPack, err := s.eblCtrl.Transfer(s.ctx, ts, req)
	s.Require().NoError(err)
	receivedBLPack, err := trade_document.ExtractBLPackFromTradeDocument(receivedTD)
	s.Require().NoError(err)
	s.Assert().Empty(blPack.BL.Events[0].BillOfLading.File.Content)
	blPack.BL.Events[0].BillOfLading.File.Content = receivedBLPack.Events[0].BillOfLading.File.Content
	s.Assert().EqualValues(util.StructToJSON(receivedBLPack), util.StructToJSON(blPack.BL))
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(receivedBLPack))
	s.Assert().EqualValues(receivedTD.Doc, receivedOutboxPayload)

	// os.WriteFile("../../../testdata/bu_server/trade_document/file_based_ebl/consignee_ebl_jws.json", receivedTD.Doc, 0644)
	// os.WriteFile("../../../testdata/bu_server/trade_document/file_based_ebl/consignee_ebl.json", []byte(util.StructToJSON(expectedBlPack)), 0644)
}

func (s *FileBasedEBLTestSuite) TestIssuerTransferEBL() {
	ts := int64(1710150099)

	req := trade_document.TransferEBLRequest{
		MetaData:         bill_of_lading.ApplicationMetaData{"requester": json.RawMessage(`"application user"`)},
		Application:      "app_id",
		TransferBy:       "did:openebl:issuer",
		AuthenticationID: "issuer_auth1",
		ID:               id,
		Note:             "transferred by issuer",
	}

	receivedTD := storage.TradeDocument{}
	var receivedOutboxPayload []byte

	gomock.InOrder(
		s.buMgr.EXPECT().ListBusinessUnits(
			gomock.Any(),
			storage.ListBusinessUnitsRequest{
				Limit:           1,
				ApplicationID:   "app_id",
				BusinessUnitIDs: []string{"did:openebl:issuer"},
			},
		).Return(
			storage.ListBusinessUnitsResult{
				Total:   1,
				Records: []storage.ListBusinessUnitsRecord{{BusinessUnit: s.issuer}},
			}, nil,
		),
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.tdStorage.EXPECT().ListTradeDocument(
			gomock.Any(),
			s.tx,
			storage.ListTradeDocumentRequest{
				Limit:  1,
				DocIDs: []string{req.ID},
			},
		).Return(
			storage.ListTradeDocumentResponse{
				Total: 1,
				Docs:  []storage.TradeDocument{s.issuerReturnedEbl},
			},
			nil,
		),
		s.buMgr.EXPECT().GetJWSSigner(
			gomock.Any(),
			business_unit.GetJWSSignerRequest{
				ApplicationID:    "app_id",
				BusinessUnitID:   did.MustParse("did:openebl:issuer"),
				AuthenticationID: "issuer_auth1",
			},
		).Return(s.shipperSigner, nil),
		s.tdStorage.EXPECT().AddTradeDocument(gomock.Any(), s.tx, gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, td storage.TradeDocument) error {
				receivedTD = td
				return nil
			},
		),
		s.tdStorage.EXPECT().AddTradeDocumentOutbox(gomock.Any(), s.tx, gomock.Eq(ts), gomock.Eq(id), gomock.Eq(kind), gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, ts int64, docID string, kind int, payload []byte) error {
				receivedOutboxPayload = payload
				return nil
			}),
		s.webhookCtrl.EXPECT().SendWebhookEvent(gomock.Any(), s.tx, ts, "app_id", id, model.WebhookEventBLTransferred).Return(nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	expectedBlPack := func() bill_of_lading.BillOfLadingPack {
		td := s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/shipper_transferred_ebl_jws.json")
		res, err := trade_document.ExtractBLPackFromTradeDocument(td)
		s.Require().NoError(err)
		return res
	}()

	blPack, err := s.eblCtrl.Transfer(s.ctx, ts, req)
	s.Require().NoError(err)
	receivedBLPack, err := trade_document.ExtractBLPackFromTradeDocument(receivedTD)
	s.Require().NoError(err)
	s.Assert().Empty(blPack.BL.Events[0].BillOfLading.File.Content)
	blPack.BL.Events[0].BillOfLading.File.Content = receivedBLPack.Events[0].BillOfLading.File.Content
	s.Assert().EqualValues(util.StructToJSON(receivedBLPack), util.StructToJSON(blPack.BL))
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(receivedBLPack))
	s.Assert().EqualValues(receivedTD.Doc, receivedOutboxPayload)

	// os.WriteFile("../../../testdata/bu_server/trade_document/file_based_ebl/shipper_transferred_ebl_jws.json", receivedTD.Doc, 0644)
	// os.WriteFile("../../../testdata/bu_server/trade_document/file_based_ebl/shipper_transferred_ebl.json", []byte(util.StructToJSON(expectedBlPack)), 0644)
}

func (s *FileBasedEBLTestSuite) TestTransferEBL_ActionNotAllowed() {
	ts := int64(1709529502)

	req := trade_document.TransferEBLRequest{
		MetaData:         bill_of_lading.ApplicationMetaData{"requester": json.RawMessage(`"application user"`)},
		Application:      "app_id",
		TransferBy:       "did:openebl:shipper",
		AuthenticationID: "shipper_auth1",
		ID:               id,
		Note:             "note",
	}

	gomock.InOrder(
		s.buMgr.EXPECT().ListBusinessUnits(
			gomock.Any(),
			storage.ListBusinessUnitsRequest{
				Limit:           1,
				ApplicationID:   "app_id",
				BusinessUnitIDs: []string{"did:openebl:shipper"},
			},
		).Return(
			storage.ListBusinessUnitsResult{
				Total:   1,
				Records: []storage.ListBusinessUnitsRecord{{BusinessUnit: s.shipper}},
			}, nil,
		),
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.tdStorage.EXPECT().ListTradeDocument(
			gomock.Any(),
			s.tx,
			storage.ListTradeDocumentRequest{
				Limit:  1,
				DocIDs: []string{req.ID},
			},
		).Return(
			storage.ListTradeDocumentResponse{
				Total: 1,
				Docs:  []storage.TradeDocument{s.consigneeEbl},
			},
			nil,
		),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	blPack, err := s.eblCtrl.Transfer(s.ctx, ts, req)
	s.Require().Empty(blPack)
	s.Require().ErrorIs(err, model.ErrEBLActionNotAllowed)
}

func (s *FileBasedEBLTestSuite) TestAmendmentRequestEBL() {
	ts := int64(1709546001)

	req := trade_document.AmendmentRequestEBLRequest{
		MetaData:         bill_of_lading.ApplicationMetaData{"requester": json.RawMessage(`"application user"`)},
		Application:      "app_id",
		RequestBy:        "did:openebl:consignee",
		AuthenticationID: "consignee_auth1",
		ID:               id,
		Note:             "amendment request note",
	}

	receivedTD := storage.TradeDocument{}
	var receivedOutboxPayload []byte

	gomock.InOrder(
		s.buMgr.EXPECT().ListBusinessUnits(
			gomock.Any(),
			storage.ListBusinessUnitsRequest{
				Limit:           1,
				ApplicationID:   "app_id",
				BusinessUnitIDs: []string{"did:openebl:consignee"},
			},
		).Return(
			storage.ListBusinessUnitsResult{
				Total:   1,
				Records: []storage.ListBusinessUnitsRecord{{BusinessUnit: s.consignee}},
			}, nil,
		),
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.tdStorage.EXPECT().ListTradeDocument(
			gomock.Any(),
			s.tx,
			storage.ListTradeDocumentRequest{
				Limit:  1,
				DocIDs: []string{req.ID},
			},
		).Return(
			storage.ListTradeDocumentResponse{
				Total: 1,
				Docs:  []storage.TradeDocument{s.consigneeEbl},
			},
			nil,
		),
		s.buMgr.EXPECT().GetJWSSigner(
			gomock.Any(),
			business_unit.GetJWSSignerRequest{
				ApplicationID:    "app_id",
				BusinessUnitID:   did.MustParse("did:openebl:consignee"),
				AuthenticationID: "consignee_auth1",
			},
		).Return(s.consigneeSigner, nil),
		s.tdStorage.EXPECT().AddTradeDocument(gomock.Any(), s.tx, gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, td storage.TradeDocument) error {
				receivedTD = td
				return nil
			},
		),
		s.tdStorage.EXPECT().AddTradeDocumentOutbox(gomock.Any(), s.tx, gomock.Eq(ts), gomock.Eq(id), gomock.Eq(kind), gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, ts int64, docID string, kind int, payload []byte) error {
				receivedOutboxPayload = payload
				return nil
			}),
		s.webhookCtrl.EXPECT().SendWebhookEvent(gomock.Any(), s.tx, ts, "app_id", id, model.WebhookEventBLAmendmentRequested).Return(nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	expectedBlPack := func() bill_of_lading.BillOfLadingPack {
		td := s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/issuer_ebl_amendment_request_by_consignee_jws.json")
		res, err := trade_document.ExtractBLPackFromTradeDocument(td)
		s.Require().NoError(err)
		return res
	}()

	blPack, err := s.eblCtrl.AmendmentRequest(s.ctx, ts, req)
	s.Require().NoError(err)
	receivedBLPack, err := trade_document.ExtractBLPackFromTradeDocument(receivedTD)
	s.Require().NoError(err)
	s.Assert().Empty(blPack.BL.Events[0].BillOfLading.File.Content)
	blPack.BL.Events[0].BillOfLading.File.Content = receivedBLPack.Events[0].BillOfLading.File.Content
	s.Assert().EqualValues(util.StructToJSON(receivedBLPack), util.StructToJSON(blPack.BL))
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(receivedBLPack))
	s.Assert().EqualValues(receivedTD.Doc, receivedOutboxPayload)

	// os.WriteFile("../../../testdata/bu_server/trade_document/file_based_ebl/issuer_ebl_amendment_request_by_consignee_jws.json", receivedTD.Doc, 0644)
	// os.WriteFile("../../../testdata/bu_server/trade_document/file_based_ebl/issuer_ebl_amendment_request_by_consignee.json", []byte(util.StructToJSON(expectedBlPack)), 0644)
}

func (s *FileBasedEBLTestSuite) TestAmendmentRequestEBL_ActionNotAllowed() {
	ts := int64(1709546001)

	req := trade_document.AmendmentRequestEBLRequest{
		MetaData:         bill_of_lading.ApplicationMetaData{"requester": json.RawMessage(`"application user"`)},
		Application:      "app_id",
		RequestBy:        "did:openebl:issuer",
		AuthenticationID: "issuer_auth1",
		ID:               id,
		Note:             "amendment request note",
	}

	gomock.InOrder(
		s.buMgr.EXPECT().ListBusinessUnits(
			gomock.Any(),
			storage.ListBusinessUnitsRequest{
				Limit:           1,
				ApplicationID:   "app_id",
				BusinessUnitIDs: []string{"did:openebl:issuer"},
			},
		).Return(
			storage.ListBusinessUnitsResult{
				Total:   1,
				Records: []storage.ListBusinessUnitsRecord{{BusinessUnit: s.issuer}},
			}, nil,
		),
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.tdStorage.EXPECT().ListTradeDocument(
			gomock.Any(),
			s.tx,
			storage.ListTradeDocumentRequest{
				Limit:  1,
				DocIDs: []string{req.ID},
			},
		).Return(
			storage.ListTradeDocumentResponse{
				Total: 1,
				Docs:  []storage.TradeDocument{s.draftEbl},
			},
			nil,
		),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	blPack, err := s.eblCtrl.AmendmentRequest(s.ctx, ts, req)
	s.Require().Empty(blPack)
	s.Require().ErrorIs(err, model.ErrEBLActionNotAllowed)
}

func (s *FileBasedEBLTestSuite) TestReturn() {
	ts := int64(1709615902)

	req := trade_document.ReturnFileBasedEBLRequest{
		MetaData:         bill_of_lading.ApplicationMetaData{"requester": json.RawMessage(`"application user"`)},
		Application:      "app_id",
		BusinessUnit:     "did:openebl:consignee",
		AuthenticationID: "consignee_auth1",
		ID:               "316f5f2d-eb10-4563-a0d2-45858a57ad5e",
		Note:             "Return the ownership back to the shipper",
	}

	var receivedTD storage.TradeDocument
	var receivedOutboxPayload []byte
	gomock.InOrder(
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.tdStorage.EXPECT().ListTradeDocument(
			gomock.Any(),
			s.tx,
			storage.ListTradeDocumentRequest{
				Limit:  1,
				DocIDs: []string{req.ID},
			},
		).Return(
			storage.ListTradeDocumentResponse{
				Total: 1,
				Docs:  []storage.TradeDocument{s.consigneeEbl},
			},
			nil,
		),
		s.buMgr.EXPECT().GetJWSSigner(
			gomock.Any(),
			business_unit.GetJWSSignerRequest{
				ApplicationID:    "app_id",
				BusinessUnitID:   did.MustParse("did:openebl:consignee"),
				AuthenticationID: "consignee_auth1",
			},
		).Return(s.consigneeSigner, nil),
		s.tdStorage.EXPECT().AddTradeDocument(gomock.Any(), s.tx, gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, td storage.TradeDocument) error {
				receivedTD = td
				return nil
			},
		),
		s.tdStorage.EXPECT().AddTradeDocumentOutbox(gomock.Any(), s.tx, gomock.Eq(ts), gomock.Eq(id), gomock.Eq(kind), gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, ts int64, docID string, kind int, payload []byte) error {
				receivedOutboxPayload = payload
				return nil
			}),
		s.webhookCtrl.EXPECT().SendWebhookEvent(gomock.Any(), s.tx, ts, "app_id", id, model.WebhookEventBLReturned).Return(nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	expectedBlPack := func() bill_of_lading.BillOfLadingPack {
		td := s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/return_to_shipper_ebl_jws.json")
		res, err := trade_document.ExtractBLPackFromTradeDocument(td)
		s.Require().NoError(err)
		return res
	}()

	result, err := s.eblCtrl.Return(s.ctx, ts, req)
	s.Require().NoError(err)
	s.Assert().Empty(result.BL.Events[0].BillOfLading.File.Content)
	result.BL.Events[0].BillOfLading.File.Content = expectedBlPack.Events[0].BillOfLading.File.Content
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(result.BL))
	receivedBLBlock, err := trade_document.ExtractBLPackFromTradeDocument(receivedTD)
	s.Require().NoError(err)
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(receivedBLBlock))
	s.Assert().EqualValues(receivedTD.Doc, receivedOutboxPayload)

	// os.WriteFile("../../../testdata/bu_server/trade_document/file_based_ebl/return_to_shipper_ebl_jws.json", receivedTD.Doc, 0644)
	// os.WriteFile("../../../testdata/bu_server/trade_document/file_based_ebl/return_to_shipper_ebl.json", []byte(util.StructToJSON(expectedBlPack)), 0644)
}

func (s *FileBasedEBLTestSuite) TestReturnAmendmentRequest() {
	ts := int64(1709615902)

	req := trade_document.ReturnFileBasedEBLRequest{
		MetaData:         bill_of_lading.ApplicationMetaData{"requester": json.RawMessage(`"application user"`)},
		Application:      "app_id",
		BusinessUnit:     "did:openebl:issuer",
		AuthenticationID: "issuer_auth1",
		ID:               "316f5f2d-eb10-4563-a0d2-45858a57ad5e",
		Note:             "Return the ownership back to the ament requester (consignee in this case)",
	}

	var receivedTD storage.TradeDocument
	var receivedOutboxPayload []byte
	gomock.InOrder(
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.tdStorage.EXPECT().ListTradeDocument(
			gomock.Any(),
			s.tx,
			storage.ListTradeDocumentRequest{
				Limit:  1,
				DocIDs: []string{req.ID},
			},
		).Return(
			storage.ListTradeDocumentResponse{
				Total: 1,
				Docs:  []storage.TradeDocument{s.issuerEblAmendmentRequested},
			},
			nil,
		),
		s.buMgr.EXPECT().GetJWSSigner(
			gomock.Any(),
			business_unit.GetJWSSignerRequest{
				ApplicationID:    "app_id",
				BusinessUnitID:   did.MustParse("did:openebl:issuer"),
				AuthenticationID: "issuer_auth1",
			},
		).Return(s.consigneeSigner, nil),
		s.tdStorage.EXPECT().AddTradeDocument(gomock.Any(), s.tx, gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, td storage.TradeDocument) error {
				receivedTD = td
				return nil
			},
		),
		s.tdStorage.EXPECT().AddTradeDocumentOutbox(gomock.Any(), s.tx, gomock.Eq(ts), gomock.Eq(id), gomock.Eq(kind), gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, ts int64, docID string, kind int, payload []byte) error {
				receivedOutboxPayload = payload
				return nil
			}),
		s.webhookCtrl.EXPECT().SendWebhookEvent(gomock.Any(), s.tx, ts, "app_id", id, model.WebhookEventBLReturned).Return(nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	expectedBlPack := func() bill_of_lading.BillOfLadingPack {
		td := s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/return_to_consignee_ebl_jws.json")
		res, err := trade_document.ExtractBLPackFromTradeDocument(td)
		s.Require().NoError(err)
		return res
	}()

	result, err := s.eblCtrl.Return(s.ctx, ts, req)
	s.Require().NoError(err)
	s.Assert().Empty(result.BL.Events[0].BillOfLading.File.Content)
	result.BL.Events[0].BillOfLading.File.Content = expectedBlPack.Events[0].BillOfLading.File.Content
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(result.BL))
	receivedBLBlock, err := trade_document.ExtractBLPackFromTradeDocument(receivedTD)
	s.Require().NoError(err)
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(receivedBLBlock))
	s.Assert().EqualValues(receivedTD.Doc, receivedOutboxPayload)

	// os.WriteFile("../../../testdata/bu_server/trade_document/file_based_ebl/return_to_consignee_ebl_jws.json", receivedTD.Doc, 0644)
	// os.WriteFile("../../../testdata/bu_server/trade_document/file_based_ebl/return_to_consignee_ebl.json", []byte(util.StructToJSON(expectedBlPack)), 0644)
}

func (s *FileBasedEBLTestSuite) TestAmendEBL() {
	ts := int64(1709613375)
	eta, err := model.NewDateTimeFromString("2024-03-30T00:00:00Z")
	s.Require().NoError(err)

	req := trade_document.AmendFileBasedEBLRequest{
		MetaData:         bill_of_lading.ApplicationMetaData{"requester": json.RawMessage(`"application user"`)},
		Application:      "app_id",
		Issuer:           "did:openebl:issuer",
		AuthenticationID: "issuer_auth1",
		ID:               id,
		File: trade_document.File{
			Name:    "new_test.txt",
			Type:    "text/plain",
			Content: []byte("new test content"),
		},
		BLNumber:  "new_bl_number",
		BLDocType: bill_of_lading.BillOfLadingDocumentTypeHouseBillOfLading,
		ToOrder:   false,
		POL: trade_document.Location{
			LocationName: "New Port of Loading",
			UNLocCode:    "POL",
		},
		POD: trade_document.Location{
			LocationName: "New Port of Discharge",
			UNLocCode:    "POD",
		},
		ETA:  &eta,
		Note: "amended by issuer",
	}

	receivedTD := storage.TradeDocument{}
	var receivedOutboxPayload []byte

	gomock.InOrder(
		s.buMgr.EXPECT().ListBusinessUnits(
			gomock.Any(),
			storage.ListBusinessUnitsRequest{
				Limit:           1,
				ApplicationID:   "app_id",
				BusinessUnitIDs: []string{"did:openebl:issuer"},
			},
		).Return(
			storage.ListBusinessUnitsResult{
				Total:   1,
				Records: []storage.ListBusinessUnitsRecord{{BusinessUnit: s.issuer}},
			}, nil,
		),
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.tdStorage.EXPECT().ListTradeDocument(
			gomock.Any(),
			s.tx,
			storage.ListTradeDocumentRequest{
				Limit:  1,
				DocIDs: []string{req.ID},
			},
		).Return(
			storage.ListTradeDocumentResponse{
				Total: 1,
				Docs:  []storage.TradeDocument{s.issuerEblAmendmentRequested},
			},
			nil,
		),
		s.buMgr.EXPECT().GetJWSSigner(
			gomock.Any(),
			business_unit.GetJWSSignerRequest{
				ApplicationID:    "app_id",
				BusinessUnitID:   did.MustParse("did:openebl:issuer"),
				AuthenticationID: "issuer_auth1",
			},
		).Return(s.issuerSigner, nil),
		s.tdStorage.EXPECT().AddTradeDocument(gomock.Any(), s.tx, gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, td storage.TradeDocument) error {
				receivedTD = td
				return nil
			},
		),
		s.tdStorage.EXPECT().AddTradeDocumentOutbox(gomock.Any(), s.tx, gomock.Eq(ts), gomock.Eq(id), gomock.Eq(kind), gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, ts int64, docID string, kind int, payload []byte) error {
				receivedOutboxPayload = payload
				return nil
			}),
		s.webhookCtrl.EXPECT().SendWebhookEvent(gomock.Any(), s.tx, ts, "app_id", id, model.WebhookEventBLAmended).Return(nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	expectedBlPack := func() bill_of_lading.BillOfLadingPack {
		td := s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/consignee_amended_ebl_jws.json")
		res, err := trade_document.ExtractBLPackFromTradeDocument(td)
		s.Require().NoError(err)
		return res
	}()

	blPack, err := s.eblCtrl.Amend(s.ctx, ts, req)
	s.Require().NoError(err)
	receivedBLPack, err := trade_document.ExtractBLPackFromTradeDocument(receivedTD)
	s.Require().NoError(err)

	lo.ForEach(blPack.BL.Events, func(event bill_of_lading.BillOfLadingEvent, i int) {
		if event.BillOfLading != nil {
			s.Assert().Empty(event.BillOfLading.File.Content)
			event.BillOfLading.File.Content = receivedBLPack.Events[i].BillOfLading.File.Content
		}
	})
	s.Assert().EqualValues(util.StructToJSON(receivedBLPack), util.StructToJSON(blPack.BL))
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(receivedBLPack))
	s.Assert().EqualValues(receivedTD.Doc, receivedOutboxPayload)

	// os.WriteFile("../../../testdata/bu_server/trade_document/file_based_ebl/consignee_amended_ebl_jws.json", receivedTD.Doc, 0644)
	// os.WriteFile("../../../testdata/bu_server/trade_document/file_based_ebl/consignee_amended_ebl.json", []byte(util.StructToJSON(expectedBlPack)), 0644)
}

func (s *FileBasedEBLTestSuite) TestAmendEBL_FileNotChange() {
	ts := int64(1709613375)
	eta, err := model.NewDateTimeFromString("2024-03-30T00:00:00Z")
	s.Require().NoError(err)

	req := trade_document.AmendFileBasedEBLRequest{
		MetaData:         bill_of_lading.ApplicationMetaData{"requester": json.RawMessage(`"application user"`)},
		Application:      "app_id",
		Issuer:           "did:openebl:issuer",
		AuthenticationID: "issuer_auth1",
		ID:               id,
		File: trade_document.File{
			Name: "test.txt",
			Type: "text/plain",
		},
		BLNumber:  "new_bl_number",
		BLDocType: bill_of_lading.BillOfLadingDocumentTypeHouseBillOfLading,
		ToOrder:   false,
		POL: trade_document.Location{
			LocationName: "New Port of Loading",
			UNLocCode:    "POL",
		},
		POD: trade_document.Location{
			LocationName: "New Port of Discharge",
			UNLocCode:    "POD",
		},
		ETA:  &eta,
		Note: "amended by issuer",
	}

	receivedTD := storage.TradeDocument{}
	var receivedOutboxPayload []byte

	gomock.InOrder(
		s.buMgr.EXPECT().ListBusinessUnits(
			gomock.Any(),
			storage.ListBusinessUnitsRequest{
				Limit:           1,
				ApplicationID:   "app_id",
				BusinessUnitIDs: []string{"did:openebl:issuer"},
			},
		).Return(
			storage.ListBusinessUnitsResult{
				Total:   1,
				Records: []storage.ListBusinessUnitsRecord{{BusinessUnit: s.issuer}},
			}, nil,
		),
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.tdStorage.EXPECT().ListTradeDocument(
			gomock.Any(),
			s.tx,
			storage.ListTradeDocumentRequest{
				Limit:  1,
				DocIDs: []string{req.ID},
			},
		).Return(
			storage.ListTradeDocumentResponse{
				Total: 1,
				Docs:  []storage.TradeDocument{s.issuerEblAmendmentRequested},
			},
			nil,
		),
		s.buMgr.EXPECT().GetJWSSigner(
			gomock.Any(),
			business_unit.GetJWSSignerRequest{
				ApplicationID:    "app_id",
				BusinessUnitID:   did.MustParse("did:openebl:issuer"),
				AuthenticationID: "issuer_auth1",
			},
		).Return(s.issuerSigner, nil),
		s.tdStorage.EXPECT().AddTradeDocument(gomock.Any(), s.tx, gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, td storage.TradeDocument) error {
				receivedTD = td
				return nil
			},
		),
		s.tdStorage.EXPECT().AddTradeDocumentOutbox(gomock.Any(), s.tx, gomock.Eq(ts), gomock.Eq(id), gomock.Eq(kind), gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, ts int64, docID string, kind int, payload []byte) error {
				receivedOutboxPayload = payload
				return nil
			}),
		s.webhookCtrl.EXPECT().SendWebhookEvent(gomock.Any(), s.tx, ts, "app_id", id, model.WebhookEventBLAmended).Return(nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	expectedBLPackJson := `{"id":"316f5f2d-eb10-4563-a0d2-45858a57ad5e","version":5,"parent_hash":"f6c1515127188c10af2a4184a2e89860ec5117773e26cf0cd2a7c308ad7388ed76e94c6c92609f11631bf5a8415c260f2ab92987eb42c9e6044882916e9f7fee","events":[{"bill_of_lading":{"bill_of_lading":{"transportDocumentReference":"bl_number","carrierCode":"","carrierCodeListProvider":"","issuingParty":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":"did:openebl:issuer"}]},"shipmentLocations":[{"location":{"locationName":"Real Port of Loading","address":null,"UNLocationCode":"POL","facilityCode":"","facilityCodeListProvider":""},"shipmentLocationTypeCode":"POL"},{"location":{"locationName":"Real Port of Discharge","address":null,"UNLocationCode":"POD","facilityCode":"","facilityCodeListProvider":""},"shipmentLocationTypeCode":"POD","eventDateTime":"2022-01-01T00:00:00Z"}],"shippingInstruction":{"shippingInstructionReference":"","documentStatus":"ISSU","transportDocumentTypeCode":"","consignmentItems":null,"utilizedTransportEquipments":null,"documentParties":[{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":"did:openebl:issuer"}]},"partyFunction":"DDR","isToBeNotified":false},{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":"did:openebl:shipper"}]},"partyFunction":"OS","isToBeNotified":false},{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":"did:openebl:consignee"}]},"partyFunction":"CN","isToBeNotified":false},{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":"did:openebl:release_agent"}]},"partyFunction":"DDS","isToBeNotified":false}]}},"file":{"name":"test.txt","file_type":"text/plain","content":"cmVhbCBjb250ZW50","created_date":"2024-02-24T08:19:59Z"},"doc_type":"HouseBillOfLading","created_by":"did:openebl:issuer","created_at":"2024-02-24T08:19:59Z","note":"note","metadata":{"requester":"application user"}}},{"transfer":{"transfer_by":"did:openebl:issuer","transfer_to":"did:openebl:shipper","transfer_at":"2024-02-24T08:19:59Z","note":"note","metadata":{"requester":"application user"}}},{"transfer":{"transfer_by":"did:openebl:shipper","transfer_to":"did:openebl:consignee","transfer_at":"2024-03-04T05:18:22Z","note":"note","metadata":{"requester":"application user"}}},{"amendment_request":{"request_by":"did:openebl:consignee","request_to":"did:openebl:issuer","request_at":"2024-03-04T09:53:21Z","note":"amendment request note","metadata":{"requester":"application user"}}},{"bill_of_lading":{"bill_of_lading":{"transportDocumentReference":"new_bl_number","carrierCode":"","carrierCodeListProvider":"","issuingParty":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":"did:openebl:issuer"}]},"shipmentLocations":[{"location":{"locationName":"New Port of Loading","address":null,"UNLocationCode":"POL","facilityCode":"","facilityCodeListProvider":""},"shipmentLocationTypeCode":"POL"},{"location":{"locationName":"New Port of Discharge","address":null,"UNLocationCode":"POD","facilityCode":"","facilityCodeListProvider":""},"shipmentLocationTypeCode":"POD","eventDateTime":"2024-03-30T00:00:00Z"}],"shippingInstruction":{"shippingInstructionReference":"","documentStatus":"ISSU","transportDocumentTypeCode":"","consignmentItems":null,"utilizedTransportEquipments":null,"documentParties":[{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":"did:openebl:issuer"}]},"partyFunction":"DDR","isToBeNotified":false},{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":"did:openebl:shipper"}]},"partyFunction":"OS","isToBeNotified":false},{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":"did:openebl:consignee"}]},"partyFunction":"CN","isToBeNotified":false},{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":"did:openebl:release_agent"}]},"partyFunction":"DDS","isToBeNotified":false}]}},"file":{"name":"test.txt","file_type":"text/plain","content":"cmVhbCBjb250ZW50","created_date":"2024-03-05T04:36:15Z"},"doc_type":"HouseBillOfLading","created_by":"did:openebl:issuer","created_at":"2024-03-05T04:36:15Z","note":"amended by issuer","metadata":{"requester":"application user"}}},{"transfer":{"transfer_by":"did:openebl:issuer","transfer_to":"did:openebl:consignee","transfer_at":"2024-03-05T04:36:15Z","note":"amended by issuer","metadata":{"requester":"application user"}}}],"current_owner":"did:openebl:consignee"}`
	expectedBLPack := bill_of_lading.BillOfLadingPack{}
	err = json.Unmarshal([]byte(expectedBLPackJson), &expectedBLPack)
	s.Assert().NoError(err)

	blPack, err := s.eblCtrl.Amend(s.ctx, ts, req)
	s.Require().NoError(err)
	receivedBLPack, err := trade_document.ExtractBLPackFromTradeDocument(receivedTD)
	s.Require().NoError(err)

	lo.ForEach(blPack.BL.Events, func(event bill_of_lading.BillOfLadingEvent, i int) {
		if event.BillOfLading != nil {
			s.Assert().Empty(event.BillOfLading.File.Content)
			event.BillOfLading.File.Content = receivedBLPack.Events[i].BillOfLading.File.Content
		}
	})
	s.Assert().EqualValues(util.StructToJSON(receivedBLPack), util.StructToJSON(blPack.BL))
	s.Assert().EqualValues(util.StructToJSON(expectedBLPack), util.StructToJSON(receivedBLPack))
	s.Assert().EqualValues(receivedTD.Doc, receivedOutboxPayload)
}

func (s *FileBasedEBLTestSuite) TestAmendEBL_ReturnedByShipper() {
	ts := int64(1710139214)
	eta, err := model.NewDateTimeFromString("2024-03-30T00:00:00Z")
	s.Require().NoError(err)

	req := trade_document.AmendFileBasedEBLRequest{
		MetaData:         bill_of_lading.ApplicationMetaData{"requester": json.RawMessage(`"application user"`)},
		Application:      "app_id",
		Issuer:           "did:openebl:issuer",
		AuthenticationID: "issuer_auth1",
		ID:               id,
		File: trade_document.File{
			Name:    "new_test.txt",
			Type:    "text/plain",
			Content: []byte("new test content"),
		},
		BLNumber:  "new_bl_number",
		BLDocType: bill_of_lading.BillOfLadingDocumentTypeHouseBillOfLading,
		ToOrder:   false,
		POL: trade_document.Location{
			LocationName: "New Port of Loading",
			UNLocCode:    "POL",
		},
		POD: trade_document.Location{
			LocationName: "New Port of Discharge",
			UNLocCode:    "POD",
		},
		ETA:  &eta,
		Note: "amended by issuer",
	}

	receivedTD := storage.TradeDocument{}
	var receivedOutboxPayload []byte

	gomock.InOrder(
		s.buMgr.EXPECT().ListBusinessUnits(
			gomock.Any(),
			storage.ListBusinessUnitsRequest{
				Limit:           1,
				ApplicationID:   "app_id",
				BusinessUnitIDs: []string{"did:openebl:issuer"},
			},
		).Return(
			storage.ListBusinessUnitsResult{
				Total:   1,
				Records: []storage.ListBusinessUnitsRecord{{BusinessUnit: s.issuer}},
			}, nil,
		),
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.tdStorage.EXPECT().ListTradeDocument(
			gomock.Any(),
			s.tx,
			storage.ListTradeDocumentRequest{
				Limit:  1,
				DocIDs: []string{req.ID},
			},
		).Return(
			storage.ListTradeDocumentResponse{
				Total: 1,
				Docs:  []storage.TradeDocument{s.issuerReturnedEbl},
			},
			nil,
		),
		s.buMgr.EXPECT().GetJWSSigner(
			gomock.Any(),
			business_unit.GetJWSSignerRequest{
				ApplicationID:    "app_id",
				BusinessUnitID:   did.MustParse("did:openebl:issuer"),
				AuthenticationID: "issuer_auth1",
			},
		).Return(s.issuerSigner, nil),
		s.tdStorage.EXPECT().AddTradeDocument(gomock.Any(), s.tx, gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, td storage.TradeDocument) error {
				receivedTD = td
				return nil
			},
		),
		s.tdStorage.EXPECT().AddTradeDocumentOutbox(gomock.Any(), s.tx, gomock.Eq(ts), gomock.Eq(id), gomock.Eq(kind), gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, ts int64, docID string, kind int, payload []byte) error {
				receivedOutboxPayload = payload
				return nil
			}),
		s.webhookCtrl.EXPECT().SendWebhookEvent(gomock.Any(), s.tx, ts, "app_id", id, model.WebhookEventBLAmended).Return(nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	expectedBlPack := func() bill_of_lading.BillOfLadingPack {
		td := s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/shipper_amended_ebl_jws.json")
		res, err := trade_document.ExtractBLPackFromTradeDocument(td)
		s.Require().NoError(err)
		return res
	}()

	blPack, err := s.eblCtrl.Amend(s.ctx, ts, req)
	s.Require().NoError(err)
	receivedBLPack, err := trade_document.ExtractBLPackFromTradeDocument(receivedTD)
	s.Require().NoError(err)

	lo.ForEach(blPack.BL.Events, func(event bill_of_lading.BillOfLadingEvent, i int) {
		if event.BillOfLading != nil {
			s.Assert().Empty(event.BillOfLading.File.Content)
			event.BillOfLading.File.Content = receivedBLPack.Events[i].BillOfLading.File.Content
		}
	})
	s.Assert().EqualValues(util.StructToJSON(receivedBLPack), util.StructToJSON(blPack.BL))
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(receivedBLPack))
	s.Assert().EqualValues(receivedTD.Doc, receivedOutboxPayload)

	// os.WriteFile("../../../testdata/bu_server/trade_document/file_based_ebl/shipper_amended_ebl_jws.json", receivedTD.Doc, 0644)
	// os.WriteFile("../../../testdata/bu_server/trade_document/file_based_ebl/shipper_amended_ebl.json", []byte(util.StructToJSON(expectedBlPack)), 0644)
}

func (s *FileBasedEBLTestSuite) TestSurrender() {
	ts := int64(1709615902)

	req := trade_document.SurrenderEBLRequest{
		MetaData:         bill_of_lading.ApplicationMetaData{"requester": json.RawMessage(`"application user"`)},
		Application:      "app_id",
		RequestBy:        "did:openebl:consignee",
		AuthenticationID: "consignee_auth1",
		ID:               "316f5f2d-eb10-4563-a0d2-45858a57ad5e",
		Note:             "Surrender the eBL to the release agent",
	}

	var receivedTD storage.TradeDocument
	var receivedOutboxPayload []byte
	gomock.InOrder(
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.tdStorage.EXPECT().ListTradeDocument(
			gomock.Any(),
			s.tx,
			storage.ListTradeDocumentRequest{
				Limit:  1,
				DocIDs: []string{req.ID},
			},
		).Return(
			storage.ListTradeDocumentResponse{
				Total: 1,
				Docs:  []storage.TradeDocument{s.consigneeEbl},
			},
			nil,
		),
		s.buMgr.EXPECT().GetJWSSigner(
			gomock.Any(),
			business_unit.GetJWSSignerRequest{
				ApplicationID:    "app_id",
				BusinessUnitID:   did.MustParse("did:openebl:consignee"),
				AuthenticationID: "consignee_auth1",
			},
		).Return(s.shipperSigner, nil),
		s.tdStorage.EXPECT().AddTradeDocument(gomock.Any(), s.tx, gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, td storage.TradeDocument) error {
				receivedTD = td
				return nil
			},
		),
		s.tdStorage.EXPECT().AddTradeDocumentOutbox(gomock.Any(), s.tx, gomock.Eq(ts), gomock.Eq(id), gomock.Eq(kind), gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, ts int64, docID string, kind int, payload []byte) error {
				receivedOutboxPayload = payload
				return nil
			}),
		s.webhookCtrl.EXPECT().SendWebhookEvent(gomock.Any(), s.tx, ts, "app_id", id, model.WebhookEventBLSurrendered).Return(nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	expectedBlPack := func() bill_of_lading.BillOfLadingPack {
		td := s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/release_agent_ebl_jws.json")
		res, err := trade_document.ExtractBLPackFromTradeDocument(td)
		s.Require().NoError(err)
		return res
	}()

	result, err := s.eblCtrl.Surrender(s.ctx, ts, req)
	s.Require().NoError(err)
	s.Assert().Empty(result.BL.Events[0].BillOfLading.File.Content)
	result.BL.Events[0].BillOfLading.File.Content = expectedBlPack.Events[0].BillOfLading.File.Content
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(result.BL))
	receivedBLBlock, err := trade_document.ExtractBLPackFromTradeDocument(receivedTD)
	s.Require().NoError(err)
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(receivedBLBlock))
	s.Assert().EqualValues(receivedTD.Doc, receivedOutboxPayload)

	// os.WriteFile("../../../testdata/bu_server/trade_document/file_based_ebl/release_agent_ebl_jws.json", receivedTD.Doc, 0644)
	// os.WriteFile("../../../testdata/bu_server/trade_document/file_based_ebl/release_agent_ebl.json", []byte(util.StructToJSON(expectedBlPack)), 0644)
}

func (s *FileBasedEBLTestSuite) TestPrintToPaper() {
	ts := int64(1709615902)

	req := trade_document.PrintFileBasedEBLToPaperRequest{
		MetaData:         bill_of_lading.ApplicationMetaData{"requester": json.RawMessage(`"application user"`)},
		Application:      "app_id",
		RequestBy:        "did:openebl:consignee",
		AuthenticationID: "consignee_auth1",
		ID:               "316f5f2d-eb10-4563-a0d2-45858a57ad5e",
		Note:             "Print the eBL",
	}

	var receivedTD storage.TradeDocument
	var receivedOutboxPayload []byte
	gomock.InOrder(
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.tdStorage.EXPECT().ListTradeDocument(
			gomock.Any(),
			s.tx,
			storage.ListTradeDocumentRequest{
				Limit:  1,
				DocIDs: []string{req.ID},
			},
		).Return(
			storage.ListTradeDocumentResponse{
				Total: 1,
				Docs:  []storage.TradeDocument{s.consigneeEbl},
			},
			nil,
		),
		s.buMgr.EXPECT().GetJWSSigner(
			gomock.Any(),
			business_unit.GetJWSSignerRequest{
				ApplicationID:    "app_id",
				BusinessUnitID:   did.MustParse("did:openebl:consignee"),
				AuthenticationID: "consignee_auth1",
			},
		).Return(s.shipperSigner, nil),
		s.tdStorage.EXPECT().AddTradeDocument(gomock.Any(), s.tx, gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, td storage.TradeDocument) error {
				receivedTD = td
				return nil
			},
		),
		s.tdStorage.EXPECT().AddTradeDocumentOutbox(gomock.Any(), s.tx, gomock.Eq(ts), gomock.Eq(id), gomock.Eq(kind), gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, ts int64, docID string, kind int, payload []byte) error {
				receivedOutboxPayload = payload
				return nil
			}),
		s.webhookCtrl.EXPECT().SendWebhookEvent(gomock.Any(), s.tx, ts, "app_id", id, model.WebhookEventBLPrintedToPaper).Return(nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	expectedBlPack := func() bill_of_lading.BillOfLadingPack {
		td := s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/consignee_printed_ebl_jws.json")
		res, err := trade_document.ExtractBLPackFromTradeDocument(td)
		s.Require().NoError(err)
		return res
	}()

	result, err := s.eblCtrl.PrintToPaper(s.ctx, ts, req)
	s.Require().NoError(err)
	s.Assert().Empty(result.BL.Events[0].BillOfLading.File.Content)
	result.BL.Events[0].BillOfLading.File.Content = expectedBlPack.Events[0].BillOfLading.File.Content
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(result.BL))
	receivedBLBlock, err := trade_document.ExtractBLPackFromTradeDocument(receivedTD)
	s.Require().NoError(err)
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(receivedBLBlock))
	s.Assert().EqualValues(receivedTD.Doc, receivedOutboxPayload)

	// os.WriteFile("../../../testdata/bu_server/trade_document/file_based_ebl/consignee_printed_ebl_jws.json", receivedTD.Doc, 0644)
	// os.WriteFile("../../../testdata/bu_server/trade_document/file_based_ebl/consignee_printed_ebl.json", []byte(util.StructToJSON(expectedBlPack)), 0644)
}

func (s *FileBasedEBLTestSuite) TestAccomplishEBL() {
	ts := int64(1709696923)

	req := trade_document.AccomplishEBLRequest{
		MetaData:         bill_of_lading.ApplicationMetaData{"requester": json.RawMessage(`"application user"`)},
		Application:      "app_id",
		RequestBy:        "did:openebl:release_agent",
		AuthenticationID: "release_agent_auth1",
		ID:               id,
		Note:             "accomplished by release agent",
	}

	var receivedTD storage.TradeDocument
	var receivedOutboxPayload []byte
	gomock.InOrder(
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.tdStorage.EXPECT().ListTradeDocument(
			gomock.Any(),
			s.tx,
			storage.ListTradeDocumentRequest{
				Limit:  1,
				DocIDs: []string{req.ID},
			},
		).Return(
			storage.ListTradeDocumentResponse{
				Total: 1,
				Docs:  []storage.TradeDocument{s.releaseAgentEbl},
			},
			nil,
		),
		s.buMgr.EXPECT().GetJWSSigner(
			gomock.Any(),
			business_unit.GetJWSSignerRequest{
				ApplicationID:    "app_id",
				BusinessUnitID:   did.MustParse("did:openebl:release_agent"),
				AuthenticationID: "release_agent_auth1",
			},
		).Return(s.releaseSigner, nil),
		s.tdStorage.EXPECT().AddTradeDocument(gomock.Any(), s.tx, gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, td storage.TradeDocument) error {
				receivedTD = td
				return nil
			},
		),
		s.tdStorage.EXPECT().AddTradeDocumentOutbox(gomock.Any(), s.tx, gomock.Eq(ts), gomock.Eq(id), gomock.Eq(kind), gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, ts int64, docID string, kind int, payload []byte) error {
				receivedOutboxPayload = payload
				return nil
			}),
		s.webhookCtrl.EXPECT().SendWebhookEvent(gomock.Any(), s.tx, ts, "app_id", id, model.WebhookEventBLAccomplished).Return(nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	expectedBlPack := func() bill_of_lading.BillOfLadingPack {
		td := s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/release_agent_accomplished_ebl_jws.json")
		res, err := trade_document.ExtractBLPackFromTradeDocument(td)
		s.Require().NoError(err)
		return res
	}()

	result, err := s.eblCtrl.Accomplish(s.ctx, ts, req)
	s.Require().NoError(err)
	s.Assert().Empty(result.BL.Events[0].BillOfLading.File.Content)
	result.BL.Events[0].BillOfLading.File.Content = expectedBlPack.Events[0].BillOfLading.File.Content
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(result.BL))
	receivedBLBlock, err := trade_document.ExtractBLPackFromTradeDocument(receivedTD)
	s.Require().NoError(err)
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(receivedBLBlock))
	s.Assert().EqualValues(receivedTD.Doc, receivedOutboxPayload)

	// os.WriteFile("../../../testdata/bu_server/trade_document/file_based_ebl/release_agent_accomplished_ebl_jws.json", receivedTD.Doc, 0644)
	// os.WriteFile("../../../testdata/bu_server/trade_document/file_based_ebl/release_agent_accomplished_ebl.json", []byte(util.StructToJSON(expectedBlPack)), 0644)
}

func (s *FileBasedEBLTestSuite) TestGetEBL() {
	req := trade_document.GetFileBasedEBLRequest{
		Requester:   "did:openebl:requester",
		Application: "appid",
		ID:          "doc_id",
	}

	listReq := storage.ListTradeDocumentRequest{
		Limit:  1,
		DocIDs: []string{"doc_id"},
		Meta:   map[string]any{"visible_to_bu": []string{"did:openebl:requester"}},
	}
	listResp := storage.ListTradeDocumentResponse{
		Total: 1,
		Docs:  []storage.TradeDocument{s.shipperEbl},
	}

	gomock.InOrder(
		s.buMgr.EXPECT().ListBusinessUnits(
			gomock.Any(),
			storage.ListBusinessUnitsRequest{
				Limit:           1,
				ApplicationID:   "appid",
				BusinessUnitIDs: []string{"did:openebl:requester"},
			},
		).Return(
			storage.ListBusinessUnitsResult{
				Total: 1,
				Records: []storage.ListBusinessUnitsRecord{
					{
						BusinessUnit: model.BusinessUnit{
							ID:            did.MustParse("did:openebl:requester"),
							Version:       1,
							ApplicationID: "appid",
							Status:        model.BusinessUnitStatusActive,
						},
					},
				},
			},
			nil,
		),
		s.tdStorage.EXPECT().CreateTx(gomock.Any()).Return(s.tx, s.ctx, nil),
		s.tdStorage.EXPECT().ListTradeDocument(gomock.Any(), s.tx, gomock.Eq(listReq)).Return(listResp, nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	expectedBlPack := func() bill_of_lading.BillOfLadingPack {
		td := s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/shipper_issued_ebl_jws.json")
		res, err := trade_document.ExtractBLPackFromTradeDocument(td)
		s.Require().NoError(err)
		res.Events[0].BillOfLading.File.Content = nil
		return res
	}()

	result, err := s.eblCtrl.Get(s.ctx, req)
	s.Require().NoError(err)
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(result.BL))
}

func (s *FileBasedEBLTestSuite) TestDeleteDraftEBL() {
	ts := int64(1709776508)

	req := trade_document.DeleteEBLRequest{
		MetaData:         bill_of_lading.ApplicationMetaData{"requester": json.RawMessage(`"application user"`)},
		Application:      "app_id",
		RequestBy:        "did:openebl:issuer",
		AuthenticationID: "issuer_auth1",
		ID:               id,
	}

	var receivedTD storage.TradeDocument
	gomock.InOrder(
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.tdStorage.EXPECT().ListTradeDocument(
			gomock.Any(),
			s.tx,
			storage.ListTradeDocumentRequest{
				Limit:  1,
				DocIDs: []string{req.ID},
			},
		).Return(
			storage.ListTradeDocumentResponse{
				Total: 1,
				Docs:  []storage.TradeDocument{s.draftEbl},
			},
			nil,
		),
		s.buMgr.EXPECT().GetJWSSigner(
			gomock.Any(),
			business_unit.GetJWSSignerRequest{
				ApplicationID:    "app_id",
				BusinessUnitID:   did.MustParse("did:openebl:issuer"),
				AuthenticationID: "issuer_auth1",
			},
		).Return(s.releaseSigner, nil),
		s.tdStorage.EXPECT().AddTradeDocument(gomock.Any(), s.tx, gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, td storage.TradeDocument) error {
				receivedTD = td
				return nil
			},
		),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	expectedBlPack := func() bill_of_lading.BillOfLadingPack {
		td := s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/deleted_ebl_jws.json")
		res, err := trade_document.ExtractBLPackFromTradeDocument(td)
		s.Require().NoError(err)
		return res
	}()

	result, err := s.eblCtrl.Delete(s.ctx, ts, req)
	s.Require().NoError(err)
	s.Assert().Empty(result.BL.Events[0].BillOfLading.File.Content)
	result.BL.Events[0].BillOfLading.File.Content = expectedBlPack.Events[0].BillOfLading.File.Content
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(result.BL))
	receivedBLBlock, err := trade_document.ExtractBLPackFromTradeDocument(receivedTD)
	s.Require().NoError(err)
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(receivedBLBlock))

	// os.WriteFile("../../../testdata/bu_server/trade_document/file_based_ebl/deleted_ebl_jws.json", receivedTD.Doc, 0644)
	// os.WriteFile("../../../testdata/bu_server/trade_document/file_based_ebl/deleted_ebl.json", []byte(util.StructToJSON(expectedBlPack)), 0644)
}

func (s *FileBasedEBLTestSuite) TestGetEBLDocument() {
	req := trade_document.GetFileBasedEBLRequest{
		Requester:   "did:openebl:requester",
		Application: "appid",
		ID:          "doc_id",
	}

	listReq := storage.ListTradeDocumentRequest{
		Limit:  1,
		DocIDs: []string{"doc_id"},
		Meta:   map[string]any{"visible_to_bu": []string{"did:openebl:requester"}},
	}
	listResp := storage.ListTradeDocumentResponse{
		Total: 1,
		Docs:  []storage.TradeDocument{s.shipperEbl},
	}

	gomock.InOrder(
		s.buMgr.EXPECT().ListBusinessUnits(
			gomock.Any(),
			storage.ListBusinessUnitsRequest{
				Limit:           1,
				ApplicationID:   "appid",
				BusinessUnitIDs: []string{"did:openebl:requester"},
			},
		).Return(
			storage.ListBusinessUnitsResult{
				Total: 1,
				Records: []storage.ListBusinessUnitsRecord{
					{
						BusinessUnit: model.BusinessUnit{
							ID:            did.MustParse("did:openebl:requester"),
							Version:       1,
							ApplicationID: "appid",
							Status:        model.BusinessUnitStatusActive,
						},
					},
				},
			},
			nil,
		),
		s.tdStorage.EXPECT().CreateTx(gomock.Any()).Return(s.tx, s.ctx, nil),
		s.tdStorage.EXPECT().ListTradeDocument(gomock.Any(), s.tx, gomock.Eq(listReq)).Return(listResp, nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	expectedFile := func() *model.File {
		td := s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/shipper_issued_ebl_jws.json")
		res, err := trade_document.ExtractBLPackFromTradeDocument(td)
		s.Require().NoError(err)
		return res.Events[0].BillOfLading.File
	}()

	result, err := s.eblCtrl.GetDocument(s.ctx, req)
	s.Require().NoError(err)
	s.Assert().EqualValues(util.StructToJSON(expectedFile), util.StructToJSON(result))
}

func (s *FileBasedEBLTestSuite) TestCreateEncryptedEBL() {
	ts := int64(1708676399)
	eta, err := model.NewDateTimeFromString("2022-01-01T00:00:00Z")
	s.Require().NoError(err)

	req := trade_document.IssueFileBasedEBLRequest{
		MetaData:         bill_of_lading.ApplicationMetaData{"requester": json.RawMessage(`"application user"`)},
		Application:      "appid",
		Issuer:           "did:openebl:issuer",
		AuthenticationID: "bu_auth_id",
		File: trade_document.File{
			Name:    "test.txt",
			Type:    "text/plain",
			Content: []byte("test content"),
		},
		BLNumber:  "bl_number",
		BLDocType: bill_of_lading.BillOfLadingDocumentTypeHouseBillOfLading,
		ToOrder:   false,
		POL: trade_document.Location{
			LocationName: "Port of Loading",
			UNLocCode:    "POL",
		},
		POD: trade_document.Location{
			LocationName: "Port of Discharge",
			UNLocCode:    "POD",
		},
		ETA:            &eta,
		Shipper:        "did:openebl:shipper",
		Consignee:      "did:openebl:consignee",
		ReleaseAgent:   "did:openebl:release_agent",
		Note:           "note",
		Draft:          util.Ptr(false),
		EncryptContent: true,
	}

	var tdOnDB storage.TradeDocument
	var receivedOutboxPayload []byte
	var receivedOutboxKey string
	var receivedOutboxKind int
	gomock.InOrder(
		s.buMgr.EXPECT().ListBusinessUnits(
			gomock.Any(),
			storage.ListBusinessUnitsRequest{
				Limit:           4,
				ApplicationID:   "appid",
				BusinessUnitIDs: []string{"did:openebl:issuer", "did:openebl:shipper", "did:openebl:consignee", "did:openebl:release_agent"},
			},
		).Return(
			storage.ListBusinessUnitsResult{
				Total: 4,
				Records: []storage.ListBusinessUnitsRecord{
					{
						BusinessUnit: model.BusinessUnit{
							ID:            did.MustParse("did:openebl:issuer"),
							Version:       1,
							ApplicationID: "appid",
							Status:        model.BusinessUnitStatusActive,
						},
					},
					{
						BusinessUnit: model.BusinessUnit{
							ID:            did.MustParse("did:openebl:shipper"),
							Version:       1,
							ApplicationID: "appid",
							Status:        model.BusinessUnitStatusActive,
						},
					},
					{
						BusinessUnit: model.BusinessUnit{
							ID:            did.MustParse("did:openebl:consignee"),
							Version:       1,
							ApplicationID: "appid",
							Status:        model.BusinessUnitStatusActive,
						},
					},
					{
						BusinessUnit: model.BusinessUnit{
							ID:            did.MustParse("did:openebl:release_agent"),
							Version:       1,
							ApplicationID: "appid",
							Status:        model.BusinessUnitStatusActive,
						},
					},
				},
			},
			nil,
		),
		s.buMgr.EXPECT().GetJWSSigner(
			gomock.Any(),
			business_unit.GetJWSSignerRequest{
				ApplicationID:    "appid",
				BusinessUnitID:   did.MustParse("did:openebl:issuer"),
				AuthenticationID: "bu_auth_id",
			},
		).Return(s.issuerSigner, nil),
		s.buMgr.EXPECT().GetJWEEncryptors(
			gomock.Any(),
			business_unit.GetJWEEncryptorsRequest{
				BusinessUnitIDs: []string{
					"did:openebl:issuer",
					"did:openebl:shipper",
					"did:openebl:consignee",
					"did:openebl:release_agent",
				},
			},
		).Return(s.encryptors, nil),
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.tdStorage.EXPECT().AddTradeDocument(gomock.Any(), s.tx, gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, tdoc storage.TradeDocument) error {
				tdOnDB = tdoc
				return nil
			},
		).Return(nil),
		s.tdStorage.EXPECT().AddTradeDocumentOutbox(gomock.Any(), s.tx, gomock.Eq(ts), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, ts int64, docID string, kind int, payload []byte) error {
				receivedOutboxKey = docID
				receivedOutboxKind = kind
				receivedOutboxPayload = payload
				return nil
			}),
		s.webhookCtrl.EXPECT().SendWebhookEvent(gomock.Any(), s.tx, ts, "appid", gomock.Any(), model.WebhookEventBLIssued).Return(nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	result, err := s.eblCtrl.Create(s.ctx, ts, req)
	s.Require().NoError(err)
	s.Assert().Equal(tdOnDB.DocID, result.BL.ID)
	s.Assert().Equal(server.GetEventID(tdOnDB.Doc), tdOnDB.RawID)
	s.Assert().EqualValues(relay.EncryptedFileBasedBillOfLading, tdOnDB.Kind)
	s.Assert().EqualValues(tdOnDB.DocVersion, result.BL.Version)
	s.Assert().EqualValues([]string{"did:openebl:issuer", "did:openebl:shipper", "did:openebl:consignee", "did:openebl:release_agent"}, tdOnDB.Meta["visible_to_bu"])
	s.Assert().EqualValues([]string{"did:openebl:shipper"}, tdOnDB.Meta["action_needed"])
	s.Assert().EqualValues([]string{"did:openebl:issuer"}, tdOnDB.Meta["sent"])
	s.Assert().EqualValues([]string{"did:openebl:consignee", "did:openebl:release_agent"}, tdOnDB.Meta["upcoming"])
	s.Assert().Empty(tdOnDB.Meta["archive"])

	// Validate the content (encrypted) can be decrypted properly.
	jwe := envelope.JWE{}
	s.Require().NoError(json.Unmarshal(tdOnDB.Doc, &jwe))
	privateKey, err := pkix.ParsePrivateKey([]byte(s.issuerAuth.PrivateKey))
	s.Require().NoError(err)
	decrypted, err := envelope.Decrypt(jwe, []any{privateKey})
	s.Require().NoError(err)
	s.Assert().Equal(tdOnDB.DecryptedDoc, decrypted)

	// Validate if tdOnDB and result are the same except the file content of result is empty.
	jws := envelope.JWS{}
	s.Require().NoError(json.Unmarshal(tdOnDB.DecryptedDoc, &jws))
	payload, err := jws.GetPayload()
	s.Require().NoError(err)
	blPackOnDB := bill_of_lading.BillOfLadingPack{}
	s.Require().NoError(json.Unmarshal(payload, &blPackOnDB))

	s.Assert().Empty(result.BL.Events[0].BillOfLading.File.Content)
	result.BL.Events[0].BillOfLading.File.Content = blPackOnDB.Events[0].BillOfLading.File.Content
	s.Assert().Equal(util.StructToJSON(result.BL), util.StructToJSON(blPackOnDB))

	// Validate the content of result (BillOfLadingPack).
	expectedBLPackJson := `{"id":"316f5f2d-eb10-4563-a0d2-45858a57ad5e","version":1,"parent_hash":"","events":[{"bill_of_lading":{"bill_of_lading":{"transportDocumentReference":"bl_number","carrierCode":"","carrierCodeListProvider":"","issuingParty":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":"did:openebl:issuer"}]},"shipmentLocations":[{"location":{"locationName":"Port of Loading","address":null,"UNLocationCode":"POL","facilityCode":"","facilityCodeListProvider":""},"shipmentLocationTypeCode":"POL"},{"location":{"locationName":"Port of Discharge","address":null,"UNLocationCode":"POD","facilityCode":"","facilityCodeListProvider":""},"shipmentLocationTypeCode":"POD","eventDateTime":"2022-01-01T00:00:00Z"}],"shippingInstruction":{"shippingInstructionReference":"","documentStatus":"ISSU","transportDocumentTypeCode":"","consignmentItems":null,"utilizedTransportEquipments":null,"documentParties":[{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":"did:openebl:issuer"}]},"partyFunction":"DDR","isToBeNotified":false},{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":"did:openebl:shipper"}]},"partyFunction":"OS","isToBeNotified":false},{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":"did:openebl:consignee"}]},"partyFunction":"CN","isToBeNotified":false},{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":"did:openebl:release_agent"}]},"partyFunction":"DDS","isToBeNotified":false}]}},"file":{"name":"test.txt","file_type":"text/plain","content":"dGVzdCBjb250ZW50","created_date":"2024-02-23T08:19:59Z"},"doc_type":"HouseBillOfLading","created_by":"did:openebl:issuer","created_at":"2024-02-23T08:19:59Z","note":"note", "metadata":{"requester":"application user"}}},{"transfer":{"transfer_by":"did:openebl:issuer","transfer_to":"did:openebl:shipper","transfer_at":"2024-02-23T08:19:59Z","metadata":{"requester":"application user"}}}],"current_owner":"did:openebl:shipper"}`
	expectedBLPack := bill_of_lading.BillOfLadingPack{}
	json.Unmarshal([]byte(expectedBLPackJson), &expectedBLPack)
	expectedBLPack.ID = result.BL.ID
	s.Assert().NotEmpty(result.BL.ID)
	s.Assert().Equal(util.StructToJSON(expectedBLPack), util.StructToJSON(result.BL))
	s.Assert().EqualValues(tdOnDB.DocID, receivedOutboxKey)
	s.Assert().EqualValues(tdOnDB.Kind, receivedOutboxKind)
	s.Assert().EqualValues(tdOnDB.Doc, receivedOutboxPayload)
}
