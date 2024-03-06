package trade_document_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did/did"
	"github.com/openebl/openebl/pkg/bu_server/business_unit"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/model/trade_document/bill_of_lading"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/bu_server/trade_document"
	"github.com/openebl/openebl/pkg/envelope"
	"github.com/openebl/openebl/pkg/relay"
	"github.com/openebl/openebl/pkg/util"
	mock_business_unit "github.com/openebl/openebl/test/mock/bu_server/business_unit"
	mock_storage "github.com/openebl/openebl/test/mock/bu_server/storage"
	"github.com/samber/lo"
	"github.com/stretchr/testify/suite"
)

type FileBasedEBLTestSuite struct {
	suite.Suite

	ctx       context.Context
	ctrl      *gomock.Controller
	tdStorage *mock_storage.MockTradeDocumentStorage
	tx        *mock_storage.MockTx
	buMgr     *mock_business_unit.MockBusinessUnitManager
	eblCtrl   trade_document.FileBaseEBLController

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

	draftEbl                storage.TradeDocument
	shipperEbl              storage.TradeDocument
	consigneeEbl            storage.TradeDocument
	releaseAgentEbl         storage.TradeDocument
	issuerEblAmentRequested storage.TradeDocument
}

const id = "316f5f2d-eb10-4563-a0d2-45858a57ad5e"

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
	s.shipperEbl = s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/shipper_ebl_jws.json")
	s.consigneeEbl = s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/consignee_ebl_jws.json")
	s.releaseAgentEbl = s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/release_agent_ebl_jws.json")
	s.issuerEblAmentRequested = s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/issuer_ebl_amendment_request_by_consignee_jws.json")

	s.issuerSigner, _ = business_unit.DefaultJWSSignerFactory.NewJWSSigner(s.issuerAuth)
	s.shipperSigner, _ = business_unit.DefaultJWSSignerFactory.NewJWSSigner(s.shipperAuth)
	s.consigneeSigner, _ = business_unit.DefaultJWSSignerFactory.NewJWSSigner(s.consigneeAuth)
	s.releaseSigner, _ = business_unit.DefaultJWSSignerFactory.NewJWSSigner(s.releaseAuth)

}

func (s *FileBasedEBLTestSuite) SetupTest() {
	s.ctx = context.Background()
	s.ctrl = gomock.NewController(s.T())
	s.tdStorage = mock_storage.NewMockTradeDocumentStorage(s.ctrl)
	s.tx = mock_storage.NewMockTx(s.ctrl)
	s.buMgr = mock_business_unit.NewMockBusinessUnitManager(s.ctrl)
	s.eblCtrl = trade_document.NewFileBaseEBLController(s.tdStorage, s.buMgr)
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
		DocID:      blPack.ID,
		DocVersion: blPack.Version,
		Doc:        raw,
	}

	return result
}

func (s *FileBasedEBLTestSuite) TestCreateEBL() {
	ts := int64(1708676399)
	eta, err := model.NewDateTimeFromString("2022-01-01T00:00:00Z")
	s.Require().NoError(err)

	req := trade_document.IssueFileBasedEBLRequest{
		Requester:        "requester",
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
		ETA:          eta,
		Shipper:      "did:openebl:shipper",
		Consignee:    "did:openebl:consignee",
		ReleaseAgent: "did:openebl:release_agent",
		Note:         "note",
		Draft:        util.Ptr(false),
	}

	var tdOnDB storage.TradeDocument
	gomock.InOrder(
		s.buMgr.EXPECT().ListBusinessUnits(
			gomock.Any(),
			business_unit.ListBusinessUnitsRequest{
				Limit:           4,
				ApplicationID:   "appid",
				BusinessUnitIDs: []string{"did:openebl:issuer", "did:openebl:shipper", "did:openebl:consignee", "did:openebl:release_agent"},
			},
		).Return(
			business_unit.ListBusinessUnitsResult{
				Total: 4,
				Records: []business_unit.ListBusinessUnitsRecord{
					{
						BusinessUnit: model.BusinessUnit{
							ID:            did.MustParseDID("did:openebl:issuer"),
							Version:       1,
							ApplicationID: "appid",
							Status:        model.BusinessUnitStatusActive,
						},
					},
					{
						BusinessUnit: model.BusinessUnit{
							ID:            did.MustParseDID("did:openebl:shipper"),
							Version:       1,
							ApplicationID: "appid",
							Status:        model.BusinessUnitStatusActive,
						},
					},
					{
						BusinessUnit: model.BusinessUnit{
							ID:            did.MustParseDID("did:openebl:consignee"),
							Version:       1,
							ApplicationID: "appid",
							Status:        model.BusinessUnitStatusActive,
						},
					},
					{
						BusinessUnit: model.BusinessUnit{
							ID:            did.MustParseDID("did:openebl:release_agent"),
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
				BusinessUnitID:   did.MustParseDID("did:openebl:issuer"),
				AuthenticationID: "bu_auth_id",
			},
		).Return(s.issuerSigner, nil),
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, nil),
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
	s.Assert().Equal(tdOnDB.DocID, result.ID)
	s.Assert().EqualValues(relay.FileBasedBillOfLading, tdOnDB.Kind)
	s.Assert().EqualValues(tdOnDB.DocVersion, result.Version)
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

	s.Assert().Empty(result.Events[0].BillOfLading.File.Content)
	result.Events[0].BillOfLading.File.Content = blPackOnDB.Events[0].BillOfLading.File.Content
	s.Assert().Equal(util.StructToJSON(result), util.StructToJSON(blPackOnDB))

	// Validate the content of result (BillOfLadingPack).
	expectedBLPackJson := `{"id":"316f5f2d-eb10-4563-a0d2-45858a57ad5e","version":1,"parent_hash":"","events":[{"bill_of_lading":{"bill_of_lading":{"transportDocumentReference":"bl_number","carrierCode":"","carrierCodeListProvider":"","issuingParty":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":"did:openebl:issuer"}]},"shipmentLocations":[{"location":{"locationName":"Port of Loading","address":null,"UNLocationCode":"POL","facilityCode":"","facilityCodeListProvider":""},"shipmentLocationTypeCode":"POL"},{"location":{"locationName":"Port of Discharge","address":null,"UNLocationCode":"POD","facilityCode":"","facilityCodeListProvider":""},"shipmentLocationTypeCode":"POD","eventDateTime":"2022-01-01T00:00:00Z"}],"shippingInstruction":{"shippingInstructionReference":"","documentStatus":"ISSU","transportDocumentTypeCode":"","consignmentItems":null,"utilizedTransportEquipments":null,"documentParties":[{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":"did:openebl:issuer"}]},"partyFunction":"DDR","isToBeNotified":false},{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":"did:openebl:shipper"}]},"partyFunction":"OS","isToBeNotified":false},{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":"did:openebl:consignee"}]},"partyFunction":"CN","isToBeNotified":false},{"party":{"partyContactDetails":null,"identifyingCodes":[{"DCSAResponsibleAgencyCode":"DID","partyCode":"did:openebl:release_agent"}]},"partyFunction":"DDS","isToBeNotified":false}]}},"file":{"name":"test.txt","file_type":"text/plain","content":"dGVzdCBjb250ZW50","created_date":"2024-02-23T08:19:59Z"},"doc_type":"HouseBillOfLading","created_by":"did:openebl:issuer","created_at":"2024-02-23T08:19:59Z","note":"note"}},{"transfer":{"transfer_by":"did:openebl:issuer","transfer_to":"did:openebl:shipper","transfer_at":"2024-02-23T08:19:59Z"}}],"current_owner":"did:openebl:shipper"}`
	expectedBLPack := bill_of_lading.BillOfLadingPack{}
	json.Unmarshal([]byte(expectedBLPackJson), &expectedBLPack)
	expectedBLPack.ID = result.ID
	s.Assert().NotEmpty(result.ID)
	s.Assert().Equal(util.StructToJSON(expectedBLPack), util.StructToJSON(result))
}

func (s *FileBasedEBLTestSuite) TestUpdateDraftEBL() {
	ts := int64(1708762799)
	eta, err := model.NewDateTimeFromString("2022-01-01T00:00:00Z")
	s.Require().NoError(err)

	req := trade_document.UpdateFileBasedEBLDraftRequest{
		ID: id,
		IssueFileBasedEBLRequest: trade_document.IssueFileBasedEBLRequest{
			Requester:        "requester",
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
			ETA:          eta,
			Shipper:      "did:openebl:shipper",
			Consignee:    "did:openebl:consignee",
			ReleaseAgent: "did:openebl:release_agent",
			Note:         "note",
			Draft:        util.Ptr(false),
		},
	}

	receivedTD := storage.TradeDocument{}

	gomock.InOrder(
		s.buMgr.EXPECT().ListBusinessUnits(
			gomock.Any(),
			business_unit.ListBusinessUnitsRequest{
				Limit:           4,
				ApplicationID:   "app_id",
				BusinessUnitIDs: []string{"did:openebl:issuer", "did:openebl:shipper", "did:openebl:consignee", "did:openebl:release_agent"},
			},
		).Return(
			business_unit.ListBusinessUnitsResult{
				Total: 4,
				Records: []business_unit.ListBusinessUnitsRecord{
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
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, nil),
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
				BusinessUnitID:   did.MustParseDID(req.Issuer),
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

	expectedBlPack := func() bill_of_lading.BillOfLadingPack {
		td := s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/shipper_ebl_jws.json")
		res, err := trade_document.ExtractBLPackFromTradeDocument(td)
		s.Require().NoError(err)
		return res
	}()
	blPack, err := s.eblCtrl.UpdateDraft(s.ctx, ts, req)
	s.Require().NoError(err)
	receivedBLPack, err := trade_document.ExtractBLPackFromTradeDocument(receivedTD)
	s.Require().NoError(err)
	s.Assert().Empty(blPack.Events[0].BillOfLading.File.Content)
	blPack.Events[0].BillOfLading.File.Content = receivedBLPack.Events[0].BillOfLading.File.Content
	s.Assert().EqualValues(util.StructToJSON(receivedBLPack), util.StructToJSON(blPack))
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(receivedBLPack))
}

func (s *FileBasedEBLTestSuite) TestListEBL() {
	req := trade_document.ListFileBasedEBLRequest{
		Application: "appid",
		Lister:      "did:openebl:issuer",
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
			business_unit.ListBusinessUnitsRequest{
				Limit:           1,
				ApplicationID:   "appid",
				BusinessUnitIDs: []string{"did:openebl:issuer"},
			},
		).Return(
			business_unit.ListBusinessUnitsResult{
				Total: 1,
				Records: []business_unit.ListBusinessUnitsRecord{
					{
						BusinessUnit: model.BusinessUnit{
							ID:            did.MustParseDID("did:openebl:issuer"),
							Version:       1,
							ApplicationID: "appid",
							Status:        model.BusinessUnitStatusActive,
						},
					},
				},
			},
			nil,
		),
		s.tdStorage.EXPECT().CreateTx(gomock.Any()).Return(s.tx, nil),
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
	s.Assert().Empty(result.Records[0].Events[0].BillOfLading.File.Content)
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(result.Records[0]))
}

func (s *FileBasedEBLTestSuite) TestTransferEBL() {
	ts := int64(1709529502)

	req := trade_document.TransferEBLRequest{
		Requester:        "requester",
		Application:      "app_id",
		TransferBy:       "did:openebl:shipper",
		AuthenticationID: "shipper_auth1",
		ID:               id,
		Note:             "note",
	}

	receivedTD := storage.TradeDocument{}

	gomock.InOrder(
		s.buMgr.EXPECT().ListBusinessUnits(
			gomock.Any(),
			business_unit.ListBusinessUnitsRequest{
				Limit:           1,
				ApplicationID:   "app_id",
				BusinessUnitIDs: []string{"did:openebl:shipper"},
			},
		).Return(
			business_unit.ListBusinessUnitsResult{
				Total:   1,
				Records: []business_unit.ListBusinessUnitsRecord{{BusinessUnit: s.shipper}},
			}, nil,
		),
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, nil),
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
				BusinessUnitID:   did.MustParseDID("did:openebl:shipper"),
				AuthenticationID: "shipper_auth1",
			},
		).Return(s.shipperSigner, nil),
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
		td := s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/consignee_ebl_jws.json")
		res, err := trade_document.ExtractBLPackFromTradeDocument(td)
		s.Require().NoError(err)
		return res
	}()

	blPack, err := s.eblCtrl.Transfer(s.ctx, ts, req)
	s.Require().NoError(err)
	receivedBLPack, err := trade_document.ExtractBLPackFromTradeDocument(receivedTD)
	s.Require().NoError(err)
	s.Assert().Empty(blPack.Events[0].BillOfLading.File.Content)
	blPack.Events[0].BillOfLading.File.Content = receivedBLPack.Events[0].BillOfLading.File.Content
	s.Assert().EqualValues(util.StructToJSON(receivedBLPack), util.StructToJSON(blPack))
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(receivedBLPack))
}

func (s *FileBasedEBLTestSuite) TestTransferEBL_ActionNotAllowed() {
	ts := int64(1709529502)

	req := trade_document.TransferEBLRequest{
		Requester:        "requester",
		Application:      "app_id",
		TransferBy:       "did:openebl:shipper",
		AuthenticationID: "shipper_auth1",
		ID:               id,
		Note:             "note",
	}

	gomock.InOrder(
		s.buMgr.EXPECT().ListBusinessUnits(
			gomock.Any(),
			business_unit.ListBusinessUnitsRequest{
				Limit:           1,
				ApplicationID:   "app_id",
				BusinessUnitIDs: []string{"did:openebl:shipper"},
			},
		).Return(
			business_unit.ListBusinessUnitsResult{
				Total:   1,
				Records: []business_unit.ListBusinessUnitsRecord{{BusinessUnit: s.shipper}},
			}, nil,
		),
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, nil),
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
		Requester:        "requester",
		Application:      "app_id",
		RequestBy:        "did:openebl:consignee",
		AuthenticationID: "consignee_auth1",
		ID:               id,
		Note:             "amendment request note",
	}

	receivedTD := storage.TradeDocument{}

	gomock.InOrder(
		s.buMgr.EXPECT().ListBusinessUnits(
			gomock.Any(),
			business_unit.ListBusinessUnitsRequest{
				Limit:           1,
				ApplicationID:   "app_id",
				BusinessUnitIDs: []string{"did:openebl:consignee"},
			},
		).Return(
			business_unit.ListBusinessUnitsResult{
				Total:   1,
				Records: []business_unit.ListBusinessUnitsRecord{{BusinessUnit: s.consignee}},
			}, nil,
		),
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, nil),
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
				BusinessUnitID:   did.MustParseDID("did:openebl:consignee"),
				AuthenticationID: "consignee_auth1",
			},
		).Return(s.consigneeSigner, nil),
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
		td := s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/issuer_ebl_amendment_request_by_consignee_jws.json")
		res, err := trade_document.ExtractBLPackFromTradeDocument(td)
		s.Require().NoError(err)
		return res
	}()

	blPack, err := s.eblCtrl.AmendmentRequest(s.ctx, ts, req)
	s.Require().NoError(err)
	receivedBLPack, err := trade_document.ExtractBLPackFromTradeDocument(receivedTD)
	s.Require().NoError(err)
	s.Assert().Empty(blPack.Events[0].BillOfLading.File.Content)
	blPack.Events[0].BillOfLading.File.Content = receivedBLPack.Events[0].BillOfLading.File.Content
	s.Assert().EqualValues(util.StructToJSON(receivedBLPack), util.StructToJSON(blPack))
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(receivedBLPack))
}

func (s *FileBasedEBLTestSuite) TestAmendmentRequestEBL_ActionNotAllowed() {
	ts := int64(1709546001)

	req := trade_document.AmendmentRequestEBLRequest{
		Requester:        "requester",
		Application:      "app_id",
		RequestBy:        "did:openebl:issuer",
		AuthenticationID: "issuer_auth1",
		ID:               id,
		Note:             "amendment request note",
	}

	gomock.InOrder(
		s.buMgr.EXPECT().ListBusinessUnits(
			gomock.Any(),
			business_unit.ListBusinessUnitsRequest{
				Limit:           1,
				ApplicationID:   "app_id",
				BusinessUnitIDs: []string{"did:openebl:issuer"},
			},
		).Return(
			business_unit.ListBusinessUnitsResult{
				Total:   1,
				Records: []business_unit.ListBusinessUnitsRecord{{BusinessUnit: s.issuer}},
			}, nil,
		),
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, nil),
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
		Requester:        "requester",
		Application:      "app_id",
		BusinessUnit:     "did:openebl:consignee",
		AuthenticationID: "consignee_auth1",
		ID:               "316f5f2d-eb10-4563-a0d2-45858a57ad5e",
		Note:             "Return the ownership back to the shipper",
	}

	var receivedTD storage.TradeDocument
	gomock.InOrder(
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, nil),
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
				BusinessUnitID:   did.MustParseDID("did:openebl:consignee"),
				AuthenticationID: "consignee_auth1",
			},
		).Return(s.consigneeSigner, nil),
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
		td := s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/return_to_shipper_ebl_jws.json")
		res, err := trade_document.ExtractBLPackFromTradeDocument(td)
		s.Require().NoError(err)
		return res
	}()

	result, err := s.eblCtrl.Return(s.ctx, ts, req)
	s.Require().NoError(err)
	s.Assert().Empty(result.Events[0].BillOfLading.File.Content)
	result.Events[0].BillOfLading.File.Content = expectedBlPack.Events[0].BillOfLading.File.Content
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(result))
	receivedBLBlock, err := trade_document.ExtractBLPackFromTradeDocument(receivedTD)
	s.Require().NoError(err)
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(receivedBLBlock))
}

func (s *FileBasedEBLTestSuite) TestReturnAmentRequest() {
	ts := int64(1709615902)

	req := trade_document.ReturnFileBasedEBLRequest{
		Requester:        "requester",
		Application:      "app_id",
		BusinessUnit:     "did:openebl:issuer",
		AuthenticationID: "issuer_auth1",
		ID:               "316f5f2d-eb10-4563-a0d2-45858a57ad5e",
		Note:             "Return the ownership back to the ament requester (consignee in this case)",
	}

	var receivedTD storage.TradeDocument
	gomock.InOrder(
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, nil),
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
				Docs:  []storage.TradeDocument{s.issuerEblAmentRequested},
			},
			nil,
		),
		s.buMgr.EXPECT().GetJWSSigner(
			gomock.Any(),
			business_unit.GetJWSSignerRequest{
				ApplicationID:    "app_id",
				BusinessUnitID:   did.MustParseDID("did:openebl:issuer"),
				AuthenticationID: "issuer_auth1",
			},
		).Return(s.consigneeSigner, nil),
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
		td := s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/return_to_consignee_ebl_jws.json")
		res, err := trade_document.ExtractBLPackFromTradeDocument(td)
		s.Require().NoError(err)
		return res
	}()

	result, err := s.eblCtrl.Return(s.ctx, ts, req)
	s.Require().NoError(err)
	s.Assert().Empty(result.Events[0].BillOfLading.File.Content)
	result.Events[0].BillOfLading.File.Content = expectedBlPack.Events[0].BillOfLading.File.Content
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(result))
	receivedBLBlock, err := trade_document.ExtractBLPackFromTradeDocument(receivedTD)
	s.Require().NoError(err)
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(receivedBLBlock))
}

func (s *FileBasedEBLTestSuite) TestAmendEBL() {
	ts := int64(1709613375)
	eta, err := model.NewDateTimeFromString("2024-03-30T00:00:00Z")
	s.Require().NoError(err)

	req := trade_document.AmendFileBasedEBLRequest{
		Requester:        "requester",
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
		ETA:  eta,
		Note: "amended by issuer",
	}

	receivedTD := storage.TradeDocument{}

	gomock.InOrder(
		s.buMgr.EXPECT().ListBusinessUnits(
			gomock.Any(),
			business_unit.ListBusinessUnitsRequest{
				Limit:           1,
				ApplicationID:   "app_id",
				BusinessUnitIDs: []string{"did:openebl:issuer"},
			},
		).Return(
			business_unit.ListBusinessUnitsResult{
				Total:   1,
				Records: []business_unit.ListBusinessUnitsRecord{{BusinessUnit: s.issuer}},
			}, nil,
		),
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, nil),
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
				Docs:  []storage.TradeDocument{s.issuerEblAmentRequested},
			},
			nil,
		),
		s.buMgr.EXPECT().GetJWSSigner(
			gomock.Any(),
			business_unit.GetJWSSignerRequest{
				ApplicationID:    "app_id",
				BusinessUnitID:   did.MustParseDID("did:openebl:issuer"),
				AuthenticationID: "issuer_auth1",
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

	lo.ForEach(blPack.Events, func(event bill_of_lading.BillOfLadingEvent, i int) {
		if event.BillOfLading != nil {
			s.Assert().Empty(event.BillOfLading.File.Content)
			event.BillOfLading.File.Content = receivedBLPack.Events[i].BillOfLading.File.Content
		}
	})
	s.Assert().EqualValues(util.StructToJSON(receivedBLPack), util.StructToJSON(blPack))
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(receivedBLPack))
}

func (s *FileBasedEBLTestSuite) TestSurrender() {
	ts := int64(1709615902)

	req := trade_document.SurrenderEBLRequest{
		Requester:        "requester",
		Application:      "app_id",
		RequestBy:        "did:openebl:consignee",
		AuthenticationID: "consignee_auth1",
		ID:               "316f5f2d-eb10-4563-a0d2-45858a57ad5e",
		Note:             "Surrender the eBL to the release agent",
	}

	var receivedTD storage.TradeDocument
	gomock.InOrder(
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, nil),
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
				BusinessUnitID:   did.MustParseDID("did:openebl:consignee"),
				AuthenticationID: "consignee_auth1",
			},
		).Return(s.shipperSigner, nil),
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
		td := s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/release_agent_ebl_jws.json")
		res, err := trade_document.ExtractBLPackFromTradeDocument(td)
		s.Require().NoError(err)
		return res
	}()

	result, err := s.eblCtrl.Surrender(s.ctx, ts, req)
	s.Require().NoError(err)
	s.Assert().Empty(result.Events[0].BillOfLading.File.Content)
	result.Events[0].BillOfLading.File.Content = expectedBlPack.Events[0].BillOfLading.File.Content
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(result))
	receivedBLBlock, err := trade_document.ExtractBLPackFromTradeDocument(receivedTD)
	s.Require().NoError(err)
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(receivedBLBlock))
}

func (s *FileBasedEBLTestSuite) TestPrintToPaper() {
	ts := int64(1709615902)

	req := trade_document.PrintFileBasedEBLToPaperRequest{
		Requester:        "requester",
		Application:      "app_id",
		RequestBy:        "did:openebl:consignee",
		AuthenticationID: "consignee_auth1",
		ID:               "316f5f2d-eb10-4563-a0d2-45858a57ad5e",
		Note:             "Print the eBL",
	}

	var receivedTD storage.TradeDocument
	gomock.InOrder(
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, nil),
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
				BusinessUnitID:   did.MustParseDID("did:openebl:consignee"),
				AuthenticationID: "consignee_auth1",
			},
		).Return(s.shipperSigner, nil),
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
		td := s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/consignee_printed_ebl_jws.json")
		res, err := trade_document.ExtractBLPackFromTradeDocument(td)
		s.Require().NoError(err)
		return res
	}()

	result, err := s.eblCtrl.PrintToPaper(s.ctx, ts, req)
	s.Require().NoError(err)
	s.Assert().Empty(result.Events[0].BillOfLading.File.Content)
	result.Events[0].BillOfLading.File.Content = expectedBlPack.Events[0].BillOfLading.File.Content
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(result))
	receivedBLBlock, err := trade_document.ExtractBLPackFromTradeDocument(receivedTD)
	s.Require().NoError(err)
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(receivedBLBlock))
}

func (s *FileBasedEBLTestSuite) TestAccomplishEBL() {
	ts := int64(1709696923)

	req := trade_document.AccomplishEBLRequest{
		Requester:        "requester",
		Application:      "app_id",
		RequestBy:        "did:openebl:release_agent",
		AuthenticationID: "release_agent_auth1",
		ID:               id,
		Note:             "accomplished by release agent",
	}

	var receivedTD storage.TradeDocument
	gomock.InOrder(
		s.tdStorage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, nil),
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
				BusinessUnitID:   did.MustParseDID("did:openebl:release_agent"),
				AuthenticationID: "release_agent_auth1",
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
		td := s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/release_agent_accomplished_ebl_jws.json")
		res, err := trade_document.ExtractBLPackFromTradeDocument(td)
		s.Require().NoError(err)
		return res
	}()

	result, err := s.eblCtrl.Accomplish(s.ctx, ts, req)
	s.Require().NoError(err)
	s.Assert().Empty(result.Events[0].BillOfLading.File.Content)
	result.Events[0].BillOfLading.File.Content = expectedBlPack.Events[0].BillOfLading.File.Content
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(result))
	receivedBLBlock, err := trade_document.ExtractBLPackFromTradeDocument(receivedTD)
	s.Require().NoError(err)
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(receivedBLBlock))
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
			business_unit.ListBusinessUnitsRequest{
				Limit:           1,
				ApplicationID:   "appid",
				BusinessUnitIDs: []string{"did:openebl:requester"},
			},
		).Return(
			business_unit.ListBusinessUnitsResult{
				Total: 1,
				Records: []business_unit.ListBusinessUnitsRecord{
					{
						BusinessUnit: model.BusinessUnit{
							ID:            did.MustParseDID("did:openebl:requester"),
							Version:       1,
							ApplicationID: "appid",
							Status:        model.BusinessUnitStatusActive,
						},
					},
				},
			},
			nil,
		),
		s.tdStorage.EXPECT().CreateTx(gomock.Any()).Return(s.tx, nil),
		s.tdStorage.EXPECT().ListTradeDocument(gomock.Any(), s.tx, gomock.Eq(listReq)).Return(listResp, nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	expectedBlPack := func() bill_of_lading.BillOfLadingPack {
		td := s.loadTradeDocument("../../../testdata/bu_server/trade_document/file_based_ebl/shipper_ebl_jws.json")
		res, err := trade_document.ExtractBLPackFromTradeDocument(td)
		s.Require().NoError(err)
		res.Events[0].BillOfLading.File.Content = nil
		return res
	}()

	result, err := s.eblCtrl.Get(s.ctx, req)
	s.Require().NoError(err)
	s.Assert().EqualValues(util.StructToJSON(expectedBlPack), util.StructToJSON(result))
}
