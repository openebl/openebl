package trade_document_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openebl/openebl/pkg/bu_server/business_unit"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/model/trade_document/bill_of_lading"
	"github.com/openebl/openebl/pkg/bu_server/model/trade_document/bill_of_lading/dcsa_v3"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/bu_server/trade_document"
	"github.com/openebl/openebl/pkg/did"
	"github.com/openebl/openebl/pkg/envelope"
	"github.com/openebl/openebl/pkg/relay"
	"github.com/openebl/openebl/pkg/util"
	mock_business_unit "github.com/openebl/openebl/test/mock/bu_server/business_unit"
	mock_storage "github.com/openebl/openebl/test/mock/bu_server/storage"
	mock_webhook "github.com/openebl/openebl/test/mock/bu_server/webhook"
	"github.com/samber/lo"
	"github.com/stretchr/testify/suite"
)

type FileBasedEBLNegotiableTestSuite struct {
	suite.Suite

	ctx context.Context

	ctrl        *gomock.Controller
	storage     *mock_storage.MockTradeDocumentStorage
	tx          *mock_storage.MockTx
	buCtrl      *mock_business_unit.MockBusinessUnitManager
	webHookCtrl *mock_webhook.MockWebhookController
	signer      *mock_business_unit.MockJWSSigner

	eblCtrl trade_document.FileBaseEBLController
}

func TestFileBasedEBLNegotiable(t *testing.T) {
	suite.Run(t, new(FileBasedEBLNegotiableTestSuite))
}

func (s *FileBasedEBLNegotiableTestSuite) SetupTest() {
	s.ctx = context.Background()
	s.ctrl = gomock.NewController(s.T())
	s.storage = mock_storage.NewMockTradeDocumentStorage(s.ctrl)
	s.tx = mock_storage.NewMockTx(s.ctrl)
	s.buCtrl = mock_business_unit.NewMockBusinessUnitManager(s.ctrl)
	s.webHookCtrl = mock_webhook.NewMockWebhookController(s.ctrl)
	s.signer = mock_business_unit.NewMockJWSSigner(s.ctrl)
	s.eblCtrl = trade_document.NewFileBaseEBLController(s.storage, s.buCtrl, s.webHookCtrl)
}

func (s *FileBasedEBLNegotiableTestSuite) TearDownTest() {
	s.ctrl.Finish()
}

func (s *FileBasedEBLNegotiableTestSuite) TestEBLAllowActions() {
	blEvent := bill_of_lading.BillOfLadingEvent{
		BillOfLading: &bill_of_lading.BillOfLading{
			BillOfLadingV3: &dcsa_v3.TransportDocument{
				TransportDocumentStatus:    trade_document.ISSUED,
				TransportDocumentReference: "bl_number",
				IsToOrder:                  true,
				DocumentParties: dcsa_v3.DocumentParties{
					IssuingParty: dcsa_v3.IssuingParty{
						IdentifyingCodes: &[]dcsa_v3.IdentifyingCode{
							{
								PartyCode: "did:openebl:issuer",
							},
						},
					},
					Shipper: dcsa_v3.Shipper{
						IdentifyingCodes: &[]dcsa_v3.IdentifyingCode{
							{
								PartyCode: "did:openebl:shipper",
							},
						},
					},
					Consignee: &dcsa_v3.Consignee{
						IdentifyingCodes: []dcsa_v3.IdentifyingCode{
							{
								PartyCode: "did:openebl:consignee",
							},
						},
					},
					Endorsee: &dcsa_v3.Endorsee{
						IdentifyingCodes: []dcsa_v3.IdentifyingCode{
							{
								PartyCode: "did:openebl:endorsee",
							},
						},
					},
					Other: &[]dcsa_v3.OtherDocumentParty{
						{
							Party: dcsa_v3.Party{
								IdentifyingCodes: &[]dcsa_v3.IdentifyingCode{
									{

										PartyCode: "did:openebl:release_agent",
									},
								},
							},
							PartyFunction: "DDS", // Consignee's freight forwarder
						},
					},
				},
			},
			DocType: bill_of_lading.BillOfLadingDocumentTypeHouseBillOfLading,
			File: &model.File{
				Name:     "bl.pdf",
				FileType: "plain/text",
				Content:  []byte("test content"),
			},
		},
	}
	type TestCase struct {
		Name                     string
		BLPack                   *bill_of_lading.BillOfLadingPack
		ConsigneeAllowActions    []trade_document.FileBasedEBLAction
		EndorseeAllowActions     []trade_document.FileBasedEBLAction
		ReleaseAgentAllowActions []trade_document.FileBasedEBLAction
	}

	testCases := []TestCase{
		{
			Name: "Negotiable BL owned by Consignee",
			BLPack: &bill_of_lading.BillOfLadingPack{
				Events: []bill_of_lading.BillOfLadingEvent{
					blEvent,
					{
						Transfer: &bill_of_lading.Transfer{
							TransferBy: "did:openebl:shipper",
							TransferTo: "did:openebl:consignee",
						},
					},
				},
			},
			ConsigneeAllowActions: []trade_document.FileBasedEBLAction{
				trade_document.FILE_EBL_REQUEST_AMEND,
				trade_document.FILE_EBL_PRINT,
				trade_document.FILE_EBL_TRANSFER,
				trade_document.FILE_EBL_RETURN,
				trade_document.FILE_EBL_SURRENDER,
			},
		},
		{
			Name: "Negotiable BL owned by Endorsee",
			BLPack: &bill_of_lading.BillOfLadingPack{
				Events: []bill_of_lading.BillOfLadingEvent{
					blEvent,
					{
						Transfer: &bill_of_lading.Transfer{
							TransferBy: "did:openebl:consignee",
							TransferTo: "did:openebl:endorsee",
						},
					},
				},
			},
			EndorseeAllowActions: []trade_document.FileBasedEBLAction{
				trade_document.FILE_EBL_REQUEST_AMEND,
				trade_document.FILE_EBL_PRINT,
				trade_document.FILE_EBL_RETURN,
				trade_document.FILE_EBL_SURRENDER,
			},
		},
		{
			Name: "Negotiable BL surrendered by Consignee to Release Agent",
			BLPack: &bill_of_lading.BillOfLadingPack{
				Events: []bill_of_lading.BillOfLadingEvent{
					blEvent,
					{
						Surrender: &bill_of_lading.Surrender{
							SurrenderBy: "did:openebl:consignee",
							SurrenderTo: "did:openebl:release_agent",
						},
					},
				},
			},
			ReleaseAgentAllowActions: []trade_document.FileBasedEBLAction{
				trade_document.FILE_EBL_REQUEST_AMEND,
				trade_document.FILE_EBL_PRINT,
				trade_document.FILE_EBL_RETURN,
				trade_document.FILE_EBL_ACCOMPLISH,
			},
		},
		{
			Name: "Negotiable BL surrendered by Endorsee to Release Agent",
			BLPack: &bill_of_lading.BillOfLadingPack{
				Events: []bill_of_lading.BillOfLadingEvent{
					blEvent,
					{
						Surrender: &bill_of_lading.Surrender{
							SurrenderBy: "did:openebl:endorsee",
							SurrenderTo: "did:openebl:release_agent",
						},
					},
				},
			},
			ReleaseAgentAllowActions: []trade_document.FileBasedEBLAction{
				trade_document.FILE_EBL_REQUEST_AMEND,
				trade_document.FILE_EBL_PRINT,
				trade_document.FILE_EBL_RETURN,
				trade_document.FILE_EBL_ACCOMPLISH,
			},
		},
	}

	for _, tc := range testCases {
		s.Run(tc.Name, func() {
			s.Require().ElementsMatch(tc.ConsigneeAllowActions, trade_document.GetFileBasedEBLAllowActions(tc.BLPack, "did:openebl:consignee"))
			s.Require().ElementsMatch(tc.EndorseeAllowActions, trade_document.GetFileBasedEBLAllowActions(tc.BLPack, "did:openebl:endorsee"))
			s.Require().ElementsMatch(tc.ReleaseAgentAllowActions, trade_document.GetFileBasedEBLAllowActions(tc.BLPack, "did:openebl:release_agent"))
		})
	}
}

func (s *FileBasedEBLNegotiableTestSuite) TestIssueNegotiableHBL() {
	const appID = "app_id"

	ts := time.Now().Unix()

	req := trade_document.IssueFileBasedEBLRequest{
		Application:      appID,
		Issuer:           "did:openebl:issuer",
		AuthenticationID: "issuer_auth_id",
		File: trade_document.File{
			Name:    "test.txt",
			Type:    "text/plain",
			Content: []byte("test content"),
		},
		BLNumber:  "bl_number",
		BLDocType: bill_of_lading.BillOfLadingDocumentTypeHouseBillOfLading,
		ToOrder:   true,
		POL: &trade_document.Location{
			LocationName: "Port of Loading",
			UNLocCode:    "POL",
		},
		POD: &trade_document.Location{
			LocationName: "Port of Discharge",
			UNLocCode:    "POD",
		},
		ETA:          lo.ToPtr(model.NewDateFromStringNoError("2024-02-26")),
		Shipper:      "did:openebl:shipper",
		Consignee:    "did:openebl:consignee",
		Endorsee:     "did:openebl:endorsee",
		ReleaseAgent: "did:openebl:release_agent",
		NotifyParties: []string{
			"did:openebl:notify_party1",
			"did:openebl:notify_party2",
			"did:openebl:notify_party3",
		},
		Note:           "note",
		Draft:          lo.ToPtr(false),
		EncryptContent: false,
	}

	var catchedTD storage.TradeDocument
	gomock.InOrder(
		s.buCtrl.EXPECT().ListBusinessUnits(
			gomock.Any(),
			storage.ListBusinessUnitsRequest{
				Limit:         8,
				ApplicationID: appID,
				BusinessUnitIDs: []string{
					"did:openebl:issuer",
					"did:openebl:shipper",
					"did:openebl:consignee",
					"did:openebl:endorsee",
					"did:openebl:release_agent",
					"did:openebl:notify_party1",
					"did:openebl:notify_party2",
					"did:openebl:notify_party3",
				},
			},
		).DoAndReturn(func(ctx context.Context, req storage.ListBusinessUnitsRequest) (storage.ListBusinessUnitsResult, error) {
			result := storage.ListBusinessUnitsResult{}
			result.Records = lo.Map(req.BusinessUnitIDs, func(id string, _ int) storage.ListBusinessUnitsRecord {
				return storage.ListBusinessUnitsRecord{
					BusinessUnit: model.BusinessUnit{
						ID:            did.MustParse(id),
						Version:       1,
						ApplicationID: appID,
						Status:        model.BusinessUnitStatusActive,
					},
				}
			})
			return result, nil
		}),
		s.buCtrl.EXPECT().GetJWSSigner(gomock.Any(), business_unit.GetJWSSignerRequest{
			ApplicationID:    appID,
			BusinessUnitID:   did.MustParse("did:openebl:issuer"),
			AuthenticationID: "issuer_auth_id",
		}).Return(s.signer, nil),
		s.signer.EXPECT().AvailableJWSSignAlgorithms().Return([]envelope.SignatureAlgorithm{envelope.SignatureAlgorithm(jwa.RS256)}),
		s.signer.EXPECT().Cert().Return([]*x509.Certificate{{}}),
		s.signer.EXPECT().Sign(gomock.Any(), gomock.Any(), gomock.Any()).Return([]byte("signature"), nil),
		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().AddTradeDocument(gomock.Any(), s.tx, gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, tradeDoc storage.TradeDocument) error {
				catchedTD = tradeDoc
				return nil
			},
		),
		s.storage.EXPECT().AddTradeDocumentOutbox(gomock.Any(), s.tx, gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, ts int64, key string, kind int, payload []byte) error {
				return nil
			},
		),
		s.webHookCtrl.EXPECT().SendWebhookEvent(gomock.Any(), s.tx, ts, appID, gomock.Any(), model.WebhookEventBLIssued).Return(nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	result, err := s.eblCtrl.Create(s.ctx, ts, req)
	s.Require().NoError(err)

	// Verify TradeDocument
	s.Assert().Equal(catchedTD.DocID, result.BL.ID)
	s.Assert().EqualValues(relay.FileBasedBillOfLading, catchedTD.Kind)
	s.Assert().EqualValues(catchedTD.DocVersion, result.BL.Version)
	s.Assert().EqualValues([]string{"did:openebl:issuer", "did:openebl:shipper", "did:openebl:consignee", "did:openebl:endorsee", "did:openebl:release_agent", "did:openebl:notify_party1", "did:openebl:notify_party2", "did:openebl:notify_party3"}, catchedTD.Meta["visible_to_bu"])
	s.Assert().EqualValues([]string{"did:openebl:shipper"}, catchedTD.Meta["action_needed"])
	s.Assert().EqualValues([]string{"did:openebl:issuer"}, catchedTD.Meta["sent"])
	s.Assert().EqualValues([]string{"did:openebl:consignee", "did:openebl:endorsee", "did:openebl:release_agent"}, catchedTD.Meta["upcoming"])
	s.Assert().Empty(catchedTD.Meta["archive"])

	// Extract BillOfLadingPack from the data on DB.
	jws := envelope.JWS{}
	s.Require().NoError(json.Unmarshal(catchedTD.Doc, &jws))
	payload, err := jws.GetPayload()
	s.Require().NoError(err)
	blPackOnDB := bill_of_lading.BillOfLadingPack{}
	s.Require().NoError(json.Unmarshal(payload, &blPackOnDB))
	s.Require().Equal("test content", string(blPackOnDB.Events[0].BillOfLading.File.Content))
	result.BL.Events[0].BillOfLading.File.Content = blPackOnDB.Events[0].BillOfLading.File.Content

	// Verify result
	s.Assert().Equal(util.StructToJSON(blPackOnDB), util.StructToJSON(*result.BL))
	parties := trade_document.GetFileBaseEBLParticipatorsFromBLPack(&blPackOnDB)
	expectedParties := trade_document.FileBaseEBLParticipators{
		Issuer:        "did:openebl:issuer",
		Shipper:       "did:openebl:shipper",
		Consignee:     "did:openebl:consignee",
		Endorsee:      "did:openebl:endorsee",
		ReleaseAgent:  "did:openebl:release_agent",
		NotifyParties: []string{"did:openebl:notify_party1", "did:openebl:notify_party2", "did:openebl:notify_party3"},
	}
	s.Assert().Equal(expectedParties, parties)
}

func (s *FileBasedEBLNegotiableTestSuite) TestIssueNegotiableHBLFromDraft() {
	const appID = "app_id"

	ts := time.Now().Unix()
	oldBLPack := bill_of_lading.BillOfLadingPack{
		ID:      "doc_id",
		Version: 1,
		Events: []bill_of_lading.BillOfLadingEvent{
			{
				BillOfLading: &bill_of_lading.BillOfLading{
					BillOfLadingV3: &dcsa_v3.TransportDocument{
						TransportDocumentStatus: trade_document.DRAFT,
						DocumentParties: dcsa_v3.DocumentParties{
							IssuingParty: dcsa_v3.IssuingParty{
								IdentifyingCodes: &[]dcsa_v3.IdentifyingCode{
									{
										PartyCode: "did:openebl:issuer",
									},
								},
							},
						},
					},
					DocType: bill_of_lading.BillOfLadingDocumentTypeHouseBillOfLading,
				},
			},
		},
		CurrentOwner: "did:openebl:issuer",
	}
	oldBLPackJson, _ := json.Marshal(oldBLPack)
	oldBLJWS := envelope.JWS{
		Payload: envelope.Base64URLEncode(oldBLPackJson),
	}

	req := trade_document.UpdateFileBasedEBLDraftRequest{
		ID: "doc_id",
		IssueFileBasedEBLRequest: trade_document.IssueFileBasedEBLRequest{
			Application:      appID,
			Issuer:           "did:openebl:issuer",
			AuthenticationID: "issuer_auth_id",
			File: trade_document.File{
				Name:    "test.txt",
				Type:    "text/plain",
				Content: []byte("test content"),
			},
			BLNumber:  "bl_number",
			BLDocType: bill_of_lading.BillOfLadingDocumentTypeHouseBillOfLading,
			ToOrder:   true,
			POL: &trade_document.Location{
				LocationName: "Port of Loading",
				UNLocCode:    "POL",
			},
			POD: &trade_document.Location{
				LocationName: "Port of Discharge",
				UNLocCode:    "POD",
			},
			ETA:          lo.ToPtr(model.NewDateFromStringNoError("2024-02-26")),
			Shipper:      "did:openebl:shipper",
			Consignee:    "did:openebl:consignee",
			Endorsee:     "did:openebl:endorsee",
			ReleaseAgent: "did:openebl:release_agent",
			NotifyParties: []string{
				"did:openebl:notify_party1",
				"did:openebl:notify_party2",
				"did:openebl:notify_party3",
			},
			Note:           "note",
			Draft:          lo.ToPtr(false),
			EncryptContent: false,
		},
	}

	var catchedTD storage.TradeDocument
	gomock.InOrder(
		s.buCtrl.EXPECT().ListBusinessUnits(
			gomock.Any(),
			storage.ListBusinessUnitsRequest{
				Limit:         8,
				ApplicationID: appID,
				BusinessUnitIDs: []string{
					"did:openebl:issuer",
					"did:openebl:shipper",
					"did:openebl:consignee",
					"did:openebl:endorsee",
					"did:openebl:release_agent",
					"did:openebl:notify_party1",
					"did:openebl:notify_party2",
					"did:openebl:notify_party3",
				},
			},
		).DoAndReturn(func(ctx context.Context, req storage.ListBusinessUnitsRequest) (storage.ListBusinessUnitsResult, error) {
			result := storage.ListBusinessUnitsResult{}
			result.Records = lo.Map(req.BusinessUnitIDs, func(id string, _ int) storage.ListBusinessUnitsRecord {
				return storage.ListBusinessUnitsRecord{
					BusinessUnit: model.BusinessUnit{
						ID:            did.MustParse(id),
						Version:       1,
						ApplicationID: appID,
						Status:        model.BusinessUnitStatusActive,
					},
				}
			})
			return result, nil
		}),
		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().ListTradeDocument(
			gomock.Any(),
			s.tx,
			storage.ListTradeDocumentRequest{
				Limit:  1,
				DocIDs: []string{req.ID},
			},
		).Return(
			storage.ListTradeDocumentResponse{
				Total: 1,
				Docs: []storage.TradeDocument{
					{
						Kind: int(relay.FileBasedBillOfLading),
						Doc:  []byte(util.StructToJSON(oldBLJWS)),
					},
				},
			},
			nil,
		),
		s.buCtrl.EXPECT().GetJWSSigner(gomock.Any(), business_unit.GetJWSSignerRequest{
			ApplicationID:    appID,
			BusinessUnitID:   did.MustParse("did:openebl:issuer"),
			AuthenticationID: "issuer_auth_id",
		}).Return(s.signer, nil),
		s.signer.EXPECT().AvailableJWSSignAlgorithms().Return([]envelope.SignatureAlgorithm{envelope.SignatureAlgorithm(jwa.RS256)}),
		s.signer.EXPECT().Cert().Return([]*x509.Certificate{{}}),
		s.signer.EXPECT().Sign(gomock.Any(), gomock.Any(), gomock.Any()).Return([]byte("signature"), nil),
		s.storage.EXPECT().AddTradeDocument(gomock.Any(), s.tx, gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, tradeDoc storage.TradeDocument) error {
				catchedTD = tradeDoc
				return nil
			},
		),
		s.storage.EXPECT().AddTradeDocumentOutbox(gomock.Any(), s.tx, gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, ts int64, key string, kind int, payload []byte) error {
				return nil
			},
		),
		s.webHookCtrl.EXPECT().SendWebhookEvent(gomock.Any(), s.tx, ts, appID, gomock.Any(), model.WebhookEventBLIssued).Return(nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	result, err := s.eblCtrl.UpdateDraft(s.ctx, ts, req)
	s.Require().NoError(err)

	// Verify TradeDocument
	s.Assert().Equal(catchedTD.DocID, result.BL.ID)
	s.Assert().EqualValues(relay.FileBasedBillOfLading, catchedTD.Kind)
	s.Assert().EqualValues(catchedTD.DocVersion, result.BL.Version)
	s.Assert().EqualValues([]string{"did:openebl:issuer", "did:openebl:shipper", "did:openebl:consignee", "did:openebl:endorsee", "did:openebl:release_agent", "did:openebl:notify_party1", "did:openebl:notify_party2", "did:openebl:notify_party3"}, catchedTD.Meta["visible_to_bu"])
	s.Assert().EqualValues([]string{"did:openebl:shipper"}, catchedTD.Meta["action_needed"])
	s.Assert().EqualValues([]string{"did:openebl:issuer"}, catchedTD.Meta["sent"])
	s.Assert().EqualValues([]string{"did:openebl:consignee", "did:openebl:endorsee", "did:openebl:release_agent"}, catchedTD.Meta["upcoming"])
	s.Assert().Empty(catchedTD.Meta["archive"])

	// Extract BillOfLadingPack from the data on DB.
	jws := envelope.JWS{}
	s.Require().NoError(json.Unmarshal(catchedTD.Doc, &jws))
	payload, err := jws.GetPayload()
	s.Require().NoError(err)
	blPackOnDB := bill_of_lading.BillOfLadingPack{}
	s.Require().NoError(json.Unmarshal(payload, &blPackOnDB))
	s.Require().Equal("test content", string(blPackOnDB.Events[0].BillOfLading.File.Content))
	result.BL.Events[0].BillOfLading.File.Content = blPackOnDB.Events[0].BillOfLading.File.Content

	// Verify result
	s.Assert().Equal(util.StructToJSON(blPackOnDB), util.StructToJSON(*result.BL))
	parties := trade_document.GetFileBaseEBLParticipatorsFromBLPack(&blPackOnDB)
	expectedParties := trade_document.FileBaseEBLParticipators{
		Issuer:        "did:openebl:issuer",
		Shipper:       "did:openebl:shipper",
		Consignee:     "did:openebl:consignee",
		Endorsee:      "did:openebl:endorsee",
		ReleaseAgent:  "did:openebl:release_agent",
		NotifyParties: []string{"did:openebl:notify_party1", "did:openebl:notify_party2", "did:openebl:notify_party3"},
	}
	s.Assert().Equal(expectedParties, parties)
}

func (s *FileBasedEBLNegotiableTestSuite) TestConsigneeTransferToEndorsee() {
	const appID = "app_id"

	ts := time.Now().Unix()
	oldBLPack := bill_of_lading.BillOfLadingPack{
		ID:      "doc_id",
		Version: 1,
		Events: []bill_of_lading.BillOfLadingEvent{
			{
				BillOfLading: &bill_of_lading.BillOfLading{
					BillOfLadingV3: &dcsa_v3.TransportDocument{
						TransportDocumentStatus:    trade_document.ISSUED,
						TransportDocumentReference: "bl_number",
						IsToOrder:                  true,
						DocumentParties: dcsa_v3.DocumentParties{
							IssuingParty: dcsa_v3.IssuingParty{
								IdentifyingCodes: &[]dcsa_v3.IdentifyingCode{
									{
										PartyCode: "did:openebl:issuer",
									},
								},
							},
							Shipper: dcsa_v3.Shipper{
								IdentifyingCodes: &[]dcsa_v3.IdentifyingCode{
									{
										PartyCode: "did:openebl:shipper",
									},
								},
							},
							Consignee: &dcsa_v3.Consignee{
								IdentifyingCodes: []dcsa_v3.IdentifyingCode{
									{
										PartyCode: "did:openebl:consignee",
									},
								},
							},
							Endorsee: &dcsa_v3.Endorsee{
								IdentifyingCodes: []dcsa_v3.IdentifyingCode{
									{
										PartyCode: "did:openebl:endorsee",
									},
								},
							},
							Other: &[]dcsa_v3.OtherDocumentParty{
								{
									Party: dcsa_v3.Party{
										IdentifyingCodes: &[]dcsa_v3.IdentifyingCode{
											{

												PartyCode: "did:openebl:release_agent",
											},
										},
									},
									PartyFunction: "DDS", // Consignee's freight forwarder
								},
							},
						},
					},
					DocType: bill_of_lading.BillOfLadingDocumentTypeHouseBillOfLading,
					File: &model.File{
						Name:     "bl.pdf",
						FileType: "plain/text",
						Content:  []byte("test content"),
					},
				},
			},
			{
				Transfer: &bill_of_lading.Transfer{
					TransferBy: "did:openebl:shipper",
					TransferTo: "did:openebl:consignee",
				},
			},
		},
		CurrentOwner: "did:openebl:issuer",
	}
	oldBLPackJson, _ := json.Marshal(oldBLPack)
	oldBLJWS := envelope.JWS{
		Payload: envelope.Base64URLEncode(oldBLPackJson),
	}

	req := trade_document.TransferEBLRequest{
		ID:               "doc_id",
		TransferBy:       "did:openebl:consignee",
		Application:      "app_id",
		AuthenticationID: "consignee_auth_id",
	}

	var catchedTD storage.TradeDocument
	gomock.InOrder(
		s.buCtrl.EXPECT().ListBusinessUnits(
			gomock.Any(),
			storage.ListBusinessUnitsRequest{
				Limit:         1,
				ApplicationID: appID,
				BusinessUnitIDs: []string{
					"did:openebl:consignee",
				},
			},
		).DoAndReturn(func(ctx context.Context, req storage.ListBusinessUnitsRequest) (storage.ListBusinessUnitsResult, error) {
			result := storage.ListBusinessUnitsResult{}
			result.Records = lo.Map(req.BusinessUnitIDs, func(id string, _ int) storage.ListBusinessUnitsRecord {
				return storage.ListBusinessUnitsRecord{
					BusinessUnit: model.BusinessUnit{
						ID:            did.MustParse(id),
						Version:       1,
						ApplicationID: appID,
						Status:        model.BusinessUnitStatusActive,
					},
				}
			})
			return result, nil
		}),
		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().ListTradeDocument(
			gomock.Any(),
			s.tx,
			storage.ListTradeDocumentRequest{
				Limit:  1,
				DocIDs: []string{req.ID},
			},
		).Return(
			storage.ListTradeDocumentResponse{
				Total: 1,
				Docs: []storage.TradeDocument{
					{
						Kind: int(relay.FileBasedBillOfLading),
						Doc:  []byte(util.StructToJSON(oldBLJWS)),
					},
				},
			},
			nil,
		),
		s.buCtrl.EXPECT().GetJWSSigner(gomock.Any(), business_unit.GetJWSSignerRequest{
			ApplicationID:    appID,
			BusinessUnitID:   did.MustParse("did:openebl:consignee"),
			AuthenticationID: "consignee_auth_id",
		}).Return(s.signer, nil),
		s.signer.EXPECT().AvailableJWSSignAlgorithms().Return([]envelope.SignatureAlgorithm{envelope.SignatureAlgorithm(jwa.RS256)}),
		s.signer.EXPECT().Cert().Return([]*x509.Certificate{{}}),
		s.signer.EXPECT().Sign(gomock.Any(), gomock.Any(), gomock.Any()).Return([]byte("signature"), nil),
		s.storage.EXPECT().AddTradeDocument(gomock.Any(), s.tx, gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, tradeDoc storage.TradeDocument) error {
				catchedTD = tradeDoc
				return nil
			},
		),
		s.storage.EXPECT().AddTradeDocumentOutbox(gomock.Any(), s.tx, gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, ts int64, key string, kind int, payload []byte) error {
				return nil
			},
		),
		s.webHookCtrl.EXPECT().SendWebhookEvent(gomock.Any(), s.tx, ts, appID, gomock.Any(), model.WebhookEventBLTransferred).Return(nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	result, err := s.eblCtrl.Transfer(s.ctx, ts, req)
	s.Require().NoError(err)

	// Verify TradeDocument
	s.Assert().Equal(catchedTD.DocID, result.BL.ID)
	s.Assert().EqualValues(relay.FileBasedBillOfLading, catchedTD.Kind)
	s.Assert().EqualValues(catchedTD.DocVersion, result.BL.Version)
	s.Assert().EqualValues([]string{"did:openebl:issuer", "did:openebl:shipper", "did:openebl:consignee", "did:openebl:endorsee", "did:openebl:release_agent"}, catchedTD.Meta["visible_to_bu"])
	s.Assert().EqualValues([]string{"did:openebl:endorsee"}, catchedTD.Meta["action_needed"])
	s.Assert().EqualValues([]string{"did:openebl:issuer", "did:openebl:shipper", "did:openebl:consignee"}, catchedTD.Meta["sent"])
	s.Assert().EqualValues([]string{"did:openebl:release_agent"}, catchedTD.Meta["upcoming"])
	s.Assert().Empty(catchedTD.Meta["archive"])

	// Extract BillOfLadingPack from the data on DB.
	jws := envelope.JWS{}
	s.Require().NoError(json.Unmarshal(catchedTD.Doc, &jws))
	payload, err := jws.GetPayload()
	s.Require().NoError(err)
	blPackOnDB := bill_of_lading.BillOfLadingPack{}
	s.Require().NoError(json.Unmarshal(payload, &blPackOnDB))
	s.Require().Equal("test content", string(blPackOnDB.Events[0].BillOfLading.File.Content))
	result.BL.Events[0].BillOfLading.File.Content = blPackOnDB.Events[0].BillOfLading.File.Content

	// Verify result
	s.Assert().Equal(util.StructToJSON(blPackOnDB), util.StructToJSON(*result.BL))
	parties := trade_document.GetFileBaseEBLParticipatorsFromBLPack(&blPackOnDB)
	expectedParties := trade_document.FileBaseEBLParticipators{
		Issuer:       "did:openebl:issuer",
		Shipper:      "did:openebl:shipper",
		Consignee:    "did:openebl:consignee",
		Endorsee:     "did:openebl:endorsee",
		ReleaseAgent: "did:openebl:release_agent",
	}
	s.Assert().Equal(expectedParties, parties)
	lastEvent := result.BL.Events[len(result.BL.Events)-1]
	s.Require().NotNil(lastEvent.Transfer)
	s.Assert().Equal("did:openebl:consignee", lastEvent.Transfer.TransferBy)
	s.Assert().Equal("did:openebl:endorsee", lastEvent.Transfer.TransferTo)
}
