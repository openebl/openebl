package trade_document_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did/did"
	"github.com/openebl/openebl/pkg/bu_server/business_unit"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/model/trade_document/bill_of_lading"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/bu_server/trade_document"
	"github.com/openebl/openebl/pkg/envelope"
	eblpkix "github.com/openebl/openebl/pkg/pkix"
	"github.com/openebl/openebl/pkg/relay"
	"github.com/openebl/openebl/pkg/util"
	mock_business_unit "github.com/openebl/openebl/test/mock/bu_server/business_unit"
	mock_storage "github.com/openebl/openebl/test/mock/bu_server/storage"
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

	jwsSigner business_unit.JWSSigner
}

func TestFileBasedEBL(t *testing.T) {
	suite.Run(t, new(FileBasedEBLTestSuite))
}

func (s *FileBasedEBLTestSuite) SetupSuite() {
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // 1 year

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Your Organization"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, _ := x509.CreateCertificate(rand.Reader, &template, &template, &ecdsaKey.PublicKey, ecdsaKey)
	cert, _ := x509.ParseCertificate(der)
	privKeyPEM, _ := eblpkix.MarshalPrivateKey(ecdsaKey)
	certPEM, _ := eblpkix.MarshalCertificates([]x509.Certificate{*cert})

	auth := model.BusinessUnitAuthentication{
		PrivateKey:  string(privKeyPEM),
		Certificate: string(certPEM),
	}
	s.jwsSigner, _ = business_unit.DefaultJWSSignerFactory.NewJWSSigner(auth)
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
		).Return(s.jwsSigner, nil),
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
	s.Assert().EqualValues(map[string]any{"visible_to_bu": []string{"did:openebl:issuer", "did:openebl:shipper", "did:openebl:consignee", "did:openebl:release_agent"}}, tdOnDB.Meta)

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
