package business_unit_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openebl/openebl/pkg/bu_server/business_unit"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/did"
	"github.com/openebl/openebl/pkg/envelope"
	"github.com/openebl/openebl/pkg/pkix"
	eblpkix "github.com/openebl/openebl/pkg/pkix"
	"github.com/openebl/openebl/pkg/relay"
	"github.com/openebl/openebl/pkg/util"
	mock_business_unit "github.com/openebl/openebl/test/mock/bu_server/business_unit"
	mock_cert "github.com/openebl/openebl/test/mock/bu_server/cert"
	mock_storage "github.com/openebl/openebl/test/mock/bu_server/storage"
	mock_webhook "github.com/openebl/openebl/test/mock/bu_server/webhook"
	"github.com/stretchr/testify/suite"
)

type BusinessUnitManagerTestSuite struct {
	suite.Suite
	ctx         context.Context
	ctrl        *gomock.Controller
	storage     *mock_storage.MockBusinessUnitStorage
	webhookCtrl *mock_webhook.MockWebhookController
	jwtFactory  *mock_business_unit.MockJWTFactory
	cv          *mock_cert.MockCertVerifier
	tx          *mock_storage.MockTx
	buManager   business_unit.BusinessUnitManager
}

func TestBusinessUnitManager(t *testing.T) {
	suite.Run(t, new(BusinessUnitManagerTestSuite))
}

func (s *BusinessUnitManagerTestSuite) SetupTest() {
	s.ctx = context.Background()
	s.ctrl = gomock.NewController(s.T())
	s.storage = mock_storage.NewMockBusinessUnitStorage(s.ctrl)
	s.webhookCtrl = mock_webhook.NewMockWebhookController(s.ctrl)
	s.jwtFactory = mock_business_unit.NewMockJWTFactory(s.ctrl)
	s.cv = mock_cert.NewMockCertVerifier(s.ctrl)
	s.tx = mock_storage.NewMockTx(s.ctrl)
	s.buManager = business_unit.NewBusinessUnitManager(s.storage, s.cv, s.webhookCtrl, s.jwtFactory)
}

func (s *BusinessUnitManagerTestSuite) TearDownTest() {
	s.ctrl.Finish()
}

func (s *BusinessUnitManagerTestSuite) TestCreateBusinessUnit() {
	ts := time.Now().Unix()

	request := business_unit.CreateBusinessUnitRequest{
		Requester:     "requester",
		ApplicationID: "application-id",
		Name:          "name",
		Addresses:     []string{"address"},
		Country:       "US",
		Emails:        []string{"email"},
		Status:        model.BusinessUnitStatusActive,
	}

	expectedBusinessUnit := model.BusinessUnit{
		Version:       1,
		ApplicationID: request.ApplicationID,
		Status:        request.Status,
		Name:          request.Name,
		Addresses:     request.Addresses,
		Country:       request.Country,
		Emails:        request.Emails,
		CreatedAt:     ts,
		CreatedBy:     request.Requester,
		UpdatedAt:     ts,
		UpdatedBy:     request.Requester,
	}

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().StoreBusinessUnit(gomock.Any(), s.tx, gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, bu model.BusinessUnit) error {
				expectedBusinessUnit.ID = bu.ID
				s.Assert().Equal(expectedBusinessUnit, bu)
				return nil
			},
		),
		s.webhookCtrl.EXPECT().SendWebhookEvent(gomock.Any(), s.tx, ts, "application-id", gomock.Any(), model.WebhookEventBUCreated).Return(nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	newBu, err := s.buManager.CreateBusinessUnit(s.ctx, ts, request)
	s.NoError(err)
	s.Assert().Equal(expectedBusinessUnit, newBu)
}

func (s *BusinessUnitManagerTestSuite) TestUpdateBusinessUnit() {
	ts := time.Now().Unix()

	buCertRaw, err := os.ReadFile("../../../testdata/cert_server/cert_authority/bu_cert.crt")
	s.Require().NoError(err)
	buPrivKeyRaw, err := os.ReadFile("../../../testdata/cert_server/cert_authority/bu_cert_priv_key.pem")
	s.Require().NoError(err)
	buAuth := model.BusinessUnitAuthentication{
		ID:           "authentication-id",
		BusinessUnit: did.MustParse("did:openebl:u0e2345"),
		Version:      1,
		Status:       model.BusinessUnitAuthenticationStatusActive,
		PrivateKey:   string(buPrivKeyRaw),
		Certificate:  string(buCertRaw),
	}

	request := business_unit.UpdateBusinessUnitRequest{
		Requester:     "requester",
		ApplicationID: "application-id",
		ID:            did.MustParse("did:openebl:u0e2345"),
		Name:          "name",
		Addresses:     []string{"address"},
		Country:       "US",
		Emails:        []string{"email"},
	}

	oldBusinessUnit := model.BusinessUnit{
		ID:            request.ID,
		Version:       1,
		ApplicationID: request.ApplicationID,
		Status:        model.BusinessUnitStatusActive,
		Name:          "old-name",
		Addresses:     []string{"old-address"},
		Country:       "CA",
		Emails:        []string{"old-email"},
		CreatedAt:     ts - 100,
		CreatedBy:     "old-requester",
		UpdatedAt:     ts - 100,
		UpdatedBy:     "old-requester",
	}

	expectedBusinessUnit := model.BusinessUnit{
		ID:            request.ID,
		Version:       2,
		ApplicationID: request.ApplicationID,
		Status:        model.BusinessUnitStatusActive,
		Name:          request.Name,
		Addresses:     request.Addresses,
		Country:       request.Country,
		Emails:        request.Emails,
		CreatedAt:     ts - 100,
		CreatedBy:     "old-requester",
		UpdatedAt:     ts,
		UpdatedBy:     request.Requester,
	}

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().ListBusinessUnits(
			gomock.Any(),
			s.tx,
			storage.ListBusinessUnitsRequest{
				Limit:           1,
				ApplicationID:   request.ApplicationID,
				BusinessUnitIDs: []string{request.ID.String()},
			},
		).Return(storage.ListBusinessUnitsResult{
			Total: 1,
			Records: []storage.ListBusinessUnitsRecord{
				{
					BusinessUnit: oldBusinessUnit,
				},
			},
		}, nil),
		s.storage.EXPECT().StoreBusinessUnit(gomock.Any(), s.tx, expectedBusinessUnit).Return(nil),
		s.webhookCtrl.EXPECT().SendWebhookEvent(gomock.Any(), s.tx, ts, "application-id", "did:openebl:u0e2345", model.WebhookEventBUUpdated).Return(nil),
		s.storage.EXPECT().ListAuthentication(
			gomock.Any(),
			s.tx,
			storage.ListAuthenticationRequest{
				Limit:          100,
				BusinessUnitID: "did:openebl:u0e2345",
				Statuses:       []model.BusinessUnitAuthenticationStatus{model.BusinessUnitAuthenticationStatusActive},
			},
		).Return(
			storage.ListAuthenticationResult{
				Total:   1,
				Records: []model.BusinessUnitAuthentication{buAuth},
			},
			nil,
		),
		s.jwtFactory.EXPECT().NewJWSSigner(buAuth).Return(business_unit.DefaultJWTFactory.NewJWSSigner(buAuth)),
		s.storage.EXPECT().AddTradeDocumentOutbox(
			gomock.Any(),
			s.tx,
			gomock.Any(),
			"did:openebl:u0e2345",
			int(relay.BusinessUnit),
			gomock.Any(),
		).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, ts int64, buID string, buType int, document []byte) error {
				jwsEvt := envelope.JWS{}
				err := json.Unmarshal(document, &jwsEvt)
				s.Require().NoError(err)
				err = jwsEvt.VerifySignature()
				s.Require().NoError(err)

				payload, err := jwsEvt.GetPayload()
				s.Require().NoError(err)
				receivedBU := model.BusinessUnit{}
				err = json.Unmarshal(payload, &receivedBU)
				s.Require().NoError(err)
				s.Require().Equal(expectedBusinessUnit, receivedBU)
				return nil
			},
		),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	newBu, err := s.buManager.UpdateBusinessUnit(s.ctx, ts, request)
	s.NoError(err)
	s.Assert().Equal(expectedBusinessUnit, newBu)
}

func (s *BusinessUnitManagerTestSuite) TestUpdateBusinessUnitByExternalEvent() {
	ts := time.Now().Unix()

	buCertRaw, err := os.ReadFile("../../../testdata/cert_server/cert_authority/bu_cert.crt")
	s.Require().NoError(err)
	buCert, err := eblpkix.ParseCertificate(buCertRaw)
	s.Require().NoError(err)
	buPrivKeyRaw, err := os.ReadFile("../../../testdata/cert_server/cert_authority/bu_cert_priv_key.pem")
	s.Require().NoError(err)
	buPrivKey, err := eblpkix.ParsePrivateKey(buPrivKeyRaw)
	s.Require().NoError(err)

	bu := model.BusinessUnit{
		ID:      did.MustParse("did:openebl:aaaabbbbcccc"),
		Version: 2,
		Status:  model.BusinessUnitStatusActive,
		Name:    "name",
	}

	signedEvent, err := envelope.Sign([]byte(util.StructToJSON(bu)), envelope.SignatureAlgorithm(jwa.ES384), buPrivKey, buCert)
	s.Require().NoError(err)

	func() { // Test successful case
		gomock.InOrder(
			s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
			s.cv.EXPECT().VerifyCert(gomock.Any(), s.tx, buCert[0].NotBefore.Unix(), buCert).Return(nil),
			s.storage.EXPECT().ListBusinessUnits(
				gomock.Any(),
				s.tx,
				storage.ListBusinessUnitsRequest{
					Limit:           1,
					BusinessUnitIDs: []string{"did:openebl:aaaabbbbcccc"},
				},
			).Return(storage.ListBusinessUnitsResult{}, nil),
			s.storage.EXPECT().StoreBusinessUnit(gomock.Any(), s.tx, bu).Return(nil),
			s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
			s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
		)

		err := s.buManager.UpdateBusinessUnitByExternalEvent(s.ctx, ts, signedEvent)
		s.Require().NoError(err)
	}()

	func() { // Test with old business unit
		oldBU := bu
		gomock.InOrder(
			s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
			s.cv.EXPECT().VerifyCert(gomock.Any(), s.tx, buCert[0].NotBefore.Unix(), buCert).Return(nil),
			s.storage.EXPECT().ListBusinessUnits(
				gomock.Any(),
				s.tx,
				storage.ListBusinessUnitsRequest{
					Limit:           1,
					BusinessUnitIDs: []string{"did:openebl:aaaabbbbcccc"},
				},
			).Return(
				storage.ListBusinessUnitsResult{
					Total: 1,
					Records: []storage.ListBusinessUnitsRecord{
						{
							BusinessUnit: oldBU,
						},
					},
				},
				nil,
			),
			s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
		)

		err := s.buManager.UpdateBusinessUnitByExternalEvent(s.ctx, ts, signedEvent)
		s.Require().NoError(err)
	}()

	func() { // Test with invalid certificate
		gomock.InOrder(
			s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
			s.cv.EXPECT().VerifyCert(gomock.Any(), s.tx, buCert[0].NotBefore.Unix(), buCert).Return(model.ErrCertInvalid),
			s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
		)
		err := s.buManager.UpdateBusinessUnitByExternalEvent(s.ctx, ts, signedEvent)
		s.Require().ErrorIs(err, model.ErrInvalidParameter)
	}()

	func() { // Test with the event is not well signed.
		badEvent := signedEvent
		badEvent.Payload = envelope.Base64URLEncode([]byte("another payload"))

		err := s.buManager.UpdateBusinessUnitByExternalEvent(s.ctx, ts, badEvent)
		s.Require().ErrorIs(err, model.ErrInvalidParameter)
	}()
}

func (s *BusinessUnitManagerTestSuite) TestListBusinessUnits() {
	request := storage.ListBusinessUnitsRequest{
		Offset:          1,
		Limit:           10,
		ApplicationID:   "application-id",
		BusinessUnitIDs: []string{"did:openebl:u0e2345"},
	}

	expectedBusinessUnit := model.BusinessUnit{
		ID:            did.MustParse("did:openebl:u0e2345"),
		Version:       1,
		ApplicationID: request.ApplicationID,
		Status:        model.BusinessUnitStatusActive,
		Name:          "name",
		Addresses:     []string{"address"},
		Country:       "US",
		Emails:        []string{"email"},
		CreatedAt:     12345,
		CreatedBy:     "requester",
		UpdatedAt:     12345,
		UpdatedBy:     "requester",
	}

	listResult := storage.ListBusinessUnitsResult{
		Total: 1,
		Records: []storage.ListBusinessUnitsRecord{
			{
				BusinessUnit: expectedBusinessUnit,
			},
		},
	}

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(0)).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().ListBusinessUnits(
			gomock.Any(),
			s.tx,
			request,
		).Return(listResult, nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	result, err := s.buManager.ListBusinessUnits(s.ctx, request)
	s.NoError(err)
	s.Assert().Equal(listResult, result)
}

func (s *BusinessUnitManagerTestSuite) TestSetBusinessUnitStatus() {
	ts := time.Now().Unix()

	request := business_unit.SetBusinessUnitStatusRequest{
		Requester:     "requester",
		ApplicationID: "application-id",
		ID:            did.MustParse("did:openebl:u0e2345"),
		Status:        model.BusinessUnitStatusInactive,
	}

	oldBusinessUnit := model.BusinessUnit{
		ID:            request.ID,
		Version:       1,
		ApplicationID: "application-id",
		Status:        model.BusinessUnitStatusActive,
		Name:          "name",
		Addresses:     []string{"address"},
		Country:       "US",
		Emails:        []string{"email"},
		CreatedAt:     ts - 100,
		CreatedBy:     "old-requester",
		UpdatedAt:     ts - 100,
		UpdatedBy:     "old-requester",
	}

	expectedBusinessUnit := model.BusinessUnit{
		ID:            request.ID,
		Version:       2,
		ApplicationID: "application-id",
		Status:        model.BusinessUnitStatusInactive,
		Name:          "name",
		Addresses:     []string{"address"},
		Country:       "US",
		Emails:        []string{"email"},
		CreatedAt:     ts - 100,
		CreatedBy:     "old-requester",
		UpdatedAt:     ts,
		UpdatedBy:     request.Requester,
	}

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().ListBusinessUnits(
			gomock.Any(),
			s.tx,
			storage.ListBusinessUnitsRequest{
				Limit:           1,
				ApplicationID:   request.ApplicationID,
				BusinessUnitIDs: []string{request.ID.String()},
			},
		).Return(storage.ListBusinessUnitsResult{
			Total: 1,
			Records: []storage.ListBusinessUnitsRecord{
				{
					BusinessUnit: oldBusinessUnit,
				},
			},
		}, nil),
		s.storage.EXPECT().StoreBusinessUnit(gomock.Any(), s.tx, expectedBusinessUnit).Return(nil),
		s.webhookCtrl.EXPECT().SendWebhookEvent(gomock.Any(), s.tx, ts, "application-id", "did:openebl:u0e2345", model.WebhookEventBUUpdated).Return(nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	newBu, err := s.buManager.SetStatus(s.ctx, ts, request)
	s.NoError(err)
	s.Assert().Equal(expectedBusinessUnit, newBu)
}

func (s *BusinessUnitManagerTestSuite) TestAddAuthentication() {
	ts := time.Now().Unix()

	request := business_unit.AddAuthenticationRequest{
		Requester:      "requester",
		ApplicationID:  "application-id",
		BusinessUnitID: did.MustParse("did:openebl:u0e2345"),
		PrivateKeyOption: eblpkix.PrivateKeyOption{
			KeyType:   eblpkix.PrivateKeyTypeECDSA,
			CurveType: eblpkix.ECDSACurveTypeP384,
		},
	}

	bu := model.BusinessUnit{
		ID:            did.MustParse("did:openebl:bu1"),
		Version:       1,
		ApplicationID: "application-id",
		Status:        model.BusinessUnitStatusActive,
		Name:          "name",
		Addresses:     []string{"address"},
		Country:       "US",
		Emails:        []string{"email"},
		CreatedAt:     ts - 100,
		CreatedBy:     "old-requester",
	}

	expectedListBuRequest := storage.ListBusinessUnitsRequest{
		Limit:           1,
		ApplicationID:   request.ApplicationID,
		BusinessUnitIDs: []string{request.BusinessUnitID.String()},
	}
	listBuResult := storage.ListBusinessUnitsResult{
		Total: 1,
		Records: []storage.ListBusinessUnitsRecord{
			{
				BusinessUnit: bu,
			},
		},
	}

	receivedAuthentication := model.BusinessUnitAuthentication{
		Version:      1,
		BusinessUnit: request.BusinessUnitID,
		Status:       model.BusinessUnitAuthenticationStatusPending,
		CreatedAt:    ts,
		CreatedBy:    request.Requester,
	}

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().ListBusinessUnits(gomock.Any(), s.tx, expectedListBuRequest).Return(listBuResult, nil),
		s.storage.EXPECT().StoreAuthentication(gomock.Any(), s.tx, gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, auth model.BusinessUnitAuthentication) error {
				receivedAuthentication.ID = auth.ID
				receivedAuthentication.PrivateKey = auth.PrivateKey
				receivedAuthentication.Certificate = auth.Certificate
				receivedAuthentication.CertFingerPrint = auth.CertFingerPrint
				receivedAuthentication.CertificateSigningRequest = auth.CertificateSigningRequest
				receivedAuthentication.PublicKeyID = auth.PublicKeyID
				receivedAuthentication.IssuerKeyID = auth.IssuerKeyID
				s.Assert().Equal(receivedAuthentication, auth)
				return nil
			},
		),
		s.webhookCtrl.EXPECT().SendWebhookEvent(gomock.Any(), s.tx, ts, "application-id", gomock.Any(), model.WebhookEventAuthCreated).Return(nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	newAuthentication, err := s.buManager.AddAuthentication(s.ctx, ts, request)
	s.NoError(err)
	s.Assert().Empty(newAuthentication.PrivateKey)
	newAuthentication.PrivateKey = receivedAuthentication.PrivateKey
	s.Assert().Equal(receivedAuthentication, newAuthentication)
	s.Assert().NotEmpty(receivedAuthentication.PrivateKey)
	s.Assert().NotEmpty(receivedAuthentication.CertificateSigningRequest)
	s.Assert().NotEmpty(receivedAuthentication.PublicKeyID)
	s.Assert().Empty(receivedAuthentication.Certificate)

	// Check if receivedCertRequest is valid and have correct public key.
	csr, err := eblpkix.ParseCertificateRequest([]byte(receivedAuthentication.CertificateSigningRequest))
	s.Require().NoError(err)
	privateKey, err := pkix.ParsePrivateKey([]byte(receivedAuthentication.PrivateKey))
	s.Require().NoError(err)
	publicKey := privateKey.(*ecdsa.PrivateKey).PublicKey
	s.Assert().True(publicKey.Equal(csr.PublicKey))
	s.Assert().Nil(csr.CheckSignature())
}

func (s *BusinessUnitManagerTestSuite) TestActivateAuthentication() {
	buID := "did:openebl:aaaabbbbcccc"
	ts := int64(987654321)

	privateKeyRaw, err := os.ReadFile("../../../testdata/cert_server/cert_authority/bu_cert_priv_key.pem")
	s.Require().NoError(err)
	privateKey, err := eblpkix.ParsePrivateKey(privateKeyRaw)
	s.Require().NoError(err)

	buCertRaw, err := os.ReadFile("../../../testdata/cert_server/cert_authority/bu_cert.crt")
	s.Require().NoError(err)
	buCert, err := eblpkix.ParseCertificate(buCertRaw)
	s.Require().NoError(err)
	certPublicKeyID := eblpkix.GetSubjectKeyIDFromCertificate(buCert[0])

	buCSRRaw, err := os.ReadFile("../../../testdata/cert_server/cert_authority/bu_cert.csr")
	s.Require().NoError(err)
	buCSR, err := eblpkix.ParseCertificateRequest(buCSRRaw)
	s.Require().NoError(err)
	_ = buCSR

	oldBuAuth := model.BusinessUnitAuthentication{
		ID:                        "authentication-id",
		BusinessUnit:              did.MustParse(buID),
		Version:                   1,
		Status:                    model.BusinessUnitAuthenticationStatusPending,
		CreatedAt:                 12345,
		CreatedBy:                 "requester",
		PrivateKey:                string(privateKeyRaw),
		CertificateSigningRequest: string(buCSRRaw),
		PublicKeyID:               eblpkix.GetPublicKeyID(eblpkix.GetPublicKey(privateKey)),
		Certificate:               string(buCertRaw),
	}

	expectedBuAuth := oldBuAuth
	expectedBuAuth.Version += 1
	expectedBuAuth.Status = model.BusinessUnitAuthenticationStatusActive
	expectedBuAuth.ActivatedAt = ts
	expectedBuAuth.Certificate = string(buCertRaw)
	expectedBuAuth.IssuerKeyID = hex.EncodeToString(buCert[0].AuthorityKeyId)
	expectedBuAuth.CertificateSerialNumber = buCert[0].SerialNumber.String()
	expectedBuAuth.CertFingerPrint = "sha1:c22d268faa8895e02d8be8ffbcfd80e03a204f30"

	bu := model.BusinessUnit{
		ID:      did.MustParse(buID),
		Version: 1,
		Status:  model.BusinessUnitStatusActive,
	}

	func() { // Test successful case
		gomock.InOrder(
			s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
			s.cv.EXPECT().VerifyCert(gomock.Any(), s.tx, gomock.Any(), buCert).Return(nil),
			s.storage.EXPECT().ListAuthentication(
				gomock.Any(),
				s.tx,
				storage.ListAuthenticationRequest{
					Limit:        1,
					PublicKeyIDs: []string{certPublicKeyID},
				},
			).Return(
				storage.ListAuthenticationResult{
					Total:   1,
					Records: []model.BusinessUnitAuthentication{oldBuAuth},
				},
				nil,
			),
			s.storage.EXPECT().StoreAuthentication(
				gomock.Any(),
				s.tx,
				expectedBuAuth,
			).Return(nil),
			s.jwtFactory.EXPECT().NewJWSSigner(expectedBuAuth).Return(business_unit.DefaultJWTFactory.NewJWSSigner(expectedBuAuth)),
			s.storage.EXPECT().AddTradeDocumentOutbox(
				gomock.Any(),
				s.tx,
				gomock.Any(),
				expectedBuAuth.ID,
				int(relay.BusinessUnitAuthentication),
				gomock.Any(),
			).DoAndReturn(
				func(ctx context.Context, tx storage.Tx, ts int64, authenticationID string, documentType int, document []byte) error {
					jwsEvt := envelope.JWS{}
					err := json.Unmarshal(document, &jwsEvt)
					s.Require().NoError(err)
					err = jwsEvt.VerifySignature()
					s.Require().NoError(err)

					payload, err := jwsEvt.GetPayload()
					s.Require().NoError(err)
					receivedAuth := model.BusinessUnitAuthentication{}
					err = json.Unmarshal(payload, &receivedAuth)
					s.Require().NoError(err)
					s.Require().Equal(expectedBuAuth, receivedAuth)
					return nil
				},
			),
			s.storage.EXPECT().ListBusinessUnits(
				gomock.Any(),
				s.tx,
				storage.ListBusinessUnitsRequest{
					Limit:           1,
					BusinessUnitIDs: []string{buID},
				},
			).Return(
				storage.ListBusinessUnitsResult{
					Total: 1,
					Records: []storage.ListBusinessUnitsRecord{
						{
							BusinessUnit: bu,
						},
					},
				},
				nil,
			),
			s.storage.EXPECT().AddTradeDocumentOutbox(
				gomock.Any(),
				s.tx,
				gomock.Any(),
				bu.ID.String(),
				int(relay.BusinessUnit),
				gomock.Any(),
			).DoAndReturn(
				func(ctx context.Context, tx storage.Tx, ts int64, authenticationID string, documentType int, document []byte) error {
					jwsEvt := envelope.JWS{}
					err := json.Unmarshal(document, &jwsEvt)
					s.Require().NoError(err)
					err = jwsEvt.VerifySignature()
					s.Require().NoError(err)
					payload, err := jwsEvt.GetPayload()
					s.Require().NoError(err)
					receivedBU := model.BusinessUnit{}
					err = json.Unmarshal(payload, &receivedBU)
					s.Require().NoError(err)
					s.Require().Equal(bu, receivedBU)
					return nil
				},
			),
			s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
			s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
		)

		result, err := s.buManager.ActivateAuthentication(s.ctx, ts, buCertRaw)
		s.Require().NoError(err)
		s.Assert().Empty(result.PrivateKey)
		result.PrivateKey = expectedBuAuth.PrivateKey
		s.Assert().Equal(expectedBuAuth, result)
	}()

	func() { // Test case of bu authentication without private key.
		emptyPrivKeyAuth := oldBuAuth
		emptyPrivKeyAuth.PrivateKey = ""
		gomock.InOrder(
			s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
			s.cv.EXPECT().VerifyCert(gomock.Any(), s.tx, gomock.Any(), buCert).Return(nil),
			s.storage.EXPECT().ListAuthentication(
				gomock.Any(),
				s.tx,
				storage.ListAuthenticationRequest{
					Limit:        1,
					PublicKeyIDs: []string{certPublicKeyID},
				},
			).Return(
				storage.ListAuthenticationResult{
					Total:   1,
					Records: []model.BusinessUnitAuthentication{emptyPrivKeyAuth},
				},
				nil,
			),
			s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
		)

		_, err := s.buManager.ActivateAuthentication(s.ctx, ts, buCertRaw)
		s.Require().ErrorIs(err, model.ErrAuthenticationNotFound)
	}()
}

func (s *BusinessUnitManagerTestSuite) TestUpdateAuthenticationByExternalEvent() {
	buCertRaw, err := os.ReadFile("../../../testdata/cert_server/cert_authority/bu_cert.crt")
	s.Require().NoError(err)
	buCert, err := eblpkix.ParseCertificate(buCertRaw)
	s.Require().NoError(err)

	buPrivateKeyRaw, err := os.ReadFile("../../../testdata/cert_server/cert_authority/bu_cert_priv_key.pem")
	s.Require().NoError(err)
	buPrivateKey, err := eblpkix.ParsePrivateKey(buPrivateKeyRaw)
	s.Require().NoError(err)

	ts := time.Now().Unix()
	buAuth := model.BusinessUnitAuthentication{
		ID:                      "authentication-id",
		Version:                 2,
		BusinessUnit:            did.MustParse("did:openebl:aaaabbbbcccc"),
		Status:                  model.BusinessUnitAuthenticationStatusActive,
		CreatedAt:               12345,
		CreatedBy:               "requester",
		Certificate:             string(buCertRaw),
		PublicKeyID:             eblpkix.GetPublicKeyID(buCert[0].PublicKey),
		IssuerKeyID:             hex.EncodeToString(buCert[0].AuthorityKeyId),
		CertFingerPrint:         eblpkix.GetFingerPrintFromCertificate(buCert[0]),
		CertificateSerialNumber: buCert[0].SerialNumber.String(),
	}
	signedEvent, err := envelope.Sign([]byte(util.StructToJSON(buAuth)), envelope.SignatureAlgorithm(jwa.ES384), buPrivateKey, buCert)
	s.Require().NoError(err)

	func() { // Test successful case
		gomock.InOrder(
			s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
			s.cv.EXPECT().VerifyCert(gomock.Any(), s.tx, buCert[0].NotBefore.Unix(), buCert).Return(nil),
			s.storage.EXPECT().ListAuthentication(
				gomock.Any(),
				s.tx,
				storage.ListAuthenticationRequest{
					Limit:             1,
					BusinessUnitID:    buAuth.BusinessUnit.String(),
					AuthenticationIDs: []string{buAuth.ID},
				},
			).Return(storage.ListAuthenticationResult{}, nil),
			s.storage.EXPECT().StoreAuthentication(gomock.Any(), s.tx, buAuth).Return(nil),
			s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
			s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
		)

		err = s.buManager.UpdateAuthenticationByExternalEvent(s.ctx, ts, signedEvent)
		s.Require().NoError(err)
	}()

	func() { // Test case when the event is an old one.
		gomock.InOrder(
			s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
			s.cv.EXPECT().VerifyCert(gomock.Any(), s.tx, buCert[0].NotBefore.Unix(), buCert).Return(nil),
			s.storage.EXPECT().ListAuthentication(
				gomock.Any(),
				s.tx,
				storage.ListAuthenticationRequest{
					Limit:             1,
					BusinessUnitID:    buAuth.BusinessUnit.String(),
					AuthenticationIDs: []string{buAuth.ID},
				},
			).Return(
				storage.ListAuthenticationResult{
					Total: 1,
					Records: []model.BusinessUnitAuthentication{
						{
							ID:      buAuth.ID,
							Version: buAuth.Version,
						},
					},
				},
				nil,
			),
			s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
		)
		err = s.buManager.UpdateAuthenticationByExternalEvent(s.ctx, ts, signedEvent)
		s.Require().NoError(err)
	}()

	func() { // Test case when the certificate is not valid
		gomock.InOrder(
			s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
			s.cv.EXPECT().VerifyCert(gomock.Any(), s.tx, buCert[0].NotBefore.Unix(), buCert).Return(model.ErrCertInvalid),
			s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
		)

		err = s.buManager.UpdateAuthenticationByExternalEvent(s.ctx, ts, signedEvent)
		s.Require().ErrorIs(err, model.ErrInvalidParameter)
	}()

	func() { // Test case when the certificates in JWS is not the same as BusinessUnitAuthentication.Certificate
		badAuth := buAuth
		badAuth.Certificate = fmt.Sprintf("%s%s", badAuth.Certificate, badAuth.Certificate)
		badEvent := signedEvent
		badEvent.Payload = envelope.Base64URLEncode([]byte(util.StructToJSON(badAuth)))
		err = s.buManager.UpdateAuthenticationByExternalEvent(s.ctx, ts, badEvent)
		s.Require().ErrorIs(err, model.ErrInvalidParameter)
	}()

	func() { // Test case when the event is not well signed.
		badEvent := signedEvent
		badEvent.Payload = envelope.Base64URLEncode([]byte("another payload"))
		err = s.buManager.UpdateAuthenticationByExternalEvent(s.ctx, ts, badEvent)
		s.Require().ErrorIs(err, model.ErrInvalidParameter)
	}()
}

func (s *BusinessUnitManagerTestSuite) TestRevokeAuthentication() {
	ts := time.Now().Unix()

	request := business_unit.RevokeAuthenticationRequest{
		Requester:        "requester",
		ApplicationID:    "application-id",
		BusinessUnitID:   did.MustParse("did:openebl:u0e2345"),
		AuthenticationID: "authentication-id",
	}

	oldAuthentication := model.BusinessUnitAuthentication{
		ID:           "authentication-id",
		Version:      1,
		BusinessUnit: request.BusinessUnitID,
		Status:       model.BusinessUnitAuthenticationStatusActive,
		CreatedAt:    ts - 100,
		CreatedBy:    "old-requester",
		PrivateKey:   "FAKE PEM PRIVATE KEY",
		Certificate:  "FAKE PEM CERT",
		RevokedAt:    0,
	}

	expectedAuthentication := model.BusinessUnitAuthentication{
		ID:           "authentication-id",
		Version:      2,
		BusinessUnit: request.BusinessUnitID,
		Status:       model.BusinessUnitAuthenticationStatusRevoked,
		CreatedAt:    ts - 100,
		CreatedBy:    "old-requester",
		PrivateKey:   "FAKE PEM PRIVATE KEY",
		Certificate:  "FAKE PEM CERT",
		RevokedAt:    ts,
		RevokedBy:    request.Requester,
	}

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().ListAuthentication(
			gomock.Any(),
			s.tx,
			storage.ListAuthenticationRequest{
				Limit:             1,
				ApplicationID:     request.ApplicationID,
				BusinessUnitID:    request.BusinessUnitID.String(),
				AuthenticationIDs: []string{request.AuthenticationID},
			},
		).Return(storage.ListAuthenticationResult{
			Total:   1,
			Records: []model.BusinessUnitAuthentication{oldAuthentication},
		}, nil),
		s.storage.EXPECT().StoreAuthentication(gomock.Any(), s.tx, expectedAuthentication).Return(nil),
		s.webhookCtrl.EXPECT().SendWebhookEvent(gomock.Any(), s.tx, ts, "application-id", "authentication-id", model.WebhookEventAuthRevoked).Return(nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	newAuthentication, err := s.buManager.RevokeAuthentication(s.ctx, ts, request)
	s.NoError(err)
	s.Assert().Empty(newAuthentication.PrivateKey)
	newAuthentication.PrivateKey = expectedAuthentication.PrivateKey
	s.Assert().Equal(expectedAuthentication, newAuthentication)
}

func (s *BusinessUnitManagerTestSuite) TestListAuthentication() {
	request := storage.ListAuthenticationRequest{
		Offset:            1,
		Limit:             10,
		ApplicationID:     "application-id",
		BusinessUnitID:    "did:openebl:u0e2345",
		AuthenticationIDs: []string{"authentication-id"},
	}

	expectedAuthentication := model.BusinessUnitAuthentication{
		ID:           "authentication-id",
		Version:      1,
		BusinessUnit: did.MustParse(request.BusinessUnitID),
		Status:       model.BusinessUnitAuthenticationStatusActive,
		CreatedAt:    12345,
		CreatedBy:    "requester",
		PrivateKey:   "FAKE PEM PRIVATE KEY",
		Certificate:  "FAKE PEM CERT",
		RevokedAt:    0,
	}

	listResult := storage.ListAuthenticationResult{
		Total:   1,
		Records: []model.BusinessUnitAuthentication{expectedAuthentication},
	}

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(0)).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().ListAuthentication(
			gomock.Any(),
			s.tx,
			request,
		).Return(listResult, nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	result, err := s.buManager.ListAuthentication(s.ctx, request)
	s.NoError(err)
	s.Require().NotEmpty(result.Records)
	s.Assert().Empty(result.Records[0].PrivateKey)
	s.Assert().Equal(listResult, result)
}

func (s *BusinessUnitManagerTestSuite) TestGetJWSSigner() {
	request := business_unit.GetJWSSignerRequest{
		ApplicationID:    "application-id",
		BusinessUnitID:   did.MustParse("did:openebl:u0e2345"),
		AuthenticationID: "authentication-id",
	}

	listAuthRequest := storage.ListAuthenticationRequest{
		Limit:             1,
		ApplicationID:     request.ApplicationID,
		BusinessUnitID:    request.BusinessUnitID.String(),
		AuthenticationIDs: []string{request.AuthenticationID},
	}

	buAuth := model.BusinessUnitAuthentication{
		ID:           "authentication-id",
		Version:      1,
		BusinessUnit: request.BusinessUnitID,
		Status:       model.BusinessUnitAuthenticationStatusActive,
		PrivateKey:   "FAKE PEM PRIVATE",
		Certificate:  "FAKE PEM CERT",
	}
	listAuthResult := storage.ListAuthenticationResult{
		Total:   1,
		Records: []model.BusinessUnitAuthentication{buAuth},
	}

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(0)).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().ListAuthentication(gomock.Any(), s.tx, listAuthRequest).Return(listAuthResult, nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
		s.jwtFactory.EXPECT().NewJWSSigner(buAuth).Return(nil, nil),
	)

	_, err := s.buManager.GetJWSSigner(s.ctx, request)
	s.NoError(err)
}

func (s *BusinessUnitManagerTestSuite) TestGetJWEEncryptors() {
	request := business_unit.GetJWEEncryptorsRequest{
		BusinessUnitIDs: []string{"did:openebl:alice", "did:openebl:bob"},
	}

	listBusinessUnitsRequest := storage.ListBusinessUnitsRequest{
		Limit:           2,
		BusinessUnitIDs: []string{"did:openebl:alice", "did:openebl:bob"},
	}
	buAlice := storage.ListBusinessUnitsRecord{
		BusinessUnit: model.BusinessUnit{ID: did.NewDID("openebl", "alice")},
		Authentications: []model.BusinessUnitAuthentication{
			{ID: "alice-auth-01", Status: model.BusinessUnitAuthenticationStatusRevoked},
			{ID: "alice-auth-02", Status: model.BusinessUnitAuthenticationStatusActive},
		},
	}
	buBob := storage.ListBusinessUnitsRecord{
		BusinessUnit: model.BusinessUnit{ID: did.NewDID("openebl", "bob")},
		Authentications: []model.BusinessUnitAuthentication{
			{ID: "bob-auth-01", Status: model.BusinessUnitAuthenticationStatusActive},
		},
	}
	listBusinessUnitsResult := storage.ListBusinessUnitsResult{
		Total: 2,
		Records: []storage.ListBusinessUnitsRecord{
			buAlice,
			buBob,
		},
	}

	aliceEncryptor := &business_unit.ECDSAEncryptor{}
	bobEncryptor := &business_unit.RSAEncryptor{}
	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(0)).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().ListBusinessUnits(gomock.Any(), s.tx, listBusinessUnitsRequest).Return(listBusinessUnitsResult, nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
		s.jwtFactory.EXPECT().NewJWEEncryptor(buAlice.Authentications[1]).Return(aliceEncryptor, nil),
		s.jwtFactory.EXPECT().NewJWEEncryptor(buBob.Authentications[0]).Return(bobEncryptor, nil),
	)

	encryptors, err := s.buManager.GetJWEEncryptors(s.ctx, request)
	s.NoError(err)
	s.Require().Len(encryptors, 2)
	s.Assert().Equal(
		[]envelope.KeyEncryptionAlgorithm{
			envelope.KeyEncryptionAlgorithm(jwa.ECDH_ES_A128KW),
			envelope.KeyEncryptionAlgorithm(jwa.ECDH_ES_A192KW),
			envelope.KeyEncryptionAlgorithm(jwa.ECDH_ES_A256KW),
		},
		encryptors[0].AvailableJWEEncryptAlgorithms(),
	)
	s.Assert().Equal(
		[]envelope.KeyEncryptionAlgorithm{
			envelope.KeyEncryptionAlgorithm(jwa.RSA_OAEP),
			envelope.KeyEncryptionAlgorithm(jwa.RSA_OAEP_256),
			envelope.KeyEncryptionAlgorithm(jwa.RSA1_5),
		},
		encryptors[1].AvailableJWEEncryptAlgorithms(),
	)
}
