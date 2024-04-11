package business_unit_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did/did"
	"github.com/openebl/openebl/pkg/bu_server/business_unit"
	"github.com/openebl/openebl/pkg/bu_server/cert_authority"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/pkix"
	eblpkix "github.com/openebl/openebl/pkg/pkix"
	mock_business_unit "github.com/openebl/openebl/test/mock/bu_server/business_unit"
	mock_cert_authority "github.com/openebl/openebl/test/mock/bu_server/cert_authority"
	mock_storage "github.com/openebl/openebl/test/mock/bu_server/storage"
	mock_webhook "github.com/openebl/openebl/test/mock/bu_server/webhook"
	"github.com/stretchr/testify/suite"
)

type BusinessUnitManagerTestSuite struct {
	suite.Suite
	ctx              context.Context
	ctrl             *gomock.Controller
	storage          *mock_storage.MockBusinessUnitStorage
	webhookCtrl      *mock_webhook.MockWebhookController
	jwsSignerFactory *mock_business_unit.MockJWSSignerFactory
	ca               *mock_cert_authority.MockCertAuthority
	tx               *mock_storage.MockTx
	buManager        business_unit.BusinessUnitManager
}

func TestBusinessUnitManager(t *testing.T) {
	suite.Run(t, new(BusinessUnitManagerTestSuite))
}

func (s *BusinessUnitManagerTestSuite) SetupTest() {
	s.ctx = context.Background()
	s.ctrl = gomock.NewController(s.T())
	s.storage = mock_storage.NewMockBusinessUnitStorage(s.ctrl)
	s.webhookCtrl = mock_webhook.NewMockWebhookController(s.ctrl)
	s.jwsSignerFactory = mock_business_unit.NewMockJWSSignerFactory(s.ctrl)
	s.ca = mock_cert_authority.NewMockCertAuthority(s.ctrl)
	s.tx = mock_storage.NewMockTx(s.ctrl)
	s.buManager = business_unit.NewBusinessUnitManager(s.storage, s.ca, s.webhookCtrl, s.jwsSignerFactory)
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

	request := business_unit.UpdateBusinessUnitRequest{
		Requester:     "requester",
		ApplicationID: "application-id",
		ID:            did.MustParseDID("did:openebl:u0e2345"),
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
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	newBu, err := s.buManager.UpdateBusinessUnit(s.ctx, ts, request)
	s.NoError(err)
	s.Assert().Equal(expectedBusinessUnit, newBu)
}

func (s *BusinessUnitManagerTestSuite) TestListBusinessUnits() {
	request := storage.ListBusinessUnitsRequest{
		Offset:          1,
		Limit:           10,
		ApplicationID:   "application-id",
		BusinessUnitIDs: []string{"did:openebl:u0e2345"},
	}

	expectedBusinessUnit := model.BusinessUnit{
		ID:            did.MustParseDID("did:openebl:u0e2345"),
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
		ID:            did.MustParseDID("did:openebl:u0e2345"),
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
		BusinessUnitID: did.MustParseDID("did:openebl:u0e2345"),
		PrivateKeyOption: eblpkix.PrivateKeyOption{
			KeyType:   eblpkix.PrivateKeyTypeECDSA,
			CurveType: eblpkix.ECDSACurveTypeP384,
		},
		ExpiredAfter: 86400 * 365,
	}

	bu := model.BusinessUnit{
		ID:            did.MustParseDID("did:openebl:bu1"),
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
		Status:       model.BusinessUnitAuthenticationStatusActive,
		CreatedAt:    ts,
		CreatedBy:    request.Requester,
	}

	receivedCertRequest := x509.CertificateRequest{}

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(0)).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().ListBusinessUnits(gomock.Any(), s.tx, expectedListBuRequest).Return(listBuResult, nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
		s.ca.EXPECT().IssueCertificate(gomock.Any(), ts, gomock.Any()).DoAndReturn(
			func(ctx context.Context, ts int64, req cert_authority.IssueCertificateRequest) ([]*x509.Certificate, error) {
				s.Assert().Equal("name", req.CertificateRequest.Subject.Organization[0])
				s.Assert().Equal("did:openebl:bu1", req.CertificateRequest.Subject.CommonName)
				s.Assert().Equal("US", req.CertificateRequest.Subject.Country[0])
				s.Assert().Equal("__root__", req.CACertID)
				s.Assert().Equal(time.Unix(ts, 0), req.NotBefore)
				s.Assert().Equal(time.Unix(ts+request.ExpiredAfter, 0), req.NotAfter)
				receivedCertRequest = req.CertificateRequest
				emptyCert := x509.Certificate{}
				return []*x509.Certificate{&emptyCert, &emptyCert}, nil
			},
		),
		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().StoreAuthentication(gomock.Any(), s.tx, gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, auth model.BusinessUnitAuthentication) error {
				receivedAuthentication.ID = auth.ID
				receivedAuthentication.PrivateKey = auth.PrivateKey
				receivedAuthentication.Certificate = auth.Certificate
				receivedAuthentication.CertFingerPrint = auth.CertFingerPrint
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
	s.Assert().NotEmpty(receivedAuthentication.Certificate)

	// Check if receivedCertRequest is valid and have correct public key.
	privateKey, err := pkix.ParsePrivateKey([]byte(receivedAuthentication.PrivateKey))
	s.Require().NoError(err)
	publicKey := privateKey.(*ecdsa.PrivateKey).PublicKey
	s.Assert().True(publicKey.Equal(receivedCertRequest.PublicKey))
	s.Assert().Nil(receivedCertRequest.CheckSignature())
}

func (s *BusinessUnitManagerTestSuite) TestRevokeAuthentication() {
	ts := time.Now().Unix()

	request := business_unit.RevokeAuthenticationRequest{
		Requester:        "requester",
		ApplicationID:    "application-id",
		BusinessUnitID:   did.MustParseDID("did:openebl:u0e2345"),
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
		BusinessUnit: did.MustParseDID(request.BusinessUnitID),
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
		BusinessUnitID:   did.MustParseDID("did:openebl:u0e2345"),
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
		s.jwsSignerFactory.EXPECT().NewJWSSigner(buAuth).Return(nil, nil),
	)

	_, err := s.buManager.GetJWSSigner(s.ctx, request)
	s.NoError(err)
}
