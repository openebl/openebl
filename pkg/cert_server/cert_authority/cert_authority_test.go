package cert_authority_test

import (
	"context"
	"crypto/x509"
	"os"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/openebl/openebl/pkg/cert_server/cert_authority"
	"github.com/openebl/openebl/pkg/cert_server/model"
	"github.com/openebl/openebl/pkg/cert_server/storage"
	eblpkix "github.com/openebl/openebl/pkg/pkix"
	mock_storage "github.com/openebl/openebl/test/mock/cert_server/storage"
	"github.com/stretchr/testify/suite"
)

type CertAuthorityTestSuite struct {
	suite.Suite

	ctrl    *gomock.Controller
	ctx     context.Context
	storage *mock_storage.MockCertStorage
	tx      *mock_storage.MockTx
	ca      cert_authority.CertAuthority
}

func TestCertAuthorityTestSuite(t *testing.T) {
	suite.Run(t, new(CertAuthorityTestSuite))
}

func (s *CertAuthorityTestSuite) SetupTest() {
	// Initialize the context
	s.ctx = context.Background()

	// Initialize the mock controller
	s.ctrl = gomock.NewController(s.T())

	// Create a new instance of the CertStorage implementation
	s.storage = mock_storage.NewMockCertStorage(s.ctrl)
	s.tx = mock_storage.NewMockTx(s.ctrl)

	// Create a new instance of the CertAuthority implementation
	s.ca = cert_authority.NewCertAuthority(s.storage)
}

func (s *CertAuthorityTestSuite) TearDownTest() {
	// Finish the controller
	s.ctrl.Finish()
}

func (s *CertAuthorityTestSuite) TestListCertificate() {
	cert := model.Cert{
		ID:              "cert_id",
		Version:         1,
		Type:            model.CACert,
		Status:          model.CertStatusActive,
		NotBefore:       1711953471,
		NotAfter:        4867627071,
		CreatedAt:       time.Now().Unix(),
		CreatedBy:       "test",
		Certificate:     "cert",
		CertFingerPrint: "sha1:cert",
		PrivateKey:      "private_key",
	}

	expectedCert := cert
	expectedCert.PrivateKey = ""

	req := storage.ListCertificatesRequest{
		Offset:   1,
		Limit:    2,
		IDs:      []string{"id"},
		Statuses: []model.CertStatus{model.CertStatusActive},
		Types:    []model.CertType{model.CACert},
	}

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(0)).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().ListCertificates(gomock.Any(), s.tx, req).Return(
			storage.ListCertificatesResponse{
				Total: 1,
				Certs: []model.Cert{cert},
			},
			nil,
		),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	result, err := s.ca.ListCertificate(s.ctx, req)
	s.Require().NoError(err)
	s.Require().Len(result.Certs, 1)
	s.Require().Equal(expectedCert, result.Certs[0])
}

func (s *CertAuthorityTestSuite) TestAddRootCertificate() {
	rootCert, err := os.ReadFile("../../../testdata/cert_server/cert_authority/root_cert.crt")
	s.Require().NoError(err)
	ts := time.Now().Unix()
	req := cert_authority.AddRootCertificateRequest{
		Requester: "test",
		Cert:      string(rootCert),
	}

	expectedCert := model.Cert{
		Version:                 1,
		Type:                    model.RootCert,
		Status:                  model.CertStatusActive,
		NotBefore:               1711953471,
		NotAfter:                4867627071,
		CreatedAt:               ts,
		CreatedBy:               "test",
		PublicKeyID:             "13166e296631defe531d0b57648e9a54d2c2dab1",
		Certificate:             string(rootCert),
		CertFingerPrint:         "sha1:eec87a02f48e6a6654886d74e64619c97850110d",
		CertificateSerialNumber: "1",
	}

	var receivedCert model.Cert
	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().AddCertificate(gomock.Any(), s.tx, gomock.Any()).DoAndReturn(func(ctx context.Context, tx storage.Tx, cert model.Cert) error {
			s.Require().NotEmpty(cert.ID)
			receivedCert = cert
			return nil
		}),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	cert, err := s.ca.AddRootCertificate(s.ctx, ts, req)
	s.Assert().NoError(err)
	expectedCert.ID = receivedCert.ID
	s.Assert().Equal(expectedCert, receivedCert)
	s.Assert().Equal(receivedCert, cert)
}

func (s *CertAuthorityTestSuite) TestRevokeRootCertificate() {
	ts := time.Now().Unix()
	rootCert, err := os.ReadFile("../../../testdata/cert_server/cert_authority/root_cert.crt")
	s.Require().NoError(err)

	oldRootCert := model.Cert{
		ID:              "root_cert_id",
		Version:         1,
		Type:            model.RootCert,
		Status:          model.CertStatusActive,
		NotBefore:       1711953471,
		NotAfter:        4867627071,
		CreatedAt:       ts - 1000,
		CreatedBy:       "test",
		Certificate:     string(rootCert),
		CertFingerPrint: "sha1:eec87a02f48e6a6654886d74e64619c97850110d",
	}

	req := cert_authority.RevokeCertificateRequest{
		Requester: "admin",
		CertID:    "root_cert_id",
	}

	expectedCert := oldRootCert
	expectedCert.Version += 1
	expectedCert.Status = model.CertStatusRevoked
	expectedCert.RevokedAt = ts
	expectedCert.RevokedBy = "admin"

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().ListCertificates(
			gomock.Any(),
			s.tx,
			storage.ListCertificatesRequest{
				Limit: 1,
				IDs:   []string{"root_cert_id"},
				Types: []model.CertType{model.RootCert},
			},
		).Return(
			storage.ListCertificatesResponse{
				Total: 1,
				Certs: []model.Cert{oldRootCert},
			},
			nil,
		),
		s.storage.EXPECT().AddCertificate(gomock.Any(), s.tx, expectedCert).Return(nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	cert, err := s.ca.RevokeRootCertificate(s.ctx, ts, req)
	s.Assert().NoError(err)
	s.Assert().Equal(expectedCert, cert)
}

func (s *CertAuthorityTestSuite) TestRevokeRootCertificateWithInvalidCertID() {
	ts := time.Now().Unix()
	req := cert_authority.RevokeCertificateRequest{
		Requester: "admin",
		CertID:    "root_cert_id",
	}

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().ListCertificates(
			gomock.Any(),
			s.tx,
			storage.ListCertificatesRequest{
				Limit: 1,
				IDs:   []string{"root_cert_id"},
				Types: []model.CertType{model.RootCert},
			},
		).Return(
			storage.ListCertificatesResponse{
				Total: 0,
			},
			nil,
		),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	cert, err := s.ca.RevokeRootCertificate(s.ctx, ts, req)
	s.Assert().ErrorIs(err, model.ErrCertNotFound)
	s.Assert().Empty(cert)
}

func (s *CertAuthorityTestSuite) TestCreateCACertificateSigningRequest() {
	ts := time.Now().Unix()
	req := cert_authority.CreateCACertificateSigningRequestRequest{
		Requester:          "test",
		PrivateKeyOption:   eblpkix.PrivateKeyOption{KeyType: eblpkix.PrivateKeyTypeRSA, BitLength: 2048},
		Country:            []string{"US"},
		Organization:       []string{"OpenEBL Foundation"},
		OrganizationalUnit: []string{"OpenEBL Certificate Authority"},
		CommonName:         "OpenEBL CA",
	}

	var receivedCert model.Cert
	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().AddCertificate(gomock.Any(), s.tx, gomock.Any()).DoAndReturn(func(ctx context.Context, tx storage.Tx, cert model.Cert) error {
			s.Require().NotEmpty(cert.ID)
			s.Require().NotEmpty(cert.CertificateSigningRequest)
			s.Require().NotEmpty(cert.PrivateKey)
			receivedCert = cert
			return nil
		}),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	expectedCert := model.Cert{
		Version:   1,
		Type:      model.CACert,
		Status:    model.CertStatusWaitingForIssued,
		CreatedAt: ts,
		CreatedBy: req.Requester,
	}

	cert, err := s.ca.CreateCACertificateSigningRequest(s.ctx, ts, req)
	s.Assert().NoError(err)
	expectedCert.ID = receivedCert.ID
	expectedCert.PrivateKey = receivedCert.PrivateKey
	expectedCert.CertificateSigningRequest = receivedCert.CertificateSigningRequest
	s.Assert().Equal(expectedCert, receivedCert)
	expectedCert.PrivateKey = ""
	s.Assert().Equal(expectedCert, cert)

	csr, err := eblpkix.ParseCertificateRequest([]byte(receivedCert.CertificateSigningRequest))
	s.Require().NoError(err)
	s.Assert().Equal(req.Country, csr.Subject.Country)
	s.Assert().Equal(req.Organization, csr.Subject.Organization)
	s.Assert().Equal(req.OrganizationalUnit, csr.Subject.OrganizationalUnit)
	s.Assert().Equal(req.CommonName, csr.Subject.CommonName)

	// os.WriteFile("../../../testdata/cert_server/cert_authority/ca_cert.csr", []byte(cert.CertificateSigningRequest), 0644)
	// os.WriteFile("../../../testdata/cert_server/cert_authority/ca_cert_priv_key.pem", []byte(cert.PrivateKey), 0644)
}

func (s *CertAuthorityTestSuite) TestRespondCACertificateSigningRequest() {
	ts := time.Now().Unix()

	rootCert, err := os.ReadFile("../../../testdata/cert_server/cert_authority/root_cert.crt")
	s.Require().NoError(err)
	caCert, err := os.ReadFile("../../../testdata/cert_server/cert_authority/ca_cert.crt")
	s.Require().NoError(err)
	caCert = append(caCert, rootCert...)
	caCertPrivKey, err := os.ReadFile("../../../testdata/cert_server/cert_authority/ca_cert_priv_key.pem")
	s.Require().NoError(err)
	caCertCSR, err := os.ReadFile("../../../testdata/cert_server/cert_authority/ca_cert.csr")
	s.Require().NoError(err)

	rootCertObj := model.Cert{
		ID:          "root_cert_id",
		Version:     1,
		Type:        model.RootCert,
		Status:      model.CertStatusActive,
		CreatedAt:   time.Now().Unix() - 1000,
		CreatedBy:   "test",
		Certificate: string(rootCert),
	}

	oldCert := model.Cert{
		ID:                        "ca_cert_id",
		Version:                   1,
		Type:                      model.CACert,
		Status:                    model.CertStatusWaitingForIssued,
		CreatedAt:                 time.Now().Unix() - 1000,
		CreatedBy:                 "test",
		CertificateSigningRequest: string(caCertCSR),
		PrivateKey:                string(caCertPrivKey),
	}

	req := cert_authority.RespondCACertificateSigningRequestRequest{
		Requester: "admin",
		CertID:    "ca_cert_id",
		Cert:      string(caCert),
	}

	expectedCert := oldCert
	expectedCert.Version += 1
	expectedCert.Status = model.CertStatusActive
	expectedCert.IssuedAt = ts
	expectedCert.IssuedBy = "admin"
	expectedCert.PublicKeyID = "f26941eb9d1623ea39111102cca949acac883ddf"
	expectedCert.IssuerKeyID = "13166e296631defe531d0b57648e9a54d2c2dab1"
	expectedCert.Certificate = string(caCert)
	expectedCert.CertFingerPrint = "sha1:4f5e1200492e23d85b77f73d67133fe64298948a"
	expectedCert.CertificateSerialNumber = "647840420638654771235247765924303228213807950539"
	expectedCert.NotBefore = 1711960293
	expectedCert.NotAfter = 4865560293

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().ListCertificates(
			gomock.Any(),
			s.tx,
			storage.ListCertificatesRequest{
				Limit:    100,
				Types:    []model.CertType{model.RootCert},
				Statuses: []model.CertStatus{model.CertStatusActive},
			},
		).Return(
			storage.ListCertificatesResponse{
				Total: 1,
				Certs: []model.Cert{rootCertObj},
			},
			nil,
		),
		s.storage.EXPECT().ListCertificates(
			gomock.Any(),
			s.tx,
			storage.ListCertificatesRequest{
				Limit: 1,
				IDs:   []string{"ca_cert_id"},
				Types: []model.CertType{model.CACert},
			},
		).Return(
			storage.ListCertificatesResponse{
				Total: 1,
				Certs: []model.Cert{oldCert},
			},
			nil,
		),
		s.storage.EXPECT().AddCertificate(gomock.Any(), s.tx, expectedCert).Return(nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	cert, err := s.ca.RespondCACertificateSigningRequest(s.ctx, ts, req)
	s.Assert().NoError(err)
	expectedCert.PrivateKey = ""
	s.Assert().Equal(expectedCert, cert)
}

func (s *CertAuthorityTestSuite) TestAddCertificateSigningRequest() {
	ts := time.Now().Unix()

	csr, err := os.ReadFile("../../../testdata/cert_server/cert_authority/bu_cert.csr")
	s.Require().NoError(err)

	for _, certType := range []model.CertType{model.ThirdPartyCACert, model.BUCert} {
		req := cert_authority.AddCertificateSigningRequestRequest{
			Requester:          "test",
			CertType:           certType,
			CertSigningRequest: string(csr),
		}

		expectedCert := model.Cert{
			Version:                   1,
			Type:                      certType,
			Status:                    model.CertStatusWaitingForIssued,
			CreatedAt:                 ts,
			CreatedBy:                 req.Requester,
			CertificateSigningRequest: string(csr),
		}

		var receivedCert model.Cert
		gomock.InOrder(
			s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
			s.storage.EXPECT().AddCertificate(gomock.Any(), s.tx, gomock.Any()).DoAndReturn(func(ctx context.Context, tx storage.Tx, cert model.Cert) error {
				s.Require().NotEmpty(cert.ID)
				receivedCert = cert
				return nil
			}),
			s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
			s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
		)

		cert, err := s.ca.AddCertificateSigningRequest(s.ctx, ts, req)
		s.Assert().NoError(err)
		expectedCert.ID = receivedCert.ID
		s.Assert().Equal(expectedCert, receivedCert)
		s.Assert().Equal(expectedCert, cert)
	}
}

func (s *CertAuthorityTestSuite) TestIssueCertificate() {
	ts := time.Now().Unix()

	csr, err := os.ReadFile("../../../testdata/cert_server/cert_authority/bu_cert.csr")
	s.Require().NoError(err)
	rootCert, err := os.ReadFile("../../../testdata/cert_server/cert_authority/root_cert.crt")
	s.Require().NoError(err)
	caCert, err := os.ReadFile("../../../testdata/cert_server/cert_authority/ca_cert.crt")
	s.Require().NoError(err)
	caCert = append(caCert, rootCert...)
	caCertPrivKey, err := os.ReadFile("../../../testdata/cert_server/cert_authority/ca_cert_priv_key.pem")
	s.Require().NoError(err)

	oldCACert := model.Cert{
		ID:              "ca_cert_id",
		Version:         2,
		Type:            model.CACert,
		Status:          model.CertStatusActive,
		CreatedAt:       time.Now().Unix() - 1000,
		CreatedBy:       "test",
		Certificate:     string(caCert),
		PrivateKey:      string(caCertPrivKey),
		CertFingerPrint: "sha1:4f5e1200492e23d85b77f73d67133fe64298948a",
		NotBefore:       1711960293,
		NotAfter:        4865560293,
	}

	for _, certType := range []model.CertType{model.ThirdPartyCACert, model.BUCert} {
		oldCert := model.Cert{
			ID:                        "bu_cert_id",
			Version:                   1,
			Type:                      certType,
			Status:                    model.CertStatusWaitingForIssued,
			CreatedAt:                 time.Now().Unix() - 1000,
			CreatedBy:                 "test",
			CertificateSigningRequest: string(csr),
		}

		req := cert_authority.IssueCertificateRequest{
			Requester: "admin",
			CertID:    "bu_cert_id",
			CACertID:  "ca_cert_id",
			CertType:  certType,
			NotBefore: 1711960293,
			NotAfter:  1711960293 + (86400 * 365 * 2),
		}

		expectedCACert := oldCACert
		expectedCACert.Version += 1
		expectedCACert.IssuedSerialNumber += 1

		expectedCert := oldCert
		expectedCert.Version += 1
		expectedCert.Status = model.CertStatusActive
		expectedCert.IssuedAt = ts
		expectedCert.IssuedBy = req.Requester
		expectedCert.NotBefore = req.NotBefore
		expectedCert.NotAfter = req.NotAfter
		expectedCert.PublicKeyID = "33b967c63a01cd744fc8f815b1aad7a3f51bc3af"
		expectedCert.IssuerKeyID = "f26941eb9d1623ea39111102cca949acac883ddf"
		expectedCert.CertificateSerialNumber = "1"

		var receivedCert model.Cert
		gomock.InOrder(
			s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
			s.storage.EXPECT().ListCertificates(
				gomock.Any(),
				s.tx,
				storage.ListCertificatesRequest{
					Limit: 1,
					IDs:   []string{req.CACertID},
					Types: []model.CertType{model.CACert},
				},
			).Return(
				storage.ListCertificatesResponse{
					Total: 1,
					Certs: []model.Cert{oldCACert},
				},
				nil,
			),
			s.storage.EXPECT().ListCertificates(
				gomock.Any(),
				s.tx,
				storage.ListCertificatesRequest{
					Limit: 1,
					IDs:   []string{req.CertID},
					Types: []model.CertType{req.CertType},
				},
			).Return(
				storage.ListCertificatesResponse{
					Total: 1,
					Certs: []model.Cert{oldCert},
				},
				nil,
			),
			s.storage.EXPECT().AddCertificate(gomock.Any(), s.tx, expectedCACert).Return(nil),
			s.storage.EXPECT().AddCertificate(gomock.Any(), s.tx, gomock.Any()).DoAndReturn(func(ctx context.Context, tx storage.Tx, cert model.Cert) error {
				receivedCert = cert
				s.Assert().NotEmpty(cert.Certificate)
				s.Assert().NotEmpty(cert.CertFingerPrint)
				return nil
			}),
			s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
			s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
		)

		cert, err := s.ca.IssueCertificate(s.ctx, ts, req)
		s.Assert().NoError(err)
		expectedCert.Certificate = receivedCert.Certificate
		expectedCert.CertFingerPrint = receivedCert.CertFingerPrint
		s.Assert().Equal(expectedCert, cert)

		if certType == model.ThirdPartyCACert {
			certs, err := eblpkix.ParseCertificate([]byte(cert.Certificate))
			s.Require().NoError(err)
			s.Require().GreaterOrEqual(len(certs), 1)
			s.Assert().NotZero(certs[0].KeyUsage & (x509.KeyUsageCRLSign | x509.KeyUsageCertSign))
		}
	}
}

func (s *CertAuthorityTestSuite) TestRejectCertificateSigningRequest() {
	ts := time.Now().Unix()

	csr, err := os.ReadFile("../../../testdata/cert_server/cert_authority/bu_cert.csr")
	s.Require().NoError(err)

	oldCert := model.Cert{
		ID:                        "bu_cert_id",
		Version:                   1,
		Type:                      model.BUCert,
		Status:                    model.CertStatusWaitingForIssued,
		CreatedAt:                 time.Now().Unix() - 1000,
		CreatedBy:                 "test",
		CertificateSigningRequest: string(csr),
	}

	req := cert_authority.RejectCertificateSigningRequestRequest{
		Requester: "admin",
		CertID:    "bu_cert_id",
		CertType:  model.BUCert,
		Reason:    "unit test",
	}

	expectedCert := oldCert
	expectedCert.Version += 1
	expectedCert.Status = model.CertStatusRejected
	expectedCert.RejectedAt = ts
	expectedCert.RejectedBy = req.Requester
	expectedCert.RejectReason = req.Reason

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().ListCertificates(
			gomock.Any(),
			s.tx,
			storage.ListCertificatesRequest{
				Limit: 1,
				IDs:   []string{req.CertID},
				Types: []model.CertType{req.CertType},
			},
		).Return(
			storage.ListCertificatesResponse{
				Total: 1,
				Certs: []model.Cert{oldCert},
			},
			nil,
		),
		s.storage.EXPECT().AddCertificate(gomock.Any(), s.tx, expectedCert).Return(nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	cert, err := s.ca.RejectCertificateSigningRequest(s.ctx, ts, req)
	s.Assert().NoError(err)
	s.Assert().Equal(expectedCert, cert)
}
