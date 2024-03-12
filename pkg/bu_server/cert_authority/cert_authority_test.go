package cert_authority_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/openebl/openebl/pkg/bu_server/cert_authority"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	eblpkix "github.com/openebl/openebl/pkg/pkix"
	mock_cert_authority "github.com/openebl/openebl/test/mock/bu_server/cert_authority"
	mock_storage "github.com/openebl/openebl/test/mock/bu_server/storage"
	"github.com/stretchr/testify/suite"
)

type CertAuthorityTestSuite struct {
	suite.Suite

	ctx     context.Context
	ctrl    *gomock.Controller
	storage *mock_cert_authority.MockCertStorage
	tx      *mock_storage.MockTx
	ca      cert_authority.CertAuthority

	caCert      model.Cert
	caECDSACert model.Cert
}

func TestCertAuthorityTestSuite(t *testing.T) {
	suite.Run(t, new(CertAuthorityTestSuite))
}

func (s *CertAuthorityTestSuite) SetupSuite() {
	// Generate Root Certificate and Private Key with RSA.
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	s.Require().NoError(err)

	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:            []string{"US", "TW"},
			Organization:       []string{"BlueX Trade"},
			OrganizationalUnit: []string{"BlueX RD Department"},
			CommonName:         "BlueX Trade Root CA",
		},
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		IsCA:      true,
		NotAfter:  time.Now().AddDate(100, 0, 0),
		NotBefore: time.Now(),
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, &privKey.PublicKey, privKey)
	s.Require().NoError(err)

	privateKeyPemBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	s.Require().NoError(err)
	privateKeyPem := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyPemBytes,
	}
	certPem := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}
	s.caCert = model.Cert{
		ID:          "ca_cert_id",
		Version:     1,
		Type:        model.CACert,
		Status:      model.CertStatusActive,
		NotBefore:   certTemplate.NotBefore.Unix(),
		NotAfter:    certTemplate.NotAfter.Unix(),
		PrivateKey:  string(pem.EncodeToMemory(&privateKeyPem)),
		Certificate: string(pem.EncodeToMemory(&certPem)),
	}

	// Generate Root Certificate and Private Key with ECDSA.
	ecdsaPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s.Require().NoError(err)
	certBytes, err = x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, &ecdsaPrivKey.PublicKey, ecdsaPrivKey)
	s.Require().NoError(err)

	privateKeyPemBytes, err = x509.MarshalPKCS8PrivateKey(ecdsaPrivKey)
	s.Require().NoError(err)
	privateKeyPem = pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyPemBytes,
	}
	certPem = pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}
	s.caECDSACert = model.Cert{
		ID:          "ca_cert_id",
		Version:     1,
		Type:        model.CACert,
		Status:      model.CertStatusActive,
		PrivateKey:  string(pem.EncodeToMemory(&privateKeyPem)),
		Certificate: string(pem.EncodeToMemory(&certPem)),
	}
}

func (s *CertAuthorityTestSuite) SetupTest() {
	s.ctx = context.Background()
	s.ctrl = gomock.NewController(s.T())
	s.storage = mock_cert_authority.NewMockCertStorage(s.ctrl)
	s.tx = mock_storage.NewMockTx(s.ctrl)
	s.ca = cert_authority.NewCertAuthority(s.storage)

}

func (s *CertAuthorityTestSuite) TearDownTest() {
	s.ctrl.Finish()
}

func (s *CertAuthorityTestSuite) TestAddCertificate() {
	ts := time.Now().Unix()

	req := cert_authority.AddCertificateRequest{
		Requester:  "requester",
		Cert:       s.caCert.Certificate,
		PrivateKey: s.caCert.PrivateKey,
	}

	expectedCert := model.Cert{
		Version:     1,
		Type:        model.BUCert,
		Status:      model.CertStatusActive,
		NotBefore:   s.caCert.NotBefore,
		NotAfter:    s.caCert.NotAfter,
		CreatedAt:   ts,
		CreatedBy:   req.Requester,
		PrivateKey:  req.PrivateKey,
		Certificate: req.Cert,
	}

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().AddCertificate(gomock.Any(), s.tx, gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, cert model.Cert) error {
				expectedCert.ID = cert.ID
				expectedCert.CertFingerPrint = cert.CertFingerPrint
				s.Require().Equal(expectedCert, cert)
				return nil
			},
		),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	newCert, err := s.ca.AddCertificate(s.ctx, ts, req)
	s.Require().NoError(err)
	s.Assert().Empty(newCert.PrivateKey)
	newCert.PrivateKey = expectedCert.PrivateKey
	s.Assert().Equal(expectedCert, newCert)

	// Test AddCertificate() with ECDSA private key.
	req.PrivateKey = s.caECDSACert.PrivateKey
	req.Cert = s.caECDSACert.Certificate

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().AddCertificate(gomock.Any(), s.tx, gomock.Any()).Return(nil),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)
	newCert, err = s.ca.AddCertificate(s.ctx, ts, req)
	s.Require().NoError(err)
	s.Assert().Empty(newCert.PrivateKey)
	s.Assert().NotEmpty(newCert.CertFingerPrint)
	s.Assert().NotEmpty(newCert.Certificate)
}

func (s *CertAuthorityTestSuite) TestRevokeCertificate() {
	ts := time.Now().Unix()

	req := cert_authority.RevokeCertificateRequest{
		Requester: "requester",
		CertID:    "cert_id",
	}

	expectedListRequest := cert_authority.ListCertificatesRequest{
		Limit: 1,
		IDs:   []string{req.CertID},
	}
	listResponse := cert_authority.ListCertificatesResponse{
		Total: 1,
		Certs: []model.Cert{s.caCert},
	}

	expectedCert := model.Cert{
		Version:     2,
		Type:        model.CACert,
		Status:      model.CertStatusRevoked,
		NotBefore:   s.caCert.NotBefore,
		NotAfter:    s.caCert.NotAfter,
		RevokedAt:   ts,
		RevokedBy:   req.Requester,
		Certificate: s.caCert.Certificate,
		PrivateKey:  s.caCert.PrivateKey,
	}

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().ListCertificates(gomock.Any(), s.tx, expectedListRequest).Return(listResponse, nil),
		s.storage.EXPECT().AddCertificate(gomock.Any(), s.tx, gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, cert model.Cert) error {
				expectedCert.ID = cert.ID
				expectedCert.CertFingerPrint = cert.CertFingerPrint
				s.Require().Equal(expectedCert, cert)
				return nil
			},
		),
		s.tx.EXPECT().Commit(gomock.Any()).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	newCert, err := s.ca.RevokeCertificate(s.ctx, ts, req)
	s.Require().NoError(err)
	s.Assert().Empty(newCert.PrivateKey)
	newCert.PrivateKey = expectedCert.PrivateKey
	s.Assert().Equal(expectedCert, newCert)
}

func (s *CertAuthorityTestSuite) TestListCertificate() {
	req := cert_authority.ListCertificatesRequest{
		Offset:   1,
		Limit:    2,
		IDs:      []string{"id"},
		Statuses: []model.CertStatus{model.CertStatusActive},
	}
	resp := cert_authority.ListCertificatesResponse{
		Total: 1,
		Certs: []model.Cert{s.caCert},
	}

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(0)).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().ListCertificates(gomock.Any(), s.tx, req).Return(resp, nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	result, err := s.ca.ListCertificates(s.ctx, req)
	s.Require().NoError(err)
	s.Require().Len(result.Certs, 1)
	result.Certs[0].PrivateKey = s.caCert.PrivateKey
	s.Assert().Equal([]model.Cert{s.caCert}, result.Certs)
}

func (s *CertAuthorityTestSuite) TestIssueCertificate() {
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	s.Require().NoError(err)

	certRequestTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			Country:            []string{"US", "TW"},
			Organization:       []string{"OpenEBL"},
			OrganizationalUnit: []string{"BlueX RD Department"},
			CommonName:         "OpenEBL Test BU",
		},
	}

	certRequestBytes, err := x509.CreateCertificateRequest(rand.Reader, &certRequestTemplate, privKey)
	s.Require().NoError(err)
	certRequest, err := x509.ParseCertificateRequest(certRequestBytes)
	s.Require().NoError(err)

	issueRequest := cert_authority.IssueCertificateRequest{
		CACertID:           "ca_cert_id",
		CertificateRequest: *certRequest,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(1, 0, 0),
	}

	expectedListCertRequest := cert_authority.ListCertificatesRequest{
		Limit:     1,
		Statuses:  []model.CertStatus{model.CertStatusActive},
		ValidFrom: issueRequest.NotBefore.Unix(),
		ValidTo:   issueRequest.NotAfter.Unix(),
	}
	listCertResponse := cert_authority.ListCertificatesResponse{
		Total: 1,
		Certs: []model.Cert{s.caCert},
	}

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Any()).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().ListCertificates(gomock.Any(), s.tx, expectedListCertRequest).Return(listCertResponse, nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	newCerts, err := s.ca.IssueCertificate(s.ctx, time.Now().Unix(), issueRequest)
	s.Require().NoError(err)
	s.Require().Len(newCerts, 2)
	s.Require().NotNil(newCerts[0].PublicKey)
	caCerts, _ := eblpkix.ParseCertificate([]byte(s.caCert.Certificate))
	s.Require().Equal(newCerts[1], caCerts[0])

	// Test certificate request with expired CA certificate.
	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Any()).Return(s.tx, s.ctx, nil),
		s.storage.EXPECT().ListCertificates(gomock.Any(), s.tx, expectedListCertRequest).Return(listCertResponse, nil),
		s.tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	newCerts, err = s.ca.IssueCertificate(s.ctx, time.Now().AddDate(200, 0, 0).Unix(), issueRequest)
	s.Require().ErrorIs(err, model.ErrCertificationExpired)
	s.Require().Empty(newCerts)
	// End of Test certificate request with expired CA certificate.

	// Test certificate request with wrong public key/signature.
	newPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	s.Require().NoError(err)
	certRequest.PublicKey = newPrivKey.Public()
	issueRequest.CertificateRequest = *certRequest

	newCerts, err = s.ca.IssueCertificate(s.ctx, time.Now().Unix(), issueRequest)
	s.Require().Error(err)
	s.Require().Empty(newCerts)
	// End of Test certificate request with wrong public key/signature.
}
