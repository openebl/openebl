package cert_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	cert_model "github.com/openebl/openebl/pkg/cert_server/model"
	cert_storage "github.com/openebl/openebl/pkg/cert_server/storage"
	eblpkix "github.com/openebl/openebl/pkg/pkix"
	"github.com/openebl/openebl/pkg/relay/server/cert"
	"github.com/openebl/openebl/pkg/relay/server/storage"
	mock_storage "github.com/openebl/openebl/test/mock/relay/server/storage"
	"github.com/stretchr/testify/suite"
)

type CertTestSuite struct {
	suite.Suite

	ctrl      *gomock.Controller
	certStore *mock_storage.MockCertDataStore

	certs     []cert_model.Cert
	x509Certs []*x509.Certificate
}

type _MockCertAuthorityServer struct {
	Certs []cert_model.Cert
}

func (m *_MockCertAuthorityServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	offsetStr := r.URL.Query().Get("offset")
	offset, _ := strconv.Atoi(offsetStr)

	result := cert_storage.ListCertificatesResponse{
		Total: int64(max(len(m.Certs)-offset, 0)),
	}

	if offset < len(m.Certs) {
		result.Certs = m.Certs[offset:]
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func TestCert(t *testing.T) {
	suite.Run(t, new(CertTestSuite))
}

func (s *CertTestSuite) SetupTest() {
	certRaw1, err := os.ReadFile("../../../../testdata/cert_server/cert_authority/root_cert.crt")
	s.Require().NoError(err)
	cert1X509, err := eblpkix.ParseCertificate(certRaw1)
	s.Require().NoError(err)
	certRaw2, err := os.ReadFile("../../../../testdata/cert_server/cert_authority/ca_cert.crt")
	s.Require().NoError(err)
	cert2X509, err := eblpkix.ParseCertificate(certRaw2)
	s.Require().NoError(err)
	certRaw3, err := os.ReadFile("../../../../testdata/cert_server/cert_authority/bu_cert.crt")
	s.Require().NoError(err)
	cert3X509, err := eblpkix.ParseCertificate(certRaw3)
	s.Require().NoError(err)
	cert1 := cert_model.Cert{
		ID:              "root_cert",
		Version:         1,
		Type:            cert_model.RootCert,
		Status:          cert_model.CertStatusActive,
		Certificate:     string(certRaw1),
		CertFingerPrint: eblpkix.GetFingerPrintFromCertificate(cert1X509[0]),
	}
	cert2 := cert_model.Cert{
		ID:              "ca_cert",
		Version:         1,
		Type:            cert_model.RootCert,
		Status:          cert_model.CertStatusRevoked,
		Certificate:     string(certRaw2),
		CertFingerPrint: eblpkix.GetFingerPrintFromCertificate(cert2X509[0]),
	}
	cert3 := cert_model.Cert{
		ID:              "bu_cert",
		Version:         1,
		Type:            cert_model.BUCert,
		Status:          cert_model.CertStatusActive,
		Certificate:     string(certRaw3),
		CertFingerPrint: eblpkix.GetFingerPrintFromCertificate(cert3X509[0]),
	}
	s.certs = []cert_model.Cert{cert1, cert2, cert3}
	s.x509Certs = []*x509.Certificate{cert1X509[0], cert2X509[0], cert3X509[0]}

	s.ctrl = gomock.NewController(s.T())
	s.certStore = mock_storage.NewMockCertDataStore(s.ctrl)
}

func (s *CertTestSuite) TearDownTest() {
	s.ctrl.Finish()
}

func (s *CertTestSuite) TestVerifyCert() {
	certMgr := cert.NewCertManager(cert.WithCertStore(s.certStore))
	ts := time.Now().Unix()

	certChain := []*x509.Certificate{s.x509Certs[2], s.x509Certs[1], s.x509Certs[0]}
	expectedGetCRLReq := storage.GetCRLRequest{
		RevokedAt: ts,
		IssuerKeysAndCertSerialNumbers: []storage.IssuerKeyAndCertSerialNumber{
			{
				IssuerKeyID:       eblpkix.GetSubjectKeyIDFromCertificate(s.x509Certs[2]),
				CertificateSerial: s.x509Certs[2].SerialNumber.String(),
			},
			{
				IssuerKeyID:       eblpkix.GetSubjectKeyIDFromCertificate(s.x509Certs[1]),
				CertificateSerial: s.x509Certs[1].SerialNumber.String(),
			},
			{
				IssuerKeyID:       eblpkix.GetSubjectKeyIDFromCertificate(s.x509Certs[0]),
				CertificateSerial: s.x509Certs[0].SerialNumber.String(),
			},
		},
	}

	// Test Certificate Valid Case
	gomock.InOrder(
		s.certStore.EXPECT().GetCRL(gomock.Any(), expectedGetCRLReq).Return(storage.GetCRLResult{}, nil),
		s.certStore.EXPECT().GetActiveRootCert(gomock.Any()).Return([][]byte{[]byte(s.certs[0].Certificate)}, nil),
	)

	err := certMgr.VerifyCert(context.Background(), ts, certChain)
	s.Require().NoError(err)

	// Test Certification Expired Case
	func() {
		newTs := ts + 200*86400*365
		getCRLReq := expectedGetCRLReq
		getCRLReq.RevokedAt = newTs
		gomock.InOrder(
			s.certStore.EXPECT().GetCRL(gomock.Any(), getCRLReq).Return(storage.GetCRLResult{}, nil),
			s.certStore.EXPECT().GetActiveRootCert(gomock.Any()).Return([][]byte{[]byte(s.certs[0].Certificate)}, nil),
		)
		err = certMgr.VerifyCert(context.Background(), newTs, certChain)
		s.Require().Error(err)
	}()

	// Test Certification Revoked Case
	crlRaw, err := os.ReadFile("../../../../testdata/cert_server/cert_authority/ca_cert.crl")
	s.Require().NoError(err)
	crl, err := eblpkix.ParseCertificateRevocationList(crlRaw)
	s.Require().NoError(err)

	gomock.InOrder(
		s.certStore.EXPECT().GetCRL(gomock.Any(), expectedGetCRLReq).Return(
			storage.GetCRLResult{
				CRLs: map[storage.IssuerKeyAndCertSerialNumber][]byte{
					{
						IssuerKeyID:       eblpkix.GetAuthorityKeyIDFromCertificateRevocationList(crl),
						CertificateSerial: crl.RevokedCertificateEntries[0].SerialNumber.String(),
					}: crlRaw,
				},
			},
			nil,
		),
		s.certStore.EXPECT().GetActiveRootCert(gomock.Any()).Return([][]byte{[]byte(s.certs[0].Certificate)}, nil),
	)
	err = certMgr.VerifyCert(context.Background(), ts, certChain)
	s.Require().Error(err)
}

func (s *CertTestSuite) TestSyncRootCert() {
	mockHttpHandler := &_MockCertAuthorityServer{
		Certs: s.certs[:2],
	}
	certServer := httptest.NewServer(mockHttpHandler)
	certMgr := cert.NewCertManager(cert.WithCertStore(s.certStore), cert.WithCertServerURL(certServer.URL))
	defer certServer.Close()

	gomock.InOrder(
		s.certStore.EXPECT().AddRootCert(gomock.Any(), gomock.Not(int64(0)), gomock.Any(), gomock.Eq([]byte(s.certs[0].Certificate))).Return(nil),
		s.certStore.EXPECT().RevokeRootCert(gomock.Any(), gomock.Not(int64(0)), gomock.Eq(s.certs[1].CertFingerPrint)).Return(nil),
	)

	err := certMgr.SyncRootCerts(context.Background())
	s.Require().NoError(err)
}

func (s *CertTestSuite) TestAddCRL() {
	crlRaw, err := os.ReadFile("../../../../testdata/cert_server/cert_authority/ca_cert.crl")
	s.Require().NoError(err)
	crl, err := eblpkix.ParseCertificateRevocationList(crlRaw)
	s.Require().NoError(err)

	certMgr := cert.NewCertManager(cert.WithCertStore(s.certStore))

	gomock.InOrder(
		s.certStore.EXPECT().AddCRL(
			gomock.Any(),
			gomock.Not(int64(0)),
			gomock.Eq(eblpkix.GetAuthorityKeyIDFromCertificateRevocationList(crl)),
			gomock.Eq(crl.RevokedCertificateEntries[0].SerialNumber.String()),
			gomock.Eq(crl.RevokedCertificateEntries[0].RevocationTime.Unix()),
			gomock.Eq(crlRaw),
		).Return(nil),
	)

	err = certMgr.AddCRL(context.Background(), []byte(crlRaw))
	s.Require().NoError(err)
}
