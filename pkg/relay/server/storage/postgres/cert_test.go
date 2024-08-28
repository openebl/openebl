package postgres_test

import (
	"os"
	"testing"
	"time"

	eblpkix "github.com/openebl/openebl/pkg/pkix"
	"github.com/openebl/openebl/pkg/relay/server/storage"
	"github.com/openebl/openebl/pkg/relay/server/storage/postgres"
	"github.com/stretchr/testify/suite"
)

type CertStorageTestSuite struct {
	BaseStorageTestSuite
	storage storage.CertDataStore
}

func TestCertStorage(t *testing.T) {
	suite.Run(t, new(CertStorageTestSuite))
}

func (s *CertStorageTestSuite) SetupSuite() {
	s.BaseStorageTestSuite.SetupSuite()
	s.storage = postgres.NewEventStorageWithPool(s.pgPool)
}

func (s *CertStorageTestSuite) TearDownSuite() {
	s.BaseStorageTestSuite.TearDownSuite()
}

func (s *CertStorageTestSuite) TestRootCert() {
	ts := time.Now().Unix()
	certRaw, err := os.ReadFile("../../../../../testdata/cert_server/cert_authority/root_cert.crt")
	s.Require().NoError(err)

	cert, err := eblpkix.ParseCertificate(certRaw)
	s.Require().NoError(err)
	fingerPrint := eblpkix.GetFingerPrintFromCertificate(cert[0])

	// AddRootCert then GetActiveRootCert.
	for i := 0; i < 2; i++ {
		err = s.storage.AddRootCert(s.ctx, ts, fingerPrint, certRaw)
		s.Require().NoError(err)
	}
	certsRaw, err := s.storage.GetActiveRootCert(s.ctx)
	s.Require().NoError(err)
	s.Require().Len(certsRaw, 1)
	s.Require().Equal(certRaw, certsRaw[0])

	// Revoke Root Cert then GetActiveRootCert.
	s.Require().NoError(s.storage.RevokeRootCert(s.ctx, ts, fingerPrint))
	certsRaw, err = s.storage.GetActiveRootCert(s.ctx)
	s.Require().NoError(err)
	s.Require().Empty(certsRaw)
}

func (s *CertStorageTestSuite) TestCRL() {
	ts := time.Now().Unix()
	crlRaw, err := os.ReadFile("../../../../../testdata/cert_server/cert_authority/ca_cert.crl")
	s.Require().NoError(err)

	crl, err := eblpkix.ParseCertificateRevocationList(crlRaw)
	s.Require().NoError(err)
	issuerKeyID := eblpkix.GetAuthorityKeyIDFromCertificateRevocationList(crl)
	certSerialNumber := crl.RevokedCertificateEntries[0].SerialNumber.String()
	revokedAt := crl.RevokedCertificateEntries[0].RevocationTime.Unix()

	for i := 0; i < 2; i++ {
		err = s.storage.AddCRL(s.ctx, ts, issuerKeyID, certSerialNumber, revokedAt, crlRaw)
		s.Require().NoError(err)
	}

	getCRLReq := storage.GetCRLRequest{
		RevokedAt: revokedAt,
		IssuerKeysAndCertSerialNumbers: []storage.IssuerKeyAndCertSerialNumber{
			{
				IssuerKeyID:       issuerKeyID,
				CertificateSerial: certSerialNumber,
			},
		},
	}
	result, err := s.storage.GetCRL(s.ctx, getCRLReq)
	s.Require().NoError(err)
	s.Require().Len(result.CRLs, 1)
	s.Assert().Equal(crlRaw, result.CRLs[getCRLReq.IssuerKeysAndCertSerialNumbers[0]])

	getCRLReq.RevokedAt = 1
	result, err = s.storage.GetCRL(s.ctx, getCRLReq)
	s.Require().NoError(err)
	s.Require().Empty(result.CRLs)
}
