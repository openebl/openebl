package postgres_test

import (
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/bu_server/storage/postgres"
	eblpkix "github.com/openebl/openebl/pkg/pkix"
	"github.com/stretchr/testify/suite"
)

type CertStorageTestSuite struct {
	BaseTestSuite
	storage storage.CertStorage
}

func TestCertStorage(t *testing.T) {
	suite.Run(t, new(CertStorageTestSuite))
}

func (s *CertStorageTestSuite) SetupTest() {
	s.BaseTestSuite.SetupTest()
	s.storage = postgres.NewStorageWithPool(s.pgPool)
}

func (s *CertStorageTestSuite) TearDownTest() {
	s.BaseTestSuite.TearDownTest()
}

func (s *CertStorageTestSuite) TestRootCert() {
	ts := time.Now().Unix()
	certRaw, err := os.ReadFile("../../../../testdata/cert_server/cert_authority/root_cert.crt")
	s.Require().NoError(err)

	cert, err := eblpkix.ParseCertificate(certRaw)
	s.Require().NoError(err)
	fingerPrint := eblpkix.GetFingerPrintFromCertificate(cert[0])

	tx, ctx, err := s.storage.CreateTx(s.ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelLinearizable))
	s.Require().NoError(err)
	defer tx.Rollback(ctx)

	// AddRootCert then GetActiveRootCert.
	for i := 0; i < 2; i++ {
		err = s.storage.AddRootCert(ctx, tx, ts, fingerPrint, certRaw)
		s.Require().NoError(err)
	}
	certsRaw, err := s.storage.GetActiveRootCert(ctx, tx)
	s.Require().NoError(err)
	s.Require().Len(certsRaw, 1)
	s.Require().Equal(certRaw, certsRaw[0])

	// Revoke Root Cert then GetActiveRootCert.
	s.Require().NoError(s.storage.RevokeRootCert(ctx, tx, ts, fingerPrint))
	certsRaw, err = s.storage.GetActiveRootCert(ctx, tx)
	s.Require().NoError(err)
	s.Require().Empty(certsRaw)

	s.Require().NoError(tx.Commit(ctx))
}

func (s *CertStorageTestSuite) TestCRL() {
	ts := time.Now().Unix()
	crlRaw, err := os.ReadFile("../../../../testdata/cert_server/cert_authority/ca_cert.crl")
	s.Require().NoError(err)

	crl, err := eblpkix.ParseCertificateRevocationList(crlRaw)
	s.Require().NoError(err)
	issuerKeyID := eblpkix.GetAuthorityKeyIDFromCertificateRevocationList(crl)
	certSerialNumber := crl.RevokedCertificateEntries[0].SerialNumber.String()
	revokedAt := crl.RevokedCertificateEntries[0].RevocationTime.Unix()

	tx, ctx, err := s.storage.CreateTx(s.ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelLinearizable))
	s.Require().NoError(err)
	defer tx.Rollback(ctx)

	for i := 0; i < 2; i++ {
		err = s.storage.AddCRL(ctx, tx, ts, issuerKeyID, certSerialNumber, revokedAt, crlRaw)
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
	result, err := s.storage.GetCRL(ctx, tx, getCRLReq)
	s.Require().NoError(err)
	s.Require().Len(result.CRLs, 1)
	s.Assert().Equal(crlRaw, result.CRLs[getCRLReq.IssuerKeysAndCertSerialNumbers[0]])

	getCRLReq.RevokedAt = 1
	result, err = s.storage.GetCRL(ctx, tx, getCRLReq)
	s.Require().NoError(err)
	s.Require().Empty(result.CRLs)

	s.Require().NoError(tx.Commit(ctx))
}
