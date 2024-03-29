package postgres_test

import (
	"database/sql"
	"testing"
	"time"

	"github.com/go-testfixtures/testfixtures/v3"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/openebl/openebl/pkg/bu_server/cert_authority"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/bu_server/storage/postgres"
	"github.com/stretchr/testify/suite"
)

type CertificateTestSuite struct {
	BaseTestSuite
	storage cert_authority.CertStorage
}

func TestCertitiicateTestSuite(t *testing.T) {
	suite.Run(t, new(CertificateTestSuite))
}

func (s *CertificateTestSuite) SetupTest() {
	s.BaseTestSuite.SetupTest()
	s.storage = postgres.NewStorageWithPool(s.pgPool)

	db := stdlib.OpenDBFromPool(s.pgPool)
	fixtures, err := testfixtures.New(
		testfixtures.Database(db),
		testfixtures.Dialect("postgres"),
		testfixtures.Directory("testdata/certificate"),
	)
	s.Require().NoError(err)
	s.Require().NoError(fixtures.Load())

}

func (s *CertificateTestSuite) TearDownTest() {
	s.BaseTestSuite.TearDownTest()
}

func (s *CertificateTestSuite) TestAddCertificate() {
	ts := time.Now().Unix()
	cert := model.Cert{
		ID:              "cert_1",
		Version:         1,
		Type:            model.BUCert,
		Status:          model.CertStatusActive,
		NotBefore:       ts,
		NotAfter:        ts + 86400*365,
		CreatedAt:       ts,
		CreatedBy:       "user_1",
		PrivateKey:      "PRIVATEKEY",
		Certificate:     "CERTIFICATE",
		CertFingerPrint: "fingerprint_1",
	}

	newCert := cert
	newCert.Version = 2
	newCert.Status = model.CertStatusRevoked
	newCert.RevokedAt = ts + 10
	newCert.RevokedBy = "user_2"

	tx, ctx, err := s.storage.CreateTx(s.ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	s.Require().NoError(err)
	defer tx.Rollback(ctx)

	err = s.storage.AddCertificate(ctx, tx, cert)
	s.Require().NoError(err)
	err = s.storage.AddCertificate(ctx, tx, newCert)
	s.Require().NoError(err)

	var certsOnDB []model.Cert
	err = tx.QueryRow(ctx, "SELECT array_agg(cert) FROM certificate WHERE id = $1", cert.ID).Scan(&certsOnDB)
	s.Require().NoError(err)
	s.Require().Len(certsOnDB, 1)
	s.Assert().Equal(newCert, certsOnDB[0])

	err = tx.QueryRow(ctx, "SELECT array_agg(cert ORDER BY rec_id ASC) FROM certificate_history WHERE id = $1", cert.ID).Scan(&certsOnDB)
	s.Require().NoError(err)
	s.Require().Len(certsOnDB, 2)
	s.Assert().Equal([]model.Cert{cert, newCert}, certsOnDB)

	s.Require().NoError(tx.Commit(ctx))
}

func (s *CertificateTestSuite) TestListCertificates() {
	tx, ctx, err := s.storage.CreateTx(s.ctx)
	s.Require().NoError(err)
	defer tx.Rollback(ctx)

	req := cert_authority.ListCertificatesRequest{
		Limit: 10,
	}

	result, err := s.storage.ListCertificates(ctx, tx, req)
	s.Require().NoError(err)
	s.Assert().Equal(int64(2), result.Total)
	s.Require().Len(result.Certs, 2)
	s.Assert().Equal("cert1", result.Certs[0].ID)
	s.Assert().Equal("cert2", result.Certs[1].ID)

	func() {
		req.IDs = []string{"cert1"}
		defer func() {
			req.IDs = nil
		}()
		result, err = s.storage.ListCertificates(ctx, tx, req)
		s.Require().NoError(err)
		s.Assert().Equal(int64(1), result.Total)
		s.Require().Len(result.Certs, 1)
		s.Assert().Equal("cert1", result.Certs[0].ID)
	}()

	func() {
		req.Statuses = []model.CertStatus{model.CertStatusRevoked}
		defer func() {
			req.Statuses = nil
		}()
		result, err = s.storage.ListCertificates(ctx, tx, req)
		s.Require().NoError(err)
		s.Assert().Equal(int64(1), result.Total)
		s.Require().Len(result.Certs, 1)
		s.Assert().Equal("cert2", result.Certs[0].ID)
	}()

	func() {
		req.ValidFrom = 1633024800
		req.ValidTo = 1633024800 + 86400*365
		defer func() {
			req.ValidFrom = 0
			req.ValidTo = 0
		}()

		result, err = s.storage.ListCertificates(ctx, tx, req)
		s.Require().NoError(err)
		s.Assert().Equal(int64(1), result.Total)
		s.Require().Len(result.Certs, 1)
		s.Assert().Equal("cert1", result.Certs[0].ID)
	}()
}
