package postgres_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/go-testfixtures/testfixtures/v3"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/openebl/openebl/pkg/cert_server/model"
	"github.com/openebl/openebl/pkg/cert_server/storage"
	"github.com/openebl/openebl/pkg/cert_server/storage/postgres"
	"github.com/openebl/openebl/pkg/util"
	"github.com/stretchr/testify/suite"
)

type CertStorageSuite struct {
	suite.Suite

	ctx    context.Context
	pgPool *pgxpool.Pool

	storage storage.CertStorage
}

func TestCertStorage(t *testing.T) {
	suite.Run(t, new(CertStorageSuite))
}

func (s *CertStorageSuite) SetupTest() {
	s.ctx = context.Background()
	dbHost := os.Getenv("DATABASE_HOST")
	dbPort, err := strconv.Atoi(os.Getenv("DATABASE_PORT"))
	if err != nil {
		dbPort = 5432
	}
	dbName := os.Getenv("DATABASE_NAME")
	userName := os.Getenv("DATABASE_USER")
	password := os.Getenv("DATABASE_PASSWORD")

	config := util.PostgresDatabaseConfig{
		Host:     dbHost,
		Port:     dbPort,
		Database: dbName,
		User:     userName,
		Password: password,
		SSLMode:  "disable",
		PoolSize: 5,
	}

	pool, err := util.NewPostgresDBPool(config)
	s.Require().NoError(err)
	s.pgPool = pool

	tableNames := []string{
		"cert",
		"cert_history",
	}
	for _, tableName := range tableNames {
		_, err := pool.Exec(context.Background(), fmt.Sprintf(`DELETE FROM %q`, tableName))
		s.Require().NoError(err)
	}

	s.storage = postgres.NewStorageWithPool(pool)
}

func (s *CertStorageSuite) TearDownTest() {
	s.pgPool.Close()
}

func (s *CertStorageSuite) TestAddCertificate() {
	tx, ctx, err := s.storage.CreateTx(s.ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	s.Require().NoError(err)
	defer tx.Rollback(ctx)

	cert := model.Cert{
		ID:        "test-id",
		Version:   1,
		Type:      model.RootCert,
		Status:    model.CertStatusActive,
		CreatedAt: 12345,
	}

	err = s.storage.AddCertificate(ctx, tx, cert)
	s.Require().NoError(err)

	certV2 := cert
	certV2.Version = 2
	certV2.RevokedAt = 12346
	certV2.Status = model.CertStatusRevoked

	err = s.storage.AddCertificate(ctx, tx, certV2)
	s.Require().NoError(err)

	var certOnDB model.Cert
	query := `SELECT cert FROM cert WHERE id = $1 AND version = $2 AND type = $3 AND status = $4 AND created_at = $5 AND updated_at = $6`
	row := tx.QueryRow(ctx, query, certV2.ID, certV2.Version, certV2.Type, certV2.Status, certV2.CreatedAt, certV2.RevokedAt)
	s.Require().NoError(row.Scan(&certOnDB))
	s.Equal(certV2, certOnDB)

	query = `SELECT cert FROM cert_history WHERE id = $1 AND version = $2`
	row = tx.QueryRow(ctx, query, cert.ID, cert.Version)
	s.Require().NoError(row.Scan(&certOnDB))
	s.Equal(cert, certOnDB)
	row = tx.QueryRow(ctx, query, certV2.ID, certV2.Version)
	s.Require().NoError(row.Scan(&certOnDB))
	s.Equal(certV2, certOnDB)

	err = tx.Commit(ctx)
	s.Require().NoError(err)
}

func (s *CertStorageSuite) TestListCertificates() {
	db := stdlib.OpenDBFromPool(s.pgPool)
	fixtures, err := testfixtures.New(
		testfixtures.Database(db),
		testfixtures.Dialect("postgres"),
		testfixtures.Directory("testdata/cert"),
	)
	s.Require().NoError(err)
	s.Require().NoError(fixtures.Load())

	tx, ctx, err := s.storage.CreateTx(s.ctx)
	s.Require().NoError(err)
	defer tx.Rollback(ctx)

	baseReq := storage.ListCertificatesRequest{
		Limit: 100,
	}

	certsOnDB := make([]model.Cert, 0, 4)
	query := `SELECT "cert" FROM "cert" ORDER BY rec_id`
	rows, err := tx.Query(ctx, query)
	s.Require().NoError(err)
	defer rows.Close()
	for rows.Next() {
		var cert model.Cert
		s.Require().NoError(rows.Scan(&cert))
		certsOnDB = append(certsOnDB, cert)
	}
	s.Require().NoError(err)
	rows.Close()

	// Test list all certificates.
	result, err := s.storage.ListCertificates(ctx, tx, baseReq)
	s.Require().NoError(err)
	s.EqualValues(len(certsOnDB), result.Total)
	s.EqualValues(certsOnDB, result.Certs)

	// Test Limit and Offset
	func() {
		req := baseReq
		req.Limit = 1
		req.Offset = 1
		result, err := s.storage.ListCertificates(ctx, tx, req)
		s.Require().NoError(err)
		s.EqualValues(len(certsOnDB), result.Total)
		s.EqualValues(certsOnDB[1:2], result.Certs)
	}()

	// Test filter by ID
	func() {
		req := baseReq
		req.IDs = []string{certsOnDB[0].ID, certsOnDB[1].ID}
		result, err := s.storage.ListCertificates(ctx, tx, req)
		s.Require().NoError(err)
		s.EqualValues(2, result.Total)
		s.EqualValues(certsOnDB[:2], result.Certs)
	}()

	// Test filter by Status
	func() {
		req := baseReq
		req.Statuses = []model.CertStatus{model.CertStatusRejected, model.CertStatusRevoked}
		result, err := s.storage.ListCertificates(ctx, tx, req)
		s.Require().NoError(err)
		s.EqualValues(2, result.Total)
		s.EqualValues(certsOnDB[1:3], result.Certs)
	}()

	// Test filter by Type
	func() {
		req := baseReq
		req.Types = []model.CertType{model.RootCert, model.ThirdPartyCACert}
		result, err := s.storage.ListCertificates(ctx, tx, req)
		s.Require().NoError(err)
		s.EqualValues(2, result.Total)
		s.EqualValues(append(make([]model.Cert, 0, 2), certsOnDB[0], certsOnDB[2]), result.Certs)
	}()
}
