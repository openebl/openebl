package postgres_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"sync"
	"testing"

	"github.com/go-testfixtures/testfixtures/v3"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/openebl/openebl/pkg/cert_server/model"
	"github.com/openebl/openebl/pkg/cert_server/storage"
	"github.com/openebl/openebl/pkg/cert_server/storage/postgres"
	"github.com/openebl/openebl/pkg/util"
	"github.com/samber/lo"
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
		"cert_revocation_list",
		"cert_outbox",
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
		ID:          "test-id",
		Version:     1,
		Type:        model.RootCert,
		Status:      model.CertStatusActive,
		CreatedAt:   12345,
		PublicKeyID: "test-public-key-id",
		IssuerKeyID: "test-issuer-key-id",
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

	// Test filter by PublicKeyID
	func() {
		req := baseReq
		req.PublicKeyIDs = []string{certsOnDB[0].PublicKeyID, certsOnDB[1].PublicKeyID}
		result, err := s.storage.ListCertificates(ctx, tx, req)
		s.Require().NoError(err)
		s.EqualValues(2, result.Total)
		s.EqualValues(certsOnDB[:2], result.Certs)
	}()
}

func (s *CertStorageSuite) TestAddCertificateRevocationList() {
	tx, ctx, err := s.storage.CreateTx(s.ctx, storage.TxOptionWithWrite(true))
	s.Require().NoError(err)
	defer tx.Rollback(ctx)

	crl := model.CertRevocationList{
		ID:          "test-id",
		IssuerKeyID: "test-issuer-key-id",
		Number:      "1234567",
		CreatedAt:   12345,
		CreatedBy:   "test-user",
		CRL:         "CRL PEM",
	}

	err = s.storage.AddCertificateRevocationList(ctx, tx, crl)
	s.Require().NoError(err)

	crlOnDB := model.CertRevocationList{}
	row := tx.QueryRow(ctx, "SELECT cert_revocation_list FROM cert_revocation_list WHERE id = $1", crl.ID)
	s.Require().NoError(row.Scan(&crlOnDB))
	s.Equal(crl, crlOnDB)
	s.Require().NoError(tx.Commit(ctx))
}

func (s *CertStorageSuite) TestCertificateOutbox() {
	type Msg struct {
		Key     string
		Kind    int
		Payload []byte
	}

	testRecordNumber := 10000
	msgsOnDB := make([]Msg, 0, testRecordNumber)
	processedMsgs := make([]Msg, 0, testRecordNumber)
	mtx := sync.Mutex{}
	addProcessedMsg := func(msg Msg) {
		mtx.Lock()
		defer mtx.Unlock()
		processedMsgs = append(processedMsgs, msg)
	}

	func() {
		tx, ctx, err := s.storage.CreateTx(s.ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
		s.Require().NoError(err)
		defer tx.Rollback(ctx)

		for i := 0; i < testRecordNumber; i++ {
			key := fmt.Sprintf("key-%d", i)
			kind := i % 2
			payload := []byte(fmt.Sprintf("payload-%d", i))
			err = s.storage.AddCertificateOutboxMsg(ctx, tx, int64(i), key, kind, payload)
			s.Require().NoError(err)
			msgsOnDB = append(msgsOnDB, Msg{Key: key, Kind: kind, Payload: payload})
		}
		s.Require().NoError(tx.Commit(ctx))
	}()

	wg := sync.WaitGroup{}
	workerNumber := 10
	batchSize := 8
	workerFunc := func() {
		for {
			tx, ctx, err := s.storage.CreateTx(s.ctx, storage.TxOptionWithWrite(true))
			s.Require().NoError(err)
			defer tx.Rollback(ctx)

			msgs, err := s.storage.GetCertificateOutboxMsg(ctx, tx, batchSize)
			s.Require().NoError(err)

			if len(msgs) == 0 {
				s.Require().NoError(tx.Commit(ctx))
				return
			}

			for _, msg := range msgs {
				addProcessedMsg(Msg{Key: msg.Key, Kind: msg.Kind, Payload: msg.Msg})
			}
			recIDs := lo.Map(msgs, func(msg storage.CertificateOutboxMsg, _ int) int64 {
				return msg.RecID
			})
			s.Require().NoError(s.storage.DeleteCertificateOutboxMsg(ctx, tx, recIDs...))
			s.Require().NoError(tx.Commit(ctx))
		}
	}

	wg.Add(workerNumber)
	for i := 1; i <= workerNumber; i++ {
		go func() {
			defer wg.Done()
			workerFunc()
		}()
	}

	wg.Wait()
	s.Assert().Equal(processedMsgs, msgsOnDB)
}
