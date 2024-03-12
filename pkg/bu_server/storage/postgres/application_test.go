package postgres_test

import (
	"database/sql"
	"testing"

	"github.com/go-testfixtures/testfixtures/v3"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/openebl/openebl/pkg/bu_server/auth"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/bu_server/storage/postgres"
	"github.com/stretchr/testify/suite"
)

type ApplicationStorageTestSuite struct {
	BaseTestSuite
	storage auth.ApplicationStorage
}

func TestApplicationStorage(t *testing.T) {
	suite.Run(t, new(ApplicationStorageTestSuite))
}

func (s *ApplicationStorageTestSuite) SetupTest() {
	s.BaseTestSuite.SetupTest()
	s.storage = postgres.NewStorageWithPool(s.pgPool)
}

func (s *ApplicationStorageTestSuite) TearDownTest() {
	s.BaseTestSuite.TearDownTest()
}

func (s *ApplicationStorageTestSuite) TestStoreApplication() {
	app := auth.Application{
		ID:           "test-app",
		Version:      1,
		Status:       auth.ApplicationStatusActive,
		CreatedAt:    1600000000,
		CreatedBy:    "test-user",
		UpdatedAt:    1600000000,
		UpdatedBy:    "test-user",
		Name:         "Test Application",
		CompanyName:  "Test Company",
		Addresses:    []string{"Test Address"},
		Emails:       []string{"email@email.com"},
		PhoneNumbers: []string{"1234567890"},
	}

	tx, ctx, err := s.storage.CreateTx(s.ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	s.Require().NoError(err)
	defer tx.Rollback(s.ctx)

	// Store application for the first time.
	err = s.storage.StoreApplication(ctx, tx, app)
	s.Require().NoError(err)

	// Store application for the second time.
	appV2 := app
	appV2.Version = 2
	appV2.Status = auth.ApplicationStatusInactive
	appV2.UpdatedBy = "test-user-2"
	err = s.storage.StoreApplication(ctx, tx, appV2)
	s.Require().NoError(err)

	s.Require().NoError(tx.Commit(ctx))
}

func (s *ApplicationStorageTestSuite) TestListApplication() {
	db := stdlib.OpenDBFromPool(s.pgPool)
	fixtures, err := testfixtures.New(
		testfixtures.Database(db),
		testfixtures.Dialect("postgres"),
		testfixtures.Directory("testdata/application"),
	)
	s.Require().NoError(err)
	s.Require().NoError(fixtures.Load())

	tx, ctx, err := s.storage.CreateTx(s.ctx, storage.TxOptionWithWrite(false))
	s.Require().NoError(err)
	defer tx.Rollback(ctx)

	appsOnDB := make([]auth.Application, 0)
	s.Require().NoError(tx.QueryRow(s.ctx, `SELECT jsonb_agg(application ORDER BY rec_id) FROM application`).Scan(&appsOnDB))
	_ = appsOnDB

	// Test Offset
	listRequest := auth.ListApplicationRequest{
		Offset: 1,
		Limit:  10,
	}
	listResult, err := s.storage.ListApplication(ctx, tx, listRequest)
	s.Require().NoError(err)
	s.Assert().Equal(3, listResult.Total)
	s.Assert().Equal(2, len(listResult.Applications))
	s.Assert().EqualValues(appsOnDB[1:3], listResult.Applications)

	// Test Limit
	listRequest = auth.ListApplicationRequest{
		Offset: 0,
		Limit:  2,
	}
	listResult, err = s.storage.ListApplication(ctx, tx, listRequest)
	s.Require().NoError(err)
	s.Assert().Equal(3, listResult.Total)
	s.Assert().Equal(2, len(listResult.Applications))
	s.Assert().EqualValues(appsOnDB[0:2], listResult.Applications)

	// Test Filter by ID
	listRequest = auth.ListApplicationRequest{
		Offset: 0,
		Limit:  10,
		IDs:    []string{"app_1", "app_3"},
	}
	listResult, err = s.storage.ListApplication(ctx, tx, listRequest)
	s.Require().NoError(err)
	s.Assert().Equal(2, listResult.Total)
	s.Assert().Equal(2, len(listResult.Applications))
	s.Assert().EqualValues(appsOnDB[0:1], listResult.Applications[:1])
	s.Assert().EqualValues(appsOnDB[2:3], listResult.Applications[1:2])

	// Test Filter by Status
	listRequest = auth.ListApplicationRequest{
		Offset:   0,
		Limit:    10,
		Statuses: []auth.ApplicationStatus{auth.ApplicationStatusActive},
	}
	listResult, err = s.storage.ListApplication(ctx, tx, listRequest)
	s.Require().NoError(err)
	s.Assert().Equal(2, listResult.Total)
	s.Assert().Equal(2, len(listResult.Applications))
	s.Assert().EqualValues(appsOnDB[0:2], listResult.Applications)
}
