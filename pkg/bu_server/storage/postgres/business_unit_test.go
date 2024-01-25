package postgres_test

import (
	"database/sql"
	"testing"
	"time"

	"github.com/go-testfixtures/testfixtures/v3"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/nuts-foundation/go-did/did"
	"github.com/openebl/openebl/pkg/bu_server/business_unit"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/bu_server/storage/postgres"
	"github.com/stretchr/testify/suite"
)

type BusinessUnitStorageTestSuite struct {
	BaseTestSuite
	storage business_unit.BusinessUnitStorage
}

func TestBusinessUnitStorage(t *testing.T) {
	suite.Run(t, new(BusinessUnitStorageTestSuite))
}

func (s *BusinessUnitStorageTestSuite) SetupTest() {
	s.BaseTestSuite.SetupTest()
	s.storage = postgres.NewStorageWithPool(s.pgPool)

	db := stdlib.OpenDBFromPool(s.pgPool)
	fixtures, err := testfixtures.New(
		testfixtures.Database(db),
		testfixtures.Dialect("postgres"),
		testfixtures.Directory("testdata/business_unit"),
	)
	s.Require().NoError(err)
	s.Require().NoError(fixtures.Load())
}

func (s *BusinessUnitStorageTestSuite) TearDownTest() {
	s.BaseTestSuite.TearDownTest()
}

func (s *BusinessUnitStorageTestSuite) TestStoreBusinessUnit() {
	ts := time.Now().Unix()
	bu := model.BusinessUnit{
		ID:            did.MustParseDID("did:openebl:test_bu"),
		Version:       1,
		ApplicationID: "app_1",
		Status:        model.BusinessUnitStatusActive,
		Name:          "Business Unit 1",
		CreatedAt:     ts,
		UpdatedAt:     ts,
	}

	tx, err := s.storage.CreateTx(s.ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	s.Require().NoError(err)
	defer tx.Rollback(s.ctx)

	err = s.storage.StoreBusinessUnit(s.ctx, tx, bu)
	s.Require().NoError(err)

	ts += 10
	newBu := bu
	newBu.Version = 2
	newBu.Status = model.BusinessUnitStatusInactive
	newBu.UpdatedAt = ts
	err = s.storage.StoreBusinessUnit(s.ctx, tx, newBu)
	s.Require().NoError(err)

	var dbData []model.BusinessUnit
	// Verify business_unit table.
	s.Require().NoError(tx.QueryRow(s.ctx, `SELECT JSONB_AGG(business_unit ORDER BY rec_id ASC) FROM business_unit WHERE id = $1`, bu.ID.String()).Scan(&dbData))
	s.Require().Equal(1, len(dbData))
	s.Assert().Equal(newBu, dbData[0])

	// Verify business_unit_history table.
	s.Require().NoError(tx.QueryRow(s.ctx, `SELECT JSONB_AGG(business_unit ORDER BY rec_id ASC) FROM business_unit_history WHERE id = $1`, bu.ID.String()).Scan(&dbData))
	s.Require().Equal(2, len(dbData))
	s.Assert().Equal(bu, dbData[0])
	s.Assert().Equal(newBu, dbData[1])

	s.Require().NoError(tx.Commit(s.ctx))
}

func (s *BusinessUnitStorageTestSuite) TestListBusinessUnit() {
	tx, err := s.storage.CreateTx(s.ctx)
	s.Require().NoError(err)
	defer tx.Rollback(s.ctx)

	req := business_unit.ListBusinessUnitsRequest{
		Limit:         10,
		ApplicationID: "app1",
	}

	// Test Basic Function (filter by ApplicationID)
	result, err := s.storage.ListBusinessUnits(s.ctx, tx, req)
	s.Require().NoError(err)
	s.Assert().Equal(2, result.Total)
	s.Require().Equal(2, len(result.Records))
	s.Assert().Equal("did:openebl:bu1", result.Records[0].BusinessUnit.ID.String())
	s.Assert().Equal("did:openebl:bu2", result.Records[1].BusinessUnit.ID.String())
	s.Require().Equal(2, len(result.Records[0].Authentications))
	s.Assert().Equal("bu1_auth1", result.Records[0].Authentications[0].ID)
	s.Assert().Equal("bu1_auth2", result.Records[0].Authentications[1].ID)
	s.Require().Equal(1, len(result.Records[1].Authentications))
	s.Assert().Equal("bu2_auth1", result.Records[1].Authentications[0].ID)
	// End of Test Basic Function

	// Test Limit and Offset
	req.Limit = 1
	req.Offset = 1
	result, err = s.storage.ListBusinessUnits(s.ctx, tx, req)
	s.Require().NoError(err)
	s.Assert().Equal(2, result.Total)
	s.Require().Equal(1, len(result.Records))
	s.Assert().Equal("did:openebl:bu2", result.Records[0].BusinessUnit.ID.String())
	// End of Test Limit and Offset

	// Test Filter by BusinessUnitIDs
	req.Limit = 10
	req.Offset = 0
	req.BusinessUnitIDs = []string{"did:openebl:bu1"}
	result, err = s.storage.ListBusinessUnits(s.ctx, tx, req)
	s.Require().NoError(err)
	s.Assert().Equal(1, result.Total)
	s.Require().Equal(1, len(result.Records))
	s.Assert().Equal("did:openebl:bu1", result.Records[0].BusinessUnit.ID.String())
}

func (s *BusinessUnitStorageTestSuite) TestStoreAuthentication() {
	ts := time.Now().Unix()
	auth := model.BusinessUnitAuthentication{
		ID:           "test_auth_1",
		Version:      1,
		BusinessUnit: did.MustParseDID("did:openebl:bu1"),
		Status:       model.BusinessUnitAuthenticationStatusActive,
		CreatedAt:    ts,
	}

	newAuth := auth
	newAuth.Version = 2
	newAuth.Status = model.BusinessUnitAuthenticationStatusRevoked
	newAuth.RevokedAt = ts + 10

	tx, err := s.storage.CreateTx(s.ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	s.Require().NoError(err)
	defer tx.Rollback(s.ctx)

	err = s.storage.StoreAuthentication(s.ctx, tx, auth)
	s.Require().NoError(err)
	err = s.storage.StoreAuthentication(s.ctx, tx, newAuth)
	s.Require().NoError(err)

	// Verify business_unit_authentication table.
	var dbData []model.BusinessUnitAuthentication
	s.Require().NoError(tx.QueryRow(s.ctx, `SELECT JSONB_AGG(authentication ORDER BY rec_id ASC) FROM business_unit_authentication WHERE id = $1`, auth.ID).Scan(&dbData))
	s.Require().Equal(1, len(dbData))
	s.Assert().Equal(newAuth, dbData[0])

	// Verify business_unit_authentication_history table.
	s.Require().NoError(tx.QueryRow(s.ctx, `SELECT JSONB_AGG(authentication ORDER BY rec_id ASC) FROM business_unit_authentication_history WHERE id = $1`, auth.ID).Scan(&dbData))
	s.Require().Equal(2, len(dbData))
	s.Assert().Equal(auth, dbData[0])
	s.Assert().Equal(newAuth, dbData[1])

	s.Require().NoError(tx.Commit(s.ctx))
}

func (s *BusinessUnitStorageTestSuite) TestListAuthentication() {
	tx, err := s.storage.CreateTx(s.ctx)
	s.Require().NoError(err)
	defer tx.Rollback(s.ctx)

	// Test Basic Function (filter by ApplicationID)
	req := business_unit.ListAuthenticationRequest{
		Limit:         10,
		ApplicationID: "app1",
	}
	result, err := s.storage.ListAuthentication(s.ctx, tx, req)
	s.Require().NoError(err)
	s.Assert().Equal(3, result.Total)
	s.Require().Equal(3, len(result.Records))
	s.Assert().Equal("bu1_auth1", result.Records[0].ID)
	s.Assert().Equal("bu1_auth2", result.Records[1].ID)
	s.Assert().Equal("bu2_auth1", result.Records[2].ID)
	// End of Test Basic Function

	// Test Limit and Offset
	req.Limit = 1
	req.Offset = 1
	result, err = s.storage.ListAuthentication(s.ctx, tx, req)
	s.Require().NoError(err)
	s.Assert().Equal(3, result.Total)
	s.Require().Equal(1, len(result.Records))
	s.Assert().Equal("bu1_auth2", result.Records[0].ID)
	// End of Test Limit and Offset

	// Test Filter by BusinessUnitIDs
	req.Limit = 10
	req.Offset = 0
	req.BusinessUnitID = "did:openebl:bu1"
	result, err = s.storage.ListAuthentication(s.ctx, tx, req)
	s.Require().NoError(err)
	s.Assert().Equal(2, result.Total)
	s.Require().Equal(2, len(result.Records))
	s.Assert().Equal("bu1_auth1", result.Records[0].ID)
	s.Assert().Equal("bu1_auth2", result.Records[1].ID)
	// End of Test Filter by BusinessUnitIDs

	// Test Filter by AuthenticationIDs
	req = business_unit.ListAuthenticationRequest{
		Limit:             10,
		ApplicationID:     "app1",
		AuthenticationIDs: []string{"bu1_auth2"},
	}
	result, err = s.storage.ListAuthentication(s.ctx, tx, req)
	s.Require().NoError(err)
	s.Assert().Equal(1, result.Total)
	s.Require().Equal(1, len(result.Records))
	s.Assert().Equal("bu1_auth2", result.Records[0].ID)
	// End of Test Filter by AuthenticationIDs
}
