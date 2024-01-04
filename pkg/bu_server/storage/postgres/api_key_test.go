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

type APIKeyStorageTestSuite struct {
	BaseTestSuite
	storage auth.APIKeyStorage
}

func TestEventStorage(t *testing.T) {
	suite.Run(t, new(APIKeyStorageTestSuite))
}

func (s *APIKeyStorageTestSuite) SetupTest() {
	s.BaseTestSuite.SetupTest()
	s.storage = postgres.NewStorageWithPool(s.pgPool)
}

func (s *APIKeyStorageTestSuite) TearDownTest() {
	s.BaseTestSuite.TearDownTest()
}

func (s *APIKeyStorageTestSuite) TestCreateAPIKey() {
	query := `SELECT api_key FROM api_key WHERE id = $1 AND "version" = $2 AND application_id = $3 AND status = $4`
	historyQuery := `SELECT api_key FROM api_key_history WHERE id = $1 AND "version" = $2`
	apiKeyFromDB := auth.APIKey{}

	apiKey := auth.APIKey{
		ID:            "test-api-key",
		HashString:    "test-api-key-hash-string",
		Version:       1,
		ApplicationID: "test-application-id",
		Scopes:        []auth.APIKeyScope{auth.APIKeyScopeAll},
		Status:        auth.APIKeyStatusActive,
		CreatedBy:     "test-created-by",
		UpdatedBy:     "test-updated-by",
		CreatedAt:     123,
		UpdatedAt:     456,
	}
	newVersionAPIKey := apiKey
	newVersionAPIKey.Version += 1
	newVersionAPIKey.Status = auth.APIKeyStatusRevoked
	newVersionAPIKey.UpdatedAt = 789
	newVersionAPIKey.UpdatedBy = "test-updated-by-2"

	tx, err := s.storage.CreateTx(s.ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	s.Require().NoError(err)
	defer tx.Rollback(s.ctx)

	// First version of APIKey
	s.Require().NoError(s.storage.StoreAPIKey(s.ctx, tx, apiKey))
	err = tx.QueryRow(s.ctx, query, apiKey.ID, apiKey.Version, apiKey.ApplicationID, apiKey.Status).Scan(&apiKeyFromDB)
	s.Require().NoError(err)
	s.Assert().Equal(apiKey, apiKeyFromDB)
	err = tx.QueryRow(s.ctx, historyQuery, apiKey.ID, apiKey.Version).Scan(&apiKeyFromDB)
	s.Require().NoError(err)
	s.Assert().Equal(apiKey, apiKeyFromDB)
	// End of first version of APIKey

	// Second version of APIKey
	s.Require().NoError(s.storage.StoreAPIKey(s.ctx, tx, newVersionAPIKey))
	err = tx.QueryRow(s.ctx, query, newVersionAPIKey.ID, newVersionAPIKey.Version, newVersionAPIKey.ApplicationID, newVersionAPIKey.Status).Scan(&apiKeyFromDB)
	s.Require().NoError(err)
	s.Assert().Equal(newVersionAPIKey, apiKeyFromDB)
	err = tx.QueryRow(s.ctx, historyQuery, newVersionAPIKey.ID, newVersionAPIKey.Version).Scan(&apiKeyFromDB)
	s.Require().NoError(err)
	s.Assert().Equal(newVersionAPIKey, apiKeyFromDB)
	// End of second version of APIKey

	s.Require().NoError(tx.Commit(s.ctx))
}

func (s *APIKeyStorageTestSuite) TestGetAPIKey() {
	db := stdlib.OpenDBFromPool(s.pgPool)
	fixtures, err := testfixtures.New(
		testfixtures.Database(db),
		testfixtures.Dialect("postgres"),
		testfixtures.Directory("testdata/api_key"),
	)
	s.Require().NoError(err)
	s.Require().NoError(fixtures.Load())

	tx, err := s.storage.CreateTx(s.ctx, storage.TxOptionWithWrite(false))
	s.Require().NoError(err)
	defer tx.Rollback(s.ctx)

	apiKey, err := s.storage.GetAPIKey(s.ctx, tx, "key_1")
	s.Require().NoError(err)
	s.Assert().Equal("key_1", apiKey.APIKey.ID)
	s.Assert().Equal(auth.APIKeyHashedString("hashed_key1"), apiKey.APIKey.HashString)
	s.Assert().Equal(1, apiKey.APIKey.Version)
	s.Assert().Equal("app_1", apiKey.APIKey.ApplicationID)
	s.Assert().Equal([]auth.APIKeyScope{auth.APIKeyScopeAll}, apiKey.APIKey.Scopes)
	s.Assert().Equal(auth.APIKeyStatusActive, apiKey.APIKey.Status)
	s.Assert().Equal("BBBBBB", apiKey.Application.CompanyName)

	apiKey, err = s.storage.GetAPIKey(s.ctx, tx, "key_2")
	s.Require().NoError(err)
	s.Assert().Equal("key_2", apiKey.APIKey.ID)
	s.Assert().Equal(auth.APIKeyHashedString("hashed_key2"), apiKey.APIKey.HashString)
	s.Assert().Equal(1, apiKey.APIKey.Version)
	s.Assert().Equal("app_2", apiKey.APIKey.ApplicationID)
	s.Assert().Equal([]auth.APIKeyScope{auth.APIKeyScopeAll}, apiKey.APIKey.Scopes)
	s.Assert().Equal(auth.APIKeyStatusActive, apiKey.APIKey.Status)
	s.Assert().Equal("AAAAAA", apiKey.Application.CompanyName)
}

func (s *APIKeyStorageTestSuite) TestListAPIKey() {
	db := stdlib.OpenDBFromPool(s.pgPool)
	fixtures, err := testfixtures.New(
		testfixtures.Database(db),
		testfixtures.Dialect("postgres"),
		testfixtures.Directory("testdata/api_key"),
	)
	s.Require().NoError(err)
	s.Require().NoError(fixtures.Load())

	tx, err := s.storage.CreateTx(s.ctx, storage.TxOptionWithWrite(false))
	s.Require().NoError(err)
	defer tx.Rollback(s.ctx)

	apiKeysOnDB := []auth.ListAPIKeyRecord{}
	rows, err := tx.Query(s.ctx, `SELECT api_key, application FROM api_key JOIN application ON application.id = api_key.application_id ORDER by api_key.rec_id`)
	s.Require().NoError(err)
	defer rows.Close()
	for rows.Next() {
		apiKeyRecord := auth.ListAPIKeyRecord{}
		if err := rows.Scan(&(apiKeyRecord.APIKey), &(apiKeyRecord.Application)); err != nil {
			s.Require().NoError(err)
		}
		apiKeysOnDB = append(apiKeysOnDB, apiKeyRecord)
	}
	if err := rows.Err(); err != nil {
		s.Require().NoError(err)
	}

	// Offset and Limit
	req := auth.ListAPIKeysRequest{
		Offset: 1,
		Limit:  1,
	}
	result, err := s.storage.ListAPIKeys(s.ctx, tx, req)
	s.Require().NoError(err)
	s.Assert().Equal(3, result.Total)
	s.Assert().Equal(apiKeysOnDB[1:2], result.Keys)
	// End of Offset and Limit

	// Filter by ApplicationID
	req = auth.ListAPIKeysRequest{
		Limit:          10,
		ApplicationIDs: []string{"app_1"},
	}
	result, err = s.storage.ListAPIKeys(s.ctx, tx, req)
	s.Require().NoError(err)
	s.Assert().Equal(1, result.Total)
	s.Assert().Equal(apiKeysOnDB[0:1], result.Keys)
	// End of Filter by ApplicationID

	// Filter by Status
	req = auth.ListAPIKeysRequest{
		Limit:    10,
		Statuses: []auth.APIKeyStatus{auth.APIKeyStatusActive},
	}
	result, err = s.storage.ListAPIKeys(s.ctx, tx, req)
	s.Require().NoError(err)
	s.Assert().Equal(2, result.Total)
	s.Assert().Equal(apiKeysOnDB[0:2], result.Keys)
	// End of Filter by Status
}
