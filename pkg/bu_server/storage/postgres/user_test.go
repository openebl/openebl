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

type UserStorageTestSuite struct {
	BaseTestSuite
	storage auth.UserStorage
}

func TestUserStorage(t *testing.T) {
	suite.Run(t, new(UserStorageTestSuite))
}

func (s *UserStorageTestSuite) SetupTest() {
	s.BaseTestSuite.SetupTest()
	s.storage = postgres.NewStorageWithPool(s.pgPool)
}

func (s *UserStorageTestSuite) TearDownTest() {
	s.BaseTestSuite.TearDownTest()
}

func (s *UserStorageTestSuite) TestStoreUser() {
	userV1 := auth.User{
		ID:        "test-user",
		Status:    auth.UserStatusActive,
		Version:   1,
		Name:      "Test User",
		Emails:    []string{"mail@mail.com"},
		Note:      "note",
		CreatedAt: 1600000000,
		CreatedBy: "root",
		UpdatedAt: 1600000000,
		UpdatedBy: "root",
	}

	userV2 := userV1
	userV2.Version = 2
	userV2.Status = auth.UserStatusInactive
	userV2.UpdatedAt = 1600000001
	userV2.UpdatedBy = "other user"

	tx, err := s.storage.CreateTx(s.ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	s.Require().NoError(err)
	defer tx.Rollback(s.ctx)

	// Store user for the first time.
	s.Require().NoError(s.storage.StoreUser(s.ctx, tx, userV1))
	userOnDB := auth.User{}
	s.Require().NoError(tx.QueryRow(s.ctx, `SELECT "user" FROM "user" WHERE id = $1`, userV1.ID).Scan(&userOnDB))
	s.Require().Equal(userV1, userOnDB)

	// Store updated user version 2.
	s.Require().NoError(s.storage.StoreUser(s.ctx, tx, userV2))
	userOnDB = auth.User{}
	s.Require().NoError(tx.QueryRow(s.ctx, `SELECT "user" FROM "user" WHERE id = $1`, userV2.ID).Scan(&userOnDB))
	s.Require().Equal(userV2, userOnDB)

	// Check if both version of user are stored in history.
	userHistory := []auth.User{}
	rows, err := tx.Query(s.ctx, `SELECT "user" FROM user_history WHERE id = $1 ORDER BY rec_id ASC`, userV1.ID)
	s.Require().NoError(err)
	for rows.Next() {
		var user auth.User
		s.Require().NoError(rows.Scan(&user))
		userHistory = append(userHistory, user)
	}
	s.Require().NoError(rows.Err())
	s.Require().Equal([]auth.User{userV1, userV2}, userHistory)
}

func (s *UserStorageTestSuite) TestListUsers() {
	db := stdlib.OpenDBFromPool(s.pgPool)
	fixtures, err := testfixtures.New(
		testfixtures.Database(db),
		testfixtures.Dialect("postgres"),
		testfixtures.Directory("testdata/user"),
	)
	s.Require().NoError(err)
	s.Require().NoError(fixtures.Load())

	tx, err := s.storage.CreateTx(s.ctx, storage.TxOptionWithWrite(false))
	s.Require().NoError(err)
	defer tx.Rollback(s.ctx)

	usersOnDB := make([]auth.User, 0)
	s.Require().NoError(tx.QueryRow(s.ctx, `SELECT jsonb_agg("user" ORDER BY rec_id) FROM "user"`).Scan(&usersOnDB))

	// Test list all users.
	req := auth.ListUserRequest{Limit: 10}
	result, err := s.storage.ListUsers(s.ctx, tx, req)
	s.Require().NoError(err)
	s.Assert().EqualValues(3, result.Total)
	s.Assert().EqualValues(usersOnDB, result.Users)

	// Test Offset
	req = auth.ListUserRequest{
		Offset: 1,
		Limit:  10,
	}
	result, err = s.storage.ListUsers(s.ctx, tx, req)
	s.Require().NoError(err)
	s.Assert().EqualValues(3, result.Total)
	s.Assert().EqualValues(usersOnDB[1:], result.Users)

	// Test Limit
	req = auth.ListUserRequest{
		Offset: 0,
		Limit:  2,
	}
	result, err = s.storage.ListUsers(s.ctx, tx, req)
	s.Require().NoError(err)
	s.Assert().EqualValues(3, result.Total)
	s.Assert().EqualValues(usersOnDB[:2], result.Users)

	// Test Filter by ID
	req = auth.ListUserRequest{
		Offset: 0,
		Limit:  10,
		IDs:    []string{"user1", "user3"},
	}
	result, err = s.storage.ListUsers(s.ctx, tx, req)
	s.Require().NoError(err)
	s.Assert().EqualValues(2, result.Total)
	s.Require().Len(result.Users, 2)
	s.Assert().EqualValues(usersOnDB[0], result.Users[0])
	s.Assert().EqualValues(usersOnDB[2], result.Users[1])
}
