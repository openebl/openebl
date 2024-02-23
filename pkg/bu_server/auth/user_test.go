package auth_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/openebl/openebl/pkg/bu_server/auth"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	mock_auth "github.com/openebl/openebl/test/mock/bu_server/auth"
	mock_storage "github.com/openebl/openebl/test/mock/bu_server/storage"
	"github.com/stretchr/testify/suite"
	"golang.org/x/crypto/bcrypt"
)

type UserManagerTestSuite struct {
	suite.Suite
	ctx     context.Context
	ctrl    *gomock.Controller
	storage *mock_auth.MockUserStorage
	tx      *mock_storage.MockTx
	manager auth.UserManager

	oldUser auth.User
}

func TestUserManager(t *testing.T) {
	suite.Run(t, &UserManagerTestSuite{})
}

func (s *UserManagerTestSuite) SetupTest() {
	s.ctx = context.Background()
	s.ctrl = gomock.NewController(s.T())
	s.storage = mock_auth.NewMockUserStorage(s.ctrl)
	s.tx = mock_storage.NewMockTx(s.ctrl)
	s.manager = auth.NewUserManager(s.storage)

	oldHashedPassword, _ := bcrypt.GenerateFromPassword([]byte("old_password"), bcrypt.DefaultCost)
	s.oldUser = auth.User{
		ID:        "usr_001",
		Username:  "user1",
		Status:    auth.UserStatusActive,
		Version:   1,
		Password:  auth.HashedPassword(oldHashedPassword),
		Name:      "User 1",
		Emails:    []string{"user1@email.com"},
		Note:      "note",
		CreatedAt: 12345,
		CreatedBy: "request_user",
		UpdatedAt: 12345,
		UpdatedBy: "request_user",
	}
}

func (s *UserManagerTestSuite) TearDownTest() {
	s.ctrl.Finish()
}

func (s *UserManagerTestSuite) TestCreateUser() {
	ts := time.Now().Unix()

	req := auth.CreateUserRequest{
		RequestUser: "request_user",
		Username:    "user1",
		Password:    "password1",
		Name:        "User 1",
		Emails:      []string{"user1@email.com"},
		Note:        "note",
	}

	expectedListUserRequest := auth.ListUserRequest{
		Limit:     1,
		Usernames: []string{"user1"},
	}

	expectedUser := auth.User{
		Username:  "user1",
		Status:    auth.UserStatusActive,
		Version:   1,
		Password:  "hashed_password1",
		Name:      "User 1",
		Emails:    []string{"user1@email.com"},
		Note:      "note",
		CreatedAt: ts,
		CreatedBy: "request_user",
		UpdatedAt: ts,
		UpdatedBy: "request_user",
	}

	var storedUser auth.User
	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Eq(s.ctx), gomock.Len(2)).Return(s.tx, nil),
		s.storage.EXPECT().ListUsers(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(expectedListUserRequest)).Return(auth.ListUserResult{}, nil),
		s.storage.EXPECT().StoreUser(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, user auth.User) error {
				storedUser = user
				return nil
			},
		),
		s.tx.EXPECT().Commit(gomock.Eq(s.ctx)).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Eq(s.ctx)).Return(nil),
	)

	user, err := s.manager.CreateUser(s.ctx, ts, req)
	s.Require().NoError(err)
	s.Assert().NotEmpty(storedUser.Password)
	s.Assert().Empty(user.Password)
	storedUser.Password = user.Password
	s.Assert().Equal(storedUser, user)
	s.Assert().NotEmpty(user.ID)
	expectedUser.ID = user.ID
	expectedUser.Password = user.Password
	s.Assert().Equal(expectedUser, user)
}

func (s *UserManagerTestSuite) TestCreateUserWithDuplicateUserID() {
	ts := time.Now().Unix()

	req := auth.CreateUserRequest{
		RequestUser: "request_user",
		Username:    "user1",
		Password:    "password1",
		Name:        "User 1",
		Emails:      []string{"user1@email.com"},
		Note:        "note",
	}

	expectedListUserRequest := auth.ListUserRequest{
		Limit:     1,
		Usernames: []string{"user1"},
	}

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Eq(s.ctx), gomock.Len(2)).Return(s.tx, nil),
		s.storage.EXPECT().ListUsers(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(expectedListUserRequest)).Return(auth.ListUserResult{Total: 1, Users: []auth.User{s.oldUser}}, nil),
		s.tx.EXPECT().Rollback(gomock.Eq(s.ctx)).Return(nil),
	)

	user, err := s.manager.CreateUser(s.ctx, ts, req)
	s.Require().ErrorIs(err, model.ErrUserAlreadyExists)
	s.Assert().EqualValues(auth.User{}, user)
}

func (s *UserManagerTestSuite) TestChangePassword() {
	ts := time.Now().Unix()

	req := auth.ChangePasswordRequest{
		UserID:      "usr_001",
		Username:    "user1",
		OldPassword: "old_password",
		Password:    "password1",
	}

	expectedListUserRequest := auth.ListUserRequest{
		Limit:     1,
		IDs:       []string{"usr_001"},
		Usernames: []string{"user1"},
	}

	expectedUser := s.oldUser
	expectedUser.Version += 1
	expectedUser.UpdatedAt = ts
	expectedUser.UpdatedBy = "usr_001"

	// Test with correct old password.
	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Eq(s.ctx), gomock.Len(2)).Return(s.tx, nil),
		s.storage.EXPECT().ListUsers(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(expectedListUserRequest)).Return(auth.ListUserResult{Total: 1, Users: []auth.User{s.oldUser}}, nil),
		s.storage.EXPECT().StoreUser(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, user auth.User) error {
				expectedUser.Password = user.Password
				s.Assert().Equal(expectedUser, user)
				return nil
			},
		),
		s.tx.EXPECT().Commit(gomock.Eq(s.ctx)).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Eq(s.ctx)).Return(nil),
	)

	newUser, err := s.manager.ChangePassword(s.ctx, ts, req)
	s.Require().NoError(err)
	s.Assert().Empty(newUser.Password)
	newUser.Password = expectedUser.Password
	s.Assert().EqualValues(expectedUser, newUser)
	s.Assert().NoError(auth.VerifyUserPassword(req.Password, newUser.Password))
	// End of Test with correct old password.

	// Test with incorrect old password.
	req.OldPassword = "incorrectOldPassword"
	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Eq(s.ctx), gomock.Len(2)).Return(s.tx, nil),
		s.storage.EXPECT().ListUsers(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(expectedListUserRequest)).Return(auth.ListUserResult{Total: 1, Users: []auth.User{s.oldUser}}, nil),
		s.tx.EXPECT().Rollback(gomock.Eq(s.ctx)).Return(nil),
	)

	newUser, err = s.manager.ChangePassword(s.ctx, ts, req)
	s.Require().ErrorIs(err, model.ErrUserAuthenticationFail)
	s.Assert().EqualValues(auth.User{}, newUser)
	// End of Test with incorrect old password.
}

func (s *UserManagerTestSuite) TestChangePasswordWithNonExistingUser() {
	ts := time.Now().Unix()

	req := auth.ChangePasswordRequest{
		UserID:      "usr_001",
		Username:    "user1",
		OldPassword: "old_password",
		Password:    "password1",
	}

	expectedListUserRequest := auth.ListUserRequest{
		Limit:     1,
		IDs:       []string{"usr_001"},
		Usernames: []string{"user1"},
	}

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Eq(s.ctx), gomock.Len(2)).Return(s.tx, nil),
		s.storage.EXPECT().ListUsers(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(expectedListUserRequest)).Return(auth.ListUserResult{}, model.ErrUserNotFound),
		s.tx.EXPECT().Rollback(gomock.Eq(s.ctx)).Return(nil),
	)

	newUser, err := s.manager.ChangePassword(s.ctx, ts, req)
	s.Require().ErrorIs(err, model.ErrUserNotFound)
	s.Assert().EqualValues(auth.User{}, newUser)
}

func (s *UserManagerTestSuite) TestResetPassword() {
	ts := time.Now().Unix()

	req := auth.ResetPasswordRequest{
		RequestUser: "other_user",
		UserID:      "usr_001",
		Username:    "user1",
		Password:    "password1",
	}

	expectedListUserRequest := auth.ListUserRequest{
		Limit:     1,
		IDs:       []string{"usr_001"},
		Usernames: []string{"user1"},
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)

	expectedUser := s.oldUser
	expectedUser.Version += 1
	expectedUser.Password = auth.HashedPassword(hashedPassword)
	expectedUser.UpdatedAt = ts
	expectedUser.UpdatedBy = "other_user"

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Eq(s.ctx), gomock.Len(2)).Return(s.tx, nil),
		s.storage.EXPECT().ListUsers(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(expectedListUserRequest)).Return(auth.ListUserResult{Total: 1, Users: []auth.User{s.oldUser}}, nil),
		s.storage.EXPECT().StoreUser(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, user auth.User) error {
				expectedUser.Password = user.Password
				s.Assert().Equal(expectedUser, user)
				return nil
			},
		),
		s.tx.EXPECT().Commit(gomock.Eq(s.ctx)).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Eq(s.ctx)).Return(nil),
	)

	newUser, err := s.manager.ResetPassword(s.ctx, ts, req)
	s.Require().NoError(err)
	s.Assert().Empty(newUser.Password)
	newUser.Password = expectedUser.Password
	s.Assert().EqualValues(expectedUser, newUser)
	s.Assert().NoError(auth.VerifyUserPassword(req.Password, newUser.Password))
}

func (s *UserManagerTestSuite) TestResetPasswordWithNonExistingUser() {
	ts := time.Now().Unix()

	req := auth.ResetPasswordRequest{
		RequestUser: "other_user",
		UserID:      "usr_001",
		Username:    "user1",
		Password:    "password1",
	}

	expectedListUserRequest := auth.ListUserRequest{
		Limit:     1,
		IDs:       []string{"usr_001"},
		Usernames: []string{"user1"},
	}

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Eq(s.ctx), gomock.Len(2)).Return(s.tx, nil),
		s.storage.EXPECT().ListUsers(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(expectedListUserRequest)).Return(auth.ListUserResult{Total: 0, Users: []auth.User{}}, nil),
		s.tx.EXPECT().Rollback(gomock.Eq(s.ctx)).Return(nil),
	)

	newUser, err := s.manager.ResetPassword(s.ctx, ts, req)
	s.Require().ErrorIs(err, model.ErrUserNotFound)
	s.Assert().EqualValues(auth.User{}, newUser)
}

func (s *UserManagerTestSuite) TestUpdateUser() {
	ts := time.Now().Unix()

	req := auth.UpdateUserRequest{
		RequestUser: "other_user",
		UserID:      "usr_001",
		Username:    "user1",
		Name:        "new name",
		Emails:      []string{"new_email@email.com"},
		Note:        "new note",
	}

	expectedListUserRequest := auth.ListUserRequest{
		Limit:     1,
		IDs:       []string{"usr_001"},
		Usernames: []string{"user1"},
	}

	expectedUser := s.oldUser
	expectedUser.Version += 1
	expectedUser.Name = req.Name
	expectedUser.Emails = req.Emails
	expectedUser.Note = req.Note
	expectedUser.UpdatedAt = ts
	expectedUser.UpdatedBy = "other_user"

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Eq(s.ctx), gomock.Len(2)).Return(s.tx, nil),
		s.storage.EXPECT().ListUsers(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(expectedListUserRequest)).Return(auth.ListUserResult{Total: 1, Users: []auth.User{s.oldUser}}, nil),
		s.storage.EXPECT().StoreUser(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(expectedUser)).Return(nil),
		s.tx.EXPECT().Commit(gomock.Eq(s.ctx)).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Eq(s.ctx)).Return(nil),
	)

	newUser, err := s.manager.UpdateUser(s.ctx, ts, req)
	s.Require().NoError(err)
	s.Assert().Empty(newUser.Password)
	newUser.Password = expectedUser.Password
	s.Assert().EqualValues(expectedUser, newUser)
}

func (s *UserManagerTestSuite) TestUpdateUserWithNonExistingUser() {
	ts := time.Now().Unix()

	req := auth.UpdateUserRequest{
		RequestUser: "other_user",
		UserID:      "usr_001",
		Username:    "user1",
		Name:        "new name",
		Emails:      []string{"new_email"},
		Note:        "new note",
	}

	expectedListUserRequest := auth.ListUserRequest{
		Limit:     1,
		IDs:       []string{"usr_001"},
		Usernames: []string{"user1"},
	}

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Eq(s.ctx), gomock.Len(2)).Return(s.tx, nil),
		s.storage.EXPECT().ListUsers(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(expectedListUserRequest)).Return(auth.ListUserResult{Total: 0, Users: []auth.User{}}, nil),
		s.tx.EXPECT().Rollback(gomock.Eq(s.ctx)).Return(nil),
	)

	newUser, err := s.manager.UpdateUser(s.ctx, ts, req)
	s.Require().ErrorIs(err, model.ErrUserNotFound)
	s.Assert().EqualValues(auth.User{}, newUser)
}

func (s *UserManagerTestSuite) TestActivateUser() {
	ts := time.Now().Unix()

	req := auth.ActivateUserRequest{
		RequestUser: "admin",
		UserID:      "usr_001",
		Username:    "user1",
	}

	expectedListUserRequest := auth.ListUserRequest{
		Limit:     1,
		IDs:       []string{"usr_001"},
		Usernames: []string{"user1"},
	}

	s.oldUser.Status = auth.UserStatusInactive
	expectedUser := s.oldUser
	expectedUser.Version += 1
	expectedUser.Status = auth.UserStatusActive
	expectedUser.UpdatedAt = ts
	expectedUser.UpdatedBy = "admin"

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Eq(s.ctx), gomock.Len(2)).Return(s.tx, nil),
		s.storage.EXPECT().ListUsers(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(expectedListUserRequest)).Return(auth.ListUserResult{Total: 1, Users: []auth.User{s.oldUser}}, nil),
		s.storage.EXPECT().StoreUser(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(expectedUser)).Return(nil),
		s.tx.EXPECT().Commit(gomock.Eq(s.ctx)).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Eq(s.ctx)).Return(nil),
	)

	activatedUser, err := s.manager.ActivateUser(s.ctx, ts, req)
	s.Require().NoError(err)
	s.Assert().Empty(activatedUser.Password)
	activatedUser.Password = expectedUser.Password
	s.Assert().EqualValues(expectedUser, activatedUser)
}

func (s *UserManagerTestSuite) TestActivateUserWithNonExistingUser() {
	ts := time.Now().Unix()

	req := auth.ActivateUserRequest{
		RequestUser: "admin",
		UserID:      "nonexistinguser",
	}

	expectedListUserRequest := auth.ListUserRequest{
		Limit: 1,
		IDs:   []string{"nonexistinguser"},
	}

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Eq(s.ctx), gomock.Len(2)).Return(s.tx, nil),
		s.storage.EXPECT().ListUsers(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(expectedListUserRequest)).Return(auth.ListUserResult{Total: 0, Users: []auth.User{}}, nil),
		s.tx.EXPECT().Rollback(gomock.Eq(s.ctx)).Return(nil),
	)

	activatedUser, err := s.manager.ActivateUser(s.ctx, ts, req)
	s.Require().ErrorIs(err, model.ErrUserNotFound)
	s.Assert().Empty(activatedUser)
}

func (s *UserManagerTestSuite) TestDeactivateUser() {
	ts := time.Now().Unix()

	req := auth.ActivateUserRequest{
		RequestUser: "admin",
		UserID:      "usr_001",
		Username:    "user1",
	}

	expectedListUserRequest := auth.ListUserRequest{
		Limit:     1,
		IDs:       []string{"usr_001"},
		Usernames: []string{"user1"},
	}

	s.oldUser.Status = auth.UserStatusActive
	expectedUser := s.oldUser
	expectedUser.Version += 1
	expectedUser.Status = auth.UserStatusInactive
	expectedUser.UpdatedAt = ts
	expectedUser.UpdatedBy = "admin"

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Eq(s.ctx), gomock.Len(2)).Return(s.tx, nil),
		s.storage.EXPECT().ListUsers(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(expectedListUserRequest)).Return(auth.ListUserResult{Total: 1, Users: []auth.User{s.oldUser}}, nil),
		s.storage.EXPECT().StoreUser(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(expectedUser)).Return(nil),
		s.tx.EXPECT().Commit(gomock.Eq(s.ctx)).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Eq(s.ctx)).Return(nil),
	)

	deactivatedUser, err := s.manager.DeactivateUser(s.ctx, ts, req)
	s.Require().NoError(err)
	s.Assert().Empty(deactivatedUser.Password)
	deactivatedUser.Password = expectedUser.Password
	s.Assert().EqualValues(expectedUser, deactivatedUser)
}

func (s *UserManagerTestSuite) TestDeactivateUserWithNonExistingUser() {
	ts := time.Now().Unix()

	req := auth.ActivateUserRequest{
		RequestUser: "admin",
		UserID:      "nonexistinguser",
	}

	expectedListUserRequest := auth.ListUserRequest{
		Limit: 1,
		IDs:   []string{"nonexistinguser"},
	}

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Eq(s.ctx), gomock.Len(2)).Return(s.tx, nil),
		s.storage.EXPECT().ListUsers(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(expectedListUserRequest)).Return(auth.ListUserResult{Total: 0, Users: []auth.User{}}, nil),
		s.tx.EXPECT().Rollback(gomock.Eq(s.ctx)).Return(nil),
	)

	deactivatedUser, err := s.manager.DeactivateUser(s.ctx, ts, req)
	s.Require().ErrorIs(err, model.ErrUserNotFound)
	s.Assert().Empty(deactivatedUser)
}

func (s *UserManagerTestSuite) TestAuthenticate() {
	ts := time.Now().Unix()

	req := auth.AuthenticateUserRequest{
		Username: "user1",
		Password: "old_password",
	}

	expectedListUserRequest := auth.ListUserRequest{
		Limit:     1,
		Usernames: []string{"user1"},
	}

	// Test with correct password.
	storedUserToken := auth.UserToken{}
	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Eq(s.ctx), gomock.Len(2)).Return(s.tx, nil),
		s.storage.EXPECT().ListUsers(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(expectedListUserRequest)).Return(auth.ListUserResult{Total: 1, Users: []auth.User{s.oldUser}}, nil),
		s.storage.EXPECT().StoreUserToken(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, userToken auth.UserToken) error {
				storedUserToken = userToken
				return nil
			},
		),
		s.tx.EXPECT().Commit(gomock.Eq(s.ctx)).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Eq(s.ctx)).Return(nil),
	)
	userToken, err := s.manager.Authenticate(s.ctx, ts, req)
	s.Require().NoError(err)
	s.Assert().EqualValues(s.oldUser.ID, userToken.UserID)
	s.Assert().NotEmpty(userToken.Token)
	s.Assert().EqualValues(storedUserToken, userToken)
	// End of Test with correct password.

	// Test with incorrect password.
	req.Password = "incorrect_password"
	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Eq(s.ctx), gomock.Len(2)).Return(s.tx, nil),
		s.storage.EXPECT().ListUsers(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(expectedListUserRequest)).Return(auth.ListUserResult{Total: 1, Users: []auth.User{s.oldUser}}, nil),
		s.tx.EXPECT().Rollback(gomock.Eq(s.ctx)).Return(nil),
	)
	userToken, err = s.manager.Authenticate(s.ctx, ts, req)
	s.Require().ErrorIs(err, model.ErrUserAuthenticationFail)
	s.Assert().Empty(userToken)
}

func (s *UserManagerTestSuite) TestAuthenticateWithNonExistingUser() {
	ts := time.Now().Unix()

	req := auth.AuthenticateUserRequest{
		Username: "nonexistinguser",
		Password: "old_password",
	}

	expectedListUserRequest := auth.ListUserRequest{
		Limit:     1,
		Usernames: []string{"nonexistinguser"},
	}

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Eq(s.ctx), gomock.Len(2)).Return(s.tx, nil),
		s.storage.EXPECT().ListUsers(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(expectedListUserRequest)).Return(auth.ListUserResult{}, nil),
		s.tx.EXPECT().Rollback(gomock.Eq(s.ctx)).Return(nil),
	)
	userToken, err := s.manager.Authenticate(s.ctx, ts, req)
	s.Require().ErrorIs(err, model.ErrUserAuthenticationFail)
	s.Assert().Empty(userToken)
}

func (s *UserManagerTestSuite) TestTokenAuthorization() {
	ts := time.Now().Unix()
	token := "token1"

	userToken := auth.UserToken{
		UserID:    "user1",
		Token:     token,
		CreatedAt: ts - 1000,
		ExpiredAt: ts + 1000,
	}

	// Test with valid token.
	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Eq(s.ctx), gomock.Len(1)).Return(s.tx, nil),
		s.storage.EXPECT().GetUserToken(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(token)).Return(userToken, nil),
		s.tx.EXPECT().Rollback(gomock.Eq(s.ctx)).Return(nil),
	)
	returnedUserToken, err := s.manager.TokenAuthorization(s.ctx, ts, token)
	s.Assert().NoError(err)
	s.Assert().EqualValues(userToken, returnedUserToken)
	// End of Test with valid token.

	// Test with expired token.
	userToken.ExpiredAt = ts - 1000
	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Eq(s.ctx), gomock.Len(1)).Return(s.tx, nil),
		s.storage.EXPECT().GetUserToken(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(token)).Return(userToken, nil),
		s.tx.EXPECT().Rollback(gomock.Eq(s.ctx)).Return(nil),
	)
	returnedUserToken, err = s.manager.TokenAuthorization(s.ctx, ts, token)
	s.Assert().ErrorIs(err, model.ErrUserTokenExpired)
	s.Assert().Empty(returnedUserToken)
}

func (s *UserManagerTestSuite) TestTokenAuthorizationWithNonExistingToken() {
	ts := time.Now().Unix()
	token := "token1"

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Eq(s.ctx), gomock.Len(1)).Return(s.tx, nil),
		s.storage.EXPECT().GetUserToken(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(token)).Return(auth.UserToken{}, sql.ErrNoRows),
		s.tx.EXPECT().Rollback(gomock.Eq(s.ctx)).Return(nil),
	)

	userToken, err := s.manager.TokenAuthorization(s.ctx, ts, token)
	s.Assert().ErrorIs(err, model.ErrUserTokenInvalid)
	s.Assert().Empty(userToken)
}

func (s *UserManagerTestSuite) TestListUsers() {
	req := auth.ListUserRequest{
		Offset: 2,
		Limit:  10,
		IDs:    []string{"user1", "user2"},
	}

	expectedListUserRequest := req
	listResult := auth.ListUserResult{
		Total: 2,
		Users: []auth.User{
			s.oldUser,
		},
	}

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Eq(s.ctx), gomock.Len(1)).Return(s.tx, nil),
		s.storage.EXPECT().ListUsers(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(expectedListUserRequest)).Return(listResult, nil),
		s.tx.EXPECT().Rollback(gomock.Eq(s.ctx)).Return(nil),
	)

	result, err := s.manager.ListUsers(s.ctx, req)
	s.Require().NoError(err)
	s.Assert().EqualValues(listResult, result)
	s.Assert().Empty(result.Users[0].Password)
}
