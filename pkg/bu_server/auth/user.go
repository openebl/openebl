package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	"golang.org/x/crypto/bcrypt"
)

type UserStatus string
type RawPassword string
type HashedPassword string

const (
	UserStatusActive   = UserStatus("active")
	UserStatusInactive = UserStatus("inactive")
)

type User struct {
	ID       string         `json:"id"`
	Status   UserStatus     `json:"status"`
	Version  int64          `json:"version"`
	Password HashedPassword `json:"password"`
	Name     string         `json:"name"`
	Emails   []string       `json:"emails"`
	Note     string         `json:"note"`

	CreatedAt int64  `json:"created_at"`
	CreatedBy string `json:"created_by"`
	UpdatedAt int64  `json:"updated_at"`
	UpdatedBy string `json:"updated_by"`
}

type UserToken struct {
	Token     string `json:"token"`
	UserID    string `json:"user_id"`
	CreatedAt int64  `json:"created_at"`
	ExpiredAt int64  `json:"expired_at"`
}

type UserManager interface {
	CreateUser(ctx context.Context, ts int64, req CreateUserRequest) (User, error)
	ChangePassword(ctx context.Context, ts int64, req ChangePasswordRequest) (User, error)
	ResetPassword(ctx context.Context, ts int64, req ResetPasswordRequest) (User, error)
	UpdateUser(ctx context.Context, ts int64, req UpdateUserRequest) (User, error)
	ActivateUser(ctx context.Context, ts int64, req ActivateUserRequest) (User, error)
	DeactivateUser(ctx context.Context, ts int64, req ActivateUserRequest) (User, error)
	Authenticate(ctx context.Context, ts int64, req AuthenticateUserRequest) (UserToken, error)
	ListUsers(ctx context.Context, req ListUserRequest) (ListUserResult, error)

	TokenAuthorization(ctx context.Context, ts int64, token string) (UserToken, error)
}
type CreateUserRequest struct {
	RequestUser string      `json:"request_user"`
	UserID      string      `json:"user_id"`
	Password    RawPassword `json:"password"`
	Name        string      `json:"name"`
	Emails      []string    `json:"emails"`
	Note        string      `json:"note"`
}
type ChangePasswordRequest struct {
	UserID      string      `json:"user_id"`
	OldPassword RawPassword `json:"old_password"`
	Password    RawPassword `json:"password"`
}
type ResetPasswordRequest struct {
	RequestUser string      `json:"request_user"`
	UserID      string      `json:"user_id"`
	Password    RawPassword `json:"password"`
}
type UpdateUserRequest struct {
	RequestUser string   `json:"request_user"`
	UserID      string   `json:"user_id"`
	Name        string   `json:"name"`
	Emails      []string `json:"emails"`
	Note        string   `json:"note"`
}
type ActivateUserRequest struct {
	RequestUser string `json:"request_user"`
	UserID      string `json:"user_id"`
}
type AuthenticateUserRequest struct {
	UserID   string      `json:"user_id"`
	Password RawPassword `json:"password"`
}
type ListUserRequest struct {
	Offset int `json:"offset"` // Offset for pagination.
	Limit  int `json:"limit"`  // Limit for pagination.

	IDs []string `json:"ids"` // Filter by application ID.
}
type ListUserResult struct {
	Total int64
	Users []User
}

type UserStorage interface {
	CreateTx(ctx context.Context, options ...storage.CreateTxOption) (storage.Tx, error)
	StoreUser(ctx context.Context, tx storage.Tx, user User) error
	ListUsers(ctx context.Context, tx storage.Tx, req ListUserRequest) (ListUserResult, error)
	StoreUserToken(ctx context.Context, tx storage.Tx, token UserToken) error
	GetUserToken(ctx context.Context, tx storage.Tx, token string) (UserToken, error)

	// This function should be called periodically to prevent the database from growing too large due to expired tokens.
	RemoveUserTokenByExpiredAt(ctx context.Context, tx storage.Tx, expiredAt int64) error
}

type _UserManager struct {
	storage UserStorage
}

func NewUserManager(s UserStorage) UserManager {
	return &_UserManager{
		storage: s,
	}
}

func (m *_UserManager) CreateUser(ctx context.Context, ts int64, req CreateUserRequest) (User, error) {
	if err := ValidateCreateUserRequest(req); err != nil {
		return User{}, err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(string(req.Password)), bcrypt.DefaultCost)
	if err != nil {
		return User{}, err
	}

	user := User{
		ID:        req.UserID,
		Password:  HashedPassword(hashedPassword),
		Status:    UserStatusActive,
		Version:   1,
		Name:      req.Name,
		Emails:    req.Emails,
		Note:      req.Note,
		CreatedAt: ts,
		CreatedBy: req.RequestUser,
		UpdatedAt: ts,
		UpdatedBy: req.RequestUser,
	}

	tx, err := m.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback(ctx)

	oldUsers, err := m.storage.ListUsers(
		ctx,
		tx,
		ListUserRequest{
			Limit: 1,
			IDs:   []string{user.ID},
		},
	)
	if err != nil {
		return User{}, err
	}
	if len(oldUsers.Users) > 0 {
		return User{}, model.ErrUserAlreadyExists
	}

	if err := m.storage.StoreUser(ctx, tx, user); err != nil {
		return User{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return User{}, err
	}

	user.Password = ""
	return user, nil
}

func (m *_UserManager) ChangePassword(ctx context.Context, ts int64, req ChangePasswordRequest) (User, error) {
	if err := ValidateChangePasswordRequest(req); err != nil {
		return User{}, err
	}

	tx, err := m.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback(ctx)

	user, err := m._GetUser(ctx, tx, req.UserID)
	if err != nil {
		return User{}, err
	}

	if err := VerifyUserPassword(req.OldPassword, user.Password); err != nil {
		return User{}, err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(string(req.Password)), bcrypt.DefaultCost)
	if err != nil {
		return User{}, err
	}

	user.UpdatedAt = ts
	user.UpdatedBy = req.UserID
	user.Password = HashedPassword(hashedPassword)
	user.Version += 1
	if err := m.storage.StoreUser(ctx, tx, user); err != nil {
		return User{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return User{}, err
	}

	user.Password = ""
	return user, nil
}

func (m *_UserManager) ResetPassword(ctx context.Context, ts int64, req ResetPasswordRequest) (User, error) {
	if err := ValidateResetPasswordRequest(req); err != nil {
		return User{}, err
	}

	tx, err := m.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback(ctx)

	user, err := m._GetUser(ctx, tx, req.UserID)
	if err != nil {
		return User{}, err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(string(req.Password)), bcrypt.DefaultCost)
	if err != nil {
		return User{}, err
	}

	user.UpdatedAt = ts
	user.UpdatedBy = req.RequestUser
	user.Password = HashedPassword(hashedPassword)
	user.Version += 1
	if err := m.storage.StoreUser(ctx, tx, user); err != nil {
		return User{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return User{}, err
	}

	user.Password = ""
	return user, nil
}

func (m *_UserManager) UpdateUser(ctx context.Context, ts int64, req UpdateUserRequest) (User, error) {
	if err := ValidateUpdateUserRequest(req); err != nil {
		return User{}, err
	}

	tx, err := m.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback(ctx)

	user, err := m._GetUser(ctx, tx, req.UserID)
	if err != nil {
		return User{}, err
	}

	user.UpdatedAt = ts
	user.UpdatedBy = req.RequestUser
	user.Name = req.Name
	user.Emails = req.Emails
	user.Note = req.Note
	user.Version += 1
	if err := m.storage.StoreUser(ctx, tx, user); err != nil {
		return User{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return User{}, err
	}

	user.Password = ""
	return user, nil
}

func (m *_UserManager) ActivateUser(ctx context.Context, ts int64, req ActivateUserRequest) (User, error) {
	if err := ValidateActivateUserRequest(req); err != nil {
		return User{}, err
	}

	tx, err := m.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback(ctx)

	user, err := m._GetUser(ctx, tx, req.UserID)
	if err != nil {
		return User{}, err
	}

	user.UpdatedAt = ts
	user.UpdatedBy = req.RequestUser
	user.Status = UserStatusActive
	user.Version += 1
	if err := m.storage.StoreUser(ctx, tx, user); err != nil {
		return User{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return User{}, err
	}

	user.Password = ""
	return user, nil
}

func (m *_UserManager) DeactivateUser(ctx context.Context, ts int64, req ActivateUserRequest) (User, error) {
	if err := ValidateActivateUserRequest(req); err != nil {
		return User{}, err
	}

	tx, err := m.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return User{}, err
	}

	defer tx.Rollback(ctx)

	user, err := m._GetUser(ctx, tx, req.UserID)
	if err != nil {
		return User{}, err
	}

	user.UpdatedAt = ts
	user.UpdatedBy = req.RequestUser
	user.Status = UserStatusInactive
	user.Version += 1
	if err := m.storage.StoreUser(ctx, tx, user); err != nil {
		return User{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return User{}, err
	}

	user.Password = ""
	return user, nil
}

func (m *_UserManager) Authenticate(ctx context.Context, ts int64, req AuthenticateUserRequest) (UserToken, error) {
	if err := ValidateAuthenticateUserRequest(req); err != nil {
		return UserToken{}, err
	}

	tx, err := m.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return UserToken{}, err
	}
	defer tx.Rollback(ctx)

	user, err := m._GetUser(ctx, tx, req.UserID)
	if errors.Is(err, model.ErrUserNotFound) {
		return UserToken{}, model.ErrUserAuthenticationFail
	}
	if err != nil {
		return UserToken{}, err
	}

	if err := VerifyUserPassword(req.Password, user.Password); err != nil {
		return UserToken{}, err
	}

	// Create a token for this user.
	token := UserToken{
		Token:     fmt.Sprintf("%s_%s", uuid.NewString(), uuid.NewString()),
		UserID:    user.ID,
		CreatedAt: ts,
		ExpiredAt: ts + 86400,
	}
	if err := m.storage.StoreUserToken(ctx, tx, token); err != nil {
		return UserToken{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return UserToken{}, err
	}

	return token, nil
}

func (m *_UserManager) TokenAuthorization(ctx context.Context, ts int64, token string) (UserToken, error) {
	tx, err := m.storage.CreateTx(ctx, storage.TxOptionWithWrite(false))
	if err != nil {
		return UserToken{}, err
	}
	defer tx.Rollback(ctx)

	userToken, err := m.storage.GetUserToken(ctx, tx, token)
	if errors.Is(err, sql.ErrNoRows) {
		return UserToken{}, model.ErrUserTokenInvalid
	}
	if err != nil {
		return UserToken{}, err
	}

	if userToken.ExpiredAt < ts {
		return UserToken{}, model.ErrUserTokenExpired
	}

	return userToken, nil
}

func (m *_UserManager) ListUsers(ctx context.Context, req ListUserRequest) (ListUserResult, error) {
	if err := ValidateListUserRequest(req); err != nil {
		return ListUserResult{}, err
	}

	tx, err := m.storage.CreateTx(ctx, storage.TxOptionWithWrite(false))
	if err != nil {
		return ListUserResult{}, err
	}
	defer tx.Rollback(ctx)

	result, err := m.storage.ListUsers(ctx, tx, req)
	if err != nil {
		return ListUserResult{}, err
	}
	for i := range result.Users {
		result.Users[i].Password = ""
	}
	return result, nil
}

func (m *_UserManager) _GetUser(ctx context.Context, tx storage.Tx, id string) (User, error) {
	listReq := ListUserRequest{
		IDs:   []string{id},
		Limit: 1,
	}

	listResult, err := m.storage.ListUsers(ctx, tx, listReq)
	if err != nil {
		return User{}, err
	}

	if len(listResult.Users) == 0 {
		return User{}, model.ErrUserNotFound
	}

	return listResult.Users[0], nil
}

func VerifyUserPassword(password RawPassword, hashedPassword HashedPassword) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err == nil {
		return nil
	}

	if err == bcrypt.ErrMismatchedHashAndPassword {
		return model.ErrUserAuthenticationFail
	}

	return err
}
