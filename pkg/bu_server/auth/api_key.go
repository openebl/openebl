package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/openebl/openebl/pkg/bu_server/storage"
	"golang.org/x/crypto/bcrypt"
)

type APIKeyStatus string
type APIKeyScope string

const (
	APIKeyStatusActive  = APIKeyStatus("active")
	APIKeyStatusRevoked = APIKeyStatus("revoked")

	APIKeyScopeAll = APIKeyScope("all")
)

// APIKeyString is the string representation of an API key.
// The BU server client has to provide this string to the BU server to authenticate itself.
// The format of APIKeyString is [ID]:[SECRET].
type APIKeyString string

// APIKeyHashedString is the hashed string representation of an API key.
// It is stored in the database. BU server is not able to recover the original APIKeyString from this.
type APIKeyHashedString string

type APIKey struct {
	ID            string             `json:"id"`
	HashString    APIKeyHashedString `json:"hash_string"`
	Version       int                `json:"version"`
	ApplicationID string             `json:"application_id"`
	Scopes        []APIKeyScope      `json:"scopes"`
	Status        APIKeyStatus       `json:"status"`

	CreatedAt int64  `json:"created_at"` // Unix Time (in second)
	CreatedBy string `json:"created_by"`
	UpdatedAt int64  `json:"updated_at"` // Unix Time (in second)
	UpdatedBy string `json:"updated_by"`
}

// APIKeyAuthenticator is the interface that wraps the basic API key authentication methods
// and other management methods.
type APIKeyAuthenticator interface {
	CreateAPIKey(
		ctx context.Context,
		ts int64,
		request CreateAPIKeyRequest,
	) (APIKey, APIKeyString, error)

	// RevokeAPIKey revokes the API key with the given ID.
	// The error can be ErrAPIKeyNotFound and others.
	RevokeAPIKey(
		ctx context.Context,
		ts int64,
		request RevokeAPIKeyRequest,
	) error

	// Authenticate authenticates the given API key string. It returns the API key if the authentication is successful.
	// The error can be ErrAPIKeyNotFound, ErrMismatchAPIKey, ErrRevokedAPIKey and others.
	Authenticate(ctx context.Context, key APIKeyString) (APIKey, error)
}
type CreateAPIKeyRequest struct {
	RequestUser
	ApplicationID string        `json:"application_id"`
	Scopes        []APIKeyScope `json:"scopes"`
}
type RevokeAPIKeyRequest struct {
	RequestUser
	ID string `json:"id"`
}

// APIKeyStorage is the interface that APIKeyAuthenticator relies on to persist the API key data.
type APIKeyStorage interface {
	CreateTx(ctx context.Context, options ...storage.CreateTxOption) (storage.Tx, error)
	StoreAPIKey(ctx context.Context, tx storage.Tx, key APIKey) error
	GetAPIKey(ctx context.Context, tx storage.Tx, id string) (ListAPIKeyRecord, error)
	ListAPIKeys(ctx context.Context, tx storage.Tx, req ListAPIKeysRequest) (ListAPIKeysResult, error)
}

type ListAPIKeysRequest struct {
	Offset int
	Limit  int

	ApplicationIDs []string       // Filter by application ID.
	Statuses       []APIKeyStatus // Filter by status.
}
type ListAPIKeysResult struct {
	Total int
	Keys  []ListAPIKeyRecord
}
type ListAPIKeyRecord struct {
	APIKey      APIKey
	Application Application
}

func (ks APIKeyString) ID() (string, error) {
	// Split ID from APIKeyString.
	parts := strings.Split(string(ks), ":")
	if len(parts) != 2 {
		return "", ErrInvalidAPIKeyString
	}

	return parts[0], nil
}

func (ks APIKeyString) Hash() (APIKeyHashedString, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(string(ks)), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return APIKeyHashedString(hashed), nil
}

func NewAPIKeyString() (APIKeyString, error) {
	prefixBytes := make([]byte, 16)
	secretBytes := make([]byte, 32)

	if _, err := rand.Read(prefixBytes); err != nil {
		return "", err
	}
	if _, err := rand.Read(secretBytes); err != nil {
		return "", err
	}

	base64Prefix := base64.RawURLEncoding.EncodeToString(prefixBytes)
	base64Secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	return APIKeyString(fmt.Sprintf("%s:%s", base64Prefix, base64Secret)), nil
}

func VerifyAPIKeyString(ks APIKeyString, hashedKs APIKeyHashedString) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashedKs), []byte(ks))
	if err == nil {
		return nil
	}

	if err == bcrypt.ErrMismatchedHashAndPassword {
		return ErrMismatchAPIKey
	}

	return err
}

type _APIKeyAuthenticator struct {
	storage APIKeyStorage
}

func NewAPIKeyAuthenticator(storage APIKeyStorage) APIKeyAuthenticator {
	return &_APIKeyAuthenticator{
		storage: storage,
	}
}

func (a *_APIKeyAuthenticator) CreateAPIKey(
	ctx context.Context,
	ts int64,
	request CreateAPIKeyRequest,
) (APIKey, APIKeyString, error) {
	if err := ValidateCreateAPIKeyRequest(request); err != nil {
		return APIKey{}, "", err
	}

	apiKeyString, err := NewAPIKeyString()
	if err != nil {
		return APIKey{}, "", nil
	}
	apiKeyID, err := apiKeyString.ID()
	if err != nil {
		return APIKey{}, "", err
	}
	apiKeyHashedString, err := apiKeyString.Hash()
	if err != nil {
		return APIKey{}, "", err
	}

	apiKey := APIKey{
		ID:            apiKeyID,
		Version:       1,
		HashString:    apiKeyHashedString,
		ApplicationID: request.ApplicationID,
		Scopes:        request.Scopes,
		Status:        APIKeyStatusActive,
		CreatedAt:     ts,
		CreatedBy:     request.User,
		UpdatedAt:     ts,
		UpdatedBy:     request.User,
	}

	tx, err := a.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return APIKey{}, "", err
	}
	defer tx.Rollback(ctx)

	if err := a.storage.StoreAPIKey(ctx, tx, apiKey); err != nil {
		return APIKey{}, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return APIKey{}, "", err
	}

	return apiKey, apiKeyString, nil
}

func (a *_APIKeyAuthenticator) RevokeAPIKey(
	ctx context.Context,
	ts int64,
	request RevokeAPIKeyRequest,
) error {
	if err := ValidateRevokeAPIKeyRequest(request); err != nil {
		return err
	}

	tx, err := a.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	apiKey, err := a.storage.GetAPIKey(ctx, tx, request.ID)
	if err != nil && err == sql.ErrNoRows {
		return ErrAPIKeyNotFound
	} else if err != nil {
		return err
	}

	if apiKey.APIKey.Status == APIKeyStatusRevoked {
		// Already revoked.
		return nil
	}

	apiKey.APIKey.Status = APIKeyStatusRevoked
	apiKey.APIKey.Version += 1
	apiKey.APIKey.UpdatedAt = ts
	apiKey.APIKey.UpdatedBy = request.User

	if err := a.storage.StoreAPIKey(ctx, tx, apiKey.APIKey); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return nil
}

// Authenticate authenticates the given API key string. It returns the API key if the authentication is successful.
func (a *_APIKeyAuthenticator) Authenticate(ctx context.Context, key APIKeyString) (APIKey, error) {
	apiKeyID, err := key.ID()
	if err != nil {
		return APIKey{}, err
	}

	tx, err := a.storage.CreateTx(ctx, storage.TxOptionWithWrite(false))
	if err != nil {
		return APIKey{}, err
	}
	defer tx.Rollback(ctx)

	apiKey, err := a.storage.GetAPIKey(ctx, tx, apiKeyID)
	if err != nil && err == sql.ErrNoRows {
		return APIKey{}, ErrAPIKeyNotFound
	} else if err != nil {
		return APIKey{}, err
	}

	if err := VerifyAPIKeyString(key, apiKey.APIKey.HashString); err != nil {
		return APIKey{}, err
	}

	if apiKey.APIKey.Status != APIKeyStatusActive {
		return APIKey{}, ErrRevokedAPIKey
	}

	if apiKey.Application.Status != ApplicationStatusActive {
		return APIKey{}, ErrApplicationInactive
	}

	apiKey.APIKey.HashString = ""
	return apiKey.APIKey, nil
}
