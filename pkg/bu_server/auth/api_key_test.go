package auth_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/openebl/openebl/pkg/bu_server/auth"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	mock_auth "github.com/openebl/openebl/test/mock/bu_server/auth"
	mock_storage "github.com/openebl/openebl/test/mock/bu_server/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

func TestAPIKeyGenerating(t *testing.T) {
	apiKeyString, err := auth.NewAPIKeyString()
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("API key string: %s", apiKeyString)

	apiKeyHashedString1, err := apiKeyString.Hash()
	if err != nil {
		t.Fatal(err)
	}
	apiKeyHashedString2, err := apiKeyString.Hash()
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("API key hashed string1: %s", apiKeyHashedString1)
	t.Logf("API key hashed string2: %s", apiKeyHashedString2)
	assert.NotEqual(t, apiKeyHashedString1, apiKeyHashedString2)

	assert.NoError(t, auth.VerifyAPIKeyString(apiKeyString, apiKeyHashedString1))
	assert.NoError(t, auth.VerifyAPIKeyString(apiKeyString, apiKeyHashedString2))

	assert.ErrorIs(t, auth.VerifyAPIKeyString(apiKeyString+"a", auth.APIKeyHashedString(apiKeyHashedString1)), auth.ErrMismatchAPIKey)
}

type APIAuthenticatorTestSuite struct {
	suite.Suite
	ctx           context.Context
	ctrl          *gomock.Controller
	storage       *mock_auth.MockAPIKeyStorage
	tx            *mock_storage.MockTx
	authenticator auth.APIKeyAuthenticator
}

func TestAPIAuthenticator(t *testing.T) {
	suite.Run(t, &APIAuthenticatorTestSuite{})
}

func (s *APIAuthenticatorTestSuite) SetupTest() {
	s.ctx = context.Background()
	s.ctrl = gomock.NewController(s.T())
	s.storage = mock_auth.NewMockAPIKeyStorage(s.ctrl)
	s.tx = mock_storage.NewMockTx(s.ctrl)
	s.authenticator = auth.NewAPIKeyAuthenticator(s.storage)
}

func (s *APIAuthenticatorTestSuite) TearDownTest() {
	s.ctrl.Finish()
}

func (s *APIAuthenticatorTestSuite) TestCreateAPIKey() {
	request := auth.CreateAPIKeyRequest{
		ApplicationID: "application-id",
		Scopes:        []auth.APIKeyScope{auth.APIKeyScopeAll},
		RequestUser: auth.RequestUser{
			User: "created-by",
		},
	}
	ts := time.Now().Unix()

	receivedAPIKey := auth.APIKey{}

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Eq(s.ctx), gomock.Len(2)).Return(s.tx, nil),
		s.storage.EXPECT().StoreAPIKey(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, key auth.APIKey) error {
				receivedAPIKey = key
				return nil
			},
		),
		s.tx.EXPECT().Commit(gomock.Eq(s.ctx)).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Eq(s.ctx)).Return(nil),
	)

	returnedAPIKey, apiKeyString, err := s.authenticator.CreateAPIKey(s.ctx, ts, request)
	s.Require().NoError(err)
	s.Assert().Equal(receivedAPIKey, returnedAPIKey)
	s.Assert().Equal(receivedAPIKey.ApplicationID, request.ApplicationID)
	s.Assert().Equal(receivedAPIKey.Scopes, request.Scopes)
	s.Assert().Equal(receivedAPIKey.CreatedBy, request.RequestUser.User)
	s.Assert().Equal(receivedAPIKey.UpdatedBy, request.RequestUser.User)
	s.Assert().Equal(receivedAPIKey.CreatedAt, ts)
	s.Assert().Equal(receivedAPIKey.UpdatedAt, ts)
	s.Assert().NoError(auth.VerifyAPIKeyString(apiKeyString, receivedAPIKey.HashString))
}

func (s *APIAuthenticatorTestSuite) TestRevokeAPIKey() {
	request := auth.RevokeAPIKeyRequest{
		ID:            "id",
		ApplicationID: "application-id",
		RequestUser: auth.RequestUser{
			User: "revoked-by",
		},
	}
	ts := time.Now().Unix()

	oldAPIKey := auth.ListAPIKeyRecord{
		APIKey: auth.APIKey{
			ID:            request.ID,
			HashString:    "hash-string",
			Version:       1,
			ApplicationID: "application-id",
			Scopes:        []auth.APIKeyScope{auth.APIKeyScopeAll},
			Status:        auth.APIKeyStatusActive,
			CreatedAt:     ts - 1000,
			CreatedBy:     "created-by",
			UpdatedAt:     ts - 1000,
			UpdatedBy:     "created-by",
		},
		Application: auth.Application{
			ID:     "application-id",
			Status: auth.ApplicationStatusActive,
		},
	}

	newAPIKey := oldAPIKey.APIKey
	newAPIKey.Status = auth.APIKeyStatusRevoked
	newAPIKey.UpdatedAt = ts
	newAPIKey.UpdatedBy = request.RequestUser.User
	newAPIKey.Version += 1

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Eq(s.ctx), gomock.Len(2)).Return(s.tx, nil),
		s.storage.EXPECT().GetAPIKey(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(request.ID)).Return(oldAPIKey, nil),
		s.storage.EXPECT().StoreAPIKey(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(newAPIKey)).Return(nil),
		s.tx.EXPECT().Commit(gomock.Eq(s.ctx)).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Eq(s.ctx)).Return(nil),
	)

	err := s.authenticator.RevokeAPIKey(s.ctx, ts, request)
	s.Require().NoError(err)
}

func (s *APIAuthenticatorTestSuite) TestRevokeAPIKeyWithNonExistAPIKey() {
	request := auth.RevokeAPIKeyRequest{
		ID: "id",
		RequestUser: auth.RequestUser{
			User: "revoked-by",
		},
	}
	ts := time.Now().Unix()

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Eq(s.ctx), gomock.Len(2)).Return(s.tx, nil),
		s.storage.EXPECT().GetAPIKey(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(request.ID)).Return(auth.ListAPIKeyRecord{}, sql.ErrNoRows),
		s.tx.EXPECT().Rollback(gomock.Eq(s.ctx)).Return(nil),
	)

	err := s.authenticator.RevokeAPIKey(s.ctx, ts, request)
	s.Require().ErrorIs(err, auth.ErrAPIKeyNotFound)
}

func (s *APIAuthenticatorTestSuite) TestAuthenticate() {
	ts := time.Now().Unix()
	apiKeyString, err := auth.NewAPIKeyString()
	s.Require().NoError(err)

	apiKeyID, _ := apiKeyString.ID()
	apiKeyHashedString, _ := apiKeyString.Hash()

	oldAPIKey := auth.ListAPIKeyRecord{
		APIKey: auth.APIKey{
			ID:            apiKeyID,
			HashString:    apiKeyHashedString,
			Version:       1,
			ApplicationID: "application-id",
			Scopes:        []auth.APIKeyScope{auth.APIKeyScopeAll},
			Status:        auth.APIKeyStatusActive,
			CreatedAt:     ts - 1000,
			CreatedBy:     "created-by",
			UpdatedAt:     ts - 1000,
			UpdatedBy:     "created-by",
		},
		Application: auth.Application{
			ID:      "application-id",
			Version: 1,
			Status:  auth.ApplicationStatusActive,
		},
	}

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Eq(s.ctx), gomock.Len(1)).Return(s.tx, nil),
		s.storage.EXPECT().GetAPIKey(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(apiKeyID)).Return(oldAPIKey, nil),
		s.tx.EXPECT().Rollback(gomock.Eq(s.ctx)).Return(nil),
	)

	returnedAPIKey, err := s.authenticator.Authenticate(s.ctx, apiKeyString)
	s.Require().NoError(err)
	s.Assert().Equal(auth.APIKeyHashedString(""), returnedAPIKey.HashString)
	returnedAPIKey.HashString = oldAPIKey.APIKey.HashString
	s.Assert().Equal(oldAPIKey.APIKey, returnedAPIKey)

	// Test with revoked API key
	oldAPIKey.APIKey.Status = auth.APIKeyStatusRevoked
	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Eq(s.ctx), gomock.Len(1)).Return(s.tx, nil),
		s.storage.EXPECT().GetAPIKey(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(apiKeyID)).Return(oldAPIKey, nil),
		s.tx.EXPECT().Rollback(gomock.Eq(s.ctx)).Return(nil),
	)

	returnedAPIKey, err = s.authenticator.Authenticate(s.ctx, apiKeyString)
	s.Require().ErrorIs(err, auth.ErrRevokedAPIKey)
	s.Assert().Equal(auth.APIKey{}, returnedAPIKey)
	// End of Test with revoked API key

	// Test with inactive application
	oldAPIKey.APIKey.Status = auth.APIKeyStatusActive
	oldAPIKey.Application.Status = auth.ApplicationStatusInactive
	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Eq(s.ctx), gomock.Len(1)).Return(s.tx, nil),
		s.storage.EXPECT().GetAPIKey(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(apiKeyID)).Return(oldAPIKey, nil),
		s.tx.EXPECT().Rollback(gomock.Eq(s.ctx)).Return(nil),
	)

	returnedAPIKey, err = s.authenticator.Authenticate(s.ctx, apiKeyString)
	s.Require().ErrorIs(err, auth.ErrApplicationInactive)
	s.Assert().Equal(auth.APIKey{}, returnedAPIKey)
	// End of Test with inactive application

	// Test with non-exist API key
	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Eq(s.ctx), gomock.Len(1)).Return(s.tx, nil),
		s.storage.EXPECT().GetAPIKey(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(apiKeyID)).Return(auth.ListAPIKeyRecord{}, sql.ErrNoRows),
		s.tx.EXPECT().Rollback(gomock.Eq(s.ctx)).Return(nil),
	)

	returnedAPIKey, err = s.authenticator.Authenticate(s.ctx, apiKeyString)
	s.Require().ErrorIs(err, auth.ErrAPIKeyNotFound)
	s.Assert().Equal(auth.APIKey{}, returnedAPIKey)
}

func (s *APIAuthenticatorTestSuite) TestListAPIKey() {
	request := auth.ListAPIKeysRequest{
		Offset:         1,
		Limit:          2,
		ApplicationIDs: []string{"application-id"},
		Statuses:       []auth.APIKeyStatus{auth.APIKeyStatusActive},
	}
	result := auth.ListAPIKeysResult{
		Total: 1,
		Keys: []auth.ListAPIKeyRecord{
			{
				APIKey: auth.APIKey{
					ID:            "id",
					Version:       1,
					ApplicationID: "application-id",
					Scopes:        []auth.APIKeyScope{auth.APIKeyScopeAll},
					Status:        auth.APIKeyStatusActive,
				},
				Application: auth.Application{
					ID:      "application-id",
					Version: 1,
					Status:  auth.ApplicationStatusActive,
				},
			},
		},
	}

	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Eq(s.ctx), gomock.Any()).Return(s.tx, nil),
		s.storage.EXPECT().ListAPIKeys(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(request)).Return(result, nil),
		s.tx.EXPECT().Rollback(gomock.Eq(s.ctx)).Return(nil),
	)

	returnedResult, err := s.authenticator.ListAPIKeys(s.ctx, request)
	s.Require().NoError(err)
	s.Assert().Equal(result, returnedResult)
}
