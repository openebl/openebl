package middleware_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/openebl/openebl/pkg/bu_server/auth"
	"github.com/openebl/openebl/pkg/bu_server/middleware"
	"github.com/openebl/openebl/pkg/bu_server/model"
	mock_auth "github.com/openebl/openebl/test/mock/bu_server/auth"
	"github.com/stretchr/testify/suite"
)

type APIKeyAuthTestSuite struct {
	suite.Suite
	ctx           context.Context
	ctrl          *gomock.Controller
	authenticator *mock_auth.MockAPIKeyAuthenticator
	auth          *middleware.APIKeyAuth
}

func TestAPIKeyAuthTestSuite(t *testing.T) {
	suite.Run(t, new(APIKeyAuthTestSuite))
}

var OkHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
})

func (s *APIKeyAuthTestSuite) SetupTest() {
	s.ctx = context.Background()
	s.ctrl = gomock.NewController(s.T())
	s.authenticator = mock_auth.NewMockAPIKeyAuthenticator(s.ctrl)
	s.auth = middleware.NewAPIKeyAuth(s.authenticator)
}

func (s *APIKeyAuthTestSuite) TearDownTest() {
	s.ctrl.Finish()
}

func (s *APIKeyAuthTestSuite) TestAuthenticate() {
	appID := "app-id"
	apiKeyString := auth.APIKeyString("fake-api-key")
	request := httptest.NewRequest("GET", "/test", nil).WithContext(s.ctx)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", apiKeyString))
	response := httptest.NewRecorder()

	s.authenticator.EXPECT().Authenticate(gomock.Any(), gomock.Eq(apiKeyString)).Return(auth.APIKey{ApplicationID: appID}, nil)

	var receivedAppID string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAppID = r.Context().Value(middleware.APPLICATION_ID).(string)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	s.auth.Authenticate(handler).ServeHTTP(response, request)
	s.Equal(http.StatusOK, response.Code)
	s.Equal(appID, receivedAppID)
}

func (s *APIKeyAuthTestSuite) TestAuthenticateWithoutProvidingAPIKey() {
	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()

	s.auth.Authenticate(OkHandler).ServeHTTP(response, request)
	s.Equal(http.StatusUnauthorized, response.Code)
	s.Equal("missing API key", response.Body.String())
}

func (s *APIKeyAuthTestSuite) TestAuthenticateWithoutPassingAPIKeyAuthentication() {
	apiKeyString := auth.APIKeyString("fake-api-key")
	request := httptest.NewRequest("GET", "/test", nil).WithContext(s.ctx)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", apiKeyString))
	response := httptest.NewRecorder()

	s.authenticator.EXPECT().Authenticate(gomock.Any(), gomock.Eq(apiKeyString)).Return(auth.APIKey{}, model.ErrMismatchAPIKey)

	s.auth.Authenticate(OkHandler).ServeHTTP(response, request)
	s.Equal(http.StatusUnauthorized, response.Code)
	s.Equal(model.ErrMismatchAPIKey.Error(), response.Body.String())
}
