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
	mock_auth "github.com/openebl/openebl/test/mock/bu_server/auth"
	"github.com/stretchr/testify/suite"
)

type UserTokenAuthTestSuite struct {
	suite.Suite
	ctx         context.Context
	ctrl        *gomock.Controller
	userManager *mock_auth.MockUserManager
	auth        *middleware.UserTokenAuth
}

func TestUserTokenAuthTestSuite(t *testing.T) {
	suite.Run(t, new(UserTokenAuthTestSuite))
}

func (s *UserTokenAuthTestSuite) SetupTest() {
	s.ctx = context.Background()
	s.ctrl = gomock.NewController(s.T())
	s.userManager = mock_auth.NewMockUserManager(s.ctrl)
	s.auth = middleware.NewUserTokenAuth(s.userManager)
}

func (s *UserTokenAuthTestSuite) TearDownTest() {
	s.ctrl.Finish()
}

func (s *UserTokenAuthTestSuite) TestAuthenticate() {
	token := "token"
	userToken := auth.UserToken{
		Token:  token,
		UserID: "user-id",
	}

	var receivedUserToken auth.UserToken
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUserToken, _ = r.Context().Value(middleware.USER_TOKEN).(auth.UserToken)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Test normal case.
	request := httptest.NewRequest("GET", "/test", nil).WithContext(s.ctx)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	response := httptest.NewRecorder()
	s.userManager.EXPECT().TokenAuthorization(gomock.Eq(s.ctx), gomock.Any(), gomock.Eq(token)).Return(userToken, nil)
	s.auth.Authenticate(handler).ServeHTTP(response, request)
	s.Equal(http.StatusOK, response.Code)
	s.Equal(userToken, receivedUserToken)
	// End of Test normal case.

	// Test invalid token.
	request = httptest.NewRequest("GET", "/test", nil).WithContext(s.ctx)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	response = httptest.NewRecorder()
	receivedUserToken = auth.UserToken{}
	s.userManager.EXPECT().TokenAuthorization(gomock.Eq(s.ctx), gomock.Any(), gomock.Eq(token)).Return(auth.UserToken{}, auth.ErrUserTokenInvalid)
	s.auth.Authenticate(handler).ServeHTTP(response, request)
	s.Equal(http.StatusUnauthorized, response.Code)
	s.Empty(receivedUserToken)
	// End of Test invalid token.

	// Test Expired token.
	request = httptest.NewRequest("GET", "/test", nil).WithContext(s.ctx)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	response = httptest.NewRecorder()
	receivedUserToken = auth.UserToken{}
	s.userManager.EXPECT().TokenAuthorization(gomock.Eq(s.ctx), gomock.Any(), gomock.Eq(token)).Return(auth.UserToken{}, auth.ErrUserTokenExpired)
	s.auth.Authenticate(handler).ServeHTTP(response, request)
	s.Equal(http.StatusUnauthorized, response.Code)
	s.Empty(receivedUserToken)
	// End of Test Expired token.
}
