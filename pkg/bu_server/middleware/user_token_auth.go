package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/openebl/openebl/pkg/bu_server/auth"
)

type UserTokenAuth struct {
	auth auth.UserManager
}

func NewUserTokenAuth(auth auth.UserManager) *UserTokenAuth {
	return &UserTokenAuth{
		auth: auth,
	}
}

func (a *UserTokenAuth) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		token := getBearerToken(r)
		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("missing token"))
			return
		}

		ts := time.Now().Unix()
		userToken, err := a.auth.TokenAuthorization(ctx, ts, token)
		if errors.Is(err, auth.ErrUserError) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(err.Error()))
			return
		} else if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf("Internal server error: %s", err.Error())))
			return
		}

		ctx = context.WithValue(ctx, USER_TOKEN, userToken)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}
