package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	otlp_util "github.com/bluexlab/otlp-util-go"
	"github.com/openebl/openebl/pkg/bu_server/auth"
	"github.com/openebl/openebl/pkg/bu_server/model"
)

type APIKeyAuth struct {
	auth auth.APIKeyAuthenticator
}

func NewAPIKeyAuth(auth auth.APIKeyAuthenticator) *APIKeyAuth {
	return &APIKeyAuth{
		auth: auth,
	}
}

func (a *APIKeyAuth) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := otlp_util.Start(r.Context(), "bu_server/middleware/Authenticate")
		defer span.End()

		apiKeyString := auth.APIKeyString(getBearerToken(r))
		if apiKeyString == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("missing API key"))
			return
		}

		apiKey, err := a.auth.Authenticate(ctx, apiKeyString)
		if errors.Is(err, model.ErrAPIKeyError) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(err.Error()))
			return
		} else if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf("Internal server error: %s", err.Error())))
			return
		}

		ctx = context.WithValue(ctx, APPLICATION_ID, apiKey.ApplicationID)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func getBearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	parts := strings.Split(h, "Bearer")
	if len(parts) != 2 {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
