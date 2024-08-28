package middleware

import (
	"context"
	"fmt"
	"net/http"
)

const BUSINESS_UNIT_ID_HEADER = "X-Business-Unit-ID"

func ExtractBusinessUnitID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buID := r.Header.Get(BUSINESS_UNIT_ID_HEADER)
		if buID == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(fmt.Sprintf("Header %s is required", BUSINESS_UNIT_ID_HEADER)))
			return
		}

		ctx := context.WithValue(r.Context(), BUSINESS_UNIT_ID, buID)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}
