package middleware

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

func TimeTrace(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		logrus.Debugf("Request %s %s returned.", r.Method, r.URL.Path)
	})
}
