package middleware

import (
	"net/http"
	"os"
	"strconv"
	"time"

	otlp_util "github.com/bluexlab/otlp-util-go"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
)

type ResponseWriter struct {
	http.ResponseWriter
	status int
}

func NewResponseWriter(w http.ResponseWriter) *ResponseWriter {
	return &ResponseWriter{w, http.StatusOK}
}

func (w *ResponseWriter) Status() int {
	return w.status
}

func (w *ResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func TimeTrace(next http.Handler) http.Handler {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, span := otlp_util.Start(r.Context(), "bu_server/middleware/TimeTrace")
		defer span.End()

		clientIP := r.RemoteAddr
		userAgent := r.UserAgent()
		referer := r.Referer()
		method := r.Method
		urlPath := r.URL.Path

		span.SetAttributes(
			attribute.String("client_ip", clientIP),
			attribute.String("user_agent", userAgent),
			attribute.String("referer", referer),
			attribute.String("method", method),
			attribute.String("path", urlPath),
		)
		if route := mux.CurrentRoute(r); route != nil {
			path, _ := route.GetPathTemplate()
			span.SetAttributes(attribute.String("route", path))
		}

		start := time.Now()
		rw := NewResponseWriter(w)
		next.ServeHTTP(rw, r)
		elapsed := time.Since(start).Milliseconds()

		statusCode := rw.Status()
		dataLength, _ := strconv.ParseInt(w.Header().Get("Content-Length"), 10, 64)
		logrus.Debugf("%s - %s \"%s %s\" %d %d \"%s\" \"%s\" (%dms)", clientIP, hostname, method, urlPath, statusCode, dataLength, referer, userAgent, elapsed)
	})
}
