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
	"go.opentelemetry.io/otel/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.25.0"
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
	requestDuration := otlp_util.NewInt64Histogram("bu_server.api.request.duration", metric.WithDescription("Request duration in milliseconds"))

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		clientIP := r.RemoteAddr
		userAgent := r.UserAgent()
		referer := r.Referer()
		method := r.Method
		urlPath := r.URL.Path

		metricAttributes := []attribute.KeyValue{
			semconv.NetworkPeerAddress(clientIP),
			semconv.UserAgentName(userAgent),
			semconv.HTTPMethod(method),
			semconv.HTTPURL(urlPath),
		}
		if route := mux.CurrentRoute(r); route != nil {
			path, _ := route.GetPathTemplate()
			metricAttributes = append(metricAttributes, semconv.HTTPRoute(path))
		}

		start := time.Now()
		rw := NewResponseWriter(w)
		next.ServeHTTP(rw, r.WithContext(ctx))
		elapsed := time.Since(start).Milliseconds()

		statusCode := rw.Status()
		dataLength, _ := strconv.ParseInt(w.Header().Get("Content-Length"), 10, 64)
		logrus.Debugf("%s - %s \"%s %s\" %d %d \"%s\" \"%s\" (%dms)", clientIP, hostname, method, urlPath, statusCode, dataLength, referer, userAgent, elapsed)

		metricAttributes = append(metricAttributes, semconv.HTTPStatusCode(statusCode))
		requestDuration.Record(ctx, elapsed, metric.WithAttributes(metricAttributes...))
	})
}
