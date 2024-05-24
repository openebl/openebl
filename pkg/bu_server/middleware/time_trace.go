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

type TimeTrace struct {
	durationHistogram metric.Int64Histogram
}

func NewTimeTrace() *TimeTrace {
	histogram := otlp_util.NewInt64Histogram(
		"observe.api.request.duration",
		metric.WithUnit("ms"),
		metric.WithDescription("Request duration in milliseconds"),
	)
	return &TimeTrace{
		durationHistogram: histogram,
	}
}

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

func (m *TimeTrace) TraceHandler(next http.Handler) http.Handler {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := NewResponseWriter(w)

		start := time.Now()
		next.ServeHTTP(rw, r)
		elapsed := time.Since(start).Milliseconds()

		statusCode := rw.Status()
		dataLength, _ := strconv.ParseInt(w.Header().Get("Content-Length"), 10, 64)
		logrus.Debugf("%s - %s \"%s %s\" %d %d \"%s\" \"%s\" (%dms)", r.RemoteAddr, hostname, r.Method, r.URL.Path, statusCode, dataLength, r.Referer(), r.UserAgent(), elapsed)

		route := mux.CurrentRoute(r)
		routeTemplate, _ := route.GetPathTemplate()
		metricAttributes := []attribute.KeyValue{
			semconv.HTTPMethod(r.Method),
			semconv.HTTPRoute(routeTemplate),
			semconv.HTTPStatusCode(statusCode),
		}
		m.durationHistogram.Record(r.Context(), elapsed, metric.WithAttributes(metricAttributes...))
	})
}
