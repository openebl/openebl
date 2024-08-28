package api

import (
	"fmt"
	"net/http"

	"github.com/sirupsen/logrus"
)

type ResponseInterceptor struct {
	writer http.ResponseWriter
	Status int
	Body   []byte
}

func NewResponseInterceptor(w http.ResponseWriter) *ResponseInterceptor {
	return &ResponseInterceptor{writer: w}
}

func (r *ResponseInterceptor) WriteHeader(status int) {
	r.Status = status
	r.writer.WriteHeader(status)
}

func (r *ResponseInterceptor) Write(b []byte) (int, error) {
	if r.Status/100 != 2 {
		r.Body = append(r.Body, b...)
	}
	return r.writer.Write(b)
}

func (r *ResponseInterceptor) Header() http.Header {
	return r.writer.Header()
}

func (r *ResponseInterceptor) Returned() string {
	if len(r.Body) > 0 {
		return fmt.Sprintf("%d %s", r.Status, string(r.Body))
	}

	return fmt.Sprintf("%d", r.Status)
}

func (r *ResponseInterceptor) IsSystemError() bool {
	return r.Status/100 == 5
}

func Log(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		interceptor := NewResponseInterceptor(w)
		w = interceptor
		logrus.Debugf("Request %s %s started.", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
		if interceptor.IsSystemError() {
			logrus.Errorf("Request %s %s returned %s", r.Method, r.URL.Path, interceptor.Returned())
		} else {
			logrus.Debugf("Request %s %s returned %s", r.Method, r.URL.Path, interceptor.Returned())
		}
	})
}
