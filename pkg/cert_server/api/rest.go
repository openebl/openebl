package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/openebl/openebl/pkg/cert_server/cert_authority"
	"github.com/openebl/openebl/pkg/cert_server/storage/postgres"
	"github.com/openebl/openebl/pkg/util"
)

type ContextKey string

const (
	REQUESTER_HEADER      = "X-Requester"
	REQUESTER_CONTEXT_KEY = ContextKey("requester")
)

type RestServerConfig struct {
	Database             util.PostgresDatabaseConfig `yaml:"database"`
	PrivateServerAddress string                      `yaml:"private_server_address"`
	PublicServerAddress  string                      `yaml:"public_server_address"`
}

type RestServer struct {
	ca cert_authority.CertAuthority

	privateHttpServer *http.Server
	publicHttpServer  *http.Server
}

func ExtractRequester(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		requester := r.Header.Get(REQUESTER_HEADER)
		ctx = context.WithValue(ctx, REQUESTER_CONTEXT_KEY, requester)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func NewRestServerWithConfig(config RestServerConfig) (*RestServer, error) {
	certStorage, err := postgres.NewStorageWithConfig(config.Database)
	if err != nil {
		return nil, err
	}

	ca := cert_authority.NewCertAuthority(certStorage)
	return NewRestServerWithController(ca, config.PrivateServerAddress, config.PublicServerAddress), nil
}

func NewRestServerWithController(ca cert_authority.CertAuthority, privateAddress, publicAddress string) *RestServer {
	restServer := &RestServer{
		ca: ca,
	}

	r := mux.NewRouter()
	r.Use(Log, ExtractRequester)
	r.HandleFunc("/root_cert", restServer.addRootCert).Methods(http.MethodPost)
	r.HandleFunc("/root_cert/{id}", restServer.revokeRootCert).Methods(http.MethodDelete)
	r.HandleFunc("/ca_cert", restServer.createCACertificateSigningRequest).Methods(http.MethodPost)
	r.HandleFunc("/ca_cert/{id}", restServer.respondCACertificateSigningRequest).Methods(http.MethodPost)
	r.HandleFunc("/cert", restServer.addCertificateSigningRequest).Methods(http.MethodPost)
	r.HandleFunc("/cert/{id}", restServer.issueCertificate).Methods(http.MethodPost)
	r.HandleFunc("/cert/{id}/reject", restServer.rejectCertificateSigningRequest).Methods(http.MethodPost)

	if privateAddress != "" {
		restServer.privateHttpServer = &http.Server{
			Addr:    privateAddress,
			Handler: r,
		}
	}
	if publicAddress != "" {
		restServer.publicHttpServer = &http.Server{
			Addr:    publicAddress,
			Handler: r,
		}
	}

	return restServer
}

func (s *RestServer) Run() error {
	if s.privateHttpServer == nil && s.publicHttpServer == nil {
		return errors.New("no server to run")
	}

	var privateServerErr error
	var publicServerErr error
	wg := sync.WaitGroup{}

	if s.privateHttpServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.privateHttpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				privateServerErr = err
			}
		}()
	}
	if s.publicHttpServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.publicHttpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				publicServerErr = err
			}
		}()
	}

	wg.Wait()
	if privateServerErr != nil {
		return privateServerErr
	}
	if publicServerErr != nil {
		return publicServerErr
	}
	return nil
}

func (s *RestServer) Close(ctx context.Context) error {
	var serverErr error
	wg := sync.WaitGroup{}
	if s.privateHttpServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.privateHttpServer.SetKeepAlivesEnabled(false)
			if err := s.privateHttpServer.Shutdown(ctx); err != nil {
				serverErr = err
			}
		}()
	}

	if s.publicHttpServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.publicHttpServer.SetKeepAlivesEnabled(false)
			if err := s.publicHttpServer.Shutdown(ctx); err != nil {
				serverErr = err
			}
		}()
	}

	wg.Wait()
	return serverErr
}

func (s *RestServer) addRootCert(w http.ResponseWriter, r *http.Request) {
	ts := time.Now().Unix()
	ctx := r.Context()
	requester := ctx.Value(REQUESTER_CONTEXT_KEY).(string)

	req := cert_authority.AddRootCertificateRequest{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %s", err.Error()), http.StatusBadRequest)
		return
	}
	req.Requester = requester

	cert, err := s.ca.AddRootCertificate(ctx, ts, req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to add root certificate: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(cert)
}

func (s *RestServer) revokeRootCert(w http.ResponseWriter, r *http.Request) {
	ts := time.Now().Unix()
	ctx := r.Context()
	requester := ctx.Value(REQUESTER_CONTEXT_KEY).(string)
	certID := mux.Vars(r)["id"]

	req := cert_authority.RevokeCertificateRequest{
		Requester: requester,
		CertID:    certID,
	}

	cert, err := s.ca.RevokeRootCertificate(ctx, ts, req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to revoke root certificate: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(cert)
}

func (s *RestServer) createCACertificateSigningRequest(w http.ResponseWriter, r *http.Request) {
	ts := time.Now().Unix()
	ctx := r.Context()
	requester := ctx.Value(REQUESTER_CONTEXT_KEY).(string)

	req := cert_authority.CreateCACertificateSigningRequestRequest{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %s", err.Error()), http.StatusBadRequest)
		return
	}
	req.Requester = requester

	csr, err := s.ca.CreateCACertificateSigningRequest(ctx, ts, req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create CA certificate signing request: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(csr)
}

func (s *RestServer) respondCACertificateSigningRequest(w http.ResponseWriter, r *http.Request) {
	ts := time.Now().Unix()
	ctx := r.Context()
	requester := ctx.Value(REQUESTER_CONTEXT_KEY).(string)
	certID := mux.Vars(r)["id"]

	req := cert_authority.RespondCACertificateSigningRequestRequest{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %s", err.Error()), http.StatusBadRequest)
		return
	}
	req.Requester = requester
	req.CertID = certID

	cert, err := s.ca.RespondCACertificateSigningRequest(ctx, ts, req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to respond to CA certificate signing request: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(cert)
}

func (s *RestServer) addCertificateSigningRequest(w http.ResponseWriter, r *http.Request) {
	ts := time.Now().Unix()
	ctx := r.Context()
	requester := ctx.Value(REQUESTER_CONTEXT_KEY).(string)

	req := cert_authority.AddCertificateSigningRequestRequest{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %s", err.Error()), http.StatusBadRequest)
		return
	}
	req.Requester = requester

	cert, err := s.ca.AddCertificateSigningRequest(ctx, ts, req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to add CSR: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(cert)
}

func (s *RestServer) issueCertificate(w http.ResponseWriter, r *http.Request) {
	ts := time.Now().Unix()
	ctx := r.Context()
	requester := ctx.Value(REQUESTER_CONTEXT_KEY).(string)
	certID := mux.Vars(r)["id"]

	req := cert_authority.IssueCertificateRequest{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %s", err.Error()), http.StatusBadRequest)
		return
	}
	req.Requester = requester
	req.CertID = certID

	cert, err := s.ca.IssueCertificate(ctx, ts, req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to issue certificate: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(cert)
}

func (s *RestServer) rejectCertificateSigningRequest(w http.ResponseWriter, r *http.Request) {
	ts := time.Now().Unix()
	ctx := r.Context()
	requester := ctx.Value(REQUESTER_CONTEXT_KEY).(string)
	certID := mux.Vars(r)["id"]

	req := cert_authority.RejectCertificateSigningRequestRequest{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %s", err.Error()), http.StatusBadRequest)
		return
	}
	req.Requester = requester
	req.CertID = certID

	cert, err := s.ca.RejectCertificateSigningRequest(ctx, ts, req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to reject CSR: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(cert)
}
