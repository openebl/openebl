package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/openebl/openebl/pkg/cert_server/cert_authority"
	"github.com/openebl/openebl/pkg/cert_server/model"
	"github.com/openebl/openebl/pkg/cert_server/publisher"
	"github.com/openebl/openebl/pkg/cert_server/storage"
	"github.com/openebl/openebl/pkg/cert_server/storage/postgres"
	"github.com/openebl/openebl/pkg/relay"
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
	RelayServer          string                      `yaml:"relay_server"`
}

type RestServer struct {
	ca                cert_authority.CertAuthority
	publisher         *publisher.Publisher
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
	var pub *publisher.Publisher
	if config.RelayServer != "" {
		pub = publisher.NewPublisher(
			publisher.PublisherWithOutboxStorage(certStorage),
			publisher.PublisherWithRelayClient(
				relay.NewNostrClient(
					relay.NostrClientWithServerURL(config.RelayServer),
					relay.NostrClientWithConnectionStatusCallback(func(ctx context.Context, cancelFunc context.CancelCauseFunc, client relay.RelayClient, serverIdentity string, status bool) {
					}),
				),
			),
		)
	}
	return NewRestServerWithController(ca, pub, config.PrivateServerAddress, config.PublicServerAddress), nil
}

func NewRestServerWithController(ca cert_authority.CertAuthority, publisher *publisher.Publisher, privateAddress, publicAddress string) *RestServer {
	restServer := &RestServer{
		ca:        ca,
		publisher: publisher,
	}

	registerPublicEndpoints := func(r *mux.Router) {
		r.HandleFunc("/root_cert", restServer.listRootCert).Methods(http.MethodGet)
		r.HandleFunc("/root_cert/{id}", restServer.getRootCert).Methods(http.MethodGet)
		r.HandleFunc("/ca_cert", restServer.listCACert).Methods(http.MethodGet)
		r.HandleFunc("/ca_cert/{id}", restServer.getCACert).Methods(http.MethodGet)
		r.HandleFunc("/cert", restServer.listCert).Methods(http.MethodGet)
		r.HandleFunc("/cert/{id}", restServer.getCert).Methods(http.MethodGet)
	}

	privateRouter := mux.NewRouter()
	privateRouter.Use(Log, ExtractRequester)
	privateRouter.HandleFunc("/root_cert", restServer.addRootCert).Methods(http.MethodPost)
	privateRouter.HandleFunc("/root_cert/{id}", restServer.revokeRootCert).Methods(http.MethodDelete)
	privateRouter.HandleFunc("/ca_cert", restServer.createCACertificateSigningRequest).Methods(http.MethodPost)
	privateRouter.HandleFunc("/ca_cert/{id}", restServer.respondCACertificateSigningRequest).Methods(http.MethodPost)
	privateRouter.HandleFunc("/ca_cert/{id}/revoke", restServer.revokeCACert).Methods(http.MethodPost)
	privateRouter.HandleFunc("/cert", restServer.addCertificateSigningRequest).Methods(http.MethodPost)
	privateRouter.HandleFunc("/cert/{id}", restServer.issueCertificate).Methods(http.MethodPost)
	privateRouter.HandleFunc("/cert/{id}/reject", restServer.rejectCertificateSigningRequest).Methods(http.MethodPost)
	privateRouter.HandleFunc("/cert/{id}", restServer.revokeCert).Methods(http.MethodDelete)
	registerPublicEndpoints(privateRouter)

	publicRouter := mux.NewRouter()
	publicRouter.Use(Log, ExtractRequester)
	registerPublicEndpoints(publicRouter)

	if privateAddress != "" {
		restServer.privateHttpServer = &http.Server{
			Addr:    privateAddress,
			Handler: privateRouter,
		}
	}
	if publicAddress != "" {
		restServer.publicHttpServer = &http.Server{
			Addr:    publicAddress,
			Handler: publicRouter,
		}
	}

	return restServer
}

func (s *RestServer) Run() error {
	if s.privateHttpServer == nil && s.publicHttpServer == nil {
		return errors.New("no server to run")
	}

	if s.publisher != nil {
		s.publisher.Start()
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
	if s.publisher != nil {
		s.publisher.Stop()
	}
	return serverErr
}

func (s *RestServer) listRootCert(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	r.URL.Query()
	if limit == 0 {
		limit = 10
	}
	req := storage.ListCertificatesRequest{
		Offset: offset,
		Limit:  limit,
		Types:  []model.CertType{model.RootCert},
	}

	result, err := s.ca.ListCertificate(ctx, req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list root certificates: %s", err.Error()), model.ErrToHttpStatus(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

func (s *RestServer) getRootCert(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	certID := mux.Vars(r)["id"]

	req := storage.ListCertificatesRequest{
		Limit: 1,
		IDs:   []string{certID},
		Types: []model.CertType{model.RootCert},
	}

	result, err := s.ca.ListCertificate(ctx, req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list root certificates: %s", err.Error()), model.ErrToHttpStatus(err))
		return
	}

	if len(result.Certs) == 0 {
		http.Error(w, fmt.Sprintf("Root certificate not found: %s", certID), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result.Certs[0])
}

func (s *RestServer) listCACert(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit == 0 {
		limit = 10
	}
	req := storage.ListCertificatesRequest{
		Offset: offset,
		Limit:  limit,
		Types:  []model.CertType{model.CACert},
	}

	result, err := s.ca.ListCertificate(ctx, req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list CA certificates: %s", err.Error()), model.ErrToHttpStatus(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

func (s *RestServer) getCACert(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	certID := mux.Vars(r)["id"]

	req := storage.ListCertificatesRequest{
		Limit: 1,
		IDs:   []string{certID},
		Types: []model.CertType{model.CACert},
	}

	result, err := s.ca.ListCertificate(ctx, req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list CA certificates: %s", err.Error()), model.ErrToHttpStatus(err))
		return
	}

	if len(result.Certs) == 0 {
		http.Error(w, fmt.Sprintf("CA certificate not found: %s", certID), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result.Certs[0])
}

func (s *RestServer) listCert(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit == 0 {
		limit = 10
	}
	req := storage.ListCertificatesRequest{
		Offset: offset,
		Limit:  limit,
		Types:  []model.CertType{model.BUCert, model.ThirdPartyCACert},
	}

	result, err := s.ca.ListCertificate(ctx, req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list certificates: %s", err.Error()), model.ErrToHttpStatus(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

func (s *RestServer) getCert(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	certID := mux.Vars(r)["id"]

	req := storage.ListCertificatesRequest{
		Limit: 1,
		IDs:   []string{certID},
		Types: []model.CertType{model.BUCert, model.ThirdPartyCACert},
	}

	result, err := s.ca.ListCertificate(ctx, req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list certificates: %s", err.Error()), model.ErrToHttpStatus(err))
		return
	}

	if len(result.Certs) == 0 {
		http.Error(w, fmt.Sprintf("Certificate not found: %s", certID), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result.Certs[0])
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
		http.Error(w, fmt.Sprintf("Failed to add root certificate: %s", err.Error()), model.ErrToHttpStatus(err))
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
		http.Error(w, fmt.Sprintf("Failed to revoke root certificate: %s", err.Error()), model.ErrToHttpStatus(err))
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
		http.Error(w, fmt.Sprintf("Failed to create CA certificate signing request: %s", err.Error()), model.ErrToHttpStatus(err))
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
		http.Error(w, fmt.Sprintf("Failed to respond to CA certificate signing request: %s", err.Error()), model.ErrToHttpStatus(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(cert)
}

func (s *RestServer) revokeCACert(w http.ResponseWriter, r *http.Request) {
	ts := time.Now().Unix()
	ctx := r.Context()
	requester := ctx.Value(REQUESTER_CONTEXT_KEY).(string)
	certID := mux.Vars(r)["id"]

	req := cert_authority.RevokeCACertificateRequest{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %s", err.Error()), http.StatusBadRequest)
		return
	}
	req.Requester = requester
	req.CertID = certID

	cert, err := s.ca.RevokeCACertificate(ctx, ts, req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to revoke CA certificate: %s", err.Error()), model.ErrToHttpStatus(err))
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
		http.Error(w, fmt.Sprintf("Failed to add CSR: %s", err.Error()), model.ErrToHttpStatus(err))
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
		http.Error(w, fmt.Sprintf("Failed to issue certificate: %s", err.Error()), model.ErrToHttpStatus(err))
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
		http.Error(w, fmt.Sprintf("Failed to reject CSR: %s", err.Error()), model.ErrToHttpStatus(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(cert)
}

func (s *RestServer) revokeCert(w http.ResponseWriter, r *http.Request) {
	ts := time.Now().Unix()
	ctx := r.Context()
	requester := ctx.Value(REQUESTER_CONTEXT_KEY).(string)
	certID := mux.Vars(r)["id"]

	req := cert_authority.RevokeCertificateRequest{
		Requester: requester,
		CertID:    certID,
	}

	cert, err := s.ca.RevokeCertificate(ctx, ts, req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to revoke certificate: %s", err.Error()), model.ErrToHttpStatus(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(cert)
}
