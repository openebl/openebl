package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	otlp_util "github.com/bluexlab/otlp-util-go"
	"github.com/gorilla/mux"
	"github.com/nuts-foundation/go-did/did"
	"github.com/openebl/openebl/pkg/bu_server/auth"
	"github.com/openebl/openebl/pkg/bu_server/business_unit"
	"github.com/openebl/openebl/pkg/bu_server/cert"
	"github.com/openebl/openebl/pkg/bu_server/middleware"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/bu_server/storage/postgres"
	"github.com/openebl/openebl/pkg/bu_server/trade_document"
	"github.com/openebl/openebl/pkg/bu_server/webhook"
	"github.com/openebl/openebl/pkg/util"
	"github.com/sirupsen/logrus"
)

type APIConfig struct {
	Database     util.PostgresDatabaseConfig `yaml:"database"`
	LocalAddress string                      `yaml:"local_address"`
}

type API struct {
	apiKeyMgr   auth.APIKeyAuthenticator
	buMgr       business_unit.BusinessUnitManager
	fileEBLCtrl trade_document.FileBaseEBLController
	webhookCtrl webhook.WebhookController

	httpServer *http.Server
}

func NewAPIWithConfig(cfg APIConfig) (*API, error) {
	dbStorage, err := postgres.NewStorageWithConfig(cfg.Database)
	if err != nil {
		logrus.Errorf("failed to create storage: %v", err)
		return nil, err
	}
	cv := cert.NewCertManager(cert.WithCertStore(dbStorage))

	apiKeyMgr := auth.NewAPIKeyAuthenticator(dbStorage)
	webhookCtrl := webhook.NewWebhookController(dbStorage)
	buMgr := business_unit.NewBusinessUnitManager(dbStorage, cv, webhookCtrl, nil)
	fileEBLCtrl := trade_document.NewFileBaseEBLController(dbStorage, buMgr, webhookCtrl)
	api, err := NewAPIWithController(apiKeyMgr, buMgr, webhookCtrl, fileEBLCtrl, cfg.LocalAddress)
	if err != nil {
		return nil, err
	}

	return api, nil
}

func NewAPIWithController(apiKeyMgr auth.APIKeyAuthenticator, buMgr business_unit.BusinessUnitManager, webhookCtrl webhook.WebhookController, fileEBLCtrl trade_document.FileBaseEBLController, localAddress string) (*API, error) {
	apiServer := &API{
		apiKeyMgr:   apiKeyMgr,
		buMgr:       buMgr,
		webhookCtrl: webhookCtrl,
		fileEBLCtrl: fileEBLCtrl,
	}

	r := mux.NewRouter()

	healthRouter := r.NewRoute().Subrouter()
	healthRouter.HandleFunc("/health", apiServer.health).Methods(http.MethodGet)

	apiRouter := r.NewRoute().Subrouter()
	apiRouter.Use(middleware.TimeTrace, middleware.NewAPIKeyAuth(apiServer.apiKeyMgr).Authenticate)
	apiRouter.HandleFunc("/business_unit", apiServer.createBusinessUnit).Methods(http.MethodPost)
	apiRouter.HandleFunc("/business_unit", apiServer.listBusinessUnit).Methods(http.MethodGet)
	apiRouter.HandleFunc("/business_unit/{id}", apiServer.getBusinessUnit).Methods(http.MethodGet)
	apiRouter.HandleFunc("/business_unit/{id}", apiServer.updateBusinessUnit).Methods(http.MethodPost)
	apiRouter.HandleFunc("/business_unit/{id}/status", apiServer.setBusinessUnitStatus).Methods(http.MethodPost)
	apiRouter.HandleFunc("/business_unit/{id}/authentication", apiServer.createBusinessUnitAuthentication).Methods(http.MethodPost)
	apiRouter.HandleFunc("/business_unit/{id}/authentication", apiServer.listBusinessUnitAuthentication).Methods(http.MethodGet)
	apiRouter.HandleFunc("/business_unit/{id}/authentication/{authentication_id}", apiServer.getBusinessUnitAuthentication).Methods(http.MethodGet)
	apiRouter.HandleFunc("/business_unit/{id}/authentication/{authentication_id}", apiServer.revokeBusinessUnitAuthentication).Methods(http.MethodDelete)
	apiRouter.HandleFunc("/webhook", apiServer.createWebhook).Methods(http.MethodPost)
	apiRouter.HandleFunc("/webhook", apiServer.listWebhook).Methods(http.MethodGet)
	apiRouter.HandleFunc("/webhook/{id}", apiServer.getWebhook).Methods(http.MethodGet)
	apiRouter.HandleFunc("/webhook/{id}", apiServer.updateWebhook).Methods(http.MethodPost)
	apiRouter.HandleFunc("/webhook/{id}", apiServer.deleteWebhook).Methods(http.MethodDelete)

	eblRouter := apiRouter.NewRoute().Subrouter()
	eblRouter.Use(middleware.ExtractBusinessUnitID)
	eblRouter.HandleFunc("/ebl", apiServer.listFileBasedEBL).Methods(http.MethodGet)
	eblRouter.HandleFunc("/ebl", apiServer.createFileBasedEBL).Methods(http.MethodPost)
	eblRouter.HandleFunc("/ebl/{id}", apiServer.getFileBasedEBL).Methods(http.MethodGet)
	eblRouter.HandleFunc("/ebl/{id}/update", apiServer.updateFileBasedEBL).Methods(http.MethodPost)
	eblRouter.HandleFunc("/ebl/{id}/transfer", apiServer.transferEBL).Methods(http.MethodPost)
	eblRouter.HandleFunc("/ebl/{id}/return", apiServer.returnEBL).Methods(http.MethodPost)
	eblRouter.HandleFunc("/ebl/{id}/amendment_request", apiServer.amendmentRequestEBL).Methods(http.MethodPost)
	eblRouter.HandleFunc("/ebl/{id}/amend", apiServer.amendFileBasedEBL).Methods(http.MethodPost)
	eblRouter.HandleFunc("/ebl/{id}/surrender", apiServer.surrenderEBL).Methods(http.MethodPost)
	eblRouter.HandleFunc("/ebl/{id}/print_to_paper", apiServer.printEBLToPaper).Methods(http.MethodPost)
	eblRouter.HandleFunc("/ebl/{id}/accomplish", apiServer.accomplishEBL).Methods(http.MethodPost)
	eblRouter.HandleFunc("/ebl/{id}/delete", apiServer.deleteEBL).Methods(http.MethodPost)
	eblRouter.HandleFunc("/ebl/{id}/document", apiServer.getFileBasedEBLDocument).Methods(http.MethodGet)

	apiServer.httpServer = &http.Server{
		Addr:    localAddress,
		Handler: r,
	}
	return apiServer, nil
}

func (a *API) Run() error {
	logrus.Infof("API server is running on %s", a.httpServer.Addr)
	err := a.httpServer.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
func (a *API) Close(ctx context.Context) error {
	a.httpServer.SetKeepAlivesEnabled(false)
	return a.httpServer.Shutdown(ctx)
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	response := struct {
		Status    string `json:"status"`
		Timestamp string `json:"timestamp"`
	}{
		Status:    "OK",
		Timestamp: time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logrus.Warnf("failed to encode/write response for health check: %v", err)
	}
}

func (a *API) createBusinessUnit(w http.ResponseWriter, r *http.Request) {
	ctx, span := otlp_util.Start(r.Context(), "bu_server/api/createBusinessUnit")
	defer span.End()

	appID, _ := ctx.Value(middleware.APPLICATION_ID).(string)

	// Parse the request body
	var req business_unit.CreateBusinessUnitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, http.StatusBadRequest, err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	logrus.Debugf("%s %s is invoked with application: %v, request: %v", r.Method, r.RequestURI, appID, util.StructToJSON(req))

	req.ApplicationID = appID
	result, err := a.buMgr.CreateBusinessUnit(ctx, time.Now().Unix(), req)
	if errors.Is(err, model.ErrInvalidParameter) {
		logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, http.StatusBadRequest, err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		logrus.Errorf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, http.StatusInternalServerError, err.Error())
		http.Error(w, fmt.Sprintf("Internal server error: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		logrus.Warnf("failed to encode/write response: %v", err)
	}
}

func (a *API) listBusinessUnit(w http.ResponseWriter, r *http.Request) {
	ctx, span := otlp_util.Start(r.Context(), "bu_server/api/listBusinessUnit")
	defer span.End()

	appID, _ := ctx.Value(middleware.APPLICATION_ID).(string)

	logrus.Debugf("%s %s is invoked with application: %v", r.Method, r.RequestURI, appID)

	// TODO: Get parameters from QueryString.
	req := storage.ListBusinessUnitsRequest{}
	req.ApplicationID = appID
	offsetStr := r.URL.Query().Get("offset")
	limitStr := r.URL.Query().Get("limit")
	if offsetStr != "" {
		offset, err := strconv.ParseInt(offsetStr, 10, 32)
		if err != nil || offset < 0 {
			http.Error(w, "offset is invalid", http.StatusBadRequest)
			return
		}
		req.Offset = int(offset)
	}
	if limitStr != "" {
		limit, err := strconv.ParseInt(limitStr, 10, 32)
		if err != nil || limit < 1 {
			http.Error(w, "limit is invalid", http.StatusBadRequest)
			return
		}
		req.Limit = int(limit)
	}

	result, err := a.buMgr.ListBusinessUnits(ctx, req)
	if errors.Is(err, model.ErrInvalidParameter) {
		logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, http.StatusBadRequest, err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, http.StatusInternalServerError, err.Error())
		http.Error(w, fmt.Sprintf("Internal server error: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		logrus.Warnf("listBusinessUnit failed to encode/write response: %v", err)
	}
}

func (a *API) getBusinessUnit(w http.ResponseWriter, r *http.Request) {
	ctx, span := otlp_util.Start(r.Context(), "bu_server/api/getBusinessUnit")
	defer span.End()

	appID, _ := ctx.Value(middleware.APPLICATION_ID).(string)
	buID := mux.Vars(r)["id"]

	logrus.Debugf("%s %s is invoked with application: %v", r.Method, r.RequestURI, appID)

	listReq := storage.ListBusinessUnitsRequest{
		Limit:           1,
		ApplicationID:   appID,
		BusinessUnitIDs: []string{buID},
	}
	result, err := a.buMgr.ListBusinessUnits(ctx, listReq)
	if errors.Is(err, model.ErrInvalidParameter) {
		logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, http.StatusBadRequest, err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		logrus.Errorf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, http.StatusInternalServerError, err.Error())
		http.Error(w, fmt.Sprintf("Internal server error: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	if len(result.Records) == 0 {
		logrus.Debugf("%s %s returns status code %d", r.Method, r.RequestURI, http.StatusNotFound)
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(result.Records[0]); err != nil {
		logrus.Warnf("getBusinessUnit failed to encode/write response: %v", err)
	}
}

func (a *API) updateBusinessUnit(w http.ResponseWriter, r *http.Request) {
	ctx, span := otlp_util.Start(r.Context(), "bu_server/api/updateBusinessUnit")
	defer span.End()

	appID, _ := ctx.Value(middleware.APPLICATION_ID).(string)
	buID := mux.Vars(r)["id"]

	logrus.Debugf("%s %s is invoked with application: %v", r.Method, r.RequestURI, appID)

	// Parse the request body
	req := business_unit.UpdateBusinessUnitRequest{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, http.StatusBadRequest, err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.ApplicationID = appID
	buDID, err := did.ParseDID(buID)
	if err != nil {
		logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, http.StatusBadRequest, err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.ID = *buDID

	result, err := a.buMgr.UpdateBusinessUnit(ctx, time.Now().Unix(), req)
	if errors.Is(err, model.ErrInvalidParameter) {
		logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, http.StatusBadRequest, err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if errors.Is(err, model.ErrBusinessUnitNotFound) {
		logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, http.StatusNotFound, err.Error())
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if err != nil {
		logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, http.StatusInternalServerError, err.Error())
		http.Error(w, fmt.Sprintf("Internal server error: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		logrus.Warnf("updateBusinessUnit failed to encode/write response: %v", err)
	}
}

func (a *API) setBusinessUnitStatus(w http.ResponseWriter, r *http.Request) {
	ctx, span := otlp_util.Start(r.Context(), "bu_server/api/setBusinessUnitStatus")
	defer span.End()

	appID, _ := ctx.Value(middleware.APPLICATION_ID).(string)

	logrus.Debugf("%s %s is invoked with application: %v", r.Method, r.RequestURI, appID)

	req := business_unit.SetBusinessUnitStatusRequest{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, http.StatusBadRequest, err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.ApplicationID = appID
	buID := mux.Vars(r)["id"]
	buDID, err := did.ParseDID(buID)
	if err != nil {
		logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, http.StatusBadRequest, err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.ID = *buDID

	result, err := a.buMgr.SetStatus(ctx, time.Now().Unix(), req)
	if errors.Is(err, model.ErrInvalidParameter) {
		logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, http.StatusBadRequest, err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if errors.Is(err, model.ErrBusinessUnitNotFound) {
		logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, http.StatusNotFound, err.Error())
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if err != nil {
		logrus.Errorf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, http.StatusInternalServerError, err.Error())
		http.Error(w, fmt.Sprintf("Internal server error: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		logrus.Warnf("setBusinessUnitStatus failed to encode/write response: %v", err)
	}
}

func (a *API) createBusinessUnitAuthentication(w http.ResponseWriter, r *http.Request) {
	ctx, span := otlp_util.Start(r.Context(), "bu_server/api/createBusinessUnitAuthentication")
	defer span.End()

	appID, _ := ctx.Value(middleware.APPLICATION_ID).(string)

	req := business_unit.AddAuthenticationRequest{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, http.StatusBadRequest, err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	logrus.Debugf("%s %s is invoked with application: %v, request: %v", r.Method, r.RequestURI, appID, util.StructToJSON(req))

	req.ApplicationID = appID
	buID := mux.Vars(r)["id"]
	buDID, err := did.ParseDID(buID)
	if err != nil {
		logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, http.StatusBadRequest, err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.BusinessUnitID = *buDID

	result, err := a.buMgr.AddAuthentication(ctx, time.Now().Unix(), req)
	if errors.Is(err, model.ErrInvalidParameter) {
		logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, http.StatusBadRequest, err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if errors.Is(err, model.ErrBusinessUnitNotFound) {
		logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, http.StatusNotFound, err.Error())
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if err != nil {
		logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, http.StatusInternalServerError, err.Error())
		http.Error(w, fmt.Sprintf("Internal server error: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		logrus.Warnf("createBusinessUnitAuthentication failed to encode/write response: %v", err)
	}
}

func (a *API) listBusinessUnitAuthentication(w http.ResponseWriter, r *http.Request) {
	ctx, span := otlp_util.Start(r.Context(), "bu_server/api/listBusinessUnitAuthentication")
	defer span.End()

	appID, _ := ctx.Value(middleware.APPLICATION_ID).(string)
	buID := mux.Vars(r)["id"]

	logrus.Debugf("%s %s is invoked with application: %v", r.Method, r.RequestURI, appID)

	req := storage.ListAuthenticationRequest{}
	offsetStr := r.URL.Query().Get("offset")
	limitStr := r.URL.Query().Get("limit")
	if offsetStr != "" {
		offset, err := strconv.ParseInt(offsetStr, 10, 32)
		if err != nil || offset < 0 {
			http.Error(w, "offset is invalid", http.StatusBadRequest)
			return
		}
		req.Offset = int(offset)
	}
	if limitStr != "" {
		limit, err := strconv.ParseInt(limitStr, 10, 32)
		if err != nil || limit < 1 {
			http.Error(w, "limit is invalid", http.StatusBadRequest)
			return
		}
		req.Limit = int(limit)
	}
	req.ApplicationID = appID
	req.BusinessUnitID = buID

	result, err := a.buMgr.ListAuthentication(ctx, req)
	if errors.Is(err, model.ErrInvalidParameter) {
		logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, http.StatusBadRequest, err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		logrus.Errorf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, http.StatusInternalServerError, err.Error())
		http.Error(w, fmt.Sprintf("Internal server error: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		logrus.Warnf("listBusinessUnitAuthentication failed to encode/write response: %v", err)
	}
}

func (a *API) getBusinessUnitAuthentication(w http.ResponseWriter, r *http.Request) {
	ctx, span := otlp_util.Start(r.Context(), "bu_server/api/getBusinessUnitAuthentication")
	defer span.End()

	appID, _ := ctx.Value(middleware.APPLICATION_ID).(string)
	buID := mux.Vars(r)["id"]
	authenticationID := mux.Vars(r)["authentication_id"]

	logrus.Debugf("%s %s is invoked with application: %v", r.Method, r.RequestURI, appID)

	req := storage.ListAuthenticationRequest{
		Limit:             1,
		ApplicationID:     appID,
		BusinessUnitID:    buID,
		AuthenticationIDs: []string{authenticationID},
	}

	result, err := a.buMgr.ListAuthentication(ctx, req)
	if errors.Is(err, model.ErrInvalidParameter) {
		logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, http.StatusBadRequest, err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		logrus.Errorf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, http.StatusInternalServerError, err.Error())
		http.Error(w, fmt.Sprintf("Internal server error: %s", err.Error()), http.StatusInternalServerError)
		return
	}
	if len(result.Records) == 0 {
		logrus.Debugf("%s %s returns status code %d", r.Method, r.RequestURI, http.StatusNotFound)
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(result.Records[0]); err != nil {
		logrus.Warnf("getBusinessUnitAuthentication failed to encode/write response: %v", err)
	}
}

func (a *API) revokeBusinessUnitAuthentication(w http.ResponseWriter, r *http.Request) {
	ctx, span := otlp_util.Start(r.Context(), "bu_server/api/revokeBusinessUnitAuthentication")
	defer span.End()

	appID, _ := ctx.Value(middleware.APPLICATION_ID).(string)
	buID := mux.Vars(r)["id"]
	authenticationID := mux.Vars(r)["authentication_id"]

	logrus.Debugf("%s %s is invoked with application: %v", r.Method, r.RequestURI, appID)

	buDID, err := did.ParseDID(buID)
	if err != nil {
		logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, http.StatusBadRequest, err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	req := business_unit.RevokeAuthenticationRequest{}
	req.Requester = r.URL.Query().Get("requester")
	req.ApplicationID = appID
	req.BusinessUnitID = *buDID
	req.AuthenticationID = authenticationID

	result, err := a.buMgr.RevokeAuthentication(ctx, time.Now().Unix(), req)
	if errors.Is(err, model.ErrInvalidParameter) || errors.Is(err, model.ErrBusinessUnitNotFound) || errors.Is(err, model.ErrAuthenticationNotFound) {
		logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, http.StatusBadRequest, err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		logrus.Errorf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, http.StatusInternalServerError, err.Error())
		http.Error(w, fmt.Sprintf("Internal server error: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		logrus.Warnf("revokeBusinessUnitAuthentication failed to encode/write response: %v", err)
	}
}
