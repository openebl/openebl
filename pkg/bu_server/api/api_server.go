package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/openebl/openebl/pkg/bu_server/auth"
	"github.com/openebl/openebl/pkg/bu_server/business_unit"
	"github.com/openebl/openebl/pkg/bu_server/middleware"
	"github.com/openebl/openebl/pkg/bu_server/storage/postgres"
	"github.com/openebl/openebl/pkg/util"
	"github.com/sirupsen/logrus"
)

type APIConfig struct {
	Database     util.PostgresDatabaseConfig `yaml:"database"`
	LocalAddress string                      `yaml:"local_address"`
}

type API struct {
	appMgr     auth.ApplicationManager
	apiKeyMgr  auth.APIKeyAuthenticator
	buMgr      business_unit.BusinessUnitManager
	httpServer *http.Server
}

func NewAPIWithConfig(cfg APIConfig) (*API, error) {
	storage, err := postgres.NewStorageWithConfig(cfg.Database)
	if err != nil {
		logrus.Errorf("failed to create storage: %v", err)
		return nil, err
	}

	appMgr := auth.NewApplicationManager(storage)
	apiKeyMgr := auth.NewAPIKeyAuthenticator(storage)
	api, err := NewAPIWithController(appMgr, apiKeyMgr, cfg)
	if err != nil {
		return nil, err
	}

	return api, nil
}

func NewAPIWithController(appMgr auth.ApplicationManager, apiKeyMgr auth.APIKeyAuthenticator, config APIConfig) (*API, error) {
	apiServer := &API{
		appMgr:    appMgr,
		apiKeyMgr: apiKeyMgr,
	}

	r := mux.NewRouter()
	r.Use(middleware.NewAPIKeyAuth(apiServer.apiKeyMgr).Authenticate)
	r.HandleFunc("/business_unit", apiServer.createBusinessUnit).Methods(http.MethodPost)
	r.HandleFunc("/business_unit", apiServer.listBusinessUnit).Methods(http.MethodGet)
	r.HandleFunc("/business_unit/{id}", apiServer.getBusinessUnit).Methods(http.MethodGet)
	r.HandleFunc("/business_unit/{id}", apiServer.updateBusinessUnit).Methods(http.MethodPost)
	r.HandleFunc("/business_unit/{id}/status", apiServer.setBusinessUnitStatus).Methods(http.MethodPost)
	r.HandleFunc("/business_unit/{id}/authentication", apiServer.createBusinessUnitAuthentication).Methods(http.MethodPost)
	r.HandleFunc("/business_unit/{id}/authentication", apiServer.listBusinessUnitAuthentication).Methods(http.MethodGet)
	r.HandleFunc("/business_unit/{id}/authentication/{authentication_id}", apiServer.getBusinessUnitAuthentication).Methods(http.MethodGet)
	r.HandleFunc("/business_unit/{id}/authentication/{authentication_id}", apiServer.revokeBusinessUnitAuthentication).Methods(http.MethodDelete)

	apiServer.httpServer = &http.Server{
		Addr:    config.LocalAddress,
		Handler: r,
	}
	return apiServer, nil
}

func (a *API) Run() error {
	err := a.httpServer.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
func (a *API) Close() error {
	return a.httpServer.Close()
}

func (a *API) createBusinessUnit(w http.ResponseWriter, r *http.Request) {
	appID, _ := r.Context().Value(middleware.APPLICATION_ID).(string)

	// Parse the request body
	var req business_unit.CreateBusinessUnitRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.ApplicationID = appID
}

func (a *API) listBusinessUnit(w http.ResponseWriter, r *http.Request) {
	appID, _ := r.Context().Value(middleware.APPLICATION_ID).(string)
	_ = appID
}

func (a *API) getBusinessUnit(w http.ResponseWriter, r *http.Request) {
	appID, _ := r.Context().Value(middleware.APPLICATION_ID).(string)
	_ = appID
}

func (a *API) updateBusinessUnit(w http.ResponseWriter, r *http.Request) {
	appID, _ := r.Context().Value(middleware.APPLICATION_ID).(string)
	_ = appID
}

func (a *API) setBusinessUnitStatus(w http.ResponseWriter, r *http.Request) {
	appID, _ := r.Context().Value(middleware.APPLICATION_ID).(string)
	_ = appID
}

func (a *API) createBusinessUnitAuthentication(w http.ResponseWriter, r *http.Request) {
	appID, _ := r.Context().Value(middleware.APPLICATION_ID).(string)
	_ = appID
}

func (a *API) listBusinessUnitAuthentication(w http.ResponseWriter, r *http.Request) {
	appID, _ := r.Context().Value(middleware.APPLICATION_ID).(string)
	_ = appID
}

func (a *API) getBusinessUnitAuthentication(w http.ResponseWriter, r *http.Request) {
	appID, _ := r.Context().Value(middleware.APPLICATION_ID).(string)
	_ = appID
}

func (a *API) revokeBusinessUnitAuthentication(w http.ResponseWriter, r *http.Request) {
	appID, _ := r.Context().Value(middleware.APPLICATION_ID).(string)
	_ = appID
}
