package manager

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/openebl/openebl/pkg/bu_server/auth"
	"github.com/openebl/openebl/pkg/bu_server/middleware"
	"github.com/openebl/openebl/pkg/bu_server/storage/postgres"
	"github.com/openebl/openebl/pkg/util"
	"github.com/sirupsen/logrus"
)

type ManagerAPIConfig struct {
	Database     util.PostgresDatabaseConfig `yaml:"database"`
	LocalAddress string                      `yaml:"local_address"`
}

type ManagerAPI struct {
	userMgr   auth.UserManager
	appMgr    auth.ApplicationManager
	apiKeyMgr auth.APIKeyAuthenticator
}

func NewManagerAPI(cfg ManagerAPIConfig) (*ManagerAPI, error) {
	apiServer := &ManagerAPI{}

	storage, err := postgres.NewStorageWithConfig(cfg.Database)
	if err != nil {
		logrus.Errorf("failed to create storage: %v", err)
		return nil, err
	}

	apiServer.userMgr = auth.NewUserManager(storage)
	userTokenMiddleware := middleware.NewUserTokenAuth(apiServer.userMgr)
	apiServer.appMgr = auth.NewApplicationManager(storage)
	apiServer.apiKeyMgr = auth.NewAPIKeyAuthenticator(storage)

	r := mux.NewRouter()
	loginRouter := r.NewRoute().Subrouter()
	loginRouter.HandleFunc("/login", apiServer.login).Methods(http.MethodGet)

	mgrRouter := r.NewRoute().Subrouter()
	mgrRouter.Use(userTokenMiddleware.Authenticate)
	mgrRouter.HandleFunc("/user", apiServer.getUserList).Methods(http.MethodGet)
	mgrRouter.HandleFunc("/user", apiServer.createUser).Methods(http.MethodPost)
	mgrRouter.HandleFunc("/user/{id}", apiServer.getUser).Methods(http.MethodGet)
	mgrRouter.HandleFunc("/user/{id}", apiServer.updateUser).Methods(http.MethodPost)
	mgrRouter.HandleFunc("/user/{id}/status", apiServer.updateUserStatus).Methods(http.MethodPost)
	mgrRouter.HandleFunc("/application", apiServer.createApplication).Methods(http.MethodPost)
	mgrRouter.HandleFunc("/application", apiServer.getApplicationList).Methods(http.MethodGet)
	mgrRouter.HandleFunc("/application/{id}", apiServer.getApplication).Methods(http.MethodGet)
	mgrRouter.HandleFunc("/application/{id}", apiServer.updateApplication).Methods(http.MethodPost)
	mgrRouter.HandleFunc("/application/{id}/status", apiServer.updateApplicationStatus).Methods(http.MethodPost)
	mgrRouter.HandleFunc("/api_key", apiServer.createAPIKey).Methods(http.MethodPost)
	mgrRouter.HandleFunc("/api_key/{key_id}", apiServer.revokeAPIKey).Methods(http.MethodDelete)

	httpServer := &http.Server{
		Addr:         cfg.LocalAddress,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// go func() {
	// 	logrus.Infof("starting manager API server on %s", cfg.LocalAddress)
	// 	if err := httpServer.ListenAndServe(); err != nil {
	// 		logrus.Errorf("failed to start manager API server: %v", err)
	// 	}
	// }()

	err = httpServer.ListenAndServe()
	if err != nil {
		logrus.Errorf("failed to start manager API server: %v", err)
	}

	return apiServer, nil
}

func (s *ManagerAPI) Close() error {
	return nil
}

func (s *ManagerAPI) login(w http.ResponseWriter, r *http.Request) {
	extractBasicAuthCredentials := func(r *http.Request) (string, string, error) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			return "", "", errors.New("Authorization header is missing")
		}

		authParts := strings.SplitN(authHeader, " ", 2)
		if len(authParts) != 2 || authParts[0] != "Basic" {
			return "", "", errors.New("Invalid Authorization header")
		}

		// Decode the base64-encoded credentials
		decoded, err := base64.StdEncoding.DecodeString(authParts[1])
		if err != nil {
			return "", "", fmt.Errorf("Failed to decode credentials: %w", err)
		}

		// Split the decoded credentials into username and password
		credentials := strings.SplitN(string(decoded), ":", 2)
		if len(credentials) != 2 {
			return "", "", errors.New("Invalid credentials format")
		}

		return credentials[0], credentials[1], nil
	}

	username, password, err := extractBasicAuthCredentials(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	req := auth.AuthenticateUserRequest{
		UserID:   username,
		Password: auth.RawPassword(password),
	}
	userToken, err := s.userMgr.Authenticate(r.Context(), time.Now().Unix(), req)
	if errors.Is(err, auth.ErrUserError) {
		logrus.Warnf("failed to authenticate user %q: %v", username, err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(userToken.Token))
}

func (s *ManagerAPI) createUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userToken, _ := r.Context().Value(middleware.USER_TOKEN).(auth.UserToken)

	// Parse the request body
	var req auth.CreateUserRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.RequestUser = userToken.UserID

	// Create the user
	user, err := s.userMgr.CreateUser(ctx, time.Now().Unix(), req)
	if errors.Is(err, auth.ErrUserAlreadyExists) {
		logrus.Warnf("failed to create user %q: %v", req.UserID, err)
		http.Error(w, err.Error(), http.StatusConflict)
		return
	} else if errors.Is(err, auth.ErrInvalidParameter) {
		logrus.Warnf("failed to create user %q: %v", req.UserID, err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else if err != nil {
		logrus.Errorf("failed to create user %q: %v", req.UserID, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return the created user to the client
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user)
}

func (s *ManagerAPI) getUserList(w http.ResponseWriter, r *http.Request) {
	listReq := auth.ListUserRequest{
		Offset: 0,
		Limit:  10,
	}

	offsetStr := r.URL.Query().Get("offset")
	limitStr := r.URL.Query().Get("limit")
	if offsetStr != "" {
		offset, err := strconv.ParseInt(offsetStr, 10, 32)
		if err != nil || offset < 0 {
			http.Error(w, "offset is invalid", http.StatusBadRequest)
			return
		}
		listReq.Offset = int(offset)
	}
	if limitStr != "" {
		limit, err := strconv.ParseInt(limitStr, 10, 32)
		if err != nil || limit < 1 {
			http.Error(w, "limit is invalid", http.StatusBadRequest)
			return
		}
		listReq.Limit = int(limit)
	}

	result, err := s.userMgr.ListUsers(r.Context(), listReq)
	if err != nil {
		logrus.Errorf("failed to list users: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

func (s *ManagerAPI) getUser(w http.ResponseWriter, r *http.Request) {
	userID := mux.Vars(r)["id"]

	listReq := auth.ListUserRequest{
		Limit: 1,
		IDs:   []string{userID},
	}
	reuslt, err := s.userMgr.ListUsers(r.Context(), listReq)
	if err != nil {
		logrus.Errorf("failed to get user %q: %v", userID, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if len(reuslt.Users) == 0 {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(reuslt.Users[0])
}

func (s *ManagerAPI) updateUser(w http.ResponseWriter, r *http.Request) {
	userToken, _ := r.Context().Value(middleware.USER_TOKEN).(auth.UserToken)
	userID := mux.Vars(r)["id"]
	updateRequest := auth.UpdateUserRequest{}
	if err := json.NewDecoder(r.Body).Decode(&updateRequest); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	updateRequest.RequestUser = userToken.UserID
	updateRequest.UserID = userID

	newUser, err := s.userMgr.UpdateUser(r.Context(), time.Now().Unix(), updateRequest)
	if errors.Is(err, auth.ErrUserNotFound) {
		logrus.Warnf("failed to update user %q: %v", userID, err)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if err != nil {
		logrus.Errorf("failed to update user %q: %v", userID, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(newUser)
}

func (s *ManagerAPI) updateUserStatus(w http.ResponseWriter, r *http.Request) {
	userToken, _ := r.Context().Value(middleware.USER_TOKEN).(auth.UserToken)
	userID := mux.Vars(r)["id"]

	type _Request struct {
		Status string `json:"status"`
	}

	request := _Request{}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	updateRequest := auth.ActivateUserRequest{}
	updateRequest.RequestUser = userToken.UserID
	updateRequest.UserID = userID
	var err error
	var newUser auth.User
	if request.Status == "active" {
		newUser, err = s.userMgr.ActivateUser(r.Context(), time.Now().Unix(), updateRequest)
	} else if request.Status == "inactive" {
		newUser, err = s.userMgr.DeactivateUser(r.Context(), time.Now().Unix(), updateRequest)
	} else {
		http.Error(w, "invalid status", http.StatusBadRequest)
		return
	}
	if errors.Is(err, auth.ErrUserNotFound) {
		logrus.Warnf("failed to update user %q: %v", userID, err)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	} else if err != nil {
		logrus.Errorf("failed to update user %q: %v", userID, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(newUser)
}

func (s *ManagerAPI) createApplication(w http.ResponseWriter, r *http.Request) {
	userToken, _ := r.Context().Value(middleware.USER_TOKEN).(auth.UserToken)

	var req auth.CreateApplicationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.User = userToken.UserID

	app, err := s.appMgr.CreateApplication(r.Context(), time.Now().Unix(), req)
	if errors.Is(err, auth.ErrInvalidParameter) {
		logrus.Warnf("failed to create application %q: %v", req.Name, err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else if err != nil {
		logrus.Errorf("failed to create application %q: %v", req.Name, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(app)
}

func (s *ManagerAPI) getApplicationList(w http.ResponseWriter, r *http.Request) {
	listRequest := auth.ListApplicationRequest{
		Limit: 10,
	}

	// Get the offset and limit from the query parameters
	offsetStr := r.URL.Query().Get("offset")
	limitStr := r.URL.Query().Get("limit")

	if offsetStr != "" {
		// Convert offset and limit to integers
		offset, err := strconv.Atoi(offsetStr)
		if err != nil || offset < 0 {
			http.Error(w, "offset is invalid", http.StatusBadRequest)
			return
		}
		listRequest.Offset = offset
	}
	if limitStr != "" {
		limit, err := strconv.Atoi(limitStr)
		if err != nil || limit < 1 {
			http.Error(w, "limit is invalid", http.StatusBadRequest)
			return
		}
		listRequest.Limit = limit
	}

	result, err := s.appMgr.ListApplications(r.Context(), listRequest)
	if err != nil {
		logrus.Errorf("failed to list applications: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

func (s *ManagerAPI) getApplication(w http.ResponseWriter, r *http.Request) {
	appID := mux.Vars(r)["id"]

	listRequest := auth.ListApplicationRequest{
		Limit: 1,
		IDs:   []string{appID},
	}
	result, err := s.appMgr.ListApplications(r.Context(), listRequest)
	if err != nil {
		logrus.Errorf("failed to get application %q: %v", appID, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if len(result.Applications) == 0 {
		http.Error(w, "application not found", http.StatusNotFound)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result.Applications[0])
}

func (s *ManagerAPI) updateApplication(w http.ResponseWriter, r *http.Request) {
	userToken, _ := r.Context().Value(middleware.USER_TOKEN).(auth.UserToken)
	appID := mux.Vars(r)["id"]

	updateRequest := auth.UpdateApplicationRequest{}
	if err := json.NewDecoder(r.Body).Decode(&updateRequest); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	updateRequest.ID = appID
	updateRequest.RequestUser.User = userToken.UserID

	newApp, err := s.appMgr.UpdateApplication(r.Context(), time.Now().Unix(), updateRequest)
	if errors.Is(err, auth.ErrInvalidParameter) {
		logrus.Warnf("failed to update application %q: %v", appID, err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if errors.Is(err, auth.ErrApplicationNotFound) {
		logrus.Warnf("failed to update application %q: %v", appID, err)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if err != nil {
		logrus.Errorf("failed to update application %q: %v", appID, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(newApp)
}

func (s *ManagerAPI) updateApplicationStatus(w http.ResponseWriter, r *http.Request) {
	userToken, _ := r.Context().Value(middleware.USER_TOKEN).(auth.UserToken)
	appID := mux.Vars(r)["id"]

	type _Request struct {
		Status string `json:"status"`
	}

	request := _Request{}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if request.Status != string(auth.ApplicationStatusActive) && request.Status != string(auth.ApplicationStatusInactive) {
		http.Error(w, "invalid status", http.StatusBadRequest)
		return
	}

	updateRequest := auth.ActivateApplicationRequest{
		RequestUser: auth.RequestUser{
			User: userToken.UserID,
		},
		ApplicationID: appID,
	}

	var newApp auth.Application
	var err error
	if request.Status == string(auth.ApplicationStatusActive) {
		newApp, err = s.appMgr.ActivateApplication(r.Context(), time.Now().Unix(), updateRequest)
	} else {
		newApp, err = s.appMgr.DeactivateApplication(r.Context(), time.Now().Unix(), auth.DeactivateApplicationRequest(updateRequest))
	}
	if errors.Is(err, auth.ErrInvalidParameter) {
		logrus.Warnf("failed to update application %q: %v", appID, err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else if errors.Is(err, auth.ErrApplicationNotFound) {
		logrus.Warnf("failed to update application %q: %v", appID, err)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(newApp)
}

func (s *ManagerAPI) createAPIKey(w http.ResponseWriter, r *http.Request) {
	userToken, _ := r.Context().Value(middleware.USER_TOKEN).(auth.UserToken)

	request := auth.CreateAPIKeyRequest{}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	request.RequestUser = auth.RequestUser{
		User: userToken.UserID,
	}

	_, apiKeyString, err := s.apiKeyMgr.CreateAPIKey(r.Context(), time.Now().Unix(), request)
	if errors.Is(err, auth.ErrInvalidParameter) || errors.Is(err, auth.ErrApplicationNotFound) {
		logrus.Warnf("failed to create API key: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else if err != nil {
		logrus.Errorf("failed to create API key: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(apiKeyString))
}

func (s *ManagerAPI) revokeAPIKey(w http.ResponseWriter, r *http.Request) {
	userToken, _ := r.Context().Value(middleware.USER_TOKEN).(auth.UserToken)
	apiKeyID := mux.Vars(r)["key_id"]

	request := auth.RevokeAPIKeyRequest{
		ID: apiKeyID,
		RequestUser: auth.RequestUser{
			User: userToken.UserID,
		},
	}

	err := s.apiKeyMgr.RevokeAPIKey(r.Context(), time.Now().Unix(), request)
	if errors.Is(err, auth.ErrInvalidParameter) {
		logrus.Warnf("failed to revoke API key %q: %v", apiKeyID, err)
		http.Error(w, err.Error(), http.StatusBadRequest)
	} else if err != nil {
		logrus.Errorf("failed to revoke API key %q: %v", apiKeyID, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
