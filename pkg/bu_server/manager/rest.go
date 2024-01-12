package manager

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
	mgrRouter.HandleFunc("/user", apiServer.getUserList).Methods(http.MethodGet).Queries()
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
	} else if err != nil {
		logrus.Errorf("failed to create user %q: %v", req.UserID, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return the created user to the client
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user)
}

func (s *ManagerAPI) getUserList(http.ResponseWriter, *http.Request) {
}

func (s *ManagerAPI) getUser(http.ResponseWriter, *http.Request) {

}

func (s *ManagerAPI) updateUser(http.ResponseWriter, *http.Request) {

}

func (s *ManagerAPI) updateUserStatus(http.ResponseWriter, *http.Request) {

}

func (s *ManagerAPI) createApplication(http.ResponseWriter, *http.Request) {

}

func (s *ManagerAPI) getApplicationList(http.ResponseWriter, *http.Request) {

}

func (s *ManagerAPI) getApplication(http.ResponseWriter, *http.Request) {

}

func (s *ManagerAPI) updateApplication(http.ResponseWriter, *http.Request) {

}

func (s *ManagerAPI) updateApplicationStatus(http.ResponseWriter, *http.Request) {

}

func (s *ManagerAPI) createAPIKey(http.ResponseWriter, *http.Request) {

}

func (s *ManagerAPI) revokeAPIKey(http.ResponseWriter, *http.Request) {

}
