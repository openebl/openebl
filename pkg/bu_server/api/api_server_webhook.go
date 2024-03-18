package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/openebl/openebl/pkg/bu_server/middleware"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/webhook"
	"github.com/sirupsen/logrus"
)

func (a *API) createWebhook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	appID, _ := ctx.Value(middleware.APPLICATION_ID).(string)

	var req webhook.CreateWebhookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.ApplicationID = appID

	ts := time.Now().Unix()
	result, err := a.webhookCtrl.Create(ctx, ts, req)
	if err != nil {
		http.Error(w, err.Error(), model.ErrorToHttpStatus(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		logrus.Warnf("createWebhook failed to encode/write response: %v", err)
	}
}

func (a *API) listWebhook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	appID, _ := ctx.Value(middleware.APPLICATION_ID).(string)

	var req webhook.ListWebhookRequest
	req.ApplicationID = appID
	req.Limit = 20

	offsetStr := r.URL.Query().Get("offset")
	if offsetStr != "" {
		offset, err := strconv.ParseInt(offsetStr, 10, 32)
		if err != nil || offset < 0 {
			http.Error(w, "offset is invalid", http.StatusBadRequest)
			return
		}
		req.Offset = int(offset)
	}
	limitStr := r.URL.Query().Get("limit")
	if limitStr != "" {
		limit, err := strconv.ParseInt(limitStr, 10, 32)
		if err != nil || limit < 1 {
			http.Error(w, "limit is invalid", http.StatusBadRequest)
			return
		}
		req.Limit = int(limit)
	}

	res, err := a.webhookCtrl.List(ctx, req)
	if err != nil {
		http.Error(w, err.Error(), model.ErrorToHttpStatus(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(res); err != nil {
		logrus.Warnf("listWebhook failed to encode/write response: %v", err)
	}
}

func (a *API) getWebhook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	appID, _ := ctx.Value(middleware.APPLICATION_ID).(string)
	webhookID := mux.Vars(r)["id"]

	res, err := a.webhookCtrl.Get(ctx, appID, webhookID)
	if err != nil {
		http.Error(w, err.Error(), model.ErrorToHttpStatus(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(res); err != nil {
		logrus.Warnf("getWebhook failed to encode/write response: %v", err)
	}
}
