package api

import (
	"net/http"
	"time"

	"github.com/goccy/go-json"
	"github.com/openebl/openebl/pkg/bu_server/middleware"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/trade_document"
	"github.com/sirupsen/logrus"
)

func (a *API) createFileBasedEBL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	appID, _ := ctx.Value(middleware.APPLICATION_ID).(string)
	buID, _ := ctx.Value(middleware.BUSINESS_UNIT_ID).(string)

	var req trade_document.IssueFileBasedEBLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.Application = appID
	req.Issuer = buID

	ts := time.Now().Unix()
	result, err := a.fileEBLCtrl.Create(ctx, ts, req)
	if err != nil {
		http.Error(w, err.Error(), model.ErrorToHttpStatus(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		logrus.Warnf("createFileBasedEBL failed to encode/write response: %v", err)
	}
}
