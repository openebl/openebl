package api

import (
	"bytes"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/goccy/go-json"
	"github.com/gorilla/mux"
	"github.com/openebl/openebl/pkg/bu_server/middleware"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/trade_document"
	"github.com/openebl/openebl/pkg/util"
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

	simplifiedReq := req
	simplifiedReq.File.Content = nil
	logrus.Debugf("%s %s is invoked with application: %v, request: %v", r.Method, r.RequestURI, appID, util.StructToJSON(simplifiedReq))

	ts := time.Now().Unix()
	result, err := a.fileEBLCtrl.Create(ctx, ts, req)
	if err != nil {
		errCode := model.ErrorToHttpStatus(err)
		if errCode/100 == 5 {
			logrus.Errorf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, errCode, err.Error())
		} else {
			logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, errCode, err.Error())
		}
		http.Error(w, err.Error(), errCode)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		logrus.Warnf("createFileBasedEBL failed to encode/write response: %v", err)
	}
}

func (a *API) updateFileBasedEBL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	appID, _ := ctx.Value(middleware.APPLICATION_ID).(string)
	buID, _ := ctx.Value(middleware.BUSINESS_UNIT_ID).(string)
	docID := mux.Vars(r)["id"]

	var req trade_document.UpdateFileBasedEBLDraftRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, http.StatusBadRequest, err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.Application = appID
	req.Issuer = buID
	req.ID = docID

	simplifiedReq := req
	simplifiedReq.File.Content = nil
	logrus.Debugf("%s %s is invoked with application: %v, request: %v", r.Method, r.RequestURI, appID, util.StructToJSON(simplifiedReq))

	ts := time.Now().Unix()
	result, err := a.fileEBLCtrl.UpdateDraft(ctx, ts, req)
	if err != nil {
		errCode := model.ErrorToHttpStatus(err)
		if errCode/100 == 5 {
			logrus.Errorf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, errCode, err.Error())
		} else {
			logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, errCode, err.Error())
		}
		http.Error(w, err.Error(), errCode)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		logrus.Warnf("updateFileBasedEBL failed to encode/write response: %v", err)
	}
}

func (a *API) listFileBasedEBL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	appID, _ := ctx.Value(middleware.APPLICATION_ID).(string)
	buID, _ := ctx.Value(middleware.BUSINESS_UNIT_ID).(string)

	logrus.Debugf("%s %s is invoked with application: %v", r.Method, r.RequestURI, appID)

	var req trade_document.ListFileBasedEBLRequest
	req.RequestBy = buID
	req.Application = appID
	req.Limit = 20
	req.Status = r.URL.Query().Get("status")
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
	reportStr := r.URL.Query().Get("report")
	if reportStr != "" {
		report, err := strconv.ParseBool(strings.ToLower(reportStr))
		if err != nil {
			logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, http.StatusBadRequest, err.Error())
			http.Error(w, "report is invalid", http.StatusBadRequest)
			return
		}
		req.Report = report
	}

	result, err := a.fileEBLCtrl.List(ctx, req)
	if err != nil {
		errCode := model.ErrorToHttpStatus(err)
		if errCode/100 == 5 {
			logrus.Errorf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, errCode, err.Error())
		} else {
			logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, errCode, err.Error())
		}
		http.Error(w, err.Error(), errCode)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		logrus.Warnf("listFileBasedEBL failed to encode/write response: %v", err)
	}
}

func (a *API) getFileBasedEBL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	appID, _ := ctx.Value(middleware.APPLICATION_ID).(string)
	buID, _ := ctx.Value(middleware.BUSINESS_UNIT_ID).(string)
	docID := mux.Vars(r)["id"]

	logrus.Debugf("%s %s is invoked with application: %v", r.Method, r.RequestURI, appID)

	var req trade_document.GetFileBasedEBLRequest
	req.Requester = buID
	req.Application = appID
	req.ID = docID

	result, err := a.fileEBLCtrl.Get(ctx, req)
	if err != nil {
		errCode := model.ErrorToHttpStatus(err)
		if errCode/100 == 5 {
			logrus.Errorf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, errCode, err.Error())
		} else {
			logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, errCode, err.Error())
		}
		http.Error(w, err.Error(), errCode)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		logrus.Warnf("getFileBasedEBL failed to encode/write response: %v", err)
	}
}

func (a *API) transferEBL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	appID, _ := ctx.Value(middleware.APPLICATION_ID).(string)
	buID, _ := ctx.Value(middleware.BUSINESS_UNIT_ID).(string)

	var req trade_document.TransferEBLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.Application = appID
	req.TransferBy = buID
	req.ID = mux.Vars(r)["id"]

	logrus.Debugf("%s %s is invoked with application: %v, request: %v", r.Method, r.RequestURI, appID, util.StructToJSON(req))

	ts := time.Now().Unix()
	result, err := a.fileEBLCtrl.Transfer(ctx, ts, req)
	if err != nil {
		errCode := model.ErrorToHttpStatus(err)
		if errCode/100 == 5 {
			logrus.Errorf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, errCode, err.Error())
		} else {
			logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, errCode, err.Error())
		}
		http.Error(w, err.Error(), errCode)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		logrus.Warnf("transferEBL failed to encode/write response: %v", err)
	}
}

func (a *API) returnEBL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	appID, _ := ctx.Value(middleware.APPLICATION_ID).(string)
	buID, _ := ctx.Value(middleware.BUSINESS_UNIT_ID).(string)

	var req trade_document.ReturnFileBasedEBLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.Application = appID
	req.BusinessUnit = buID
	req.ID = mux.Vars(r)["id"]

	logrus.Debugf("%s %s is invoked with application: %v, request: %v", r.Method, r.RequestURI, appID, util.StructToJSON(req))

	ts := time.Now().Unix()
	result, err := a.fileEBLCtrl.Return(ctx, ts, req)
	if err != nil {
		errCode := model.ErrorToHttpStatus(err)
		if errCode/100 == 5 {
			logrus.Errorf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, errCode, err.Error())
		} else {
			logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, errCode, err.Error())
		}
		http.Error(w, err.Error(), errCode)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		logrus.Warnf("returnEBL failed to encode/write response: %v", err)
	}
}

func (a *API) amendmentRequestEBL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	appID, _ := ctx.Value(middleware.APPLICATION_ID).(string)
	buID, _ := ctx.Value(middleware.BUSINESS_UNIT_ID).(string)

	var req trade_document.AmendmentRequestEBLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.Application = appID
	req.RequestBy = buID
	req.ID = mux.Vars(r)["id"]

	logrus.Debugf("%s %s is invoked with application: %v, request: %v", r.Method, r.RequestURI, appID, util.StructToJSON(req))

	ts := time.Now().Unix()
	result, err := a.fileEBLCtrl.AmendmentRequest(ctx, ts, req)
	if err != nil {
		errCode := model.ErrorToHttpStatus(err)
		if errCode/100 == 5 {
			logrus.Errorf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, errCode, err.Error())
		} else {
			logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, errCode, err.Error())
		}
		http.Error(w, err.Error(), errCode)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		logrus.Warnf("amendmentRequestEBL failed to encode/write response: %v", err)
	}
}

func (a *API) amendFileBasedEBL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	appID, _ := ctx.Value(middleware.APPLICATION_ID).(string)
	buID, _ := ctx.Value(middleware.BUSINESS_UNIT_ID).(string)

	var req trade_document.AmendFileBasedEBLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.Application = appID
	req.Issuer = buID
	req.ID = mux.Vars(r)["id"]

	simplifiedReq := req
	simplifiedReq.File.Content = nil
	logrus.Debugf("%s %s is invoked with application: %v, request: %v", r.Method, r.RequestURI, appID, util.StructToJSON(simplifiedReq))

	ts := time.Now().Unix()
	result, err := a.fileEBLCtrl.Amend(ctx, ts, req)
	if err != nil {
		errCode := model.ErrorToHttpStatus(err)
		if errCode/100 == 5 {
			logrus.Errorf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, errCode, err.Error())
		} else {
			logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, errCode, err.Error())
		}
		http.Error(w, err.Error(), errCode)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		logrus.Warnf("amendFileBasedEBL failed to encode/write response: %v", err)
	}
}

func (a *API) surrenderEBL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	appID, _ := ctx.Value(middleware.APPLICATION_ID).(string)
	buID, _ := ctx.Value(middleware.BUSINESS_UNIT_ID).(string)

	var req trade_document.SurrenderEBLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.Application = appID
	req.RequestBy = buID
	req.ID = mux.Vars(r)["id"]

	logrus.Debugf("%s %s is invoked with application: %v, request: %v", r.Method, r.RequestURI, appID, util.StructToJSON(req))

	ts := time.Now().Unix()
	result, err := a.fileEBLCtrl.Surrender(ctx, ts, req)
	if err != nil {
		errCode := model.ErrorToHttpStatus(err)
		if errCode/100 == 5 {
			logrus.Errorf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, errCode, err.Error())
		} else {
			logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, errCode, err.Error())
		}
		http.Error(w, err.Error(), errCode)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		logrus.Warnf("surrenderEBL failed to encode/write response: %v", err)
	}
}

func (a *API) printEBLToPaper(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	appID, _ := ctx.Value(middleware.APPLICATION_ID).(string)
	buID, _ := ctx.Value(middleware.BUSINESS_UNIT_ID).(string)

	var req trade_document.PrintFileBasedEBLToPaperRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.Application = appID
	req.RequestBy = buID
	req.ID = mux.Vars(r)["id"]

	logrus.Debugf("%s %s is invoked with application: %v, request: %v", r.Method, r.RequestURI, appID, util.StructToJSON(req))

	ts := time.Now().Unix()
	result, err := a.fileEBLCtrl.PrintToPaper(ctx, ts, req)
	if err != nil {
		errCode := model.ErrorToHttpStatus(err)
		if errCode/100 == 5 {
			logrus.Errorf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, errCode, err.Error())
		} else {
			logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, errCode, err.Error())
		}
		http.Error(w, err.Error(), errCode)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		logrus.Warnf("printEBLToPaper failed to encode/write response: %v", err)
	}
}

func (a *API) accomplishEBL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	appID, _ := ctx.Value(middleware.APPLICATION_ID).(string)
	buID, _ := ctx.Value(middleware.BUSINESS_UNIT_ID).(string)

	var req trade_document.AccomplishEBLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.Application = appID
	req.RequestBy = buID
	req.ID = mux.Vars(r)["id"]

	logrus.Debugf("%s %s is invoked with application: %v, request: %v", r.Method, r.RequestURI, appID, util.StructToJSON(req))

	ts := time.Now().Unix()
	result, err := a.fileEBLCtrl.Accomplish(ctx, ts, req)
	if err != nil {
		errCode := model.ErrorToHttpStatus(err)
		if errCode/100 == 5 {
			logrus.Errorf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, errCode, err.Error())
		} else {
			logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, errCode, err.Error())
		}
		http.Error(w, err.Error(), errCode)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		logrus.Warnf("accomplishEBL failed to encode/write response: %v", err)
	}
}

func (a *API) deleteEBL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	appID, _ := ctx.Value(middleware.APPLICATION_ID).(string)
	buID, _ := ctx.Value(middleware.BUSINESS_UNIT_ID).(string)

	var req trade_document.DeleteEBLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.Application = appID
	req.RequestBy = buID
	req.ID = mux.Vars(r)["id"]

	logrus.Debugf("%s %s is invoked with application: %v, request: %v", r.Method, r.RequestURI, appID, util.StructToJSON(req))

	ts := time.Now().Unix()
	result, err := a.fileEBLCtrl.Delete(ctx, ts, req)
	if err != nil {
		errCode := model.ErrorToHttpStatus(err)
		if errCode/100 == 5 {
			logrus.Errorf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, errCode, err.Error())
		} else {
			logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, errCode, err.Error())
		}
		http.Error(w, err.Error(), errCode)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		logrus.Warnf("deleteEBL failed to encode/write response: %v", err)
	}
}

func (a *API) getFileBasedEBLDocument(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	appID, _ := ctx.Value(middleware.APPLICATION_ID).(string)
	buID, _ := ctx.Value(middleware.BUSINESS_UNIT_ID).(string)
	docID := mux.Vars(r)["id"]

	var req trade_document.GetFileBasedEBLRequest
	req.Requester = buID
	req.Application = appID
	req.ID = docID

	logrus.Debugf("%s %s is invoked with application: %v, request: %v", r.Method, r.RequestURI, appID, util.StructToJSON(req))

	file, err := a.fileEBLCtrl.GetDocument(ctx, req)
	if err != nil {
		errCode := model.ErrorToHttpStatus(err)
		if errCode/100 == 5 {
			logrus.Errorf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, errCode, err.Error())
		} else {
			logrus.Debugf("%s %s returns status code %d with error: %v", r.Method, r.RequestURI, errCode, err.Error())
		}
		http.Error(w, err.Error(), errCode)
		return
	}

	mimeType := http.DetectContentType(file.Content)
	fileSize := len(file.Content)
	w.Header().Set("Content-Type", mimeType)
	w.Header().Set("Content-Disposition", "attachment; filename="+file.Name)
	w.Header().Set("Content-Length", strconv.Itoa(fileSize))
	w.WriteHeader(http.StatusOK)
	http.ServeContent(w, r, file.Name, time.Now(), bytes.NewReader(file.Content))
}
