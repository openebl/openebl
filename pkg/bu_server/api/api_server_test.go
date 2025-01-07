package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/openebl/openebl/pkg/bu_server/api"
	"github.com/openebl/openebl/pkg/bu_server/auth"
	"github.com/openebl/openebl/pkg/bu_server/business_unit"
	"github.com/openebl/openebl/pkg/bu_server/middleware"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/model/trade_document/bill_of_lading"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/bu_server/trade_document"
	"github.com/openebl/openebl/pkg/bu_server/webhook"
	"github.com/openebl/openebl/pkg/did"
	"github.com/openebl/openebl/pkg/util"
	mock_auth "github.com/openebl/openebl/test/mock/bu_server/auth"
	mock_business_unit "github.com/openebl/openebl/test/mock/bu_server/business_unit"
	mock_trade_document "github.com/openebl/openebl/test/mock/bu_server/trade_document"
	mock_webhook "github.com/openebl/openebl/test/mock/bu_server/webhook"
	"github.com/samber/lo"
	"github.com/stretchr/testify/suite"
)

type APITestSuite struct {
	suite.Suite

	ctx         context.Context
	ctrl        *gomock.Controller
	apiKeyMgr   *mock_auth.MockAPIKeyAuthenticator
	buMgr       *mock_business_unit.MockBusinessUnitManager
	fileEBLCtrl *mock_trade_document.MockFileBaseEBLController
	webhookCtrl *mock_webhook.MockWebhookController

	basePortNumber int32
	localAddress   string
	api            *api.API

	appId        string
	apiKeyString auth.APIKeyString
	apiKey       auth.APIKey
}

func TestAPITestSuite(t *testing.T) {
	suite.Run(t, new(APITestSuite))
}

func (s *APITestSuite) SetupSuite() {
	s.basePortNumber = 9200
}

func (s *APITestSuite) SetupTest() {
	s.ctx = context.Background()
	s.ctrl = gomock.NewController(s.T())
	s.apiKeyMgr = mock_auth.NewMockAPIKeyAuthenticator(s.ctrl)
	s.buMgr = mock_business_unit.NewMockBusinessUnitManager(s.ctrl)
	s.fileEBLCtrl = mock_trade_document.NewMockFileBaseEBLController(s.ctrl)
	s.webhookCtrl = mock_webhook.NewMockWebhookController(s.ctrl)

	portNum := atomic.AddInt32(&s.basePortNumber, 1)
	s.localAddress = fmt.Sprintf("localhost:%d", portNum)
	api, err := api.NewAPIWithController(s.apiKeyMgr, s.buMgr, s.webhookCtrl, s.fileEBLCtrl, s.localAddress)
	s.Require().NoError(err)
	s.api = api
	go func() {
		s.api.Run()
	}()
	time.Sleep(100 * time.Millisecond)

	s.appId = "test-app-id"
	s.apiKeyString, _ = auth.NewAPIKeyString()
	apiKeyId, _ := s.apiKeyString.ID()
	s.apiKey = auth.APIKey{
		ID:            apiKeyId,
		ApplicationID: s.appId,
	}
}

func (s *APITestSuite) TearDownTest() {
	s.ctrl.Finish()
	s.api.Close(s.ctx)
}

func (s *APITestSuite) TestHealthCheck() {
	endPoint := fmt.Sprintf("http://%s/health", s.localAddress)
	httpRequest, _ := http.NewRequestWithContext(s.ctx, http.MethodGet, endPoint, nil)
	resp, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusOK, resp.StatusCode)
}

func (s *APITestSuite) TestCreateBusinessUnit() {
	request := business_unit.CreateBusinessUnitRequest{
		Requester:    "John Doe",
		Name:         "Business Unit 1",
		Addresses:    []string{"123 Main St", "456 Oak St"},
		Emails:       []string{"test1@example.com", "test2@example.com"},
		PhoneNumbers: []string{"123-456-7890", "098-765-4321"},
		Status:       model.BusinessUnitStatusActive, // Assuming model.BusinessUnitStatusActive is a valid status
	}

	expectedRequest := request
	expectedRequest.ApplicationID = s.appId

	bu := model.BusinessUnit{
		ID:     did.MustParse("did:openebl:1234567890"),
		Status: model.BusinessUnitStatusActive,
	}

	endPoint := fmt.Sprintf("http://%s/business_unit", s.localAddress)
	httpRequest, _ := http.NewRequestWithContext(s.ctx, http.MethodPost, endPoint, util.StructToJSONReader(request))
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Authorization", "Bearer "+string(s.apiKeyString))

	gomock.InOrder(
		s.apiKeyMgr.EXPECT().Authenticate(gomock.Any(), s.apiKeyString).Return(s.apiKey, nil),
		s.buMgr.EXPECT().CreateBusinessUnit(gomock.Any(), gomock.Any(), expectedRequest).Return(bu, nil),
	)

	// Test Normal Case.
	resp, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusCreated, resp.StatusCode)
	s.Require().Equal("application/json", resp.Header.Get("Content-Type"))
	body, _ := io.ReadAll(resp.Body)
	s.Assert().Equal(util.StructToJSON(bu), strings.TrimSpace(string(body)))
	// End of Test Normal Case.

	// Test with invalid credential.
	gomock.InOrder(
		s.apiKeyMgr.EXPECT().Authenticate(gomock.Any(), s.apiKeyString).Return(auth.APIKey{}, model.ErrMismatchAPIKey),
	)
	resp, err = http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusUnauthorized, resp.StatusCode)
}

func (s *APITestSuite) TestListBusinessUnit() {
	endPoint := fmt.Sprintf("http://%s/business_unit?offset=1&limit=2", s.localAddress)

	expectedRequest := storage.ListBusinessUnitsRequest{
		ApplicationID: s.appId,
		Offset:        1,
		Limit:         2,
	}

	result := storage.ListBusinessUnitsResult{
		Total: 10,
		Records: []storage.ListBusinessUnitsRecord{
			{
				BusinessUnit: model.BusinessUnit{
					ID: did.MustParse("did:openebl:1234567890"),
				},
				Authentications: []model.BusinessUnitAuthentication{
					{
						ID: "auth1",
					},
				},
			},
		},
	}

	gomock.InOrder(
		s.apiKeyMgr.EXPECT().Authenticate(gomock.Any(), s.apiKeyString).Return(s.apiKey, nil),
		s.buMgr.EXPECT().ListBusinessUnits(gomock.Any(), expectedRequest).Return(result, nil),
	)

	httpRequest, _ := http.NewRequestWithContext(s.ctx, http.MethodGet, endPoint, nil)
	httpRequest.Header.Set("Authorization", "Bearer "+string(s.apiKeyString))

	resp, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusOK, resp.StatusCode)
	s.Require().Equal("application/json", resp.Header.Get("Content-Type"))
	body, _ := io.ReadAll(resp.Body)
	s.Assert().Equal(util.StructToJSON(result), strings.TrimSpace(string(body)))
}

func (s *APITestSuite) TestGetBusinessUnit() {
	buId := "did:openebl:1234567890"
	endPoint := fmt.Sprintf("http://%s/business_unit/%s", s.localAddress, buId)

	expectedRequest := storage.ListBusinessUnitsRequest{
		ApplicationID:   s.appId,
		BusinessUnitIDs: []string{buId},
		Limit:           1,
	}

	result := storage.ListBusinessUnitsResult{
		Total: 10,
		Records: []storage.ListBusinessUnitsRecord{
			{
				BusinessUnit: model.BusinessUnit{
					ID: did.MustParse("did:openebl:1234567890"),
				},
				Authentications: []model.BusinessUnitAuthentication{
					{
						ID: "auth1",
					},
				},
			},
		},
	}

	gomock.InOrder(
		s.apiKeyMgr.EXPECT().Authenticate(gomock.Any(), s.apiKeyString).Return(s.apiKey, nil),
		s.buMgr.EXPECT().ListBusinessUnits(gomock.Any(), expectedRequest).Return(result, nil),
	)

	httpRequest, _ := http.NewRequestWithContext(s.ctx, http.MethodGet, endPoint, nil)
	httpRequest.Header.Set("Authorization", "Bearer "+string(s.apiKeyString))

	resp, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusOK, resp.StatusCode)
	s.Require().Equal("application/json", resp.Header.Get("Content-Type"))
	body, _ := io.ReadAll(resp.Body)
	s.Assert().Equal(util.StructToJSON(result.Records[0]), strings.TrimSpace(string(body)))
}

func (s *APITestSuite) TestUpdateBusinessUnit() {
	buId := "did:openebl:1234567890"
	endPoint := fmt.Sprintf("http://%s/business_unit/%s", s.localAddress, buId)

	request := business_unit.UpdateBusinessUnitRequest{
		Requester:    "requester",
		ID:           did.MustParse(buId),
		Name:         "name",
		Addresses:    []string{"address"},
		Emails:       []string{"email"},
		PhoneNumbers: []string{"phone number"},
	}

	expectedRequest := request
	expectedRequest.ApplicationID = s.appId

	newBu := model.BusinessUnit{
		ID: did.MustParse(buId),
	}

	gomock.InOrder(
		s.apiKeyMgr.EXPECT().Authenticate(gomock.Any(), s.apiKeyString).Return(s.apiKey, nil),
		s.buMgr.EXPECT().UpdateBusinessUnit(gomock.Any(), gomock.Any(), expectedRequest).Return(newBu, nil),
	)

	httpRequest, _ := http.NewRequestWithContext(s.ctx, http.MethodPost, endPoint, util.StructToJSONReader(request))
	httpRequest.Header.Set("Authorization", "Bearer "+string(s.apiKeyString))
	resp, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusOK, resp.StatusCode)
	s.Require().Equal("application/json", resp.Header.Get("Content-Type"))
	body, _ := io.ReadAll(resp.Body)
	s.Assert().Equal(util.StructToJSON(newBu), strings.TrimSpace(string(body)))
}

func (s *APITestSuite) TestSetStatus() {
	buId := "did:openebl:1234567890"
	endPoint := fmt.Sprintf("http://%s/business_unit/%s/status", s.localAddress, buId)

	request := business_unit.SetBusinessUnitStatusRequest{
		Requester: "requester",
		ID:        did.MustParse(buId),
		Status:    model.BusinessUnitStatusInactive,
	}

	expectedRequest := request
	expectedRequest.ApplicationID = s.appId

	newBu := model.BusinessUnit{
		ID:     did.MustParse(buId),
		Status: model.BusinessUnitStatusInactive,
	}

	gomock.InOrder(
		s.apiKeyMgr.EXPECT().Authenticate(gomock.Any(), s.apiKeyString).Return(s.apiKey, nil),
		s.buMgr.EXPECT().SetStatus(gomock.Any(), gomock.Any(), expectedRequest).Return(newBu, nil),
	)

	httpRequest, _ := http.NewRequestWithContext(s.ctx, http.MethodPost, endPoint, util.StructToJSONReader(request))
	httpRequest.Header.Set("Authorization", "Bearer "+string(s.apiKeyString))
	resp, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusOK, resp.StatusCode)
	s.Require().Equal("application/json", resp.Header.Get("Content-Type"))
	body, _ := io.ReadAll(resp.Body)
	s.Assert().Equal(util.StructToJSON(newBu), strings.TrimSpace(string(body)))
}

func (s *APITestSuite) TestCreateFileBasedEBL() {
	endPoint := fmt.Sprintf("http://%s/ebl", s.localAddress)

	req := trade_document.IssueFileBasedEBLRequest{
		MetaData:         bill_of_lading.ApplicationMetaData{"requester": json.RawMessage(`"application user"`)},
		AuthenticationID: "bu_auth_id",

		File: trade_document.File{
			Name:    "test.txt",
			Type:    "text/plain",
			Content: []byte("test content"),
		},
		BLNumber:  "bl_number",
		BLDocType: bill_of_lading.BillOfLadingDocumentTypeHouseBillOfLading,
		ToOrder:   false,
		POL: trade_document.Location{
			LocationName: "Port of Loading",
			UNLocCode:    "POL",
		},
		POD: trade_document.Location{
			LocationName: "Port of Discharge",
			UNLocCode:    "POD",
		},
		ETA:          lo.ToPtr(model.NewDateFromStringNoError("2024-02-26")),
		Shipper:      "shipper",
		Consignee:    "consignee",
		ReleaseAgent: "release agent",
		Note:         "note",
		Draft:        lo.ToPtr(true),
	}

	expectedRequest := req
	expectedRequest.Application = s.appId
	expectedRequest.Issuer = "issuer"

	newBillOfLadingPack := trade_document.FileBasedBillOfLadingRecord{
		BL: &bill_of_lading.BillOfLadingPack{
			ID:      "pack_id",
			Version: 1,
		},
	}

	httpRequest, err := http.NewRequest("POST", endPoint, util.StructToJSONReader(req))
	s.Require().NoError(err)
	httpRequest.Header.Set("Authorization", "Bearer "+string(s.apiKeyString))
	httpRequest.Header.Set(middleware.BUSINESS_UNIT_ID_HEADER, "issuer")

	gomock.InOrder(
		s.apiKeyMgr.EXPECT().Authenticate(gomock.Any(), s.apiKeyString).Return(s.apiKey, nil),
		s.fileEBLCtrl.EXPECT().Create(gomock.Any(), gomock.Any(), expectedRequest).Return(newBillOfLadingPack, nil),
	)

	httpResponse, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	returnedBody, _ := io.ReadAll(httpResponse.Body)
	s.Require().Equal(http.StatusCreated, httpResponse.StatusCode)
	s.Require().Equal("application/json", httpResponse.Header.Get("Content-Type"))
	s.Require().Equal(util.StructToJSON(newBillOfLadingPack), strings.TrimSpace(string(returnedBody)))
}

func (s *APITestSuite) TestUpdateFileBasedEBL() {
	endPoint := fmt.Sprintf("http://%s/ebl/doc_id/update", s.localAddress)

	req := trade_document.UpdateFileBasedEBLDraftRequest{
		IssueFileBasedEBLRequest: trade_document.IssueFileBasedEBLRequest{
			MetaData:         bill_of_lading.ApplicationMetaData{"requester": json.RawMessage(`12345`)},
			AuthenticationID: "bu_auth_id",
			File: trade_document.File{
				Name:    "test.txt",
				Type:    "text/plain",
				Content: []byte("test content"),
			},
			BLNumber:  "bl_number",
			BLDocType: bill_of_lading.BillOfLadingDocumentTypeHouseBillOfLading,
			ToOrder:   false,
			POL: trade_document.Location{
				LocationName: "Port of Loading",
				UNLocCode:    "POL",
			},
			POD: trade_document.Location{
				LocationName: "Port of Discharge",
				UNLocCode:    "POD",
			},
			ETA:          lo.ToPtr(model.NewDateFromStringNoError("2024-02-26")),
			Shipper:      "shipper",
			Consignee:    "consignee",
			ReleaseAgent: "release agent",
			Note:         "note",
			Draft:        lo.ToPtr(true),
		},
	}

	expectedRequest := req
	expectedRequest.Application = s.appId
	expectedRequest.Issuer = "issuer"
	expectedRequest.ID = "doc_id"

	newBillOfLadingPack := trade_document.FileBasedBillOfLadingRecord{
		BL: &bill_of_lading.BillOfLadingPack{
			ID:      "pack_id",
			Version: 1,
		},
	}

	httpRequest, err := http.NewRequest("POST", endPoint, util.StructToJSONReader(req))
	s.Require().NoError(err)
	httpRequest.Header.Set("Authorization", "Bearer "+string(s.apiKeyString))
	httpRequest.Header.Set(middleware.BUSINESS_UNIT_ID_HEADER, "issuer")

	gomock.InOrder(
		s.apiKeyMgr.EXPECT().Authenticate(gomock.Any(), s.apiKeyString).Return(s.apiKey, nil),
		s.fileEBLCtrl.EXPECT().UpdateDraft(gomock.Any(), gomock.Any(), expectedRequest).Return(newBillOfLadingPack, nil),
	)

	httpResponse, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	returnedBody, _ := io.ReadAll(httpResponse.Body)
	s.Require().Equal(http.StatusOK, httpResponse.StatusCode)
	s.Require().Equal("application/json", httpResponse.Header.Get("Content-Type"))
	s.Require().Equal(util.StructToJSON(newBillOfLadingPack), strings.TrimSpace(string(returnedBody)))
}

func (s *APITestSuite) TestListFileBasedEBL() {
	endPoint := fmt.Sprintf("http://%s/ebl?offset=2&limit=5&status=sent&report=TrUe&keyword=%s", s.localAddress, url.QueryEscape("hello world"))

	expectedReq := trade_document.ListFileBasedEBLRequest{
		Application: s.appId,
		RequestBy:   "issuer",
		Offset:      2,
		Limit:       5,
		Status:      "sent",
		Report:      true,
		Keyword:     "hello world",
	}

	billOfLadingRecord := trade_document.ListFileBasedEBLRecord{
		Total:   5,
		Report:  &storage.ListTradeDocumentReport{},
		Records: []trade_document.FileBasedBillOfLadingRecord{},
	}

	httpRequest, err := http.NewRequest(http.MethodGet, endPoint, nil)
	s.Require().NoError(err)
	httpRequest.Header.Set("Authorization", "Bearer "+string(s.apiKeyString))
	httpRequest.Header.Set(middleware.BUSINESS_UNIT_ID_HEADER, "issuer")

	gomock.InOrder(
		s.apiKeyMgr.EXPECT().Authenticate(gomock.Any(), s.apiKeyString).Return(s.apiKey, nil),
		s.fileEBLCtrl.EXPECT().List(gomock.Any(), expectedReq).Return(billOfLadingRecord, nil),
	)

	httpResponse, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	returnedBody, _ := io.ReadAll(httpResponse.Body)
	s.Require().Equal(http.StatusOK, httpResponse.StatusCode)
	s.Require().Equal("application/json", httpResponse.Header.Get("Content-Type"))
	s.Require().Equal(util.StructToJSON(billOfLadingRecord), strings.TrimSpace(string(returnedBody)))
}

func (s *APITestSuite) TestTransferFileBasedEBL() {
	endPoint := fmt.Sprintf("http://%s/ebl/doc_id/transfer", s.localAddress)

	req := trade_document.TransferEBLRequest{
		MetaData:         bill_of_lading.ApplicationMetaData{"requester": json.RawMessage(`1234.4566`)},
		AuthenticationID: "bu_auth_id",
		Note:             "note",
	}

	expectedRequest := req
	expectedRequest.Application = s.appId
	expectedRequest.TransferBy = "shipper"
	expectedRequest.ID = "doc_id"

	newBillOfLadingPack := trade_document.FileBasedBillOfLadingRecord{
		BL: &bill_of_lading.BillOfLadingPack{
			ID:      "pack_id",
			Version: 2,
		},
	}

	httpRequest, err := http.NewRequest(http.MethodPost, endPoint, util.StructToJSONReader(req))
	s.Require().NoError(err)
	httpRequest.Header.Set("Authorization", "Bearer "+string(s.apiKeyString))
	httpRequest.Header.Set(middleware.BUSINESS_UNIT_ID_HEADER, "shipper")

	gomock.InOrder(
		s.apiKeyMgr.EXPECT().Authenticate(gomock.Any(), s.apiKeyString).Return(s.apiKey, nil),
		s.fileEBLCtrl.EXPECT().Transfer(gomock.Any(), gomock.Any(), expectedRequest).Return(newBillOfLadingPack, nil),
	)

	httpResponse, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	returnedBody, _ := io.ReadAll(httpResponse.Body)
	s.Require().Equal(http.StatusOK, httpResponse.StatusCode)
	s.Require().Equal("application/json", httpResponse.Header.Get("Content-Type"))
	s.Require().Equal(util.StructToJSON(newBillOfLadingPack), strings.TrimSpace(string(returnedBody)))
}

func (s *APITestSuite) TestReturnFileBasedEBL() {
	endPoint := fmt.Sprintf("http://%s/ebl/doc_id/return", s.localAddress)

	req := trade_document.ReturnFileBasedEBLRequest{
		MetaData:         bill_of_lading.ApplicationMetaData{"requester": json.RawMessage(`{}`)},
		AuthenticationID: "bu_auth_id",
		Note:             "note",
	}

	expectedRequest := req
	expectedRequest.Application = s.appId
	expectedRequest.BusinessUnit = "consignee"
	expectedRequest.ID = "doc_id"

	newBillOfLadingPack := trade_document.FileBasedBillOfLadingRecord{
		BL: &bill_of_lading.BillOfLadingPack{
			ID:      "pack_id",
			Version: 2,
		},
	}

	httpRequest, err := http.NewRequest(http.MethodPost, endPoint, util.StructToJSONReader(req))
	s.Require().NoError(err)
	httpRequest.Header.Set("Authorization", "Bearer "+string(s.apiKeyString))
	httpRequest.Header.Set(middleware.BUSINESS_UNIT_ID_HEADER, "consignee")

	gomock.InOrder(
		s.apiKeyMgr.EXPECT().Authenticate(gomock.Any(), s.apiKeyString).Return(s.apiKey, nil),
		s.fileEBLCtrl.EXPECT().Return(gomock.Any(), gomock.Any(), expectedRequest).Return(newBillOfLadingPack, nil),
	)

	httpResponse, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	returnedBody, _ := io.ReadAll(httpResponse.Body)
	s.Require().Equal(http.StatusOK, httpResponse.StatusCode)
	s.Require().Equal("application/json", httpResponse.Header.Get("Content-Type"))
	s.Require().Equal(util.StructToJSON(newBillOfLadingPack), strings.TrimSpace(string(returnedBody)))
}

func (s *APITestSuite) TestAmendmentRequestFileBasedEBL() {
	endPoint := fmt.Sprintf("http://%s/ebl/doc_id/amendment_request", s.localAddress)

	req := trade_document.AmendmentRequestEBLRequest{
		MetaData:         bill_of_lading.ApplicationMetaData{"requester": json.RawMessage(`true`)},
		AuthenticationID: "bu_auth_id",
		Note:             "note",
	}

	expectedRequest := req
	expectedRequest.Application = s.appId
	expectedRequest.RequestBy = "consignee"
	expectedRequest.ID = "doc_id"

	newBillOfLadingPack := trade_document.FileBasedBillOfLadingRecord{
		BL: &bill_of_lading.BillOfLadingPack{
			ID:      "pack_id",
			Version: 3,
		},
	}

	httpRequest, err := http.NewRequest(http.MethodPost, endPoint, util.StructToJSONReader(req))
	s.Require().NoError(err)
	httpRequest.Header.Set("Authorization", "Bearer "+string(s.apiKeyString))
	httpRequest.Header.Set(middleware.BUSINESS_UNIT_ID_HEADER, "consignee")

	gomock.InOrder(
		s.apiKeyMgr.EXPECT().Authenticate(gomock.Any(), s.apiKeyString).Return(s.apiKey, nil),
		s.fileEBLCtrl.EXPECT().AmendmentRequest(gomock.Any(), gomock.Any(), expectedRequest).Return(newBillOfLadingPack, nil),
	)

	httpResponse, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	returnedBody, _ := io.ReadAll(httpResponse.Body)
	s.Require().Equal(http.StatusOK, httpResponse.StatusCode)
	s.Require().Equal("application/json", httpResponse.Header.Get("Content-Type"))
	s.Require().Equal(util.StructToJSON(newBillOfLadingPack), strings.TrimSpace(string(returnedBody)))
}

func (s *APITestSuite) TestAmendFileBasedEBL() {
	endPoint := fmt.Sprintf("http://%s/ebl/doc_id/amend", s.localAddress)

	req := trade_document.AmendFileBasedEBLRequest{
		MetaData:         bill_of_lading.ApplicationMetaData{"requester": json.RawMessage(`false`)},
		AuthenticationID: "bu_auth_id",

		File: trade_document.File{
			Name:    "new_test.txt",
			Type:    "text/plain",
			Content: []byte("new test content"),
		},
		BLNumber:  "new_bl_number",
		BLDocType: bill_of_lading.BillOfLadingDocumentTypeHouseBillOfLading,
		ToOrder:   false,
		POL: trade_document.Location{
			LocationName: "New Port of Loading",
			UNLocCode:    "POL",
		},
		POD: trade_document.Location{
			LocationName: "New Port of Discharge",
			UNLocCode:    "POD",
		},
		ETA:  lo.ToPtr(model.NewDateFromStringNoError("2024-02-26")),
		Note: "amend note",
	}

	expectedRequest := req
	expectedRequest.Application = s.appId
	expectedRequest.Issuer = "issuer"
	expectedRequest.ID = "doc_id"

	newBillOfLadingPack := trade_document.FileBasedBillOfLadingRecord{
		BL: &bill_of_lading.BillOfLadingPack{
			ID:      "pack_id",
			Version: 4,
		},
	}

	httpRequest, err := http.NewRequest(http.MethodPost, endPoint, util.StructToJSONReader(req))
	s.Require().NoError(err)
	httpRequest.Header.Set("Authorization", "Bearer "+string(s.apiKeyString))
	httpRequest.Header.Set(middleware.BUSINESS_UNIT_ID_HEADER, "issuer")

	gomock.InOrder(
		s.apiKeyMgr.EXPECT().Authenticate(gomock.Any(), s.apiKeyString).Return(s.apiKey, nil),
		s.fileEBLCtrl.EXPECT().Amend(gomock.Any(), gomock.Any(), expectedRequest).Return(newBillOfLadingPack, nil),
	)

	httpResponse, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	returnedBody, _ := io.ReadAll(httpResponse.Body)
	s.Require().Equal(http.StatusOK, httpResponse.StatusCode)
	s.Require().Equal("application/json", httpResponse.Header.Get("Content-Type"))
	s.Require().Equal(util.StructToJSON(newBillOfLadingPack), strings.TrimSpace(string(returnedBody)))
}

func (s *APITestSuite) TestSurrenderFileBasedEBL() {
	endPoint := fmt.Sprintf("http://%s/ebl/doc_id/surrender", s.localAddress)

	req := trade_document.SurrenderEBLRequest{
		MetaData:         bill_of_lading.ApplicationMetaData{"requester": json.RawMessage(`null`)},
		AuthenticationID: "bu_auth_id",
	}

	expectedRequest := req
	expectedRequest.Application = s.appId
	expectedRequest.RequestBy = "consignee"
	expectedRequest.ID = "doc_id"

	newBillOfLadingPack := trade_document.FileBasedBillOfLadingRecord{
		BL: &bill_of_lading.BillOfLadingPack{
			ID:      "pack_id",
			Version: 3,
		},
	}

	httpRequest, err := http.NewRequest(http.MethodPost, endPoint, util.StructToJSONReader(req))
	s.Require().NoError(err)
	httpRequest.Header.Set("Authorization", "Bearer "+string(s.apiKeyString))
	httpRequest.Header.Set(middleware.BUSINESS_UNIT_ID_HEADER, "consignee")

	gomock.InOrder(
		s.apiKeyMgr.EXPECT().Authenticate(gomock.Any(), s.apiKeyString).Return(s.apiKey, nil),
		s.fileEBLCtrl.EXPECT().Surrender(gomock.Any(), gomock.Any(), expectedRequest).Return(newBillOfLadingPack, nil),
	)

	httpResponse, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	returnedBody, _ := io.ReadAll(httpResponse.Body)
	s.Require().Equal(http.StatusOK, httpResponse.StatusCode)
	s.Require().Equal("application/json", httpResponse.Header.Get("Content-Type"))
	s.Require().Equal(util.StructToJSON(newBillOfLadingPack), strings.TrimSpace(string(returnedBody)))
}

func (s *APITestSuite) TestPrintFileBasedEBL() {
	endPoint := fmt.Sprintf("http://%s/ebl/doc_id/print_to_paper", s.localAddress)

	req := trade_document.PrintFileBasedEBLToPaperRequest{
		MetaData:         bill_of_lading.ApplicationMetaData{"requester": json.RawMessage(`"application user"`)},
		AuthenticationID: "bu_auth_id",
	}

	expectedRequest := req
	expectedRequest.Application = s.appId
	expectedRequest.RequestBy = "consignee"
	expectedRequest.ID = "doc_id"

	newBillOfLadingPack := trade_document.FileBasedBillOfLadingRecord{
		BL: &bill_of_lading.BillOfLadingPack{
			ID:      "pack_id",
			Version: 3,
		},
	}

	httpRequest, err := http.NewRequest(http.MethodPost, endPoint, util.StructToJSONReader(req))
	s.Require().NoError(err)
	httpRequest.Header.Set("Authorization", "Bearer "+string(s.apiKeyString))
	httpRequest.Header.Set(middleware.BUSINESS_UNIT_ID_HEADER, "consignee")

	gomock.InOrder(
		s.apiKeyMgr.EXPECT().Authenticate(gomock.Any(), s.apiKeyString).Return(s.apiKey, nil),
		s.fileEBLCtrl.EXPECT().PrintToPaper(gomock.Any(), gomock.Any(), expectedRequest).Return(newBillOfLadingPack, nil),
	)

	httpResponse, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	returnedBody, _ := io.ReadAll(httpResponse.Body)
	s.Require().Equal(http.StatusOK, httpResponse.StatusCode)
	s.Require().Equal("application/json", httpResponse.Header.Get("Content-Type"))
	s.Require().Equal(util.StructToJSON(newBillOfLadingPack), strings.TrimSpace(string(returnedBody)))
}

func (s *APITestSuite) TestAccomplishFileBasedEBL() {
	endPoint := fmt.Sprintf("http://%s/ebl/doc_id/accomplish", s.localAddress)

	req := trade_document.AccomplishEBLRequest{
		MetaData:         bill_of_lading.ApplicationMetaData{"requester": json.RawMessage(`"application user"`)},
		AuthenticationID: "bu_auth_id",
	}

	expectedRequest := req
	expectedRequest.Application = s.appId
	expectedRequest.RequestBy = "release_agent"
	expectedRequest.ID = "doc_id"

	newBillOfLadingPack := trade_document.FileBasedBillOfLadingRecord{
		BL: &bill_of_lading.BillOfLadingPack{
			ID:      "pack_id",
			Version: 3,
		},
	}

	httpRequest, err := http.NewRequest(http.MethodPost, endPoint, util.StructToJSONReader(req))
	s.Require().NoError(err)
	httpRequest.Header.Set("Authorization", "Bearer "+string(s.apiKeyString))
	httpRequest.Header.Set(middleware.BUSINESS_UNIT_ID_HEADER, "release_agent")

	gomock.InOrder(
		s.apiKeyMgr.EXPECT().Authenticate(gomock.Any(), s.apiKeyString).Return(s.apiKey, nil),
		s.fileEBLCtrl.EXPECT().Accomplish(gomock.Any(), gomock.Any(), expectedRequest).Return(newBillOfLadingPack, nil),
	)

	httpResponse, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	returnedBody, _ := io.ReadAll(httpResponse.Body)
	s.Require().Equal(http.StatusOK, httpResponse.StatusCode)
	s.Require().Equal("application/json", httpResponse.Header.Get("Content-Type"))
	s.Require().Equal(util.StructToJSON(newBillOfLadingPack), strings.TrimSpace(string(returnedBody)))
}

func (s *APITestSuite) TestGetFileBasedEBL() {
	endPoint := fmt.Sprintf("http://%s/ebl/doc_id", s.localAddress)

	expectedReq := trade_document.GetFileBasedEBLRequest{
		Requester:   "requester",
		Application: s.appId,
		ID:          "doc_id",
	}

	billOfLadingPack := trade_document.FileBasedBillOfLadingRecord{
		BL: &bill_of_lading.BillOfLadingPack{
			ID:      "pack_id",
			Version: 1,
		},
	}

	httpRequest, err := http.NewRequest(http.MethodGet, endPoint, nil)
	s.Require().NoError(err)
	httpRequest.Header.Set("Authorization", "Bearer "+string(s.apiKeyString))
	httpRequest.Header.Set(middleware.BUSINESS_UNIT_ID_HEADER, "requester")

	gomock.InOrder(
		s.apiKeyMgr.EXPECT().Authenticate(gomock.Any(), s.apiKeyString).Return(s.apiKey, nil),
		s.fileEBLCtrl.EXPECT().Get(gomock.Any(), expectedReq).Return(billOfLadingPack, nil),
	)

	httpResponse, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	returnedBody, _ := io.ReadAll(httpResponse.Body)
	s.Require().Equal(http.StatusOK, httpResponse.StatusCode)
	s.Require().Equal("application/json", httpResponse.Header.Get("Content-Type"))
	s.Require().Equal(util.StructToJSON(billOfLadingPack), strings.TrimSpace(string(returnedBody)))
}

func (s *APITestSuite) TestDeleteFileBasedEBL() {
	endPoint := fmt.Sprintf("http://%s/ebl/doc_id/delete", s.localAddress)

	req := trade_document.DeleteEBLRequest{
		MetaData:         bill_of_lading.ApplicationMetaData{"requester": json.RawMessage(`"application user"`)},
		AuthenticationID: "bu_auth_id",
	}

	expectedRequest := req
	expectedRequest.Application = s.appId
	expectedRequest.RequestBy = "issuer"
	expectedRequest.ID = "doc_id"

	newBillOfLadingPack := trade_document.FileBasedBillOfLadingRecord{
		BL: &bill_of_lading.BillOfLadingPack{
			ID:      "pack_id",
			Version: 2,
		},
	}

	httpRequest, err := http.NewRequest(http.MethodPost, endPoint, util.StructToJSONReader(req))
	s.Require().NoError(err)
	httpRequest.Header.Set("Authorization", "Bearer "+string(s.apiKeyString))
	httpRequest.Header.Set(middleware.BUSINESS_UNIT_ID_HEADER, "issuer")

	gomock.InOrder(
		s.apiKeyMgr.EXPECT().Authenticate(gomock.Any(), s.apiKeyString).Return(s.apiKey, nil),
		s.fileEBLCtrl.EXPECT().Delete(gomock.Any(), gomock.Any(), expectedRequest).Return(newBillOfLadingPack, nil),
	)

	httpResponse, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	returnedBody, _ := io.ReadAll(httpResponse.Body)
	s.Require().Equal(http.StatusOK, httpResponse.StatusCode)
	s.Require().Equal("application/json", httpResponse.Header.Get("Content-Type"))
	s.Require().Equal(util.StructToJSON(newBillOfLadingPack), strings.TrimSpace(string(returnedBody)))
}

func (s *APITestSuite) TestDownloadFileBasedEBLDocument() {
	endPoint := fmt.Sprintf("http://%s/ebl/doc_id/document", s.localAddress)

	expectedReq := trade_document.GetFileBasedEBLRequest{
		Requester:   "requester",
		Application: s.appId,
		ID:          "doc_id",
	}

	uploadedFile := &model.File{
		Name:        "bill_of_lading.pdf",
		FileType:    "application/auto-detected",
		Content:     []byte("%PDF-1.7 Hello World!"),
		CreatedDate: model.NewDateTimeFromUnix(1708905600),
	}

	httpRequest, err := http.NewRequest(http.MethodGet, endPoint, nil)
	s.Require().NoError(err)
	httpRequest.Header.Set("Authorization", "Bearer "+string(s.apiKeyString))
	httpRequest.Header.Set(middleware.BUSINESS_UNIT_ID_HEADER, "requester")

	gomock.InOrder(
		s.apiKeyMgr.EXPECT().Authenticate(gomock.Any(), s.apiKeyString).Return(s.apiKey, nil),
		s.fileEBLCtrl.EXPECT().GetDocument(gomock.Any(), expectedReq).Return(uploadedFile, nil),
	)

	httpResponse, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	returnedBody, _ := io.ReadAll(httpResponse.Body)
	s.Require().Equal(http.StatusOK, httpResponse.StatusCode)
	s.Assert().Equal("application/pdf", httpResponse.Header.Get("Content-Type"))
	s.Assert().Equal("attachment; filename=bill_of_lading.pdf", httpResponse.Header.Get("Content-Disposition"))
	s.Assert().Equal("21", httpResponse.Header.Get("Content-Length"))
	s.Assert().Equal([]byte("%PDF-1.7 Hello World!"), returnedBody)
}

func (s *APITestSuite) TestCreateWebhook() {
	req := webhook.CreateWebhookRequest{
		Requester: "requester",
		Events:    []model.WebhookEventType{model.WebhookEventBLAccomplished, model.WebhookEventBLPrintedToPaper},
		Url:       "https://example.com/notify",
		Secret:    "secret_key",
	}

	expectedReq := req
	expectedReq.ApplicationID = s.appId

	w := model.Webhook{
		ID:      "webhook_id",
		Deleted: false,
	}

	endPoint := fmt.Sprintf("http://%s/webhook", s.localAddress)
	httpRequest, _ := http.NewRequestWithContext(s.ctx, http.MethodPost, endPoint, util.StructToJSONReader(req))
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Authorization", "Bearer "+string(s.apiKeyString))

	gomock.InOrder(
		s.apiKeyMgr.EXPECT().Authenticate(gomock.Any(), s.apiKeyString).Return(s.apiKey, nil),
		s.webhookCtrl.EXPECT().Create(gomock.Any(), gomock.Any(), expectedReq).Return(w, nil),
	)

	// Test Normal Case.
	resp, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	defer func() { _ = resp.Body.Close() }()

	s.Require().Equal(http.StatusCreated, resp.StatusCode)
	s.Require().Equal("application/json", resp.Header.Get("Content-Type"))
	body, _ := io.ReadAll(resp.Body)
	s.Assert().Equal(util.StructToJSON(w), strings.TrimSpace(string(body)))
	// End of Test Normal Case.

	// Test with invalid credential.
	gomock.InOrder(
		s.apiKeyMgr.EXPECT().Authenticate(gomock.Any(), s.apiKeyString).Return(auth.APIKey{}, model.ErrMismatchAPIKey),
	)
	resp, err = http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	defer func() { _ = resp.Body.Close() }()

	s.Require().Equal(http.StatusUnauthorized, resp.StatusCode)
}

func (s *APITestSuite) TestListWebhook() {
	endPoint := fmt.Sprintf("http://%s/webhook?offset=1&limit=2", s.localAddress)

	expectedReq := webhook.ListWebhookRequest{
		Offset:        1,
		Limit:         2,
		ApplicationID: s.appId,
	}

	result := webhook.ListWebhookResponse{
		Total:   2,
		Records: []model.Webhook{},
	}

	gomock.InOrder(
		s.apiKeyMgr.EXPECT().Authenticate(gomock.Any(), s.apiKeyString).Return(s.apiKey, nil),
		s.webhookCtrl.EXPECT().List(gomock.Any(), expectedReq).Return(result, nil),
	)

	httpRequest, _ := http.NewRequestWithContext(s.ctx, http.MethodGet, endPoint, nil)
	httpRequest.Header.Set("Authorization", "Bearer "+string(s.apiKeyString))

	resp, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	defer func() { _ = resp.Body.Close() }()

	s.Require().Equal(http.StatusOK, resp.StatusCode)
	s.Require().Equal("application/json", resp.Header.Get("Content-Type"))
	body, _ := io.ReadAll(resp.Body)
	s.Assert().Equal(util.StructToJSON(result), strings.TrimSpace(string(body)))
}

func (s *APITestSuite) TestGetWebhook() {
	webhookId := "webhook_id"
	endPoint := fmt.Sprintf("http://%s/webhook/%s", s.localAddress, webhookId)

	expectedWebhook := model.Webhook{
		ID:            webhookId,
		Version:       1,
		ApplicationID: s.appId,
		Url:           "https://example.com/notify",
		Events:        []model.WebhookEventType{model.WebhookEventBLAccomplished, model.WebhookEventBLPrintedToPaper},
		Secret:        "secret_key",
		CreatedAt:     12345,
		CreatedBy:     "requester",
		UpdatedAt:     12345,
		UpdatedBy:     "requester",
		Deleted:       false,
	}

	gomock.InOrder(
		s.apiKeyMgr.EXPECT().Authenticate(gomock.Any(), s.apiKeyString).Return(s.apiKey, nil),
		s.webhookCtrl.EXPECT().Get(gomock.Any(), s.appId, webhookId).Return(expectedWebhook, nil),
	)

	httpRequest, _ := http.NewRequestWithContext(s.ctx, http.MethodGet, endPoint, nil)
	httpRequest.Header.Set("Authorization", "Bearer "+string(s.apiKeyString))

	resp, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	defer func() { _ = resp.Body.Close() }()

	s.Require().Equal(http.StatusOK, resp.StatusCode)
	s.Require().Equal("application/json", resp.Header.Get("Content-Type"))
	body, _ := io.ReadAll(resp.Body)
	s.Assert().Equal(util.StructToJSON(expectedWebhook), strings.TrimSpace(string(body)))
}

func (s *APITestSuite) TestUpdateWebhook() {
	webhookId := "webhook_id"
	endPoint := fmt.Sprintf("http://%s/webhook/%s", s.localAddress, webhookId)

	req := webhook.UpdateWebhookRequest{
		Requester: "requester",
		Events:    []model.WebhookEventType{model.WebhookEventBLIssued, model.WebhookEventBLAccomplished, model.WebhookEventBLPrintedToPaper},
		Url:       "https://example2.com/notify",
		Secret:    "new_secret_key",
	}

	expectedReq := req
	expectedReq.ApplicationID = s.appId
	expectedReq.ID = webhookId

	updatedWebhook := model.Webhook{
		ID:      "webhook_id",
		Version: 2,
		Deleted: false,
	}

	httpRequest, _ := http.NewRequestWithContext(s.ctx, http.MethodPost, endPoint, util.StructToJSONReader(req))
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Authorization", "Bearer "+string(s.apiKeyString))

	gomock.InOrder(
		s.apiKeyMgr.EXPECT().Authenticate(gomock.Any(), s.apiKeyString).Return(s.apiKey, nil),
		s.webhookCtrl.EXPECT().Update(gomock.Any(), gomock.Any(), expectedReq).Return(updatedWebhook, nil),
	)

	resp, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	defer func() { _ = resp.Body.Close() }()

	s.Require().Equal(http.StatusOK, resp.StatusCode)
	s.Require().Equal("application/json", resp.Header.Get("Content-Type"))
	body, _ := io.ReadAll(resp.Body)
	s.Assert().Equal(util.StructToJSON(updatedWebhook), strings.TrimSpace(string(body)))
}

func (s *APITestSuite) TestDeleteWebhook() {
	webhookId := "webhook_id"
	endPoint := fmt.Sprintf("http://%s/webhook/%s?requester=test", s.localAddress, webhookId)

	expectedReq := webhook.DeleteWebhookRequest{
		ID:            webhookId,
		Requester:     "test",
		ApplicationID: s.appId,
	}

	updatedWebhook := model.Webhook{
		ID:      "webhook_id",
		Version: 2,
		Deleted: true,
	}

	httpRequest, _ := http.NewRequestWithContext(s.ctx, http.MethodDelete, endPoint, nil)
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Authorization", "Bearer "+string(s.apiKeyString))

	gomock.InOrder(
		s.apiKeyMgr.EXPECT().Authenticate(gomock.Any(), s.apiKeyString).Return(s.apiKey, nil),
		s.webhookCtrl.EXPECT().Delete(gomock.Any(), gomock.Any(), expectedReq).Return(updatedWebhook, nil),
	)

	resp, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	defer func() { _ = resp.Body.Close() }()

	s.Require().Equal(http.StatusOK, resp.StatusCode)
	s.Require().Equal("application/json", resp.Header.Get("Content-Type"))
	body, _ := io.ReadAll(resp.Body)
	s.Assert().Equal(util.StructToJSON(updatedWebhook), strings.TrimSpace(string(body)))
}
