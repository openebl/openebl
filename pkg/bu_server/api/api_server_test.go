package api_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did/did"
	"github.com/openebl/openebl/pkg/bu_server/api"
	"github.com/openebl/openebl/pkg/bu_server/auth"
	"github.com/openebl/openebl/pkg/bu_server/business_unit"
	"github.com/openebl/openebl/pkg/bu_server/middleware"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/model/trade_document/bill_of_lading"
	"github.com/openebl/openebl/pkg/bu_server/trade_document"
	"github.com/openebl/openebl/pkg/util"
	mock_auth "github.com/openebl/openebl/test/mock/bu_server/auth"
	mock_business_unit "github.com/openebl/openebl/test/mock/bu_server/business_unit"
	mock_trade_document "github.com/openebl/openebl/test/mock/bu_server/trade_document"
	"github.com/stretchr/testify/suite"
)

type APITestSuite struct {
	suite.Suite

	ctx         context.Context
	ctrl        *gomock.Controller
	apiKeyMgr   *mock_auth.MockAPIKeyAuthenticator
	buMgr       *mock_business_unit.MockBusinessUnitManager
	fileEBLCtrl *mock_trade_document.MockFileBaseEBLController

	basePortNumber int32
	localAddress   string
	api            *api.API

	appId        string
	apiKeyString auth.APIKeyString
	apiKey       auth.APIKey
}

func TestAPITestSuite(t *testing.T) {
	ts := new(APITestSuite)
	ts.basePortNumber = 9200
	suite.Run(t, ts)
}

func (s *APITestSuite) SetupTest() {
	s.ctx = context.Background()
	s.ctrl = gomock.NewController(s.T())
	s.apiKeyMgr = mock_auth.NewMockAPIKeyAuthenticator(s.ctrl)
	s.buMgr = mock_business_unit.NewMockBusinessUnitManager(s.ctrl)
	s.fileEBLCtrl = mock_trade_document.NewMockFileBaseEBLController(s.ctrl)

	portNum := atomic.AddInt32(&s.basePortNumber, 1)
	s.localAddress = fmt.Sprintf("localhost:%d", portNum)
	api, err := api.NewAPIWithController(s.apiKeyMgr, s.buMgr, s.fileEBLCtrl, s.localAddress)
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
	s.api.Close()
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
		ID:     did.MustParseDID("did:openebl:1234567890"),
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

	expectedRequest := business_unit.ListBusinessUnitsRequest{
		ApplicationID: s.appId,
		Offset:        1,
		Limit:         2,
	}

	result := business_unit.ListBusinessUnitsResult{
		Total: 10,
		Records: []business_unit.ListBusinessUnitsRecord{
			{
				BusinessUnit: model.BusinessUnit{
					ID: did.MustParseDID("did:openebl:1234567890"),
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

	expectedRequest := business_unit.ListBusinessUnitsRequest{
		ApplicationID:   s.appId,
		BusinessUnitIDs: []string{buId},
		Limit:           1,
	}

	result := business_unit.ListBusinessUnitsResult{
		Total: 10,
		Records: []business_unit.ListBusinessUnitsRecord{
			{
				BusinessUnit: model.BusinessUnit{
					ID: did.MustParseDID("did:openebl:1234567890"),
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
		ID:           did.MustParseDID(buId),
		Name:         "name",
		Addresses:    []string{"address"},
		Emails:       []string{"email"},
		PhoneNumbers: []string{"phone number"},
	}

	expectedRequest := request
	expectedRequest.ApplicationID = s.appId

	newBu := model.BusinessUnit{
		ID: did.MustParseDID(buId),
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
		ID:        did.MustParseDID(buId),
		Status:    model.BusinessUnitStatusInactive,
	}

	expectedRequest := request
	expectedRequest.ApplicationID = s.appId

	newBu := model.BusinessUnit{
		ID:     did.MustParseDID(buId),
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
		Requester:        "requester",
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
		ETA:          model.NewDateTimeFromUnix(1708905600),
		Shipper:      "shipper",
		Consignee:    "consignee",
		ReleaseAgent: "release agent",
		Note:         "note",
		Draft:        util.Ptr(true),
	}

	expectedRequest := req
	expectedRequest.Application = s.appId
	expectedRequest.Issuer = "issuer"

	newBillOfLadingPack := bill_of_lading.BillOfLadingPack{
		ID:      "pack_id",
		Version: 1,
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
	s.Require().Equal(http.StatusOK, httpResponse.StatusCode)
	s.Require().Equal("application/json", httpResponse.Header.Get("Content-Type"))
	s.Require().Equal(util.StructToJSON(newBillOfLadingPack), strings.TrimSpace(string(returnedBody)))
}
