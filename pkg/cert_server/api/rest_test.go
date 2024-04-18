package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/openebl/openebl/pkg/cert_server/api"
	"github.com/openebl/openebl/pkg/cert_server/cert_authority"
	"github.com/openebl/openebl/pkg/cert_server/model"
	"github.com/openebl/openebl/pkg/cert_server/storage"
	eblpkix "github.com/openebl/openebl/pkg/pkix"
	"github.com/openebl/openebl/pkg/util"
	mock_cert_authority "github.com/openebl/openebl/test/mock/cert_server/cert_authority"
	"github.com/stretchr/testify/suite"
)

type RestServerTestSuite struct {
	suite.Suite

	ctx            context.Context
	basePortNumber int32
	privateAddress string

	ctrl       *gomock.Controller
	ca         *mock_cert_authority.MockCertAuthority
	restServer *api.RestServer
}

func TestRestServerTestSuite(t *testing.T) {
	suite.Run(t, new(RestServerTestSuite))
}

func (s *RestServerTestSuite) SetupSuite() {
	s.basePortNumber = 10000
}

func (s *RestServerTestSuite) SetupTest() {
	s.ctx = context.Background()
	s.ctrl = gomock.NewController(s.T())

	portNum := atomic.AddInt32(&s.basePortNumber, 1)
	s.privateAddress = fmt.Sprintf("localhost:%d", portNum)

	s.ca = mock_cert_authority.NewMockCertAuthority(s.ctrl)
	s.restServer = api.NewRestServerWithController(s.ca, s.privateAddress, "")

	go func() {
		s.restServer.Run()
	}()
	time.Sleep(100 * time.Millisecond)
}

func (s *RestServerTestSuite) TearDownTest() {
	s.ctrl.Finish()
	s.restServer.Close(s.ctx)
}

func (s *RestServerTestSuite) TestListRootCert() {
	offset := 3
	limit := 10

	expectedRequest := storage.ListCertificatesRequest{
		Offset: offset,
		Limit:  limit,
		Types:  []model.CertType{model.RootCert},
	}

	result := storage.ListCertificatesResponse{
		Total: 1,
		Certs: []model.Cert{
			{
				ID:      "cert id",
				Version: 1,
				Type:    model.RootCert,
				Status:  model.CertStatusActive,
			},
		},
	}

	s.ca.EXPECT().ListCertificate(gomock.Any(), expectedRequest).Return(result, nil)

	endPoint := fmt.Sprintf("http://%s/root_cert?offset=%d&limit=%d", s.privateAddress, offset, limit)
	httpRequest, _ := http.NewRequest(http.MethodGet, endPoint, nil)

	resp, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	defer resp.Body.Close()
	returnedCerts := storage.ListCertificatesResponse{}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&returnedCerts))

	s.Equal(http.StatusOK, resp.StatusCode)
	s.Equal(result, returnedCerts)
}

func (s *RestServerTestSuite) TestGetRootCert() {
	certID := "cert_id"

	expectedRequest := storage.ListCertificatesRequest{
		Limit: 1,
		IDs:   []string{certID},
		Types: []model.CertType{model.RootCert},
	}

	result := storage.ListCertificatesResponse{
		Total: 1,
		Certs: []model.Cert{
			{
				ID:      "cert id",
				Version: 1,
				Type:    model.RootCert,
				Status:  model.CertStatusActive,
			},
		},
	}

	s.ca.EXPECT().ListCertificate(gomock.Any(), expectedRequest).Return(result, nil)

	endPoint := fmt.Sprintf("http://%s/root_cert/%s", s.privateAddress, certID)
	httpRequest, _ := http.NewRequest(http.MethodGet, endPoint, nil)

	resp, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	defer resp.Body.Close()
	returnedCert := model.Cert{}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&returnedCert))

	s.Equal(http.StatusOK, resp.StatusCode)
	s.Equal(result.Certs[0], returnedCert)
}

func (s *RestServerTestSuite) TestListCACert() {
	offset := 3
	limit := 10

	expectedRequest := storage.ListCertificatesRequest{
		Offset: offset,
		Limit:  limit,
		Types:  []model.CertType{model.CACert},
	}

	result := storage.ListCertificatesResponse{
		Total: 1,
		Certs: []model.Cert{
			{
				ID:      "cert id",
				Version: 1,
				Type:    model.CACert,
				Status:  model.CertStatusActive,
			},
		},
	}

	s.ca.EXPECT().ListCertificate(gomock.Any(), expectedRequest).Return(result, nil)

	endPoint := fmt.Sprintf("http://%s/ca_cert?offset=%d&limit=%d", s.privateAddress, offset, limit)
	httpRequest, _ := http.NewRequest(http.MethodGet, endPoint, nil)

	resp, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	defer resp.Body.Close()
	returnedCerts := storage.ListCertificatesResponse{}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&returnedCerts))

	s.Equal(http.StatusOK, resp.StatusCode)
	s.Equal(result, returnedCerts)
}

func (s *RestServerTestSuite) TestGetCACert() {
	certID := "cert_id"

	expectedRequest := storage.ListCertificatesRequest{
		Limit: 1,
		IDs:   []string{certID},
		Types: []model.CertType{model.CACert},
	}

	result := storage.ListCertificatesResponse{
		Total: 1,
		Certs: []model.Cert{
			{
				ID:      "cert id",
				Version: 1,
				Type:    model.CACert,
				Status:  model.CertStatusActive,
			},
		},
	}

	s.ca.EXPECT().ListCertificate(gomock.Any(), expectedRequest).Return(result, nil)

	endPoint := fmt.Sprintf("http://%s/ca_cert/%s", s.privateAddress, certID)
	httpRequest, _ := http.NewRequest(http.MethodGet, endPoint, nil)

	resp, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	defer resp.Body.Close()
	returnedCert := model.Cert{}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&returnedCert))

	s.Equal(http.StatusOK, resp.StatusCode)
	s.Equal(result.Certs[0], returnedCert)

}

func (s *RestServerTestSuite) TestListCert() {
	offset := 3
	limit := 10

	expectedRequest := storage.ListCertificatesRequest{
		Offset: offset,
		Limit:  limit,
		Types:  []model.CertType{model.BUCert, model.ThirdPartyCACert},
	}

	result := storage.ListCertificatesResponse{
		Total: 1,
		Certs: []model.Cert{
			{
				ID:      "cert id",
				Version: 1,
				Type:    model.BUCert,
				Status:  model.CertStatusActive,
			},
		},
	}

	s.ca.EXPECT().ListCertificate(gomock.Any(), expectedRequest).Return(result, nil)

	endPoint := fmt.Sprintf("http://%s/cert?offset=%d&limit=%d", s.privateAddress, offset, limit)
	httpRequest, _ := http.NewRequest(http.MethodGet, endPoint, nil)

	resp, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	defer resp.Body.Close()
	returnedCerts := storage.ListCertificatesResponse{}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&returnedCerts))

	s.Equal(http.StatusOK, resp.StatusCode)
	s.Equal(result, returnedCerts)
}

func (s *RestServerTestSuite) TestGetCert() {
	certID := "cert_id"

	expectedRequest := storage.ListCertificatesRequest{
		Limit: 1,
		IDs:   []string{certID},
		Types: []model.CertType{model.BUCert, model.ThirdPartyCACert},
	}

	result := storage.ListCertificatesResponse{
		Total: 1,
		Certs: []model.Cert{
			{
				ID:      "cert id",
				Version: 1,
				Type:    model.BUCert,
				Status:  model.CertStatusActive,
			},
		},
	}

	s.ca.EXPECT().ListCertificate(gomock.Any(), expectedRequest).Return(result, nil)

	endPoint := fmt.Sprintf("http://%s/cert/%s", s.privateAddress, certID)
	httpRequest, _ := http.NewRequest(http.MethodGet, endPoint, nil)

	resp, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	defer resp.Body.Close()
	returnedCert := model.Cert{}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&returnedCert))

	s.Equal(http.StatusOK, resp.StatusCode)
	s.Equal(result.Certs[0], returnedCert)
}

func (s *RestServerTestSuite) TestAddRootCert() {
	requester := "administrator"
	req := cert_authority.AddRootCertificateRequest{
		Cert: "cert pem file",
	}

	expectedReq := req
	expectedReq.Requester = requester

	cert := model.Cert{
		ID:          "cert id",
		Version:     1,
		Type:        model.RootCert,
		Status:      model.CertStatusActive,
		Certificate: req.Cert,
	}

	s.ca.EXPECT().AddRootCertificate(gomock.Any(), gomock.Any(), expectedReq).Return(cert, nil)

	endPoint := fmt.Sprintf("http://%s/root_cert", s.privateAddress)
	httpRequest, _ := http.NewRequest(http.MethodPost, endPoint, util.StructToJSONReader(req))
	httpRequest.Header.Set(api.REQUESTER_HEADER, requester)

	resp, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	defer resp.Body.Close()
	returnedCert := model.Cert{}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&returnedCert))

	s.Equal(http.StatusCreated, resp.StatusCode)
	s.Equal(cert, returnedCert)
}

func (s *RestServerTestSuite) TestRevokeRootCert() {
	requester := "administrator"
	certID := "cert_id"

	expectedRequest := cert_authority.RevokeCertificateRequest{
		CertID:    certID,
		Requester: requester,
	}

	cert := model.Cert{
		ID:      certID,
		Version: 1,
		Type:    model.RootCert,
		Status:  model.CertStatusRevoked,
	}

	s.ca.EXPECT().RevokeRootCertificate(gomock.Any(), gomock.Any(), expectedRequest).Return(cert, nil)

	endPoint := fmt.Sprintf("http://%s/root_cert/%s", s.privateAddress, certID)
	httpRequest, _ := http.NewRequest(http.MethodDelete, endPoint, nil)
	httpRequest.Header.Set(api.REQUESTER_HEADER, requester)

	resp, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	defer resp.Body.Close()
	returnedCert := model.Cert{}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&returnedCert))

	s.Equal(http.StatusOK, resp.StatusCode)
	s.Equal(cert, returnedCert)
}

func (s *RestServerTestSuite) TestCreateCACertificateSigningRequest() {
	requester := "administrator"
	req := cert_authority.CreateCACertificateSigningRequestRequest{
		PrivateKeyOption: eblpkix.PrivateKeyOption{
			KeyType:   eblpkix.PrivateKeyTypeECDSA,
			CurveType: eblpkix.ECDSACurveTypeP521,
		},
		Country:            []string{"US"},
		Organization:       []string{"OpenEbl"},
		OrganizationalUnit: []string{"Engineering"},
		CommonName:         "OpenEbl CA",
	}
	expectedReq := req
	expectedReq.Requester = requester

	cert := model.Cert{
		ID:                        "cert_id",
		Version:                   1,
		Type:                      model.CACert,
		Status:                    model.CertStatusWaitingForIssued,
		PrivateKey:                "private key",
		CertificateSigningRequest: "csr",
	}

	s.ca.EXPECT().CreateCACertificateSigningRequest(gomock.Any(), gomock.Any(), expectedReq).Return(cert, nil)

	endPoint := fmt.Sprintf("http://%s/ca_cert", s.privateAddress)
	httpRequest, _ := http.NewRequest(http.MethodPost, endPoint, util.StructToJSONReader(req))
	httpRequest.Header.Set(api.REQUESTER_HEADER, requester)

	resp, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	defer resp.Body.Close()
	returnedCert := model.Cert{}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&returnedCert))

	s.Equal(http.StatusCreated, resp.StatusCode)
	s.Equal(cert, returnedCert)
}

func (s *RestServerTestSuite) TestRespondCACertificateSigningRequest() {
	requester := "administrator"
	certID := "cert_id"
	req := cert_authority.RespondCACertificateSigningRequestRequest{
		Cert: "cert pem file",
	}
	expectedReq := req
	expectedReq.Requester = requester
	expectedReq.CertID = certID

	cert := model.Cert{
		ID:                        certID,
		Version:                   1,
		Type:                      model.CACert,
		Status:                    model.CertStatusActive,
		Certificate:               req.Cert,
		CertificateSigningRequest: "csr",
		PrivateKey:                "private key",
	}

	s.ca.EXPECT().RespondCACertificateSigningRequest(gomock.Any(), gomock.Any(), expectedReq).Return(cert, nil)

	endPoint := fmt.Sprintf("http://%s/ca_cert/%s", s.privateAddress, certID)
	httpRequest, _ := http.NewRequest(http.MethodPost, endPoint, util.StructToJSONReader(req))
	httpRequest.Header.Set(api.REQUESTER_HEADER, requester)

	resp, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	defer resp.Body.Close()
	returnedCert := model.Cert{}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&returnedCert))

	s.Equal(http.StatusOK, resp.StatusCode)
	s.Equal(cert, returnedCert)
}

func (s *RestServerTestSuite) TestRevokeCACertificate() {
	requester := "administrator"
	certID := "cert_id"

	req := cert_authority.RevokeCACertificateRequest{
		CRL: "crl pem file",
	}
	expectReq := req
	expectReq.Requester = requester
	expectReq.CertID = certID

	cert := model.Cert{
		ID:      certID,
		Version: 1,
		Type:    model.CACert,
		Status:  model.CertStatusRevoked,
	}

	s.ca.EXPECT().RevokeCACertificate(gomock.Any(), gomock.Any(), expectReq).Return(cert, nil)

	endPoint := fmt.Sprintf("http://%s/ca_cert/%s/revoke", s.privateAddress, certID)
	httpRequest, _ := http.NewRequest(http.MethodPost, endPoint, util.StructToJSONReader(req))
	httpRequest.Header.Set(api.REQUESTER_HEADER, requester)

	resp, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	defer resp.Body.Close()
	returnedCert := model.Cert{}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&returnedCert))

	s.Equal(http.StatusOK, resp.StatusCode)
	s.Equal(cert, returnedCert)
}

func (s *RestServerTestSuite) TestAddCertificateSigningRequest() {
	requester := "administrator"
	req := cert_authority.AddCertificateSigningRequestRequest{
		CertType:           model.BUCert,
		CertSigningRequest: "csr pem file",
	}

	expectedReq := req
	expectedReq.Requester = requester

	cert := model.Cert{
		ID:                        "cert id",
		Version:                   1,
		Type:                      model.ThirdPartyCACert,
		Status:                    model.CertStatusActive,
		CertificateSigningRequest: req.CertSigningRequest,
	}

	s.ca.EXPECT().AddCertificateSigningRequest(gomock.Any(), gomock.Any(), expectedReq).Return(cert, nil)

	endPoint := fmt.Sprintf("http://%s/cert", s.privateAddress)
	httpRequest, _ := http.NewRequest(http.MethodPost, endPoint, util.StructToJSONReader(req))
	httpRequest.Header.Set(api.REQUESTER_HEADER, requester)

	resp, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	defer resp.Body.Close()
	returnedCert := model.Cert{}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&returnedCert))

	s.Equal(http.StatusCreated, resp.StatusCode)
	s.Equal(cert, returnedCert)
}

func (s *RestServerTestSuite) TestIssueCertificate() {
	requester := "administrator"
	certID := "cert_id"
	req := cert_authority.IssueCertificateRequest{
		CACertID:  "ca cert id",
		CertType:  model.ThirdPartyCACert,
		NotBefore: time.Now().Unix(),
		NotAfter:  time.Now().Add(time.Hour * 8760).Unix(),
	}
	expectedReq := req
	expectedReq.Requester = requester
	expectedReq.CertID = certID

	cert := model.Cert{
		ID:                        certID,
		Version:                   1,
		Type:                      model.BUCert,
		Status:                    model.CertStatusWaitingForIssued,
		CertificateSigningRequest: "csr pem file",
	}

	s.ca.EXPECT().IssueCertificate(gomock.Any(), gomock.Any(), expectedReq).Return(cert, nil)

	endPoint := fmt.Sprintf("http://%s/cert/%s", s.privateAddress, certID)
	httpRequest, _ := http.NewRequest(http.MethodPost, endPoint, util.StructToJSONReader(req))
	httpRequest.Header.Set(api.REQUESTER_HEADER, requester)

	resp, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	defer resp.Body.Close()
	returnedCert := model.Cert{}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&returnedCert))

	s.Equal(http.StatusOK, resp.StatusCode)
	s.Equal(cert, returnedCert)
}

func (s *RestServerTestSuite) TestRejectCertificateSigningRequest() {
	requester := "administrator"
	certID := "cert_id"

	req := cert_authority.RejectCertificateSigningRequestRequest{
		CertType: model.ThirdPartyCACert,
		Reason:   "reason",
	}
	expectedReq := req
	expectedReq.Requester = requester
	expectedReq.CertID = certID

	cert := model.Cert{
		ID:                        certID,
		Version:                   1,
		Type:                      model.ThirdPartyCACert,
		Status:                    model.CertStatusRejected,
		CertificateSigningRequest: "csr pem file",
		RejectedBy:                requester,
		RejectReason:              req.Reason,
	}

	s.ca.EXPECT().RejectCertificateSigningRequest(gomock.Any(), gomock.Any(), expectedReq).Return(cert, nil)

	endPoint := fmt.Sprintf("http://%s/cert/%s/reject", s.privateAddress, certID)
	httpRequest, _ := http.NewRequest(http.MethodPost, endPoint, util.StructToJSONReader(req))
	httpRequest.Header.Set(api.REQUESTER_HEADER, requester)

	resp, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	defer resp.Body.Close()
	returnedCert := model.Cert{}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&returnedCert))

	s.Equal(http.StatusOK, resp.StatusCode)
	s.Equal(cert, returnedCert)
}

func (s *RestServerTestSuite) TestRevokeCertificate() {
	requester := "administrator"
	certID := "cert_id"

	expectedReq := cert_authority.RevokeCertificateRequest{
		Requester: requester,
		CertID:    certID,
	}

	cert := model.Cert{
		ID:      certID,
		Version: 1,
		Type:    model.BUCert,
		Status:  model.CertStatusRevoked,
	}

	s.ca.EXPECT().RevokeCertificate(gomock.Any(), gomock.Any(), expectedReq).Return(cert, nil)

	endPoint := fmt.Sprintf("http://%s/cert/%s", s.privateAddress, certID)
	httpRequest, _ := http.NewRequest(http.MethodDelete, endPoint, nil)
	httpRequest.Header.Set(api.REQUESTER_HEADER, requester)

	resp, err := http.DefaultClient.Do(httpRequest)
	s.Require().NoError(err)
	defer resp.Body.Close()
	returnedCert := model.Cert{}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&returnedCert))

	s.Equal(http.StatusOK, resp.StatusCode)
	s.Equal(cert, returnedCert)
}
