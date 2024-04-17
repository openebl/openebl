package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/openebl/openebl/pkg/cert_server/api"
	"github.com/openebl/openebl/pkg/cert_server/cert_authority"
	"github.com/openebl/openebl/pkg/cert_server/model"
	"github.com/openebl/openebl/pkg/cert_server/storage"
	eblpkix "github.com/openebl/openebl/pkg/pkix"
	"github.com/openebl/openebl/pkg/util"
)

type RestClient struct {
	requester string
	server    string // http://server/
}

func NewRestClient(server, requester string) *RestClient {
	return &RestClient{
		requester: requester,
		server:    server,
	}
}

func (r *RestClient) ListRootCert(offset, limit int) (storage.ListCertificatesResponse, error) {
	path := fmt.Sprintf("/root_cert?offset=%d&limit=%d", offset, limit)
	certs := storage.ListCertificatesResponse{}
	if err := r.execute(http.MethodGet, path, nil, &certs); err != nil {
		return storage.ListCertificatesResponse{}, err
	}
	return certs, nil
}

func (r *RestClient) GetRootCert(certID string) (model.Cert, error) {
	path := fmt.Sprintf("/root_cert/%s", certID)
	cert := model.Cert{}
	if err := r.execute(http.MethodGet, path, nil, &cert); err != nil {
		return model.Cert{}, err
	}
	return cert, nil
}

func (r *RestClient) ListCACert(offset, limit int) (storage.ListCertificatesResponse, error) {
	path := fmt.Sprintf("/ca_cert?offset=%d&limit=%d", offset, limit)
	certs := storage.ListCertificatesResponse{}
	if err := r.execute(http.MethodGet, path, nil, &certs); err != nil {
		return storage.ListCertificatesResponse{}, err
	}
	return certs, nil
}

func (r *RestClient) GetCACert(certID string) (model.Cert, error) {
	path := fmt.Sprintf("/ca_cert/%s", certID)
	cert := model.Cert{}
	if err := r.execute(http.MethodGet, path, nil, &cert); err != nil {
		return model.Cert{}, err
	}
	return cert, nil
}

func (r *RestClient) ListCert(offset, limit int) (storage.ListCertificatesResponse, error) {
	path := fmt.Sprintf("/cert?offset=%d&limit=%d", offset, limit)
	certs := storage.ListCertificatesResponse{}
	if err := r.execute(http.MethodGet, path, nil, &certs); err != nil {
		return storage.ListCertificatesResponse{}, err
	}
	return certs, nil
}

func (r *RestClient) GetCert(certID string) (model.Cert, error) {
	path := fmt.Sprintf("/cert/%s", certID)
	cert := model.Cert{}
	if err := r.execute(http.MethodGet, path, nil, &cert); err != nil {
		return model.Cert{}, err
	}
	return cert, nil
}

func (r *RestClient) AddRootCert(cert string) (model.Cert, error) {
	path := "/root_cert"
	req := cert_authority.AddRootCertificateRequest{
		Cert: cert,
	}

	returnedCert := model.Cert{}
	if err := r.execute(http.MethodPost, path, util.StructToJSONReader(req), &returnedCert); err != nil {
		return model.Cert{}, err
	}
	return returnedCert, nil
}

func (r *RestClient) RevokeRootCert(certID string) (model.Cert, error) {
	path := fmt.Sprintf("/root_cert/%s", certID)
	returnedCert := model.Cert{}
	if err := r.execute(http.MethodDelete, path, nil, &returnedCert); err != nil {
		return returnedCert, err
	}
	return returnedCert, nil
}

func (r *RestClient) AddCACert(cmd *CACertAddCmd) (model.Cert, error) {
	path := "/ca_cert"

	req := cert_authority.CreateCACertificateSigningRequestRequest{
		Country:            cmd.Country,
		Organization:       cmd.Org,
		OrganizationalUnit: cmd.Unit,
		CommonName:         cmd.CommonName,
		PrivateKeyOption: eblpkix.PrivateKeyOption{
			KeyType:   cmd.KeyType,
			CurveType: cmd.CurveType,
			BitLength: cmd.BitLength,
		},
	}

	returnedCert := model.Cert{}
	if err := r.execute(http.MethodPost, path, util.StructToJSONReader(req), &returnedCert); err != nil {
		return returnedCert, err
	}
	return returnedCert, nil
}

func (r *RestClient) RespondCACert(certID string, cert string) (model.Cert, error) {
	path := fmt.Sprintf("/ca_cert/%s", certID)
	req := cert_authority.RespondCACertificateSigningRequestRequest{
		Cert: cert,
	}

	returnedCert := model.Cert{}
	if err := r.execute(http.MethodPost, path, util.StructToJSONReader(req), &returnedCert); err != nil {
		return returnedCert, err
	}
	return returnedCert, nil
}

func (r *RestClient) AddCert(cmd *CertAddCmd) (model.Cert, error) {
	path := "/cert"

	req := cert_authority.AddCertificateSigningRequestRequest{
		CertType:           cmd.CertType,
		CertSigningRequest: string(cmd.CSR),
	}

	returnedCert := model.Cert{}
	if err := r.execute(http.MethodPost, path, util.StructToJSONReader(req), &returnedCert); err != nil {
		return returnedCert, err
	}
	return returnedCert, nil
}

func (r *RestClient) IssueCert(cmd *CertIssueCmd) (model.Cert, error) {
	path := fmt.Sprintf("/cert/%s", cmd.ID)
	req := cert_authority.IssueCertificateRequest{
		CACertID:  cmd.CACertID,
		CertType:  cmd.CertType,
		NotBefore: cmd.NotBefore.Unix(),
		NotAfter:  cmd.NotAfter.Unix(),
	}

	returnedCert := model.Cert{}
	if err := r.execute(http.MethodPost, path, util.StructToJSONReader(req), &returnedCert); err != nil {
		return returnedCert, err
	}
	return returnedCert, nil
}

func (r *RestClient) RejectCert(certID string, certType model.CertType, reason string) (model.Cert, error) {
	path := fmt.Sprintf("/cert/%s/reject", certID)
	req := cert_authority.RejectCertificateSigningRequestRequest{
		CertType: certType,
		Reason:   reason,
	}

	returnedCert := model.Cert{}
	if err := r.execute(http.MethodPost, path, util.StructToJSONReader(req), &returnedCert); err != nil {
		return returnedCert, err
	}
	return returnedCert, nil
}

func (r *RestClient) execute(method, path string, body io.Reader, result any) error {
	endPoint := r.server + path
	req, err := http.NewRequest(method, endPoint, body)
	if err != nil {
		return err
	}
	req.Header.Set(api.REQUESTER_HEADER, r.requester)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	status := resp.StatusCode
	if status/100 != 2 {
		message, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("request failed with status %d, message: %s", status, string(message))
	}

	if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
		return err
	}
	return nil
}
