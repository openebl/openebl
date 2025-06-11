package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/openebl/openebl/pkg/cert_server/model"
	"github.com/openebl/openebl/pkg/util"
)

// CAClient is a client for interacting with the Certificate Authority server's REST API
type CAClient struct {
	serverURL string
	requester string
	client    *http.Client
}

// NewCAClient creates a new Certificate Authority client
func NewCAClient(serverURL, requester string) *CAClient {
	return &CAClient{
		serverURL: serverURL,
		requester: requester,
		client:    &http.Client{},
	}
}

// AddCert creates a certificate signing request (CSR) for a business unit
func (c *CAClient) AddCert(csr string) (*model.Cert, error) {
	type request struct {
		CertType           model.CertType `json:"cert_type"`
		CertSigningRequest string         `json:"cert_signing_request"`
	}

	req := request{
		CertType:           model.BUCert,
		CertSigningRequest: csr,
	}

	var result model.Cert
	err := c.execute(http.MethodPost, "/cert", util.StructToJSONReader(req), &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// IssueCert issues a certificate for a CSR
func (c *CAClient) IssueCert(certID, caCertID string) (*model.Cert, error) {
	type request struct {
		CertType  model.CertType `json:"cert_type"`
		CACertID  string         `json:"ca_cert_id"`
		NotBefore int64          `json:"not_before"`
		NotAfter  int64          `json:"not_after"`
	}

	// Set validity period: from now to 2 year later
	now := time.Now()
	oneYearLater := now.AddDate(2, 0, 0)

	req := request{
		CertType:  model.BUCert,
		CACertID:  caCertID,
		NotBefore: now.Unix(),
		NotAfter:  oneYearLater.Unix(),
	}

	path := fmt.Sprintf("/cert/%s", certID)
	var result model.Cert
	err := c.execute(http.MethodPost, path, util.StructToJSONReader(req), &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// ListCACerts lists all CA certificates
func (c *CAClient) ListCACerts(offset, limit int) ([]model.Cert, int, error) {
	path := fmt.Sprintf("/ca_cert?offset=%d&limit=%d", offset, limit)

	type response struct {
		Total   int          `json:"total"`
		Records []model.Cert `json:"records"`
	}

	var result response
	err := c.execute(http.MethodGet, path, nil, &result)
	if err != nil {
		return nil, 0, err
	}

	return result.Records, result.Total, nil
}

// GetCert gets a certificate by ID
func (c *CAClient) GetCert(certID string) (*model.Cert, error) {
	path := fmt.Sprintf("/cert/%s", certID)
	var result model.Cert
	err := c.execute(http.MethodGet, path, nil, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// execute performs an HTTP request and unmarshals the response
func (c *CAClient) execute(method, path string, body io.Reader, result interface{}) error {
	url := c.serverURL + path
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Requester", c.requester)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("request failed with status code %d: %s", resp.StatusCode, string(responseBody))
	}

	if result != nil {
		return json.Unmarshal(responseBody, result)
	}

	return nil
}
