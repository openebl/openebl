package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/did"
	"github.com/openebl/openebl/pkg/util"
)

// BUClient is a client for interacting with the Business Unit server's REST API
type BUClient struct {
	serverURL string
	requester string
	apiKey    string
	client    *http.Client
}

// NewBUClient creates a new Business Unit client
func NewBUClient(serverURL, requester string, apiKey string) *BUClient {
	return &BUClient{
		serverURL: serverURL,
		requester: requester,
		apiKey:    apiKey,
		client:    &http.Client{},
	}
}

// CreateBusinessUnit creates a new business unit
func (c *BUClient) CreateBusinessUnit(bu *model.BusinessUnit) (*model.BusinessUnit, error) {
	type createRequest struct {
		Requester    string   `json:"requester"`
		Name         string   `json:"name"`
		Addresses    []string `json:"addresses"`
		Country      string   `json:"country"`
		Emails       []string `json:"emails"`
		PhoneNumbers []string `json:"phone_numbers"`
		Status       string   `json:"status"`
	}

	req := createRequest{
		Requester:    c.requester,
		Name:         bu.Name,
		Addresses:    bu.Addresses,
		Country:      bu.Country,
		Emails:       bu.Emails,
		PhoneNumbers: bu.PhoneNumbers,
		Status:       string(bu.Status),
	}

	var result model.BusinessUnit
	err := c.execute(http.MethodPost, "/business_unit", util.StructToJSONReader(req), &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// CreateBUAuthentication creates a new authentication for a business unit
func (c *BUClient) CreateBUAuthentication(buID did.DID, keyType string, bitLength int) (*model.BusinessUnitAuthentication, error) {
	type privateKeyOption struct {
		KeyType   string `json:"key_type"`
		BitLength int    `json:"bit_length,omitempty"`
		CurveType string `json:"curve_type,omitempty"`
	}

	type createRequest struct {
		Requester        string           `json:"requester"`
		PrivateKeyOption privateKeyOption `json:"private_key_option"`
	}

	pko := privateKeyOption{
		KeyType: keyType,
	}

	if keyType == "RSA" {
		pko.BitLength = bitLength
	} else if keyType == "ECDSA" {
		pko.CurveType = "P-256" // Default curve
	}

	req := createRequest{
		Requester:        c.requester,
		PrivateKeyOption: pko,
	}

	path := fmt.Sprintf("/business_unit/%s/authentication", buID.String())
	var result model.BusinessUnitAuthentication
	err := c.execute(http.MethodPost, path, util.StructToJSONReader(req), &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// GetBUAuthentication retrieves a business unit authentication by ID
func (c *BUClient) GetBUAuthentication(buID did.DID, authID string) (*model.BusinessUnitAuthentication, error) {
	path := fmt.Sprintf("/business_unit/%s/authentication/%s", buID.String(), authID)
	var result model.BusinessUnitAuthentication
	err := c.execute(http.MethodGet, path, nil, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdateBUAuthentication updates a business unit authentication with certificate
func (c *BUClient) UpdateBUAuthentication(buID did.DID, authID, certificate string) (*model.BusinessUnitAuthentication, error) {
	type updateRequest struct {
		Requester   string `json:"requester"`
		Certificate string `json:"certificate"`
	}

	req := updateRequest{
		Requester:   c.requester,
		Certificate: certificate,
	}

	path := fmt.Sprintf("/business_unit/%s/authentication/%s", buID.String(), authID)
	var result model.BusinessUnitAuthentication
	err := c.execute(http.MethodPost, path, util.StructToJSONReader(req), &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// execute performs an HTTP request and unmarshals the response
func (c *BUClient) execute(method, path string, body io.Reader, result interface{}) error {
	url := c.serverURL + path
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Add API key as Bearer token if provided
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

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
