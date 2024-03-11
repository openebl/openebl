// Package business_unit implement the management functions of business unit.
package business_unit

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/nuts-foundation/go-did/did"
	"github.com/openebl/openebl/pkg/bu_server/cert_authority"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/envelope"
	eblpkix "github.com/openebl/openebl/pkg/pkix"
)

// BusinessUnitManager is the interface that wraps the basic management functions of business unit.
type BusinessUnitManager interface {
	CreateBusinessUnit(ctx context.Context, ts int64, req CreateBusinessUnitRequest) (model.BusinessUnit, error)
	UpdateBusinessUnit(ctx context.Context, ts int64, req UpdateBusinessUnitRequest) (model.BusinessUnit, error)
	ListBusinessUnits(ctx context.Context, req ListBusinessUnitsRequest) (ListBusinessUnitsResult, error)
	SetStatus(ctx context.Context, ts int64, req SetBusinessUnitStatusRequest) (model.BusinessUnit, error)
	AddAuthentication(ctx context.Context, ts int64, req AddAuthenticationRequest) (model.BusinessUnitAuthentication, error)
	RevokeAuthentication(ctx context.Context, ts int64, req RevokeAuthenticationRequest) (model.BusinessUnitAuthentication, error)
	ListAuthentication(ctx context.Context, req ListAuthenticationRequest) (ListAuthenticationResult, error)
	GetJWSSigner(ctx context.Context, req GetJWSSignerRequest) (JWSSigner, error)
}

type JWSSigner interface {
	// Public returns the public key corresponding to the opaque,
	// private key.
	Public() crypto.PublicKey

	// Sign signs digest with the private key, possibly using entropy from
	// rand. For an RSA key, the resulting signature should be either a
	// PKCS #1 v1.5 or PSS signature (as indicated by opts). For an (EC)DSA
	// key, it should be a DER-serialised, ASN.1 signature structure.
	//
	// Hash implements the SignerOpts interface and, in most cases, one can
	// simply pass in the hash function used as opts. Sign may also attempt
	// to type assert opts to other types in order to obtain algorithm
	// specific values. See the documentation in each package for details.
	//
	// Note that when a signature of a hash of a larger message is needed,
	// the caller is responsible for hashing the larger message and passing
	// the hash (as digest) and the hash function (as opts) to Sign.
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)

	AvailableJWSSignAlgorithms() []envelope.SignatureAlgorithm
	Cert() []*x509.Certificate
}

// CreateBusinessUnitRequest is the request to create a business unit.
type CreateBusinessUnitRequest struct {
	Requester     string `json:"requester"`      // User who makes the request.
	ApplicationID string `json:"application_id"` // The ID of the application this BusinessUnit belongs to.

	Name         string                   `json:"name"`          // Name of the BusinessUnit.
	Addresses    []string                 `json:"addresses"`     // List of addresses associated with the BusinessUnit.
	Country      string                   `json:"country"`       // Country Code of the BusinessUnit. (Eg: US, TW, JP)
	Emails       []string                 `json:"emails"`        // List of emails associated with the BusinessUnit.
	PhoneNumbers []string                 `json:"phone_numbers"` // List of phone numbers associated with the BusinessUnit.
	Status       model.BusinessUnitStatus `json:"status"`        // Status of the application.
}

// UpdateBusinessUnitRequest is the request to update a business unit.
type UpdateBusinessUnitRequest struct {
	Requester     string   `json:"requester"`      // User who makes the request.
	ApplicationID string   `json:"application_id"` // The ID of the application this BusinessUnit belongs to.
	ID            did.DID  `json:"id"`             // Unique DID of a BusinessUnit.
	Name          string   `json:"name"`           // Name of the BusinessUnit.
	Addresses     []string `json:"addresses"`      // List of addresses associated with the BusinessUnit.
	Country       string   `json:"country"`        // Country Code of the BusinessUnit. (Eg: US, TW, JP)
	Emails        []string `json:"emails"`         // List of emails associated with the BusinessUnit.
	PhoneNumbers  []string `json:"phone_numbers"`  // List of phone numbers associated with the BusinessUnit.
}

// ListBusinessUnitsRequest is the request to list business units.
type ListBusinessUnitsRequest struct {
	Offset int `json:"offset"` // Offset of the business units to be listed.
	Limit  int `json:"limit"`  // Limit of the business units to be listed.

	// Filters
	ApplicationID   string   `json:"application_id"`    // The ID of the application this BusinessUnit belongs to.
	BusinessUnitIDs []string `json:"business_unit_ids"` // The IDs of the business units.
}

// ListBusinessUnitsRecord is the record of a business unit.
type ListBusinessUnitsRecord struct {
	BusinessUnit    model.BusinessUnit                 `json:"business_unit"`   // The business unit.
	Authentications []model.BusinessUnitAuthentication `json:"authentications"` // The authentications of the business unit.
}

// ListBusinessUnitsResult is the result of listing business units.
type ListBusinessUnitsResult struct {
	Total   int                       `json:"total"`   // Total number of business units.
	Records []ListBusinessUnitsRecord `json:"records"` // Records of business units.
}

// SetBusinessUnitStatusRequest is the request to set the status of a business unit.
type SetBusinessUnitStatusRequest struct {
	Requester     string                   `json:"requester"`      // User who makes the request.
	ApplicationID string                   `json:"application_id"` // The ID of the application this BusinessUnit belongs to.
	ID            did.DID                  `json:"id"`             // Unique DID of a BusinessUnit.
	Status        model.BusinessUnitStatus `json:"status"`         // Status of the application.
}

// AddAuthenticationRequest is the request to add an authentication to a business unit.
type AddAuthenticationRequest struct {
	Requester        string           `json:"requester"`          // User who makes the request.
	ApplicationID    string           `json:"application_id"`     // The ID of the application this BusinessUnit belongs to.
	BusinessUnitID   did.DID          `json:"id"`                 // Unique DID of a BusinessUnit.
	PrivateKeyOption PrivateKeyOption `json:"private_key_option"` // Option of the private key.
	ExpiredAfter     int64            `json:"expired_after"`      // How long (in second) the authentication/certificate will be valid.
}

type PrivateKeyType string // PrivateKeyType is the type of the private key.
type ECDSACurveType string

const (
	PrivateKeyTypeRSA   PrivateKeyType = "RSA"
	PrivateKeyTypeECDSA PrivateKeyType = "ECDSA"

	ECDSACurveTypeP256 ECDSACurveType = "P-256"
	ECDSACurveTypeP384 ECDSACurveType = "P-384"
	ECDSACurveTypeP521 ECDSACurveType = "P-521"
)

type PrivateKeyOption struct {
	KeyType   PrivateKeyType `json:"key_type"`   // Type of the private key.
	BitLength int            `json:"bit_length"` // Bit length of the private key. Only used when KeyType is RSA.
	CurveType ECDSACurveType `json:"curve_type"` // Curve type of the private key. Only used when KeyType is ECDSA.
}

// RevokeAuthenticationRequest is the request to revoke an authentication from a business unit.
type RevokeAuthenticationRequest struct {
	Requester        string  `json:"requester"`         // User who makes the request.
	ApplicationID    string  `json:"application_id"`    // The ID of the application this BusinessUnit belongs to.
	BusinessUnitID   did.DID `json:"id"`                // Unique DID of a BusinessUnit.
	AuthenticationID string  `json:"authentication_id"` // Unique ID of the authentication.
}

// ListAuthenticationRequest is the request to list authentications.
type ListAuthenticationRequest struct {
	Offset int `json:"offset"` // Offset of the authentications to be listed.
	Limit  int `json:"limit"`  // Limit of the authentications to be listed.

	// Filters
	ApplicationID     string   `json:"application_id"`     // The ID of the application this BusinessUnit belongs to.
	BusinessUnitID    string   `json:"id"`                 // Unique DID of a BusinessUnit.
	AuthenticationIDs []string `json:"authentication_ids"` // Unique IDs of the authentications.
}

// ListAuthenticationResult is the result of listing authentications.
type ListAuthenticationResult struct {
	Total   int                                `json:"total"`   // Total number of authentications.
	Records []model.BusinessUnitAuthentication `json:"records"` // Records of authentications.
}

type GetJWSSignerRequest struct {
	ApplicationID    string  `json:"application_id"`    // The ID of the application this BusinessUnit belongs to.
	BusinessUnitID   did.DID `json:"id"`                // Unique DID of a BusinessUnit.
	AuthenticationID string  `json:"authentication_id"` // Unique ID of the authentication.
}

type _BusinessUnitManager struct {
	ca               cert_authority.CertAuthority
	storage          BusinessUnitStorage
	jwsSignerFactory JWSSignerFactory
}

func NewBusinessUnitManager(storage BusinessUnitStorage, ca cert_authority.CertAuthority, jwsSignerFactory JWSSignerFactory) *_BusinessUnitManager {
	return &_BusinessUnitManager{
		ca:               ca,
		storage:          storage,
		jwsSignerFactory: jwsSignerFactory,
	}
}

func (m *_BusinessUnitManager) CreateBusinessUnit(ctx context.Context, ts int64, req CreateBusinessUnitRequest) (model.BusinessUnit, error) {
	if err := ValidateCreateBusinessUnitRequest(req); err != nil {
		return model.BusinessUnit{}, err
	}

	bu := model.BusinessUnit{
		ID: did.DID{
			Method: model.DIDMethod,
			ID:     uuid.NewString(),
		},
		ApplicationID: req.ApplicationID,
		Version:       1,
		Status:        req.Status,
		Name:          req.Name,
		Addresses:     req.Addresses,
		Country:       req.Country,
		Emails:        req.Emails,
		PhoneNumbers:  req.PhoneNumbers,
		CreatedAt:     ts,
		CreatedBy:     req.Requester,
		UpdatedAt:     ts,
		UpdatedBy:     req.Requester,
	}

	tx, err := m.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return model.BusinessUnit{}, err
	}
	defer tx.Rollback(ctx)

	if err := m.storage.StoreBusinessUnit(ctx, tx, bu); err != nil {
		return model.BusinessUnit{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return model.BusinessUnit{}, err
	}
	return bu, nil
}

func (m *_BusinessUnitManager) UpdateBusinessUnit(ctx context.Context, ts int64, req UpdateBusinessUnitRequest) (model.BusinessUnit, error) {
	if err := ValidateUpdateBusinessUnitRequest(req); err != nil {
		return model.BusinessUnit{}, err
	}

	tx, err := m.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return model.BusinessUnit{}, err
	}
	defer tx.Rollback(ctx)

	bu, err := m.getBusinessUnit(ctx, tx, req.ApplicationID, req.ID)
	if err != nil {
		return model.BusinessUnit{}, err
	}
	bu.Version += 1
	bu.Name = req.Name
	bu.Addresses = req.Addresses
	bu.Country = req.Country
	bu.Emails = req.Emails
	bu.PhoneNumbers = req.PhoneNumbers
	bu.UpdatedAt = ts
	bu.UpdatedBy = req.Requester

	if err := m.storage.StoreBusinessUnit(ctx, tx, bu); err != nil {
		return model.BusinessUnit{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return model.BusinessUnit{}, err
	}
	return bu, nil
}

func (m *_BusinessUnitManager) ListBusinessUnits(ctx context.Context, req ListBusinessUnitsRequest) (ListBusinessUnitsResult, error) {
	if err := ValidateListBusinessUnitRequest(req); err != nil {
		return ListBusinessUnitsResult{}, err
	}

	tx, err := m.storage.CreateTx(ctx)
	if err != nil {
		return ListBusinessUnitsResult{}, err
	}
	defer tx.Rollback(ctx)

	result, err := m.storage.ListBusinessUnits(ctx, tx, req)
	if err != nil {
		return ListBusinessUnitsResult{}, err
	}
	for i := range result.Records {
		for j := range result.Records[i].Authentications {
			result.Records[i].Authentications[j].PrivateKey = "" // Erase PrivateKey before returning.
		}
	}
	return result, err
}

func (m *_BusinessUnitManager) SetStatus(ctx context.Context, ts int64, req SetBusinessUnitStatusRequest) (model.BusinessUnit, error) {
	if err := ValidateSetBusinessUnitStatusRequest(req); err != nil {
		return model.BusinessUnit{}, err
	}

	tx, err := m.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return model.BusinessUnit{}, err
	}
	defer tx.Rollback(ctx)

	listReq := ListBusinessUnitsRequest{
		Limit:         1,
		ApplicationID: req.ApplicationID,
		BusinessUnitIDs: []string{
			req.ID.String(),
		},
	}
	listResult, err := m.storage.ListBusinessUnits(ctx, tx, listReq)
	if err != nil {
		return model.BusinessUnit{}, err
	}
	if len(listResult.Records) == 0 {
		return model.BusinessUnit{}, model.ErrBusinessUnitNotFound
	}

	bu := listResult.Records[0].BusinessUnit
	bu.Version += 1
	bu.Status = req.Status
	bu.UpdatedAt = ts
	bu.UpdatedBy = req.Requester

	if err := m.storage.StoreBusinessUnit(ctx, tx, bu); err != nil {
		return model.BusinessUnit{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return model.BusinessUnit{}, err
	}
	return bu, nil
}

func (m *_BusinessUnitManager) AddAuthentication(ctx context.Context, ts int64, req AddAuthenticationRequest) (model.BusinessUnitAuthentication, error) {
	if err := ValidateAddAuthenticationRequest(req); err != nil {
		return model.BusinessUnitAuthentication{}, err
	}

	privateKey, err := m.createPrivateKey(ctx, req.PrivateKeyOption)
	if err != nil {
		return model.BusinessUnitAuthentication{}, err
	}

	oldBu, err := m.getBusinessUnit(ctx, nil, req.ApplicationID, req.BusinessUnitID)
	if err != nil {
		return model.BusinessUnitAuthentication{}, err
	}
	if oldBu.Status != model.BusinessUnitStatusActive {
		return model.BusinessUnitAuthentication{}, model.ErrBusinessUnitInActive
	}
	certificateRequest, err := m.createCertificateRequest(ctx, privateKey, oldBu)
	if err != nil {
		return model.BusinessUnitAuthentication{}, err
	}

	caRequest := cert_authority.IssueCertificateRequest{
		CACertID:           "__root__",
		CertificateRequest: certificateRequest,
		NotBefore:          time.Unix(ts, 0),
		NotAfter:           time.Unix(ts+req.ExpiredAfter, 0),
	}
	cert, err := m.ca.IssueCertificate(ctx, ts, caRequest)
	if err != nil {
		return model.BusinessUnitAuthentication{}, err
	}

	auth := model.BusinessUnitAuthentication{
		ID:           uuid.NewString(),
		Version:      1,
		BusinessUnit: req.BusinessUnitID,
		Status:       model.BusinessUnitAuthenticationStatusActive,
		CreatedAt:    ts,
		CreatedBy:    req.Requester,
	}
	auth.PrivateKey, err = eblpkix.MarshalPrivateKey(privateKey)
	if err != nil {
		return model.BusinessUnitAuthentication{}, err
	}
	auth.Certificate, err = eblpkix.MarshalCertificates(cert)
	if err != nil {
		return model.BusinessUnitAuthentication{}, err
	}

	tx, err := m.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return model.BusinessUnitAuthentication{}, err
	}
	defer tx.Rollback(ctx)

	if err := m.storage.StoreAuthentication(ctx, tx, auth); err != nil {
		return model.BusinessUnitAuthentication{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return model.BusinessUnitAuthentication{}, err
	}

	auth.PrivateKey = "" // Erase PrivateKey before returning.
	return auth, nil
}

func (m *_BusinessUnitManager) RevokeAuthentication(ctx context.Context, ts int64, req RevokeAuthenticationRequest) (model.BusinessUnitAuthentication, error) {
	if err := ValidateRevokeAuthenticationRequest(req); err != nil {
		return model.BusinessUnitAuthentication{}, err
	}

	tx, err := m.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return model.BusinessUnitAuthentication{}, err
	}
	defer tx.Rollback(ctx)

	listReq := ListAuthenticationRequest{
		Limit:          1,
		ApplicationID:  req.ApplicationID,
		BusinessUnitID: req.BusinessUnitID.String(),
		AuthenticationIDs: []string{
			req.AuthenticationID,
		},
	}
	listResult, err := m.storage.ListAuthentication(ctx, tx, listReq)
	if err != nil {
		return model.BusinessUnitAuthentication{}, err
	}
	if len(listResult.Records) == 0 {
		return model.BusinessUnitAuthentication{}, model.ErrAuthenticationNotFound
	}

	auth := listResult.Records[0]
	if auth.Status == model.BusinessUnitAuthenticationStatusRevoked {
		auth.PrivateKey = "" // Erase PrivateKey before returning.
		return auth, nil     // Already revoked.
	}

	auth.Version += 1
	auth.Status = model.BusinessUnitAuthenticationStatusRevoked
	auth.RevokedAt = ts
	auth.RevokedBy = req.Requester

	if err := m.storage.StoreAuthentication(ctx, tx, auth); err != nil {
		return model.BusinessUnitAuthentication{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return model.BusinessUnitAuthentication{}, err
	}

	auth.PrivateKey = "" // Erase PrivateKey before returning.
	return auth, nil
}

func (m *_BusinessUnitManager) ListAuthentication(ctx context.Context, req ListAuthenticationRequest) (ListAuthenticationResult, error) {
	if err := ValidateListAuthenticationRequest(req); err != nil {
		return ListAuthenticationResult{}, err
	}

	tx, err := m.storage.CreateTx(ctx)
	if err != nil {
		return ListAuthenticationResult{}, err
	}
	defer tx.Rollback(ctx)

	result, err := m.storage.ListAuthentication(ctx, tx, req)
	if err != nil {
		return ListAuthenticationResult{}, err
	}

	for i := range result.Records {
		result.Records[i].PrivateKey = "" // Erase PrivateKey before returning.
	}
	return result, nil
}

func (m _BusinessUnitManager) GetJWSSigner(ctx context.Context, req GetJWSSignerRequest) (JWSSigner, error) {
	auth, err := func() (model.BusinessUnitAuthentication, error) {
		tx, err := m.storage.CreateTx(ctx)
		if err != nil {
			return model.BusinessUnitAuthentication{}, err
		}
		defer tx.Rollback(ctx)

		listReq := ListAuthenticationRequest{
			Limit:          1,
			ApplicationID:  req.ApplicationID,
			BusinessUnitID: req.BusinessUnitID.String(),
			AuthenticationIDs: []string{
				req.AuthenticationID,
			},
		}
		listResult, err := m.storage.ListAuthentication(ctx, tx, listReq)
		if err != nil {
			return model.BusinessUnitAuthentication{}, err
		}
		if len(listResult.Records) == 0 {
			return model.BusinessUnitAuthentication{}, model.ErrAuthenticationNotFound
		}

		return listResult.Records[0], nil
	}()

	if err != nil {
		return nil, err
	}

	if auth.Status != model.BusinessUnitAuthenticationStatusActive {
		return nil, model.ErrAuthenticationNotActive
	}

	if m.jwsSignerFactory == nil {
		return DefaultJWSSignerFactory.NewJWSSigner(auth)
	}
	return m.jwsSignerFactory.NewJWSSigner(auth)
}

func (m *_BusinessUnitManager) getBusinessUnit(ctx context.Context, tx storage.Tx, appID string, id did.DID) (model.BusinessUnit, error) {
	if tx == nil {
		newTx, err := m.storage.CreateTx(ctx)
		if err != nil {
			return model.BusinessUnit{}, err
		}
		defer newTx.Rollback(ctx)
		tx = newTx
	}
	req := ListBusinessUnitsRequest{
		Limit:         1,
		ApplicationID: appID,
		BusinessUnitIDs: []string{
			id.String(),
		},
	}
	result, err := m.storage.ListBusinessUnits(ctx, tx, req)
	if err != nil {
		return model.BusinessUnit{}, err
	}
	if len(result.Records) == 0 {
		return model.BusinessUnit{}, model.ErrBusinessUnitNotFound
	}
	return result.Records[0].BusinessUnit, nil
}

// createPrivateKey will return a private key. The type will be *rsa.PrivateKey or *ecdsa.PrivateKey.
func (m *_BusinessUnitManager) createPrivateKey(ctx context.Context, opt PrivateKeyOption) (any, error) {
	switch opt.KeyType {
	case PrivateKeyTypeRSA:
		return rsa.GenerateKey(rand.Reader, opt.BitLength)
	case PrivateKeyTypeECDSA:
		switch opt.CurveType {
		case ECDSACurveTypeP256:
			return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case ECDSACurveTypeP384:
			return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		case ECDSACurveTypeP521:
			return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		default:
			return nil, model.ErrInvalidParameter
		}
	default:
		return nil, model.ErrInvalidParameter
	}
}

func (m *_BusinessUnitManager) createCertificateRequest(ctx context.Context, privateKey interface{}, bu model.BusinessUnit) (x509.CertificateRequest, error) {
	certRequestTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			Country:      []string{bu.Country},
			Organization: []string{bu.Name},
			CommonName:   bu.ID.String(),
		},
	}

	csrRaw, err := x509.CreateCertificateRequest(rand.Reader, &certRequestTemplate, privateKey)
	if err != nil {
		return x509.CertificateRequest{}, err
	}

	csr, err := x509.ParseCertificateRequest(csrRaw)
	if err != nil {
		return x509.CertificateRequest{}, err
	}

	return *csr, nil
}
