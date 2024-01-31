// Package business_unit implement the management functions of business unit.
package business_unit

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/nuts-foundation/go-did/did"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/storage"
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
}

// CreateBusinessUnitRequest is the request to create a business unit.
type CreateBusinessUnitRequest struct {
	Requester     string `json:"requester"`      // User who makes the request.
	ApplicationID string `json:"application_id"` // The ID of the application this BusinessUnit belongs to.

	Name         string                   `json:"name"`          // Name of the BusinessUnit.
	Addresses    []string                 `json:"addresses"`     // List of addresses associated with the BusinessUnit.
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
	Requester      string  `json:"requester"`      // User who makes the request.
	ApplicationID  string  `json:"application_id"` // The ID of the application this BusinessUnit belongs to.
	BusinessUnitID did.DID `json:"id"`             // Unique DID of a BusinessUnit.
	PrivateKey     string  `json:"private_key"`    // PEM encoded private key.
	Certificate    string  `json:"certificate"`    // PEM encoded certificate.
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

type _BusinessUnitManager struct {
	storage BusinessUnitStorage
}

func NewBusinessUnitManager(storage BusinessUnitStorage) *_BusinessUnitManager {
	return &_BusinessUnitManager{
		storage: storage,
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
	bu.Name = req.Name
	bu.Addresses = req.Addresses
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

	tx, err := m.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return model.BusinessUnitAuthentication{}, err
	}
	defer tx.Rollback(ctx)

	auth := model.BusinessUnitAuthentication{
		ID:           uuid.NewString(),
		Version:      1,
		BusinessUnit: req.BusinessUnitID,
		Status:       model.BusinessUnitAuthenticationStatusActive,
		CreatedAt:    ts,
		CreatedBy:    req.Requester,
		PrivateKey:   req.PrivateKey,
		Certificate:  req.Certificate,
	}

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
