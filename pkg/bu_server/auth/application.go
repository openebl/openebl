// Package auth provides functionality for managing applications and their authentication.

package auth

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/util"
)

// ApplicationStatus represents the status of an application.
type ApplicationStatus string

const (
	ApplicationStatusActive   = ApplicationStatus("active")
	ApplicationStatusInactive = ApplicationStatus("inactive")
)

// Application represents an application. It's the client of BU server.
type Application struct {
	ID      string            `json:"id"`      // Unique identifier of the application.
	Version int64             `json:"version"` // Version number of the application.
	Status  ApplicationStatus `json:"status"`  // Status of the application.

	CreatedAt int64  `json:"created_at"` // Unix Time (in second) when the application was created.
	CreatedBy string `json:"created_by"` // User who created the application.
	UpdatedAt int64  `json:"updated_at"` // Unix Time (in second) when the application was last updated.
	UpdatedBy string `json:"updated_by"` // User who last updated the application.

	Name         string   `json:"name"`          // Name of the application.
	CompanyName  string   `json:"company_name"`  // Name of the company associated with the application.
	Addresses    []string `json:"addresses"`     // List of addresses associated with the application.
	Emails       []string `json:"emails"`        // List of emails associated with the application.
	PhoneNumbers []string `json:"phone_numbers"` // List of phone numbers associated with the application.
}

type ApplicationManager interface {
	CreateApplication(ctx context.Context, ts int64, req CreateApplicationRequest) (Application, error)
	ListApplications(ctx context.Context, req ListApplicationRequest) (ListApplicationResult, error)
	UpdateApplication(ctx context.Context, ts int64, req UpdateApplicationRequest) (Application, error)
	ActivateApplication(ctx context.Context, ts int64, req ActivateApplicationRequest) (Application, error)
	DeactivateApplication(ctx context.Context, ts int64, req DeactivateApplicationRequest) (Application, error)
}
type RequestUser struct {
	User string `json:"user"` // User who makes the request.
}
type CreateApplicationRequest struct {
	RequestUser

	Name         string   `json:"name"`          // Name of the application.
	CompanyName  string   `json:"company_name"`  // Name of the company associated with the application.
	Addresses    []string `json:"addresses"`     // List of addresses associated with the application.
	Emails       []string `json:"emails"`        // List of emails associated with the application.
	PhoneNumbers []string `json:"phone_numbers"` // List of phone numbers associated with the application.
}
type UpdateApplicationRequest struct {
	CreateApplicationRequest

	ID string `json:"id"` // Unique identifier of the application.
}
type ActivateApplicationRequest struct {
	RequestUser
	ApplicationID string `json:"application_id"` // Unique identifier of the application.
}
type DeactivateApplicationRequest ActivateApplicationRequest

// ApplicationStorage represents a storage interface for managing applications.
type ApplicationStorage interface {
	CreateTx(ctx context.Context, options ...storage.CreateTxOption) (storage.Tx, context.Context, error)
	StoreApplication(ctx context.Context, tx storage.Tx, app Application) error
	ListApplication(ctx context.Context, tx storage.Tx, req ListApplicationRequest) (ListApplicationResult, error)
}
type ListApplicationRequest struct {
	Offset int // Offset for pagination.
	Limit  int // Limit for pagination.

	IDs      []string            // Filter by application ID.
	Statuses []ApplicationStatus // Filter by status.
}
type ListApplicationResult struct {
	Total        int           `json:"total"` // Total number of applications.
	Applications []Application `json:"apps"`  // List of Applications.
}

type _ApplicationManager struct {
	storage ApplicationStorage
}

func NewApplicationManager(s ApplicationStorage) ApplicationManager {
	return &_ApplicationManager{storage: s}
}

func (m *_ApplicationManager) CreateApplication(ctx context.Context, ts int64, req CreateApplicationRequest) (Application, error) {
	if err := ValidateCreateApplicationRequest(req); err != nil {
		return Application{}, err
	}

	app := Application{
		ID:           fmt.Sprintf("app_%s", util.NewUUID()),
		Version:      1,
		Status:       ApplicationStatusInactive,
		CreatedAt:    ts,
		CreatedBy:    req.User,
		UpdatedAt:    ts,
		UpdatedBy:    req.User,
		Name:         req.Name,
		CompanyName:  req.CompanyName,
		Addresses:    req.Addresses,
		Emails:       req.Emails,
		PhoneNumbers: req.PhoneNumbers,
	}

	tx, ctx, err := m.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return Application{}, fmt.Errorf("failed to create transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	if err := m.storage.StoreApplication(ctx, tx, app); err != nil {
		return Application{}, fmt.Errorf("failed to store application: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return Application{}, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return app, nil
}

func (m *_ApplicationManager) ListApplications(ctx context.Context, req ListApplicationRequest) (ListApplicationResult, error) {
	tx, ctx, err := m.storage.CreateTx(ctx)
	if err != nil {
		return ListApplicationResult{}, fmt.Errorf("failed to create transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	return m.storage.ListApplication(ctx, tx, req)
}

func (m *_ApplicationManager) UpdateApplication(ctx context.Context, ts int64, req UpdateApplicationRequest) (Application, error) {
	if err := ValidateUpdateApplicationRequest(req); err != nil {
		return Application{}, err
	}
	tx, ctx, err := m.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return Application{}, fmt.Errorf("failed to create transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	app, err := m.getApplication(ctx, tx, req.ID)
	if err != nil {
		return Application{}, fmt.Errorf("failed to get application: %w", err)
	}

	app.Version += 1
	app.UpdatedAt = ts
	app.UpdatedBy = req.User
	app.Name = req.Name
	app.CompanyName = req.CompanyName
	app.Addresses = req.Addresses
	app.Emails = req.Emails
	app.PhoneNumbers = req.PhoneNumbers

	if err := m.storage.StoreApplication(ctx, tx, app); err != nil {
		return Application{}, fmt.Errorf("failed to store application: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return Application{}, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return app, nil
}

func (m *_ApplicationManager) ActivateApplication(ctx context.Context, ts int64, req ActivateApplicationRequest) (Application, error) {
	if err := ValidateActivateApplicationRequest(req); err != nil {
		return Application{}, err
	}
	tx, ctx, err := m.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return Application{}, fmt.Errorf("failed to create transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	app, err := m.getApplication(ctx, tx, req.ApplicationID)
	if err != nil {
		return Application{}, fmt.Errorf("failed to get application: %w", err)
	}

	app.Version += 1
	app.UpdatedAt = ts
	app.UpdatedBy = req.User
	app.Status = ApplicationStatusActive

	if err := m.storage.StoreApplication(ctx, tx, app); err != nil {
		return Application{}, fmt.Errorf("failed to store application: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return Application{}, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return app, nil
}

func (m *_ApplicationManager) DeactivateApplication(ctx context.Context, ts int64, req DeactivateApplicationRequest) (Application, error) {
	if err := ValidateActivateApplicationRequest(ActivateApplicationRequest(req)); err != nil {
		return Application{}, err
	}
	tx, ctx, err := m.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return Application{}, fmt.Errorf("failed to create transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	app, err := m.getApplication(ctx, tx, req.ApplicationID)
	if err != nil {
		return Application{}, fmt.Errorf("failed to get application: %w", err)
	}

	app.Version += 1
	app.UpdatedAt = ts
	app.UpdatedBy = req.User
	app.Status = ApplicationStatusInactive

	if err := m.storage.StoreApplication(ctx, tx, app); err != nil {
		return Application{}, fmt.Errorf("failed to store application: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return Application{}, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return app, nil
}

func (m *_ApplicationManager) getApplication(ctx context.Context, tx storage.Tx, id string) (Application, error) {
	req := ListApplicationRequest{
		Limit: 1,
		IDs:   []string{id},
	}
	res, err := m.storage.ListApplication(ctx, tx, req)
	if err != nil {
		return Application{}, err
	}
	if len(res.Applications) == 0 {
		return Application{}, model.ErrApplicationNotFound
	}
	return res.Applications[0], nil
}
