package business_unit

import (
	"context"

	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/storage"
)

type BusinessUnitStorage interface {
	CreateTx(ctx context.Context, options ...storage.CreateTxOption) (storage.Tx, error)
	StoreBusinessUnit(ctx context.Context, tx storage.Tx, bu model.BusinessUnit) error
	ListBusinessUnits(ctx context.Context, tx storage.Tx, req ListBusinessUnitsRequest) (ListBusinessUnitsResult, error)
	StoreAuthentication(ctx context.Context, tx storage.Tx, auth model.BusinessUnitAuthentication) error
	ListAuthentication(ctx context.Context, tx storage.Tx, req ListAuthenticationRequest) (ListAuthenticationResult, error)
}
