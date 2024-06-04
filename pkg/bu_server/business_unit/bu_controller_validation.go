package business_unit

import (
	"fmt"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	eblpkix "github.com/openebl/openebl/pkg/pkix"
)

func ValidateCreateBusinessUnitRequest(req CreateBusinessUnitRequest) error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.Requester, validation.Required),
		validation.Field(&req.ApplicationID, validation.Required),
		validation.Field(&req.Name, validation.Required),
		validation.Field(&req.Status, validation.Required),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	return nil
}

func ValidateUpdateBusinessUnitRequest(req UpdateBusinessUnitRequest) error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.Requester, validation.Required),
		validation.Field(&req.ApplicationID, validation.Required),
		validation.Field(&req.ID, validation.Required),
		validation.Field(&req.Name, validation.Required),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	return nil
}

func ValidateListBusinessUnitRequest(req storage.ListBusinessUnitsRequest) error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.Limit, validation.Min(1)),
		validation.Field(&req.Offset, validation.Min(0)),
		validation.Field(&req.ApplicationID, validation.Required),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	return nil
}

func ValidateSetBusinessUnitStatusRequest(req SetBusinessUnitStatusRequest) error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.Requester, validation.Required),
		validation.Field(&req.ID, validation.Required),
		validation.Field(&req.Status, validation.Required),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	return nil
}

func ValidateAddAuthenticationRequest(req AddAuthenticationRequest) error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.Requester, validation.Required),
		validation.Field(&req.ApplicationID, validation.Required),
		validation.Field(&req.BusinessUnitID, validation.Required),
		validation.Field(&req.PrivateKeyOption, validation.Required),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	privateKeyOption := req.PrivateKeyOption
	if err := validation.ValidateStruct(&privateKeyOption,
		validation.Field(&privateKeyOption.KeyType, validation.Required, validation.In(eblpkix.PrivateKeyTypeRSA, eblpkix.PrivateKeyTypeECDSA)),
		validation.Field(&privateKeyOption.BitLength, validation.Required.When(privateKeyOption.KeyType == eblpkix.PrivateKeyTypeRSA)),
		validation.Field(&privateKeyOption.CurveType, validation.Required.When(privateKeyOption.KeyType == eblpkix.PrivateKeyTypeECDSA)),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	return nil
}

func ValidateRevokeAuthenticationRequest(req RevokeAuthenticationRequest) error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.Requester, validation.Required),
		validation.Field(&req.ApplicationID, validation.Required),
		validation.Field(&req.BusinessUnitID, validation.Required),
		validation.Field(&req.AuthenticationID, validation.Required),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	return nil
}

func ValidateListAuthenticationRequest(req storage.ListAuthenticationRequest) error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.Limit, validation.Min(1)),
		validation.Field(&req.Offset, validation.Min(0)),
		validation.Field(&req.ApplicationID, validation.Required),
		validation.Field(&req.BusinessUnitID, validation.Required),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	return nil
}
