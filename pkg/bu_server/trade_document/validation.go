package trade_document

import (
	"fmt"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/openebl/openebl/pkg/bu_server/model"
)

func ValidateLocation(loc Location) error {
	if err := validation.ValidateStruct(&loc,
		validation.Field(&loc.LocationName, validation.Required),
		validation.Field(&loc.UNLocCode, validation.Required),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	return nil
}

type LocationRule struct{}

func (r LocationRule) Validate(value interface{}) error {
	loc, ok := value.(Location)
	if !ok {
		return fmt.Errorf("invalid type: %T", value)
	}

	return validation.ValidateStruct(&loc,
		validation.Field(&loc.LocationName, validation.Required),
		validation.Field(&loc.UNLocCode, validation.Required),
	)
}

func ValidateIssueFileBasedEBLRequest(req IssueFileBasedEBLRequest) error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.Requester, validation.Required),
		validation.Field(&req.AuthenticationID, validation.Required),
		validation.Field(&req.Application, validation.Required),
		validation.Field(&req.File, validation.Required),
		validation.Field(&req.BLNumber, validation.Required),
		validation.Field(&req.BLDocType, validation.Required),
		validation.Field(&req.POL, validation.Required, &LocationRule{}),
		validation.Field(&req.POD, validation.Required, &LocationRule{}),
		validation.Field(&req.ETA, validation.Required),
		validation.Field(&req.Issuer, validation.Required),
		validation.Field(&req.Shipper, validation.Required),
		validation.Field(&req.Consignee, validation.Required),
		validation.Field(&req.ReleaseAgent, validation.Required),
		validation.Field(&req.Draft, validation.NotNil),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	return nil
}

func ValidateUpdateFileBasedEBLRequest(req UpdateFileBasedEBLDraftRequest) error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.ID, validation.Required),
		validation.Field(&req.Requester, validation.Required),
		validation.Field(&req.AuthenticationID, validation.Required),
		validation.Field(&req.Application, validation.Required),
		validation.Field(&req.File, validation.Required),
		validation.Field(&req.BLNumber, validation.Required),
		validation.Field(&req.BLDocType, validation.Required),
		validation.Field(&req.POL, validation.Required, &LocationRule{}),
		validation.Field(&req.POD, validation.Required, &LocationRule{}),
		validation.Field(&req.ETA, validation.Required),
		validation.Field(&req.Issuer, validation.Required),
		validation.Field(&req.Shipper, validation.Required),
		validation.Field(&req.Consignee, validation.Required),
		validation.Field(&req.ReleaseAgent, validation.Required),
		validation.Field(&req.Draft, validation.NotNil),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	return nil
}
