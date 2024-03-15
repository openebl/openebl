package trade_document

import (
	"fmt"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/model/trade_document/bill_of_lading"
)

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
		validation.Field(&req.AuthenticationID, validation.Required),
		validation.Field(&req.Application, validation.Required),
		validation.Field(&req.File, validation.Required),
		validation.Field(&req.BLNumber, validation.Required),
		validation.Field(&req.BLDocType, validation.Required, validation.In(bill_of_lading.BillOfLadingDocumentTypeHouseBillOfLading)),
		validation.Field(&req.ToOrder, validation.In(false)),
		validation.Field(&req.POL, validation.When(req.Draft != nil && !*req.Draft, validation.Required, &LocationRule{})),
		validation.Field(&req.POD, validation.When(req.Draft != nil && !*req.Draft, validation.Required, &LocationRule{})),
		validation.Field(&req.Issuer, validation.Required),
		validation.Field(&req.Shipper, validation.Required.When(req.Draft != nil && !*req.Draft)),
		validation.Field(&req.Consignee, validation.Required.When(req.Draft != nil && !*req.Draft)),
		validation.Field(&req.ReleaseAgent, validation.Required.When(req.Draft != nil && !*req.Draft)),
		validation.Field(&req.Draft, validation.NotNil),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	return nil
}

func ValidateUpdateFileBasedEBLRequest(req UpdateFileBasedEBLDraftRequest) error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.ID, validation.Required),
		validation.Field(&req.AuthenticationID, validation.Required),
		validation.Field(&req.Application, validation.Required),
		validation.Field(&req.File, validation.Required),
		validation.Field(&req.BLNumber, validation.Required),
		validation.Field(&req.BLDocType, validation.Required, validation.In(bill_of_lading.BillOfLadingDocumentTypeHouseBillOfLading)),
		validation.Field(&req.ToOrder, validation.In(false)),
		validation.Field(&req.POL, validation.When(req.Draft != nil && !*req.Draft, validation.Required, &LocationRule{})),
		validation.Field(&req.POD, validation.When(req.Draft != nil && !*req.Draft, validation.Required, &LocationRule{})),
		validation.Field(&req.Issuer, validation.Required),
		validation.Field(&req.Shipper, validation.Required.When(req.Draft != nil && !*req.Draft)),
		validation.Field(&req.Consignee, validation.Required.When(req.Draft != nil && !*req.Draft)),
		validation.Field(&req.ReleaseAgent, validation.Required.When(req.Draft != nil && !*req.Draft)),
		validation.Field(&req.Draft, validation.NotNil),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	return nil
}

func ValidateReturnFileBasedEBLRequest(req ReturnFileBasedEBLRequest) error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.Application, validation.Required),
		validation.Field(&req.BusinessUnit, validation.Required),
		validation.Field(&req.AuthenticationID, validation.Required),
		validation.Field(&req.ID, validation.Required),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}
	return nil
}

func ValidateListFileBasedEBLRequest(req ListFileBasedEBLRequest) error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.Application, validation.Required),
		validation.Field(&req.RequestBy, validation.Required),
		validation.Field(&req.Offset, validation.Min(0)),
		validation.Field(&req.Limit, validation.Min(1)),
		validation.Field(&req.Status, validation.When(req.Status != "", validation.In("action_needed", "upcoming", "sent", "archive"))),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	return nil
}

func ValidateTransferEBLRequest(req TransferEBLRequest) error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.Application, validation.Required),
		validation.Field(&req.TransferBy, validation.Required),
		validation.Field(&req.AuthenticationID, validation.Required),
		validation.Field(&req.ID, validation.Required),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	return nil
}

func ValidateAmendmentRequestEBLRequest(req AmendmentRequestEBLRequest) error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.Application, validation.Required),
		validation.Field(&req.RequestBy, validation.Required),
		validation.Field(&req.AuthenticationID, validation.Required),
		validation.Field(&req.ID, validation.Required),
		validation.Field(&req.Note, validation.Required),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	return nil
}

func ValidateAmendFileBasedEBLRequest(req AmendFileBasedEBLRequest) error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.Application, validation.Required),
		validation.Field(&req.Issuer, validation.Required),
		validation.Field(&req.AuthenticationID, validation.Required),
		validation.Field(&req.ID, validation.Required),
		validation.Field(&req.File, validation.Required),
		validation.Field(&req.BLNumber, validation.Required),
		validation.Field(&req.BLDocType, validation.Required, validation.In(bill_of_lading.BillOfLadingDocumentTypeHouseBillOfLading)),
		validation.Field(&req.ToOrder, validation.In(false)),
		validation.Field(&req.POL, validation.Required, &LocationRule{}),
		validation.Field(&req.POD, validation.Required, &LocationRule{}),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	return nil
}

func ValidateSurrenderEBLRequest(req SurrenderEBLRequest) error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.Application, validation.Required),
		validation.Field(&req.RequestBy, validation.Required),
		validation.Field(&req.AuthenticationID, validation.Required),
		validation.Field(&req.ID, validation.Required),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	return nil
}

func ValidatePrintFileBasedEBLRequest(req PrintFileBasedEBLToPaperRequest) error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.Application, validation.Required),
		validation.Field(&req.RequestBy, validation.Required),
		validation.Field(&req.AuthenticationID, validation.Required),
		validation.Field(&req.ID, validation.Required),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	return nil
}

func ValidateAccomplishEBLRequest(req AccomplishEBLRequest) error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.Application, validation.Required),
		validation.Field(&req.RequestBy, validation.Required),
		validation.Field(&req.AuthenticationID, validation.Required),
		validation.Field(&req.ID, validation.Required),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	return nil
}

func ValidateDeleteEBLRequest(req DeleteEBLRequest) error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.Application, validation.Required),
		validation.Field(&req.RequestBy, validation.Required),
		validation.Field(&req.ID, validation.Required),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	return nil
}
