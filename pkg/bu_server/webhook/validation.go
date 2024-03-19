package webhook

import (
	"fmt"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/openebl/openebl/pkg/bu_server/model"
)

func ValidateCreateWebhookRequest(req CreateWebhookRequest) error {
	err := validation.ValidateStruct(&req,
		validation.Field(&req.Requester, validation.Required),
		validation.Field(&req.ApplicationID, validation.Required),
		validation.Field(&req.Events, validation.Required, validation.Each(validation.In(
			model.WebhookEventBLIssued,
			model.WebhookEventBLTransferred,
			model.WebhookEventBLReturned,
			model.WebhookEventBLAmendmentRequested,
			model.WebhookEventBLAmended,
			model.WebhookEventBLSurrendered,
			model.WebhookEventBLAccomplished,
			model.WebhookEventBLPrintedToPaper,
			model.WebhookEventBUCreated,
			model.WebhookEventBUUpdated,
			model.WebhookEventAuthCreated,
			model.WebhookEventAuthRevoked,
		))),
		validation.Field(&req.Secret, validation.Required),
		validation.Field(&req.Url, validation.Required, is.URL),
	)
	if err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	return nil
}

func ValidateListWebhookRequest(req ListWebhookRequest) error {
	err := validation.ValidateStruct(&req,
		validation.Field(&req.Limit, validation.Required),
		validation.Field(&req.ApplicationID, validation.Required),
	)
	if err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	return nil
}

func ValidateUpdateWebhookRequest(req UpdateWebhookRequest) error {
	err := validation.ValidateStruct(&req,
		validation.Field(&req.ID, validation.Required),
		validation.Field(&req.Requester, validation.Required),
		validation.Field(&req.ApplicationID, validation.Required),
		validation.Field(&req.Events, validation.Required, validation.Each(validation.In(
			model.WebhookEventBLIssued,
			model.WebhookEventBLTransferred,
			model.WebhookEventBLReturned,
			model.WebhookEventBLAmendmentRequested,
			model.WebhookEventBLAmended,
			model.WebhookEventBLSurrendered,
			model.WebhookEventBLAccomplished,
			model.WebhookEventBLPrintedToPaper,
			model.WebhookEventBUCreated,
			model.WebhookEventBUUpdated,
			model.WebhookEventAuthCreated,
			model.WebhookEventAuthRevoked,
		))),
		validation.Field(&req.Secret, validation.Required),
		validation.Field(&req.Url, validation.Required, is.URL),
	)
	if err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	return nil
}

func ValidateDeleteWebhookRequest(req DeleteWebhookRequest) error {
	err := validation.ValidateStruct(&req,
		validation.Field(&req.ID, validation.Required),
		validation.Field(&req.Requester, validation.Required),
		validation.Field(&req.ApplicationID, validation.Required),
	)
	if err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	return nil
}
