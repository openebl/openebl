package cert_authority

import (
	"fmt"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/openebl/openebl/pkg/bu_server/model"
)

func ValidateIssueCertificateRequest(req IssueCertificateRequest) error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.CACertID, validation.Required),
		validation.Field(&req.CertificateRequest, validation.Required),
		validation.Field(&req.NotBefore, validation.Required),
		validation.Field(&req.NotAfter, validation.Required),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}
	return nil
}
