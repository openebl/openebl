package cert_authority

import (
	"fmt"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/openebl/openebl/pkg/bu_server/model"
)

func ValidateAddCertificateRequest(req AddCertificateRequest) error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.Requester, validation.Required),
		validation.Field(&req.Cert, validation.Required),
		validation.Field(&req.PrivateKey, validation.Required),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}
	return nil
}

func ValidateRevokeCertificateRequest(req RevokeCertificateRequest) error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.Requester, validation.Required),
		validation.Field(&req.CertID, validation.Required),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}
	return nil
}

func ValidateListCertificatesRequest(req ListCertificatesRequest) error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.Limit, validation.Required),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}
	return nil
}

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
