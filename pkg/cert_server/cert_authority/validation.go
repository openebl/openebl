package cert_authority

import (
	"fmt"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/openebl/openebl/pkg/cert_server/model"
	"github.com/openebl/openebl/pkg/cert_server/storage"
	eblpkix "github.com/openebl/openebl/pkg/pkix"
)

func ValidateListCertificatesRequest(req storage.ListCertificatesRequest) error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.Offset, validation.Min(0)),
		validation.Field(&req.Limit, validation.Min(1)),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	return nil
}

func ValidateAddRootCertificateRequest(req AddRootCertificateRequest) error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.Requester, validation.Required),
		validation.Field(&req.Cert, validation.Required),
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

func ValidateCreateCACertificateSigningRequestRequest(req CreateCACertificateSigningRequestRequest) error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.Requester, validation.Required),
		validation.Field(&req.PrivateKeyOption, validation.Required),
		validation.Field(&req.Country, validation.Required),
		validation.Field(&req.Organization, validation.Required),
		validation.Field(&req.OrganizationalUnit, validation.Required),
		validation.Field(&req.CommonName, validation.Required),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	privateKeyOption := req.PrivateKeyOption
	if err := validation.ValidateStruct(&privateKeyOption,
		validation.Field(&privateKeyOption.KeyType, validation.Required),
		validation.Field(&privateKeyOption.BitLength, validation.Required.When(privateKeyOption.KeyType == eblpkix.PrivateKeyTypeRSA)),
		validation.Field(&privateKeyOption.CurveType, validation.Required.When(privateKeyOption.KeyType == eblpkix.PrivateKeyTypeECDSA)),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	return nil
}

func ValidateRespondCACertificateSigningRequestRequest(req RespondCACertificateSigningRequestRequest) error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.Requester, validation.Required),
		validation.Field(&req.CertID, validation.Required),
		validation.Field(&req.Cert, validation.Required),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	return nil
}

func ValidateRevokeCACertificateRequest(req RevokeCACertificateRequest) error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.Requester, validation.Required),
		validation.Field(&req.CertID, validation.Required),
		validation.Field(&req.CRL, validation.Required),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	return nil
}

func ValidateAddCertificateSigningRequestRequest(req AddCertificateSigningRequestRequest) error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.Requester, validation.Required),
		validation.Field(&req.CertType, validation.Required, validation.In(model.ThirdPartyCACert, model.BUCert)),
		validation.Field(&req.CertSigningRequest, validation.Required),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	return nil
}

func ValidateIssueCertificateRequest(req IssueCertificateRequest) error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.Requester, validation.Required),
		validation.Field(&req.CACertID, validation.Required),
		validation.Field(&req.CertID, validation.Required),
		validation.Field(&req.CertType, validation.Required, validation.In(model.ThirdPartyCACert, model.BUCert)),
		validation.Field(&req.NotBefore, validation.Required),
		validation.Field(&req.NotAfter, validation.Required),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	return nil
}

func ValidateRejectCertificateSigningRequestRequest(req RejectCertificateSigningRequestRequest) error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.Requester, validation.Required),
		validation.Field(&req.CertID, validation.Required),
		validation.Field(&req.CertType, validation.Required, validation.In(model.ThirdPartyCACert, model.BUCert)),
		validation.Field(&req.Reason, validation.Required),
	); err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}

	return nil
}
