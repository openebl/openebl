package model

import "github.com/openebl/openebl/pkg/did"

type BusinessUnitStatus string
type BusinessUnitAuthenticationStatus string

const (
	DIDMethod string = "openebl"

	BusinessUnitStatusActive   BusinessUnitStatus = "active"
	BusinessUnitStatusInactive BusinessUnitStatus = "inactive"

	BusinessUnitAuthenticationStatusPending BusinessUnitAuthenticationStatus = "pending"
	BusinessUnitAuthenticationStatusActive  BusinessUnitAuthenticationStatus = "active"
	BusinessUnitAuthenticationStatusRevoked BusinessUnitAuthenticationStatus = "revoked"
)

type BusinessUnit struct {
	ID            did.DID `json:"id"`             // Unique DID of a BusinessUnit.
	Version       int64   `json:"version"`        // Version of the BusinessUnit.
	ApplicationID string  `json:"application_id"` // The ID of the application this BusinessUnit belongs to.

	Status BusinessUnitStatus `json:"status"` // Status of the application.

	Name         string   `json:"name"`          // Name of the BusinessUnit.
	Addresses    []string `json:"addresses"`     // List of addresses associated with the BusinessUnit.
	Country      string   `json:"country"`       // Country Code of the BusinessUnit. (Eg: US, TW, JP)
	Emails       []string `json:"emails"`        // List of emails associated with the BusinessUnit.
	PhoneNumbers []string `json:"phone_numbers"` // List of phone numbers associated with the BusinessUnit.

	CreatedAt int64  `json:"created_at"` // Unix Time (in second) when the BusinessUnit was created.
	CreatedBy string `json:"created_by"` // User who created the BusinessUnit.
	UpdatedAt int64  `json:"updated_at"` // Unix Time (in second) when the BusinessUnit was last updated.
	UpdatedBy string `json:"updated_by"` // User who last updated the BusinessUnit.
}

type BusinessUnitAuthentication struct {
	ID           string                           `json:"id"`            // Unique ID of the authentication.
	Version      int64                            `json:"version"`       // Version of the authentication.
	BusinessUnit did.DID                          `json:"business_unit"` // Unique DID of a BusinessUnit.
	Status       BusinessUnitAuthenticationStatus `json:"status"`        // Status of the authentication.

	CreatedAt   int64  `json:"created_at"`   // Unix Time (in second) when the authentication was created.
	CreatedBy   string `json:"created_by"`   // User who created the authentication.
	ActivatedAt int64  `json:"activated_at"` // Unix Time (in second) when the authentication was activated.
	RevokedAt   int64  `json:"revoked_at"`   // Unix Time (in second) when the authentication was revoked.
	RevokedBy   string `json:"revoked_by"`   // User who revoked the authentication.

	PrivateKey                string `json:"private_key,omitempty"`       // PEM encoded private key.
	CertificateSigningRequest string `json:"certificate_signing_request"` // PEM encoded certificate signing request (CSR).
	Certificate               string `json:"certificate"`                 // PEM encoded certificate. It may contains multiple certificates. The first certificate is the leaf certificate. Others are intermediate certificates.
	CertFingerPrint           string `json:"cert_fingerprint"`            // Fingerprint of the leaf certificate. The format is [HASH_ALGORITHM]:[FINGERPRINT_HEX_ENCODED].
	PublicKeyID               string `json:"public_key_id"`               // Certificate Public key ID.
	IssuerKeyID               string `json:"issuer_key_id"`               // Issuer public key ID.
	CertificateSerialNumber   string `json:"certificate_serial_number"`   // Serial number of the certificate.
}
