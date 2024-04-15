package model

type CertStatus string
type CertType string

const (
	CertStatusActive           CertStatus = "active"
	CertStatusWaitingForIssued CertStatus = "waiting_for_issued"
	CertStatusRejected         CertStatus = "rejected"
	CertStatusRevoked          CertStatus = "revoked"

	RootCert         CertType = "root"
	CACert           CertType = "ca"
	ThirdPartyCACert CertType = "third_party_ca"
	BUCert           CertType = "business_unit"
)

type Cert struct {
	ID      string     `json:"id"`      // Unique ID of the certificate.
	Version int64      `json:"version"` // Version of the certificate.
	Type    CertType   `json:"type"`    // Type of the certificate.
	Status  CertStatus `json:"status"`  // Status of the certificate.

	NotBefore int64 `json:"not_before"` // Unix Time (in second) when the certificate becomes valid.
	NotAfter  int64 `json:"not_after"`  // Unix Time (in second) when the certificate becomes invalid.

	IssuedSerialNumber int64 `json:"issued_serial_number"` // Serial number of the issued certificate by the CA cert.

	CreatedAt  int64  `json:"created_at"`  // Unix Time (in second) when the certificate was created.
	CreatedBy  string `json:"created_by"`  // User who created the certificate.
	RevokedAt  int64  `json:"revoked_at"`  // Unix Time (in second) when the certificate was revoked.
	RevokedBy  string `json:"revoked_by"`  // User who revoked the certificate.
	IssuedAt   int64  `json:"issued_at"`   // Unix Time (in second) when the certificate was issued.
	IssuedBy   string `json:"issued_by"`   // User who issued the certificate.
	RejectedAt int64  `json:"rejected_at"` // Unix Time (in second) when the certificate was rejected.
	RejectedBy string `json:"rejected_by"` // User who rejected the certificate.

	PrivateKey                string `json:"private_key"`                 // PEM encoded private key.
	PublicKeyID               string `json:"public_key_id"`               // Certificate Public key ID.
	IssuerKeyID               string `json:"issuer_key_id"`               // Issuer public key ID.
	Certificate               string `json:"certificate"`                 // PEM encoded certificate. It may contains multiple certificates. The first certificate is the leaf certificate. Others are intermediate certificates.
	CertificateSerialNumber   string `json:"certificate_serial_number"`   // Serial number of the certificate.
	CertificateSigningRequest string `json:"certificate_signing_request"` // PEM encoded certificate signing request (CSR).
	CertFingerPrint           string `json:"cert_fingerprint"`            // Fingerprint of the leaf certificate. The format is [HASH_ALGORITHM]:[FINGERPRINT_HEX_ENCODED].
	RejectReason              string `json:"reject_reason"`               // Reason for rejecting the certificate signing request.
}
