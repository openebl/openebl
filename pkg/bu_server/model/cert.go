package model

type CertStatus string
type CertType string

const (
	CertStatusActive  CertStatus = "active"
	CertStatusRevoked CertStatus = "revoked"

	CACert CertType = "ca"
	BUCert CertType = "business_unit"
)

type Cert struct {
	ID      string     `json:"id"`      // Unique ID of the certificate.
	Version int64      `json:"version"` // Version of the certificate.
	Type    CertType   `json:"type"`    // Type of the certificate.
	Status  CertStatus `json:"status"`  // Status of the certificate.

	CreatedAt int64  `json:"created_at"` // Unix Time (in second) when the certificate was created.
	CreatedBy string `json:"created_by"` // User who created the certificate.
	RevokedAt int64  `json:"revoked_at"` // Unix Time (in second) when the certificate was revoked.
	RevokedBy string `json:"revoked_by"` // User who revoked the certificate.

	PrivateKey      string `json:"private_key"`      // PEM encoded private key.
	Certificate     string `json:"certificate"`      // PEM encoded certificate. It may contains multiple certificates. The first certificate is the leaf certificate. Others are intermediate certificates.
	CertFingerPrint string `json:"cert_fingerprint"` // Fingerprint of the leaf certificate. The format is [HASH_ALGORITHM]:[FINGERPRINT_HEX_ENCODED].
}
