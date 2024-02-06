package cert_authority

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/pkix"
)

type CertAuthority interface {
	// AddCertificate adds a CA certificate into the system.
	AddCertificate(ctx context.Context, ts int64, req AddCertificateRequest) (model.Cert, error)

	// Revoke a CA certificate.
	RevokeCertificate(ctx context.Context, ts int64, req RevokeCertificateRequest) (model.Cert, error)

	ListCertificates(ctx context.Context, req ListCertificatesRequest) ([]model.Cert, error)
	IssueCertificate(ctx context.Context, ts int64, req IssueCertificateRequest) (x509.Certificate, error)
}

type CertStorage interface {
	CreateTx(ctx context.Context, options ...storage.CreateTxOption) (storage.Tx, error)
	AddCertificate(ctx context.Context, tx storage.Tx, cert model.Cert) error
	ListCertificates(ctx context.Context, tx storage.Tx, req ListCertificatesRequest) ([]model.Cert, error)
}

type AddCertificateRequest struct {
	Requester  string `json:"requester"`   // Who makes the request.
	Cert       string `json:"cert"`        // PEM encoded certificate. It may contains multiple certificates. The first certificate is the leaf certificate. Others are intermediate certificates.
	PrivateKey string `json:"private_key"` // PEM encoded private key of the leaf certificate.
}

type RevokeCertificateRequest struct {
	Requester string `json:"requester"` // Who makes the request.
	CertID    string `json:"cert_id"`   // ID of the certificate to be revoked.
}

type ListCertificatesRequest struct {
	Offset int `json:"offset"` // Offset of the list.
	Limit  int `json:"limit"`  // Limit of the list.

	// Filter by type of the certificate.
	IDs      []string           `json:"ids"`      // List of IDs of the certificates to be listed.
	Statuses []model.CertStatus `json:"statuses"` // List of statuses of the certificates to be listed.
}

type IssueCertificateRequest struct {
	CACertID           string                  `json:"ca_cert_id"` // ID of the CA certificate. It's optional. If it's empty, the system choose one available CA certificate.
	CertificateRequest x509.CertificateRequest `json:"certificate_request"`
	NotBefore          time.Time               `json:"not_before"` // When the issued certificate becomes valid.
	NotAfter           time.Time               `json:"not_after"`  // When the issued certificate becomes invalid.
}

type _CertAuthority struct {
	certStorage CertStorage
}

func NewCertAuthority(certStorage CertStorage) *_CertAuthority {
	return &_CertAuthority{
		certStorage: certStorage,
	}
}

func (ca *_CertAuthority) AddCertificate(ctx context.Context, ts int64, req AddCertificateRequest) (model.Cert, error) {
	if err := ValidateAddCertificateRequest(req); err != nil {
		return model.Cert{}, err
	}

	// Validate if private key and certificate are valid.
	privateKeyPtr, err := pkix.ParsePrivateKey([]byte(req.PrivateKey))
	if err != nil {
		return model.Cert{}, fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}
	rsaPrivateKey, _ := privateKeyPtr.(*rsa.PrivateKey)
	ecdsaPrivateKey, _ := privateKeyPtr.(*ecdsa.PrivateKey)
	if rsaPrivateKey == nil && ecdsaPrivateKey == nil {
		return model.Cert{}, fmt.Errorf("invalid private key type%w", model.ErrInvalidParameter)
	}
	if rsaPrivateKey != nil && rsaPrivateKey.N.BitLen() < 2048 {
		return model.Cert{}, fmt.Errorf("invalid private key length%w", model.ErrInvalidParameter)
	}

	certs, err := pkix.ParseCertificate([]byte(req.Cert))
	if err != nil {
		return model.Cert{}, fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}
	cert := certs[0]
	if rsaPrivateKey != nil {
		rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)
		if !rsaPublicKey.Equal(cert.PublicKey) {
			return model.Cert{}, fmt.Errorf("private key and certificate do not match%w", model.ErrInvalidParameter)
		}
	} else if ecdsaPrivateKey != nil {
		ecdsaPublicKey := cert.PublicKey.(*ecdsa.PublicKey)
		if !ecdsaPublicKey.Equal(cert.PublicKey) {
			return model.Cert{}, fmt.Errorf("private key and certificate do not match%w", model.ErrInvalidParameter)
		}
	}
	// End of validating private key and certificate.

	hashValue := sha1.Sum(cert.Raw)
	certData := model.Cert{
		ID:              uuid.NewString(),
		Version:         1,
		Type:            model.BUCert,
		Status:          model.CertStatusActive,
		CreatedAt:       ts,
		CreatedBy:       req.Requester,
		PrivateKey:      req.PrivateKey,
		Certificate:     req.Cert,
		CertFingerPrint: fmt.Sprintf("%s:%x", "sha1", hex.EncodeToString(hashValue[:])),
	}

	tx, err := ca.certStorage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return model.Cert{}, err
	}
	defer tx.Rollback(ctx)

	if err := ca.certStorage.AddCertificate(ctx, tx, certData); err != nil {
		return model.Cert{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.Cert{}, err
	}

	certData.PrivateKey = "" // Erase PrivateKey field before returning because it is sensitive and the user should not touch it anymore.
	return certData, nil
}

func (ca *_CertAuthority) RevokeCertificate(ctx context.Context, ts int64, req RevokeCertificateRequest) (model.Cert, error) {
	if err := ValidateRevokeCertificateRequest(req); err != nil {
		return model.Cert{}, err
	}

	tx, err := ca.certStorage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return model.Cert{}, err
	}
	defer tx.Rollback(ctx)

	cert, err := ca.getCert(ctx, req.CertID, tx)
	if err != nil {
		return model.Cert{}, err
	}

	if cert.Status == model.CertStatusRevoked {
		return cert, nil // Already revoked.
	}
	cert.Version += 1
	cert.Status = model.CertStatusRevoked
	cert.RevokedAt = ts
	cert.RevokedBy = req.Requester
	if err := ca.certStorage.AddCertificate(ctx, tx, cert); err != nil {
		return model.Cert{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return model.Cert{}, err
	}

	cert.PrivateKey = "" // Erase PrivateKey field before returning because it is sensitive and the user should not touch it anymore.
	return cert, nil
}

func (ca *_CertAuthority) ListCertificates(ctx context.Context, req ListCertificatesRequest) ([]model.Cert, error) {
	if err := ValidateListCertificatesRequest(req); err != nil {
		return nil, err
	}

	tx, err := ca.certStorage.CreateTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	result, err := ca.certStorage.ListCertificates(ctx, tx, req)
	if err != nil {
		return nil, err
	}
	for i := range result {
		result[i].PrivateKey = "" // Erase PrivateKey field before returning because it is sensitive and the user should not touch it anymore.
	}
	return result, nil
}

func (ca *_CertAuthority) IssueCertificate(ctx context.Context, ts int64, req IssueCertificateRequest) (x509.Certificate, error) {
	if err := ValidateIssueCertificateRequest(req); err != nil {
		return x509.Certificate{}, err
	}
	if err := req.CertificateRequest.CheckSignature(); err != nil {
		return x509.Certificate{}, fmt.Errorf("invalid certificate request: %s%w", err.Error(), model.ErrInvalidParameter)
	}

	cert, err := ca.getCert(ctx, req.CACertID, nil)
	if err != nil {
		return x509.Certificate{}, err
	}

	privateKey, err := pkix.ParsePrivateKey([]byte(cert.PrivateKey))
	if err != nil {
		return x509.Certificate{}, err
	}
	caCerts, err := pkix.ParseCertificate([]byte(cert.Certificate))
	if err != nil {
		return x509.Certificate{}, err
	}
	caCert := caCerts[0]
	currentTime := time.Unix(ts, 0)
	if currentTime.Before(caCert.NotBefore) || currentTime.After(caCert.NotAfter) {
		return x509.Certificate{}, model.ErrCertificationExpired
	}

	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      req.CertificateRequest.Subject,
		NotBefore:    req.NotBefore,
		NotAfter:     req.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	newCertRaw, err := x509.CreateCertificate(rand.Reader, &certTemplate, &caCert, req.CertificateRequest.PublicKey, privateKey)
	if err != nil {
		return x509.Certificate{}, err
	}

	newCert, err := x509.ParseCertificate(newCertRaw)
	if err != nil {
		return x509.Certificate{}, err
	}
	return *newCert, nil
}

func (ca *_CertAuthority) getCert(ctx context.Context, certID string, tx storage.Tx) (model.Cert, error) {
	if tx == nil {
		newTx, err := ca.certStorage.CreateTx(ctx)
		if err != nil {
			return model.Cert{}, err
		}
		defer newTx.Rollback(ctx)
		tx = newTx
	}

	listReq := ListCertificatesRequest{
		Limit: 1,
		IDs:   []string{certID},
	}
	certs, err := ca.certStorage.ListCertificates(ctx, tx, listReq)
	if err != nil {
		return model.Cert{}, err
	}
	if len(certs) == 0 {
		return model.Cert{}, model.ErrCertificationNotFound
	}

	return certs[0], nil
}
