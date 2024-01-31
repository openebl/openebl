package cert_authority

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/pkix"
)

type CertAuthority interface {
	AddCertificate(ctx context.Context, ts int64, req AddCertificateRequest) (model.Cert, error)
	ListCertificates(ctx context.Context, ts int64, req ListCertificatesRequest) ([]model.Cert, error)
	IssueCertificate(ctx context.Context, ts int64, req IssueCertificateRequest) (x509.Certificate, error)
}

type CertStorage interface {
	CreateTx(ctx context.Context, options ...storage.CreateTxOption) (storage.Tx, error)
	AddCertificate(ctx context.Context, tx storage.Tx, cert model.Cert) error
	ListCertificates(ctx context.Context, tx storage.Tx, req ListCertificatesRequest) ([]model.Cert, error)
}

type AddCertificateRequest struct {
	Requester  string `json:"requester"`   // Who makes the request.
	Cert       string `json:"cert"`        // PEM encoded certificate.
	PrivateKey string `json:"private_key"` // PEM encoded private key.
}

type ListCertificatesRequest struct {
	Offset int `json:"offset"` // Offset of the list.
	Limit  int `json:"limit"`  // Limit of the list.

	// Filter by type of the certificate.
	IDs []string `json:"ids"` // List of IDs of the certificates to be listed.
}

type IssueCertificateRequest struct {
	CACertID           string                  `json:"ca_cert_id"` // ID of the CA certificate.
	CertificateRequest x509.CertificateRequest `json:"certificate_request"`
	NotBefore          time.Time
	NotAfter           time.Time
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
	return model.Cert{}, errors.New("not implemented")
}

func (ca *_CertAuthority) ListCertificates(ctx context.Context, ts int64, req ListCertificatesRequest) ([]model.Cert, error) {
	return nil, errors.New("not implemented")
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
	caCert, err := pkix.ParseCertificate([]byte(cert.Certificate))
	if err != nil {
		return x509.Certificate{}, err
	}
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

	newCertRaw, err := x509.CreateCertificate(rand.Reader, &certTemplate, caCert, req.CertificateRequest.PublicKey, privateKey)
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
