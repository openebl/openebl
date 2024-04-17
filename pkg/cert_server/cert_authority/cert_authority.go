package cert_authority

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"github.com/openebl/openebl/pkg/cert_server/model"
	"github.com/openebl/openebl/pkg/cert_server/storage"
	eblpkix "github.com/openebl/openebl/pkg/pkix"
)

type CertAuthority interface {
	ListCertificate(ctx context.Context, req storage.ListCertificatesRequest) (storage.ListCertificatesResponse, error)

	// AddCertificate adds a root certificate into the system.
	AddRootCertificate(ctx context.Context, ts int64, req AddRootCertificateRequest) (model.Cert, error)

	// Revoke a root certificate.
	RevokeRootCertificate(ctx context.Context, ts int64, req RevokeCertificateRequest) (model.Cert, error)

	// CA Certificate Signing Request (CSR) operations.
	// CrateCACertificateSigningRequest creates a CSR for the CA certificate of the cert server.
	CreateCACertificateSigningRequest(ctx context.Context, ts int64, req CreateCACertificateSigningRequestRequest) (model.Cert, error)
	// RespondCACertificateSigningRequest responds to a CSR for the CA certificate of the cert server. The response is the CA certificate.
	// The certificate will be used in issuing certificates for business units or immediate CAs.
	RespondCACertificateSigningRequest(ctx context.Context, ts int64, req RespondCACertificateSigningRequestRequest) (model.Cert, error)

	// Certificate Signing Request (CSR) operations.
	AddCertificateSigningRequest(ctx context.Context, ts int64, req AddCertificateSigningRequestRequest) (model.Cert, error)
	IssueCertificate(ctx context.Context, ts int64, req IssueCertificateRequest) (model.Cert, error)
	RejectCertificateSigningRequest(ctx context.Context, ts int64, req RejectCertificateSigningRequestRequest) (model.Cert, error)
}

type AddRootCertificateRequest struct {
	Requester string `json:"requester"` // Who makes the request.
	Cert      string `json:"cert"`      // PEM encoded certificate. It may contains multiple certificates. The first certificate is root certificate for the server. Others are intermediate certificates of the root certificate.
}

type RevokeCertificateRequest struct {
	Requester string `json:"requester"` // Who makes the request.
	CertID    string `json:"cert_id"`   // ID of the certificate to be revoked.
}

type CreateCACertificateSigningRequestRequest struct {
	Requester string `json:"requester"` // Who makes the request.

	PrivateKeyOption eblpkix.PrivateKeyOption `json:"private_key_option"` // Option of the private key.

	// Subject of the certificate.
	Country            []string `json:"country"`             // Countries of the organization.
	Organization       []string `json:"organization"`        // Organizations of the certificate.
	OrganizationalUnit []string `json:"organizational_unit"` // Organizational units of the certificate.
	CommonName         string   `json:"common_name"`         // Common name of the certificate.
}

type RespondCACertificateSigningRequestRequest struct {
	Requester string `json:"requester"` // Who makes the request.
	CertID    string `json:"cert_id"`   // ID of the certificate to be responded.
	Cert      string `json:"cert"`      // PEM encoded certificate. It may contains multiple certificates. The first certificate is the leaf certificate. Others are intermediate certificates.
}

type AddCertificateSigningRequestRequest struct {
	Requester          string         `json:"requester"`            // Who makes the request.
	CertType           model.CertType `json:"cert_type"`            // Type of the certificate.
	CertSigningRequest string         `json:"cert_signing_request"` // PEM encoded certificate signing request (CSR).
}

type IssueCertificateRequest struct {
	Requester string         `json:"requester"`  // Who makes the request.
	CACertID  string         `json:"ca_cert_id"` // ID of the CA certificate.
	CertID    string         `json:"cert_id"`    // ID of the certificate to be issued.
	CertType  model.CertType `json:"cert_type"`  // Type of the certificate. It can be only third_party_ca or business_unit.
	NotBefore int64          `json:"not_before"` // Unix Time (in second) when the certificate becomes valid.
	NotAfter  int64          `json:"not_after"`  // Unix Time (in second) when the certificate becomes invalid.
}

type RejectCertificateSigningRequestRequest struct {
	Requester string         `json:"requester"` // Who makes the request.
	CertID    string         `json:"cert_id"`   // ID of the certificate to be rejected.
	CertType  model.CertType `json:"cert_type"` // Type of the certificate. It can be only third_party_ca or business_unit.
	Reason    string         `json:"reason"`    // Reason of the rejection.
}

type _CertAuthority struct {
	certStorage storage.CertStorage
}

func NewCertAuthority(certStorage storage.CertStorage) *_CertAuthority {
	return &_CertAuthority{
		certStorage: certStorage,
	}
}

func (ca *_CertAuthority) ListCertificate(ctx context.Context, req storage.ListCertificatesRequest) (storage.ListCertificatesResponse, error) {
	if err := ValidateListCertificatesRequest(req); err != nil {
		return storage.ListCertificatesResponse{}, err
	}

	tx, ctx, err := ca.certStorage.CreateTx(ctx)
	if err != nil {
		return storage.ListCertificatesResponse{}, err
	}
	defer tx.Rollback(ctx)

	result, err := ca.certStorage.ListCertificates(ctx, tx, req)
	if err != nil {
		return storage.ListCertificatesResponse{}, err
	}
	for i := range result.Certs {
		result.Certs[i].PrivateKey = "" // Do not return the private key.
	}
	return result, nil
}

func (ca *_CertAuthority) AddRootCertificate(ctx context.Context, ts int64, req AddRootCertificateRequest) (model.Cert, error) {
	if err := ValidateAddRootCertificateRequest(req); err != nil {
		return model.Cert{}, err
	}

	certs, err := eblpkix.ParseCertificate([]byte(req.Cert))
	if err != nil {
		return model.Cert{}, err
	}

	cert := model.Cert{
		ID:                      uuid.NewString(),
		Version:                 1,
		Type:                    model.RootCert,
		CreatedBy:               req.Requester,
		CreatedAt:               ts,
		Status:                  model.CertStatusActive,
		NotBefore:               certs[0].NotBefore.Unix(),
		NotAfter:                certs[0].NotAfter.Unix(),
		PublicKeyID:             eblpkix.GetSubjectKeyIDFromCertificate(certs[0]),
		IssuerKeyID:             hex.EncodeToString(certs[0].AuthorityKeyId),
		Certificate:             req.Cert,
		CertFingerPrint:         fmt.Sprintf("sha1:%x", sha1.Sum(certs[0].Raw)),
		CertificateSerialNumber: certs[0].SerialNumber.String(),
	}

	tx, ctx, err := ca.certStorage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return model.Cert{}, err
	}
	defer tx.Rollback(ctx)

	if err := ca.certStorage.AddCertificate(ctx, tx, cert); err != nil {
		return model.Cert{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.Cert{}, err
	}

	cert.PrivateKey = "" // Do not return the private key.
	return cert, nil
}

func (ca *_CertAuthority) RevokeRootCertificate(ctx context.Context, ts int64, req RevokeCertificateRequest) (model.Cert, error) {
	if err := ValidateRevokeCertificateRequest(req); err != nil {
		return model.Cert{}, err
	}

	tx, ctx, err := ca.certStorage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return model.Cert{}, err
	}
	defer tx.Rollback(ctx)

	cert, err := ca.getCert(ctx, tx, req.CertID, []model.CertType{model.RootCert})
	if err != nil {
		return model.Cert{}, err
	}

	if cert.Status == model.CertStatusRevoked {
		return model.Cert{}, fmt.Errorf("certificate %s is already revoked %w", req.CertID, model.ErrWrongStatus)
	}

	cert.Status = model.CertStatusRevoked
	cert.Version += 1
	cert.RevokedAt = ts
	cert.RevokedBy = req.Requester

	if err := ca.certStorage.AddCertificate(ctx, tx, cert); err != nil {
		return model.Cert{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.Cert{}, err
	}

	cert.PrivateKey = "" // Do not return the private key.
	return cert, nil
}

func (ca *_CertAuthority) CreateCACertificateSigningRequest(ctx context.Context, ts int64, req CreateCACertificateSigningRequestRequest) (model.Cert, error) {
	if err := ValidateCreateCACertificateSigningRequestRequest(req); err != nil {
		return model.Cert{}, err
	}

	privKey, err := eblpkix.CreatePrivateKey(req.PrivateKeyOption)
	if errors.Is(err, eblpkix.ErrInvalidParameter) {
		return model.Cert{}, model.ErrInvalidParameter
	} else if err != nil {
		return model.Cert{}, err
	}
	privKeyPEM, err := eblpkix.MarshalPrivateKey(privKey)
	if err != nil {
		return model.Cert{}, err
	}

	csr, err := eblpkix.CreateCertificateSigningRequest(privKey, req.Country, req.Organization, req.OrganizationalUnit, req.CommonName)
	if err != nil {
		return model.Cert{}, err
	}

	cert := model.Cert{
		ID:                        uuid.NewString(),
		Version:                   1,
		Type:                      model.CACert,
		Status:                    model.CertStatusWaitingForIssued,
		CreatedBy:                 req.Requester,
		CreatedAt:                 ts,
		PrivateKey:                privKeyPEM,
		CertificateSigningRequest: string(csr),
	}

	tx, ctx, err := ca.certStorage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return model.Cert{}, err
	}
	defer tx.Rollback(ctx)

	if err := ca.certStorage.AddCertificate(ctx, tx, cert); err != nil {
		return model.Cert{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.Cert{}, err
	}

	cert.PrivateKey = "" // Do not return the private key.
	return cert, nil
}

func (ca *_CertAuthority) RespondCACertificateSigningRequest(ctx context.Context, ts int64, req RespondCACertificateSigningRequestRequest) (model.Cert, error) {
	if err := ValidateRespondCACertificateSigningRequestRequest(req); err != nil {
		return model.Cert{}, err
	}

	cert, err := eblpkix.ParseCertificate([]byte(req.Cert))
	if err != nil {
		return model.Cert{}, fmt.Errorf("failed to parse certificate: %s%w", err.Error(), model.ErrInvalidParameter)
	}
	if len(cert) == 0 {
		return model.Cert{}, fmt.Errorf("certificate is empty %w", model.ErrInvalidParameter)
	}

	tx, ctx, err := ca.certStorage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return model.Cert{}, err
	}
	defer tx.Rollback(ctx)

	if err := ca.validateCert(ctx, tx, cert); err != nil {
		return model.Cert{}, fmt.Errorf("failed to validate certificate: %s%w", err.Error(), model.ErrInvalidParameter)
	}

	oldCert, err := ca.getCert(ctx, tx, req.CertID, []model.CertType{model.CACert})
	if err != nil {
		return model.Cert{}, err
	}
	if oldCert.Status != model.CertStatusWaitingForIssued {
		return model.Cert{}, fmt.Errorf("certificate %s is not waiting for issued %w", req.CertID, model.ErrWrongStatus)
	}
	privKey, err := eblpkix.ParsePrivateKey([]byte(oldCert.PrivateKey))
	if err != nil {
		return model.Cert{}, err
	}
	if !eblpkix.IsPublicKeyOf(privKey, cert[0].PublicKey) {
		return model.Cert{}, fmt.Errorf("certificate %s is not matched with the private key %w", req.CertID, model.ErrInvalidParameter)
	}
	if cert[0].KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature|x509.KeyUsageCRLSign) == 0 {
		return model.Cert{}, fmt.Errorf("certificate %s is not a CA certificate %w", req.CertID, model.ErrInvalidParameter)
	}

	hashValue := sha1.Sum(cert[0].Raw)
	newCert := oldCert
	newCert.Version += 1
	newCert.Status = model.CertStatusActive
	newCert.IssuedAt = ts
	newCert.IssuedBy = req.Requester
	newCert.PublicKeyID = eblpkix.GetSubjectKeyIDFromCertificate(cert[0])
	newCert.IssuerKeyID = hex.EncodeToString(cert[0].AuthorityKeyId)
	newCert.Certificate = req.Cert
	newCert.NotBefore = cert[0].NotBefore.Unix()
	newCert.NotAfter = cert[0].NotAfter.Unix()
	newCert.CertFingerPrint = fmt.Sprintf("sha1:%x", hashValue)
	newCert.CertificateSerialNumber = cert[0].SerialNumber.String()

	if err := ca.certStorage.AddCertificate(ctx, tx, newCert); err != nil {
		return model.Cert{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.Cert{}, err
	}

	newCert.PrivateKey = "" // Do not return the private key.
	return newCert, nil
}

func (ca *_CertAuthority) AddCertificateSigningRequest(ctx context.Context, ts int64, req AddCertificateSigningRequestRequest) (model.Cert, error) {
	if err := ValidateAddCertificateSigningRequestRequest(req); err != nil {
		return model.Cert{}, err
	}

	_, err := eblpkix.ParseCertificateRequest([]byte(req.CertSigningRequest))
	if err != nil {
		return model.Cert{}, err
	}

	cert := model.Cert{
		ID:                        uuid.NewString(),
		Version:                   1,
		Type:                      req.CertType,
		Status:                    model.CertStatusWaitingForIssued,
		CreatedBy:                 req.Requester,
		CreatedAt:                 ts,
		CertificateSigningRequest: req.CertSigningRequest,
	}

	tx, ctx, err := ca.certStorage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return model.Cert{}, err
	}
	defer tx.Rollback(ctx)

	if err := ca.certStorage.AddCertificate(ctx, tx, cert); err != nil {
		return model.Cert{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.Cert{}, err
	}

	cert.PrivateKey = "" // Do not return the private key.
	return cert, nil
}

func (ca *_CertAuthority) IssueCertificate(ctx context.Context, ts int64, req IssueCertificateRequest) (model.Cert, error) {
	if err := ValidateIssueCertificateRequest(req); err != nil {
		return model.Cert{}, err
	}

	tx, ctx, err := ca.certStorage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return model.Cert{}, err
	}
	defer tx.Rollback(ctx)

	caCert, err := ca.getCert(ctx, tx, req.CACertID, []model.CertType{model.CACert})
	if err != nil {
		return model.Cert{}, fmt.Errorf("CACert Error: %w", err)
	}
	if caCert.Status != model.CertStatusActive {
		return model.Cert{}, fmt.Errorf("CA certificate %s is not active %w", req.CACertID, model.ErrWrongStatus)
	}
	caCertPrivKey, err := eblpkix.ParsePrivateKey([]byte(caCert.PrivateKey))
	if err != nil {
		return model.Cert{}, err
	}
	caCertCert, err := eblpkix.ParseCertificate([]byte(caCert.Certificate))
	if err != nil {
		return model.Cert{}, err
	} else if len(caCertCert) == 0 {
		return model.Cert{}, fmt.Errorf("CA certificate %s is empty", req.CACertID)
	}
	if caCertCert[0].NotBefore.Unix() > req.NotBefore || caCertCert[0].NotAfter.Unix() < req.NotAfter {
		return model.Cert{}, fmt.Errorf("CA Cert valid range not fit into the request: %w", model.ErrInvalidParameter)
	}

	cert, err := ca.getCert(ctx, tx, req.CertID, []model.CertType{req.CertType})
	if err != nil {
		return model.Cert{}, fmt.Errorf("getCert Error: %w", err)
	}
	if cert.Status != model.CertStatusWaitingForIssued {
		return model.Cert{}, fmt.Errorf("certificate %s is not waiting for issued %w", req.CertID, model.ErrWrongStatus)
	}

	csr, err := eblpkix.ParseCertificateRequest([]byte(cert.CertificateSigningRequest))
	if err != nil {
		return model.Cert{}, err
	}

	caCert.Version += 1
	caCert.IssuedSerialNumber += 1
	certTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(caCert.IssuedSerialNumber),
		Subject:               csr.Subject,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		NotBefore:             time.Unix(req.NotBefore, 0),
		NotAfter:              time.Unix(req.NotAfter, 0),
	}
	if req.CertType == model.ThirdPartyCACert {
		certTemplate.IsCA = true
		certTemplate.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}

	rawCert, err := x509.CreateCertificate(rand.Reader, &certTemplate, caCertCert[0], csr.PublicKey, caCertPrivKey)
	if err != nil {
		return model.Cert{}, fmt.Errorf("fail to CreateCertificate: %w", err)
	}
	leafCert, err := x509.ParseCertificate(rawCert)
	if err != nil {
		return model.Cert{}, fmt.Errorf("fail to ParseCertificate: %w", err)
	}
	intermediateCerts, err := eblpkix.ParseCertificate([]byte(caCert.Certificate))
	if err != nil {
		return model.Cert{}, fmt.Errorf("fail to ParseCertificate: %w", err)
	}
	certChain := append([]*x509.Certificate{leafCert}, intermediateCerts...)
	certPem, err := eblpkix.MarshalCertificates(certChain...)
	if err != nil {
		return model.Cert{}, fmt.Errorf("fail to MarshalCertificates: %w", err)
	}

	cert.Version += 1
	cert.IssuedAt = ts
	cert.IssuedBy = req.Requester
	cert.Status = model.CertStatusActive
	cert.PublicKeyID = eblpkix.GetSubjectKeyIDFromCertificate(leafCert)
	cert.IssuerKeyID = hex.EncodeToString(leafCert.AuthorityKeyId)
	cert.Certificate = string(certPem)
	cert.NotBefore = leafCert.NotBefore.Unix()
	cert.NotAfter = leafCert.NotAfter.Unix()
	cert.CertFingerPrint = fmt.Sprintf("sha1:%x", sha1.Sum(leafCert.Raw))
	cert.CertificateSerialNumber = leafCert.SerialNumber.String()

	if err := ca.certStorage.AddCertificate(ctx, tx, caCert); err != nil {
		return model.Cert{}, err
	}
	if err := ca.certStorage.AddCertificate(ctx, tx, cert); err != nil {
		return model.Cert{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.Cert{}, err
	}

	cert.PrivateKey = "" // Do not return the private key.
	return cert, nil
}

func (ca *_CertAuthority) RejectCertificateSigningRequest(ctx context.Context, ts int64, req RejectCertificateSigningRequestRequest) (model.Cert, error) {
	if err := ValidateRejectCertificateSigningRequestRequest(req); err != nil {
		return model.Cert{}, err
	}

	tx, ctx, err := ca.certStorage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return model.Cert{}, err
	}
	defer tx.Rollback(ctx)

	cert, err := ca.getCert(ctx, tx, req.CertID, []model.CertType{req.CertType})
	if err != nil {
		return model.Cert{}, err
	}
	if cert.Status != model.CertStatusWaitingForIssued {
		return model.Cert{}, fmt.Errorf("certificate %s is not waiting for issued %w", req.CertID, model.ErrWrongStatus)
	}

	cert.Status = model.CertStatusRejected
	cert.Version += 1
	cert.RejectedAt = ts
	cert.RejectedBy = req.Requester
	cert.RejectReason = req.Reason

	if err := ca.certStorage.AddCertificate(ctx, tx, cert); err != nil {
		return model.Cert{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.Cert{}, err
	}

	cert.PrivateKey = "" // Do not return the private key.
	return cert, nil
}

func (ca *_CertAuthority) getCert(ctx context.Context, tx storage.Tx, certID string, certTypes []model.CertType) (model.Cert, error) {
	req := storage.ListCertificatesRequest{
		IDs:   []string{certID},
		Types: certTypes,
		Limit: 1,
	}

	resp, err := ca.certStorage.ListCertificates(ctx, tx, req)
	if err != nil {
		return model.Cert{}, err
	}

	if len(resp.Certs) == 0 {
		return model.Cert{}, model.ErrCertNotFound
	}

	return resp.Certs[0], nil
}

func (ca *_CertAuthority) validateCert(ctx context.Context, tx storage.Tx, certs []*x509.Certificate) error {
	// Pool all the active root certificates.
	req := storage.ListCertificatesRequest{
		Types:    []model.CertType{model.RootCert},
		Statuses: []model.CertStatus{model.CertStatusActive},
		Limit:    100,
	}

	rootCerts := make([]*x509.Certificate, 0, 100)
	for {
		resp, err := ca.certStorage.ListCertificates(ctx, tx, req)
		if err != nil {
			return err
		}
		if len(resp.Certs) == 0 {
			break
		}

		for _, cert := range resp.Certs {
			certs, err := eblpkix.ParseCertificate([]byte(cert.Certificate))
			if err != nil {
				return err
			}
			if len(certs) == 0 {
				return fmt.Errorf("certificate %s is empty", cert.ID)
			}
			rootCerts = append(rootCerts, certs[0])
		}

		req.Offset += len(resp.Certs)
		if req.Offset >= int(resp.Total) {
			break
		}
	}

	return eblpkix.Verify(certs, rootCerts, time.Now().Unix())
}
