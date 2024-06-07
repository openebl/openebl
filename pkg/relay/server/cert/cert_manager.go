package cert

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/openebl/openebl/pkg/cert_server/cli"
	cert_model "github.com/openebl/openebl/pkg/cert_server/model"
	eblpkix "github.com/openebl/openebl/pkg/pkix"
	"github.com/openebl/openebl/pkg/relay/server/storage"
	"github.com/openebl/openebl/pkg/util"
	"github.com/sirupsen/logrus"
)

type CertVerifier interface {
	VerifyCert(ctx context.Context, ts int64, certChain []*x509.Certificate) error
}

type CertManager interface {
	SyncRootCerts(ctx context.Context) error
	AddCRL(ctx context.Context, crlRaw []byte) error
}

type _CertManager struct {
	certServerURL string
	certStore     storage.CertDataStore
}

type CertManagerOption func(*_CertManager)

func WithCertServerURL(certServerURL string) CertManagerOption {
	return func(cm *_CertManager) {
		cm.certServerURL = certServerURL
	}
}

func WithCertStore(certStore storage.CertDataStore) CertManagerOption {
	return func(cm *_CertManager) {
		cm.certStore = certStore
	}
}

func NewCertManager(opts ...CertManagerOption) *_CertManager {
	cm := &_CertManager{}
	for _, opt := range opts {
		opt(cm)
	}

	if cm.certStore == nil {
		panic("certStore is required")
	}

	return cm
}

func (cm *_CertManager) VerifyCert(ctx context.Context, ts int64, certChain []*x509.Certificate) error {
	cvh, err := NewCertVerifyHelper(ctx, ts, cm, certChain)
	if err != nil {
		return fmt.Errorf("CertManager::VerifyCert(): fail to NewCertVerifyHelper(): %w", err)
	}

	rootCerts, err := cm.getActiveRootCert(ctx)
	if err != nil {
		return fmt.Errorf("CertManager::VerifyCert(): fail to getActiveRootCert(): %w", err)
	}

	err = eblpkix.Verify(certChain, rootCerts, ts, cvh)
	if err != nil {
		return fmt.Errorf("%s%w", err.Error(), ErrCertInvalid)
	}
	return nil
}

func (cm *_CertManager) SyncRootCerts(ctx context.Context) error {
	if err := cm.syncRootCerts(); err != nil {
		return fmt.Errorf("CertManager::SyncRootCerts(): fail to syncRootCerts(): %w", err)
	}
	return nil
}

func (cm *_CertManager) AddCRL(ctx context.Context, crlRaw []byte) error {
	ts := time.Now().Unix()

	crl, err := eblpkix.ParseCertificateRevocationList(crlRaw)
	if err != nil {
		return fmt.Errorf("CertManager::AddCRL(): fail to ParseCertificateRevocationList(): %s%w", err, ErrInvalidParameter)
	}
	issuerKeyID := eblpkix.GetAuthorityKeyIDFromCertificateRevocationList(crl)

	for _, entry := range crl.RevokedCertificateEntries {
		revokedAt := entry.RevocationTime.Unix()
		serialNumber := entry.SerialNumber.String()
		if err := cm.certStore.AddCRL(ctx, ts, issuerKeyID, serialNumber, revokedAt, crlRaw); err != nil {
			return fmt.Errorf("CertManager::AddCRL(): fail to AddCRL(): %w", err)
		}
	}

	return nil
}

func (cm *_CertManager) syncRootCerts() error {
	client := cli.NewRestClient(cm.certServerURL, "relay_server_cert_manager")

	offset := 0
	for {
		certs, err := client.ListRootCert(offset, 100)
		if err != nil {
			return err
		}
		if len(certs.Certs) == 0 {
			break
		}
		offset += len(certs.Certs)

		if err := cm.storeRootCert(certs.Certs); err != nil {
			return err
		}
	}
	return nil
}

func (cm *_CertManager) storeRootCert(rootCerts []cert_model.Cert) error {
	ctx := context.Background()
	ts := time.Now().Unix()

	for _, rootCertObj := range rootCerts {
		cert, err := eblpkix.ParseCertificate([]byte(rootCertObj.Certificate))
		if err != nil {
			logrus.Errorf("CertManager::storeRootCert(): fail to ParseCertificate(%v): %v", util.StructToJSON(rootCertObj), err)
			continue
		}
		if len(cert) == 0 {
			logrus.Errorf("CertManager::storeRootCert(): empty certificate %v", util.StructToJSON(rootCertObj))
			continue
		}
		fingerPrint := eblpkix.GetFingerPrintFromCertificate(cert[0])

		if rootCertObj.Status == cert_model.CertStatusActive {
			if err := cm.certStore.AddRootCert(ctx, ts, fingerPrint, []byte(rootCertObj.Certificate)); err != nil {
				return fmt.Errorf("CertManager::storeRootCert(): fail to AddRootCert(%v): %w", util.StructToJSON(rootCertObj), err)
			}
		} else if rootCertObj.Status == cert_model.CertStatusRevoked {
			if err := cm.certStore.RevokeRootCert(ctx, ts, fingerPrint); err != nil {
				return fmt.Errorf("CertManager::storeRootCert(): fail to RevokeRootCert(%v): %w", util.StructToJSON(rootCertObj), err)
			}
		}
	}

	return nil
}

func (cm *_CertManager) getActiveRootCert(ctx context.Context) ([]*x509.Certificate, error) {
	certsRaw, err := cm.certStore.GetActiveRootCert(ctx)
	if err != nil {
		return nil, fmt.Errorf("CertManager::GetActiveRootCert(): fail to GetActiveRootCert(): %w", err)
	}
	certs := make([]*x509.Certificate, 0, len(certsRaw))
	for _, certRaw := range certsRaw {
		cert, err := eblpkix.ParseCertificate(certRaw)
		if err != nil {
			logrus.Errorf("CertManager::GetActiveRootCert(): fail to ParseCertificate(): %v", err)
			continue
		}
		if len(cert) == 0 {
			logrus.Errorf("CertManager::GetActiveRootCert(): empty certificate")
			continue
		}
		certs = append(certs, cert[0])
	}
	return certs, nil
}
