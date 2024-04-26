package cert

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/cert_server/cli"
	cert_model "github.com/openebl/openebl/pkg/cert_server/model"
	eblpkix "github.com/openebl/openebl/pkg/pkix"
	"github.com/openebl/openebl/pkg/util"
	"github.com/sirupsen/logrus"
)

type CertManager struct {
	certServerURL string
	certStore     storage.CertStorage
}

type CertManagerOption func(*CertManager)

func WithCertServerURL(certServerURL string) CertManagerOption {
	return func(cm *CertManager) {
		cm.certServerURL = certServerURL
	}
}

func WithCertStore(certStore storage.CertStorage) CertManagerOption {
	return func(cm *CertManager) {
		cm.certStore = certStore
	}
}

func NewCertManager(opts ...CertManagerOption) *CertManager {
	cm := &CertManager{}
	for _, opt := range opts {
		opt(cm)
	}

	if cm.certStore == nil {
		panic("certStore is required")
	}

	return cm
}

func (cm *CertManager) SyncRootCerts(ctx context.Context) error {
	if err := cm.syncRootCerts(); err != nil {
		return fmt.Errorf("CertManager::SyncRootCerts(): fail to syncRootCerts(): %w", err)
	}
	return nil
}

func (cm *CertManager) AddCRL(ctx context.Context, crlRaw []byte) error {
	ts := time.Now().Unix()

	crl, err := eblpkix.ParseCertificateRevocationList(crlRaw)
	if err != nil {
		return fmt.Errorf("CertManager::AddCRL(): fail to ParseCertificateRevocationList(): %s%w", err, model.ErrInvalidParameter)
	}
	issuerKeyID := eblpkix.GetAuthorityKeyIDFromCertificateRevocationList(crl)

	tx, ctx, err := cm.certStore.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelLinearizable))
	if err != nil {
		return fmt.Errorf("CertManager::AddCRL(): fail to CreateTx(): %w", err)
	}
	defer tx.Rollback(ctx)

	for _, entry := range crl.RevokedCertificateEntries {
		revokedAt := entry.RevocationTime.Unix()
		serialNumber := entry.SerialNumber.String()
		if err := cm.certStore.AddCRL(ctx, tx, ts, issuerKeyID, serialNumber, revokedAt, crlRaw); err != nil {
			return fmt.Errorf("CertManager::AddCRL(): fail to AddCRL(): %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("CertManager::AddCRL(): fail to Commit(): %w", err)
	}
	return nil
}

func (cm *CertManager) syncRootCerts() error {
	client := cli.NewRestClient(cm.certServerURL, "bu_server_cert_manager")

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

func (cm *CertManager) storeRootCert(rootCerts []cert_model.Cert) error {
	ts := time.Now().Unix()
	tx, ctx, err := cm.certStore.CreateTx(context.Background(), storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelLinearizable))
	if err != nil {
		return fmt.Errorf("CertManager::storeRootCert(): fail to CreateTx(): %w", err)
	}
	defer tx.Rollback(ctx)

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
			if err := cm.certStore.AddRootCert(ctx, tx, ts, fingerPrint, []byte(rootCertObj.Certificate)); err != nil {
				return fmt.Errorf("CertManager::storeRootCert(): fail to AddRootCert(%v): %w", util.StructToJSON(rootCertObj), err)
			}
		} else if rootCertObj.Status == cert_model.CertStatusRevoked {
			if err := cm.certStore.RevokeRootCert(ctx, tx, ts, fingerPrint); err != nil {
				return fmt.Errorf("CertManager::storeRootCert(): fail to RevokeRootCert(%v): %w", util.StructToJSON(rootCertObj), err)
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("CertManager::storeRootCert(): fail to Commit(): %w", err)
	}
	return nil
}
