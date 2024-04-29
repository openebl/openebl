package cert

import (
	"context"
	"crypto/x509"
	"encoding/hex"

	"github.com/openebl/openebl/pkg/bu_server/storage"
	eblpkix "github.com/openebl/openebl/pkg/pkix"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
)

type CertVerifyHelper struct {
	revocations map[storage.IssuerKeyAndCertSerialNumber][]byte
}

func NewCertVerifyHelper(ctx context.Context, tx storage.Tx, ts int64, cm *CertManager, certs []*x509.Certificate) (*CertVerifyHelper, error) {
	issuerKeyAndSerialNumber := lo.Map(
		certs,
		func(c *x509.Certificate, _ int) storage.IssuerKeyAndCertSerialNumber {
			return storage.IssuerKeyAndCertSerialNumber{
				IssuerKeyID:       eblpkix.GetSubjectKeyIDFromCertificate(c),
				CertificateSerial: c.SerialNumber.String(),
			}
		},
	)
	req := storage.GetCRLRequest{
		RevokedAt:                      ts,
		IssuerKeysAndCertSerialNumbers: issuerKeyAndSerialNumber,
	}
	result, err := cm.certStore.GetCRL(ctx, tx, req)
	if err != nil {
		logrus.Errorf("NewCertVerifyHelper(): fail to GetCRL() %v", err.Error())
		return nil, err
	}

	cvh := &CertVerifyHelper{
		revocations: result.CRLs,
	}

	return cvh, nil
}

func (cvh *CertVerifyHelper) IsCertsRevoked(ts int64, certs []*x509.Certificate) []*x509.Certificate {
	revokedCerts := make([]*x509.Certificate, 0)
	for _, c := range certs {
		keyID := hex.EncodeToString(c.AuthorityKeyId)
		serial := c.SerialNumber.String()
		if _, ok := cvh.revocations[storage.IssuerKeyAndCertSerialNumber{
			IssuerKeyID:       keyID,
			CertificateSerial: serial,
		}]; ok {
			revokedCerts = append(revokedCerts, c)
		}
	}
	if len(revokedCerts) == 0 {
		return nil
	}
	return revokedCerts
}
