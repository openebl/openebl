package cert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	eblpkix "github.com/openebl/openebl/pkg/pkix"
	"github.com/openebl/openebl/pkg/relay/server/storage"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
)

type CertVerifyHelper struct {
	revocations map[storage.IssuerKeyAndCertSerialNumber][]byte
}

func NewTLSConfig(certRaw []byte, privateKey []byte, certMgr CertManager) (*tls.Config, error) {
	tlsCert, err := tls.X509KeyPair(certRaw, privateKey)
	if err != nil {
		return nil, err
	}

	verifyFunc := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		certs := make([]*x509.Certificate, 0, len(rawCerts))
		for i := range rawCerts {
			cert, err := x509.ParseCertificate(rawCerts[i])
			if err != nil {
				return err
			}
			certs = append(certs, cert)
		}

		err := certMgr.VerifyCert(context.Background(), time.Now().Unix(), certs)
		if err != nil {
			return err
		}

		crlVerify, err := NewCertVerifyHelper(context.Background(), time.Now().Unix(), certMgr.(*_CertManager), certs)
		if err != nil {
			return err
		}

		revokedCerts := crlVerify.IsCertsRevoked(time.Now().Unix(), certs)
		if revokedCerts != nil {
			strBuilder := strings.Builder{}
			strBuilder.WriteString("certs (issuer key id, serial number) ")
			for i, cert := range revokedCerts {
				if i > 0 {
					strBuilder.WriteString(", ")
				}
				strBuilder.WriteString(fmt.Sprintf("{%s, %s}", hex.EncodeToString(cert.AuthorityKeyId), cert.SerialNumber.String()))
			}
			strBuilder.WriteString(" are revoked")
			return errors.New(strBuilder.String())
		}

		return nil
	}

	tlsConfig := &tls.Config{
		Certificates:          []tls.Certificate{tlsCert},
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: verifyFunc,
	}

	return tlsConfig, nil
}

func NewCertVerifyHelper(ctx context.Context, ts int64, cm *_CertManager, certs []*x509.Certificate) (*CertVerifyHelper, error) {
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
	result, err := cm.certStore.GetCRL(ctx, req)
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
