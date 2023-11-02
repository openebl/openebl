package pkix

import (
	"crypto/x509"
	"errors"
)

// Verify verifies the certificate chain of trust.
//
// The first certificate in the chain is the end-entity certificate.
// The rest of the certificates are intermediate certificates.
//
// The rootCerts parameter is optional. If provided, the rootCerts and the system
// preinstalled trusted certs are used to verify the certificate chain.
//
// !!! Current implementation doesn't check KeyUsage extension for better new user migration.
func Verify(certs []*x509.Certificate, rootCerts []*x509.Certificate) error {
	if len(certs) == 0 {
		return errors.New("no certificate provided")
	}

	cert := certs[0]
	intermediateCerts := certs[1:]

	// This is a workaround to prevent the error "x509: certificate is not authorized to sign other certificates"
	// when the intermediate certificates don't have the keyCertSign KeyUsage extension.
	for len(intermediateCerts) > 0 {
		rootPool := x509.NewCertPool()
		rootPool.AddCert(intermediateCerts[0])
		options := x509.VerifyOptions{
			Roots:     rootPool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}
		if _, err := cert.Verify(options); err != nil {
			return err
		}
		cert = intermediateCerts[0]
		intermediateCerts = intermediateCerts[1:]
	}

	var err error
	var rootPool *x509.CertPool
	if len(rootCerts) > 0 {
		rootPool, err = x509.SystemCertPool()
		if err != nil {
			return err
		}
		for _, rootCert := range rootCerts {
			rootPool.AddCert(rootCert)
		}
	}

	options := x509.VerifyOptions{
		Roots:     rootPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err = cert.Verify(options); err != nil {
		return err
	}

	return nil
}
