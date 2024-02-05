package pkix

import (
	"crypto/x509"
	"encoding/pem"
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

func ParsePrivateKey(key []byte) (interface{}, error) {
	pemBlock, _ := pem.Decode(key)
	if pemBlock == nil {
		return nil, errors.New("invalid private key")
	}

	ecPrivateKey, ecErr := x509.ParseECPrivateKey(pemBlock.Bytes)
	if ecErr == nil {
		return ecPrivateKey, nil
	}

	privKey, pkcs8Err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if pkcs8Err == nil {
		return privKey, nil
	}

	// Fallback to PKCS1
	privKey, pkcs1Err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if pkcs1Err == nil {
		return privKey, nil
	}

	return nil, pkcs8Err
}

func ParseCertificate(certRaw []byte) ([]x509.Certificate, error) {
	certs := make([]x509.Certificate, 0, 4)
	for {
		pemBlock, remains := pem.Decode(certRaw)
		if pemBlock == nil {
			return nil, errors.New("invalid certificate")
		}

		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, *cert)

		if len(remains) == 0 {
			break
		}
		certRaw = remains
	}

	return certs, nil
}

func ParseCertificateRequest(certRequest []byte) (*x509.CertificateRequest, error) {
	pemBlock, _ := pem.Decode(certRequest)
	if pemBlock == nil {
		return nil, errors.New("invalid certificate request")
	}

	return x509.ParseCertificateRequest(pemBlock.Bytes)
}
