package pkix

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"
)

// Verify verifies the certificate chain of trust.
//
// The first certificate in the chain is the end-entity certificate.
// The rest of the certificates are intermediate certificates.
//
// The rootCerts parameter is optional. If provided, the rootCerts and the system
// preinstalled trusted certs are used to verify the certificate chain.
//
// ts is the timestamp to verify the certificate chain. If ts is 0, the current time is used.
//
// !!! Current implementation doesn't check KeyUsage extension for better new user migration.
func Verify(certs []*x509.Certificate, rootCerts []*x509.Certificate, ts int64) error {
	if len(certs) == 0 {
		return errors.New("no certificate provided")
	}

	if ts == 0 {
		ts = time.Now().Unix()
	}

	cert := certs[0]
	intermediateCerts := certs[1:]

	var err error
	var rootPool *x509.CertPool
	var intermediatePool *x509.CertPool
	if len(intermediateCerts) > 0 {
		pool := x509.NewCertPool()
		for _, intermediateCert := range intermediateCerts {
			pool.AddCert(intermediateCert)
		}
		intermediatePool = pool
	}
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
		Roots:         rootPool,
		Intermediates: intermediatePool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   time.Unix(ts, 0),
	}

	certChains, err := cert.Verify(options)
	if err != nil {
		return err
	}

	// TODO: Check if certificates involved in certChains are not revoked.
	_ = certChains

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

func MarshalPrivateKey(privateKey any) (string, error) {
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		keyBytes, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return "", err
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})), nil
	case *ecdsa.PrivateKey:
		keyBytes, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return "", err
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})), nil
	default:
		return "", errors.New("unsupported private key type")
	}
}

func MarshalCertificates(certs []x509.Certificate) (string, error) {
	certBytes := make([]byte, 0)
	for _, cert := range certs {
		certBytes = append(certBytes, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return string(certBytes), nil
}
