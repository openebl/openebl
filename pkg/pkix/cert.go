package pkix

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	gopkix "crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"time"
)

var ErrInvalidParameter = errors.New("")

type PrivateKeyType string // PrivateKeyType is the type of the private key.
type ECDSACurveType string

const (
	PrivateKeyTypeRSA   PrivateKeyType = "RSA"
	PrivateKeyTypeECDSA PrivateKeyType = "ECDSA"

	ECDSACurveTypeP256 ECDSACurveType = "P-256"
	ECDSACurveTypeP384 ECDSACurveType = "P-384"
	ECDSACurveTypeP521 ECDSACurveType = "P-521"
)

type PrivateKeyOption struct {
	KeyType   PrivateKeyType `json:"key_type"`   // Type of the private key.
	BitLength int            `json:"bit_length"` // Bit length of the private key. Only used when KeyType is RSA.
	CurveType ECDSACurveType `json:"curve_type"` // Curve type of the private key. Only used when KeyType is ECDSA.
}

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

func ParseCertificate(certRaw []byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0, 4)
	for {
		pemBlock, remains := pem.Decode(certRaw)
		if pemBlock == nil {
			return nil, errors.New("invalid certificate")
		}

		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)

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

func ParseCertificateRevocationList(crl []byte) (*x509.RevocationList, error) {
	pemBlock, _ := pem.Decode(crl)
	if pemBlock == nil {
		return nil, errors.New("invalid certificate revocation list")
	}

	return x509.ParseRevocationList(pemBlock.Bytes)
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

func MarshalCertificates(certs ...*x509.Certificate) (string, error) {
	certBytes := make([]byte, 0)
	for _, cert := range certs {
		certBytes = append(certBytes, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return string(certBytes), nil
}

func CreateCertificateSigningRequest(privKey interface{}, country, organization, organizationalUnit []string, commonName string) ([]byte, error) {
	certRequestTemplate := x509.CertificateRequest{
		Subject: gopkix.Name{
			Country:            country,
			Organization:       organization,
			OrganizationalUnit: organizationalUnit,
			CommonName:         commonName,
		},
	}

	csrRaw, err := x509.CreateCertificateRequest(rand.Reader, &certRequestTemplate, privKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrRaw}), nil
}

func CreatePrivateKey(opt PrivateKeyOption) (any, error) {
	switch opt.KeyType {
	case PrivateKeyTypeRSA:
		return rsa.GenerateKey(rand.Reader, opt.BitLength)
	case PrivateKeyTypeECDSA:
		switch opt.CurveType {
		case ECDSACurveTypeP256:
			return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case ECDSACurveTypeP384:
			return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		case ECDSACurveTypeP521:
			return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		default:
			return nil, ErrInvalidParameter
		}
	default:
		return nil, ErrInvalidParameter
	}
}

func IsPublicKeyOf(privKey any, pubKey any) bool {
	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		return k.PublicKey.Equal(pubKey)
	case *ecdsa.PrivateKey:
		return k.PublicKey.Equal(pubKey)
	default:
		return false
	}
}

func GetPublicKey(privKey any) any {
	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func GetSubjectKeyIDFromCertificate(cert *x509.Certificate) string {
	if len(cert.SubjectKeyId) != 0 {
		return hex.EncodeToString(cert.SubjectKeyId)
	}

	getBytes := func() []byte {
		rsaPubKey, _ := cert.PublicKey.(*rsa.PublicKey)
		if rsaPubKey != nil {
			return x509.MarshalPKCS1PublicKey(rsaPubKey)
		}

		ecdsaPubKey, _ := cert.PublicKey.(*ecdsa.PublicKey)
		if ecdsaPubKey != nil {
			ecdhPubKey, err := ecdsaPubKey.ECDH()
			if err != nil {
				return nil
			}
			return ecdhPubKey.Bytes()
		}

		ecdhPubKey, _ := cert.PublicKey.(*ecdh.PublicKey)
		if ecdhPubKey != nil {
			return ecdhPubKey.Bytes()
		}

		return nil
	}

	keyBytes := getBytes()
	hashResult := sha1.Sum(keyBytes)
	return hex.EncodeToString(hashResult[:])
}

func GetAuthorityKeyIDFromCertificateRevocationList(crl *x509.RevocationList) string {
	type authKeyId struct {
		Id []byte `asn1:"optional,tag:0"`
	}

	if len(crl.AuthorityKeyId) == 0 {
		return ""
	}

	var keyId authKeyId
	_, err := asn1.Unmarshal(crl.AuthorityKeyId, &keyId)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(keyId.Id)
}
