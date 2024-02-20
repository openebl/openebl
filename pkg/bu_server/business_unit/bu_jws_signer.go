package business_unit

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/envelope"
	"github.com/openebl/openebl/pkg/pkix"
)

type JWSSignerFactory interface {
	NewJWSSigner(authentication model.BusinessUnitAuthentication) (JWSSigner, error)
}

type _JWSSignerFactory struct{}

var DefaultJWSSignerFactory = _JWSSignerFactory{}

func (_JWSSignerFactory) NewJWSSigner(authentication model.BusinessUnitAuthentication) (JWSSigner, error) {
	privateKey, err := pkix.ParsePrivateKey([]byte(authentication.PrivateKey))
	if err != nil {
		return nil, err
	}

	certs, err := pkix.ParseCertificate([]byte(authentication.Certificate))
	if err != nil {
		return nil, err
	}

	switch pk := privateKey.(type) {
	case *rsa.PrivateKey:
		return &RSASigner{key: pk, cert: certs}, nil
	case *ecdsa.PrivateKey:
		return &ECDSASigner{key: pk, cert: certs}, nil
	default:
		return nil, fmt.Errorf("invalid private key type for JWS Signer")
	}
}

type RSASigner struct {
	cert []x509.Certificate
	key  *rsa.PrivateKey
}

type ECDSASigner struct {
	cert []x509.Certificate
	key  *ecdsa.PrivateKey
}

func (s *RSASigner) Public() crypto.PublicKey {
	return s.key.Public()
}

func (s *RSASigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return s.key.Sign(rand, digest, opts)
}

func (s *RSASigner) AvailableJWSSignAlgorithms() []envelope.SignatureAlgorithm {
	return []envelope.SignatureAlgorithm{
		envelope.SignatureAlgorithm(jwa.RS256),
		envelope.SignatureAlgorithm(jwa.RS384),
		envelope.SignatureAlgorithm(jwa.RS512),
	}
}

func (s *RSASigner) Cert() []x509.Certificate {
	return s.cert
}

func (s *ECDSASigner) Public() crypto.PublicKey {
	return s.key.Public()
}

func (s *ECDSASigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return s.key.Sign(rand, digest, opts)
}

func (s *ECDSASigner) AvailableJWSSignAlgorithms() []envelope.SignatureAlgorithm {
	switch s.key.Curve {
	case elliptic.P256():
		return []envelope.SignatureAlgorithm{envelope.SignatureAlgorithm(jwa.ES256)}
	case elliptic.P384():
		return []envelope.SignatureAlgorithm{envelope.SignatureAlgorithm(jwa.ES384)}
	case elliptic.P521():
		return []envelope.SignatureAlgorithm{envelope.SignatureAlgorithm(jwa.ES512)}
	}
	return nil
}

func (s *ECDSASigner) Cert() []x509.Certificate {
	return s.cert
}
