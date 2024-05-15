package business_unit

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"

	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/pkix"
)

type JWTFactory interface {
	NewJWSSigner(authentication model.BusinessUnitAuthentication) (JWSSigner, error)
	NewJWEEncryptor(authentication model.BusinessUnitAuthentication) (JWEEncryptor, error)
}

type _JWTFactory struct{}

var DefaultJWTFactory = _JWTFactory{}

func (_JWTFactory) NewJWSSigner(authentication model.BusinessUnitAuthentication) (JWSSigner, error) {
	privateKey, err := pkix.ParsePrivateKey([]byte(authentication.PrivateKey))
	if err != nil {
		return nil, err
	}

	certs, err := pkix.ParseCertificate([]byte(authentication.Certificate))
	if err != nil {
		return nil, err
	} else if len(certs) == 0 {
		return nil, fmt.Errorf("no certificate for JWS Signer")
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

func (_JWTFactory) NewJWEEncryptor(authentication model.BusinessUnitAuthentication) (JWEEncryptor, error) {
	certs, err := pkix.ParseCertificate([]byte(authentication.Certificate))
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificate found")
	}
	publicKey := certs[0].PublicKey

	switch pk := publicKey.(type) {
	case *rsa.PublicKey:
		return &RSAEncryptor{key: pk}, nil
	case *ecdsa.PublicKey:
		return &ECDSAEncryptor{key: pk}, nil
	default:
		return nil, fmt.Errorf("invalid public key type for JWE Encryptor")
	}
}
