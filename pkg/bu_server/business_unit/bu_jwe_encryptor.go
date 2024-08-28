package business_unit

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openebl/openebl/pkg/envelope"
)

type RSAEncryptor struct {
	key *rsa.PublicKey
}

type ECDSAEncryptor struct {
	key *ecdsa.PublicKey
}

func (s *RSAEncryptor) Public() crypto.PublicKey {
	return s.key
}

func (s *RSAEncryptor) AvailableJWEEncryptAlgorithms() []envelope.KeyEncryptionAlgorithm {
	return []envelope.KeyEncryptionAlgorithm{
		envelope.KeyEncryptionAlgorithm(jwa.RSA_OAEP),
		envelope.KeyEncryptionAlgorithm(jwa.RSA_OAEP_256),
		envelope.KeyEncryptionAlgorithm(jwa.RSA1_5), // not recommended due to security vulnerability
	}
}

func (s *ECDSAEncryptor) Public() crypto.PublicKey {
	return s.key
}

func (s *ECDSAEncryptor) AvailableJWEEncryptAlgorithms() []envelope.KeyEncryptionAlgorithm {
	return []envelope.KeyEncryptionAlgorithm{
		envelope.KeyEncryptionAlgorithm(jwa.ECDH_ES_A128KW),
		envelope.KeyEncryptionAlgorithm(jwa.ECDH_ES_A192KW),
		envelope.KeyEncryptionAlgorithm(jwa.ECDH_ES_A256KW),
	}
}
