package business_unit_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openebl/openebl/pkg/bu_server/business_unit"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/envelope"
	eblpkix "github.com/openebl/openebl/pkg/pkix"
	"github.com/stretchr/testify/require"
)

func TestRSAEncryptor(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // 1 year

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Your Organization"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &rsaKey.PublicKey, rsaKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	certPEM, err := eblpkix.MarshalCertificates(cert)
	require.NoError(t, err)

	auth := model.BusinessUnitAuthentication{
		Certificate: certPEM,
	}
	encryptor, err := business_unit.DefaultJWTFactory.NewJWEEncryptor(auth)
	require.NoError(t, err)
	require.NotNil(t, encryptor)

	pubKey := encryptor.Public()
	require.True(t, rsaKey.PublicKey.Equal(pubKey))
	require.Equal(t,
		[]envelope.KeyEncryptionAlgorithm{
			envelope.KeyEncryptionAlgorithm(jwa.RSA_OAEP),
			envelope.KeyEncryptionAlgorithm(jwa.RSA_OAEP_256),
			envelope.KeyEncryptionAlgorithm(jwa.RSA1_5),
		},
		encryptor.AvailableJWEEncryptAlgorithms(),
	)
}

func TestECDSAEncryptor(t *testing.T) {
	curves := []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()}
	for _, curve := range curves {
		ecdsaKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)

		notBefore := time.Now()
		notAfter := notBefore.Add(365 * 24 * time.Hour) // 1 year

		template := x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				Organization: []string{"Your Organization"},
			},
			NotBefore: notBefore,
			NotAfter:  notAfter,

			KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}

		der, err := x509.CreateCertificate(rand.Reader, &template, &template, &ecdsaKey.PublicKey, ecdsaKey)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		certPEM, err := eblpkix.MarshalCertificates(cert)
		require.NoError(t, err)

		auth := model.BusinessUnitAuthentication{
			Certificate: certPEM,
		}
		encryptor, err := business_unit.DefaultJWTFactory.NewJWEEncryptor(auth)
		require.NoError(t, err)
		require.NotNil(t, encryptor)

		pubKey := encryptor.Public()
		require.True(t, ecdsaKey.PublicKey.Equal(pubKey))
		require.Equal(t,
			[]envelope.KeyEncryptionAlgorithm{
				envelope.KeyEncryptionAlgorithm(jwa.ECDH_ES_A128KW),
				envelope.KeyEncryptionAlgorithm(jwa.ECDH_ES_A192KW),
				envelope.KeyEncryptionAlgorithm(jwa.ECDH_ES_A256KW),
			},
			encryptor.AvailableJWEEncryptAlgorithms(),
		)
	}
}
