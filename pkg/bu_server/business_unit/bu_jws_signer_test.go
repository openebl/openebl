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

func TestRSASigner(t *testing.T) {
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
	privKeyPEM, _ := eblpkix.MarshalPrivateKey(rsaKey)
	certPEM, err := eblpkix.MarshalCertificates(cert)
	require.NoError(t, err)

	auth := model.BusinessUnitAuthentication{
		PrivateKey:  string(privKeyPEM),
		Certificate: string(certPEM),
	}
	signer, err := business_unit.DefaultJWTFactory.NewJWSSigner(auth)
	require.NoError(t, err)
	require.NotNil(t, signer)

	pubKey := signer.Public()
	require.True(t, rsaKey.PublicKey.Equal(pubKey))
	require.Equal(t,
		[]envelope.SignatureAlgorithm{
			envelope.SignatureAlgorithm(jwa.RS256),
			envelope.SignatureAlgorithm(jwa.RS384),
			envelope.SignatureAlgorithm(jwa.RS512),
		},
		signer.AvailableJWSSignAlgorithms(),
	)

	payload := []byte("hahahahaha")

	for i := range signer.AvailableJWSSignAlgorithms() {
		signedEnvelope, err := envelope.Sign(payload, signer.AvailableJWSSignAlgorithms()[i], signer, signer.Cert())
		require.NoError(t, err)
		require.NoError(t, signedEnvelope.VerifySignature())
	}
}

func TestECDSASigner(t *testing.T) {
	curves := []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()}
	payload := []byte("hahahahaha")

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
		privKeyPEM, _ := eblpkix.MarshalPrivateKey(ecdsaKey)
		certPEM, err := eblpkix.MarshalCertificates(cert)
		require.NoError(t, err)

		auth := model.BusinessUnitAuthentication{
			PrivateKey:  string(privKeyPEM),
			Certificate: string(certPEM),
		}
		signer, err := business_unit.DefaultJWTFactory.NewJWSSigner(auth)
		require.NoError(t, err)
		require.NotNil(t, signer)

		pubKey := signer.Public()
		require.True(t, ecdsaKey.PublicKey.Equal(pubKey))
		if curve == elliptic.P256() {
			require.Equal(t,
				[]envelope.SignatureAlgorithm{
					envelope.SignatureAlgorithm(jwa.ES256),
				},
				signer.AvailableJWSSignAlgorithms(),
			)
		} else if curve == elliptic.P384() {
			require.Equal(t,
				[]envelope.SignatureAlgorithm{
					envelope.SignatureAlgorithm(jwa.ES384),
				},
				signer.AvailableJWSSignAlgorithms(),
			)
		} else if curve == elliptic.P521() {
			require.Equal(t,
				[]envelope.SignatureAlgorithm{
					envelope.SignatureAlgorithm(jwa.ES512),
				},
				signer.AvailableJWSSignAlgorithms(),
			)
		}

		for i := range signer.AvailableJWSSignAlgorithms() {
			signedEnvelope, err := envelope.Sign(payload, signer.AvailableJWSSignAlgorithms()[i], signer, signer.Cert())
			require.NoError(t, err)
			require.NoError(t, signedEnvelope.VerifySignature())
		}
	}
}
