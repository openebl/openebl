package envelope_test

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openebl/openebl/pkg/envelope"
)

func TestJWSSignAndVerify(t *testing.T) {
	alg := jwa.ES256
	payload := []byte("hahahahaha")

	privKeyPem, err := os.ReadFile("../../credential/user1_priv_key.pem_")
	if err != nil {
		t.Fatal(err)
	}
	privKeyBlock, _ := pem.Decode(privKeyPem)
	privKey, err := x509.ParseECPrivateKey(privKeyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	certPem, err := os.ReadFile("../../credential/user1_1.crt")
	if err != nil {
		t.Fatal(err)
	}
	certBlock, _ := pem.Decode(certPem)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	signed, err := envelope.Sign(payload, envelope.SignatureAlgorithm(alg), privKey, []*x509.Certificate{cert})
	if err != nil {
		t.Fatal(err)
	}
	rawSigned, _ := json.Marshal(signed)

	_, err = jws.Verify(rawSigned, jws.WithKey(jwa.SignatureAlgorithm(alg), &privKey.PublicKey))
	if err != nil {
		t.Fatal(err)
	}

	err = signed.VerifySignature()
	if err != nil {
		t.Fatal(err)
	}
}
