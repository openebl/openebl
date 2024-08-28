package envelope_test

import (
	"crypto/ecdsa"
	"crypto/rsa"
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
	payload := []byte("hahahahaha")

	type TestCase struct {
		alg         jwa.SignatureAlgorithm
		certFile    string
		privKeyFile string
	}

	testCases := []TestCase{
		{
			alg:         jwa.ES256,
			certFile:    "../../credential/bob_ecc.crt",
			privKeyFile: "../../credential/bob_ecc.pem",
		},
		{
			alg:         jwa.ES384,
			certFile:    "../../credential/bob_ecc.crt",
			privKeyFile: "../../credential/bob_ecc.pem",
		},
		{
			alg:         jwa.ES512,
			certFile:    "../../credential/bob_ecc.crt",
			privKeyFile: "../../credential/bob_ecc.pem",
		},
		{
			alg:         jwa.RS256,
			certFile:    "../../credential/claire_rsa.crt",
			privKeyFile: "../../credential/claire_rsa.pem",
		},
		{
			alg:         jwa.RS384,
			certFile:    "../../credential/claire_rsa.crt",
			privKeyFile: "../../credential/claire_rsa.pem",
		},
		{
			alg:         jwa.RS512,
			certFile:    "../../credential/claire_rsa.crt",
			privKeyFile: "../../credential/claire_rsa.pem",
		},
	}

	for _, tc := range testCases {
		alg := tc.alg

		privKeyPem, err := os.ReadFile(tc.privKeyFile)
		if err != nil {
			t.Fatalf("case %s: %v", tc.alg, err)
		}
		privKeyBlock, _ := pem.Decode(privKeyPem)
		var privKey any
		privKey, err = x509.ParseECPrivateKey(privKeyBlock.Bytes)
		if err != nil {
			privKey, err = x509.ParsePKCS8PrivateKey(privKeyBlock.Bytes)
			if err != nil {
				t.Fatalf("case %s: %v", tc.alg, err)
			}
		}

		certPem, err := os.ReadFile(tc.certFile)
		if err != nil {
			t.Fatalf("case %s: %v", tc.alg, err)
		}
		certBlock, _ := pem.Decode(certPem)
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			t.Fatalf("case %s: %v", tc.alg, err)
		}

		rootCertPem, err := os.ReadFile("../../credential/root_ca.crt")
		if err != nil {
			t.Fatalf("case %s: %v", tc.alg, err)
		}
		rootCertBlock, _ := pem.Decode(rootCertPem)
		rootCert, err := x509.ParseCertificate(rootCertBlock.Bytes)
		if err != nil {
			t.Fatalf("case %s: %v", tc.alg, err)
		}

		signed, err := envelope.Sign(payload, envelope.SignatureAlgorithm(alg), privKey, []*x509.Certificate{cert, rootCert})
		if err != nil {
			t.Fatalf("case %s: %v", tc.alg, err)
		}
		rawSigned, _ := json.Marshal(signed)
		// fmt.Printf("%s\n", string(rawSigned))

		var publicKey any
		switch k := privKey.(type) {
		case *rsa.PrivateKey:
			publicKey = &k.PublicKey
		case *ecdsa.PrivateKey:
			publicKey = &k.PublicKey
		}
		_, err = jws.Verify(rawSigned, jws.WithKey(jwa.SignatureAlgorithm(alg), publicKey))
		if err != nil {
			t.Fatalf("case %s: %v", tc.alg, err)
		}

		err = signed.VerifySignature()
		if err != nil {
			t.Fatalf("case %s: %v", tc.alg, err)
		}
	}
}

func TestJWSVerify(t *testing.T) {
	type TestCase struct {
		name        string
		jwsFile     string
		replaceCert string
	}

	testCases := []TestCase{
		{
			name:        "ES256",
			jwsFile:     "../../testdata/envelope/jws/bob_signed_jws.json",
			replaceCert: "../../credential/alice_ecc.crt",
		},
		{
			name:        "RS512",
			jwsFile:     "../../testdata/envelope/jws/claire_signed_jws.json",
			replaceCert: "../../credential/alice_ecc.crt",
		},
	}

	for _, tc := range testCases {
		raw, err := os.ReadFile(tc.jwsFile)
		if err != nil {
			t.Fatalf("case %s: %v", tc.name, err)
		}

		signature := envelope.JWS{}
		if err := json.Unmarshal(raw, &signature); err != nil {
			t.Fatalf("case %s: %v", tc.name, err)
		}

		// Replace the first certificate in the chain with Alice's to make the signature invalid.
		aliceCertPem, _ := os.ReadFile(tc.replaceCert)
		certBlock, _ := pem.Decode(aliceCertPem)
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			t.Fatalf("case %s: %v", tc.name, err)
		}
		jose, _ := signature.GetProtectedHeader()
		jose.X5C[0] = envelope.Base64URLEncode(cert.Raw)
		signature.Protected = jose.Base64URLEncode()

		err = signature.VerifySignature()
		if err == nil {
			t.Fatalf("case %s: %v", tc.name, err)
		}
	}
}
