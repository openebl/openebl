package envelope_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openebl/openebl/pkg/envelope"
)

func TestJWEEncryptWithECDSAAndRSA(t *testing.T) {
	bobPrivKey, err := LoadKey("../../credential/bob_ecc.pem")
	if err != nil {
		t.Fatal(err)
	}

	clairePrivKey, err := LoadKey("../../credential/claire_rsa.pem")
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("Hello, World!")

	result, err := envelope.Encrypt(
		payload,
		envelope.ContentEncryptionAlgorithm(jwa.A256GCM),
		[]envelope.KeyEncryptionSetting{
			{
				PublicKey: &bobPrivKey.(*ecdsa.PrivateKey).PublicKey,
				Algorithm: envelope.KeyEncryptionAlgorithm(jwa.ECDH_ES_A256KW),
			},
			{
				PublicKey: &clairePrivKey.(*rsa.PrivateKey).PublicKey,
				Algorithm: envelope.KeyEncryptionAlgorithm(jwa.RSA_OAEP_256),
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	jsonRaw, _ := json.Marshal(result)
	fmt.Printf("%s\n", string(jsonRaw))

	plainText, err := envelope.Decrypt(result, []any{bobPrivKey})
	if err != nil {
		t.Fatal(err)
	}
	if string(plainText) != string(payload) {
		t.Fatalf("expected %s, got %s", payload, plainText)
	}

	plainText, err = envelope.Decrypt(result, []any{clairePrivKey})
	if err != nil {
		t.Fatal(err)
	}
	if string(plainText) != string(payload) {
		t.Fatalf("expected %s, got %s", payload, plainText)
	}

	// Use a random key to decrypt, it should fail.
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, err = envelope.Decrypt(result, []any{privKey})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestJWEEncryptWithRSA(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("Hello, World!")

	result, err := envelope.Encrypt(
		payload,
		envelope.ContentEncryptionAlgorithm(jwa.A256GCM),
		[]envelope.KeyEncryptionSetting{
			{
				PublicKey: &privKey.PublicKey,
				Algorithm: envelope.KeyEncryptionAlgorithm(jwa.RSA_OAEP_256),
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%v\n", result)

	plainText, err := envelope.Decrypt(result, []any{privKey})
	if err != nil {
		t.Fatal(err)
	}
	if string(plainText) != string(payload) {
		t.Fatalf("expected %s, got %s", payload, plainText)
	}
}

func TestJWEDecrypt(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/envelope/jwe/to_bob_and_claire.json")
	if err != nil {
		t.Fatal(err)
	}

	encryptedEnvelope := envelope.JWE{}
	if err := json.Unmarshal(raw, &encryptedEnvelope); err != nil {
		t.Fatal(err)
	}

	type TestCase struct {
		name    string
		keyPath string
		succeed bool
	}

	testCases := []TestCase{
		{
			name:    "Use Bob Private Key",
			keyPath: "../../credential/bob_ecc.pem",
			succeed: true,
		},
		{
			name:    "Use Claire Private Key",
			keyPath: "../../credential/claire_rsa.pem",
			succeed: true,
		},
		{
			name:    "Use Alice Private Key",
			keyPath: "../../credential/alice_ecc.pem",
			succeed: false,
		},
	}

	for _, tc := range testCases {
		privKey, err := LoadKey(tc.keyPath)
		if err != nil {
			t.Fatal(err)
		}

		plainText, err := envelope.Decrypt(encryptedEnvelope, []any{privKey})
		if err != nil {
			if tc.succeed {
				t.Fatalf("case %s: %v", tc.name, err)
			}
		} else {
			if !tc.succeed {
				t.Fatalf("case %s: expected error, got nil", tc.name)
			}
			if string(plainText) != "Hello, World!" {
				t.Fatalf("case %s: expected %s, got %s", tc.name, "Hello, World!", plainText)
			}
		}
	}
}

func LoadKey(fileName string) (any, error) {
	privKeyPem, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	privKeyBlock, _ := pem.Decode(privKeyPem)
	ecPrivKey, ecKeyErr := x509.ParseECPrivateKey(privKeyBlock.Bytes)
	rsaPrivKey, rsaKeyErr := x509.ParsePKCS8PrivateKey(privKeyBlock.Bytes)
	if ecPrivKey == nil && rsaPrivKey == nil {
		if ecKeyErr != nil {
			return nil, ecKeyErr
		}
		return nil, rsaKeyErr
	}

	if ecPrivKey != nil {
		return ecPrivKey, nil
	}
	return rsaPrivKey, nil
}
