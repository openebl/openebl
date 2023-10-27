package envelope_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openebl/openebl/pkg/envelope"
)

func TestJWEEncryptWithECDSA(t *testing.T) {
	privKeyPem, err := os.ReadFile("../../credential/user1_priv_key.pem_")
	if err != nil {
		t.Fatal(err)
	}
	privKeyBlock, _ := pem.Decode(privKeyPem)
	privKey, err := x509.ParseECPrivateKey(privKeyBlock.Bytes)
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
				Algorithm: envelope.KeyEncryptionAlgorithm(jwa.ECDH_ES_A256KW),
			},
			{
				PublicKey: &privKey.PublicKey,
				Algorithm: envelope.KeyEncryptionAlgorithm(jwa.ECDH_ES_A256KW),
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
