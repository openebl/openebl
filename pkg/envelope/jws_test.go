package envelope_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openebl/openebl/pkg/envelope"
)

func TestJWSSign(t *testing.T) {
	payload := []byte("hahahahaha")
	// alg := jwa.RS256
	// key, err := rsa.GenerateKey(rand.Reader, 1024)
	alg := jwa.ES256
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := envelope.Sign(payload, envelope.SignatureAlgorithm(alg), key)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%v\n", signed)
	rawSigned, _ := json.Marshal(signed)

	_, err = jws.Verify(rawSigned, jws.WithKey(jwa.SignatureAlgorithm(alg), &key.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
}
