package envelope

import (
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
)

func (s *JWS) VerifySignature() error {
	rawJWS, err := json.Marshal(s)
	if err != nil {
		return err
	}

	_, err = jws.Verify(rawJWS)
	if err != nil {
		return err
	}
	return nil
}

func (s *JWS) GetPayload() ([]byte, error) {
	return Base64URLDecode(s.Payload)
}

func (s *JWS) GetProtectedHeader() (JOSEHeader, error) {
	protected, err := Base64URLDecode(s.Protected)
	if err != nil {
		return JOSEHeader{}, err
	}
	if len(protected) == 0 {
		return JOSEHeader{}, nil
	}

	header := JOSEHeader{}
	if err := json.Unmarshal(protected, &header); err != nil {
		return JOSEHeader{}, err
	}
	return header, nil
}

func Sign(payload []byte, algorithm SignatureAlgorithm, key any) (JWS, error) {
	signer, err := jws.NewSigner(jwa.SignatureAlgorithm(algorithm))
	if err != nil {
		return JWS{}, err
	}

	header := JOSEHeader{}
	header.Alg = string(algorithm)

	signInput := genSignInput(payload, header)
	signature, err := signer.Sign(signInput, key)
	_ = signature
	if err != nil {
		return JWS{}, err
	}

	jws := JWS{}
	jws.Protected = header.Base64URLEncode()
	jws.Payload = Base64URLEncode(payload)
	jws.Signature = Base64URLEncode(signature)
	return jws, nil
}

func genSignInput(payload []byte, header JOSEHeader) []byte {
	headerB64 := header.Base64URLEncode()
	payloadB64 := Base64URLEncode(payload)
	return []byte(fmt.Sprintf("%s.%s", headerB64, payloadB64))
}
