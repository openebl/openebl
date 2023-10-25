package envelope

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
)

func (s *JWS) VerifySignature() error {
	// Identify Public Key and Algorithm from X5C and Alg.
	header, err := s.GetProtectedHeader()
	if err != nil {
		return err
	}
	if header.Alg == "" {
		return errors.New("missing alg")
	}
	if len(header.X5C) == 0 {
		return errors.New("missing x5c")
	}
	certDER, err := Base64URLDecode(header.X5C[0])
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return err
	}

	verifier, err := jws.NewVerifier(jwa.SignatureAlgorithm(header.Alg))
	if err != nil {
		return err
	}

	signature, err := Base64URLDecode(s.Signature)
	if err != nil {
		return err
	}
	err = verifier.Verify([]byte(fmt.Sprintf("%s.%s", s.Protected, s.Payload)), signature, cert.PublicKey)
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

func Sign(payload []byte, algorithm SignatureAlgorithm, key any, certChain []*x509.Certificate) (JWS, error) {
	if len(certChain) == 0 {
		return JWS{}, errors.New("missing certificate chain")
	}

	signer, err := jws.NewSigner(jwa.SignatureAlgorithm(algorithm))
	if err != nil {
		return JWS{}, err
	}

	header := JOSEHeader{}
	header.Alg = string(algorithm)
	header.X5C = make([]string, len(certChain))
	for i, cert := range certChain {
		header.X5C[i] = Base64URLEncode(cert.Raw)
	}

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
