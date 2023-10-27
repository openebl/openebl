package envelope

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// VerifySignature verifies the signature of the JWS with the public key of the first certificate in X5C parameter.
func (s *JWS) VerifySignature() error {
	// Identify Public Key and Algorithm from X5C and Alg.
	header, err := s.GetProtectedHeader()
	if err != nil {
		return err
	}
	if header.Alg == "" {
		return errors.New("missing alg")
	}
	certChain, err := s.GetCertificateChain()
	if err != nil {
		return err
	}
	if len(certChain) == 0 {
		return errors.New("missing certificate chain (x5c)")
	}

	verifier, err := jws.NewVerifier(jwa.SignatureAlgorithm(header.Alg))
	if err != nil {
		return err
	}

	signature, err := Base64URLDecode(s.Signature)
	if err != nil {
		return err
	}
	err = verifier.Verify([]byte(fmt.Sprintf("%s.%s", s.Protected, s.Payload)), signature, certChain[0].PublicKey)
	if err != nil {
		return err
	}

	return nil
}

// GetPayload returns the payload (decoded) of the JWS.
func (s *JWS) GetPayload() ([]byte, error) {
	return Base64URLDecode(s.Payload)
}

// GetProtectedHeader returns the protected header (decoded) of the JWS.
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

func (s *JWS) GetCertificateChain() ([]*x509.Certificate, error) {
	jose, err := s.GetProtectedHeader()
	if err != nil {
		return nil, err
	}

	if len(jose.X5C) == 0 {
		return nil, nil
	}

	certChain := make([]*x509.Certificate, len(jose.X5C))
	for i, certB64 := range jose.X5C {
		certDER, err := Base64URLDecode(certB64)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, err
		}
		certChain[i] = cert
	}
	return certChain, nil
}

// Sign signs the payload with the given algorithm and key.
//
//	key is the private key used for signing.
//	certChain is the certificate chain used for identifying the public key.
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
