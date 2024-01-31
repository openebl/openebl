package pkix_test

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"testing"

	"github.com/openebl/openebl/pkg/pkix"
)

func TestVerifyWithCustomizedRootCertificates(t *testing.T) {
	rootCert, err := LoadCert("../../credential/root_ca.crt")
	if err != nil {
		t.Fatal(err)
	}

	fingerPrint := sha1.Sum(rootCert.Raw)
	fmt.Println(hex.EncodeToString(fingerPrint[:]))

	cert, err := LoadCert("../../credential/bob_ecc.crt")
	if err != nil {
		t.Fatal(err)
	}
	err = pkix.Verify([]*x509.Certificate{cert}, []*x509.Certificate{rootCert})
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyWithIntermediatesCertificates(t *testing.T) {
	rootCert, err := LoadCert("../../credential/root_ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	intermediateCert, err := LoadCert("../../credential/bob_ecc.crt")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := LoadCert("../../credential/bob_ecc2.crt")
	if err != nil {
		t.Fatal(err)
	}
	err = pkix.Verify([]*x509.Certificate{cert, intermediateCert}, []*x509.Certificate{rootCert})
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyWithWrongIntermediatesCertificates(t *testing.T) {
	rootCert, err := LoadCert("../../credential/root_ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	intermediateCert, err := LoadCert("../../credential/bob_ecc.crt")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := LoadCert("../../credential/alice_ecc.crt")
	if err != nil {
		t.Fatal(err)
	}
	err = pkix.Verify([]*x509.Certificate{cert, intermediateCert}, []*x509.Certificate{rootCert})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func LoadCert(fileName string) (*x509.Certificate, error) {
	pemFile, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	certBlock, _ := pem.Decode(pemFile)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}
