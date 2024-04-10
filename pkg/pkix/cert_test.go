package pkix_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	gopkix "crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/openebl/openebl/pkg/pkix"
	"github.com/stretchr/testify/suite"
)

type CertVerifyTestSuite struct {
	suite.Suite
	rootCert          *x509.Certificate // Cert of Root CA. Self-signed in this test suite.
	intermediateCert  *x509.Certificate // Cert of Intermediate CA. Signed by Root CA
	intermediateCert2 *x509.Certificate // Cert of level 2 Intermediate CA. Signed by Intermediate CA
	cert              *x509.Certificate // Cert of End Entity. Signed by Intermediate CA
}

func (s *CertVerifyTestSuite) SetupSuite() {
	// Generate Root Certificate and Private Key with RSA.
	rootPrivKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	interMediatePrivKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	interMediate2PrivKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	leafPrivKey, _ := rsa.GenerateKey(rand.Reader, 4096)

	rootTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: gopkix.Name{
			Country:            []string{"US", "TW"},
			Organization:       []string{"BlueX Trade"},
			OrganizationalUnit: []string{"BlueX RD Department"},
			CommonName:         "BlueX Trade Root CA",
		},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		NotAfter:              time.Now().AddDate(100, 0, 0),
		NotBefore:             time.Now(),
	}

	interMediateTemplate := rootTemplate
	interMediateTemplate.Subject.CommonName = "BlueX Trade Intermediate CA"

	interMediate2Template := rootTemplate
	interMediate2Template.Subject.CommonName = "BlueX Trade Intermediate2 CA"

	leafTemplate := rootTemplate
	leafTemplate.Subject.CommonName = "BlueX Trade Leaf Certificate"
	leafTemplate.IsCA = false
	leafTemplate.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature

	rootCertBytes, _ := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, &rootPrivKey.PublicKey, rootPrivKey)
	rootCert, _ := x509.ParseCertificate(rootCertBytes)

	interMediateCertBytes, _ := x509.CreateCertificate(rand.Reader, &interMediateTemplate, rootCert, &interMediatePrivKey.PublicKey, rootPrivKey)
	interMediateCert, _ := x509.ParseCertificate(interMediateCertBytes)

	interMediate2CertBytes, _ := x509.CreateCertificate(rand.Reader, &interMediate2Template, interMediateCert, &interMediate2PrivKey.PublicKey, interMediatePrivKey)
	interMediate2Cert, _ := x509.ParseCertificate(interMediate2CertBytes)

	leafCertBytes, _ := x509.CreateCertificate(rand.Reader, &leafTemplate, interMediateCert, &leafPrivKey.PublicKey, interMediatePrivKey)
	leafCert, _ := x509.ParseCertificate(leafCertBytes)

	s.rootCert = rootCert
	s.intermediateCert = interMediateCert
	s.intermediateCert2 = interMediate2Cert
	s.cert = leafCert
}

func TestCertVerifyTestSuite(t *testing.T) {
	suite.Run(t, new(CertVerifyTestSuite))
}

func (s *CertVerifyTestSuite) TestVerifyWithRootCertificate() {
	// s.intermediateCert is signed by s.rootCert, it should pass.
	err := pkix.Verify([]*x509.Certificate{s.intermediateCert}, []*x509.Certificate{s.rootCert}, 0)
	s.Assert().NoError(err)

	// s.intermediateCert is signed by s.rootCert, but the certificates are too old.
	err = pkix.Verify([]*x509.Certificate{s.intermediateCert}, []*x509.Certificate{s.rootCert}, time.Now().AddDate(200, 0, 0).Unix())
	s.Assert().Error(err)

	// s.cert is not signed by s.rootCert, it should fail.
	err = pkix.Verify([]*x509.Certificate{s.cert}, []*x509.Certificate{s.rootCert}, 0)
	s.Assert().Error(err)
}

func (s *CertVerifyTestSuite) TestVerifyWithIntermediateCertificates() {
	// s.cert is signed by s.intermediateCert, it should pass because s.intermediateCert is signed by s.rootCert.
	err := pkix.Verify([]*x509.Certificate{s.cert, s.intermediateCert}, []*x509.Certificate{s.rootCert}, 0)
	s.Assert().NoError(err)

	// s.cert is signed by s.intermediateCert, it should fail because s.intermediateCert is signed by s.rootCert but they are too old..
	err = pkix.Verify([]*x509.Certificate{s.cert, s.intermediateCert}, []*x509.Certificate{s.rootCert}, time.Now().AddDate(200, 0, 0).Unix())
	s.Assert().Error(err)

	// s.cert is not signed by s.intermediateCert2, it should fail.
	err = pkix.Verify([]*x509.Certificate{s.cert, s.intermediateCert2}, []*x509.Certificate{s.rootCert}, 0)
	s.Assert().Error(err)
}

func TestParseCertificate(t *testing.T) {
	pemData := `-----BEGIN CERTIFICATE-----
MIIFVDCCBDygAwIBAgIRAMj6vmF8SNMvEAU489YLMGUwDQYJKoZIhvcNAQELBQAw
RjELMAkGA1UEBhMCVVMxIjAgBgNVBAoTGUdvb2dsZSBUcnVzdCBTZXJ2aWNlcyBM
TEMxEzARBgNVBAMTCkdUUyBDQSAxQzMwHhcNMjQwMTA5MDYzMTM5WhcNMjQwNDAy
MDYzMTM4WjAZMRcwFQYDVQQDEw53d3cuZ29vZ2xlLmNvbTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBALHfbzZh9gDuq6YU18lZGS1xxvFJ9GWpX+EdqQ2T
iAw6hTS8vFNG/jt76uZhJlRK33derWlvpq+Bbct3pqkYp4kMkFFMURDRvPFrX/3t
Tp2Mv9V9Br1GvB9VXLYFDGpmpPi6LlMDMJMkUOczb4QuDxJ21wdyL62DbVJxGuqv
kAk0cRAPhtMC7ZYGBSqaXOwhHneuzzE5UBlRqODALuUdmBAmbgXd+UxvUsavmqt1
7AYtFiVj8lgEsrXGRFEfGYaaIOXKKzNNQwC4D3B/yEPO1qFVT7ZaIbGWkGf8F0AK
xYClusXyRFIeJNt1atjsfyFwf/gDomwvc+B1LuFJQ1J+ZIECAwEAAaOCAmgwggJk
MA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8E
AjAAMB0GA1UdDgQWBBQRLzybIKbyXeW1ms1CC+hmzv1B2DAfBgNVHSMEGDAWgBSK
dH+vhc3ulc09nNDiRhTzcTUdJzBqBggrBgEFBQcBAQReMFwwJwYIKwYBBQUHMAGG
G2h0dHA6Ly9vY3NwLnBraS5nb29nL2d0czFjMzAxBggrBgEFBQcwAoYlaHR0cDov
L3BraS5nb29nL3JlcG8vY2VydHMvZ3RzMWMzLmRlcjAZBgNVHREEEjAQgg53d3cu
Z29vZ2xlLmNvbTAhBgNVHSAEGjAYMAgGBmeBDAECATAMBgorBgEEAdZ5AgUDMDwG
A1UdHwQ1MDMwMaAvoC2GK2h0dHA6Ly9jcmxzLnBraS5nb29nL2d0czFjMy9RcUZ4
Ymk5TTQ4Yy5jcmwwggEFBgorBgEEAdZ5AgQCBIH2BIHzAPEAdgB2/4g/Crb7lVHC
Ycz1h7o0tKTNuyncaEIKn+ZnTFo6dAAAAYztIlshAAAEAwBHMEUCIQDJzUYIHoy3
xGVtTGPoj5JSC14ZrhUJhEK8PFiDFh7emgIgIbfFX+so1ifIzaaaaDa6u+rzYL/o
qLK6PzVOx0vTrBcAdwBIsONr2qZHNA/lagL6nTDrHFIBy1bdLIHZu7+rOdiEcwAA
AYztIlsWAAAEAwBIMEYCIQCfzSZyKnYqoLc8xw7Djrbezmj9wKeDLiL6UN29hXkn
jQIhAKelO6nIhdU+tGGdY46PXEHpb9REGDlF+mvgb8MZ4waQMA0GCSqGSIb3DQEB
CwUAA4IBAQCpyQ5acH1BrM4jGnXclQKBFh8WfOS/lfzDi4HruRkr2w24qPvbJOy6
3ebm5tKv33cN93GfWFv9Ioy/47O9TyZCzEJYSRH4WDAsj9m9gGiknkvLJfsOaqDo
GX2tmAUu1iUlZv8LDEdfz7lNFDEmWGUM6570bySPX4Ea1w/FOKS0KTNto/OkRkkN
P9Mnj2KGbV6jW3M8TZe5pfGOQk8rllIcnMs72oiKDeaQzPWy2b7Ckil6Ye1ZtKP2
id+tcxoUlhRW/2wTCIVcnvRTBI/gJoVXEg3uKJouUb4NSeA1WKINRy7+1MOi/Jaa
kPTNzO8cc/TgWULoU66wj7DJGI3iIWt/
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFljCCA36gAwIBAgINAgO8U1lrNMcY9QFQZjANBgkqhkiG9w0BAQsFADBHMQsw
CQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEU
MBIGA1UEAxMLR1RTIFJvb3QgUjEwHhcNMjAwODEzMDAwMDQyWhcNMjcwOTMwMDAw
MDQyWjBGMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZp
Y2VzIExMQzETMBEGA1UEAxMKR1RTIENBIDFDMzCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAPWI3+dijB43+DdCkH9sh9D7ZYIl/ejLa6T/belaI+KZ9hzp
kgOZE3wJCor6QtZeViSqejOEH9Hpabu5dOxXTGZok3c3VVP+ORBNtzS7XyV3NzsX
lOo85Z3VvMO0Q+sup0fvsEQRY9i0QYXdQTBIkxu/t/bgRQIh4JZCF8/ZK2VWNAcm
BA2o/X3KLu/qSHw3TT8An4Pf73WELnlXXPxXbhqW//yMmqaZviXZf5YsBvcRKgKA
gOtjGDxQSYflispfGStZloEAoPtR28p3CwvJlk/vcEnHXG0g/Zm0tOLKLnf9LdwL
tmsTDIwZKxeWmLnwi/agJ7u2441Rj72ux5uxiZ0CAwEAAaOCAYAwggF8MA4GA1Ud
DwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwEgYDVR0T
AQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUinR/r4XN7pXNPZzQ4kYU83E1HScwHwYD
VR0jBBgwFoAU5K8rJnEaK0gnhS9SZizv8IkTcT4waAYIKwYBBQUHAQEEXDBaMCYG
CCsGAQUFBzABhhpodHRwOi8vb2NzcC5wa2kuZ29vZy9ndHNyMTAwBggrBgEFBQcw
AoYkaHR0cDovL3BraS5nb29nL3JlcG8vY2VydHMvZ3RzcjEuZGVyMDQGA1UdHwQt
MCswKaAnoCWGI2h0dHA6Ly9jcmwucGtpLmdvb2cvZ3RzcjEvZ3RzcjEuY3JsMFcG
A1UdIARQME4wOAYKKwYBBAHWeQIFAzAqMCgGCCsGAQUFBwIBFhxodHRwczovL3Br
aS5nb29nL3JlcG9zaXRvcnkvMAgGBmeBDAECATAIBgZngQwBAgIwDQYJKoZIhvcN
AQELBQADggIBAIl9rCBcDDy+mqhXlRu0rvqrpXJxtDaV/d9AEQNMwkYUuxQkq/BQ
cSLbrcRuf8/xam/IgxvYzolfh2yHuKkMo5uhYpSTld9brmYZCwKWnvy15xBpPnrL
RklfRuFBsdeYTWU0AIAaP0+fbH9JAIFTQaSSIYKCGvGjRFsqUBITTcFTNvNCCK9U
+o53UxtkOCcXCb1YyRt8OS1b887U7ZfbFAO/CVMkH8IMBHmYJvJh8VNS/UKMG2Yr
PxWhu//2m+OBmgEGcYk1KCTd4b3rGS3hSMs9WYNRtHTGnXzGsYZbr8w0xNPM1IER
lQCh9BIiAfq0g3GvjLeMcySsN1PCAJA/Ef5c7TaUEDu9Ka7ixzpiO2xj2YC/WXGs
Yye5TBeg2vZzFb8q3o/zpWwygTMD0IZRcZk0upONXbVRWPeyk+gB9lm+cZv9TSjO
z23HFtz30dZGm6fKa+l3D/2gthsjgx0QGtkJAITgRNOidSOzNIb2ILCkXhAd4FJG
AJ2xDx8hcFH1mt0G/FX0Kw4zd8NLQsLxdxP8c4CU6x+7Nz/OAipmsHMdMqUybDKw
juDEI/9bfU1lcKwrmz3O2+BtjjKAvpafkmO8l7tdufThcV4q5O8DIrGKZTqPwJNl
1IXNDw9bg1kWRxYtnCQ6yICmJhSFm/Y3m6xv+cXDBlHz4n/FsRC6UfTd
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFYjCCBEqgAwIBAgIQd70NbNs2+RrqIQ/E8FjTDTANBgkqhkiG9w0BAQsFADBX
MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEQMA4GA1UE
CxMHUm9vdCBDQTEbMBkGA1UEAxMSR2xvYmFsU2lnbiBSb290IENBMB4XDTIwMDYx
OTAwMDA0MloXDTI4MDEyODAwMDA0MlowRzELMAkGA1UEBhMCVVMxIjAgBgNVBAoT
GUdvb2dsZSBUcnVzdCBTZXJ2aWNlcyBMTEMxFDASBgNVBAMTC0dUUyBSb290IFIx
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAthECix7joXebO9y/lD63
ladAPKH9gvl9MgaCcfb2jH/76Nu8ai6Xl6OMS/kr9rH5zoQdsfnFl97vufKj6bwS
iV6nqlKr+CMny6SxnGPb15l+8Ape62im9MZaRw1NEDPjTrETo8gYbEvs/AmQ351k
KSUjB6G00j0uYODP0gmHu81I8E3CwnqIiru6z1kZ1q+PsAewnjHxgsHA3y6mbWwZ
DrXYfiYaRQM9sHmklCitD38m5agI/pboPGiUU+6DOogrFZYJsuB6jC511pzrp1Zk
j5ZPaK49l8KEj8C8QMALXL32h7M1bKwYUH+E4EzNktMg6TO8UpmvMrUpsyUqtEj5
cuHKZPfmghCN6J3Cioj6OGaK/GP5Afl4/Xtcd/p2h/rs37EOeZVXtL0m79YB0esW
CruOC7XFxYpVq9Os6pFLKcwZpDIlTirxZUTQAs6qzkm06p98g7BAe+dDq6dso499
iYH6TKX/1Y7DzkvgtdizjkXPdsDtQCv9Uw+wp9U7DbGKogPeMa3Md+pvez7W35Ei
Eua++tgy/BBjFFFy3l3WFpO9KWgz7zpm7AeKJt8T11dleCfeXkkUAKIAf5qoIbap
sZWwpbkNFhHax2xIPEDgfg1azVY80ZcFuctL7TlLnMQ/0lUTbiSw1nH69MG6zO0b
9f6BQdgAmD06yK56mDcYBZUCAwEAAaOCATgwggE0MA4GA1UdDwEB/wQEAwIBhjAP
BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTkrysmcRorSCeFL1JmLO/wiRNxPjAf
BgNVHSMEGDAWgBRge2YaRQ2XyolQL30EzTSo//z9SzBgBggrBgEFBQcBAQRUMFIw
JQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnBraS5nb29nL2dzcjEwKQYIKwYBBQUH
MAKGHWh0dHA6Ly9wa2kuZ29vZy9nc3IxL2dzcjEuY3J0MDIGA1UdHwQrMCkwJ6Al
oCOGIWh0dHA6Ly9jcmwucGtpLmdvb2cvZ3NyMS9nc3IxLmNybDA7BgNVHSAENDAy
MAgGBmeBDAECATAIBgZngQwBAgIwDQYLKwYBBAHWeQIFAwIwDQYLKwYBBAHWeQIF
AwMwDQYJKoZIhvcNAQELBQADggEBADSkHrEoo9C0dhemMXoh6dFSPsjbdBZBiLg9
NR3t5P+T4Vxfq7vqfM/b5A3Ri1fyJm9bvhdGaJQ3b2t6yMAYN/olUazsaL+yyEn9
WprKASOshIArAoyZl+tJaox118fessmXn1hIVw41oeQa1v1vg4Fv74zPl6/AhSrw
9U5pCZEt4Wi4wStz6dTZ/CLANx8LZh1J7QJVj2fhMtfTJr9w4z30Z209fOU0iOMy
+qduBmpvvYuR7hZL6Dupszfnw0Skfths18dG9ZKb59UhvmaSGZRVbNQpsg3BZlvi
d0lIKO2d1xozclOzgjXPYovJJIultzkMu34qQb9Sz/yilrbCgj8=
-----END CERTIFICATE-----
`

	certs, err := pkix.ParseCertificate([]byte(pemData))
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 3 {
		t.Fatalf("expected 3 certificates, got %d", len(certs))
	}

	certStr, err := pkix.MarshalCertificates(certs...)
	if err != nil {
		t.Fatal(err)
	}
	if certStr != pemData {
		t.Fatalf("expected %s, got %s", pemData, certStr)
	}
}
