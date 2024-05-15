package relay

type EventType int

const (
	BusinessUnit               EventType = 801
	BusinessUnitAuthentication EventType = 802

	X509Certificate               EventType = 901
	X509CertificateRevocationList EventType = 902

	FileBasedBillOfLading          EventType = 1001
	EncryptedFileBasedBillOfLading EventType = 1002
)
