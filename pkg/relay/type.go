package relay

type EventType int

const (
	FileBasedBillOfLading          EventType = 1001
	EncryptedFileBasedBillOfLading EventType = 1002
)
