package server

import (
	"crypto/sha512"
	"encoding/hex"
)

func GetEventID(data []byte) string {
	sum512Result := sha512.Sum512(data)
	eventID := hex.EncodeToString(sum512Result[:])
	return eventID
}
