package envelope

import (
	"crypto"
	"encoding/hex"
)

func SHA512(in []byte) string {
	hasher := crypto.SHA512.New()
	offset := 0
	for offset < len(in) {
		bytesWritten, err := hasher.Write(in[offset:])
		if err != nil {
			panic(err)
		}
		offset += bytesWritten
	}
	out := hasher.Sum(nil)
	result := make([]byte, hex.EncodedLen(len(out)))
	hex.Encode(result, out)
	return string(result)
}
