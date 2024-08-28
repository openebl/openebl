package envelope

import "encoding/base64"

func Base64URLDecode(in string) ([]byte, error) {
	outputLen := base64.RawURLEncoding.DecodedLen(len(in))
	if outputLen == 0 {
		return nil, nil
	}

	output := make([]byte, outputLen)
	len, err := base64.RawURLEncoding.Decode(output, []byte(in))
	if err != nil {
		return nil, err
	}
	return output[:len], nil
}

func Base64URLEncode(in []byte) string {
	return base64.RawURLEncoding.EncodeToString(in)
}
