package util

import (
	"bytes"
	"encoding/json"
	"io"
)

func StructToJSONReader(data interface{}) io.Reader {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil
	}
	return bytes.NewReader(jsonBytes)
}

func StructToJSON(data interface{}) string {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return ""
	}
	return string(jsonBytes)
}
