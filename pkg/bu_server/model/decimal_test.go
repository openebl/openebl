package model_test

import (
	"encoding/json"
	"testing"

	"github.com/openebl/openebl/pkg/bu_server/model"
)

func TestDecimalJson(t *testing.T) {
	strVal := `{"value":123.456}`
	strValWithQuotes := `{"value":"123.456"}`

	type Node struct {
		Value model.Decimal `json:"value"`
	}

	node := Node{}
	err := json.Unmarshal([]byte(strVal), &node)
	if err != nil {
		t.Fatal(err)
	}

	nodeForQuote := Node{}
	err = json.Unmarshal([]byte(strValWithQuotes), &nodeForQuote)
	if err != nil {
		t.Fatal(err)
	}

	if node.Value.String() != nodeForQuote.Value.String() {
		t.Fatal("JSON Unmarshal with/without quotes is not consistent")
	}

	jsonRaw, err := json.Marshal(node)
	if err != nil {
		t.Fatal(err)
	}
	if string(jsonRaw) != strVal {
		t.Fatal("JSON marshaling/unmarshaling is not consistent")
	}
}
