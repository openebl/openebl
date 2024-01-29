package model_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/openebl/openebl/pkg/bu_server/model"
)

func TestDateTimeJSON(t *testing.T) {
	type testStruct struct {
		DateTime model.DateTime `json:"date_time"`
	}

	dateTimeString := `"2021-03-31T15:04:05+08:00"`
	jsonString := fmt.Sprintf(`{"date_time":%s}`, dateTimeString)

	var ts testStruct
	err := json.Unmarshal([]byte(jsonString), &ts)
	if err != nil {
		t.Fatal(err)
	}

	newJsonStr, err := json.Marshal(ts)
	if err != nil {
		t.Fatal(err)
	}
	if string(newJsonStr) != jsonString {
		t.Fatal("JSON marshaling/unmarshaling is not consistent")
	}
}

func TestDateJson(t *testing.T) {
	type testStruct struct {
		Date model.Date `json:"date"`
	}

	dateString := `"2021-03-31"`
	jsonString := fmt.Sprintf(`{"date":%s}`, dateString)

	var ts testStruct
	err := json.Unmarshal([]byte(jsonString), &ts)
	if err != nil {
		t.Fatal(err)
	}

	newJsonStr, err := json.Marshal(ts)
	if err != nil {
		t.Fatal(err)
	}
	if string(newJsonStr) != jsonString {
		t.Fatal("JSON marshaling/unmarshaling is not consistent")
	}
}
