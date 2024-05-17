package did_test

import (
	"encoding/json"
	"testing"

	"github.com/openebl/openebl/pkg/did"
)

func TestDIDParse(t *testing.T) {
	// Test cases
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "valid did",
			input:    "did:example:123",
			expected: "did:example:123",
		},
		{
			name:     "valid did with multiple colons",
			input:    "did:example:123:456",
			expected: "did:example:123:456",
		},
		{
			name:     "invalid did",
			input:    "did:example",
			expected: "",
		},
		{
			name:     "empty input",
			input:    "",
			expected: "",
		},
		{
			name:     "invalid method",
			input:    "did:Invalid:123",
			expected: "",
		},
		{
			name:     "invalid id",
			input:    "did:example:",
			expected: "",
		},
		{
			name:     "valid did with additional characters",
			input:    "did:example:123?param=value",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			did, err := did.Parse(tt.input)
			if tt.expected == "" {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if did.String() != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, did.String())
			}
		})
	}
}

func TestDIDJsonMarshalUnmarshal(t *testing.T) {
	type JsonObj struct {
		DID did.DID `json:"did"`
	}

	tests := []struct {
		name     string
		input    string // input json
		expected string // the expected json output after unmarshalling and marshalling
	}{
		{
			name:     "valid json",
			input:    `{"did":"did:example:123"}`,
			expected: `{"did":"did:example:123"}`,
		},
		{
			name:     "invalid json",
			input:    `{"did":123}`,
			expected: "",
		},
		{
			name:     "empty json",
			input:    `{}`,
			expected: `{"did":""}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var obj JsonObj
			err := json.Unmarshal([]byte(tt.input), &obj)
			if tt.expected == "" {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			b, err := json.Marshal(obj)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if string(b) != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, string(b))
			}
		})
	}

}
