// Package envelope provides the data structure of JWS and JWE. It also provides related functions to decrypt and verify the signature.
package envelope

import "encoding/json"

type JWK struct {
	KeyType string `json:"kty,omitempty"`

	// EC key
	Curve string `json:"crv,omitempty"` // Public key
	X     string `json:"x,omitempty"`   // Public key
	Y     string `json:"y,omitempty"`   // Public key
	D     string `json:"d,omitempty"`   // Private key of EC key or RSA key

	// RSA Key
	N  string `json:"n,omitempty"`  // Public key
	E  string `json:"e,omitempty"`  // Public key
	P  string `json:"p,omitempty"`  // Private key
	Q  string `json:"q,omitempty"`  // Private key
	DP string `json:"dp,omitempty"` // Private key
	DQ string `json:"dq,omitempty"` // Private key
	QI string `json:"qi,omitempty"` // Private key

	// Symmetric Key
	K string `json:"k,omitempty"` // Symmetric key, base64 url encoded

	// Other fields
	Alg string `json:"alg,omitempty"`
}

type JOSEHeader struct {
	Alg  string   `json:"alg,omitempty"`
	Enc  string   `json:"enc,omitempty"`
	Epk  *JWK     `json:"epk,omitempty"`
	Type string   `json:"typ,omitempty"`
	X5C  []string `json:"x5c,omitempty"` // Base64 encoded DER PKIX certificate value
}

type JWS struct {
	Protected string      `json:"protected,omitempty"` // Base64 URL encoded
	Header    *JOSEHeader `json:"header,omitempty"`
	Payload   string      `json:"payload,omitempty"`   // Base64 URL encoded
	Signature string      `json:"signature,omitempty"` // Base64 URL encoded
}

type JWERecipient struct {
	Header       *JOSEHeader `json:"header,omitempty"`
	EncryptedKey string      `json:"encrypted_key,omitempty"` // Base64 URL encoded
}

type JWE struct {
	Protected   string      `json:"protected,omitempty"` // Base64 URL encoded
	Unprotected *JOSEHeader `json:"unprotected,omitempty"`

	// Header, EncryptedKey are mutual exclusive to Recipients.
	// When Recipients is present, Header and EncryptedKey must be empty.
	Header       *JOSEHeader    `json:"header,omitempty"`
	EncryptedKey string         `json:"encrypted_key,omitempty"` // Base64 URL encoded
	Recipients   []JWERecipient `json:"recipients,omitempty"`

	IV         string `json:"iv,omitempty"`         // Base64 URL encoded
	AAD        string `json:"aad,omitempty"`        // Base64 URL encoded
	Ciphertext string `json:"ciphertext,omitempty"` // Base64 URL encoded
	Tag        string `json:"tag,omitempty"`        // Base64 URL encoded
}

func (header JOSEHeader) Base64URLEncode() string {
	jsonRaw, _ := json.Marshal(header)
	return Base64URLEncode(jsonRaw)
}
