package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type APIKeyStatus string
type APIKeyScope string

const (
	APIKeyStatusActive  = APIKeyStatus("active")
	APIKeyStatusRevoked = APIKeyStatus("revoked")

	APIKeyScopeAll = APIKeyScope("all")
)

// APIKeyString is the string representation of an API key.
// The BU server client has to provide this string to the BU server to authenticate itself.
// The format of APIKeyString is [ID]:[SECRET].
type APIKeyString string

// APIKeyHashedString is the hashed string representation of an API key.
// It is stored in the database. BU server is not able to recover the original APIKeyString from this.
type APIKeyHashedString string

type APIKey struct {
	ID          string             `json:"id"`
	HashString  APIKeyHashedString `json:"hash_string"`
	Version     int                `json:"version"`
	Application string             `json:"application"`
	Scopes      []string           `json:"scopes"`
	Status      APIKeyStatus       `json:"status"`

	UpdatedAt int64  `json:"updated_at"`
	UpdatedBy string `json:"updated_by"`
}

func (ks APIKeyString) ID() (string, error) {
	// Split ID from APIKeyString.
	parts := strings.Split(string(ks), ":")
	if len(parts) != 2 {
		return "", ErrInvalidAPIKeyString
	}

	return parts[0], nil
}

func (ks APIKeyString) Hash() (APIKeyHashedString, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(string(ks)), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return APIKeyHashedString(hashed), nil
}

func NewAPIKeyString() (APIKeyString, error) {
	prefixBytes := make([]byte, 16)
	secretBytes := make([]byte, 32)

	if _, err := rand.Read(prefixBytes); err != nil {
		return "", err
	}
	if _, err := rand.Read(secretBytes); err != nil {
		return "", err
	}

	base64Prefix := base64.RawURLEncoding.EncodeToString(prefixBytes)
	base64Secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	return APIKeyString(fmt.Sprintf("%s:%s", base64Prefix, base64Secret)), nil
}

func VerifyAPIKeyString(ks APIKeyString, hashedKs APIKeyHashedString) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashedKs), []byte(ks))
	if err == nil {
		return nil
	}

	if err == bcrypt.ErrMismatchedHashAndPassword {
		return ErrMismatchAPIKey
	}

	return err
}
