package util

import (
	"github.com/google/uuid"
	"github.com/mr-tron/base58"
)

// NewUUID returns a new base58 encoded UUID
func NewUUID() string {
	id := uuid.New()
	return base58.Encode(id[:])
}
