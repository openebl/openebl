package model

import "github.com/nuts-foundation/go-did/did"

type BusinessUnit struct {
	ID            int `json:"id"`             // Unique ID of a BusinessUnit.
	ApplicationID int `json:"application_id"` // The ID of the application this BusinessUnit belongs to.
	DID           did.DID
}

type DIDDocument did.Document
