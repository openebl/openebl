package bill_of_lading

import "github.com/openebl/openebl/pkg/bu_server/model"

type BillOfLadingPack struct {
	ID           string              `json:"id"`            // Identity of the bill of lading pack
	Version      int64               `json:"version"`       // Version of the bill of lading pack
	ParentHash   string              `json:"parent_hash"`   // SHA512 hash of the previous version of the bill of lading pack
	Events       []BillOfLadingEvent `json:"events"`        // Events of the bill of lading pack
	CurrentOwner string              `json:"current_owner"` // DID of the current owner of the latest bill of lading of the pack.
}

type BillOfLadingEvent struct {
	// All fields in this struct are mutually exclusive.
	// Only one of them can be set.
	BillOfLading     *BillOfLading     `json:"bill_of_lading,omitempty"`
	Transfer         *Transfer         `json:"transfer,omitempty"`
	Return           *Return           `json:"return,omitempty"`
	Surrender        *Surrender        `json:"surrender,omitempty"`
	AmendmentRequest *AmendmentRequest `json:"amendment_request,omitempty"`
	PrintToPaper     *PrintToPaper     `json:"print_to_paper,omitempty"`
}

type BillOfLading struct {
	BillOfLading *TransportDocument `json:"bill_of_lading,omitempty"`
	File         *model.File        `json:"file,omitempty"`
	TransferTo   string             `json:"transfer_to,omitempty"` // DID
	CreatedBy    string             `json:"created_by,omitempty"`  // DID
	CreatedAt    *model.DateTime    `json:"created_at,omitempty"`
}

type Transfer struct {
	TransferBy string          `json:"transfer_by,omitempty"` // DID
	TransferTo string          `json:"transfer_to,omitempty"` // DID
	TransferAt *model.DateTime `json:"transfer_at,omitempty"`
	Note       string          `json:"note,omitempty"`
}

type Return struct {
	ReturnBy string          `json:"return_by,omitempty"` // DID
	ReturnTo string          `json:"return_to,omitempty"` // DID
	ReturnAt *model.DateTime `json:"return_at,omitempty"`
	Note     string          `json:"note,omitempty"`
}

type Surrender struct {
	SurrenderBy string          `json:"surrender_by,omitempty"` // DID
	SurrenderAt *model.DateTime `json:"surrender_at,omitempty"`
	Note        string          `json:"note,omitempty"`
}

type AmendmentRequest struct {
	RequestBy string          `json:"requested_by,omitempty"` // DID
	RequestAt *model.DateTime `json:"requested_at,omitempty"`
	Note      string          `json:"note,omitempty"`
}

type PrintToPaper struct {
	PrintBy string          `json:"print_by,omitempty"` // DID
	PrintAt *model.DateTime `json:"print_at,omitempty"`
	Note    string          `json:"note,omitempty"`
}
