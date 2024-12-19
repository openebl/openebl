package bill_of_lading

import (
	"encoding/json"

	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/model/trade_document/bill_of_lading/dcsa_v2"
)

type BillOfLadingDocumentType string
type ApplicationMetaData map[string]json.RawMessage

const (
	BillOfLadingDocumentTypeMasterBillOfLading BillOfLadingDocumentType = "MasterBillOfLading"
	BillOfLadingDocumentTypeHouseBillOfLading  BillOfLadingDocumentType = "HouseBillOfLading"
)

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
	Accomplish       *Accomplish       `json:"accomplish,omitempty"`
	Delete           *Delete           `json:"delete,omitempty"`
}

type BillOfLading struct {
	BillOfLading *dcsa_v2.TransportDocument `json:"bill_of_lading,omitempty"`
	File         *model.File                `json:"file,omitempty"`
	DocType      BillOfLadingDocumentType   `json:"doc_type,omitempty"`
	CreatedBy    string                     `json:"created_by,omitempty"` // DID
	CreatedAt    *model.DateTime            `json:"created_at,omitempty"`
	Note         string                     `json:"note,omitempty"`
	MetaData     ApplicationMetaData        `json:"metadata,omitempty"` // Fully customized object. It can be used to store any additional information but will not be used for any business logic.
}

type Transfer struct {
	TransferBy string              `json:"transfer_by,omitempty"` // DID
	TransferTo string              `json:"transfer_to,omitempty"` // DID
	TransferAt *model.DateTime     `json:"transfer_at,omitempty"`
	Note       string              `json:"note,omitempty"`
	MetaData   ApplicationMetaData `json:"metadata,omitempty"` // Fully customized object. It can be used to store any additional information but will not be used for any business logic.
}

type Return struct {
	ReturnBy string              `json:"return_by,omitempty"` // DID
	ReturnTo string              `json:"return_to,omitempty"` // DID
	ReturnAt *model.DateTime     `json:"return_at,omitempty"`
	Note     string              `json:"note,omitempty"`
	MetaData ApplicationMetaData `json:"metadata,omitempty"` // Fully customized object. It can be used to store any additional information but will not be used for any business logic.
}

type Surrender struct {
	SurrenderBy string              `json:"surrender_by,omitempty"` // DID
	SurrenderTo string              `json:"surrender_to,omitempty"` // DID
	SurrenderAt *model.DateTime     `json:"surrender_at,omitempty"`
	Note        string              `json:"note,omitempty"`
	MetaData    ApplicationMetaData `json:"metadata,omitempty"` // Fully customized object. It can be used to store any additional information but will not be used for any business logic.
}

type AmendmentRequest struct {
	RequestBy string              `json:"request_by,omitempty"` // DID
	RequestTo string              `json:"request_to,omitempty"` // DID
	RequestAt *model.DateTime     `json:"request_at,omitempty"`
	Note      string              `json:"note,omitempty"`
	MetaData  ApplicationMetaData `json:"metadata,omitempty"` // Fully customized object. It can be used to store any additional information but will not be used for any business logic.
}

type PrintToPaper struct {
	PrintBy  string              `json:"print_by,omitempty"` // DID
	PrintAt  *model.DateTime     `json:"print_at,omitempty"`
	Note     string              `json:"note,omitempty"`
	MetaData ApplicationMetaData `json:"metadata,omitempty"` // Fully customized object. It can be used to store any additional information but will not be used for any business logic.
}

type Accomplish struct {
	AccomplishBy string              `json:"accomplish_by,omitempty"` // DID
	AccomplishAt *model.DateTime     `json:"accomplish_at,omitempty"`
	Note         string              `json:"note,omitempty"`
	MetaData     ApplicationMetaData `json:"metadata,omitempty"` // Fully customized object. It can be used to store any additional information but will not be used for any business logic.
}

type Delete struct {
	DeleteBy string              `json:"delete_by,omitempty"` // DID
	DeleteAt *model.DateTime     `json:"delete_at,omitempty"`
	Note     string              `json:"note,omitempty"`
	MetaData ApplicationMetaData `json:"metadata,omitempty"` // Fully customized object. It can be used to store any additional information but will not be used for any business logic.
}
