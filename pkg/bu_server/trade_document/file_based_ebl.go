package trade_document

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/nuts-foundation/go-did/did"
	"github.com/openebl/openebl/pkg/bu_server/business_unit"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/model/trade_document/bill_of_lading"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/envelope"
	"github.com/openebl/openebl/pkg/relay"
	"github.com/openebl/openebl/pkg/relay/server"
	"github.com/openebl/openebl/pkg/util"
	"github.com/samber/lo"
)

type File struct {
	Name    string `json:"name"`    // File name
	Type    string `json:"type"`    // MIME type of the file.
	Content []byte `json:"content"` // File content.
}

type Location struct {
	LocationName string `json:"locationName"`
	UNLocCode    string `json:"UNLocationCode"`
}

type IssueFileBasedEBLRequest struct {
	Application      string                             `json:"application"`
	Issuer           string                             `json:"issuer"`
	AuthenticationID string                             `json:"authentication_id"`
	MetaData         bill_of_lading.ApplicationMetaData `json:"metadata"`

	File         File                                    `json:"file"`
	BLNumber     string                                  `json:"bl_number"`
	BLDocType    bill_of_lading.BillOfLadingDocumentType `json:"bl_doc_type"`
	ToOrder      bool                                    `json:"to_order"`
	POL          Location                                `json:"pol"`
	POD          Location                                `json:"pod"`
	ETA          *model.DateTime                         `json:"eta,omitempty"`
	Shipper      string                                  `json:"shipper"`
	Consignee    string                                  `json:"consignee"`
	ReleaseAgent string                                  `json:"release_agent"`
	Note         string                                  `json:"note"`
	Draft        *bool                                   `json:"draft"`
}

type UpdateFileBasedEBLDraftRequest struct {
	IssueFileBasedEBLRequest
	ID string `json:"id"` // ID of the bill of lading pack to be updated.
}

type ReturnFileBasedEBLRequest struct {
	Application      string                             `json:"application"`
	BusinessUnit     string                             `json:"business_unit"`
	AuthenticationID string                             `json:"authentication_id"`
	MetaData         bill_of_lading.ApplicationMetaData `json:"metadata"`

	ID   string `json:"id"`
	Note string `json:"note"`
}

type ListFileBasedEBLRequest struct {
	Application string `json:"application"`
	RequestBy   string `json:"lister"`

	Offset int    `json:"offset"`
	Limit  int    `json:"limit"`
	Status string `json:"status"`
	Report bool   `json:"report"`
}

type ListFileBasedEBLRecord struct {
	Total   int                              `json:"total"`
	Records []FileBasedBillOfLadingRecord    `json:"records"`
	Report  *storage.ListTradeDocumentReport `json:"report,omitempty"`
}

type FileBasedBillOfLadingRecord struct {
	AllowActions []FileBasedEBLAction             `json:"allow_actions"`
	BL           *bill_of_lading.BillOfLadingPack `json:"bl"`
}

type TransferEBLRequest struct {
	Application      string                             `json:"application"`
	TransferBy       string                             `json:"transfer_by"`
	AuthenticationID string                             `json:"authentication_id"`
	MetaData         bill_of_lading.ApplicationMetaData `json:"metadata"`

	ID   string `json:"id"`
	Note string `json:"note"`
}

type AmendmentRequestEBLRequest struct {
	Application      string                             `json:"application"`
	RequestBy        string                             `json:"request_by"`
	AuthenticationID string                             `json:"authentication_id"`
	MetaData         bill_of_lading.ApplicationMetaData `json:"metadata"`

	ID   string `json:"id"`
	Note string `json:"note"`
}

type AmendFileBasedEBLRequest struct {
	Application      string                             `json:"application"`
	Issuer           string                             `json:"issuer"`
	AuthenticationID string                             `json:"authentication_id"`
	MetaData         bill_of_lading.ApplicationMetaData `json:"metadata"`

	ID        string                                  `json:"id"`
	File      File                                    `json:"file"`
	BLNumber  string                                  `json:"bl_number"`
	BLDocType bill_of_lading.BillOfLadingDocumentType `json:"bl_doc_type"`
	ToOrder   bool                                    `json:"to_order"`
	POL       Location                                `json:"pol"`
	POD       Location                                `json:"pod"`
	ETA       *model.DateTime                         `json:"eta,omitempty"`
	Note      string                                  `json:"note"`
}

type SurrenderEBLRequest struct {
	Application      string                             `json:"application"`
	RequestBy        string                             `json:"request_by"`
	AuthenticationID string                             `json:"authentication_id"`
	MetaData         bill_of_lading.ApplicationMetaData `json:"metadata"`

	ID   string `json:"id"`
	Note string `json:"note"`
}

type PrintFileBasedEBLToPaperRequest struct {
	Application      string                             `json:"application"`
	RequestBy        string                             `json:"request_by"`
	AuthenticationID string                             `json:"authentication_id"`
	MetaData         bill_of_lading.ApplicationMetaData `json:"metadata"`

	ID   string `json:"id"`
	Note string `json:"note"`
}

type AccomplishEBLRequest struct {
	Application      string                             `json:"application"`
	RequestBy        string                             `json:"request_by"`
	AuthenticationID string                             `json:"authentication_id"`
	MetaData         bill_of_lading.ApplicationMetaData `json:"metadata"`

	ID   string `json:"id"`
	Note string `json:"note"`
}

type GetFileBasedEBLRequest struct {
	Requester   string `json:"requester"`
	Application string `json:"application"`

	ID string `json:"id"`
}

type DeleteEBLRequest struct {
	Application      string                             `json:"application"`
	RequestBy        string                             `json:"request_by"`
	AuthenticationID string                             `json:"authentication_id"`
	MetaData         bill_of_lading.ApplicationMetaData `json:"metadata"`

	ID   string `json:"id"`
	Note string `json:"note"`
}

type FileBaseEBLParticipators struct {
	Issuer       string `json:"issuer"`
	Shipper      string `json:"shipper"`
	Consignee    string `json:"consignee"`
	ReleaseAgent string `json:"release_agent"`
}

type FileBaseEBLController interface {
	Create(ctx context.Context, ts int64, request IssueFileBasedEBLRequest) (FileBasedBillOfLadingRecord, error)
	UpdateDraft(ctx context.Context, ts int64, request UpdateFileBasedEBLDraftRequest) (FileBasedBillOfLadingRecord, error)
	Return(ctx context.Context, ts int64, request ReturnFileBasedEBLRequest) (FileBasedBillOfLadingRecord, error)
	List(ctx context.Context, request ListFileBasedEBLRequest) (ListFileBasedEBLRecord, error)
	Transfer(ctx context.Context, ts int64, request TransferEBLRequest) (FileBasedBillOfLadingRecord, error)
	AmendmentRequest(ctx context.Context, ts int64, request AmendmentRequestEBLRequest) (FileBasedBillOfLadingRecord, error)
	Amend(ctx context.Context, ts int64, request AmendFileBasedEBLRequest) (FileBasedBillOfLadingRecord, error)
	Surrender(ctx context.Context, ts int64, request SurrenderEBLRequest) (FileBasedBillOfLadingRecord, error)
	PrintToPaper(ctx context.Context, ts int64, request PrintFileBasedEBLToPaperRequest) (FileBasedBillOfLadingRecord, error)
	Accomplish(ctx context.Context, ts int64, request AccomplishEBLRequest) (FileBasedBillOfLadingRecord, error)
	Get(ctx context.Context, request GetFileBasedEBLRequest) (FileBasedBillOfLadingRecord, error)
	Delete(ctx context.Context, ts int64, request DeleteEBLRequest) (FileBasedBillOfLadingRecord, error)
	GetDocument(ctx context.Context, request GetFileBasedEBLRequest) (*model.File, error)
}

type _FileBaseEBLController struct {
	storage storage.TradeDocumentStorage
	buCtrl  business_unit.BusinessUnitManager
}

func NewFileBaseEBLController(storage storage.TradeDocumentStorage, buCtrl business_unit.BusinessUnitManager) *_FileBaseEBLController {
	return &_FileBaseEBLController{
		storage: storage,
		buCtrl:  buCtrl,
	}
}

func (c *_FileBaseEBLController) Create(ctx context.Context, ts int64, request IssueFileBasedEBLRequest) (FileBasedBillOfLadingRecord, error) {
	currentTime := model.NewDateTimeFromUnix(ts)
	if err := ValidateIssueFileBasedEBLRequest(request); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	requiredBUList := []string{request.Issuer}
	if !*request.Draft {
		requiredBUList = append(requiredBUList, request.Shipper, request.Consignee, request.ReleaseAgent)
	}
	if err := c.checkBUExistence(ctx, request.Application, requiredBUList); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	var currentOwner string
	if *request.Draft {
		currentOwner = request.Issuer
	} else {
		currentOwner = request.Shipper
	}

	bl := CreateFileBasedBillOfLadingFromRequest(request, currentTime)
	blPack := bill_of_lading.BillOfLadingPack{
		ID:           uuid.NewString(),
		Version:      1,
		CurrentOwner: currentOwner,
		Events: []bill_of_lading.BillOfLadingEvent{
			{
				BillOfLading: bl,
			},
		},
	}

	if !*request.Draft {
		transfer := bill_of_lading.BillOfLadingEvent{
			Transfer: &bill_of_lading.Transfer{
				TransferBy: request.Issuer,
				TransferTo: request.Shipper,
				TransferAt: &currentTime,
				MetaData:   request.MetaData,
			},
		}
		blPack.Events = append(blPack.Events, transfer)
	}

	td, err := c.signBillOfLadingPack(ctx, ts, blPack, request.Application, request.Issuer, request.AuthenticationID)
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	tx, ctx, err := c.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	defer tx.Rollback(ctx)

	if err := c.storage.AddTradeDocument(ctx, tx, td); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	blPack.Events[0].BillOfLading.File.Content = nil
	result := FileBasedBillOfLadingRecord{
		AllowActions: GetFileBasedEBLAllowActions(&blPack, request.Issuer),
		BL:           &blPack,
	}
	return result, nil
}

func (c *_FileBaseEBLController) UpdateDraft(ctx context.Context, ts int64, request UpdateFileBasedEBLDraftRequest) (FileBasedBillOfLadingRecord, error) {
	currentTime := model.NewDateTimeFromUnix(ts)
	if err := ValidateUpdateFileBasedEBLRequest(request); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	requiredBUList := []string{request.Issuer}
	if !*request.Draft {
		requiredBUList = append(requiredBUList, request.Shipper, request.Consignee, request.ReleaseAgent)
	}
	if err := c.checkBUExistence(ctx, request.Application, requiredBUList); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	tx, ctx, err := c.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	defer tx.Rollback(ctx)

	oldPack, oldHash, err := c.getEBL(ctx, tx, request.ID)
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err := IsFileEBLUpdatable(&oldPack, request.Issuer, true); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	var currentOwner string
	if *request.Draft {
		currentOwner = request.Issuer
	} else {
		currentOwner = request.Shipper
	}

	bl := CreateFileBasedBillOfLadingFromRequest(request.IssueFileBasedEBLRequest, currentTime)
	blPack := bill_of_lading.BillOfLadingPack{
		ID:           oldPack.ID,
		Version:      oldPack.Version + 1,
		CurrentOwner: currentOwner,
		ParentHash:   oldHash,
		Events: []bill_of_lading.BillOfLadingEvent{
			{
				BillOfLading: bl,
			},
		},
	}

	if !*request.Draft {
		transfer := bill_of_lading.BillOfLadingEvent{
			Transfer: &bill_of_lading.Transfer{
				TransferBy: request.Issuer,
				TransferTo: request.Shipper,
				TransferAt: &currentTime,
				Note:       request.Note,
				MetaData:   request.MetaData,
			},
		}
		blPack.Events = append(blPack.Events, transfer)
	}

	td, err := c.signBillOfLadingPack(ctx, ts, blPack, request.Application, request.Issuer, request.AuthenticationID)
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	if err := c.storage.AddTradeDocument(ctx, tx, td); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	blPack.Events[0].BillOfLading.File.Content = nil
	result := FileBasedBillOfLadingRecord{
		AllowActions: GetFileBasedEBLAllowActions(&blPack, request.Issuer),
		BL:           &blPack,
	}
	return result, nil
}

func (c *_FileBaseEBLController) Return(ctx context.Context, ts int64, req ReturnFileBasedEBLRequest) (FileBasedBillOfLadingRecord, error) {
	currentTime := model.NewDateTimeFromUnix(ts)
	if err := ValidateReturnFileBasedEBLRequest(req); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	tx, ctx, err := c.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	defer tx.Rollback(ctx)

	oldPack, oldHash, err := c.getEBL(ctx, tx, req.ID)
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err := IsFileEBLReturnable(&oldPack, req.BusinessUnit, true); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	nextOwner := GetNextOwnerByAction(FILE_EBL_RETURN, req.BusinessUnit, &oldPack)
	if nextOwner == "" {
		return FileBasedBillOfLadingRecord{}, errors.New("cannot determine next owner due to invalid role or action")
	}

	blPack := bill_of_lading.BillOfLadingPack{
		ID:           oldPack.ID,
		Version:      oldPack.Version + 1,
		ParentHash:   oldHash,
		Events:       oldPack.Events,
		CurrentOwner: nextOwner,
	}
	returnEvent := bill_of_lading.BillOfLadingEvent{
		Return: &bill_of_lading.Return{
			ReturnBy: req.BusinessUnit,
			ReturnTo: nextOwner,
			ReturnAt: &currentTime,
			Note:     req.Note,
			MetaData: req.MetaData,
		},
	}
	blPack.Events = append(blPack.Events, returnEvent)

	td, err := c.signBillOfLadingPack(ctx, ts, blPack, req.Application, req.BusinessUnit, req.AuthenticationID)
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	if err := c.storage.AddTradeDocument(ctx, tx, td); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	blPack.Events[0].BillOfLading.File.Content = nil
	result := FileBasedBillOfLadingRecord{
		AllowActions: GetFileBasedEBLAllowActions(&blPack, req.BusinessUnit),
		BL:           &blPack,
	}
	return result, nil
}

func CreateFileBasedBillOfLadingFromRequest(request IssueFileBasedEBLRequest, currentTime model.DateTime) *bill_of_lading.BillOfLading {
	bl := &bill_of_lading.BillOfLading{
		BillOfLading: &bill_of_lading.TransportDocument{
			TransportDocumentReference: request.BLNumber,
		},
		File: &model.File{
			Name:        request.File.Name,
			FileType:    request.File.Type,
			Content:     request.File.Content,
			CreatedDate: currentTime,
		},
		DocType:   request.BLDocType,
		CreatedBy: request.Issuer,
		CreatedAt: &currentTime,
		Note:      request.Note,
		MetaData:  request.MetaData,
	}

	td := bl.BillOfLading
	SetPOL(td, request.POL)
	SetPOD(td, request.POD)
	if request.ETA != nil {
		SetETA(td, *request.ETA)
	}
	SetIssuer(td, request.Issuer)
	SetShipper(td, request.Shipper)
	SetConsignee(td, request.Consignee)
	SetReleaseAgent(td, request.ReleaseAgent)
	SetToOrder(td, request.ToOrder)
	if request.Draft != nil {
		SetDraft(td, *request.Draft)
	}
	return bl
}

func AmendFileBasedBillOfLadingFromRequest(req AmendFileBasedEBLRequest, oldPack bill_of_lading.BillOfLadingPack, currentTime model.DateTime) *bill_of_lading.BillOfLading {
	bl := &bill_of_lading.BillOfLading{
		BillOfLading: &bill_of_lading.TransportDocument{
			TransportDocumentReference: req.BLNumber,
		},
		File: &model.File{
			Name:        req.File.Name,
			FileType:    req.File.Type,
			Content:     req.File.Content,
			CreatedDate: currentTime,
		},
		DocType:   req.BLDocType,
		CreatedBy: req.Issuer,
		CreatedAt: &currentTime,
		Note:      req.Note,
		MetaData:  req.MetaData,
	}

	parties := GetFileBaseEBLParticipatorsFromBLPack(&oldPack)
	td := bl.BillOfLading
	SetPOL(td, req.POL)
	SetPOD(td, req.POD)
	if req.ETA != nil {
		SetETA(td, *req.ETA)
	}
	SetIssuer(td, parties.Issuer)
	SetShipper(td, parties.Shipper)
	SetConsignee(td, parties.Consignee)
	SetReleaseAgent(td, parties.ReleaseAgent)
	SetToOrder(td, req.ToOrder)
	SetDraft(td, false)
	return bl
}

func (c *_FileBaseEBLController) List(ctx context.Context, req ListFileBasedEBLRequest) (ListFileBasedEBLRecord, error) {
	if err := ValidateListFileBasedEBLRequest(req); err != nil {
		return ListFileBasedEBLRecord{}, err
	}

	if err := c.checkBUExistence(ctx, req.Application, []string{req.RequestBy}); err != nil {
		return ListFileBasedEBLRecord{}, err
	}

	tx, ctx, err := c.storage.CreateTx(ctx)
	if err != nil {
		return ListFileBasedEBLRecord{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	listReq := storage.ListTradeDocumentRequest{
		Offset:    req.Offset,
		Limit:     req.Limit,
		RequestBy: req.RequestBy,
		Kind:      int(relay.FileBasedBillOfLading),
		Report:    req.Report,
	}
	if req.Status != "" {
		listReq.Meta = map[string]any{strings.ToLower(req.Status): []string{req.RequestBy}}
	}

	listResp, err := c.storage.ListTradeDocument(ctx, tx, listReq)
	if err != nil {
		return ListFileBasedEBLRecord{}, err
	}

	res := ListFileBasedEBLRecord{
		Total:  listResp.Total,
		Report: listResp.Report,
		Records: lo.Map(listResp.Docs, func(td storage.TradeDocument, _ int) FileBasedBillOfLadingRecord {
			blPack, _ := ExtractBLPackFromTradeDocument(td)
			for _, e := range blPack.Events {
				if e.BillOfLading != nil {
					e.BillOfLading.File.Content = nil
				}
			}

			return FileBasedBillOfLadingRecord{
				AllowActions: GetFileBasedEBLAllowActions(&blPack, req.RequestBy),
				BL:           &blPack,
			}
		}),
	}

	return res, nil
}

func (c *_FileBaseEBLController) Transfer(ctx context.Context, ts int64, req TransferEBLRequest) (FileBasedBillOfLadingRecord, error) {
	currentTime := model.NewDateTimeFromUnix(ts)
	if err := ValidateTransferEBLRequest(req); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	if err := c.checkBUExistence(ctx, req.Application, []string{req.TransferBy}); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	tx, ctx, err := c.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	oldPack, oldHash, err := c.getEBL(ctx, tx, req.ID)
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = IsFileEBLTransferable(&oldPack, req.TransferBy, true); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	nextOwner := GetNextOwnerByAction(FILE_EBL_TRANSFER, req.TransferBy, &oldPack)
	if nextOwner == "" {
		return FileBasedBillOfLadingRecord{}, errors.New("cannot determine next owner due to invalid role or action")
	}

	blPack := bill_of_lading.BillOfLadingPack{
		ID:           oldPack.ID,
		Version:      oldPack.Version + 1,
		ParentHash:   oldHash,
		Events:       oldPack.Events,
		CurrentOwner: nextOwner,
	}
	transfer := bill_of_lading.BillOfLadingEvent{
		Transfer: &bill_of_lading.Transfer{
			TransferBy: req.TransferBy,
			TransferTo: nextOwner,
			TransferAt: &currentTime,
			Note:       req.Note,
			MetaData:   req.MetaData,
		},
	}
	blPack.Events = append(blPack.Events, transfer)

	td, err := c.signBillOfLadingPack(ctx, ts, blPack, req.Application, req.TransferBy, req.AuthenticationID)
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = c.storage.AddTradeDocument(ctx, tx, td); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	lo.ForEach(blPack.Events, func(e bill_of_lading.BillOfLadingEvent, _ int) {
		if e.BillOfLading != nil {
			e.BillOfLading.File.Content = nil
		}
	})
	result := FileBasedBillOfLadingRecord{
		AllowActions: GetFileBasedEBLAllowActions(&blPack, req.TransferBy),
		BL:           &blPack,
	}
	return result, nil
}

func (c *_FileBaseEBLController) AmendmentRequest(ctx context.Context, ts int64, req AmendmentRequestEBLRequest) (FileBasedBillOfLadingRecord, error) {
	currentTime := model.NewDateTimeFromUnix(ts)
	if err := ValidateAmendmentRequestEBLRequest(req); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	if err := c.checkBUExistence(ctx, req.Application, []string{req.RequestBy}); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	tx, ctx, err := c.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	oldPack, oldHash, err := c.getEBL(ctx, tx, req.ID)
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = IsFileEBLRequestAmendable(&oldPack, req.RequestBy, true); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	nextOwner := GetNextOwnerByAction(FILE_EBL_REQUEST_AMEND, req.RequestBy, &oldPack)
	if nextOwner == "" {
		return FileBasedBillOfLadingRecord{}, errors.New("cannot determine next owner due to invalid role or action")
	}

	blPack := bill_of_lading.BillOfLadingPack{
		ID:           oldPack.ID,
		Version:      oldPack.Version + 1,
		ParentHash:   oldHash,
		Events:       oldPack.Events,
		CurrentOwner: nextOwner,
	}
	amendmentRequest := bill_of_lading.BillOfLadingEvent{
		AmendmentRequest: &bill_of_lading.AmendmentRequest{
			RequestBy: req.RequestBy,
			RequestTo: nextOwner,
			RequestAt: &currentTime,
			Note:      req.Note,
			MetaData:  req.MetaData,
		},
	}
	blPack.Events = append(blPack.Events, amendmentRequest)

	td, err := c.signBillOfLadingPack(ctx, ts, blPack, req.Application, req.RequestBy, req.AuthenticationID)
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = c.storage.AddTradeDocument(ctx, tx, td); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	lo.ForEach(blPack.Events, func(e bill_of_lading.BillOfLadingEvent, _ int) {
		if e.BillOfLading != nil {
			e.BillOfLading.File.Content = nil
		}
	})
	result := FileBasedBillOfLadingRecord{
		AllowActions: GetFileBasedEBLAllowActions(&blPack, req.RequestBy),
		BL:           &blPack,
	}
	return result, nil
}

func (c *_FileBaseEBLController) Amend(ctx context.Context, ts int64, req AmendFileBasedEBLRequest) (FileBasedBillOfLadingRecord, error) {
	currentTime := model.NewDateTimeFromUnix(ts)
	if err := ValidateAmendFileBasedEBLRequest(req); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	if err := c.checkBUExistence(ctx, req.Application, []string{req.Issuer}); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	tx, ctx, err := c.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	oldPack, oldHash, err := c.getEBL(ctx, tx, req.ID)
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err := IsFileEBLAmendable(&oldPack, req.Issuer, true); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	nextOwner := GetNextOwnerByAction(FILE_EBL_AMEND, req.Issuer, &oldPack)
	if nextOwner == "" {
		return FileBasedBillOfLadingRecord{}, errors.New("cannot determine next owner due to invalid role or action")
	}
	blPack := bill_of_lading.BillOfLadingPack{
		ID:           oldPack.ID,
		Version:      oldPack.Version + 1,
		CurrentOwner: nextOwner,
		ParentHash:   oldHash,
		Events:       oldPack.Events,
	}

	amendedBL := bill_of_lading.BillOfLadingEvent{BillOfLading: AmendFileBasedBillOfLadingFromRequest(req, oldPack, currentTime)}
	transfer := bill_of_lading.BillOfLadingEvent{Transfer: &bill_of_lading.Transfer{
		TransferBy: req.Issuer,
		TransferTo: nextOwner,
		TransferAt: &currentTime,
		Note:       req.Note,
		MetaData:   req.MetaData,
	}}
	blPack.Events = append(blPack.Events, amendedBL, transfer)

	td, err := c.signBillOfLadingPack(ctx, ts, blPack, req.Application, req.Issuer, req.AuthenticationID)
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = c.storage.AddTradeDocument(ctx, tx, td); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	lo.ForEach(blPack.Events, func(e bill_of_lading.BillOfLadingEvent, _ int) {
		if e.BillOfLading != nil {
			e.BillOfLading.File.Content = nil
		}
	})
	result := FileBasedBillOfLadingRecord{
		AllowActions: GetFileBasedEBLAllowActions(&blPack, req.Issuer),
		BL:           &blPack,
	}
	return result, nil
}

func (c *_FileBaseEBLController) Surrender(ctx context.Context, ts int64, req SurrenderEBLRequest) (FileBasedBillOfLadingRecord, error) {
	currentTime := model.NewDateTimeFromUnix(ts)
	if err := ValidateSurrenderEBLRequest(req); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	tx, ctx, err := c.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	oldPack, oldHash, err := c.getEBL(ctx, tx, req.ID)
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = IsFileEBLSurrenderable(&oldPack, req.RequestBy, true); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	nextOwner := GetNextOwnerByAction(FILE_EBL_SURRENDER, req.RequestBy, &oldPack)
	if nextOwner == "" {
		return FileBasedBillOfLadingRecord{}, errors.New("cannot determine next owner due to invalid role or action")
	}

	blPack := bill_of_lading.BillOfLadingPack{
		ID:           oldPack.ID,
		Version:      oldPack.Version + 1,
		ParentHash:   oldHash,
		Events:       oldPack.Events,
		CurrentOwner: nextOwner,
	}
	surrender := bill_of_lading.BillOfLadingEvent{
		Surrender: &bill_of_lading.Surrender{
			SurrenderBy: req.RequestBy,
			SurrenderTo: nextOwner,
			SurrenderAt: &currentTime,
			Note:        req.Note,
			MetaData:    req.MetaData,
		},
	}
	blPack.Events = append(blPack.Events, surrender)

	td, err := c.signBillOfLadingPack(ctx, ts, blPack, req.Application, req.RequestBy, req.AuthenticationID)
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = c.storage.AddTradeDocument(ctx, tx, td); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	lo.ForEach(blPack.Events, func(e bill_of_lading.BillOfLadingEvent, _ int) {
		if e.BillOfLading != nil {
			e.BillOfLading.File.Content = nil
		}
	})
	result := FileBasedBillOfLadingRecord{
		AllowActions: GetFileBasedEBLAllowActions(&blPack, req.RequestBy),
		BL:           &blPack,
	}
	return result, nil
}

func (c *_FileBaseEBLController) PrintToPaper(ctx context.Context, ts int64, req PrintFileBasedEBLToPaperRequest) (FileBasedBillOfLadingRecord, error) {
	if err := ValidatePrintFileBasedEBLRequest(req); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	currentTime := model.NewDateTimeFromUnix(ts)
	tx, ctx, err := c.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	oldPack, oldHash, err := c.getEBL(ctx, tx, req.ID)
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = IsFileEBLPrintable(&oldPack, req.RequestBy, true); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	blPack := bill_of_lading.BillOfLadingPack{
		ID:           oldPack.ID,
		Version:      oldPack.Version + 1,
		ParentHash:   oldHash,
		Events:       oldPack.Events,
		CurrentOwner: oldPack.CurrentOwner,
	}
	print := bill_of_lading.BillOfLadingEvent{
		PrintToPaper: &bill_of_lading.PrintToPaper{
			PrintBy:  req.RequestBy,
			PrintAt:  &currentTime,
			Note:     req.Note,
			MetaData: req.MetaData,
		},
	}
	blPack.Events = append(blPack.Events, print)

	td, err := c.signBillOfLadingPack(ctx, ts, blPack, req.Application, req.RequestBy, req.AuthenticationID)
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = c.storage.AddTradeDocument(ctx, tx, td); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	if err = tx.Commit(ctx); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	lo.ForEach(blPack.Events, func(e bill_of_lading.BillOfLadingEvent, _ int) {
		if e.BillOfLading != nil {
			e.BillOfLading.File.Content = nil
		}
	})
	result := FileBasedBillOfLadingRecord{
		AllowActions: GetFileBasedEBLAllowActions(&blPack, req.RequestBy),
		BL:           &blPack,
	}
	return result, nil
}

func (c *_FileBaseEBLController) Accomplish(ctx context.Context, ts int64, req AccomplishEBLRequest) (FileBasedBillOfLadingRecord, error) {
	currentTime := model.NewDateTimeFromUnix(ts)
	if err := ValidateAccomplishEBLRequest(req); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	tx, ctx, err := c.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	oldPack, oldHash, err := c.getEBL(ctx, tx, req.ID)
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = IsFileEBLAccomplishable(&oldPack, req.RequestBy, true); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	blPack := bill_of_lading.BillOfLadingPack{
		ID:           oldPack.ID,
		Version:      oldPack.Version + 1,
		ParentHash:   oldHash,
		Events:       oldPack.Events,
		CurrentOwner: oldPack.CurrentOwner,
	}
	accomplish := bill_of_lading.BillOfLadingEvent{
		Accomplish: &bill_of_lading.Accomplish{
			AccomplishBy: req.RequestBy,
			AccomplishAt: &currentTime,
			Note:         req.Note,
			MetaData:     req.MetaData,
		},
	}
	blPack.Events = append(blPack.Events, accomplish)

	td, err := c.signBillOfLadingPack(ctx, ts, blPack, req.Application, req.RequestBy, req.AuthenticationID)
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = c.storage.AddTradeDocument(ctx, tx, td); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	lo.ForEach(blPack.Events, func(e bill_of_lading.BillOfLadingEvent, _ int) {
		if e.BillOfLading != nil {
			e.BillOfLading.File.Content = nil
		}
	})
	result := FileBasedBillOfLadingRecord{
		AllowActions: GetFileBasedEBLAllowActions(&blPack, req.RequestBy),
		BL:           &blPack,
	}
	return result, nil
}

func (c *_FileBaseEBLController) Delete(ctx context.Context, ts int64, req DeleteEBLRequest) (FileBasedBillOfLadingRecord, error) {
	currentTime := model.NewDateTimeFromUnix(ts)
	if err := ValidateDeleteEBLRequest(req); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	tx, ctx, err := c.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	oldPack, oldHash, err := c.getEBL(ctx, tx, req.ID)
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = IsFileEBLDeletable(&oldPack, req.RequestBy, true); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	blPack := bill_of_lading.BillOfLadingPack{
		ID:           oldPack.ID,
		Version:      oldPack.Version + 1,
		ParentHash:   oldHash,
		Events:       oldPack.Events,
		CurrentOwner: oldPack.CurrentOwner,
	}
	del := bill_of_lading.BillOfLadingEvent{
		Delete: &bill_of_lading.Delete{
			DeleteBy: req.RequestBy,
			DeleteAt: &currentTime,
			MetaData: req.MetaData,
		},
	}
	blPack.Events = append(blPack.Events, del)

	td, err := c.signBillOfLadingPack(ctx, ts, blPack, req.Application, req.RequestBy, req.AuthenticationID)
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = c.storage.AddTradeDocument(ctx, tx, td); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	blPack.Events[0].BillOfLading.File.Content = nil
	result := FileBasedBillOfLadingRecord{
		AllowActions: GetFileBasedEBLAllowActions(&blPack, req.RequestBy),
		BL:           &blPack,
	}
	return result, nil
}

func (c *_FileBaseEBLController) Get(ctx context.Context, request GetFileBasedEBLRequest) (FileBasedBillOfLadingRecord, error) {
	if err := c.checkBUExistence(ctx, request.Application, []string{request.Requester}); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	tx, ctx, err := c.storage.CreateTx(ctx)
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	req := storage.ListTradeDocumentRequest{
		Limit:  1,
		DocIDs: []string{request.ID},
		Meta:   map[string]any{"visible_to_bu": []string{request.Requester}},
	}

	resp, err := c.storage.ListTradeDocument(ctx, tx, req)
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	if len(resp.Docs) == 0 {
		return FileBasedBillOfLadingRecord{}, model.ErrEBLNotFound
	}

	blPack, err := ExtractBLPackFromTradeDocument(resp.Docs[0])
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	lo.ForEach(blPack.Events, func(e bill_of_lading.BillOfLadingEvent, _ int) {
		if e.BillOfLading != nil {
			e.BillOfLading.File.Content = nil
		}
	})
	result := FileBasedBillOfLadingRecord{
		AllowActions: GetFileBasedEBLAllowActions(&blPack, request.Requester),
		BL:           &blPack,
	}
	return result, nil
}

func (c *_FileBaseEBLController) GetDocument(ctx context.Context, request GetFileBasedEBLRequest) (*model.File, error) {
	if err := c.checkBUExistence(ctx, request.Application, []string{request.Requester}); err != nil {
		return nil, err
	}

	tx, ctx, err := c.storage.CreateTx(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	req := storage.ListTradeDocumentRequest{
		Limit:  1,
		DocIDs: []string{request.ID},
		Meta:   map[string]any{"visible_to_bu": []string{request.Requester}},
	}

	resp, err := c.storage.ListTradeDocument(ctx, tx, req)
	if err != nil {
		return nil, err
	}

	if len(resp.Docs) == 0 {
		return nil, model.ErrEBLNotFound
	}

	blPack, err := ExtractBLPackFromTradeDocument(resp.Docs[0])
	if err != nil {
		return nil, err
	}

	blPackEvent, _, ok := lo.FindLastIndexOf(blPack.Events, func(e bill_of_lading.BillOfLadingEvent) bool {
		return e.BillOfLading != nil && e.BillOfLading.File != nil
	})
	if !ok {
		return nil, model.ErrEBLNoDocument
	}

	return blPackEvent.BillOfLading.File, nil
}

func (c *_FileBaseEBLController) checkBUExistence(ctx context.Context, appID string, buIDs []string) error {
	req := business_unit.ListBusinessUnitsRequest{
		Limit:           len(buIDs),
		ApplicationID:   appID,
		BusinessUnitIDs: buIDs,
	}

	result, err := c.buCtrl.ListBusinessUnits(ctx, req)
	if err != nil {
		return err
	}

	buIDSet := make(map[string]bool)
	for _, id := range buIDs {
		buIDSet[id] = true
	}

	for _, bu := range result.Records {
		if !buIDSet[bu.BusinessUnit.ID.String()] {
			continue
		}
		delete(buIDSet, bu.BusinessUnit.ID.String())
		if bu.BusinessUnit.Status != model.BusinessUnitStatusActive {
			return fmt.Errorf("business unit %q is not active. %w", bu.BusinessUnit.ID.String(), model.ErrBusinessUnitInActive)
		}
	}

	if len(buIDSet) > 0 {
		return fmt.Errorf("business unit %q not found. %w", lo.Keys(buIDSet), model.ErrBusinessUnitNotFound)
	}

	return nil
}

func (c *_FileBaseEBLController) signBillOfLadingPack(ctx context.Context, ts int64, blPack bill_of_lading.BillOfLadingPack, appID, signer, authID string) (storage.TradeDocument, error) {
	getSignerReq := business_unit.GetJWSSignerRequest{
		ApplicationID:    appID,
		BusinessUnitID:   did.MustParseDID(signer),
		AuthenticationID: authID,
	}

	jwsSigner, err := c.buCtrl.GetJWSSigner(ctx, getSignerReq)
	if err != nil {
		return storage.TradeDocument{}, err
	}

	doc, err := envelope.Sign(
		[]byte(util.StructToJSON(blPack)),
		jwsSigner.AvailableJWSSignAlgorithms()[0],
		jwsSigner,
		jwsSigner.Cert(),
	)
	if err != nil {
		return storage.TradeDocument{}, err
	}

	rawDoc := util.StructToJSON(doc)
	meta, err := GetBillOfLadingPackMeta(&blPack)
	if err != nil {
		return storage.TradeDocument{}, err
	}

	td := storage.TradeDocument{
		RawID:      server.GetEventID([]byte(rawDoc)),
		Kind:       int(relay.FileBasedBillOfLading),
		DocID:      blPack.ID,
		DocVersion: blPack.Version,
		Doc:        []byte(rawDoc),
		CreatedAt:  ts,
		Meta:       meta,
	}

	return td, nil
}

func (c *_FileBaseEBLController) getEBL(ctx context.Context, tx storage.Tx, id string) (bill_of_lading.BillOfLadingPack, string, error) {
	req := storage.ListTradeDocumentRequest{
		Limit:  1,
		DocIDs: []string{id},
	}

	resp, err := c.storage.ListTradeDocument(ctx, tx, req)
	if err != nil {
		return bill_of_lading.BillOfLadingPack{}, "", err
	}

	if len(resp.Docs) == 0 {
		return bill_of_lading.BillOfLadingPack{}, "", model.ErrEBLNotFound
	}

	pack, err := ExtractBLPackFromTradeDocument(resp.Docs[0])
	if err != nil {
		return bill_of_lading.BillOfLadingPack{}, "", err
	}

	hash := envelope.SHA512(resp.Docs[0].Doc)
	return pack, hash, nil
}

func ExtractBLPackFromTradeDocument(td storage.TradeDocument) (bill_of_lading.BillOfLadingPack, error) {
	doc := envelope.JWS{}
	if err := json.Unmarshal(td.Doc, &doc); err != nil {
		return bill_of_lading.BillOfLadingPack{}, err
	}
	rawPack, err := doc.GetPayload()
	if err != nil {
		return bill_of_lading.BillOfLadingPack{}, err
	}

	res := bill_of_lading.BillOfLadingPack{}
	err = json.Unmarshal(rawPack, &res)
	if err != nil {
		return bill_of_lading.BillOfLadingPack{}, err
	}

	return res, nil
}

func SetPOL(td *bill_of_lading.TransportDocument, pol Location) {
	loc := bill_of_lading.ShipmentLocation{
		Location: &bill_of_lading.Location{
			LocationName:   pol.LocationName,
			UNLocationCode: pol.UNLocCode,
		},
		ShipmentLocationTypeCode: bill_of_lading.POL_ShipmentLocationTypeCode,
	}

	ReplaceShipmentLocation(td, loc)
}

func SetPOD(td *bill_of_lading.TransportDocument, pod Location) {
	loc := bill_of_lading.ShipmentLocation{
		Location: &bill_of_lading.Location{
			LocationName:   pod.LocationName,
			UNLocationCode: pod.UNLocCode,
		},
		ShipmentLocationTypeCode: bill_of_lading.POD_ShipmentLocationTypeCode,
	}

	ReplaceShipmentLocation(td, loc)
}

func SetETA(td *bill_of_lading.TransportDocument, eta model.DateTime) {
	for i := range td.ShipmentLocations {
		if td.ShipmentLocations[i].ShipmentLocationTypeCode == bill_of_lading.POD_ShipmentLocationTypeCode {
			td.ShipmentLocations[i].EventDateTime = &eta
			return
		}
	}
}

func SetIssuer(td *bill_of_lading.TransportDocument, issuer string) {
	si := PrepareSI(td)
	party := PrepareDocumentParty(issuer, bill_of_lading.DDR_PartyFunction)
	td.IssuingParty = party.Party
	ReplaceSIParty(si, party)
}

func SetConsignee(td *bill_of_lading.TransportDocument, consignee string) {
	si := PrepareSI(td)
	party := PrepareDocumentParty(consignee, bill_of_lading.CN_PartyFunction)
	ReplaceSIParty(si, party)
}

func SetShipper(td *bill_of_lading.TransportDocument, shipper string) {
	si := PrepareSI(td)
	party := PrepareDocumentParty(shipper, bill_of_lading.OS_PartyFunction)
	ReplaceSIParty(si, party)
}

func SetReleaseAgent(td *bill_of_lading.TransportDocument, releaseAgent string) {
	si := PrepareSI(td)
	party := PrepareDocumentParty(releaseAgent, bill_of_lading.DDS_PartyFunction)
	ReplaceSIParty(si, party)
}

func SetToOrder(td *bill_of_lading.TransportDocument, toOrder bool) {
	si := PrepareSI(td)
	si.IsToOrder = toOrder
}

func SetDraft(td *bill_of_lading.TransportDocument, draft bool) {
	si := PrepareSI(td)

	if draft {
		si.DocumentStatus = bill_of_lading.DRFT_EblDocumentStatus
	} else {
		si.DocumentStatus = bill_of_lading.ISSU_EblDocumentStatus
	}
}

func GetDraft(blPack *bill_of_lading.BillOfLadingPack) *bool {
	if blPack == nil || len(blPack.Events) == 0 {
		return nil
	}
	if len(blPack.Events) > 1 {
		return util.Ptr(false)
	}
	firstEvent := blPack.Events[0]
	if firstEvent.BillOfLading == nil ||
		firstEvent.BillOfLading.BillOfLading == nil ||
		firstEvent.BillOfLading.BillOfLading.ShippingInstruction == nil {
		return nil
	}

	status := firstEvent.BillOfLading.BillOfLading.ShippingInstruction.DocumentStatus
	if status == bill_of_lading.DRFT_EblDocumentStatus {
		return util.Ptr(true)
	}
	if status == bill_of_lading.ISSU_EblDocumentStatus {
		return util.Ptr(false)
	}
	return nil
}

func GetIssuer(blPack *bill_of_lading.BillOfLadingPack) *string {
	if blPack == nil || len(blPack.Events) == 0 {
		return nil
	}

	firstEvent := blPack.Events[0]
	if firstEvent.BillOfLading == nil ||
		firstEvent.BillOfLading.BillOfLading == nil ||
		firstEvent.BillOfLading.BillOfLading.ShippingInstruction == nil {
		return nil
	}

	si := firstEvent.BillOfLading.BillOfLading.ShippingInstruction
	for i := range si.DocumentParties {
		party := si.DocumentParties[i]
		if party.PartyFunction != nil && *party.PartyFunction == bill_of_lading.DDR_PartyFunction {
			return util.Ptr(party.Party.IdentifyingCodes[0].PartyCode)
		}
	}

	return nil
}

func GetFileBaseEBLParticipatorsFromBLPack(blPack *bill_of_lading.BillOfLadingPack) FileBaseEBLParticipators {
	if blPack == nil || len(blPack.Events) == 0 {
		return FileBaseEBLParticipators{}
	}

	var bl *bill_of_lading.BillOfLading
	for i := len(blPack.Events) - 1; i >= 0; i-- {
		if blPack.Events[i].BillOfLading != nil {
			bl = blPack.Events[i].BillOfLading
			break
		}
	}
	if bl == nil {
		return FileBaseEBLParticipators{}
	}
	return GetFileBaseEBLParticipatorFromBL(bl)
}

func GetFileBaseEBLParticipatorFromBL(bl *bill_of_lading.BillOfLading) FileBaseEBLParticipators {
	if bl.BillOfLading == nil {
		return FileBaseEBLParticipators{}
	}

	si := bl.BillOfLading.ShippingInstruction
	if si == nil {
		return FileBaseEBLParticipators{}
	}

	result := FileBaseEBLParticipators{}
	for i := len(si.DocumentParties) - 1; i >= 0; i-- {
		if len(si.DocumentParties[i].Party.IdentifyingCodes) == 0 {
			continue
		}
		partyFunction := si.DocumentParties[i].PartyFunction
		if partyFunction == nil {
			continue
		}
		switch *partyFunction {
		case bill_of_lading.DDR_PartyFunction: // Issuer
			result.Issuer = si.DocumentParties[i].Party.IdentifyingCodes[0].PartyCode
		case bill_of_lading.OS_PartyFunction: // Shipper
			result.Shipper = si.DocumentParties[i].Party.IdentifyingCodes[0].PartyCode
		case bill_of_lading.CN_PartyFunction: // Consignee
			result.Consignee = si.DocumentParties[i].Party.IdentifyingCodes[0].PartyCode
		case bill_of_lading.DDS_PartyFunction: // Release Agent
			result.ReleaseAgent = si.DocumentParties[i].Party.IdentifyingCodes[0].PartyCode
		}
	}
	return result
}

func GetCurrentOwner(blPack *bill_of_lading.BillOfLadingPack) string {
	if blPack == nil || len(blPack.Events) == 0 {
		return ""
	}

	return blPack.CurrentOwner
}

func GetNextOwnerByAction(action FileBasedEBLAction, bu string, blPack *bill_of_lading.BillOfLadingPack) string {
	parties := GetFileBaseEBLParticipatorsFromBLPack(blPack)
	switch action {
	case FILE_EBL_TRANSFER:
		if bu == parties.Issuer {
			lastEvent := GetLastEvent(blPack)
			if lastEvent.Return != nil && lastEvent.Return.ReturnBy == parties.Shipper {
				return lastEvent.Return.ReturnBy
			}
		}
		if bu == parties.Shipper {
			return parties.Consignee
		}
	case FILE_EBL_RETURN:
		if bu == parties.ReleaseAgent {
			return parties.Consignee
		}
		if bu == parties.Consignee {
			return parties.Shipper
		}
		if bu == parties.Shipper {
			return parties.Issuer
		}
		if bu == parties.Issuer {
			lastEvent := GetLastEvent(blPack)
			if lastEvent.AmendmentRequest != nil {
				return lastEvent.AmendmentRequest.RequestBy
			}
		}
	case FILE_EBL_SURRENDER:
		if bu == parties.Consignee {
			return parties.ReleaseAgent
		}
	case FILE_EBL_REQUEST_AMEND:
		if bu != parties.Issuer {
			return parties.Issuer
		}
	case FILE_EBL_AMEND:
		if bu == parties.Issuer {
			lastEvent := GetLastEvent(blPack)
			if lastEvent.AmendmentRequest != nil {
				return lastEvent.AmendmentRequest.RequestBy
			}
			if lastEvent.Return != nil && lastEvent.Return.ReturnBy == parties.Shipper {
				return lastEvent.Return.ReturnBy
			}
		}
	}

	return ""
}

func GetLastEvent(blPack *bill_of_lading.BillOfLadingPack) *bill_of_lading.BillOfLadingEvent {
	if blPack == nil || len(blPack.Events) == 0 {
		return nil
	}

	return &blPack.Events[len(blPack.Events)-1]
}

// GetOwnerShipTransferringByEvent returns the transferring information of the bill of lading event.
// The first return value is the transferring by DID, and the second return value is the transferring to DID.
func GetOwnerShipTransferringByEvent(event *bill_of_lading.BillOfLadingEvent) (string, string) {
	if event == nil {
		return "", ""
	}

	if event.BillOfLading != nil {
		parties := GetFileBaseEBLParticipatorFromBL(event.BillOfLading)
		return parties.Issuer, parties.Issuer
	}
	if event.Transfer != nil {
		return event.Transfer.TransferBy, event.Transfer.TransferTo
	}
	if event.Return != nil {
		return event.Return.ReturnBy, event.Return.ReturnTo
	}
	if event.Surrender != nil {
		return event.Surrender.SurrenderBy, event.Surrender.SurrenderTo
	}
	if event.AmendmentRequest != nil {
		return event.AmendmentRequest.RequestBy, event.AmendmentRequest.RequestTo
	}
	if event.Accomplish != nil {
		return event.Accomplish.AccomplishBy, event.Accomplish.AccomplishBy
	}
	if event.PrintToPaper != nil {
		return event.PrintToPaper.PrintBy, event.PrintToPaper.PrintBy
	}

	return "", ""
}

func PrepareSI(td *bill_of_lading.TransportDocument) *bill_of_lading.ShippingInstruction {
	if td.ShippingInstruction != nil {
		return td.ShippingInstruction
	}

	si := &bill_of_lading.ShippingInstruction{}

	td.ShippingInstruction = si
	return si
}

func ReplaceSIParty(si *bill_of_lading.ShippingInstruction, party bill_of_lading.DocumentParty) {
	for i := range si.DocumentParties {
		partyFunc := si.DocumentParties[i].PartyFunction
		if partyFunc != nil && *partyFunc == *party.PartyFunction {
			si.DocumentParties[i] = party
			return
		}
	}
	si.DocumentParties = append(si.DocumentParties, party)
}

func ReplaceShipmentLocation(td *bill_of_lading.TransportDocument, loc bill_of_lading.ShipmentLocation) {
	for i := range td.ShipmentLocations {
		if td.ShipmentLocations[i].ShipmentLocationTypeCode == loc.ShipmentLocationTypeCode {
			td.ShipmentLocations[i] = loc
			return
		}
	}
	td.ShipmentLocations = append(td.ShipmentLocations, loc)
}

func PrepareDocumentParty(party string, partyFunction bill_of_lading.PartyFunction) bill_of_lading.DocumentParty {
	return bill_of_lading.DocumentParty{
		Party: &bill_of_lading.Party{
			IdentifyingCodes: []bill_of_lading.IdentifyingCode{
				{
					DCSAResponsibleAgencyCode: bill_of_lading.DID_DcsaResponsibleAgencyCode,
					PartyCode:                 party,
				},
			},
		},
		PartyFunction: util.Ptr(partyFunction),
	}
}

func GetBillOfLadingPackMeta(blPack *bill_of_lading.BillOfLadingPack) (map[string]any, error) {
	res := make(map[string]any)
	if draft := GetDraft(blPack); draft != nil && *draft {
		res["visible_to_bu"] = []string{blPack.CurrentOwner}
		res["action_needed"] = []string{blPack.CurrentOwner}
		return res, nil
	}

	parties := GetFileBaseEBLParticipatorsFromBLPack(blPack)
	partiesByOrder := []string{parties.Issuer, parties.Shipper, parties.Consignee, parties.ReleaseAgent}

	lastEvent := GetLastEvent(blPack)
	if lastEvent.Delete != nil {
		res["visible_to_bu"] = []string{blPack.CurrentOwner}
		res["deleted"] = true
	} else if lastEvent.Accomplish != nil || lastEvent.PrintToPaper != nil {
		res["visible_to_bu"] = partiesByOrder
		res["archive"] = partiesByOrder
	} else if lastEvent.AmendmentRequest != nil {
		_, amendmentRequesterIdx, _ := lo.FindIndexOf(partiesByOrder, func(p string) bool {
			return p == lastEvent.AmendmentRequest.RequestBy
		})
		if amendmentRequesterIdx < 1 {
			return nil, errors.New("amendment requested by invalid party")
		}

		res["action_needed"] = []string{blPack.CurrentOwner}
		res["visible_to_bu"] = partiesByOrder
		res["sent"] = partiesByOrder[1:amendmentRequesterIdx]    // amendment requested eB/L is 'action_needed' for issuer
		res["upcoming"] = partiesByOrder[amendmentRequesterIdx:] // amendment requested eB/L is 'upcoming' for requester
	} else {
		_, currentOwnerIdx, _ := lo.FindIndexOf(partiesByOrder, func(p string) bool {
			return p == blPack.CurrentOwner
		})

		res["action_needed"] = []string{blPack.CurrentOwner}
		res["visible_to_bu"] = partiesByOrder
		res["sent"] = partiesByOrder[:currentOwnerIdx]
		res["upcoming"] = partiesByOrder[currentOwnerIdx+1:]
	}

	return res, nil
}
