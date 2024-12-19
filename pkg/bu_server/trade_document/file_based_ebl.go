package trade_document

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openebl/openebl/pkg/bu_server/business_unit"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/model/trade_document/bill_of_lading"
	"github.com/openebl/openebl/pkg/bu_server/model/trade_document/bill_of_lading/dcsa_v2"
	"github.com/openebl/openebl/pkg/bu_server/model/trade_document/bill_of_lading/dcsa_v3"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/bu_server/webhook"
	"github.com/openebl/openebl/pkg/did"
	"github.com/openebl/openebl/pkg/envelope"
	"github.com/openebl/openebl/pkg/relay"
	"github.com/openebl/openebl/pkg/relay/server"
	"github.com/openebl/openebl/pkg/util"
	"github.com/samber/lo"
)

const (
	CodeListName     = "DID"
	CodeListProvider = "OEBL"

	DRAFT  = "DRAFT"
	ISSUED = "ISSUED"
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

	File           File                                    `json:"file"`
	BLNumber       string                                  `json:"bl_number"`
	BLDocType      bill_of_lading.BillOfLadingDocumentType `json:"bl_doc_type"`
	ToOrder        bool                                    `json:"to_order"`
	POL            Location                                `json:"pol"`
	POD            Location                                `json:"pod"`
	ETA            *model.Date                             `json:"eta,omitempty"`
	Shipper        string                                  `json:"shipper"`
	Consignee      string                                  `json:"consignee"`
	ReleaseAgent   string                                  `json:"release_agent"`
	Note           string                                  `json:"note"`
	Draft          *bool                                   `json:"draft"`
	EncryptContent bool                                    `json:"encrypt_content"`
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

	Offset  int    `json:"offset"`
	Limit   int    `json:"limit"`
	Status  string `json:"status"`
	Report  bool   `json:"report"`
	Keyword string `json:"keyword"`
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
	ETA       *model.Date                             `json:"eta,omitempty"`
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
	storage     storage.TradeDocumentStorage
	buCtrl      business_unit.BusinessUnitManager
	webhookCtrl webhook.WebhookController
}

func NewFileBaseEBLController(storage storage.TradeDocumentStorage, buCtrl business_unit.BusinessUnitManager, webhookCtrl webhook.WebhookController) FileBaseEBLController {
	return &_FileBaseEBLController{
		storage:     storage,
		buCtrl:      buCtrl,
		webhookCtrl: webhookCtrl,
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

	bl := CreateFileBasedBillOfLadingFromRequest(request, nil, currentTime)
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

	// Draft should always be unencrypted.
	kind := int(relay.FileBasedBillOfLading)
	if !*request.Draft && request.EncryptContent {
		kind = int(relay.EncryptedFileBasedBillOfLading)
	}
	td, err := c.signBillOfLadingPack(ctx, ts, blPack, request.Application, request.Issuer, request.AuthenticationID, kind)
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	tx, ctx, err := c.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	defer tx.Rollback(ctx)

	if *request.Draft {
		if err := c.storeTradeDocument(ctx, tx, td); err != nil {
			return FileBasedBillOfLadingRecord{}, err
		}
	} else {
		if err := c.storeAndPublishTradeDocument(ctx, tx, td); err != nil {
			return FileBasedBillOfLadingRecord{}, err
		}
		if err = c.webhookCtrl.SendWebhookEvent(ctx, tx, ts, request.Application, td.DocID, model.WebhookEventBLIssued); err != nil {
			return FileBasedBillOfLadingRecord{}, err
		}
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

	oldPack, oldHash, oldKind, err := c.getEBL(ctx, tx, request.ID)
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

	oldBL := GetLastBillOfLading(&oldPack)
	bl := CreateFileBasedBillOfLadingFromRequest(request.IssueFileBasedEBLRequest, oldBL, currentTime)
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

	// Draft should always be unencrypted.
	kind := oldKind
	if !*request.Draft && request.EncryptContent {
		kind = int(relay.EncryptedFileBasedBillOfLading)
	}
	td, err := c.signBillOfLadingPack(ctx, ts, blPack, request.Application, request.Issuer, request.AuthenticationID, kind)
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	if *request.Draft {
		if err := c.storeTradeDocument(ctx, tx, td); err != nil {
			return FileBasedBillOfLadingRecord{}, err
		}
	} else {
		if err := c.storeAndPublishTradeDocument(ctx, tx, td); err != nil {
			return FileBasedBillOfLadingRecord{}, err
		}
		if err = c.webhookCtrl.SendWebhookEvent(ctx, tx, ts, request.Application, td.DocID, model.WebhookEventBLIssued); err != nil {
			return FileBasedBillOfLadingRecord{}, err
		}
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

	oldPack, oldHash, oldKind, err := c.getEBL(ctx, tx, req.ID)
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

	td, err := c.signBillOfLadingPack(ctx, ts, blPack, req.Application, req.BusinessUnit, req.AuthenticationID, oldKind)
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}

	if err := c.storeAndPublishTradeDocument(ctx, tx, td); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = c.webhookCtrl.SendWebhookEvent(ctx, tx, ts, req.Application, td.DocID, model.WebhookEventBLReturned); err != nil {
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

func CreateFileBasedBillOfLadingFromRequest(request IssueFileBasedEBLRequest, oldBL *bill_of_lading.BillOfLading, currentTime model.DateTime) *bill_of_lading.BillOfLading {
	bl := &bill_of_lading.BillOfLading{
		BillOfLadingV3: &dcsa_v3.TransportDocument{
			TransportDocumentReference: request.BLNumber,
			TransportDocumentTypeCode:  dcsa_v3.TransportDocumentTransportDocumentTypeCodeBOL,
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
	FallbackFileInfoFromOldBL(bl, oldBL)

	td := bl.BillOfLadingV3
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
		BillOfLadingV3: &dcsa_v3.TransportDocument{
			TransportDocumentReference: req.BLNumber,
			TransportDocumentTypeCode:  dcsa_v3.TransportDocumentTransportDocumentTypeCodeBOL,
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
	oldBL := GetLastBillOfLading(&oldPack)
	FallbackFileInfoFromOldBL(bl, oldBL)

	parties := GetFileBaseEBLParticipatorsFromBLPack(&oldPack)
	td := bl.BillOfLadingV3
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

func FallbackFileInfoFromOldBL(bl, oldBL *bill_of_lading.BillOfLading) {
	if oldBL == nil {
		return
	}

	if bl.File.Name == "" {
		bl.File.Name = oldBL.File.Name
	}
	if bl.File.FileType == "" {
		bl.File.FileType = oldBL.File.FileType
	}
	if len(bl.File.Content) == 0 {
		bl.File.Content = oldBL.File.Content
	}
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
		Offset:       req.Offset,
		Limit:        req.Limit,
		RequestBy:    req.RequestBy,
		Kinds:        []int{int(relay.FileBasedBillOfLading), int(relay.EncryptedFileBasedBillOfLading)},
		Report:       req.Report,
		From:         req.Keyword,
		DocReference: strings.ReplaceAll(req.Keyword, "%", "\\%"), // escape '%' character for ILIKE query
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

	oldPack, oldHash, oldKind, err := c.getEBL(ctx, tx, req.ID)
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

	td, err := c.signBillOfLadingPack(ctx, ts, blPack, req.Application, req.TransferBy, req.AuthenticationID, oldKind)
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = c.storeAndPublishTradeDocument(ctx, tx, td); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = c.webhookCtrl.SendWebhookEvent(ctx, tx, ts, req.Application, td.DocID, model.WebhookEventBLTransferred); err != nil {
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

	oldPack, oldHash, oldKind, err := c.getEBL(ctx, tx, req.ID)
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

	td, err := c.signBillOfLadingPack(ctx, ts, blPack, req.Application, req.RequestBy, req.AuthenticationID, oldKind)
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = c.storeAndPublishTradeDocument(ctx, tx, td); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = c.webhookCtrl.SendWebhookEvent(ctx, tx, ts, req.Application, td.DocID, model.WebhookEventBLAmendmentRequested); err != nil {
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

	oldPack, oldHash, oldKind, err := c.getEBL(ctx, tx, req.ID)
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

	td, err := c.signBillOfLadingPack(ctx, ts, blPack, req.Application, req.Issuer, req.AuthenticationID, oldKind)
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = c.storeAndPublishTradeDocument(ctx, tx, td); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = c.webhookCtrl.SendWebhookEvent(ctx, tx, ts, req.Application, td.DocID, model.WebhookEventBLAmended); err != nil {
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
	oldPack, oldHash, oldKind, err := c.getEBL(ctx, tx, req.ID)
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

	td, err := c.signBillOfLadingPack(ctx, ts, blPack, req.Application, req.RequestBy, req.AuthenticationID, oldKind)
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = c.storeAndPublishTradeDocument(ctx, tx, td); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = c.webhookCtrl.SendWebhookEvent(ctx, tx, ts, req.Application, td.DocID, model.WebhookEventBLSurrendered); err != nil {
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

	oldPack, oldHash, oldKind, err := c.getEBL(ctx, tx, req.ID)
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

	td, err := c.signBillOfLadingPack(ctx, ts, blPack, req.Application, req.RequestBy, req.AuthenticationID, oldKind)
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = c.storeAndPublishTradeDocument(ctx, tx, td); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = c.webhookCtrl.SendWebhookEvent(ctx, tx, ts, req.Application, td.DocID, model.WebhookEventBLPrintedToPaper); err != nil {
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
	oldPack, oldHash, oldKind, err := c.getEBL(ctx, tx, req.ID)
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

	td, err := c.signBillOfLadingPack(ctx, ts, blPack, req.Application, req.RequestBy, req.AuthenticationID, oldKind)
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = c.storeAndPublishTradeDocument(ctx, tx, td); err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = c.webhookCtrl.SendWebhookEvent(ctx, tx, ts, req.Application, td.DocID, model.WebhookEventBLAccomplished); err != nil {
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
	oldPack, oldHash, oldKind, err := c.getEBL(ctx, tx, req.ID)
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

	td, err := c.signBillOfLadingPack(ctx, ts, blPack, req.Application, req.RequestBy, req.AuthenticationID, oldKind)
	if err != nil {
		return FileBasedBillOfLadingRecord{}, err
	}
	if err = c.storeTradeDocument(ctx, tx, td); err != nil {
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
	req := storage.ListBusinessUnitsRequest{
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

func (c *_FileBaseEBLController) signBillOfLadingPack(ctx context.Context, ts int64, blPack bill_of_lading.BillOfLadingPack, appID, signer, authID string, kind int) (storage.TradeDocument, error) {
	getSignerReq := business_unit.GetJWSSignerRequest{
		ApplicationID:    appID,
		BusinessUnitID:   did.MustParse(signer),
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

	var bl *bill_of_lading.BillOfLading
	for i := len(blPack.Events) - 1; i >= 0; i-- {
		if blPack.Events[i].BillOfLading != nil {
			bl = blPack.Events[i].BillOfLading
			break
		}
	}
	blNumber := bl.BillOfLadingV3.TransportDocumentReference

	td := storage.TradeDocument{
		Kind:         kind,
		DocID:        blPack.ID,
		DocVersion:   blPack.Version,
		Doc:          []byte(rawDoc),
		DocReference: blNumber,
		CreatedAt:    ts,
		Meta:         meta,
	}

	if td.Kind == int(relay.EncryptedFileBasedBillOfLading) {
		encryptedDoc, err := c.encryptBillOfLadingPack(ctx, td.Doc, meta["visible_to_bu"])
		if err != nil {
			return storage.TradeDocument{}, err
		}
		td.Doc, td.DecryptedDoc = encryptedDoc, td.Doc
	}
	td.RawID = server.GetEventID(td.Doc)

	return td, nil
}

func (c *_FileBaseEBLController) encryptBillOfLadingPack(ctx context.Context, doc []byte, visibleTo any) ([]byte, error) {
	recipients, ok := visibleTo.([]string)
	if !ok {
		return nil, errors.New("invalid visible_to_bu metadata")
	}
	if len(recipients) == 0 {
		return nil, errors.New("no recipient to encrypt")
	}
	req := business_unit.GetJWEEncryptorsRequest{
		BusinessUnitIDs: recipients,
	}
	encryptors, err := c.buCtrl.GetJWEEncryptors(ctx, req)
	if err != nil {
		return nil, err
	}
	keySettings := lo.Map(encryptors, func(e business_unit.JWEEncryptor, _ int) envelope.KeyEncryptionSetting {
		return envelope.KeyEncryptionSetting{
			PublicKey: e.Public(),
			Algorithm: e.AvailableJWEEncryptAlgorithms()[0],
		}
	})

	encrypted, err := envelope.Encrypt(doc, envelope.ContentEncryptionAlgorithm(jwa.A256GCM), keySettings)
	if err != nil {
		return nil, err
	}
	encryptedDoc, err := json.Marshal(encrypted)
	if err != nil {
		return nil, err
	}

	return encryptedDoc, nil
}

func (c *_FileBaseEBLController) getEBL(ctx context.Context, tx storage.Tx, id string) (bill_of_lading.BillOfLadingPack, string, int, error) {
	req := storage.ListTradeDocumentRequest{
		Limit:  1,
		DocIDs: []string{id},
	}

	resp, err := c.storage.ListTradeDocument(ctx, tx, req)
	if err != nil {
		return bill_of_lading.BillOfLadingPack{}, "", 0, err
	}

	if len(resp.Docs) == 0 {
		return bill_of_lading.BillOfLadingPack{}, "", 0, model.ErrEBLNotFound
	}

	pack, err := ExtractBLPackFromTradeDocument(resp.Docs[0])
	if err != nil {
		return bill_of_lading.BillOfLadingPack{}, "", 0, err
	}

	kind := resp.Docs[0].Kind
	hash := envelope.SHA512(resp.Docs[0].Doc)
	return pack, hash, kind, nil
}

func (c *_FileBaseEBLController) storeTradeDocument(ctx context.Context, tx storage.Tx, tradeDoc storage.TradeDocument) error {
	return c.storage.AddTradeDocument(ctx, tx, tradeDoc)
}

func (c *_FileBaseEBLController) storeAndPublishTradeDocument(ctx context.Context, tx storage.Tx, tradeDoc storage.TradeDocument) error {
	if err := c.storage.AddTradeDocument(ctx, tx, tradeDoc); err != nil {
		return err
	}
	return c.storage.AddTradeDocumentOutbox(ctx, tx, tradeDoc.CreatedAt, tradeDoc.DocID, tradeDoc.Kind, tradeDoc.Doc)
}

func ExtractBLPackFromTradeDocument(td storage.TradeDocument) (bill_of_lading.BillOfLadingPack, error) {
	doc := envelope.JWS{}
	switch td.Kind {
	case int(relay.FileBasedBillOfLading):
		if err := json.Unmarshal(td.Doc, &doc); err != nil {
			return bill_of_lading.BillOfLadingPack{}, err
		}
	case int(relay.EncryptedFileBasedBillOfLading):
		if err := json.Unmarshal(td.DecryptedDoc, &doc); err != nil {
			return bill_of_lading.BillOfLadingPack{}, err
		}
	default:
		return bill_of_lading.BillOfLadingPack{}, fmt.Errorf("unsupported trade document kind %d", td.Kind)
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

func SetPOL(td *dcsa_v3.TransportDocument, pol Location) {
	td.Transports.PortOfLoading = dcsa_v3.PortOfLoading{
		UNLocationCode: lo.ToPtr(pol.UNLocCode),
		LocationName:   lo.ToPtr(pol.LocationName),
	}
}

func SetPOD(td *dcsa_v3.TransportDocument, pod Location) {
	td.Transports.PortOfDischarge = dcsa_v3.PortOfDischarge{
		UNLocationCode: lo.ToPtr(pod.UNLocCode),
		LocationName:   lo.ToPtr(pod.LocationName),
	}
}

func SetETA(td *dcsa_v3.TransportDocument, eta model.Date) {
	td.Transports.PlannedArrivalDate.Time = eta.GetTime()
}

func SetIssuer(td *dcsa_v3.TransportDocument, issuer string) {
	td.DocumentParties.IssuingParty = dcsa_v3.IssuingParty{
		IdentifyingCodes: &[]dcsa_v3.IdentifyingCode{
			{
				CodeListName:     lo.ToPtr(CodeListName),
				CodeListProvider: CodeListProvider,
				PartyCode:        issuer,
			},
		},
	}
}

func SetConsignee(td *dcsa_v3.TransportDocument, consignee string) {
	td.DocumentParties.Consignee = &dcsa_v3.Consignee{
		IdentifyingCodes: []dcsa_v3.IdentifyingCode{
			{
				CodeListName:     lo.ToPtr(CodeListName),
				CodeListProvider: CodeListProvider,
				PartyCode:        consignee,
			},
		},
	}
}

func SetShipper(td *dcsa_v3.TransportDocument, shipper string) {
	td.DocumentParties.Shipper = dcsa_v3.Shipper{
		IdentifyingCodes: &[]dcsa_v3.IdentifyingCode{
			{
				CodeListName:     lo.ToPtr(CodeListName),
				CodeListProvider: CodeListProvider,
				PartyCode:        shipper,
			},
		},
	}
}

func SetReleaseAgent(td *dcsa_v3.TransportDocument, releaseAgent string) {
	replaceConsigneeForwarder := func(party dcsa_v3.OtherDocumentParty) {
		if td.DocumentParties.Other == nil {
			td.DocumentParties.Other = &[]dcsa_v3.OtherDocumentParty{}
		}
		for i := range *td.DocumentParties.Other {
			oldParty := (*td.DocumentParties.Other)[i]
			if oldParty.PartyFunction == party.PartyFunction {
				(*td.DocumentParties.Other)[i] = party
				return
			}
		}
		*td.DocumentParties.Other = append(*td.DocumentParties.Other, party)
	}

	party := dcsa_v3.OtherDocumentParty{
		PartyFunction: "DDS", // Consignee's freight forwarder
		Party: dcsa_v3.Party{
			IdentifyingCodes: &[]dcsa_v3.IdentifyingCode{
				{
					CodeListName:     lo.ToPtr(CodeListName),
					CodeListProvider: CodeListProvider,
					PartyCode:        releaseAgent,
				},
			},
		},
	}

	replaceConsigneeForwarder(party)
}

func SetToOrder(td *dcsa_v3.TransportDocument, toOrder bool) {
	td.IsToOrder = toOrder
}

func SetDraft(td *dcsa_v3.TransportDocument, draft bool) {
	if draft {
		td.TransportDocumentStatus = DRAFT
	} else {
		td.TransportDocumentStatus = ISSUED
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
	if firstEvent.BillOfLading == nil || firstEvent.BillOfLading.BillOfLadingV3 == nil {
		return nil
	}

	status := firstEvent.BillOfLading.BillOfLadingV3.TransportDocumentStatus
	if status == DRAFT {
		return util.Ptr(true)
	}
	if status == ISSUED {
		return util.Ptr(false)
	}
	return nil
}

func GetIssuer(blPack *bill_of_lading.BillOfLadingPack) *string {
	if blPack == nil || len(blPack.Events) == 0 {
		return nil
	}

	firstEvent := blPack.Events[0]
	if firstEvent.BillOfLading == nil || firstEvent.BillOfLading.BillOfLadingV3 == nil {
		return nil
	}

	if firstEvent.BillOfLading.BillOfLadingV3.DocumentParties.IssuingParty.IdentifyingCodes == nil ||
		len(*firstEvent.BillOfLading.BillOfLadingV3.DocumentParties.IssuingParty.IdentifyingCodes) == 0 {
		return nil
	}
	return util.Ptr((*firstEvent.BillOfLading.BillOfLadingV3.DocumentParties.IssuingParty.IdentifyingCodes)[0].PartyCode)
}

func GetFileBaseEBLParticipatorsFromBLPack(blPack *bill_of_lading.BillOfLadingPack) FileBaseEBLParticipators {
	if blPack == nil || len(blPack.Events) == 0 {
		return FileBaseEBLParticipators{}
	}

	bl := GetLastBillOfLading(blPack)
	if bl == nil {
		return FileBaseEBLParticipators{}
	}
	return GetFileBaseEBLParticipatorFromBL(bl)
}

func GetFileBaseEBLParticipatorFromBL(bl *bill_of_lading.BillOfLading) FileBaseEBLParticipators {
	td := bl.GetBillOfLadingV3()
	if td == nil {
		return FileBaseEBLParticipators{}
	}

	getIdentityCode := func(codes *[]dcsa_v3.IdentifyingCode) *string {
		if codes == nil || len(*codes) == 0 {
			return nil
		}
		return &(*codes)[0].PartyCode
	}

	result := FileBaseEBLParticipators{}

	if issuer := getIdentityCode(td.DocumentParties.IssuingParty.IdentifyingCodes); issuer != nil {
		result.Issuer = *issuer
	}
	if shipper := getIdentityCode(td.DocumentParties.Shipper.IdentifyingCodes); shipper != nil {
		result.Shipper = *shipper
	}
	consigneeParty := td.DocumentParties.Consignee
	if consigneeParty != nil {
		if consignee := getIdentityCode(&consigneeParty.IdentifyingCodes); consignee != nil {
			result.Consignee = *consignee
		}
	}

	for i := range *td.DocumentParties.Other {
		party := (*td.DocumentParties.Other)[i]
		if party.PartyFunction == "DDS" {
			if forwarder := getIdentityCode(party.Party.IdentifyingCodes); forwarder != nil {
				result.ReleaseAgent = *forwarder
			}
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

func GetLastBillOfLading(blPack *bill_of_lading.BillOfLadingPack) *bill_of_lading.BillOfLading {
	if blPack == nil || len(blPack.Events) == 0 {
		return nil
	}

	for i := len(blPack.Events) - 1; i >= 0; i-- {
		if blPack.Events[i].BillOfLading != nil {
			return blPack.Events[i].BillOfLading
		}
	}
	return nil
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

func PrepareSI(td *dcsa_v2.TransportDocument) *dcsa_v2.ShippingInstruction {
	if td.ShippingInstruction != nil {
		return td.ShippingInstruction
	}

	si := &dcsa_v2.ShippingInstruction{}

	td.ShippingInstruction = si
	return si
}

func ReplaceSIParty(si *dcsa_v2.ShippingInstruction, party dcsa_v2.DocumentParty) {
	for i := range si.DocumentParties {
		partyFunc := si.DocumentParties[i].PartyFunction
		if partyFunc != nil && *partyFunc == *party.PartyFunction {
			si.DocumentParties[i] = party
			return
		}
	}
	si.DocumentParties = append(si.DocumentParties, party)
}

func PrepareDocumentParty(party string, partyFunction dcsa_v2.PartyFunction) dcsa_v2.DocumentParty {
	return dcsa_v2.DocumentParty{
		Party: &dcsa_v2.Party{
			IdentifyingCodes: []dcsa_v2.IdentifyingCode{
				{
					DCSAResponsibleAgencyCode: dcsa_v2.DID_DcsaResponsibleAgencyCode,
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

		from, _ := GetOwnerShipTransferringByEvent(lastEvent)
		res["action_needed"] = []string{blPack.CurrentOwner}
		res["visible_to_bu"] = partiesByOrder
		res["sent"] = partiesByOrder[1:amendmentRequesterIdx]    // amendment requested eB/L is 'action_needed' for issuer
		res["upcoming"] = partiesByOrder[amendmentRequesterIdx:] // amendment requested eB/L is 'upcoming' for requester
		res["from"] = from                                       // amendment requested eB/L is 'from' requester
	} else {
		_, currentOwnerIdx, _ := lo.FindIndexOf(partiesByOrder, func(p string) bool {
			return p == blPack.CurrentOwner
		})

		from, _ := GetOwnerShipTransferringByEvent(lastEvent)
		res["action_needed"] = []string{blPack.CurrentOwner}
		res["visible_to_bu"] = partiesByOrder
		res["sent"] = partiesByOrder[:currentOwnerIdx]
		res["upcoming"] = partiesByOrder[currentOwnerIdx+1:]
		res["from"] = from
	}

	return res, nil
}
