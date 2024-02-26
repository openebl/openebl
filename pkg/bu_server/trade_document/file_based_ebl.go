package trade_document

import (
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"

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
	Requester        string `json:"requester"`
	Application      string `json:"application"`
	Issuer           string `json:"issuer"`
	AuthenticationID string `json:"authentication_id"`

	File         File                                    `json:"file"`
	BLNumber     string                                  `json:"bl_number"`
	BLDocType    bill_of_lading.BillOfLadingDocumentType `json:"bl_doc_type"`
	ToOrder      bool                                    `json:"to_order"`
	POL          Location                                `json:"pol"`
	POD          Location                                `json:"pod"`
	ETA          model.DateTime                          `json:"eta"`
	Shipper      string                                  `json:"shipper"`
	Consignee    string                                  `json:"consignee"`
	ReleaseAgent string                                  `json:"release_agent"`
	Note         string                                  `json:"note"`
	Draft        *bool                                   `json:"draft"`
}

type FileBaseEBLController interface {
	Create(ctx context.Context, ts int64, request IssueFileBasedEBLRequest) (bill_of_lading.BillOfLadingPack, error)
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

func (c *_FileBaseEBLController) Create(ctx context.Context, ts int64, request IssueFileBasedEBLRequest) (bill_of_lading.BillOfLadingPack, error) {
	currentTime := model.NewDateTimeFromUnix(ts)
	if err := ValidateIssueFileBasedEBLRequest(request); err != nil {
		return bill_of_lading.BillOfLadingPack{}, err
	}

	if err := c.checkBUExistence(ctx, request.Application, []string{request.Issuer, request.Shipper, request.Consignee, request.ReleaseAgent}); err != nil {
		return bill_of_lading.BillOfLadingPack{}, err
	}

	var currentOwner string
	if *request.Draft {
		currentOwner = request.Issuer
	} else {
		currentOwner = request.Shipper
	}

	blPack := bill_of_lading.BillOfLadingPack{
		ID:           uuid.NewString(),
		Version:      1,
		CurrentOwner: currentOwner,
		Events: []bill_of_lading.BillOfLadingEvent{
			{
				BillOfLading: &bill_of_lading.BillOfLading{
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
				},
			},
		},
	}

	if !*request.Draft {
		transfer := bill_of_lading.BillOfLadingEvent{
			Transfer: &bill_of_lading.Transfer{
				TransferBy: request.Issuer,
				TransferTo: request.Shipper,
				TransferAt: &currentTime,
			},
		}
		blPack.Events = append(blPack.Events, transfer)
	}

	bl := blPack.Events[0].BillOfLading.BillOfLading
	SetPOL(bl, request.POL)
	SetPOD(bl, request.POD)
	SetETA(bl, request.ETA)
	SetIssuer(bl, request.Issuer)
	SetShipper(bl, request.Shipper)
	SetConsignee(bl, request.Consignee)
	SetReleaseAgent(bl, request.ReleaseAgent)
	SetToOrder(bl, request.ToOrder)
	if request.Draft != nil {
		SetDraft(bl, *request.Draft)
	}

	td, err := c.signBillOfLadingPack(ctx, ts, blPack, request.Application, request.Issuer, request.AuthenticationID)
	if err != nil {
		return bill_of_lading.BillOfLadingPack{}, err
	}

	tx, err := c.storage.CreateTx(ctx, storage.TxOptionWithWrite(true), storage.TxOptionWithIsolationLevel(sql.LevelSerializable))
	if err != nil {
		return bill_of_lading.BillOfLadingPack{}, err
	}
	defer tx.Rollback(ctx)

	if err := c.storage.AddTradeDocument(ctx, tx, td); err != nil {
		return bill_of_lading.BillOfLadingPack{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return bill_of_lading.BillOfLadingPack{}, err
	}

	blPack.Events[0].BillOfLading.File.Content = nil
	return blPack, nil
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
		lo.Map(
			jwsSigner.Cert(),
			func(c x509.Certificate, _ int) *x509.Certificate {
				return &c
			},
		),
	)
	if err != nil {
		return storage.TradeDocument{}, err
	}

	rawDoc := util.StructToJSON(doc)
	meta, err := GetBillOfLadingPackMeta(ctx, ts, &blPack)
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

func GetBillOfLadingPackMeta(ctx context.Context, ts int64, blPack *bill_of_lading.BillOfLadingPack) (map[string]any, error) {
	// Get last BillOfLading from the pack
	var bl *bill_of_lading.BillOfLading
	for i := len(blPack.Events) - 1; i >= 0; i-- {
		if blPack.Events[i].BillOfLading != nil {
			bl = blPack.Events[i].BillOfLading
			break
		}
	}
	if bl == nil {
		return nil, errors.New("no bill of lading found in the pack")
	}

	visibleBUs := lo.Map(
		bl.BillOfLading.ShippingInstruction.DocumentParties,
		func(p bill_of_lading.DocumentParty, _ int) string {
			return p.Party.IdentifyingCodes[0].PartyCode
		},
	)

	return map[string]any{
		"visible_to_bu": visibleBUs,
	}, nil
}
