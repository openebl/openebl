/*
 * DCSA OpenAPI specification for Electronic Bill of Lading
 *
 * API specification issued by DCSA.org.  For explanation to specific values or objects please refer to the [Information Model 2022.Q4](https://dcsa.org/wp-content/uploads/2022/12/DCSA_Information-Model-2022.Q4-final.pdf). **Please be aware that version 2022.Q4 of the Information Model includes Reefers - this API does not include Reefers.** This API does not define the business rules regarding what is allowed to update at what time. For this the [Interface Standard for the Bill of Lading 2.0](https://dcsa.org/wp-content/uploads/2022/12/12-23-2022_DCSA_Interface_Standard_Bill_of_Lading_v2.0.pdf) should be consulted.  All other documents related to the Electronic Bill of Lading publication can be found [here](https://dcsa.org/standards/ebill-of-lading/)  It is possible to use this API as a standalone API. In order to do so it is necessary to use the poll-endPoint - /v2/events  in order to poll event information.  It is recomended to implement the [DCSA Documentation Event Hub](https://app.swaggerhub.com/apis/dcsaorg/DOCUMENTATION_EVENT_HUB) in order to use the push model. Here events are pushed as they occur.  For a changelog please click [here](https://github.com/dcsaorg/DCSA-OpenAPI/tree/master/ebl/v2#v200). Please also [create a GitHub issue](https://github.com/dcsaorg/DCSA-OpenAPI/issues/new) if you have any questions/comments.
 *
 * API version: 2.0.0
 * Contact: info@dcsa.org
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package dcsa_v2

import (
	"github.com/openebl/openebl/pkg/bu_server/model"
)

// The document that governs the terms of carriage between shipper and carrier for maritime transportation. Two distinct types of transport documents exist: - Bill of Lading - Sea Waybill.
type TransportDocument struct {
	TransportDocumentReference       string                         `json:"transportDocumentReference"`
	TransportDocumentCreatedDateTime *model.DateTime                `json:"transportDocumentCreatedDateTime,omitempty"`
	TransportDocumentUpdatedDateTime *model.DateTime                `json:"transportDocumentUpdatedDateTime,omitempty"`
	IssueDate                        *model.Date                    `json:"issueDate,omitempty"`
	ShippedOnBoardDate               *model.Date                    `json:"shippedOnBoardDate,omitempty"`
	ReceivedForShipmentDate          *model.Date                    `json:"receivedForShipmentDate,omitempty"`
	CarrierCode                      string                         `json:"carrierCode"`
	CarrierCodeListProvider          CarrierCodeListProvider        `json:"carrierCodeListProvider"`
	IssuingParty                     *Party                         `json:"issuingParty"`
	NumberOfRiderPages               int32                          `json:"numberOfRiderPages,omitempty"`
	TermsAndConditions               string                         `json:"termsAndConditions,omitempty"`
	ReceiptTypeAtOrigin              ReceiptTypeAtOrigin            `json:"receiptTypeAtOrigin,omitempty"`
	DeliveryTypeAtDestination        DeliveryTypeAtDestination      `json:"deliveryTypeAtDestination,omitempty"`
	CargoMovementTypeAtOrigin        CargoMovementTypeAtOrigin      `json:"cargoMovementTypeAtOrigin,omitempty"`
	CargoMovementTypeAtDestination   CargoMovementTypeAtDestination `json:"cargoMovementTypeAtDestination,omitempty"`
	ServiceContractReference         string                         `json:"serviceContractReference,omitempty"`
	VesselName                       string                         `json:"vesselName,omitempty"`                     // Example: King of the Seas
	CarrierServiceName               string                         `json:"carrierServiceName,omitempty"`             // Example: Great Lion Service
	CarrierServiceCode               string                         `json:"carrierServiceCode,omitempty"`             // Example: FE1
	UniversalServiceReference        string                         `json:"universalServiceReference,omitempty"`      // Example: SR12345A	Pattern: SR\d{5}[A-Z]
	CarrierExportVoyageNumber        string                         `json:"carrierExportVoyageNumber,omitempty"`      // Example: 2103S
	UniversalExportVoyageReference   string                         `json:"universalExportVoyageReference,omitempty"` // Example: 2103N	Pattern: \d{2}[0-9A-Z]{2}[NEWS]
	DeclaredValue                    *model.Decimal                 `json:"declaredValue,omitempty"`
	DeclaredValueCurrency            string                         `json:"declaredValueCurrency,omitempty"`
	Transports                       []Transport                    `json:"transports,omitempty"`
	ShipmentLocations                []ShipmentLocation             `json:"shipmentLocations,omitempty"`
	InvoicePayableAt                 *Location                      `json:"invoicePayableAt,omitempty"`
	PlaceOfIssue                     *Location                      `json:"placeOfIssue,omitempty"`
	ShippingInstruction              *ShippingInstruction           `json:"shippingInstruction"`
	Charges                          []Charge                       `json:"charges,omitempty"`
	CarrierClauses                   []CarrierClause                `json:"carrierClauses,omitempty"`
}
