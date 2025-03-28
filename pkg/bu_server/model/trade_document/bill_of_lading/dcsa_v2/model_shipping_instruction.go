/*
 * DCSA OpenAPI specification for Electronic Bill of Lading
 *
 * API specification issued by DCSA.org.  For explanation to specific values or objects please refer to the [Information Model 2022.Q4](https://dcsa.org/wp-content/uploads/2022/12/DCSA_Information-Model-2022.Q4-final.pdf). **Please be aware that version 2022.Q4 of the Information Model includes Reefers - this API does not include Reefers.** This API does not define the business rules regarding what is allowed to update at what time. For this the [Interface Standard for the Bill of Lading 2.0](https://dcsa.org/wp-content/uploads/2022/12/12-23-2022_DCSA_Interface_Standard_Bill_of_Lading_v2.0.pdf) should be consulted.  All other documents related to the Electronic Bill of Lading publication can be found [here](https://dcsa.org/standards/ebill-of-lading/)  It is possible to use this API as a standalone API. In order to do so it is necessary to use the poll-endPoint - /v2/events  in order to poll event information.  It is recomended to implement the [DCSA Documentation Event Hub](https://app.swaggerhub.com/apis/dcsaorg/DOCUMENTATION_EVENT_HUB) in order to use the push model. Here events are pushed as they occur.  For a changelog please click [here](https://github.com/dcsaorg/DCSA-OpenAPI/tree/master/ebl/v2#v200). Please also [create a GitHub issue](https://github.com/dcsaorg/DCSA-OpenAPI/issues/new) if you have any questions/comments.
 *
 * API version: 2.0.0
 */
package dcsa_v2

import "github.com/openebl/openebl/pkg/bu_server/model"

// The Shipping Instruction is an enrichment to the original booking shared by the shipper to the carrier. The shipping instruction includes volume or weight, cargo items, shipping dates, origin, destination, and other special instructions. The information given by the shipper through the shipping instruction is the information required to create a Transport Document.
type ShippingInstruction struct {
	ShippingInstructionReference       string                    `json:"shippingInstructionReference"`
	DocumentStatus                     EblDocumentStatus         `json:"documentStatus"`
	ShippingInstructionCreatedDateTime *model.DateTime           `json:"shippingInstructionCreatedDateTime,omitempty"`
	ShippingInstructionUpdatedDateTime *model.DateTime           `json:"shippingInstructionUpdatedDateTime,omitempty"`
	AmendToTransportDocument           string                    `json:"amendToTransportDocument,omitempty"`
	TransportDocumentTypeCode          TransportDocumentTypeCode `json:"transportDocumentTypeCode"`
	IsShippedOnBoardType               bool                      `json:"isShippedOnBoardType,omitempty"` // Specifies whether the Transport document is a received for shipment, or shipped on board.
	NumberOfCopiesWithCharges          int32                     `json:"numberOfCopiesWithCharges,omitempty"`
	NumberOfCopiesWithoutCharges       int32                     `json:"numberOfCopiesWithoutCharges,omitempty"`
	NumberOfOriginalsWithCharges       int32                     `json:"numberOfOriginalsWithCharges,omitempty"`
	NumberOfOriginalsWithoutCharges    int32                     `json:"numberOfOriginalsWithoutCharges,omitempty"`
	IsElectronic                       bool                      `json:"isElectronic,omitempty"` // An indicator whether the transport document is electronically transferred.
	IsToOrder                          bool                      `json:"isToOrder,omitempty"`    // An indicator whether the transport document is "to order".
	DisplayedNameForPlaceOfReceipt     []string                  `json:"displayedNameForPlaceOfReceipt,omitempty"`
	DisplayedNameForPortOfLoad         []string                  `json:"displayedNameForPortOfLoad,omitempty"`
	DisplayedNameForPortOfDischarge    []string                  `json:"displayedNameForPortOfDischarge,omitempty"`
	DisplayedNameForPlaceOfDelivery    []string                  `json:"displayedNameForPlaceOfDelivery,omitempty"`
	CarrierBookingReference            string                    `json:"carrierBookingReference,omitempty"`
	PlaceOfIssue                       *Location                 `json:"placeOfIssue,omitempty"`
	ConsignmentItems                   []ConsignmentItem         `json:"consignmentItems"`

	UtilizedTransportEquipments []UtilizedTransportEquipment `json:"utilizedTransportEquipments"`
	DocumentParties             []DocumentParty              `json:"documentParties,omitempty"`
	References                  []Reference                  `json:"references,omitempty"`
}
