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

// ShipmentLocationTypeCode : Links to the Location Type Code defined by DCSA. - PRE (Place of Receipt) - POL (Port of Loading) - POD (Port of Discharge) - PDE (Place of Delivery) - PCF (Pre-carriage From) - PSR (Pre-carriage under shipper’s responsibility) - OIR (Onward In-land Routing) - DRL (Depot release location) - ORI (Origin of goods) - IEL (Container intermediate export stop off location) - PTP (Prohibited transshipment port) - RTP (Requested transshipment port) - FCD (Full container drop-off location) - ECP (Empty container pick-up location)
type ShipmentLocationTypeCode string

// List of shipmentLocationTypeCode
const (
	PRE_ShipmentLocationTypeCode ShipmentLocationTypeCode = "PRE"
	POL_ShipmentLocationTypeCode ShipmentLocationTypeCode = "POL"
	POD_ShipmentLocationTypeCode ShipmentLocationTypeCode = "POD"
	PDE_ShipmentLocationTypeCode ShipmentLocationTypeCode = "PDE"
	PCF_ShipmentLocationTypeCode ShipmentLocationTypeCode = "PCF"
	PSR_ShipmentLocationTypeCode ShipmentLocationTypeCode = "PSR"
	OIR_ShipmentLocationTypeCode ShipmentLocationTypeCode = "OIR"
	DRL_ShipmentLocationTypeCode ShipmentLocationTypeCode = "DRL"
	ORI_ShipmentLocationTypeCode ShipmentLocationTypeCode = "ORI"
	IEL_ShipmentLocationTypeCode ShipmentLocationTypeCode = "IEL"
	PTP_ShipmentLocationTypeCode ShipmentLocationTypeCode = "PTP"
	RTP_ShipmentLocationTypeCode ShipmentLocationTypeCode = "RTP"
	FCD_ShipmentLocationTypeCode ShipmentLocationTypeCode = "FCD"
	ECP_ShipmentLocationTypeCode ShipmentLocationTypeCode = "ECP"
)
