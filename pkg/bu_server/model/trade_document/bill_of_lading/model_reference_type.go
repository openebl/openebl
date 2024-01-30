/*
 * DCSA OpenAPI specification for Electronic Bill of Lading
 *
 * API specification issued by DCSA.org.  For explanation to specific values or objects please refer to the [Information Model 2022.Q4](https://dcsa.org/wp-content/uploads/2022/12/DCSA_Information-Model-2022.Q4-final.pdf). **Please be aware that version 2022.Q4 of the Information Model includes Reefers - this API does not include Reefers.** This API does not define the business rules regarding what is allowed to update at what time. For this the [Interface Standard for the Bill of Lading 2.0](https://dcsa.org/wp-content/uploads/2022/12/12-23-2022_DCSA_Interface_Standard_Bill_of_Lading_v2.0.pdf) should be consulted.  All other documents related to the Electronic Bill of Lading publication can be found [here](https://dcsa.org/standards/ebill-of-lading/)  It is possible to use this API as a standalone API. In order to do so it is necessary to use the poll-endPoint - /v2/events  in order to poll event information.  It is recomended to implement the [DCSA Documentation Event Hub](https://app.swaggerhub.com/apis/dcsaorg/DOCUMENTATION_EVENT_HUB) in order to use the push model. Here events are pushed as they occur.  For a changelog please click [here](https://github.com/dcsaorg/DCSA-OpenAPI/tree/master/ebl/v2#v200). Please also [create a GitHub issue](https://github.com/dcsaorg/DCSA-OpenAPI/issues/new) if you have any questions/comments.
 *
 * API version: 2.0.0
 * Contact: info@dcsa.org
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package bill_of_lading

// ReferenceType : The reference type codes defined by DCSA. - FF (Freight Forwarder’s Reference) - SI (Shipper’s Reference) - PO (Purchase Order Reference) - CR (Customer’s Reference) - AAO (Consignee’s Reference) - ECR (Empty container release reference) - CSI (Customer shipment ID) - BPR (Booking party reference number) - BID (Booking Request ID) - RUC (Registro Único del Contribuyente) - DUE (Declaração Única de Exportação) - CER (Canadian Export Reporting System) - AES (Automated Export System)  More details can be found on [GitHub](https://github.com/dcsaorg/DCSA-Information-Model/blob/master/datamodel/referencedata.d/referencetypes.csv). Be aware that the list is a subset of the possible values.
type ReferenceType string

// List of referenceType
const (
	FF_ReferenceType  ReferenceType = "FF"
	SI_ReferenceType  ReferenceType = "SI"
	PO_ReferenceType  ReferenceType = "PO"
	CR_ReferenceType  ReferenceType = "CR"
	AAO_ReferenceType ReferenceType = "AAO"
	ECR_ReferenceType ReferenceType = "ECR"
	CSI_ReferenceType ReferenceType = "CSI"
	BPR_ReferenceType ReferenceType = "BPR"
	BID_ReferenceType ReferenceType = "BID"
	RUC_ReferenceType ReferenceType = "RUC"
	DUE_ReferenceType ReferenceType = "DUE"
	CER_ReferenceType ReferenceType = "CER"
	AES_ReferenceType ReferenceType = "AES"
)