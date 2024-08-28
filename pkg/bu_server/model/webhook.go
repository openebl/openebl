package model

type WebhookEventType string

const (
	WebhookEventBLIssued             WebhookEventType = "bl.issued"
	WebhookEventBLTransferred        WebhookEventType = "bl.transferred"
	WebhookEventBLReturned           WebhookEventType = "bl.returned"
	WebhookEventBLAmendmentRequested WebhookEventType = "bl.amendment_requested"
	WebhookEventBLAmended            WebhookEventType = "bl.amended"
	WebhookEventBLSurrendered        WebhookEventType = "bl.surrendered"
	WebhookEventBLAccomplished       WebhookEventType = "bl.accomplished"
	WebhookEventBLPrintedToPaper     WebhookEventType = "bl.printed_to_paper"
	WebhookEventBUCreated            WebhookEventType = "bu.created"
	WebhookEventBUUpdated            WebhookEventType = "bu.updated"
	WebhookEventAuthCreated          WebhookEventType = "auth.created"
	WebhookEventAuthRevoked          WebhookEventType = "auth.revoked"
)

type Webhook struct {
	ID            string             `json:"id"`                // Unique ID of a Webhook.
	Version       int64              `json:"version"`           // Version of the Webhook.
	ApplicationID string             `json:"application_id"`    // The ID of the application this Webhook belongs to.
	Url           string             `json:"url"`               // The URL the WebhookEvent sent to.
	Events        []WebhookEventType `json:"events"`            // List of events to trigger the Webhook.
	Secret        string             `json:"secret,omitempty"`  // Secret used to generate the HMAC-SHA1 signature.
	CreatedAt     int64              `json:"created_at"`        // Unix Time (in second) when the Webhook was created.
	CreatedBy     string             `json:"created_by"`        // User who created the Webhook.
	UpdatedAt     int64              `json:"updated_at"`        // Unix Time (in second) when the Webhook was last updated.
	UpdatedBy     string             `json:"updated_by"`        // User who last updated the Webhook.
	Deleted       bool               `json:"deleted,omitempty"` // Whether the Webhook is deleted.`
}

type WebhookEvent struct {
	ID        string           `json:"id"`         // ID of the subject of the event.
	Url       string           `json:"url"`        // The URL the WebhookEvent sent to.
	Type      WebhookEventType `json:"type"`       // Type of the event.
	CreatedAt int64            `json:"created_at"` // Unix Time (in second) when the WebhookEvent was created.
}
