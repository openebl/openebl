package middleware

// keys of values stored in context
type MiddleWareContextKey string

const (
	APPLICATION_ID   = MiddleWareContextKey("application_id")   // The context value is a string representing the application ID.
	USER_TOKEN       = MiddleWareContextKey("user_token")       // The context value is a auth.UserToken.
	BUSINESS_UNIT_ID = MiddleWareContextKey("business_unit_id") // The context value is a string representing the business unit ID.
)
