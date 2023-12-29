package auth

import (
	"errors"
	"fmt"
)

var ErrAPIKeyError = errors.New("") // Base error for API key
var ErrInvalidAPIKeyString = fmt.Errorf("invalid API key string%w", ErrAPIKeyError)
var ErrMismatchAPIKey = fmt.Errorf("mismatch API key%w", ErrAPIKeyError)
var ErrRevokedAPIKey = fmt.Errorf("revoked API key%w", ErrAPIKeyError)
var ErrAPIKeyNotFound = fmt.Errorf("API key not found%w", ErrAPIKeyError)
