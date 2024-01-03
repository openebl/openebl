package auth

import (
	"errors"
	"fmt"
)

var ErrAPIKeyError = errors.New("")      // Base error for API key
var ErrApplicationError = errors.New("") // Base error for Application

var ErrInvalidAPIKeyString = fmt.Errorf("invalid API key string%w", ErrAPIKeyError)
var ErrMismatchAPIKey = fmt.Errorf("mismatch API key%w", ErrAPIKeyError)
var ErrRevokedAPIKey = fmt.Errorf("revoked API key%w", ErrAPIKeyError)
var ErrAPIKeyNotFound = fmt.Errorf("API key not found%w", ErrAPIKeyError)
var ErrApplicationInactive = fmt.Errorf("application is inactive%w", ErrAPIKeyError)

var ErrApplicationNotFound = fmt.Errorf("application not found%w", ErrApplicationError)
