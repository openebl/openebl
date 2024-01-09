package auth

import (
	"errors"
	"fmt"
)

var ErrInvalidParameter = errors.New("") // Base error for invalid parameter
var ErrAPIKeyError = errors.New("")      // Base error for API key
var ErrApplicationError = errors.New("") // Base error for Application
var ErrUserError = errors.New("")        // Base error for User

// API Key errors
var ErrInvalidAPIKeyString = fmt.Errorf("invalid API key string%w", ErrAPIKeyError)
var ErrMismatchAPIKey = fmt.Errorf("mismatch API key%w", ErrAPIKeyError)
var ErrRevokedAPIKey = fmt.Errorf("revoked API key%w", ErrAPIKeyError)
var ErrAPIKeyNotFound = fmt.Errorf("API key not found%w", ErrAPIKeyError)
var ErrApplicationInactive = fmt.Errorf("application is inactive%w", ErrAPIKeyError)

// Application errors
var ErrApplicationNotFound = fmt.Errorf("application not found%w", ErrApplicationError)

// User errors
var ErrUserNotFound = fmt.Errorf("user not found%w", ErrUserError)
var ErrUserAlreadyExists = fmt.Errorf("user already exists%w", ErrUserError)
var ErrUserInactive = fmt.Errorf("user is inactive%w", ErrUserError)
var ErrUserAuthenticationFail = fmt.Errorf("user name/password mismatch%w", ErrUserError)
