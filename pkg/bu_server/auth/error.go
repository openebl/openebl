package auth

import "errors"

var ErrInvalidAPIKeyString = errors.New("invalid API key string")
var ErrMismatchAPIKey = errors.New("mismatch API key")
var ErrRevokedAPIKey = errors.New("revoked API key")
var ErrAPIKeyNotFound = errors.New("API key not found")
