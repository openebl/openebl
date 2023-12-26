package auth

import "errors"

var ErrInvalidAPIKeyString = errors.New("invalid API key string")
var ErrMismatchAPIKey = errors.New("mismatch API key")
