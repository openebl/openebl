package cert

import "errors"

var ErrInvalidParameter = errors.New("") // Base error for invalid parameter
var ErrCertInvalid = errors.New("")      // Base error for Certification Verification Error
