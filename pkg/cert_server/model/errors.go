package model

import (
	"errors"
	"fmt"
)

var ErrInvalidParameter = errors.New("") // Base error for invalid parameter
var ErrWrongStatus = errors.New("")
var ErrDataNotFound = errors.New("") // Base error for data not found

var ErrCertNotFound = fmt.Errorf("%w", ErrDataNotFound)
