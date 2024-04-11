package model

import (
	"errors"
	"fmt"
	"net/http"
)

var ErrInvalidParameter = errors.New("") // Base error for invalid parameter
var ErrWrongStatus = errors.New("")
var ErrDataNotFound = errors.New("") // Base error for data not found

var ErrCertNotFound = fmt.Errorf("%w", ErrDataNotFound)

func ErrToHttpStatus(err error) int {
	if errors.Is(ErrInvalidParameter, err) {
		return http.StatusBadRequest
	} else if errors.Is(ErrDataNotFound, err) {
		return http.StatusNotFound
	} else if errors.Is(ErrWrongStatus, err) {
		return http.StatusConflict
	}

	return http.StatusInternalServerError
}
