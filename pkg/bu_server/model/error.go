package model

import (
	"errors"
	"fmt"
	"net/http"
)

var ErrInvalidParameter = errors.New("")            // Base error for invalid parameter
var ErrAPIKeyError = errors.New("")                 // Base error for API key
var ErrApplicationError = errors.New("")            // Base error for Application
var ErrUserError = errors.New("")                   // Base error for User
var ErrBusinessUnitError = errors.New("")           // Base error for Business Unit
var ErrCertificationAuthorityError = errors.New("") // Base error for Certification Authority
var ErrFileBasedEBLError = errors.New("")           // Base error for File Based EBL
var ErrWebhookError = errors.New("")                // Base error for Webhook

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
var ErrUserTokenExpired = fmt.Errorf("user token expired%w", ErrUserError)
var ErrUserTokenInvalid = fmt.Errorf("user token invalid%w", ErrUserError)

// Business Unit errors
var ErrBusinessUnitNotFound = fmt.Errorf("business unit not found%w", ErrBusinessUnitError)
var ErrBusinessUnitInActive = fmt.Errorf("business unit is not active%w", ErrBusinessUnitError)
var ErrAuthenticationNotFound = fmt.Errorf("authentication not found%w", ErrBusinessUnitError)
var ErrAuthenticationNotActive = fmt.Errorf("authentication is not active%w", ErrBusinessUnitError)

// Certification Authority errors
var ErrCertificationNotFound = fmt.Errorf("certification not found%w", ErrCertificationAuthorityError)
var ErrCertificationExpired = fmt.Errorf("certification expired%w", ErrCertificationAuthorityError)
var ErrCACertificationNotAvailable = fmt.Errorf("CA certification not available%w", ErrCertificationAuthorityError)

// File Based EBL errors
var ErrEBLNotFound = fmt.Errorf("EBL not found%w", ErrFileBasedEBLError)
var ErrEBLNoDocument = fmt.Errorf("EBL has no document%w", ErrFileBasedEBLError)
var ErrEBLActionNotAllowed = fmt.Errorf("%w", ErrFileBasedEBLError)

// Webhook errors
var ErrWebhookNotFound = fmt.Errorf("webhook not found%w", ErrWebhookError)

func ErrorToHttpStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}

	if errors.Is(err, ErrEBLActionNotAllowed) {
		return http.StatusConflict
	}
	if errors.Is(err, ErrEBLNotFound) {
		return http.StatusNotFound
	}
	if errors.Is(err, ErrEBLNoDocument) {
		return http.StatusNotFound
	}
	if errors.Is(err, ErrApplicationNotFound) {
		return http.StatusNotFound
	}
	if errors.Is(err, ErrUserNotFound) {
		return http.StatusNotFound
	}
	if errors.Is(err, ErrUserAlreadyExists) {
		return http.StatusConflict
	}
	if errors.Is(err, ErrUserAuthenticationFail) {
		return http.StatusBadRequest
	}
	if errors.Is(err, ErrBusinessUnitNotFound) {
		return http.StatusNotFound
	}
	if errors.Is(err, ErrBusinessUnitInActive) {
		return http.StatusConflict
	}
	if errors.Is(err, ErrAuthenticationNotFound) {
		return http.StatusNotFound
	}
	if errors.Is(err, ErrAuthenticationNotActive) {
		return http.StatusConflict
	}
	if errors.Is(err, ErrCertificationNotFound) {
		return http.StatusNotFound
	}
	if errors.Is(err, ErrCertificationExpired) {
		return http.StatusConflict
	}

	if errors.Is(err, ErrInvalidParameter) {
		return http.StatusBadRequest
	}
	if errors.Is(err, ErrAPIKeyError) {
		return http.StatusUnauthorized
	}
	if errors.Is(err, ErrUserError) {
		return http.StatusUnauthorized
	}

	return http.StatusInternalServerError
}
