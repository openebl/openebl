package auth

import (
	"fmt"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

func ValidateCreateUserRequest(req CreateUserRequest) error {
	err := validation.ValidateStruct(&req,
		validation.Field(&req.RequestUser, validation.Required),
		validation.Field(&req.UserID, validation.Required),
		validation.Field(&req.Password, validation.Required),
	)
	if err != nil {
		return fmt.Errorf("%s%w", err.Error(), ErrInvalidParameter)
	}
	return nil
}

func ValidateChangePasswordRequest(req ChangePasswordRequest) error {
	err := validation.ValidateStruct(&req,
		validation.Field(&req.UserID, validation.Required),
		validation.Field(&req.OldPassword, validation.Required),
		validation.Field(&req.Password, validation.Required),
	)
	if err != nil {
		return fmt.Errorf("%s%w", err.Error(), ErrInvalidParameter)
	}
	return nil
}

func ValidateResetPasswordRequest(req ResetPasswordRequest) error {
	err := validation.ValidateStruct(&req,
		validation.Field(&req.RequestUser, validation.Required),
		validation.Field(&req.UserID, validation.Required),
		validation.Field(&req.Password, validation.Required),
	)
	if err != nil {
		return fmt.Errorf("%s%w", err.Error(), ErrInvalidParameter)
	}
	return nil
}

func ValidateUpdateUserRequest(req UpdateUserRequest) error {
	err := validation.ValidateStruct(&req,
		validation.Field(&req.RequestUser, validation.Required),
		validation.Field(&req.UserID, validation.Required),
		validation.Field(&req.Name, validation.Required),
	)
	if err != nil {
		return fmt.Errorf("%s%w", err.Error(), ErrInvalidParameter)
	}
	return nil
}

func ValidateActivateUserRequest(req ActivateUserRequest) error {
	err := validation.ValidateStruct(&req,
		validation.Field(&req.RequestUser, validation.Required),
		validation.Field(&req.UserID, validation.Required),
	)
	if err != nil {
		return fmt.Errorf("%s%w", err.Error(), ErrInvalidParameter)
	}
	return nil
}

func ValidateAuthenticateUserRequest(req AuthenticateUserRequest) error {
	err := validation.ValidateStruct(&req,
		validation.Field(&req.UserID, validation.Required),
		validation.Field(&req.Password, validation.Required),
	)
	if err != nil {
		return fmt.Errorf("%s%w", err.Error(), ErrInvalidParameter)
	}
	return nil
}

func ValidateListUserRequest(req ListUserRequest) error {
	err := validation.ValidateStruct(&req,
		validation.Field(&req.Limit, validation.Required),
	)
	if err != nil {
		return fmt.Errorf("%s%w", err.Error(), ErrInvalidParameter)
	}
	return nil
}
