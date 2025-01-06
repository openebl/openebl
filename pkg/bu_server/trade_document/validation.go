package trade_document

import (
	"fmt"

	validate "github.com/go-playground/validator/v10"
	"github.com/go-playground/validator/v10/non-standard/validators"
	"github.com/openebl/openebl/pkg/bu_server/model"
)

func ValidateRequest(req any) error {
	validator := validate.New()
	validator.RegisterValidation("notblank", validators.NotBlank)
	err := validator.Struct(req)
	if err != nil {
		return fmt.Errorf("%s%w", err.Error(), model.ErrInvalidParameter)
	}
	return nil
}
