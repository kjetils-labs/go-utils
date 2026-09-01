package http

import (
	"testing"

	"github.com/go-playground/assert/v2"
	"github.com/go-playground/validator/v10"
)

type TestValidationRequest struct {
	Name string `validate:"required"`
	Age  int    `validate:"required,min=18"`
}

func TestNewValidationErrors(t *testing.T) {
	validate := validator.New()
	request := TestValidationRequest{} // Missing required fields to trigger validation errors

	err := validate.Struct(request)
	if err == nil {
		t.Fatal("Expected validation errors, but got none")
	}

	validationErrors := NewValidationErrors(err)

	expectedErrors := map[string][]string{
		"Name": {"Name required"},
		"Age":  {"Age required"},
	}

	assert.Equal(t, expectedErrors, validationErrors.Errors)
}
