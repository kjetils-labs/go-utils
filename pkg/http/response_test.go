package http

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsRequestValid(t *testing.T) {
	tests := []struct {
		name           string
		request        TestValidationRequest
		expectedErrors *ValidationErrors
	}{
		{
			name:           "Valid request",
			request:        TestValidationRequest{Name: "Alice", Age: 25},
			expectedErrors: nil, // No errors expected for valid input
		},
		{
			name:    "Missing Name and Age below minimum",
			request: TestValidationRequest{Age: 17},
			expectedErrors: &ValidationErrors{
				Errors: map[string][]string{
					"Name": {"Name required"},
					"Age":  {"Age min"},
				},
			},
		},
		{
			name:    "Missing Age",
			request: TestValidationRequest{Name: "Alice"},
			expectedErrors: &ValidationErrors{
				Errors: map[string][]string{
					"Age": {"Age required"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := IsRequestValid(tt.request)
			if tt.expectedErrors == nil {
				assert.Nil(t, errs)
			} else {
				assert.NotNil(t, errs)
				assert.Equal(t, tt.expectedErrors.Errors, errs.Errors)
			}
		})
	}
}
