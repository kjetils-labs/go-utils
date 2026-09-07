package http

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

type (
	apiError struct {
		error                error
		internalErrorMessage string
		externalErrorMessage string
		statusCode           int
	}

	JSONErrorOption func(*apiError)

	ErrorResponse struct {
		Error      string `json:"error"`
		StatusCode int    `json:"status_code,omitempty"`
		Message    string `json:"message,omitempty"`
	}
)

// WithError sets the actual error that occurred, which is sent to the client in the JSON response.
func WithError(err error) JSONErrorOption {
	return func(e *apiError) {
		e.error = err
	}
}

// WithErrorMessage sets both the internal and external error messages to the same value.
func WithErrorMessage(msg string) JSONErrorOption {
	return func(e *apiError) {
		e.internalErrorMessage = msg
		e.externalErrorMessage = msg
	}
}

// WithInternalErrorMessage sets the internal error message, which is useful for logging and debugging purposes.
func WithInternalErrorMessage(msg string) JSONErrorOption {
	return func(e *apiError) {
		e.internalErrorMessage = msg
	}
}

// WithExternalErrorMessage sets the external error message, which is intended to be sent to the client in the JSON response.
func WithExternalErrorMessage(msg string) JSONErrorOption {
	return func(e *apiError) {
		e.externalErrorMessage = msg
	}
}

func NewAPIError(statusCode int, opts ...JSONErrorOption) *apiError {
	apiErr := &apiError{
		statusCode: statusCode,
	}

	for _, opt := range opts {
		opt(apiErr)
	}

	return apiErr
}

func newErrorResponse(err error, statusCode int, message string) *ErrorResponse {

	if err != nil {
		return &ErrorResponse{
			Error:      err.Error(),
			StatusCode: statusCode,
			Message:    message,
		}
	}

	return &ErrorResponse{
		Error:      "",
		StatusCode: statusCode,
		Message:    message,
	}
}

// WriteJSONError writes a JSON error response to the http.ResponseWriter with the given status code and options.
// It logs the error if present and sets the appropriate headers for the response.
func WriteJSONError(w http.ResponseWriter, status int, opts ...JSONErrorOption) {
	apiErr := NewAPIError(status, opts...)

	if apiErr.error != nil || apiErr.internalErrorMessage != "" {
		slog.Error("API error occurred",
			"error", apiErr.error,
			"message", apiErr.internalErrorMessage,
			"status_code", apiErr.statusCode,
		)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	errResponse := newErrorResponse(apiErr.error, apiErr.statusCode, apiErr.externalErrorMessage)

	err := json.NewEncoder(w).Encode(errResponse)
	if err != nil {
		http.Error(w, "failed to write error response", http.StatusInternalServerError)
		slog.Error("failed to write error response", "error", err)
	}
}
