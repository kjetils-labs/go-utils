package http

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

type APIError struct {
	Error string `json:"error"`
}

func WriteJSONError(w http.ResponseWriter, msg string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	err := json.NewEncoder(w).Encode(APIError{Error: msg})
	if err != nil {
		http.Error(w, "failed to write error response", http.StatusInternalServerError)
		slog.Error("failed to write error response", "error", err)
	}
}
