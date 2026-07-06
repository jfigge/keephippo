// Package http exposes the /v1/* HTTP API. In Phase 1 it serves the control
// plane: sys/health, sys/seal-status, sys/init, sys/unseal, and sys/seal, with
// Vault-compatible response shapes and status codes.
//
// Note: within this package the identifier "http" refers to the imported
// standard-library net/http, per Go's rule that a package never qualifies its
// own names.
package http

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

// Response is the standard Vault-compatible JSON envelope used by logical
// endpoints (populated from Phase 2). The Phase 1 control-plane sys endpoints
// return their own top-level shapes, matching Vault.
type Response struct {
	RequestID     string `json:"request_id"`
	LeaseID       string `json:"lease_id"`
	Renewable     bool   `json:"renewable"`
	LeaseDuration int    `json:"lease_duration"`
	Data          any    `json:"data"`
	WrapInfo      any    `json:"wrap_info"`
	Warnings      any    `json:"warnings"`
	Auth          any    `json:"auth"`
}

// errorBody is Vault's error shape: {"errors": [...]}.
type errorBody struct {
	Errors []string `json:"errors"`
}

func respondJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func respondError(w http.ResponseWriter, status int, msgs ...string) {
	respondJSON(w, status, errorBody{Errors: msgs})
}

func respondEmpty(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

// decodeJSON reads a JSON request body into v. An empty body is treated as {}.
func decodeJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return nil
	}
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	return nil
}

// decodeUnsealKey accepts an unseal key as hex (the primary form we emit) or
// base64, returning the raw bytes.
func decodeUnsealKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("'key' must be specified")
	}
	if b, err := hex.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, errors.New("'key' is not valid hex or base64")
}
