// Package handler holds the HTTP handlers for the passkey service.
//
// Two rules govern this package:
//   - Errors returned by inner layers are mapped to stable response *codes*
//     (short strings like "username_taken") via writeError. They are never
//     written to the response body verbatim. See [[feedback-error-masking-at-boundary]].
//   - Logging is the responsibility of the handler: log the full error
//     server-side, then call writeError with the stable code.
package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// errorBody is the wire shape for all error responses.
type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// codeMessages maps stable response codes to a generic human-readable
// message. Internal error details are never included.
var codeMessages = map[string]string{
	"invalid_request":   "Request body could not be parsed.",
	"missing_fields":    "One or more required fields are missing.",
	"username_taken":    "That username is already registered.",
	"credential_exists": "That credential is already registered.",
	"session_invalid":   "Registration session is invalid or has expired. Please start over.",
	"attestation_rejected": "Authenticator returned an attestation format we do not accept.",
	"unauthorized":      "Authentication required.",
	"not_found":         "Resource not found.",
	"internal_error":    "Internal server error.",
}

// writeJSON writes v as a JSON response with status. It logs (but does not
// surface) any encoding error.
func writeJSON(w http.ResponseWriter, logger *slog.Logger, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if v == nil {
		return
	}

	if err := json.NewEncoder(w).Encode(v); err != nil {
		logger.Error("write json response", "err", err)
	}
}

// writeError writes an error response with the given HTTP status and a
// stable machine code. Code MUST be one of the keys in codeMessages — that
// constraint is what keeps internal error details out of the response.
func writeError(w http.ResponseWriter, logger *slog.Logger, status int, code string) {
	msg, ok := codeMessages[code]
	if !ok {
		// A code not in the map is a programmer error; fall back to a
		// generic 500 message and log loudly so it gets caught in dev.
		logger.Error("writeError called with unknown code", "code", code)

		msg = codeMessages["internal_error"]
		code = "internal_error"
		status = http.StatusInternalServerError
	}

	writeJSON(w, logger, status, errorBody{Code: code, Message: msg})
}
