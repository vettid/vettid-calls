package issuer

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// Error codes (CALLING-SERVICE §5.2; grammar and body of RELAY-PROTOCOL
// §7.1, as the push gateway answers them).
const (
	CodeSignatureInvalid   = "signature_invalid"
	CodeTimestampStale     = "timestamp_stale"
	CodeAttestationInvalid = "attestation_invalid"
	CodeBadRequest         = "bad_request"
	CodeRateLimited        = "rate_limited"
	CodeInternal           = "internal"
	CodeNotFound           = "not_found"
)

// Outcomes is the closed set of the requests metric's outcome dimension.
var Outcomes = []string{"ok", CodeSignatureInvalid, CodeTimestampStale, CodeAttestationInvalid,
	CodeBadRequest, CodeRateLimited, CodeInternal}

func statusFor(code string) int {
	switch code {
	case CodeSignatureInvalid, CodeTimestampStale:
		return http.StatusUnauthorized
	case CodeAttestationInvalid:
		return http.StatusForbidden
	case CodeBadRequest:
		return http.StatusBadRequest
	case CodeRateLimited:
		return http.StatusTooManyRequests
	case CodeNotFound:
		return http.StatusNotFound
	default:
		return http.StatusInternalServerError
	}
}

// messages are fixed per code: an error body never echoes request
// content.
var messages = map[string]string{
	CodeSignatureInvalid:   "request signature invalid",
	CodeTimestampStale:     "request timestamp outside the freshness window",
	CodeAttestationInvalid: "attestation invalid",
	CodeBadRequest:         "malformed request",
	CodeRateLimited:        "rate limited",
	CodeInternal:           "internal error",
	CodeNotFound:           "not found",
}

type errorBody struct {
	Code       string `json:"code"`
	Message    string `json:"message,omitempty"`
	RetryAfter int    `json:"retry_after,omitempty"`
}

type apiError struct {
	code       string
	retryAfter int
}

func fail(code string) *apiError { return &apiError{code: code} }

func writeError(w http.ResponseWriter, e *apiError) {
	if e.retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(e.retryAfter))
	}
	writeJSON(w, statusFor(e.code), errorBody{Code: e.code, Message: messages[e.code], RetryAfter: e.retryAfter})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
