package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

type contextKey uint8

const (
	requestIDKey contextKey = iota
	identityKey
)

type Error struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
	status    int
}

func (e *Error) Error() string             { return e.Code }
func (e *Error) GetStatus() int            { return e.status }
func (e *Error) ContentType(string) string { return "application/json" }

// Install once during package initialization, never mutate Huma globals per
// router. Validation errors deliberately discard input values and raw errors.
func init() {
	huma.NewError = func(status int, _ string, _ ...error) huma.StatusError { return apiError(status) }
}
func apiError(status int) *Error {
	code := map[int]string{400: "invalid_request", 401: "unauthorized", 403: "forbidden", 404: "not_found", 405: "method_not_allowed", 406: "not_acceptable", 408: "request_timeout", 409: "conflict", 413: "body_too_large", 415: "unsupported_media_type", 422: "validation_failed", 429: "rate_limited", 503: "unavailable"}[status]
	if code == "" {
		code = "internal_error"
	}
	message := http.StatusText(status)
	if message == "" {
		message = "Request failed"
	}
	return &Error{Code: code, Message: message, status: status}
}
func requestID(ctx context.Context) string {
	value, _ := ctx.Value(requestIDKey).(string)
	return value
}
func writeError(w http.ResponseWriter, r *http.Request, status int) {
	e := apiError(status)
	e.RequestID = requestID(r.Context())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(e)
}
