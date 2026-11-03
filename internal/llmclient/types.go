// Package llmclient is the transport client for the remote LLM inference
// service. It knows prompts and generated text; it has no knowledge of code
// audit, findings or verdicts.
package llmclient

import (
	"errors"
	"time"
)

// CurrentProtocolVersion identifies the wire protocol spoken on /v1/llm/*.
const CurrentProtocolVersion = "teellm-protocol/v1"

// MaxResponsePayloadBytes bounds one response body (1MB).
const MaxResponsePayloadBytes = 1 << 20

// DefaultHealthCheckTimeout is the budget a health check gets when the caller
// sets no HealthCheckTimeout of its own.
//
// It is far longer than an ordinary request timeout because /v1/llm/healthz is
// not a ping: the service answers it only once the model is loaded, which on a
// cold service is seconds of disk and memory work. Budgeting it like an
// ordinary request yields a readiness gate a cold service can never pass - and
// retrying does not help, because cutting an attempt off cancels the load it
// was waiting on, so the next attempt starts the load again from nothing.
const DefaultHealthCheckTimeout = 120 * time.Second

// Status values returned by the inference service.
const (
	StatusSuccess            = "SUCCESS"
	StatusInvalidRequest     = "INVALID_REQUEST"
	StatusModelNotFound      = "MODEL_NOT_FOUND"
	StatusInternalError      = "INTERNAL_ERROR"
	StatusServiceUnavailable = "SERVICE_UNAVAILABLE"
)

var (
	// ErrPayloadTooLarge is returned when the response payload exceeds 1MB.
	ErrPayloadTooLarge = errors.New("response payload exceeds 1MB limit")
	// ErrInvalidStatus is returned when the server returns an unexpected non-success HTTP status.
	ErrInvalidStatus = errors.New("unexpected response status")
	// ErrCircuitOpen is returned while the circuit breaker rejects requests.
	ErrCircuitOpen = errors.New("circuit breaker is OPEN: inference service is unavailable")
	// ErrRetryable marks an error eligible for retry.
	ErrRetryable = errors.New("retryable error")
)

// GenerateRequest is one inference request: a prompt and optional sampling
// options, both opaque to this package.
type GenerateRequest struct {
	ProtocolVersion string         `json:"protocolVersion"`
	RequestID       string         `json:"requestId"`
	Model           string         `json:"model,omitempty"`
	Prompt          string         `json:"prompt"`
	Options         map[string]any `json:"options,omitempty"`
}

// GenerateResponse carries the model's raw text output.
type GenerateResponse struct {
	ProtocolVersion string `json:"protocolVersion"`
	RequestID       string `json:"requestId"`
	Status          string `json:"status"`
	ErrorMessage    string `json:"errorMessage,omitempty"`
	Model           string `json:"model,omitempty"`
	Text            string `json:"text,omitempty"`
}
