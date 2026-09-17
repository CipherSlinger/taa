package inference

import (
	"context"
)

// InferenceClient specifies the unified interface for model inference communication.
type InferenceClient interface {
	// VerifyFinding arbitrates a detected security finding.
	VerifyFinding(ctx context.Context, req *RequestEnvelope) (*ResponseEnvelope, error)

	// HealthCheck performs a readiness probe on the inference service.
	HealthCheck(ctx context.Context) error

	// Close releases any network or IPC resources.
	Close() error
}
