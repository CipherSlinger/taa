package inference

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HTTPAdapter communicates with an inference gateway over HTTP/REST.
type HTTPAdapter struct {
	endpoint       string
	authToken      string
	client         *http.Client
	circuitBreaker *CircuitBreaker
	validator      *EndpointValidator
}

var _ InferenceClient = (*HTTPAdapter)(nil)

// NewHTTPAdapter creates an HTTP inference adapter.
func NewHTTPAdapter(endpoint, token string, timeout time.Duration, cb *CircuitBreaker, v *EndpointValidator) (*HTTPAdapter, error) {
	if v == nil {
		v = NewEndpointValidator(nil, false)
	}
	if err := v.Validate(endpoint); err != nil {
		return nil, fmt.Errorf("endpoint validation failed: %w", err)
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if cb == nil {
		cb = NewCircuitBreaker(3, 30*time.Second)
	}
	return &HTTPAdapter{
		endpoint:       endpoint,
		authToken:      token,
		client:         &http.Client{Timeout: timeout},
		circuitBreaker: cb,
		validator:      v,
	}, nil
}

// VerifyFinding sends a structured finding verification request.
func (a *HTTPAdapter) VerifyFinding(ctx context.Context, req *RequestEnvelope) (*ResponseEnvelope, error) {
	if !a.circuitBreaker.Allow() {
		return nil, ErrCircuitOpen
	}

	if req == nil {
		return nil, errors.New("request envelope cannot be nil")
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	var respEnv ResponseEnvelope
	verifyURL := strings.TrimRight(a.endpoint, "/") + "/v1/verify"

	retryOp := func() error {
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, verifyURL, bytes.NewReader(body))
		if err != nil {
			return err
		}
		httpReq.Header.Set("Content-Type", "application/json")
		if a.authToken != "" {
			httpReq.Header.Set("Authorization", "Bearer "+a.authToken)
		}

		resp, err := a.client.Do(httpReq)
		if err != nil {
			if ctx != nil && ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("%w: %v", ErrRetryable, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError {
			return fmt.Errorf("%w: HTTP %d", ErrRetryable, resp.StatusCode)
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("inference server returned HTTP %d", resp.StatusCode)
		}

		respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		if err != nil {
			return fmt.Errorf("read response body: %w", err)
		}

		var env ResponseEnvelope
		if err := json.Unmarshal(respBytes, &env); err != nil {
			return fmt.Errorf("unmarshal response envelope: %w", err)
		}
		respEnv = env
		return nil
	}

	if err := ExecuteWithRetryContext(ctx, retryOp, 2, 200*time.Millisecond); err != nil {
		a.circuitBreaker.RecordFailure()
		return nil, err
	}

	a.circuitBreaker.RecordSuccess()
	return &respEnv, nil
}

// HealthCheck verifies availability of the HTTP endpoint.
func (a *HTTPAdapter) HealthCheck(ctx context.Context) error {
	healthURL := strings.TrimRight(a.endpoint, "/") + "/healthz"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return fmt.Errorf("create health check request: %w", err)
	}
	if a.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+a.authToken)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("health check request failed: %w", err)
	}
	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// Close releases resources.
func (a *HTTPAdapter) Close() error {
	if a.client != nil {
		a.client.CloseIdleConnections()
	}
	return nil
}
