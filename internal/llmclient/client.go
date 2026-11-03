package llmclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/CipherSlinger/teetls"
)

// Config configures the LLM inference client.
type Config struct {
	Endpoint string
	// Timeout bounds an ordinary request. Zero means no deadline: generation
	// time is a property of the deployment's hardware and model, and cutting a
	// request short mid-generation is indistinguishable, to the caller, from
	// the service being unavailable. It does not bound a health check; see
	// HealthCheckTimeout.
	Timeout time.Duration
	// HealthCheckTimeout bounds a health check, which gets its own budget
	// because /v1/llm/healthz answers only after the model is loaded. Zero
	// means DefaultHealthCheckTimeout.
	HealthCheckTimeout             time.Duration
	AllowedHosts                   []string
	TEETLS                         *teetls.Config
	CircuitBreakerFailureThreshold int
	CircuitBreakerCooldown         time.Duration
	MaxRetries                     int
	RetryBaseDelay                 time.Duration
	RetryMaxDelay                  time.Duration
}

// Client talks to the remote inference service.
type Client interface {
	Generate(ctx context.Context, req *GenerateRequest) (*GenerateResponse, error)
	HealthCheck(ctx context.Context) error
	Close() error
}

type client struct {
	cfg          Config
	httpClient   *http.Client
	healthClient *http.Client
	cb           *CircuitBreaker
	endpoint     string
}

// NewClient creates and validates a new inference client.
func NewClient(cfg Config) (Client, error) {
	if err := ValidateEndpoint(cfg.Endpoint, cfg.AllowedHosts); err != nil {
		return nil, fmt.Errorf("invalid endpoint: %w", err)
	}

	if cfg.CircuitBreakerFailureThreshold <= 0 {
		cfg.CircuitBreakerFailureThreshold = 3
	}
	if cfg.CircuitBreakerCooldown <= 0 {
		cfg.CircuitBreakerCooldown = 30 * time.Second
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 3
	}
	if cfg.RetryBaseDelay <= 0 {
		cfg.RetryBaseDelay = 100 * time.Millisecond
	}
	if cfg.RetryMaxDelay <= 0 {
		cfg.RetryMaxDelay = 2 * time.Second
	}
	// cfg.Timeout is left untouched: zero is the zero value of http.Client's
	// timeout, which means "no deadline", and that is the intended default
	// rather than a configuration mistake to correct.
	if cfg.HealthCheckTimeout <= 0 {
		cfg.HealthCheckTimeout = DefaultHealthCheckTimeout
	}

	cb := NewCircuitBreaker(cfg.CircuitBreakerFailureThreshold, cfg.CircuitBreakerCooldown)

	var httpClient *http.Client
	if cfg.TEETLS != nil {
		httpClient = teetls.NewHTTPClient(cfg.TEETLS)
		httpClient.Timeout = cfg.Timeout
	} else {
		httpClient = &http.Client{Timeout: cfg.Timeout}
	}

	// A second client, sharing the transport so the connection pool and any
	// TEE-TLS state stay common, but carrying the health budget instead of the
	// request budget.
	healthClient := *httpClient
	healthClient.Timeout = cfg.HealthCheckTimeout

	endpoint := strings.TrimRight(cfg.Endpoint, "/")

	return &client{
		cfg:          cfg,
		httpClient:   httpClient,
		healthClient: &healthClient,
		cb:           cb,
		endpoint:     endpoint,
	}, nil
}

// isTransientStatus reports whether an HTTP status code represents a transient server failure.
func isTransientStatus(code int) bool {
	return code == http.StatusTooManyRequests ||
		code == http.StatusInternalServerError ||
		code == http.StatusBadGateway ||
		code == http.StatusServiceUnavailable ||
		code == http.StatusGatewayTimeout
}

// Generate sends one prompt to the inference service and returns its raw text.
func (c *client) Generate(ctx context.Context, req *GenerateRequest) (*GenerateResponse, error) {
	if !c.cb.AllowRequest() {
		return nil, ErrCircuitOpen
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal generate request: %w", err)
	}

	var respEnvelope *GenerateResponse
	err = ExecuteWithRetryContext(ctx, c.cfg.MaxRetries, c.cfg.RetryBaseDelay, c.cfg.RetryMaxDelay, func(attempt int) error {
		httpReq, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/v1/llm/generate", bytes.NewReader(reqBytes))
		if reqErr != nil {
			return reqErr
		}
		httpReq.Header.Set("Content-Type", "application/json")

		resp, doErr := c.httpClient.Do(httpReq)
		if doErr != nil {
			if ctx != nil && ctx.Err() != nil {
				c.cb.ResetProbe()
				return ctx.Err()
			}
			c.cb.RecordFailure()
			return fmt.Errorf("%w: %v", ErrRetryable, doErr)
		}
		defer resp.Body.Close()

		if isTransientStatus(resp.StatusCode) {
			c.cb.RecordFailure()
			return fmt.Errorf("%w: server returned transient status %d", ErrRetryable, resp.StatusCode)
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%w: unexpected HTTP status %d", ErrInvalidStatus, resp.StatusCode)
		}

		limitedReader := io.LimitReader(resp.Body, int64(MaxResponsePayloadBytes)+1)
		bodyBytes, readErr := io.ReadAll(limitedReader)
		if readErr != nil {
			c.cb.RecordFailure()
			return fmt.Errorf("%w: read response body: %v", ErrRetryable, readErr)
		}
		if len(bodyBytes) > MaxResponsePayloadBytes {
			return ErrPayloadTooLarge
		}

		var parsedEnv GenerateResponse
		if jsonErr := json.Unmarshal(bodyBytes, &parsedEnv); jsonErr != nil {
			return fmt.Errorf("decode response envelope: %w", jsonErr)
		}

		respEnvelope = &parsedEnv
		c.cb.RecordSuccess()
		return nil
	})

	if err != nil {
		if ctx != nil && ctx.Err() != nil {
			c.cb.ResetProbe()
		}
		return nil, err
	}

	return respEnvelope, nil
}

// HealthCheck executes a health check against the inference endpoint.
func (c *client) HealthCheck(ctx context.Context) error {
	if !c.cb.AllowRequest() {
		return ErrCircuitOpen
	}

	err := ExecuteWithRetryContext(ctx, c.cfg.MaxRetries, c.cfg.RetryBaseDelay, c.cfg.RetryMaxDelay, func(attempt int) error {
		httpReq, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+"/v1/llm/healthz", nil)
		if reqErr != nil {
			return reqErr
		}

		resp, doErr := c.healthClient.Do(httpReq)
		if doErr != nil {
			if ctx != nil && ctx.Err() != nil {
				c.cb.ResetProbe()
				return ctx.Err()
			}
			c.cb.RecordFailure()
			return fmt.Errorf("%w: %v", ErrRetryable, doErr)
		}
		defer resp.Body.Close()

		if isTransientStatus(resp.StatusCode) {
			c.cb.RecordFailure()
			return fmt.Errorf("%w: server returned transient status %d", ErrRetryable, resp.StatusCode)
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%w: unexpected HTTP status %d", ErrInvalidStatus, resp.StatusCode)
		}

		limitedReader := io.LimitReader(resp.Body, int64(MaxResponsePayloadBytes)+1)
		bodyBytes, readErr := io.ReadAll(limitedReader)
		if readErr != nil {
			c.cb.RecordFailure()
			return fmt.Errorf("%w: read response body: %v", ErrRetryable, readErr)
		}
		if len(bodyBytes) > MaxResponsePayloadBytes {
			return ErrPayloadTooLarge
		}

		c.cb.RecordSuccess()
		return nil
	})

	if err != nil {
		if ctx != nil && ctx.Err() != nil {
			c.cb.ResetProbe()
		}
		return err
	}

	return nil
}

// Close releases any idle HTTP transport connections.
func (c *client) Close() error {
	if transport, ok := c.httpClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	return nil
}
