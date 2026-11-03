package llmclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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
//
// Generate returns a nil error when the service answered, even if the answer
// carries an application-level failure status; callers must check
// GenerateResponse.Status in addition to err.
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

	cfg = withDefaults(cfg)

	var httpClient *http.Client
	if cfg.TEETLS != nil {
		httpClient = teetls.NewHTTPClient(cfg.TEETLS)
		httpClient.Timeout = cfg.Timeout
	} else {
		httpClient = &http.Client{Timeout: cfg.Timeout}
	}

	return newClient(cfg, httpClient), nil
}

// withDefaults fills the zero values a caller is not required to set.
//
// cfg.Timeout is deliberately not defaulted: zero is http.Client's "no
// deadline", which is the intended default rather than a configuration mistake
// to correct.
func withDefaults(cfg Config) Config {
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
	if cfg.HealthCheckTimeout <= 0 {
		cfg.HealthCheckTimeout = DefaultHealthCheckTimeout
	}
	return cfg
}

// newClient finishes the wiring for an already validated and defaulted config.
// Tests call it directly to supply a test server's TLS client, so the health
// client copy and the circuit breaker construction stay on the production path.
func newClient(cfg Config, httpClient *http.Client) *client {
	// A second client, sharing the transport so the connection pool and any
	// TEE-TLS state stay common, but carrying the health budget instead of the
	// request budget.
	healthClient := *httpClient
	healthClient.Timeout = cfg.HealthCheckTimeout

	return &client{
		cfg:          cfg,
		httpClient:   httpClient,
		healthClient: &healthClient,
		cb:           NewCircuitBreaker(cfg.CircuitBreakerFailureThreshold, cfg.CircuitBreakerCooldown),
		endpoint:     strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/"),
	}
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
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal generate request: %w", err)
	}

	var resp GenerateResponse
	if err := c.do(ctx, c.httpClient, http.MethodPost, "/v1/llm/generate", reqBytes, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// HealthCheck executes a health check against the inference endpoint.
func (c *client) HealthCheck(ctx context.Context) error {
	return c.do(ctx, c.healthClient, http.MethodGet, "/v1/llm/healthz", nil, nil)
}

// do performs one logical request, retrying transient failures.
//
// Every path after AllowRequest ends in exactly one RecordSuccess,
// RecordFailure or ResetProbe, and accounting happens once per logical call
// rather than once per attempt: the breaker counts calls that failed, not the
// attempts inside them, so a single flaky request cannot open it and a
// half-open probe can never wedge the breaker.
func (c *client) do(ctx context.Context, httpClient *http.Client, method, path string, reqBody []byte, out any) error {
	if !c.cb.AllowRequest() {
		return ErrCircuitOpen
	}

	err := ExecuteWithRetryContext(ctx, c.cfg.MaxRetries, c.cfg.RetryBaseDelay, c.cfg.RetryMaxDelay, func(attempt int) error {
		var reader io.Reader
		if reqBody != nil {
			reader = bytes.NewReader(reqBody)
		}

		httpReq, reqErr := http.NewRequestWithContext(ctx, method, c.endpoint+path, reader)
		if reqErr != nil {
			return reqErr
		}
		if reqBody != nil {
			httpReq.Header.Set("Content-Type", "application/json")
		}

		resp, doErr := httpClient.Do(httpReq)
		if doErr != nil {
			if ctx != nil && ctx.Err() != nil {
				return ctx.Err()
			}
			var netErr net.Error
			if errors.As(doErr, &netErr) && netErr.Timeout() {
				// The attempt already spent the work it was waiting on;
				// retrying starts that work over. For the health endpoint that
				// work is the model load, which is exactly what a bounded
				// health budget exists to stop repeating.
				return fmt.Errorf("%w: %v", ErrInvalidStatus, doErr)
			}
			return fmt.Errorf("%w: %v", ErrRetryable, doErr)
		}
		defer resp.Body.Close()

		if isTransientStatus(resp.StatusCode) {
			// Drain so the connection can be reused; a TEE-TLS retry otherwise
			// pays for a fresh handshake.
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			return fmt.Errorf("%w: server returned transient status %d", ErrRetryable, resp.StatusCode)
		}

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			return fmt.Errorf("%w: unexpected HTTP status %d", ErrInvalidStatus, resp.StatusCode)
		}

		limitedReader := io.LimitReader(resp.Body, int64(MaxResponsePayloadBytes)+1)
		bodyBytes, readErr := io.ReadAll(limitedReader)
		if readErr != nil {
			return fmt.Errorf("%w: read response body: %v", ErrRetryable, readErr)
		}
		if len(bodyBytes) > MaxResponsePayloadBytes {
			return ErrPayloadTooLarge
		}

		if out != nil {
			if jsonErr := json.Unmarshal(bodyBytes, out); jsonErr != nil {
				return fmt.Errorf("decode response envelope: %w", jsonErr)
			}
		}
		return nil
	})

	if err != nil {
		if ctx != nil && ctx.Err() != nil {
			// The caller went away; that says nothing about the service, so the
			// breaker must not count it - but the half-open probe still has to
			// be released.
			c.cb.ResetProbe()
			return err
		}
		c.cb.RecordFailure()
		return err
	}

	c.cb.RecordSuccess()
	return nil
}

// Close releases any idle HTTP transport connections.
func (c *client) Close() error {
	if transport, ok := c.httpClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	return nil
}
