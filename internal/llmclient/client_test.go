package llmclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// newTestClient wires the client around a test TLS server. NewClient cannot be
// used directly because it owns the http.Client and the test server's
// self-signed certificate is only trusted by the client httptest hands back;
// the wiring after that point is the production one.
func newTestClient(t *testing.T, server *httptest.Server, mutate func(*Config)) Client {
	t.Helper()
	cfg := Config{Endpoint: server.URL, RetryBaseDelay: time.Millisecond, RetryMaxDelay: time.Millisecond}
	if mutate != nil {
		mutate(&cfg)
	}
	return newClient(withDefaults(cfg), server.Client())
}

func TestNewClientRejectsPlainHTTP(t *testing.T) {
	if _, err := NewClient(Config{Endpoint: "http://127.0.0.1:8080"}); err == nil {
		t.Fatal("NewClient must reject a plain http endpoint")
	}
	if _, err := NewClient(Config{Endpoint: "https://127.0.0.1:8080"}); err != nil {
		t.Fatalf("NewClient must accept an https endpoint: %v", err)
	}
}

func TestGeneratePostsPromptAndReturnsText(t *testing.T) {
	var got map[string]any
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/llm/generate" {
			t.Errorf("path = %q, want /v1/llm/generate", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"protocolVersion":"teellm-protocol/v1","requestId":"r1","status":"SUCCESS","model":"m","text":"answer"}`))
	}))
	defer server.Close()

	c := newTestClient(t, server, nil)
	resp, err := c.Generate(context.Background(), &GenerateRequest{
		ProtocolVersion: CurrentProtocolVersion,
		RequestID:       "r1",
		Model:           "m",
		Prompt:          "hello",
		Options:         map[string]any{"temperature": 0},
	})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if resp.Text != "answer" || resp.Status != StatusSuccess {
		t.Fatalf("response = %+v", resp)
	}
	if got["prompt"] != "hello" {
		t.Errorf("prompt sent = %v", got["prompt"])
	}
	if got["requestId"] != "r1" {
		t.Errorf("requestId sent = %v", got["requestId"])
	}
	if got["protocolVersion"] != CurrentProtocolVersion {
		t.Errorf("protocolVersion sent = %v", got["protocolVersion"])
	}
}

func TestGenerateRetriesTransientStatus(t *testing.T) {
	var attempts int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"status":"SUCCESS","text":"ok"}`))
	}))
	defer server.Close()

	c := newTestClient(t, server, nil)
	if _, err := c.Generate(context.Background(), &GenerateRequest{ProtocolVersion: CurrentProtocolVersion, Prompt: "p"}); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
}

func TestGenerateDoesNotRetryClientError(t *testing.T) {
	var attempts int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	c := newTestClient(t, server, nil)
	if _, err := c.Generate(context.Background(), &GenerateRequest{ProtocolVersion: CurrentProtocolVersion, Prompt: "p"}); err == nil {
		t.Fatal("expected an error for HTTP 400")
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1 (a 400 is not retryable)", attempts)
	}
}

func TestHealthCheckOutlastsTheRequestTimeout(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	c := newTestClient(t, server, func(cfg *Config) {
		cfg.Timeout = 50 * time.Millisecond
		cfg.HealthCheckTimeout = 2 * time.Second
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.HealthCheck(ctx); err != nil {
		t.Fatalf("HealthCheck must outlast the request timeout: %v", err)
	}
}

func TestHealthCheckRemainsBounded(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	c := newTestClient(t, server, func(cfg *Config) {
		cfg.Timeout = 50 * time.Millisecond
		cfg.HealthCheckTimeout = 200 * time.Millisecond
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.HealthCheck(ctx); err == nil {
		t.Fatal("HealthCheck must fail when the endpoint outlasts its budget")
	}
}

func TestGenerateCountsOneFailurePerLogicalCall(t *testing.T) {
	var attempts int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	c := newTestClient(t, server, func(cfg *Config) {
		cfg.CircuitBreakerFailureThreshold = 2
		cfg.CircuitBreakerCooldown = time.Hour
	})

	// First logical call: one attempt plus retries, but exactly one failure.
	_, _ = c.Generate(context.Background(), &GenerateRequest{ProtocolVersion: CurrentProtocolVersion, Prompt: "p"})
	if attempts < 2 {
		t.Fatalf("attempts = %d, want retries", attempts)
	}
	// A second call must still be allowed; the first one alone must not trip a
	// threshold of 2.
	if _, err := c.Generate(context.Background(), &GenerateRequest{ProtocolVersion: CurrentProtocolVersion, Prompt: "p"}); errors.Is(err, ErrCircuitOpen) {
		t.Fatal("one logical call's retries must count as a single failure")
	}
	// The second logical call opens it.
	if _, err := c.Generate(context.Background(), &GenerateRequest{ProtocolVersion: CurrentProtocolVersion, Prompt: "p"}); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("breaker must open after two failed calls, got %v", err)
	}
}

func TestHalfOpenProbeIsReleasedOnMalformedBody(t *testing.T) {
	var good bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if good {
			_, _ = w.Write([]byte(`{"status":"SUCCESS","text":"ok"}`))
			return
		}
		_, _ = w.Write([]byte("not json"))
	}))
	defer server.Close()

	c := newTestClient(t, server, func(cfg *Config) {
		cfg.CircuitBreakerFailureThreshold = 1
		cfg.CircuitBreakerCooldown = 10 * time.Millisecond
	})

	// Trip it.
	if _, err := c.Generate(context.Background(), &GenerateRequest{ProtocolVersion: CurrentProtocolVersion, Prompt: "p"}); err == nil {
		t.Fatal("expected a decode error")
	}
	time.Sleep(20 * time.Millisecond)

	// This call runs as the half-open probe and fails again. Before the fix the
	// probe stayed active forever and every later call returned ErrCircuitOpen.
	if _, err := c.Generate(context.Background(), &GenerateRequest{ProtocolVersion: CurrentProtocolVersion, Prompt: "p"}); err == nil || errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("half-open probe must report the real error, got %v", err)
	}

	time.Sleep(20 * time.Millisecond)
	good = true
	resp, err := c.Generate(context.Background(), &GenerateRequest{ProtocolVersion: CurrentProtocolVersion, Prompt: "p"})
	if err != nil {
		t.Fatalf("breaker must recover after a good probe: %v", err)
	}
	if resp.Text != "ok" {
		t.Fatalf("response = %+v", resp)
	}
}

func TestHealthCheckDoesNotRetryTimeouts(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer server.Close()

	c := newTestClient(t, server, func(cfg *Config) {
		cfg.HealthCheckTimeout = 100 * time.Millisecond
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.HealthCheck(ctx); err == nil {
		t.Fatal("expected a timeout")
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("attempts = %d, want 1: a timed-out health check must not be retried", got)
	}
}
