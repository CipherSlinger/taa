package llmclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestClient wires the unexported client around a test TLS server. The
// exported constructor validates the endpoint scheme (https only), so a test
// server on 127.0.0.1 could not pass through it; everything else - request
// shape, retry, circuit breaker and the separate health budget - is the
// production code path.
func newTestClient(t *testing.T, server *httptest.Server, mutate func(*Config)) Client {
	t.Helper()
	cfg := Config{
		Endpoint:           server.URL,
		MaxRetries:         3,
		RetryBaseDelay:     time.Millisecond,
		RetryMaxDelay:      time.Millisecond,
		HealthCheckTimeout: DefaultHealthCheckTimeout,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	httpClient := server.Client()
	httpClient.Timeout = cfg.Timeout
	healthClient := *httpClient
	healthClient.Timeout = cfg.HealthCheckTimeout
	return &client{
		cfg:          cfg,
		httpClient:   httpClient,
		healthClient: &healthClient,
		cb:           NewCircuitBreaker(3, time.Second),
		endpoint:     strings.TrimRight(cfg.Endpoint, "/"),
	}
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
		time.Sleep(3 * time.Second)
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
