package inference_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"taa/internal/inference"
)

func TestHTTPAdapter_VerifyFinding_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/verify" {
			http.Error(w, "unexpected path: "+r.URL.Path, http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "invalid content type", http.StatusBadRequest)
			return
		}

		var req inference.RequestEnvelope
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "decode error: "+err.Error(), http.StatusBadRequest)
			return
		}

		if req.Action != inference.ActionVerifyFinding {
			http.Error(w, "unexpected action", http.StatusBadRequest)
			return
		}

		resp := inference.ResponseEnvelope{
			ProtocolVersion: inference.CurrentProtocolVersion,
			RequestID:       req.RequestID,
			Status:          inference.StatusSuccess,
			Decision: &inference.DecisionResult{
				Verdict:    inference.VerdictBenign,
				Confidence: 0.95,
				RiskLevel:  "LOW",
				ReasonCode: "VALIDATED_SAFE",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "encode error", http.StatusInternalServerError)
		}
	}))
	defer ts.Close()

	cfg := inference.Config{
		Transport: "http",
		Endpoint:  ts.URL,
		AuthToken: "test-token",
		Timeout:   2 * time.Second,
	}

	client, err := inference.NewClient(cfg)
	if err != nil {
		t.Fatalf("create client failed: %v", err)
	}
	defer client.Close()

	req := &inference.RequestEnvelope{
		ProtocolVersion: inference.CurrentProtocolVersion,
		RequestID:       "req-test-1",
		Action:          inference.ActionVerifyFinding,
	}

	resp, err := client.VerifyFinding(context.Background(), req)
	if err != nil {
		t.Fatalf("verify finding failed: %v", err)
	}

	if resp.Decision == nil {
		t.Fatal("expected non-nil decision")
	}
	if resp.Decision.Verdict != inference.VerdictBenign {
		t.Errorf("got verdict %s, want %s", resp.Decision.Verdict, inference.VerdictBenign)
	}
	if resp.Status != inference.StatusSuccess {
		t.Errorf("got status %s, want %s", resp.Status, inference.StatusSuccess)
	}
}

func TestHTTPAdapter_VerifyFinding_RetryOn500(t *testing.T) {
	var attempts atomic.Int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := attempts.Add(1)
		if current < 3 {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		resp := inference.ResponseEnvelope{
			ProtocolVersion: inference.CurrentProtocolVersion,
			RequestID:       "req-retry-1",
			Status:          inference.StatusSuccess,
			Decision: &inference.DecisionResult{
				Verdict:    inference.VerdictBenign,
				Confidence: 0.88,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	cfg := inference.Config{
		Transport: "http",
		Endpoint:  ts.URL,
		Timeout:   2 * time.Second,
	}

	client, err := inference.NewClient(cfg)
	if err != nil {
		t.Fatalf("create client failed: %v", err)
	}
	defer client.Close()

	req := &inference.RequestEnvelope{
		ProtocolVersion: inference.CurrentProtocolVersion,
		RequestID:       "req-retry-1",
		Action:          inference.ActionVerifyFinding,
	}

	resp, err := client.VerifyFinding(context.Background(), req)
	if err != nil {
		t.Fatalf("expected verify finding to succeed after retry, got: %v", err)
	}

	if resp.Decision.Verdict != inference.VerdictBenign {
		t.Errorf("got verdict %s, want %s", resp.Decision.Verdict, inference.VerdictBenign)
	}

	if total := attempts.Load(); total != 3 {
		t.Errorf("expected exactly 3 attempts, got %d", total)
	}
}

func TestHTTPAdapter_VerifyFinding_RetryOn429(t *testing.T) {
	var attempts atomic.Int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := attempts.Add(1)
		if current < 2 {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}

		resp := inference.ResponseEnvelope{
			ProtocolVersion: inference.CurrentProtocolVersion,
			RequestID:       "req-429-1",
			Status:          inference.StatusSuccess,
			Decision: &inference.DecisionResult{
				Verdict: inference.VerdictMalicious,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	cfg := inference.Config{
		Transport: "http",
		Endpoint:  ts.URL,
		Timeout:   2 * time.Second,
	}

	client, err := inference.NewClient(cfg)
	if err != nil {
		t.Fatalf("create client failed: %v", err)
	}
	defer client.Close()

	req := &inference.RequestEnvelope{
		ProtocolVersion: inference.CurrentProtocolVersion,
		RequestID:       "req-429-1",
		Action:          inference.ActionVerifyFinding,
	}

	resp, err := client.VerifyFinding(context.Background(), req)
	if err != nil {
		t.Fatalf("expected verify finding to succeed after retry on 429, got: %v", err)
	}

	if resp.Decision.Verdict != inference.VerdictMalicious {
		t.Errorf("got verdict %s, want %s", resp.Decision.Verdict, inference.VerdictMalicious)
	}

	if total := attempts.Load(); total != 2 {
		t.Errorf("expected exactly 2 attempts, got %d", total)
	}
}

func TestHTTPAdapter_VerifyFinding_NonRetryableStatus(t *testing.T) {
	var attempts atomic.Int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer ts.Close()

	cb := inference.NewCircuitBreaker(3, 10*time.Second)
	v := inference.NewEndpointValidator(nil, false)
	adapter, err := inference.NewHTTPAdapter(ts.URL, "", 2*time.Second, cb, v)
	if err != nil {
		t.Fatalf("new adapter: %v", err)
	}
	defer adapter.Close()

	req := &inference.RequestEnvelope{
		ProtocolVersion: inference.CurrentProtocolVersion,
		RequestID:       "req-400-1",
		Action:          inference.ActionVerifyFinding,
	}

	_, err = adapter.VerifyFinding(context.Background(), req)
	if err == nil {
		t.Fatal("expected error on HTTP 400, got nil")
	}

	// 400 is not retryable, should only attempt once
	if total := attempts.Load(); total != 1 {
		t.Errorf("expected exactly 1 attempt for non-retryable 400, got %d", total)
	}

	// 400 should not trip the circuit breaker
	if cb.State() != inference.StateClosed {
		t.Errorf("expected circuit breaker to remain CLOSED after 400, got %s", cb.State())
	}
}

func TestHTTPAdapter_VerifyFinding_NilRequestNoProbeLock(t *testing.T) {
	cb := inference.NewCircuitBreaker(1, 10*time.Millisecond)
	cb.RecordFailure() // transition to OPEN

	time.Sleep(20 * time.Millisecond) // cooldown expires -> StateHalfOpen on next Allow()

	adapter, err := inference.NewHTTPAdapter("http://127.0.0.1:11434", "", time.Second, cb, nil)
	if err != nil {
		t.Fatalf("new adapter: %v", err)
	}
	defer adapter.Close()

	// Calling with nil request should fail validation before touching circuit breaker
	_, err = adapter.VerifyFinding(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error on nil request, got nil")
	}

	// Circuit breaker probe slot must not have been consumed or locked
	if !cb.Allow() {
		t.Error("expected circuit breaker to still allow probe after nil request validation failure")
	}
}

func TestHTTPAdapter_VerifyFinding_400DoesNotTripCircuitBreaker(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer ts.Close()

	cb := inference.NewCircuitBreaker(2, 10*time.Second)
	adapter, err := inference.NewHTTPAdapter(ts.URL, "", time.Second, cb, nil)
	if err != nil {
		t.Fatalf("new adapter: %v", err)
	}
	defer adapter.Close()

	req := &inference.RequestEnvelope{
		ProtocolVersion: inference.CurrentProtocolVersion,
		RequestID:       "req-400-loop",
		Action:          inference.ActionVerifyFinding,
	}

	// Send 5 requests returning 400 (threshold is 2)
	for i := 0; i < 5; i++ {
		_, err = adapter.VerifyFinding(context.Background(), req)
		if err == nil {
			t.Fatal("expected error on HTTP 400")
		}
	}

	// Breaker should still be CLOSED
	if cb.State() != inference.StateClosed {
		t.Errorf("expected circuit breaker to remain CLOSED after multiple 400s, got %s", cb.State())
	}
}

func TestHTTPAdapter_VerifyFinding_BodySizeExceeded(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Write 1MB + 100 bytes
		largeBytes := make([]byte, 1024*1024+100)
		_, _ = w.Write(largeBytes)
	}))
	defer ts.Close()

	adapter, err := inference.NewHTTPAdapter(ts.URL, "", time.Second, nil, nil)
	if err != nil {
		t.Fatalf("new adapter: %v", err)
	}
	defer adapter.Close()

	req := &inference.RequestEnvelope{
		ProtocolVersion: inference.CurrentProtocolVersion,
		RequestID:       "req-large-body",
		Action:          inference.ActionVerifyFinding,
	}

	_, err = adapter.VerifyFinding(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for response body exceeding 1MB limit, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum body size limit") {
		t.Errorf("expected body size limit error message, got: %v", err)
	}
}

func TestHTTPAdapter_VerifyFinding_CircuitOpen(t *testing.T) {
	var serverHits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverHits.Add(1)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	cb := inference.NewCircuitBreaker(1, 10*time.Second)
	// Trigger failure to open breaker.
	cb.RecordFailure()

	v := inference.NewEndpointValidator(nil, false)
	adapter, err := inference.NewHTTPAdapter(ts.URL, "", time.Second, cb, v)
	if err != nil {
		t.Fatalf("new adapter failed: %v", err)
	}
	defer adapter.Close()

	req := &inference.RequestEnvelope{
		ProtocolVersion: inference.CurrentProtocolVersion,
		RequestID:       "req-circuit-open",
		Action:          inference.ActionVerifyFinding,
	}

	_, err = adapter.VerifyFinding(context.Background(), req)
	if !errors.Is(err, inference.ErrCircuitOpen) {
		t.Fatalf("expected ErrCircuitOpen, got: %v", err)
	}

	if hits := serverHits.Load(); hits != 0 {
		t.Errorf("expected 0 requests to reach server while circuit breaker is open, got %d", hits)
	}
}

func TestHTTPAdapter_HealthCheck(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/healthz" {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		cfg := inference.Config{
			Transport: "http",
			Endpoint:  ts.URL,
			Timeout:   1 * time.Second,
		}

		client, err := inference.NewClient(cfg)
		if err != nil {
			t.Fatalf("create client failed: %v", err)
		}
		defer client.Close()

		if err := client.HealthCheck(context.Background()); err != nil {
			t.Errorf("health check failed: %v", err)
		}
	})

	t.Run("success_with_auth", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/healthz" {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			if r.Header.Get("Authorization") != "Bearer secret" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		cfg := inference.Config{
			Transport: "http",
			Endpoint:  ts.URL,
			AuthToken: "secret",
			Timeout:   1 * time.Second,
		}

		client, err := inference.NewClient(cfg)
		if err != nil {
			t.Fatalf("create client failed: %v", err)
		}
		defer client.Close()

		if err := client.HealthCheck(context.Background()); err != nil {
			t.Errorf("health check with auth failed: %v", err)
		}
	})

	t.Run("failure_non_200", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "unhealthy", http.StatusServiceUnavailable)
		}))
		defer ts.Close()

		cfg := inference.Config{
			Transport: "http",
			Endpoint:  ts.URL,
			Timeout:   1 * time.Second,
		}

		client, err := inference.NewClient(cfg)
		if err != nil {
			t.Fatalf("create client failed: %v", err)
		}
		defer client.Close()

		if err := client.HealthCheck(context.Background()); err == nil {
			t.Error("expected health check to fail on 503")
		}
	})

	t.Run("failure_unreachable", func(t *testing.T) {
		cfg := inference.Config{
			Transport: "http",
			Endpoint:  "http://127.0.0.1:59999", // Unopened port
			Timeout:   500 * time.Millisecond,
		}

		client, err := inference.NewClient(cfg)
		if err != nil {
			t.Fatalf("create client failed: %v", err)
		}
		defer client.Close()

		if err := client.HealthCheck(context.Background()); err == nil {
			t.Error("expected health check to fail on unreachable server")
		}
	})
}

func TestUDSAdapter_EndToEnd(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "inference.sock")

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	defer listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req inference.RequestEnvelope
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		resp := inference.ResponseEnvelope{
			ProtocolVersion: inference.CurrentProtocolVersion,
			RequestID:       req.RequestID,
			Status:          inference.StatusSuccess,
			Decision: &inference.DecisionResult{
				Verdict:    inference.VerdictBenign,
				Confidence: 0.99,
				RiskLevel:  "NONE",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	server := &http.Server{Handler: mux}
	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Close()

	cfg := inference.Config{
		Transport: "uds",
		UDSPath:   socketPath,
		Timeout:   2 * time.Second,
	}

	client, err := inference.NewClient(cfg)
	if err != nil {
		t.Fatalf("create UDS client failed: %v", err)
	}
	defer client.Close()

	if err := client.HealthCheck(context.Background()); err != nil {
		t.Fatalf("UDS health check failed: %v", err)
	}

	req := &inference.RequestEnvelope{
		ProtocolVersion: inference.CurrentProtocolVersion,
		RequestID:       "req-uds-1",
		Action:          inference.ActionVerifyFinding,
	}

	resp, err := client.VerifyFinding(context.Background(), req)
	if err != nil {
		t.Fatalf("UDS verify finding failed: %v", err)
	}

	if resp.Decision.Verdict != inference.VerdictBenign {
		t.Errorf("got verdict %s, want %s", resp.Decision.Verdict, inference.VerdictBenign)
	}
}

func TestUDSAdapter_DirectConstruction(t *testing.T) {
	adapter, err := inference.NewUDSAdapter("/run/test.sock", 0, nil)
	if err != nil {
		t.Fatalf("expected NewUDSAdapter to succeed with defaults, got: %v", err)
	}
	defer adapter.Close()
}

func TestFactory_Routing(t *testing.T) {
	t.Run("route_to_uds_via_transport", func(t *testing.T) {
		cfg := inference.Config{
			Transport: "uds",
			UDSPath:   "/run/taa/ipc/test.sock",
		}
		client, err := inference.NewClient(cfg)
		if err != nil {
			t.Fatalf("expected client creation to succeed: %v", err)
		}
		defer client.Close()
	})

	t.Run("route_to_uds_via_empty_transport_with_udspath", func(t *testing.T) {
		cfg := inference.Config{
			UDSPath: "/run/taa/ipc/test.sock",
		}
		client, err := inference.NewClient(cfg)
		if err != nil {
			t.Fatalf("expected client creation to succeed: %v", err)
		}
		defer client.Close()
	})

	t.Run("route_to_http_valid", func(t *testing.T) {
		cfg := inference.Config{
			Transport: "http",
			Endpoint:  "http://127.0.0.1:11434",
		}
		client, err := inference.NewClient(cfg)
		if err != nil {
			t.Fatalf("expected client creation to succeed: %v", err)
		}
		defer client.Close()
	})

	t.Run("validator_rejection_metadata", func(t *testing.T) {
		cfg := inference.Config{
			Transport: "http",
			Endpoint:  "http://169.254.169.254/latest/meta-data",
		}
		_, err := inference.NewClient(cfg)
		if err == nil {
			t.Fatal("expected client creation to fail on restricted address")
		}
	})

	t.Run("validator_rejection_unallowed_host", func(t *testing.T) {
		cfg := inference.Config{
			Transport:    "http",
			Endpoint:     "http://evil.com:11434",
			AllowedHosts: []string{"localhost", "127.0.0.1"},
		}
		_, err := inference.NewClient(cfg)
		if err == nil {
			t.Fatal("expected client creation to fail on unlisted host")
		}
	})

	t.Run("uds_invalid_relative_path", func(t *testing.T) {
		cfg := inference.Config{
			Transport: "uds",
			UDSPath:   "relative/path/test.sock",
		}
		_, err := inference.NewClient(cfg)
		if err == nil {
			t.Fatal("expected client creation to fail on relative UDS path")
		}
	})

	t.Run("route_to_uds_via_unix_endpoint", func(t *testing.T) {
		cfg := inference.Config{
			Endpoint: "unix:///run/taa/ipc/test.sock",
		}
		client, err := inference.NewClient(cfg)
		if err != nil {
			t.Fatalf("expected client creation to succeed for unix:// endpoint: %v", err)
		}
		defer client.Close()
	})

	t.Run("unsupported_transport", func(t *testing.T) {
		cfg := inference.Config{
			Transport: "grpc",
			Endpoint:  "http://localhost:8080",
		}
		_, err := inference.NewClient(cfg)
		if err == nil {
			t.Fatal("expected client creation to fail on unsupported transport")
		}
	})
}
