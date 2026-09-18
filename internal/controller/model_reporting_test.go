package controller

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestReportModelLogPayload(t *testing.T) {
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != modelLogEndpoint {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(w, `{"msg":"success","result":{"received":true},"error":0}`)
	}))
	defer server.Close()

	err := ReportModelLog(context.Background(), server.URL, "docker-1", "req-1", "", 1,
		[]ModelLogEntry{{Seq: 1, Message: "epoch=1"}})
	if err != nil {
		t.Fatal(err)
	}
	if got["dockerId"] != "docker-1" || got["requestId"] != "req-1" {
		t.Fatalf("identity payload = %#v", got)
	}
	if got["taskId"] != nil {
		t.Fatalf("optional taskId should be omitted, payload = %#v", got)
	}
	if got["seqStart"] != float64(1) {
		t.Fatalf("seqStart = %#v", got["seqStart"])
	}
}

func TestReportModelLogRejectsNonSuccessAck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"msg":"rejected","result":{"received":false},"error":1}`)
	}))
	defer server.Close()

	err := ReportModelLog(context.Background(), server.URL, "docker-1", "req-1", "task-1", 1,
		[]ModelLogEntry{{Seq: 1, Message: "hello"}})
	if err == nil || !strings.Contains(err.Error(), "received") {
		t.Fatalf("error = %v, want acknowledgement error", err)
	}
}

func TestReportProgressRejectsInvalidPercent(t *testing.T) {
	err := ReportProgress(context.Background(), "127.0.0.1:1", "docker-1", "req-1", "", 100.1, time.Now().UTC())
	if err == nil || !strings.Contains(err.Error(), "percent") {
		t.Fatalf("error = %v, want percent validation error", err)
	}
}

func TestReportProgressPayload(t *testing.T) {
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != reportProgressEndpoint {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(w, `{"msg":"success","result":{"received":true},"error":0}`)
	}))
	defer server.Close()

	timestamp := time.Date(2026, time.September, 15, 9, 31, 0, 0, time.UTC)
	if err := ReportProgress(context.Background(), server.URL, "docker-1", "req-1", "task-1", 35.5, timestamp); err != nil {
		t.Fatal(err)
	}
	if got["dockerId"] != "docker-1" || got["requestId"] != "req-1" || got["taskId"] != "task-1" {
		t.Fatalf("identity payload = %#v", got)
	}
	if got["percent"] != 35.5 || got["timestamp"] != timestamp.Format(time.RFC3339) {
		t.Fatalf("progress payload = %#v", got)
	}
}

func TestReportWatcherSendsLogAndProgress(t *testing.T) {
	var mu sync.Mutex
	var logSeen, progressSeen bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case modelLogEndpoint:
			logSeen = true
		case reportProgressEndpoint:
			progressSeen = true
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"msg":"success","result":{"received":true},"error":0}`)
	}))
	defer server.Close()

	root := t.TempDir()
	logDir := filepath.Join(root, "log")
	progressDir := filepath.Join(root, "progress")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(progressDir, 0o755); err != nil {
		t.Fatal(err)
	}
	state := &TAAState{PlatformIP: server.URL, DockerID: "docker-1", Security: SecurityConfig{
		ModelLogDir:      logDir,
		ModelProgressDir: progressDir,
	}}
	watcher := newReportWatcher(context.Background(), state, "req-1", "task-1", 5*time.Millisecond)
	watcher.platformAddr = server.URL
	watcher.start()
	if err := os.WriteFile(filepath.Join(logDir, "train.jsonl"), []byte("{\"message\":\"epoch=1\"}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(progressDir, "progress.json"), []byte(`{"percent":25,"timestamp":"2026-09-15T00:00:00Z"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		seen := logSeen && progressSeen
		mu.Unlock()
		if seen {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	watcher.Stop()
	mu.Lock()
	defer mu.Unlock()
	if !logSeen || !progressSeen {
		t.Fatalf("logSeen=%v progressSeen=%v", logSeen, progressSeen)
	}
}
