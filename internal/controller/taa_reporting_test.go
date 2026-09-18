package controller

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestReportTaaLogPayload(t *testing.T) {
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != taaLogEndpoint {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(w, `{"msg":"success","result":{"received":true},"error":0}`)
	}))
	defer server.Close()

	err := ReportTaaLog(context.Background(), server.URL, "docker-1", "req-1", "", 1,
		[]TaaLogEntry{{Seq: 1, Message: "[INFO] [system] started"}})
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
	entries, ok := got["entries"].([]any)
	if !ok || len(entries) != 1 {
		t.Fatalf("entries = %#v", got["entries"])
	}
}

func TestReportTaaLogRejectsNonSuccessAck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"msg":"rejected","result":{"received":false},"error":1}`)
	}))
	defer server.Close()

	err := ReportTaaLog(context.Background(), server.URL, "docker-1", "req-1", "task-1", 1,
		[]TaaLogEntry{{Seq: 1, Message: "[INFO] [system] hello"}})
	if err == nil || !strings.Contains(err.Error(), "received") {
		t.Fatalf("error = %v, want acknowledgement error", err)
	}
}

func TestReportTaaLogValidation(t *testing.T) {
	ctx := context.Background()
	// missing platformAddr
	if err := ReportTaaLog(ctx, "", "docker-1", "req-1", "", 1, []TaaLogEntry{{Seq: 1, Message: "m"}}); err == nil {
		t.Fatal("expected error on missing platformAddr")
	}
	// missing dockerID
	if err := ReportTaaLog(ctx, "http://127.0.0.1", "", "req-1", "", 1, []TaaLogEntry{{Seq: 1, Message: "m"}}); err == nil {
		t.Fatal("expected error on missing dockerID")
	}
	// missing requestID
	if err := ReportTaaLog(ctx, "http://127.0.0.1", "docker-1", "", "", 1, []TaaLogEntry{{Seq: 1, Message: "m"}}); err == nil {
		t.Fatal("expected error on missing requestID")
	}
	// empty entries
	if err := ReportTaaLog(ctx, "http://127.0.0.1", "docker-1", "req-1", "", 1, nil); err == nil {
		t.Fatal("expected error on nil entries")
	}
	if err := ReportTaaLog(ctx, "http://127.0.0.1", "docker-1", "req-1", "", 1, []TaaLogEntry{}); err == nil {
		t.Fatal("expected error on empty entries")
	}
	// non-contiguous seq
	badEntries := []TaaLogEntry{
		{Seq: 1, Message: "msg1"},
		{Seq: 3, Message: "msg2"},
	}
	if err := ReportTaaLog(ctx, "http://127.0.0.1", "docker-1", "req-1", "", 1, badEntries); err == nil {
		t.Fatal("expected error on non-contiguous seq")
	}
	// empty message
	badMsgEntries := []TaaLogEntry{
		{Seq: 1, Message: "  "},
	}
	if err := ReportTaaLog(ctx, "http://127.0.0.1", "docker-1", "req-1", "", 1, badMsgEntries); err == nil {
		t.Fatal("expected error on blank message")
	}
}

func TestTaaLogWatcherFlushesAndBatches(t *testing.T) {
	var mu sync.Mutex
	var receivedBatches []taaLogRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != taaLogEndpoint {
			http.Error(w, "bad endpoint", http.StatusNotFound)
			return
		}
		var req taaLogRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		receivedBatches = append(receivedBatches, req)
		mu.Unlock()

		_, _ = io.WriteString(w, `{"msg":"success","result":{"received":true},"error":0}`)
	}))
	defer server.Close()

	state := &TAAState{
		PlatformIP: server.URL,
		DockerID:   "test-docker",
		Logs:       NewLogStore(200),
	}

	state.Logs.Info("system", "taa starting")
	state.Logs.Info("system", "taa initialized")

	watcher := state.StartTaaLogWatcher(context.Background())
	// 等待定时器触发 flush 或主动 Stop 触发 flush
	time.Sleep(100 * time.Millisecond)
	watcher.Stop()

	mu.Lock()
	defer mu.Unlock()

	if len(receivedBatches) == 0 {
		t.Fatal("expected at least 1 reported batch")
	}
	first := receivedBatches[0]
	if first.DockerID != "test-docker" {
		t.Errorf("dockerId = %s, want test-docker", first.DockerID)
	}
	if first.RequestID != "system" {
		t.Errorf("requestId = %s, want system", first.RequestID)
	}
	if len(first.Entries) != 2 {
		t.Fatalf("entries len = %d, want 2", len(first.Entries))
	}
	if first.Entries[0].Seq != 1 || !strings.Contains(first.Entries[0].Message, "taa starting") {
		t.Errorf("entry 0 = %+v", first.Entries[0])
	}
}
