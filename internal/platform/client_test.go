package platform_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"taa/internal/platform"
)

func TestClient_ReportRes(t *testing.T) {
	received := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != platform.ReportResEndpoint {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body["dockerId"] != "dock-1" || body["taskId"] != "task-1" {
			t.Fatalf("unexpected payload: %+v", body)
		}
		received = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := platform.NewClient(server.URL, "dock-1")
	err := client.ReportRes(context.Background(), "req-1", "task-1", 0, "success", "{}")
	if err != nil {
		t.Fatalf("reportRes failed: %v", err)
	}
	if !received {
		t.Fatal("expected server to receive request")
	}
}

func TestClient_ReportProgressValidation(t *testing.T) {
	client := platform.NewClient("http://127.0.0.1:9999", "dock-1")
	if err := client.ReportProgress(context.Background(), "req-1", "task-1", 105.0, time.Now()); err == nil {
		t.Fatal("expected error for percent > 100")
	}
	if err := client.ReportProgress(context.Background(), "req-1", "task-1", -1.0, time.Now()); err == nil {
		t.Fatal("expected error for percent < 0")
	}
}

func TestClient_ReportModelLog_Payload(t *testing.T) {
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != platform.ModelLogEndpoint {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"msg":"success","result":{"received":true},"error":0}`))
	}))
	defer server.Close()

	client := platform.NewClient(server.URL, "dock-1")
	entries := []platform.ModelLogEntry{
		{
			Seq:     0,
			Message: "starting training",
		},
		{
			Seq:       1,
			Message:   "epoch=1",
			Timestamp: "2026-09-21T10:00:00Z",
			Component: "trainer",
			Level:     "INFO",
		},
	}
	// Test with empty taskID -> taskId should be omitted in json
	err := client.ReportModelLog(context.Background(), "req-1", "", 0, entries)
	if err != nil {
		t.Fatalf("ReportModelLog failed: %v", err)
	}

	if got["dockerId"] != "dock-1" || got["requestId"] != "req-1" {
		t.Fatalf("unexpected identity payload: %+v", got)
	}
	if _, hasTaskID := got["taskId"]; hasTaskID {
		t.Fatalf("expected taskId to be omitted when empty, got: %#v", got["taskId"])
	}
	if got["seqStart"] != float64(0) {
		t.Fatalf("expected seqStart=0, got: %#v", got["seqStart"])
	}

	rawEntries, ok := got["entries"].([]any)
	if !ok || len(rawEntries) != 2 {
		t.Fatalf("unexpected entries: %#v", got["entries"])
	}

	// First entry: Seq is 0 (must be present!), timestamp/component/level omitted
	e0, ok := rawEntries[0].(map[string]any)
	if !ok {
		t.Fatalf("entry 0 is not a map: %#v", rawEntries[0])
	}
	if _, hasSeq := e0["seq"]; !hasSeq {
		t.Fatalf("expected entry 0 to have seq field even when 0, got: %#v", e0)
	}
	if e0["seq"] != float64(0) {
		t.Fatalf("expected entry 0 seq=0, got: %#v", e0["seq"])
	}
	if e0["message"] != "starting training" {
		t.Fatalf("expected entry 0 message, got: %#v", e0["message"])
	}
	if _, hasTS := e0["timestamp"]; hasTS {
		t.Fatalf("expected entry 0 timestamp to be omitted, got: %#v", e0["timestamp"])
	}
	if _, hasComp := e0["component"]; hasComp {
		t.Fatalf("expected entry 0 component to be omitted, got: %#v", e0["component"])
	}
	if _, hasLevel := e0["level"]; hasLevel {
		t.Fatalf("expected entry 0 level to be omitted, got: %#v", e0["level"])
	}

	// Second entry: all fields populated
	e1, ok := rawEntries[1].(map[string]any)
	if !ok {
		t.Fatalf("entry 1 is not a map: %#v", rawEntries[1])
	}
	if e1["seq"] != float64(1) {
		t.Fatalf("expected entry 1 seq=1, got: %#v", e1["seq"])
	}
	if e1["message"] != "epoch=1" {
		t.Fatalf("expected entry 1 message, got: %#v", e1["message"])
	}
	if e1["timestamp"] != "2026-09-21T10:00:00Z" {
		t.Fatalf("expected entry 1 timestamp, got: %#v", e1["timestamp"])
	}
	if e1["component"] != "trainer" {
		t.Fatalf("expected entry 1 component, got: %#v", e1["component"])
	}
	if e1["level"] != "INFO" {
		t.Fatalf("expected entry 1 level, got: %#v", e1["level"])
	}
}

