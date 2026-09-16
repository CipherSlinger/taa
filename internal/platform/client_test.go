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
