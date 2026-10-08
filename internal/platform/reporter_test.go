package platform

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReportDepsPostsChecksum(t *testing.T) {
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != ReportDepsEndpoint {
			t.Errorf("path = %q, want %q", r.URL.Path, ReportDepsEndpoint)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"msg":"ok","result":{"received":true},"error":0}`))
	}))
	defer server.Close()

	checksum := map[string]any{"size": int64(7), "algorithm": "sm3", "value": "h"}
	if err := ReportDeps(context.Background(), server.URL, "docker-1", "req-1", "task-1", 0, "依赖包导入成功", checksum); err != nil {
		t.Fatalf("ReportDeps: %v", err)
	}
	if got["checksum"] == nil {
		t.Fatalf("checksum missing from payload: %#v", got)
	}
}

func TestReportAuditScopedCarriesScope(t *testing.T) {
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"msg":"ok","result":{"received":true},"error":0}`))
	}))
	defer server.Close()

	if err := ReportAuditScoped(context.Background(), server.URL, "docker-1", "req-1", "task-1", 0, "ok", "{}", "deps"); err != nil {
		t.Fatalf("ReportAuditScoped: %v", err)
	}
	if got["scope"] != "deps" {
		t.Fatalf("scope = %v, want deps", got["scope"])
	}
}

// TestReportTaskOutcomeDispatchesDepsToReportDeps pins the dispatch branch: a deps_import task
// must reach reportDeps, not reportRes. Asserting "no error" would pass under a mutation that
// deletes the branch (reportRes also returns nil), so the assertion is on the URL the request
// actually arrives at.
func TestReportTaskOutcomeDispatchesDepsToReportDeps(t *testing.T) {
	var path string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"msg":"ok","result":{"received":true},"error":0}`))
	}))
	defer server.Close()

	if err := ReportTaskOutcome(context.Background(), server.URL, "docker-1", "req-1", "task-1", "deps_import", 1, "依赖包导入失败", ""); err != nil {
		t.Fatalf("ReportTaskOutcome: %v", err)
	}
	if path != ReportDepsEndpoint {
		t.Fatalf("path = %q, want %q -- a deps task must not be reported through the training-result callback", path, ReportDepsEndpoint)
	}
}
