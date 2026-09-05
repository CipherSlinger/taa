package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReportResIncludesTrainingReport(t *testing.T) {
	type reportResBody struct {
		DockerID  string  `json:"dockerId"`
		RequestID string  `json:"requestId"`
		TaskID    string  `json:"taskId"`
		Code      int     `json:"code"`
		Msg       *string `json:"msg"`
		Report    string  `json:"report"`
	}

	var got reportResBody
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != reportResEndpoint {
			t.Fatalf("path = %s, want %s", r.URL.Path, reportResEndpoint)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	report := `{"schema_version":"1.0","training_task":{"status":"succeeded"},"codeaudit":{}}`
	if err := ReportRes(context.Background(), server.URL, "docker-1", "req-1", "task-1", 0, "", report); err != nil {
		t.Fatalf("ReportRes() error = %v", err)
	}

	if got.DockerID != "docker-1" || got.RequestID != "req-1" || got.TaskID != "task-1" || got.Code != 0 {
		t.Fatalf("body = %+v", got)
	}
	if got.Msg != nil {
		t.Fatalf("msg = %#v, want nil", got.Msg)
	}
	if got.Report != report {
		t.Fatalf("report = %q, want %q", got.Report, report)
	}
}
