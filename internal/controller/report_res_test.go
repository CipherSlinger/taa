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

	report := `{"schema_version":"1.0","training_task":{"status":"succeeded"},"codeaudit":{"conclusion":{"passed":true,"risk_level":"NONE","summary":"ok","recommendation":"none","statistics":{"total_findings":0,"high":0,"medium":0,"malicious":0,"suspicious":0,"benign":0,"uncertain":0}},"file_reports":null}}`
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

func TestReportResAutoFillsEmptyTaskIDFromRequestID(t *testing.T) {
	type reportResBody struct {
		DockerID  string `json:"dockerId"`
		RequestID string `json:"requestId"`
		TaskID    string `json:"taskId"`
	}

	var got reportResBody
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		// 模拟真实管控平台强校验
		if got.DockerID == "" || got.RequestID == "" || got.TaskID == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":  1,
				"msg":    "requestId、dockerId 和 taskId 不能为空",
				"result": nil,
			})
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":  0,
			"msg":    "success",
			"result": map[string]any{"received": true},
		})
	}))
	defer server.Close()

	// 1. 传入空 taskId，应自动由 requestId 补齐并成功上报
	reqID := "contract-model-import-2c928082a0994fef01a0a30dcfba0078"
	if err := ReportRes(context.Background(), server.URL, "docker-1", reqID, "", 0, "", "{}"); err != nil {
		t.Fatalf("ReportRes with empty taskId failed: %v", err)
	}
	if got.TaskID != reqID {
		t.Fatalf("expected TaskID to be auto-filled to %q, got %q", reqID, got.TaskID)
	}
	if got.RequestID != reqID {
		t.Fatalf("expected RequestID to be %q, got %q", reqID, got.RequestID)
	}

	// 2. 传入空 requestId，应自动由 taskId 补齐并成功上报
	taskID := "task-standalone-001"
	if err := ReportRes(context.Background(), server.URL, "docker-1", "", taskID, 0, "", "{}"); err != nil {
		t.Fatalf("ReportRes with empty requestId failed: %v", err)
	}
	if got.RequestID != taskID {
		t.Fatalf("expected RequestID to be auto-filled to %q, got %q", taskID, got.RequestID)
	}
	if got.TaskID != taskID {
		t.Fatalf("expected TaskID to be %q, got %q", taskID, got.TaskID)
	}
}

