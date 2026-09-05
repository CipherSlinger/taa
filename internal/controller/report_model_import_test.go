package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReportModelImportIncludesRequestID(t *testing.T) {
	var got struct {
		DockerID  string  `json:"dockerId"`
		RequestID string  `json:"requestId"`
		TaskID    string  `json:"taskId"`
		Code      int     `json:"code"`
		Msg       *string `json:"msg"`
		Report    string  `json:"report"`
	}
	var rawBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != reportModelImportEndpoint {
			t.Fatalf("path = %s, want %s", r.URL.Path, reportModelImportEndpoint)
		}
		rawBody, _ = io.ReadAll(r.Body)
		if err := json.Unmarshal(rawBody, &got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	report := `{"conclusion":{"passed":true},"file_reports":null}`
	if err := ReportModelImport(context.Background(), server.URL, "docker-1", "req-1", "task-1", 0, "", report); err != nil {
		t.Fatalf("ReportModelImport() error = %v", err)
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
	if !bytes.Contains(rawBody, []byte(`"requestId":"req-1"`)) {
		t.Fatalf("raw body does not contain requestId: %s", rawBody)
	}
}
