package controller

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"taa/internal/codeaudit"
)

func TestBuildTrainingReportAddsModelChecksumAndKeepsTrainingMetrics(t *testing.T) {
	startedAt := mustParseReportTime(t, "2026-09-02T10:03:35Z")
	finishedAt := mustParseReportTime(t, "2026-09-02T10:03:43Z")

	trainingResult := map[string]any{
		"training_task": map[string]any{
			"task_id":          "task-20260902-001",
			"started_at":       "2026-09-02T10:03:35Z",
			"finished_at":      "2026-09-02T10:03:43Z",
			"duration_seconds": 8,
			"status":           "succeeded",
			"exit_code":        0,
			"failure_reason":   nil,
			"metrics": map[string]any{
				"final_accuracy": 0.91,
				"final_loss":     0.21,
				"epochs":         []any{map[string]any{"epoch": 1, "accuracy": 0.52, "loss": 1.23}},
			},
		},
		"dataset": map[string]any{
			"total_samples":  12500,
			"splits":         map[string]any{"train": 10000, "test": 1000},
			"data_structure": map[string]any{"features": []any{map[string]any{"name": "feature1"}, map[string]any{"name": "label"}}},
			"checksum":       map[string]any{"algorithm": "sm3", "value": "dataset-digest"},
		},
	}
	audit := &codeaudit.AuditReport{
		Conclusion: codeaudit.AuditConclusion{
			Passed:         true,
			RiskLevel:      "NONE",
			Summary:        "未发现安全问题，代码通过审计",
			Recommendation: "无需修复",
			Statistics:     codeaudit.AuditStatistics{TotalFindings: 0},
		},
		FileReports: nil,
		Target: codeaudit.AuditTarget{
			Directory:    "models/examples",
			FilesScanned: 3,
		},
	}

	report, err := buildTrainingReport(
		"task-20260902-001",
		startedAt,
		finishedAt,
		"succeeded",
		0,
		"",
		map[string]any{"algorithm": "sm3", "value": "model-digest"},
		trainingResult,
		audit,
		true,
	)
	if err != nil {
		t.Fatalf("buildTrainingReport: %v", err)
	}

	if report["schema_version"] != "1.0" {
		t.Fatalf("schema_version = %v, want 1.0", report["schema_version"])
	}
	trainingTask := report["training_task"].(map[string]any)
	if trainingTask["task_id"] != "task-20260902-001" {
		t.Fatalf("task_id = %v", trainingTask["task_id"])
	}
	metrics := trainingTask["metrics"].(map[string]any)
	if metrics["final_accuracy"] != 0.91 || metrics["final_loss"] != 0.21 {
		t.Fatalf("training_task.metrics = %v", metrics)
	}
	if trainingTask["model_checksum"].(map[string]any)["value"] != "model-digest" {
		t.Fatalf("training_task.model_checksum = %v", trainingTask["model_checksum"])
	}
	dataset := report["dataset"].(map[string]any)
	if dataset["checksum"].(map[string]any)["algorithm"] != "sm3" {
		t.Fatalf("dataset checksum = %v", dataset["checksum"])
	}
	codeauditSection, ok := report["codeaudit"].(map[string]any)
	if !ok {
		t.Fatalf("report missing codeaudit: %v", report)
	}
	if _, ok := codeauditSection["report_id"]; ok {
		t.Fatalf("codeaudit should not include report_id: %v", codeauditSection)
	}
	if _, ok := codeauditSection["target"]; ok {
		t.Fatalf("codeaudit should not include target: %v", codeauditSection)
	}
	if _, ok := codeauditSection["statistics"]; ok {
		t.Fatalf("codeaudit should not include statistics: %v", codeauditSection)
	}
	if _, ok := codeauditSection["scan_metadata"]; ok {
		t.Fatalf("codeaudit should not include scan_metadata: %v", codeauditSection)
	}
	conclusion, ok := codeauditSection["conclusion"].(codeaudit.AuditConclusion)
	if !ok {
		t.Fatalf("codeaudit conclusion type = %T, want codeaudit.AuditConclusion", codeauditSection["conclusion"])
	}
	if conclusion.Summary != "未发现安全问题，代码通过审计" {
		t.Fatalf("codeaudit conclusion summary = %v", conclusion.Summary)
	}
	if fileReports, ok := codeauditSection["file_reports"]; ok && fileReports != nil {
		t.Fatalf("file_reports = %v, want nil", fileReports)
	}
	if _, ok := report["model"]; ok {
		t.Fatalf("report should not include model: %v", report)
	}
	if _, ok := report["metrics"]; ok {
		t.Fatalf("report should not include metrics: %v", report)
	}
	if _, ok := report["artifacts"]; ok {
		t.Fatalf("report should not include artifacts: %v", report)
	}
}

func TestBuildDirectoryChecksumSkipsSymlinkedDirectories(t *testing.T) {
	dir := t.TempDir()

	payloadDir := filepath.Join(dir, "payload")
	if err := os.Mkdir(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload: %v", err)
	}
	if err := os.WriteFile(filepath.Join(payloadDir, "model.bin"), []byte("abc"), 0o644); err != nil {
		t.Fatalf("write payload file: %v", err)
	}
	if err := os.Symlink(payloadDir, filepath.Join(dir, "data")); err != nil {
		t.Fatalf("symlink data: %v", err)
	}

	checksum, err := buildDirectoryChecksum(dir, "sm3")
	if err != nil {
		t.Fatalf("buildDirectoryChecksum: %v", err)
	}
	if got := checksum["size"].(int64); got != 3 {
		t.Fatalf("checksum size = %d, want 3", got)
	}
	if checksum["value"] == "" {
		t.Fatalf("checksum value is empty: %v", checksum)
	}
}

func mustParseReportTime(t *testing.T, value string) (result time.Time) {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse time %q: %v", value, err)
	}
	return parsed
}
