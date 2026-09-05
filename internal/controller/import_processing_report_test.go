package controller

import (
	"testing"
	"time"
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

	report, err := buildTrainingReport(
		"task-20260902-001",
		startedAt,
		finishedAt,
		"succeeded",
		0,
		"",
		map[string]any{"algorithm": "sm3", "value": "model-digest"},
		trainingResult,
		nil,
		false,
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

func mustParseReportTime(t *testing.T, value string) (result time.Time) {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse time %q: %v", value, err)
	}
	return parsed
}
