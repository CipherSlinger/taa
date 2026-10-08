package runtime

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadTrainingResult(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "training_result.json")

	// Missing file returns empty map
	res, err := LoadTrainingResult(path)
	if err != nil {
		t.Fatalf("expected no error for missing file, got %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("expected empty map, got %v", res)
	}

	// Valid JSON
	_ = os.WriteFile(path, []byte(`{"metrics": {"accuracy": 0.95}}`), 0o644)
	res, err = LoadTrainingResult(path)
	if err != nil {
		t.Fatalf("LoadTrainingResult failed: %v", err)
	}
	metrics, ok := res["metrics"].(map[string]any)
	if !ok || metrics["accuracy"] != 0.95 {
		t.Fatalf("unexpected result: %v", res)
	}
}

func TestBuildTrainingReport(t *testing.T) {
	startedAt := time.Date(2026, 9, 16, 10, 0, 0, 0, time.UTC)
	finishedAt := time.Date(2026, 9, 16, 10, 10, 0, 0, time.UTC)

	modelChecksum := map[string]any{"algorithm": "sm3", "value": "model-hash-sm3"}
	dataChecksum := map[string]any{"algorithm": "sm3", "value": "data-hash-sm3"}
	trainingResult := map[string]any{
		"training_task": map[string]any{
			"epochs": 10,
		},
		"metrics": map[string]any{
			"loss": 0.05,
		},
		"dataset": map[string]any{
			"samples":        1000,
			"data_structure": "should-be-cleaned",
		},
	}
	codeauditSection := map[string]any{
		"decision": "APPROVED",
	}

	report, err := BuildTrainingReport("task-001", startedAt, finishedAt, "succeeded", 0, "", modelChecksum, dataChecksum, nil, trainingResult, codeauditSection)
	if err != nil {
		t.Fatalf("BuildTrainingReport failed: %v", err)
	}

	if report["schema_version"] != "1.0" {
		t.Fatalf("unexpected schema_version: %v", report["schema_version"])
	}

	trainingTask, ok := report["training_task"].(map[string]any)
	if !ok {
		t.Fatalf("missing training_task: %v", report)
	}
	if trainingTask["task_id"] != "task-001" {
		t.Fatalf("task_id mismatch: %v", trainingTask["task_id"])
	}
	if trainingTask["duration_seconds"] != int64(600) {
		t.Fatalf("duration_seconds = %v, want 600", trainingTask["duration_seconds"])
	}
	if trainingTask["status"] != "succeeded" || trainingTask["exit_code"] != 0 {
		t.Fatalf("unexpected status/exit_code: %v, %v", trainingTask["status"], trainingTask["exit_code"])
	}
	// This call passes nil for the dependency checksum, and the report for a session that never
	// imported dependencies must not grow a deps_checksum key at all.
	if _, exists := trainingTask["deps_checksum"]; exists {
		t.Fatal("deps_checksum must be absent when no deps are imported")
	}

	metrics, ok := trainingTask["metrics"].(map[string]any)
	if !ok || metrics["loss"] != 0.05 {
		t.Fatalf("metrics mismatch: %v", trainingTask["metrics"])
	}

	dataset, ok := report["dataset"].(map[string]any)
	if !ok {
		t.Fatalf("missing dataset: %v", report)
	}
	if _, exists := dataset["data_structure"]; exists {
		t.Fatal("data_structure should have been stripped by CleanDatasetField")
	}
	if dataset["samples"] != 1000 {
		t.Fatalf("samples mismatch: %v", dataset["samples"])
	}

	if report["codeaudit"] == nil {
		t.Fatal("expected codeaudit section in report")
	}
}

func TestBuildCrashFailureReport(t *testing.T) {
	startedAt := time.Date(2026, 9, 16, 10, 0, 0, 0, time.UTC)
	finishedAt := time.Date(2026, 9, 16, 10, 2, 0, 0, time.UTC)

	modelChecksum := map[string]any{"algorithm": "sm3", "value": "model-hash"}
	report, err := BuildCrashFailureReport("task-crash-1", startedAt, finishedAt, "", modelChecksum, nil)
	if err != nil {
		t.Fatalf("BuildCrashFailureReport failed: %v", err)
	}

	trainingTask := report["training_task"].(map[string]any)
	if trainingTask["status"] != "failed" {
		t.Fatalf("status = %v, want failed", trainingTask["status"])
	}
	if trainingTask["exit_code"] != 137 {
		t.Fatalf("exit_code = %v, want 137", trainingTask["exit_code"])
	}
	if trainingTask["failure_reason"] == nil {
		t.Fatal("expected non-empty failure_reason for crash report")
	}

	dataset := report["dataset"].(map[string]any)
	dataChecksum := dataset["checksum"].(map[string]any)
	if dataChecksum["value"] != "N/A" {
		t.Fatalf("expected N/A for default dataChecksum, got %v", dataChecksum)
	}
}

func TestBuildTrainingReportIncludesDepsChecksum(t *testing.T) {
	startedAt := time.Date(2026, 10, 8, 1, 0, 0, 0, time.UTC)
	finishedAt := startedAt.Add(3 * time.Minute)

	depsChecksum := map[string]any{"size": int64(42), "algorithm": "sm3", "value": "deps-hash"}

	report, err := BuildTrainingReport("task-deps", startedAt, finishedAt, "succeeded", 0, "",
		nil, nil, depsChecksum, nil, nil)
	if err != nil {
		t.Fatalf("BuildTrainingReport: %v", err)
	}

	task, ok := report["training_task"].(map[string]any)
	if !ok {
		t.Fatalf("training_task missing: %#v", report)
	}
	got, ok := task["deps_checksum"].(map[string]any)
	if !ok {
		t.Fatalf("deps_checksum missing or not an object: %#v", task["deps_checksum"])
	}
	// Compare the value, not just its presence: a hardcoded placeholder or the wrong map would
	// still satisfy an existence check while delivering nothing useful to the platform.
	if got["value"] != "deps-hash" {
		t.Fatalf("deps_checksum.value = %v, want deps-hash", got["value"])
	}
	if got["algorithm"] != "sm3" {
		t.Fatalf("deps_checksum.algorithm = %v, want sm3", got["algorithm"])
	}
}

// TestBuildTrainingReportOmitsEmptyDepsChecksum covers the shape the dependency state actually has
// on a cold start: a freshly initialized state holds a non-nil but empty checksum map. Checking
// only for nil would let that empty map through as "deps_checksum": {}, which a session that never
// imported dependencies must never report.
func TestBuildTrainingReportOmitsEmptyDepsChecksum(t *testing.T) {
	startedAt := time.Date(2026, 10, 8, 1, 0, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Minute)

	report, err := BuildTrainingReport("task-cold", startedAt, finishedAt, "succeeded", 0, "",
		nil, nil, map[string]any{}, nil, nil)
	if err != nil {
		t.Fatalf("BuildTrainingReport: %v", err)
	}

	task, ok := report["training_task"].(map[string]any)
	if !ok {
		t.Fatalf("training_task missing: %#v", report)
	}
	if got, exists := task["deps_checksum"]; exists {
		t.Fatalf("deps_checksum must be absent for an empty checksum map, got %#v", got)
	}
}
