package runtime

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestJSONLLogReaderIncremental(t *testing.T) {
	logDir := t.TempDir()
	reader := NewJSONLLogReader(logDir)

	entries, err := reader.ReadNew()
	if err != nil {
		t.Fatalf("ReadNew on empty dir failed: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}

	logFile := filepath.Join(logDir, "train.log")
	// write 2 lines
	if err := os.WriteFile(logFile, []byte("epoch 1: loss 0.5\nepoch 2: loss 0.4\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	entries, err = reader.ReadNew()
	if err != nil {
		t.Fatalf("ReadNew failed: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Seq != 1 || entries[0].Message != "epoch 1: loss 0.5" {
		t.Fatalf("unexpected entry 0: %+v", entries[0])
	}
	if entries[1].Seq != 2 || entries[1].Message != "epoch 2: loss 0.4" {
		t.Fatalf("unexpected entry 1: %+v", entries[1])
	}

	// second read without changes returns nothing
	entries, err = reader.ReadNew()
	if err != nil {
		t.Fatalf("ReadNew second time failed: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries on second read, got %d", len(entries))
	}

	// append partial line (no trailing newline)
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("epoch 3: in progress...")
	_ = f.Close()

	entries, err = reader.ReadNew()
	if err != nil {
		t.Fatalf("ReadNew after partial line failed: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries for partial line without newline, got %d", len(entries))
	}

	// complete line with newline
	f, err = os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(" done\n")
	_ = f.Close()

	entries, err = reader.ReadNew()
	if err != nil {
		t.Fatalf("ReadNew after line completion failed: %v", err)
	}
	if len(entries) != 1 || entries[0].Seq != 3 || entries[0].Message != "epoch 3: in progress... done" {
		t.Fatalf("unexpected completed entry: %+v", entries)
	}
}

func TestJSONLLogReaderPrependTimestamp(t *testing.T) {
	logDir := t.TempDir()
	reader := NewJSONLLogReader(logDir)

	logFile := filepath.Join(logDir, "train.log")
	content := `{"timestamp": "2026-09-16T10:00:00Z", "message": "[Train] Starting Epoch 1/30 (lr=0.001)"}` + "\n" +
		`{"time": "2026-09-16T10:00:05Z", "message": "Epoch 1 finished"}` + "\n" +
		`{"timestamp": "2026-09-16T10:00:10Z", "msg": "Evaluating..."}` + "\n"
	if err := os.WriteFile(logFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	entries, err := reader.ReadNew()
	if err != nil {
		t.Fatalf("ReadNew failed: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	expected0 := "[2026-09-16T10:00:00Z] [Train] Starting Epoch 1/30 (lr=0.001)"
	if entries[0].Message != expected0 {
		t.Fatalf("entries[0].Message = %q, want %q", entries[0].Message, expected0)
	}

	expected1 := "[2026-09-16T10:00:05Z] Epoch 1 finished"
	if entries[1].Message != expected1 {
		t.Fatalf("entries[1].Message = %q, want %q", entries[1].Message, expected1)
	}

	expected2 := "[2026-09-16T10:00:10Z] Evaluating..."
	if entries[2].Message != expected2 {
		t.Fatalf("entries[2].Message = %q, want %q", entries[2].Message, expected2)
	}
}

func TestReadLatestProgress(t *testing.T) {
	progressDir := t.TempDir()

	// Empty dir
	snapshot, ok, err := ReadLatestProgress(progressDir)
	if err != nil {
		t.Fatalf("ReadLatestProgress failed: %v", err)
	}
	if ok {
		t.Fatal("expected ok = false for empty dir")
	}

	// Write invalid files
	_ = os.WriteFile(filepath.Join(progressDir, "invalid_nan.json"), []byte(`{"percent": 150}`), 0o644)
	_ = os.WriteFile(filepath.Join(progressDir, "not_json.txt"), []byte(`hello`), 0o644)

	snapshot, ok, err = ReadLatestProgress(progressDir)
	if err != nil {
		t.Fatalf("ReadLatestProgress failed: %v", err)
	}
	if ok {
		t.Fatal("expected ok = false for invalid files")
	}

	// Write valid progress 1
	p1 := filepath.Join(progressDir, "step1.json")
	_ = os.WriteFile(p1, []byte(`{"percent": 25.5, "timestamp": "2026-09-16T10:00:00Z"}`), 0o644)

	snapshot, ok, err = ReadLatestProgress(progressDir)
	if err != nil || !ok {
		t.Fatalf("ReadLatestProgress failed: ok=%v, err=%v", ok, err)
	}
	if snapshot.Percent != 25.5 {
		t.Fatalf("expected 25.5, got %f", snapshot.Percent)
	}

	// Write valid progress 2 with newer timestamp
	time.Sleep(10 * time.Millisecond)
	p2 := filepath.Join(progressDir, "step2.json")
	_ = os.WriteFile(p2, []byte(`{"percentage": 75.0, "timestamp": "2026-09-16T10:05:00Z"}`), 0o644)

	snapshot, ok, err = ReadLatestProgress(progressDir)
	if err != nil || !ok {
		t.Fatalf("ReadLatestProgress failed: ok=%v, err=%v", ok, err)
	}
	if snapshot.Percent != 75.0 {
		t.Fatalf("expected 75.0, got %f", snapshot.Percent)
	}
	if snapshot.Key == "" {
		t.Fatal("expected non-empty Key in snapshot")
	}
}
