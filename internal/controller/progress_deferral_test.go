package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// progressCapture records every training progress TAA reports to the platform, and
// lets a test observe the TAA state at the very moment a given percent arrives - which
// is how the ordering between the 100% report and the training-end result check is
// pinned without relying on wall-clock timing.
type progressCapture struct {
	mu       sync.Mutex
	percents []float64
	results  []importedReportPayload
	onReport func(percent float64)
}

func newProgressCaptureServer(t *testing.T, onReport func(percent float64)) (*progressCapture, *httptest.Server) {
	t.Helper()
	capture := &progressCapture{onReport: onReport}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture.mu.Lock()
		switch r.URL.Path {
		case reportProgressEndpoint:
			var payload struct {
				Percent float64 `json:"percent"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode reportProgress payload: %v", err)
			}
			capture.percents = append(capture.percents, payload.Percent)
			capture.mu.Unlock()
			if capture.onReport != nil {
				capture.onReport(payload.Percent)
			}
		case reportResEndpoint:
			var payload importedReportPayload
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode reportRes payload: %v", err)
			}
			capture.results = append(capture.results, payload)
			capture.mu.Unlock()
		default:
			capture.mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"msg":"success","result":{"received":true},"error":0}`)
	}))
	t.Cleanup(server.Close)
	return capture, server
}

// waitForResult blocks until the training result report lands, so a test never asserts
// while reportTrainingAsync is still in flight. Returns the code the platform was given.
func (c *progressCapture) waitForResult(t *testing.T) int {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		landed := len(c.results) > 0
		code := 0
		if landed {
			code = c.results[len(c.results)-1].Code
		}
		c.mu.Unlock()
		if landed {
			return code
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("training result was never reported to the platform")
	return 0
}

func (c *progressCapture) reported() []float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]float64(nil), c.percents...)
}

func newProgressTestState(t *testing.T, platformAddr string) *TAAState {
	t.Helper()
	root := t.TempDir()
	logDir := filepath.Join(root, "log")
	progressDir := filepath.Join(root, "progress")
	for _, dir := range []string{logDir, progressDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("create %s: %v", dir, err)
		}
	}
	return &TAAState{
		PlatformIP: platformAddr,
		DockerID:   "docker-progress",
		Security: SecurityConfig{
			ModelLogDir:      logDir,
			ModelProgressDir: progressDir,
		},
	}
}

func writeProgressFile(t *testing.T, state *TAAState, percent float64, timestamp string) {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"percent": percent, "timestamp": timestamp})
	if err != nil {
		t.Fatalf("marshal progress: %v", err)
	}
	if err := os.WriteFile(filepath.Join(state.Security.GetModelProgressDir(), "progress.json"), payload, 0o644); err != nil {
		t.Fatalf("write progress: %v", err)
	}
}

// A 100% snapshot means the model finished training, not that the task is over: TAA
// still copies the artifacts out and runs the result leakage check. The watcher must
// hold it and hand it over only when the pipeline releases it.
func TestReportWatcherHoldsFullProgressUntilReleased(t *testing.T) {
	capture, server := newProgressCaptureServer(t, nil)
	state := newProgressTestState(t, server.URL)
	watcher := newReportWatcher(context.Background(), state, "req-1", "task-1", time.Hour)

	writeProgressFile(t, state, 88.5, "2026-09-15T00:00:00Z")
	watcher.flushWithContext(context.Background())
	if got := capture.reported(); len(got) != 1 || got[0] != 88.5 {
		t.Fatalf("reported percents = %v, want [88.5]", got)
	}

	writeProgressFile(t, state, 100, "2026-09-15T01:00:00Z")
	watcher.flushWithContext(context.Background())
	if got := capture.reported(); len(got) != 1 {
		t.Fatalf("reported percents = %v, want the 100%% held back", got)
	}

	watcher.reportDeferredProgress(context.Background())
	if got := capture.reported(); len(got) != 2 || got[1] != 100 {
		t.Fatalf("reported percents = %v, want [88.5 100] once released", got)
	}

	watcher.reportDeferredProgress(context.Background())
	if got := capture.reported(); len(got) != 2 {
		t.Fatalf("reported percents = %v, want the 100%% released exactly once", got)
	}
}

// A model that never reported 100% must not have one invented for it: the platform
// keeps the last percentage the model actually wrote.
func TestReportWatcherWithoutAFullProgressReleasesNothing(t *testing.T) {
	capture, server := newProgressCaptureServer(t, nil)
	state := newProgressTestState(t, server.URL)
	watcher := newReportWatcher(context.Background(), state, "req-1", "task-1", time.Hour)

	writeProgressFile(t, state, 97, "2026-09-15T00:00:00Z")
	watcher.flushWithContext(context.Background())
	watcher.reportDeferredProgress(context.Background())

	if got := capture.reported(); len(got) != 1 || got[0] != 97 {
		t.Fatalf("reported percents = %v, want [97] and no synthesised 100", got)
	}
}

// The end-to-end order the platform must see: the training-end leakage check has
// already reached its verdict - it is persisted on the import index record from inside
// the check - by the time the 100% report lands.
func TestExecuteTrainingReportsFullProgressAfterTheResultCheck(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.ResultCheck = true

	req := importRequest{TaskID: "task-progress-order", RequestID: "req-progress-order"}
	record := ImportIndexRecord{
		TaskID:    req.TaskID,
		RequestID: req.RequestID,
		Hash:      "hash-progress-order",
		DataDir:   t.TempDir(),
		ResultDir: t.TempDir(),
	}
	store := seedImportIndexRecord(t, state, record)

	var mu sync.Mutex
	verdictAtFullProgress := false
	fullProgressSeen := false
	capture, platformServer := newProgressCaptureServer(t, func(percent float64) {
		if percent < 100 {
			return
		}
		stored, ok := store.LookupByTaskID(req.TaskID)
		mu.Lock()
		defer mu.Unlock()
		fullProgressSeen = true
		verdictAtFullProgress = ok && stored.ResultCheck != nil
	})
	pointTrainingAtPlatform(state, platformServer.URL)

	cfg := runtimeConfig{Commands: []string{
		writeFullProgressCommand(t, state),
	}}

	state.executeTraining(req, 1, record, cfg, nil, time.Now().UTC())

	if code := capture.waitForResult(t); code != 0 {
		t.Fatalf("reportRes code = %d, want 0 for a run whose result passed the check", code)
	}

	mu.Lock()
	seen, verdictReady := fullProgressSeen, verdictAtFullProgress
	mu.Unlock()
	if !seen {
		t.Fatal("the platform was never told the task reached 100%")
	}
	if !verdictReady {
		t.Fatal("100% was reported before the result leakage check had reached its verdict")
	}
	if full := countFullProgress(capture.reported()); full != 1 {
		t.Fatalf("reported percents = %v, want exactly one 100%% report", capture.reported())
	}
}

// A result directory the check rejects is still a run that reached its end: the 100% is
// released and the rejection travels separately, as reportRes code 2.
func TestExecuteTrainingReleasesFullProgressWhenTheResultIsRejected(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.ResultCheck = true

	dataDir := t.TempDir()
	data := []byte(strings.Repeat("sample-row-0001\n", 16))
	if err := os.WriteFile(filepath.Join(dataDir, "train.csv"), data, 0o644); err != nil {
		t.Fatalf("write training data: %v", err)
	}
	// The check hashes the training input directory named on the import record.
	state.Security.DataDir = dataDir

	req := importRequest{TaskID: "task-progress-leak", RequestID: "req-progress-leak"}
	record := ImportIndexRecord{
		TaskID:    req.TaskID,
		RequestID: req.RequestID,
		Hash:      "hash-progress-leak",
		DataDir:   dataDir,
		ResultDir: t.TempDir(),
	}
	seedImportIndexRecord(t, state, record)

	capture, platformServer := newProgressCaptureServer(t, nil)
	pointTrainingAtPlatform(state, platformServer.URL)

	// The training data is carried into the result directory, which is what the leakage
	// check exists to catch.
	cfg := runtimeConfig{Commands: []string{
		writeFullProgressCommand(t, state),
		`cp "$TAA_INPUT_DIR/train.csv" "$TAA_OUTPUT_DIR/train.csv"`,
	}}

	state.executeTraining(req, 1, record, cfg, nil, time.Now().UTC())

	if code := capture.waitForResult(t); code != reportCodeResultLeak {
		t.Fatalf("reportRes code = %d, want %d for a rejected result", code, reportCodeResultLeak)
	}
	if full := countFullProgress(capture.reported()); full != 1 {
		t.Fatalf("reported percents = %v, want the 100%% released even though the result was rejected", capture.reported())
	}
}

// seedImportIndexRecord commits a record the training pipeline can attach its leakage
// verdict to, which is what makes the ordering assertion in the test above possible.
func seedImportIndexRecord(t *testing.T, state *TAAState, record ImportIndexRecord) *ImportIndexStore {
	t.Helper()
	store, err := state.importIndexStore()
	if err != nil {
		t.Fatalf("import index store: %v", err)
	}
	if err := store.Reserve(record.RequestID, record.TaskID); err != nil {
		t.Fatalf("reserve import index slot: %v", err)
	}
	if err := store.Commit(record); err != nil {
		t.Fatalf("seed import index record: %v", err)
	}
	return store
}

func pointTrainingAtPlatform(state *TAAState, platformAddr string) {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.PlatformIP = platformAddr
	state.DockerID = "docker-progress"
}

// writeFullProgressCommand is the shell command a training run uses to report 100%: the
// progress directory is emptied before training starts, so the file has to be written
// while the training command runs.
func writeFullProgressCommand(t *testing.T, state *TAAState) string {
	t.Helper()
	progressPath := filepath.Join(state.Security.GetModelProgressDir(), "progress.json")
	return fmt.Sprintf("printf '%%s\\n' '%s' > %q", `{"percent":100,"timestamp":"2026-09-15T02:00:00Z"}`, progressPath)
}

func countFullProgress(percents []float64) int {
	full := 0
	for _, percent := range percents {
		if percent >= progressHoldPercent {
			full++
		}
	}
	return full
}
