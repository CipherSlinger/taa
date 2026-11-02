package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// newOutboxTestState builds a state bound to a real sealed store, which is what
// the outbox needs: the queue is the sealed state, not an in-memory list.
func newOutboxTestState(t *testing.T, platformAddr string) (*TAAState, *StateStore) {
	t.Helper()
	st, _ := createTestStateStore(t)
	state := NewTAAState("", platformAddr, "docker-outbox", "", "", nil, nil, SecurityConfig{})
	state.SetStateStore(st)
	return state, st
}

func TestPendingReportsSurviveSealAndRestore(t *testing.T) {
	state, st := newOutboxTestState(t, "127.0.0.1:18081")
	state.pendingReports = []PendingReportSnapshot{
		{
			ID:           "report-1",
			Kind:         ReportKindRes,
			RequestID:    "req-1",
			TaskID:       "task-1",
			Code:         0,
			Report:       `{"status":"succeeded"}`,
			PlatformAddr: "127.0.0.1:18081",
			DockerID:     "docker-outbox",
			CreatedAt:    time.Now().UTC(),
		},
	}
	if err := state.sealStateLocked(); err != nil {
		t.Fatalf("seal state: %v", err)
	}

	persisted, err := st.UnsealState()
	if err != nil {
		t.Fatalf("unseal state: %v", err)
	}
	if len(persisted.PendingReports) != 1 || persisted.PendingReports[0].TaskID != "task-1" {
		t.Fatalf("pending report was not sealed: %+v", persisted.PendingReports)
	}

	restored := NewTAAState("", "", "", "", "", nil, nil, SecurityConfig{})
	restored.RestoreFromPersistentState(persisted)
	if len(restored.pendingReports) != 1 || restored.pendingReports[0].ID != "report-1" {
		t.Fatalf("pending report was not restored: %+v", restored.pendingReports)
	}
}

// TestAckPendingReportsRemovesOnlyAcked pins the batch ack used by a drain pass,
// which delivers several reports but must seal them away in one write.
func TestAckPendingReportsRemovesOnlyAcked(t *testing.T) {
	state, st := newOutboxTestState(t, "127.0.0.1:18081")
	state.pendingReports = []PendingReportSnapshot{
		{ID: "keep-1", Kind: ReportKindRes, RequestID: "req-1", TaskID: "task-1"},
		{ID: "drop-1", Kind: ReportKindRes, RequestID: "req-2", TaskID: "task-2"},
		{ID: "drop-2", Kind: ReportKindAudit, RequestID: "req-3", TaskID: "task-3"},
		{ID: "keep-2", Kind: ReportKindRes, RequestID: "req-4", TaskID: "task-4"},
	}

	state.ackPendingReports("drop-1", "drop-2")

	if got := state.pendingReportsSnapshot(); len(got) != 2 || got[0].ID != "keep-1" || got[1].ID != "keep-2" {
		t.Fatalf("remaining queue = %+v, want keep-1 and keep-2", got)
	}
	persisted, err := st.UnsealState()
	if err != nil {
		t.Fatalf("unseal state: %v", err)
	}
	if len(persisted.PendingReports) != 2 {
		t.Fatalf("sealed queue = %+v, want the two survivors", persisted.PendingReports)
	}
}

func TestReportOutboxRetriesUntilDelivered(t *testing.T) {
	var mu sync.Mutex
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		n := attempts
		mu.Unlock()
		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	state, _ := newOutboxTestState(t, server.Listener.Addr().String())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	outbox := state.startReportOutbox(ctx, 5*time.Millisecond, 20*time.Millisecond)
	defer outbox.Stop()

	if err := state.EnqueuePlatformReport(PendingReportSnapshot{
		Kind: ReportKindRes, RequestID: "req-retry", TaskID: "task-retry",
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !state.hasPendingReports() {
			mu.Lock()
			got := attempts
			mu.Unlock()
			if got < 3 {
				t.Fatalf("report delivered after %d attempts, want at least 3", got)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("pending report was never delivered")
}

func TestReportOutboxDispatchesByKind(t *testing.T) {
	type arrival struct {
		path string
		body map[string]any
	}
	arrivals := make(chan arrival, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		arrivals <- arrival{path: r.URL.Path, body: body}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	state, _ := newOutboxTestState(t, server.Listener.Addr().String())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	outbox := state.startReportOutbox(ctx, 5*time.Millisecond, 20*time.Millisecond)
	defer outbox.Stop()

	entries := []PendingReportSnapshot{
		{Kind: ReportKindModelImport, RequestID: "req-import", TaskID: "task-import", Checksum: map[string]any{"value": "sm3"}},
		{Kind: ReportKindAudit, RequestID: "req-audit", TaskID: "task-audit", Code: 2, Report: `{"passed":false}`},
		{Kind: ReportKindRes, RequestID: "req-res", TaskID: "task-res", Report: `{"status":"succeeded"}`},
	}
	for _, entry := range entries {
		if err := state.EnqueuePlatformReport(entry); err != nil {
			t.Fatalf("enqueue %s: %v", entry.Kind, err)
		}
	}

	wantPaths := []string{reportModelImportEndpoint, reportAuditEndpoint, reportResEndpoint}
	for i, want := range wantPaths {
		select {
		case got := <-arrivals:
			if got.path != want {
				t.Fatalf("arrival %d path = %s, want %s", i, got.path, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("arrival %d never reached %s", i, want)
		}
	}
	// The handler returning is not the same event as the ack: the worker still
	// has to seal the shortened queue. Poll instead of asserting immediately.
	deadline := time.Now().Add(3 * time.Second)
	for state.hasPendingReports() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if state.hasPendingReports() {
		t.Fatal("outbox still holds pending reports after delivery")
	}
}

func TestReportOutboxKeepsFIFO(t *testing.T) {
	var mu sync.Mutex
	var order []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		order = append(order, fmt.Sprint(body["taskId"]))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	state, _ := newOutboxTestState(t, server.Listener.Addr().String())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	outbox := state.startReportOutbox(ctx, 5*time.Millisecond, 20*time.Millisecond)
	defer outbox.Stop()

	for _, taskID := range []string{"task-1", "task-2", "task-3"} {
		if err := state.EnqueuePlatformReport(PendingReportSnapshot{
			Kind: ReportKindRes, RequestID: "req-" + taskID, TaskID: taskID,
		}); err != nil {
			t.Fatalf("enqueue %s: %v", taskID, err)
		}
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := append([]string(nil), order...)
		mu.Unlock()
		if len(got) == 3 {
			want := []string{"task-1", "task-2", "task-3"}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("delivery order = %v, want %v", got, want)
				}
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("not all reports were delivered")
}

func TestReportOutboxResumesAfterRestart(t *testing.T) {
	st, statePath := createTestStateStore(t)

	// First process: the platform is down, so the report can only stay in the
	// sealed state.
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer down.Close()

	first := NewTAAState("", down.Listener.Addr().String(), "docker-outbox", "", "", nil, nil, SecurityConfig{})
	first.SetStateStore(st)
	ctx1, cancel1 := context.WithCancel(context.Background())
	firstOutbox := first.startReportOutbox(ctx1, 5*time.Millisecond, 20*time.Millisecond)
	if err := first.EnqueuePlatformReport(PendingReportSnapshot{
		Kind: ReportKindRes, RequestID: "req-restart", TaskID: "task-restart", Report: `{"status":"succeeded"}`,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	persisted, err := st.UnsealState()
	if err != nil {
		t.Fatalf("unseal first store: %v", err)
	}
	if len(persisted.PendingReports) != 1 {
		t.Fatalf("pending report was not sealed before the restart: %+v", persisted.PendingReports)
	}
	firstOutbox.Stop()
	cancel1()

	// Second process: the platform is back, and the worker started from the
	// restored queue has to deliver what the previous process could not. Reusing
	// the same store is the restart: it re-reads the sealed file from disk.
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer up.Close()

	if _, err := st.DetectAndHandleKeyDrift(false); err != nil {
		t.Fatalf("load sealed state %s: %v", statePath, err)
	}
	second := NewTAAState("", up.Listener.Addr().String(), "docker-outbox", "", "", nil, nil, SecurityConfig{})
	second.SetStateStore(st)
	second.RestoreFromPersistentState(st.GetState())

	// The entry carries the platform identity captured when it was queued, so
	// the test repoints it at the recovered server the way an operator would
	// after the platform moves.
	second.mu.Lock()
	for i := range second.pendingReports {
		second.pendingReports[i].PlatformAddr = up.Listener.Addr().String()
	}
	second.mu.Unlock()

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	secondOutbox := second.startReportOutbox(ctx2, 5*time.Millisecond, 20*time.Millisecond)
	defer secondOutbox.Stop()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !second.hasPendingReports() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the report left by the previous process was never delivered")
}

func TestEnqueueRejectsMissingPlatformIdentity(t *testing.T) {
	state, _ := newOutboxTestState(t, "")
	err := state.EnqueuePlatformReport(PendingReportSnapshot{Kind: ReportKindRes, RequestID: "req-1", TaskID: "task-1"})
	if err == nil {
		t.Fatal("enqueue accepted a report with no platform address")
	}
	if state.hasPendingReports() {
		t.Fatal("a misconfigured report was queued")
	}
}
