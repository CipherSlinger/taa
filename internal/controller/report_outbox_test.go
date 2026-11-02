package controller

import (
	"path/filepath"
	"testing"
	"time"
)

// newOutboxTestState builds a state bound to a real sealed store, which is what
// the outbox needs: the queue is the sealed state, not an in-memory list.
func newOutboxTestState(t *testing.T, platformAddr string) (*TAAState, *StateStore) {
	t.Helper()
	dir := t.TempDir()
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i + 1)
	}
	st, err := NewStateStore(filepath.Join(dir, "state.sealed"), key, KeySourceSM2)
	if err != nil {
		t.Fatalf("new state store: %v", err)
	}
	state := NewTAAState(filepath.Join(dir, "attestation.report"), platformAddr, "docker-outbox", "", "", nil, nil, SecurityConfig{})
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