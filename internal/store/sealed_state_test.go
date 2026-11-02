package store_test

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"taa/internal/store"
	teecrypto "taa/pkg/crypto"
)

func TestStateStore_SealAndUnseal(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.sealed")
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i + 1)
	}

	st, err := store.NewStateStore(statePath, key, store.KeySourceSM2)
	if err != nil {
		t.Fatalf("new state store: %v", err)
	}

	state := &store.PersistentState{
		Version:         store.DefaultStateVersion,
		StateSeq:        1,
		IncarnationID:   "inc-001",
		CurrentPhase:    1,
		ModelImported:   true,
		TrainingRunning: false,
		UpdatedAt:       time.Now().UTC(),
	}

	if err := st.SealState(state); err != nil {
		t.Fatalf("seal state: %v", err)
	}

	recovered, err := st.UnsealState()
	if err != nil {
		t.Fatalf("unseal state: %v", err)
	}
	if recovered.StateSeq != 2 || recovered.IncarnationID != "inc-001" {
		t.Fatalf("state mismatch: got %+v", recovered)
	}
}

func TestStateStore_DeriveSealingKey(t *testing.T) {
	priv, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	key := store.DeriveSealingKey(priv)
	if len(key) != 16 {
		t.Fatalf("expected 16 bytes key, got %d", len(key))
	}
}

// AuditPending is the only record that survives a crash to say a model never got
// a security verdict, so its persistence is load-bearing rather than incidental.
// These two tests pin the two halves of that contract: a live audit round-trips
// intact, and an absent one leaves no key behind — the second matters because a
// state file written before this field existed must keep unsealing, and a reader
// that finds a zero-valued struct where there was no audit at all would
// quarantine every model imported by an older build.
func TestPersistentState_AuditPendingRoundTrips(t *testing.T) {
	started := time.Date(2026, 10, 9, 13, 0, 0, 0, time.UTC)
	state := &store.PersistentState{
		Version:       store.DefaultStateVersion,
		IncarnationID: "inc-audit",
		ModelImported: true,
		AuditPending: &store.AuditPendingSnapshot{
			RequestID: "req-audit-01",
			TaskID:    "task-audit-01",
			Phase:     1,
			StartedAt: started,
		},
		UpdatedAt: time.Now().UTC(),
	}

	st, err := store.NewStateStore(filepath.Join(t.TempDir(), "state.sealed"), testSealingKey(), store.KeySourceSM2)
	if err != nil {
		t.Fatalf("new state store: %v", err)
	}
	if err := st.SealState(state); err != nil {
		t.Fatalf("seal state: %v", err)
	}

	recovered, err := st.UnsealState()
	if err != nil {
		t.Fatalf("unseal state: %v", err)
	}
	if recovered.AuditPending == nil {
		t.Fatal("AuditPending did not survive the round trip; a crash mid-audit would be invisible on restart")
	}
	if recovered.AuditPending.RequestID != "req-audit-01" || recovered.AuditPending.TaskID != "task-audit-01" {
		t.Errorf("audit identifiers were not preserved: %+v", recovered.AuditPending)
	}
	if recovered.AuditPending.Phase != 1 {
		t.Errorf("audit phase was not preserved: %d", recovered.AuditPending.Phase)
	}
	if !recovered.AuditPending.StartedAt.Equal(started) {
		t.Errorf("audit start time was not preserved: got %s want %s", recovered.AuditPending.StartedAt, started)
	}
}

func TestPersistentState_NoAuditPendingOmitsTheKey(t *testing.T) {
	state := &store.PersistentState{
		Version:       store.DefaultStateVersion,
		IncarnationID: "inc-no-audit",
		ModelImported: true,
		AuditPending:  nil,
		UpdatedAt:     time.Now().UTC(),
	}

	// Asserted on the JSON rather than on the decoded struct: "no audit" and
	// "audit with empty fields" decode to different things, and only the wire
	// format distinguishes them for a reader of an old state file.
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	if strings.Contains(string(raw), "auditPending") {
		t.Errorf("a state with no audit in flight still carries an auditPending key: %s", raw)
	}
}

// A terminal platform report the platform never acknowledged has to survive a
// restart, or a long outage silently loses a task's final outcome. The wire
// format matters as much as the round trip: an unacknowledged report is a list,
// and a state file written before this field existed must keep unsealing.
func TestPersistentState_PendingReportsRoundTrip(t *testing.T) {
	created := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	state := &store.PersistentState{
		Version:       store.DefaultStateVersion,
		IncarnationID: "inc-outbox",
		UpdatedAt:     time.Now().UTC(),
		PendingReports: []store.PendingReportSnapshot{
			{
				ID:           "report-1",
				Kind:         store.ReportKindRes,
				RequestID:    "req-1",
				TaskID:       "task-1",
				Code:         1,
				Msg:          "failed",
				Report:       `{"status":"failed"}`,
				PlatformAddr: "127.0.0.1:18081",
				DockerID:     "docker-1",
				CreatedAt:    created,
			},
			{
				ID:           "report-2",
				Kind:         store.ReportKindModelImport,
				RequestID:    "req-2",
				TaskID:       "task-2",
				Code:         0,
				Checksum:     map[string]any{"value": "abc"},
				PlatformAddr: "127.0.0.1:18081",
				DockerID:     "docker-1",
				CreatedAt:    created,
			},
		},
	}

	st, err := store.NewStateStore(filepath.Join(t.TempDir(), "state.sealed"), testSealingKey(), store.KeySourceSM2)
	if err != nil {
		t.Fatalf("new state store: %v", err)
	}
	if err := st.SealState(state); err != nil {
		t.Fatalf("seal state: %v", err)
	}
	recovered, err := st.UnsealState()
	if err != nil {
		t.Fatalf("unseal state: %v", err)
	}

	if len(recovered.PendingReports) != 2 {
		t.Fatalf("pending reports lost across seal: %+v", recovered.PendingReports)
	}
	first := recovered.PendingReports[0]
	if first.ID != "report-1" || first.Kind != store.ReportKindRes || first.TaskID != "task-1" {
		t.Errorf("first pending report did not round-trip: %+v", first)
	}
	if !first.CreatedAt.Equal(created) {
		t.Errorf("createdAt = %v, want %v", first.CreatedAt, created)
	}
	if recovered.PendingReports[1].Checksum["value"] != "abc" {
		t.Errorf("checksum did not round-trip: %+v", recovered.PendingReports[1].Checksum)
	}
}

func testSealingKey() []byte {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}
