package coordinator

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"taa/internal/store"
	teecrypto "taa/pkg/crypto"
	pkgerrors "taa/pkg/errors"
)

func setupTestStore(t *testing.T) (*store.StateStore, string) {
	t.Helper()
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.sealed")
	privKey, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate SM2 key pair failed: %v", err)
	}
	sealingKey := store.DeriveSealingKey(privKey)
	st, err := store.NewStateStore(statePath, sealingKey)
	if err != nil {
		t.Fatalf("NewStateStore failed: %v", err)
	}
	return st, dir
}

func TestTaskManagerExclusiveLocking(t *testing.T) {
	tm := NewTaskManager()

	token1, err := tm.AcquireTaskLock("req-1", "task-1", "model_import", 1)
	if err != nil {
		t.Fatalf("AcquireTaskLock 1 failed: %v", err)
	}
	if token1 == 0 {
		t.Fatal("expected non-zero token")
	}

	// Second acquire while lock held must fail with Conflict
	_, err = tm.AcquireTaskLock("req-2", "task-2", "train", 2)
	if err == nil {
		t.Fatal("expected conflict error, got nil")
	}
	if pkgerrors.CodeOf(err, 0) != pkgerrors.CodeConflict {
		t.Fatalf("expected CodeConflict, got %v", pkgerrors.CodeOf(err, 0))
	}

	// Release first lock
	tm.ReleaseTaskLock(token1)

	// Now second lock should succeed
	token2, err := tm.AcquireTaskLock("req-2", "task-2", "train", 2)
	if err != nil {
		t.Fatalf("AcquireTaskLock 2 failed: %v", err)
	}
	if token2 == 0 {
		t.Fatal("expected non-zero token2")
	}
	tm.ReleaseTaskLock(token2)
}

func TestPhaseStateTransitionsAndSealing(t *testing.T) {
	st, _ := setupTestStore(t)
	ps := NewPhaseState(st)

	if ps.CurrentPhase() != 1 {
		t.Fatalf("initial phase = %d, want 1", ps.CurrentPhase())
	}
	if ps.IsModelImported() {
		t.Fatal("initial model imported should be false")
	}

	// Transition phase
	if err := ps.SetPhase(2); err != nil {
		t.Fatalf("SetPhase(2) failed: %v", err)
	}
	if ps.CurrentPhase() != 2 {
		t.Fatalf("phase = %d, want 2", ps.CurrentPhase())
	}

	// Mark model imported and save URL
	ps.SetModelImported(true, "http://example.com/model.enc")
	if !ps.IsModelImported() {
		t.Fatal("expected model imported = true")
	}
	if ps.SavedModelURL() != "http://example.com/model.enc" {
		t.Fatalf("unexpected saved model URL: %s", ps.SavedModelURL())
	}

	// Verify persistence in store
	persisted, err := st.UnsealState()
	if err != nil {
		t.Fatalf("UnsealState failed: %v", err)
	}
	if persisted.CurrentPhase != 2 || !persisted.ModelImported {
		t.Fatalf("persisted mismatch: phase=%d, modelImported=%v", persisted.CurrentPhase, persisted.ModelImported)
	}
}

func TestCoordinatorStopTraining(t *testing.T) {
	tm := NewTaskManager()
	control := tm.EnsureTrainingControl()
	if control == nil {
		t.Fatal("expected non-nil training control")
	}
	if control.IsCancelled() {
		t.Fatal("training control should not be cancelled initially")
	}

	stopped := tm.StopTraining()
	if !stopped {
		t.Fatal("expected StopTraining = true")
	}
	if !control.IsCancelled() {
		t.Fatal("training control should be cancelled after StopTraining")
	}

	// Idempotent stop
	stoppedSecond := tm.StopTraining()
	if stoppedSecond {
		t.Fatal("expected second StopTraining = false")
	}
}

func TestCrashRecoveryCircuitBreaker(t *testing.T) {
	st, _ := setupTestStore(t)
	ps := NewPhaseState(st)
	tm := NewTaskManager()

	// Setup an active task that exceeded recovery attempts
	task := &store.ActiveTaskSnapshot{
		TaskID:           "task-cb-1",
		RequestID:        "req-cb-1",
		Type:             "training",
		Phase:            2,
		RecoveryAttempts: 3,
		StartedAt:        time.Now().UTC(),
	}
	_ = st.SealState(&store.PersistentState{
		CurrentPhase: 2,
		ActiveTask:   task,
	})

	sec := SecurityConfig{
		ModelDir:  t.TempDir(),
		DataDir:   t.TempDir(),
		ResultDir: t.TempDir(),
	}

	c := NewCoordinator(CoordinatorParams{
		StateStore:  st,
		PhaseState:  ps,
		TaskManager: tm,
		Security:    sec,
	})

	err := c.ReconcileRecovery(context.Background())
	if err != nil {
		t.Fatalf("ReconcileRecovery failed: %v", err)
	}

	// Verify active task was cleared from store
	unsealed, err := st.UnsealState()
	if err != nil {
		t.Fatalf("UnsealState failed: %v", err)
	}
	if unsealed.ActiveTask != nil {
		t.Fatalf("expected ActiveTask to be cleared after circuit breaker, got %+v", unsealed.ActiveTask)
	}
}
