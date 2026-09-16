package store_test

import (
	"path/filepath"
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

	st, err := store.NewStateStore(statePath, key)
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
