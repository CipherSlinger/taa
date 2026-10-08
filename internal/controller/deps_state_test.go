package controller

import (
	"path/filepath"
	"testing"

	"taa/internal/store"
)

func TestSaveDepsSuccessPersistsHashAndChecksum(t *testing.T) {
	state, _ := setupTestState(t)

	checksum := map[string]any{"size": int64(1234), "algorithm": "sm3", "value": "abc"}
	state.saveDepsSuccess("abc", checksum)

	if !state.DepsImported {
		t.Fatal("DepsImported = false, want true")
	}
	if state.DepsHash != "abc" {
		t.Fatalf("DepsHash = %q, want abc", state.DepsHash)
	}
	if got := state.getDepsChecksum(); got["value"] != "abc" {
		t.Fatalf("checksum value = %v, want abc", got["value"])
	}
	if got := state.currentDepsDir(); got == "" {
		t.Fatal("currentDepsDir returned empty while deps imported")
	}
}

func TestClearDepsStateResetsEverything(t *testing.T) {
	state, _ := setupTestState(t)
	state.saveDepsSuccess("abc", map[string]any{"size": int64(1), "algorithm": "sm3", "value": "abc"})

	state.clearDepsState()

	if state.DepsImported {
		t.Fatal("DepsImported = true after clear")
	}
	if state.DepsHash != "" {
		t.Fatalf("DepsHash = %q after clear, want empty", state.DepsHash)
	}
	if got := state.currentDepsDir(); got != "" {
		t.Fatalf("currentDepsDir = %q after clear, want empty", got)
	}
}

func TestRestoreFromPersistentStateCarriesDeps(t *testing.T) {
	state, _ := setupTestState(t)

	state.RestoreFromPersistentState(&store.PersistentState{
		CurrentPhase: 1,
		DepsImported: true,
		DepsHash:     "deadbeef",
		DepsChecksum: map[string]any{"size": int64(9), "algorithm": "sm3", "value": "deadbeef"},
	})

	if !state.DepsImported || state.DepsHash != "deadbeef" {
		t.Fatalf("restore lost deps state: imported=%v hash=%q", state.DepsImported, state.DepsHash)
	}
	if got := state.getDepsChecksum(); got["value"] != "deadbeef" {
		t.Fatalf("restored checksum = %v, want deadbeef", got["value"])
	}
	wantDir := filepath.Join(state.Security.GetDepsDir(), "deadbeef")
	if got := state.currentDepsDir(); got != wantDir {
		t.Fatalf("currentDepsDir = %q, want %q", got, wantDir)
	}
}

// TestDepsStateSurvivesSealedRoundTrip drives the deps fields through a real sealed
// state store: save, read back from disk, and restore into a fresh in-memory state,
// which is what surviving a TAA restart actually means. Its value is that it fails
// loudly if sealStateLocked stops mirroring the deps fields onto PersistentState.
func TestDepsStateSurvivesSealedRoundTrip(t *testing.T) {
	state, _ := setupTestState(t)
	store, _ := createTestStateStore(t)
	state.SetStateStore(store)

	state.saveDepsSuccess("cafebabe", map[string]any{"size": int64(4321), "algorithm": "sm3", "value": "cafebabe"})

	diskState, err := store.UnsealState()
	if err != nil {
		t.Fatalf("unseal state failed: %v", err)
	}
	if !diskState.DepsImported || diskState.DepsHash != "cafebabe" {
		t.Fatalf("disk lost deps state: imported=%v hash=%q", diskState.DepsImported, diskState.DepsHash)
	}
	if got := diskState.DepsChecksum["value"]; got != "cafebabe" {
		t.Fatalf("disk checksum value = %v, want cafebabe", got)
	}

	// A restart rebuilds in-memory state from the sealed on-disk state.
	restarted, _ := setupTestState(t)
	restarted.SetStateStore(store)
	restarted.RestoreFromPersistentState(diskState)
	if !restarted.DepsImported || restarted.DepsHash != "cafebabe" {
		t.Fatalf("restart lost deps state: imported=%v hash=%q", restarted.DepsImported, restarted.DepsHash)
	}
	wantDir := restarted.depsDirForHash("cafebabe")
	if got := restarted.currentDepsDir(); got != wantDir {
		t.Fatalf("currentDepsDir after restart = %q, want %q", got, wantDir)
	}

	// A rollback must also reach disk, otherwise a stale hash would come back on restart.
	restarted.clearDepsState()
	diskState, err = store.UnsealState()
	if err != nil {
		t.Fatalf("unseal state after clear failed: %v", err)
	}
	if diskState.DepsImported || diskState.DepsHash != "" {
		t.Fatalf("disk kept deps state after clear: imported=%v hash=%q", diskState.DepsImported, diskState.DepsHash)
	}
}
