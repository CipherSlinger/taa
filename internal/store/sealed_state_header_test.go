package store_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"taa/internal/store"
	teecrypto "taa/pkg/crypto"
)

func writeLegacyState(t *testing.T, path, key string) {
	t.Helper()
	keyBytes := []byte(key)
	ciphertext, err := teecrypto.Encrypt(keyBytes, []byte(`{"version":"1.4","currentPhase":3}`))
	if err != nil {
		t.Fatalf("encrypt legacy state: %v", err)
	}
	if err := os.WriteFile(path, ciphertext, 0o600); err != nil {
		t.Fatalf("write legacy state: %v", err)
	}
}

func assertHeader(t *testing.T, path string, wantSource byte) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if len(raw) < 8 {
		t.Fatalf("state file is shorter than the header: %d bytes", len(raw))
	}
	if string(raw[0:4]) != "TAAS" {
		t.Fatalf("unexpected magic: %q", raw[0:4])
	}
	if raw[4] != 1 {
		t.Fatalf("unexpected format version: %d", raw[4])
	}
	if raw[5] != wantSource {
		t.Fatalf("unexpected key source byte: got %d want %d", raw[5], wantSource)
	}
	if raw[6] != 0 || raw[7] != 0 {
		t.Fatalf("reserved bytes are not zero: %v", raw[6:8])
	}
}

func TestStateStore_HeaderRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source store.KeySource
		byteV  byte
	}{
		{"sm2", store.KeySourceSM2, 1},
		{"csv-hw", store.KeySourceCSVHW, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			statePath := filepath.Join(t.TempDir(), "state.sealed")
			st, err := store.NewStateStore(statePath, []byte("0123456789abcdef"), tc.source)
			if err != nil {
				t.Fatalf("new store: %v", err)
			}

			state := store.NewCleanPersistentState()
			state.CurrentPhase = 3
			if err := st.SealState(state); err != nil {
				t.Fatalf("seal: %v", err)
			}

			assertHeader(t, statePath, tc.byteV)

			restored, err := st.UnsealState()
			if err != nil {
				t.Fatalf("unseal: %v", err)
			}
			if restored.CurrentPhase != 3 {
				t.Fatalf("phase did not survive: %d", restored.CurrentPhase)
			}
		})
	}
}

func TestStateStore_LegacyFileWithoutHeaderReadsAsSM2(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.sealed")
	writeLegacyState(t, statePath, "0123456789abcdef")

	st, err := store.NewStateStore(statePath, []byte("0123456789abcdef"), store.KeySourceSM2)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	restored, err := st.UnsealState()
	if err != nil {
		t.Fatalf("unseal legacy state: %v", err)
	}
	if restored.CurrentPhase != 3 {
		t.Fatalf("legacy state did not survive: phase %d", restored.CurrentPhase)
	}
}

func TestStateStore_SourceMismatchIsTypedError(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.sealed")
	writeLegacyState(t, statePath, "0123456789abcdef")

	st, err := store.NewStateStore(statePath, []byte("0123456789abcdef"), store.KeySourceCSVHW)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if _, err := st.UnsealState(); !errors.Is(err, store.ErrKeySourceMismatch) {
		t.Fatalf("expected ErrKeySourceMismatch, got %v", err)
	}
}

func TestStateStore_DetectAndHandleKeyDrift_ArchivesLegacyFileForCSVHW(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.sealed")
	writeLegacyState(t, statePath, "0123456789abcdef")

	st, err := store.NewStateStore(statePath, []byte("0123456789abcdef"), store.KeySourceCSVHW)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	drifted, err := st.DetectAndHandleKeyDrift(false)
	if err != nil {
		t.Fatalf("drift handling: %v", err)
	}
	if !drifted {
		t.Fatal("expected the legacy file to be archived")
	}
	orphans, err := filepath.Glob(filepath.Join(dir, ".orphaned.*"))
	if err != nil {
		t.Fatalf("glob orphans: %v", err)
	}
	if len(orphans) != 1 {
		t.Fatalf("expected one orphaned file, got %d", len(orphans))
	}
	assertHeader(t, statePath, 2)

	state := st.GetState()
	if state == nil || state.CurrentPhase != 1 {
		t.Fatalf("expected a clean state in phase 1, got %+v", state)
	}
}

func TestStateStore_DetectAndHandleKeyDrift_ArchivesCSVHWFileForSM2(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.sealed")

	hwStore, err := store.NewStateStore(statePath, []byte("0123456789abcdef"), store.KeySourceCSVHW)
	if err != nil {
		t.Fatalf("new hw store: %v", err)
	}
	if err := hwStore.SealState(store.NewCleanPersistentState()); err != nil {
		t.Fatalf("seal with hw source: %v", err)
	}

	sm2Store, err := store.NewStateStore(statePath, []byte("0123456789abcdef"), store.KeySourceSM2)
	if err != nil {
		t.Fatalf("new sm2 store: %v", err)
	}
	drifted, err := sm2Store.DetectAndHandleKeyDrift(false)
	if err != nil {
		t.Fatalf("drift handling: %v", err)
	}
	if !drifted {
		t.Fatal("expected the csv-hw file to be archived")
	}
	assertHeader(t, statePath, 1)
}

func TestStateStore_DetectAndHandleKeyDrift_SameSourceTamperFailsClosed(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.sealed")

	st, err := store.NewStateStore(statePath, []byte("0123456789abcdef"), store.KeySourceCSVHW)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := st.SealState(store.NewCleanPersistentState()); err != nil {
		t.Fatalf("seal: %v", err)
	}

	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	raw[len(raw)-1] ^= 0xff
	if err := os.WriteFile(statePath, raw, 0o600); err != nil {
		t.Fatalf("tamper state: %v", err)
	}

	if _, err := st.DetectAndHandleKeyDrift(false); err == nil {
		t.Fatal("expected fail-closed on same-source tamper")
	} else if !bytes.Contains([]byte(err.Error()), []byte("fail-closed")) {
		t.Fatalf("expected a fail-closed error, got %v", err)
	}
	orphans, err := filepath.Glob(filepath.Join(dir, ".orphaned.*"))
	if err != nil {
		t.Fatalf("glob orphans: %v", err)
	}
	if len(orphans) != 0 {
		t.Fatalf("tampered same-source state must not be archived, found %v", orphans)
	}
}

func TestStateStore_RejectsUnknownKeySource(t *testing.T) {
	if _, err := store.NewStateStore(filepath.Join(t.TempDir(), "state.sealed"), []byte("0123456789abcdef"), store.KeySource("bogus")); err == nil {
		t.Fatal("expected an unknown key source to be rejected")
	}
}
