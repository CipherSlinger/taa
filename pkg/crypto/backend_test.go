package crypto

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// SelectBackend is the one seam between TAA and the crypto implementation.
// These tests pin the fail-closed rule: a backend that cannot start must leave
// the previous one installed and report the error, so startup can refuse to
// continue instead of silently running on gmsm.

// withFakeHCT replaces the HCT constructor for one test and restores the real
// one (and the built-in backend) afterwards.
func withFakeHCT(t *testing.T, fn func(HCTConfig) (Backend, func() error, error)) {
	t.Helper()
	orig := newHCTBackend
	newHCTBackend = fn
	t.Cleanup(func() {
		newHCTBackend = orig
		if err := CloseBackend(); err != nil {
			t.Errorf("CloseBackend: %v", err)
		}
	})
}

func TestSelectBackendEmptyMeansBuiltin(t *testing.T) {
	if err := SelectBackend(BackendConfig{}); err != nil {
		t.Fatalf("SelectBackend(empty) error = %v", err)
	}
	if got := BackendName(); got != BackendBuiltin {
		t.Fatalf("BackendName() = %q, want %q", got, BackendBuiltin)
	}
}

func TestSelectBackendRejectsUnknownName(t *testing.T) {
	err := SelectBackend(BackendConfig{Backend: "tkm"})
	if err == nil {
		t.Fatal("expected an error for an unknown backend")
	}
	if !strings.Contains(err.Error(), "tkm") {
		t.Fatalf("err = %v, want it to name the rejected backend", err)
	}
	if got := BackendName(); got != BackendBuiltin {
		t.Fatalf("BackendName() = %q, want the previous backend to stay installed", got)
	}
}

// TestSelectBackendHCTFailureIsFailClosed stands in for every way the HCT
// constructor can fail (helper missing, version mismatch, KAT failure): the
// caller sees the error and the built-in backend is still the active one.
func TestSelectBackendHCTFailureIsFailClosed(t *testing.T) {
	withFakeHCT(t, func(HCTConfig) (Backend, func() error, error) {
		return nil, nil, errors.New("HCT 启动自检失败")
	})

	err := SelectBackend(BackendConfig{Backend: BackendHCT})
	if err == nil {
		t.Fatal("expected an error when the HCT backend cannot start")
	}
	if !strings.Contains(err.Error(), "HCT") {
		t.Fatalf("err = %v, want it to name the HCT backend", err)
	}
	if got := BackendName(); got != BackendBuiltin {
		t.Fatalf("BackendName() = %q, want %q after a failed selection", got, BackendBuiltin)
	}

	// The package-level helpers must still work on the surviving backend.
	if SM3Sum([]byte("abc")) != SM3Sum([]byte("abc")) {
		t.Fatal("SM3Sum is not deterministic after a failed selection")
	}
}

func TestSelectBackendHCTInstallsAndCloses(t *testing.T) {
	closed := 0
	withFakeHCT(t, func(HCTConfig) (Backend, func() error, error) {
		return builtinBackend{}, func() error {
			closed++
			return nil
		}, nil
	})

	if err := SelectBackend(BackendConfig{Backend: BackendHCT}); err != nil {
		t.Fatalf("SelectBackend(hct) error = %v", err)
	}
	if got := BackendName(); got != BackendHCT {
		t.Fatalf("BackendName() = %q, want %q", got, BackendHCT)
	}

	if err := CloseBackend(); err != nil {
		t.Fatalf("CloseBackend() error = %v", err)
	}
	if closed != 1 {
		t.Fatalf("close fn called %d times, want 1", closed)
	}
	if got := BackendName(); got != BackendBuiltin {
		t.Fatalf("BackendName() = %q after CloseBackend, want %q", got, BackendBuiltin)
	}
}

// A configured hct backend whose helper does not exist must fail at openHCT
// time, not at the first cryptographic operation.
func TestOpenHCTBackendRejectsMissingHelper(t *testing.T) {
	_, _, err := openHCTBackend(HCTConfig{
		HelperPath: filepath.Join(t.TempDir(), "missing-taa-hct-helper"),
		Accel:      HCTAccelSW,
	})
	if err == nil {
		t.Fatal("expected an error for a missing helper")
	}
}
