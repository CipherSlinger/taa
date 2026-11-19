package taa

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"taa/internal/config"
	teecrypto "taa/pkg/crypto"
)

// selectCryptoBackend is the startup gate in front of the crypto seam. These
// tests cover the paths that decide whether TAA starts at all: an unknown
// backend, the builtin default, and accel=ccp on a guest with no CCP device.
// The hct success path needs a real helper and lives in the differential test.

func cryptoConfig(backend, accel string) config.StartupConfig {
	return config.StartupConfig{
		Crypto: config.CryptoConfig{
			Backend: backend,
			HCT: config.HCTCryptoConfig{
				HelperPath: "/usr/local/bin/taa-hct-helper",
				LoaderPath: "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
				LibDir:     "/opt/hygon/hct/lib64",
				Accel:      accel,
			},
		},
	}
}

func TestSelectCryptoBackendBuiltin(t *testing.T) {
	t.Cleanup(func() { _ = teecrypto.CloseBackend() })

	if err := selectCryptoBackend(cryptoConfig("", "")); err != nil {
		t.Fatalf("selectCryptoBackend(builtin) error = %v", err)
	}
	if got := teecrypto.BackendName(); got != teecrypto.BackendBuiltin {
		t.Fatalf("BackendName() = %q, want %q", got, teecrypto.BackendBuiltin)
	}
}

func TestSelectCryptoBackendRejectsUnknown(t *testing.T) {
	t.Cleanup(func() { _ = teecrypto.CloseBackend() })

	err := selectCryptoBackend(cryptoConfig("tkm", ""))
	if err == nil {
		t.Fatal("expected an error for an unknown crypto backend")
	}
	if !strings.Contains(err.Error(), "tkm") {
		t.Fatalf("err = %v, want it to name the rejected backend", err)
	}
	if got := teecrypto.BackendName(); got != teecrypto.BackendBuiltin {
		t.Fatalf("BackendName() = %q, want the built-in backend to stay installed", got)
	}
}

// TestSelectCryptoBackendCCPWithoutDevice pins the refusal itself: on a CSV2
// guest there is no /dev/ccp*, and the check must fire before the helper is
// started, so the error names the device rather than a helper failure.
func TestSelectCryptoBackendCCPWithoutDevice(t *testing.T) {
	t.Cleanup(func() { _ = teecrypto.CloseBackend() })

	orig := ccpDeviceGlob
	ccpDeviceGlob = filepath.Join(t.TempDir(), "ccp*")
	t.Cleanup(func() { ccpDeviceGlob = orig })

	err := selectCryptoBackend(cryptoConfig(teecrypto.BackendHCT, teecrypto.HCTAccelCCP))
	if err == nil {
		t.Fatal("expected an error for accel=ccp with no CCP device")
	}
	if !strings.Contains(err.Error(), "/dev/ccp") {
		t.Fatalf("err = %v, want it to name the missing device", err)
	}
	if got := teecrypto.BackendName(); got != teecrypto.BackendBuiltin {
		t.Fatalf("BackendName() = %q, want no backend switch after a refusal", got)
	}
}

func TestRequireCCPDeviceAcceptsAnExistingDevice(t *testing.T) {
	orig := ccpDeviceGlob
	dir := t.TempDir()
	ccpDeviceGlob = filepath.Join(dir, "ccp*")
	t.Cleanup(func() { ccpDeviceGlob = orig })

	if err := requireCCPDevice(); err == nil {
		t.Fatal("expected an error before any device exists")
	}
	if err := os.WriteFile(filepath.Join(dir, "ccp0"), nil, 0o600); err != nil {
		t.Fatalf("create fake device node: %v", err)
	}
	if err := requireCCPDevice(); err != nil {
		t.Fatalf("requireCCPDevice() error = %v, want nil once a device exists", err)
	}
}
