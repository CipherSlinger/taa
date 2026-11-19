package taa

import (
	"fmt"
	"log"
	"path/filepath"
	"strings"

	"taa/internal/config"
	teecrypto "taa/pkg/crypto"
)

// selectCryptoBackend installs the configured SM2/SM3/SM4 backend. It runs
// before any key material exists: key generation, state sealing and the
// platform envelope all go through this backend.
//
// HCT is preferred when configured, but a helper that cannot start does not
// take TAA down. The deployment contract is availability: the original gmsm
// software implementation takes over, and the log states both why HCT was
// dropped and which interface is now doing the work. An unknown backend name
// is still a configuration error — that is a typo, not an availability
// problem — and is refused.
func selectCryptoBackend(cfg config.StartupConfig) error {
	c := cfg.Crypto
	backend := strings.ToLower(strings.TrimSpace(c.Backend))
	if backend == "" {
		backend = teecrypto.BackendBuiltin
	}
	accel := strings.ToLower(strings.TrimSpace(c.HCT.Accel))
	if accel == "" {
		accel = teecrypto.HCTAccelSW
	}

	switch backend {
	case teecrypto.BackendBuiltin:
		return selectBuiltinCryptoBackend()
	case teecrypto.BackendHCT:
		// keep going
	default:
		return fmt.Errorf("teecrypto: 未知的密码后端 %q (支持 %q、%q)",
			backend, teecrypto.BackendBuiltin, teecrypto.BackendHCT)
	}

	if accel == teecrypto.HCTAccelCCP {
		if err := requireCCPDevice(); err != nil {
			return fallbackToBuiltinCryptoBackend(err)
		}
	}

	err := teecrypto.SelectBackend(teecrypto.BackendConfig{
		Backend: backend,
		HCT: teecrypto.HCTConfig{
			HelperPath:     c.HCT.HelperPath,
			LoaderPath:     c.HCT.LoaderPath,
			LibDir:         c.HCT.LibDir,
			Accel:          accel,
			RequireVersion: c.HCT.RequireVersion,
		},
	})
	if err != nil {
		return fallbackToBuiltinCryptoBackend(err)
	}

	log.Printf("crypto backend: hct (Hygon HCT interface; libhct %s, accel=%s)",
		teecrypto.BackendVersion(), accel)
	return nil
}

// selectBuiltinCryptoBackend installs the pure-Go gmsm implementation. Its log
// line is the operator's answer to "which crypto interface is in use": the
// software one.
func selectBuiltinCryptoBackend() error {
	err := teecrypto.SelectBackend(teecrypto.BackendConfig{Backend: teecrypto.BackendBuiltin})
	if err != nil {
		return fmt.Errorf("select builtin crypto backend: %w", err)
	}
	log.Printf("crypto backend: builtin (original software implementation, gmsm)")
	return nil
}

// fallbackToBuiltinCryptoBackend keeps TAA serving on the software
// implementation after HCT could not be installed.
func fallbackToBuiltinCryptoBackend(reason error) error {
	log.Printf("crypto backend: HCT unavailable (%v); falling back to the original software implementation (gmsm)", reason)
	return selectBuiltinCryptoBackend()
}

// ccpDeviceGlob is the device pattern requireCCPDevice looks for. It is a
// variable so tests can exercise both outcomes on a machine with no CCP.
var ccpDeviceGlob = "/dev/ccp*"

// requireCCPDevice refuses accel=ccp when no CCP character device exists. The
// CSV2 guests TAA runs in do not expose one; without this check the failure
// would only surface on the first cryptographic operation.
func requireCCPDevice() error {
	matches, err := filepath.Glob(ccpDeviceGlob)
	if err != nil {
		return fmt.Errorf("check CCP device: %w", err)
	}
	if len(matches) == 0 {
		return fmt.Errorf("crypto.hct.accel=ccp requires a /dev/ccp* device, but none exists")
	}
	return nil
}
