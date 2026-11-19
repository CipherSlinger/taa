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
// platform envelope all go through this backend, so a broken HCT deployment
// must stop startup here rather than after keys were written with it.
//
// There is no fallback to the built-in backend. A configured hct that cannot
// start is a deployment error; silently running on gmsm would make the
// instance look healthy while doing something nobody asked for.
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

	if backend == teecrypto.BackendHCT && accel == teecrypto.HCTAccelCCP {
		if err := requireCCPDevice(); err != nil {
			return err
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
		return fmt.Errorf("select %s crypto backend: %w", backend, err)
	}

	if backend == teecrypto.BackendHCT {
		log.Printf("crypto backend: hct (libhct %s, accel=%s)", teecrypto.BackendVersion(), accel)
	} else {
		log.Printf("crypto backend: builtin")
	}
	return nil
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
