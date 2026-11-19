package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	teecrypto "github.com/CipherSlinger/teeaudit/pkg/crypto"
)

// The crypto block is a top-level section: every role performs SM2/SM3/SM4
// work (state sealing, the platform envelope, attestation), so the block must
// survive applyStartupConfigFile on an fhe or data-analysis instance too. These
// tests pin the defaults, the applied values and the rejection paths.

func TestLoadStartupConfigCryptoDefaults(t *testing.T) {
	t.Setenv("CONTRACT_TYPE", "")

	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}

	if cfg.Crypto.Backend != teecrypto.BackendBuiltin {
		t.Errorf("Crypto.Backend = %q, want %q", cfg.Crypto.Backend, teecrypto.BackendBuiltin)
	}
	hct := cfg.Crypto.HCT
	if hct.HelperPath != "/usr/local/bin/taa-hct-helper" ||
		hct.LoaderPath != "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" ||
		hct.LibDir != "/opt/hygon/hct/lib64" ||
		hct.Accel != teecrypto.HCTAccelSW ||
		hct.RequireVersion != teecrypto.HCTDefaultVersion {
		t.Errorf("Crypto.HCT defaults = %+v", hct)
	}
}

// TestLoadStartupConfigCryptoIsNotRoleGated is the point of putting the block
// at the top level: the same config must configure crypto on every role.
// Without it, moving the block under a role capability Set would keep the tee
// case green while silently ignoring an hct deployment on fhe.
func TestLoadStartupConfigCryptoIsNotRoleGated(t *testing.T) {
	roles := []string{ServerTypeTEE, ServerTypeFHE, ServerTypeDataAnalysis}
	for _, role := range roles {
		t.Run(role, func(t *testing.T) {
			t.Setenv("CONTRACT_TYPE", "")

			path := filepath.Join(t.TempDir(), DefaultFileName)
			// The fhe role requires its own section; the crypto block is the
			// subject here, so the fixture carries the minimum fhe shape.
			fhe := ""
			if role == ServerTypeFHE {
				fhe = `
				"fhe": {
					"endpoint": "http://127.0.0.1:58996",
					"dataDir": "/opt/fhe-data",
					"keyCacheDir": "/opt/fhe-data/keys"
				},`
			}
			writeTestConfig(t, path, `{
				"server": {"type": "`+role+`"},`+fhe+`
				"crypto": {
					"backend": "hct",
					"hct": {
						"helperPath": "/opt/test/taa-hct-helper",
						"loaderPath": "/opt/test/ld-linux-x86-64.so.2",
						"libDir": "/opt/test/lib64",
						"accel": "ccp",
						"requireVersion": "3.0.10"
					}
				}
			}`)

			cfg, err := LoadStartupConfig(path)
			if err != nil {
				t.Fatalf("LoadStartupConfig() error = %v", err)
			}

			if cfg.Crypto.Backend != teecrypto.BackendHCT {
				t.Errorf("Crypto.Backend = %q, want %q", cfg.Crypto.Backend, teecrypto.BackendHCT)
			}
			hct := cfg.Crypto.HCT
			if hct.HelperPath != "/opt/test/taa-hct-helper" ||
				hct.LoaderPath != "/opt/test/ld-linux-x86-64.so.2" ||
				hct.LibDir != "/opt/test/lib64" ||
				hct.Accel != teecrypto.HCTAccelCCP ||
				hct.RequireVersion != "3.0.10" {
				t.Errorf("Crypto.HCT = %+v, want the file's values", hct)
			}
		})
	}
}

func TestLoadStartupConfigCryptoNormalizesBackendAndAccel(t *testing.T) {
	t.Setenv("CONTRACT_TYPE", "")

	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{
		"crypto": {
			"backend": " HCT ",
			"hct": {"accel": " SW "}
		}
	}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}
	if cfg.Crypto.Backend != teecrypto.BackendHCT || cfg.Crypto.HCT.Accel != teecrypto.HCTAccelSW {
		t.Errorf("Crypto = %+v, want normalized hct/sw", cfg.Crypto)
	}
}

func TestLoadStartupConfigCryptoRejectsUnknownBackend(t *testing.T) {
	t.Setenv("CONTRACT_TYPE", "")

	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{"crypto": {"backend": "tkm"}}`)

	_, err := LoadStartupConfig(path)
	if err == nil {
		t.Fatal("expected an error for an unknown crypto backend")
	}
	if !strings.Contains(err.Error(), "crypto.backend") {
		t.Fatalf("err = %v, want it to name crypto.backend", err)
	}
}

func TestLoadStartupConfigCryptoRejectsUnknownAccel(t *testing.T) {
	t.Setenv("CONTRACT_TYPE", "")

	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{"crypto": {"backend": "hct", "hct": {"accel": "gpu"}}}`)

	_, err := LoadStartupConfig(path)
	if err == nil {
		t.Fatal("expected an error for an unknown HCT accel")
	}
	if !strings.Contains(err.Error(), "crypto.hct.accel") {
		t.Fatalf("err = %v, want it to name crypto.hct.accel", err)
	}
}

// An hct backend whose helper or library paths are relative cannot be started:
// the helper is spawned with an explicit loader, and relative paths would be
// resolved against whatever directory TAA happens to run in.
func TestLoadStartupConfigCryptoHCTRequiresAbsolutePaths(t *testing.T) {
	t.Setenv("CONTRACT_TYPE", "")

	cases := []struct {
		name string
		json string
		want string
	}{
		{
			name: "relative helper path",
			json: `{"crypto": {"backend": "hct", "hct": {"helperPath": "bin/taa-hct-helper"}}}`,
			want: "crypto.hct.helperPath",
		},
		{
			name: "relative loader path",
			json: `{"crypto": {"backend": "hct", "hct": {"loaderPath": "ld-linux.so.2"}}}`,
			want: "crypto.hct.loaderPath",
		},
		{
			name: "relative lib dir",
			json: `{"crypto": {"backend": "hct", "hct": {"libDir": "lib64"}}}`,
			want: "crypto.hct.libDir",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), DefaultFileName)
			writeTestConfig(t, path, tc.json)

			_, err := LoadStartupConfig(path)
			if err == nil {
				t.Fatal("expected an error for a non-absolute HCT path")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to name %s", err, tc.want)
			}
		})
	}
}

// The initrd build rewrites the crypto backend with a byte-level sed, which
// needs exactly one literal anchor. Two anchors would make the rewrite
// ambiguous, and a missing one would silently produce an initrd that claims
// hct while running builtin - so both are pinned here, before the packaging
// script relies on them.
func TestShippedTemplatesCarryOneCryptoAnchor(t *testing.T) {
	templates := []string{
		"../../configs/taa-production.json",
		"../../configs/taa-docker.json",
		"../../configs/taa-fhe.json",
	}
	anchor := []byte(`"backend": "builtin"`)
	for _, rel := range templates {
		t.Run(filepath.Base(rel), func(t *testing.T) {
			raw, err := os.ReadFile(rel)
			if err != nil {
				t.Fatalf("read %s: %v", rel, err)
			}
			if got := bytes.Count(raw, anchor); got != 1 {
				t.Fatalf("%s contains %d crypto anchors, want exactly 1", rel, got)
			}
			// TAA_HCT_ACCEL=ccp needs the same kind of anchor.
			if got := bytes.Count(raw, []byte(`"accel": "sw"`)); got != 1 {
				t.Fatalf("%s contains %d accel anchors, want exactly 1", rel, got)
			}
			if !bytes.Contains(raw, []byte(`"crypto": {`)) {
				t.Fatalf("%s has a backend value but no crypto block", rel)
			}

			cfg, err := LoadStartupConfig(rel)
			if err != nil {
				t.Fatalf("LoadStartupConfig(%s) error = %v", rel, err)
			}
			if cfg.Crypto.Backend != teecrypto.BackendBuiltin {
				t.Errorf("Crypto.Backend = %q, want %q", cfg.Crypto.Backend, teecrypto.BackendBuiltin)
			}
		})
	}
}
