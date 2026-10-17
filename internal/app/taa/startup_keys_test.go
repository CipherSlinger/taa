package taa

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"taa/internal/config"
	"taa/internal/store"
	teecrypto "taa/pkg/crypto"
)

func fetchTestHardwareKey(buf []byte) error {
	copy(buf, testHardwareKey())
	return nil
}

func TestResolveStartupKeyMaterial_SM2WithoutSecret(t *testing.T) {
	keysDir := t.TempDir()

	material, err := resolveStartupKeyMaterial(keysDir, config.StateSealingKeySourceSM2, "contract", "", nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if material.loaded || material.recovered {
		t.Fatalf("loaded=%v recovered=%v, want a freshly generated pair", material.loaded, material.recovered)
	}
	if material.taaSecretKey != "" {
		t.Fatalf("taaSecretKey = %q, want empty on an sm2 instance", material.taaSecretKey)
	}
	if material.keySource != store.KeySourceSM2 {
		t.Fatalf("source = %q, want %q", material.keySource, store.KeySourceSM2)
	}
	if want := store.DeriveSealingKey(material.keyPair.PrivateKey); !bytes.Equal(material.sealingKey, want) {
		t.Fatal("sealing key does not match the legacy derivation")
	}
	for _, name := range []string{defaultSM2PrivateKeyFile, defaultSM2PublicKeyFile} {
		if _, err := os.Stat(filepath.Join(keysDir, name)); err != nil {
			t.Fatalf("key file %s was not persisted: %v", name, err)
		}
	}
}

func TestResolveStartupKeyMaterial_CSVHWExportsSecret(t *testing.T) {
	keysDir := t.TempDir()

	material, err := resolveStartupKeyMaterial(keysDir, config.StateSealingKeySourceCSVHW, "contract", "", fetchTestHardwareKey)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if material.recovered {
		t.Fatal("a fresh startup must not be marked as recovered")
	}
	if material.keySource != store.KeySourceCSVHW {
		t.Fatalf("source = %q, want %q", material.keySource, store.KeySourceCSVHW)
	}
	if len(material.taaSecretKey) != 120 {
		t.Fatalf("taaSecretKey has %d hex chars, want 120", len(material.taaSecretKey))
	}

	recovered, err := openTAASecretKey(testHardwareKey(), "contract", material.taaSecretKey)
	if err != nil {
		t.Fatalf("open reported taaSecretKey: %v", err)
	}
	if recovered.D.Cmp(material.keyPair.PrivateKey.D) != 0 {
		t.Fatal("taaSecretKey does not wrap the instance private key")
	}
}

func TestResolveStartupKeyMaterial_RecoversAndArchivesConflictingFiles(t *testing.T) {
	keysDir := t.TempDir()
	wantPriv, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate SM2 key: %v", err)
	}
	secret, err := sealTAASecretKey(testHardwareKey(), "contract", wantPriv)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	// Seed a different pair so recovery has to archive it.
	oldPriv, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate old SM2 key: %v", err)
	}
	oldPrivPEM, err := teecrypto.MarshalSM2PrivateKeyPEM(oldPriv)
	if err != nil {
		t.Fatalf("marshal old private key: %v", err)
	}
	oldPubPEM, err := teecrypto.MarshalSM2PublicKeyPEM(&oldPriv.PublicKey)
	if err != nil {
		t.Fatalf("marshal old public key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, defaultSM2PrivateKeyFile), oldPrivPEM, 0o600); err != nil {
		t.Fatalf("write old private key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, defaultSM2PublicKeyFile), oldPubPEM, 0o644); err != nil {
		t.Fatalf("write old public key: %v", err)
	}

	material, err := resolveStartupKeyMaterial(keysDir, config.StateSealingKeySourceCSVHW, "contract", secret, fetchTestHardwareKey)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !material.recovered {
		t.Fatal("the pair must be marked as recovered")
	}
	if material.taaSecretKey != "" {
		t.Fatalf("taaSecretKey = %q, want empty after recovery", material.taaSecretKey)
	}
	if material.keyPair.PrivateKey.D.Cmp(wantPriv.D) != 0 {
		t.Fatal("recovered scalar differs from the sealed one")
	}
	if material.keyPair.PrivateKey.PublicKey.X.Cmp(wantPriv.PublicKey.X) != 0 ||
		material.keyPair.PrivateKey.PublicKey.Y.Cmp(wantPriv.PublicKey.Y) != 0 {
		t.Fatal("recovered public key differs from the sealed one")
	}

	backups, err := filepath.Glob(filepath.Join(keysDir, "*.bak.*"))
	if err != nil {
		t.Fatalf("glob backups: %v", err)
	}
	if len(backups) != 2 {
		t.Fatalf("archived %d key files, want 2: %v", len(backups), backups)
	}

	// Keeping TAASECRETKEY set across restarts must be idempotent.
	again, err := resolveStartupKeyMaterial(keysDir, config.StateSealingKeySourceCSVHW, "contract", secret, fetchTestHardwareKey)
	if err != nil {
		t.Fatalf("resolve again: %v", err)
	}
	if !again.recovered {
		t.Fatal("the second startup must also be marked as recovered")
	}
	backupsAgain, err := filepath.Glob(filepath.Join(keysDir, "*.bak.*"))
	if err != nil {
		t.Fatalf("glob backups: %v", err)
	}
	if len(backupsAgain) != len(backups) {
		t.Fatalf("recovery archived key files again: %d -> %d", len(backups), len(backupsAgain))
	}
}

func TestResolveStartupKeyMaterial_RecoveryFailures(t *testing.T) {
	goodPriv, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate SM2 key: %v", err)
	}
	secret, err := sealTAASecretKey(testHardwareKey(), "contract", goodPriv)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	t.Run("non-CSV instance cannot recover", func(t *testing.T) {
		_, err := resolveStartupKeyMaterial(t.TempDir(), config.StateSealingKeySourceSM2, "contract", secret, nil)
		if err == nil || !strings.Contains(err.Error(), "TAASECRETKEY requires") {
			t.Fatalf("error = %v, want a clear non-CSV rejection", err)
		}
	})

	t.Run("wrong contract", func(t *testing.T) {
		_, err := resolveStartupKeyMaterial(t.TempDir(), config.StateSealingKeySourceCSVHW, "other-contract", secret, fetchTestHardwareKey)
		if err == nil {
			t.Fatal("expected decryption to fail with a different contract")
		}
	})

	t.Run("hardware fetch failure is fatal", func(t *testing.T) {
		_, err := resolveStartupKeyMaterial(t.TempDir(), config.StateSealingKeySourceCSVHW, "contract", "",
			func([]byte) error { return errors.New("open /dev/csv-guest: no such file") })
		if err == nil {
			t.Fatal("expected the fetch failure to abort startup")
		}
	})

	t.Run("malformed secret", func(t *testing.T) {
		_, err := resolveStartupKeyMaterial(t.TempDir(), config.StateSealingKeySourceCSVHW, "contract", "not-hex", fetchTestHardwareKey)
		if err == nil {
			t.Fatal("expected malformed TAASECRETKEY to abort startup")
		}
	})
}
