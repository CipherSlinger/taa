package taa

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"taa/internal/config"
	"taa/internal/store"
	teecrypto "taa/pkg/crypto"
)

// startupKeyMaterial groups everything the startup flow derives from the TAA
// key pair and the CSV hardware key.
type startupKeyMaterial struct {
	keyPair      *taaKeyPair
	loaded       bool // the pair came from the keys directory
	recovered    bool // the pair came from TAASECRETKEY
	sealingKey   []byte
	keySource    store.KeySource
	taaSecretKey string // empty means the register request omits it
}

// resolveStartupKeyMaterial resolves the SM2 key pair, the state sealing key
// and the taaSecretKey reported to the platform.
//
// The CSV hardware key is fetched at most once per startup and never falls
// back: both the state sealing key (csv-hw) and the taaSecretKey derivation
// consume the same bytes.
func resolveStartupKeyMaterial(
	keysDir, source, contract, secretEnv string,
	fetch hardwareSealingKeyFetcher,
) (*startupKeyMaterial, error) {
	var hwKey []byte
	if source == config.StateSealingKeySourceCSVHW {
		var err error
		hwKey, err = fetchStartupHardwareKey(fetch)
		if err != nil {
			return nil, err
		}
	}
	defer clear(hwKey)

	var (
		keyPair   *taaKeyPair
		loaded    bool
		recovered bool
	)

	if secretEnv = strings.TrimSpace(secretEnv); secretEnv != "" {
		if len(hwKey) == 0 {
			return nil, fmt.Errorf("%s requires storage.stateSealingKeySource=%q; non-CSV instances cannot recover a TAA key pair",
				taaSecretKeyEnv, config.StateSealingKeySourceCSVHW)
		}
		priv, err := openTAASecretKey(hwKey, contract, secretEnv)
		if err != nil {
			return nil, fmt.Errorf("recover TAA SM2 key pair from %s: %w", taaSecretKeyEnv, err)
		}
		keyPair, err = persistRecoveredTAAKeyPair(keysDir, priv)
		if err != nil {
			return nil, fmt.Errorf("persist recovered TAA SM2 key pair: %w", err)
		}
		recovered = true
	} else {
		var err error
		keyPair, loaded, err = loadOrGenerateTAAKeyPair(keysDir)
		if err != nil {
			return nil, fmt.Errorf("initialize TAA SM2 key pair: %w", err)
		}
	}

	sealingKey, keySource, err := resolveStateSealingKey(source, keyPair.PrivateKey, hwKey)
	if err != nil {
		return nil, err
	}

	material := &startupKeyMaterial{
		keyPair:    keyPair,
		loaded:     loaded,
		recovered:  recovered,
		sealingKey: sealingKey,
		keySource:  keySource,
	}

	switch {
	case keySource == store.KeySourceCSVHW && !recovered:
		material.taaSecretKey, err = sealTAASecretKey(hwKey, contract, keyPair.PrivateKey)
		if err != nil {
			clear(sealingKey)
			return nil, err
		}
	case keySource == store.KeySourceSM2:
		log.Printf("non-CSV instance: %s is not reported", taaSecretKeyEnv)
	}

	return material, nil
}

// persistRecoveredTAAKeyPair stores a key pair recovered from TAASECRETKEY.
//
// The environment variable takes precedence over the on-disk files: a
// different or unreadable existing pair is archived as *.bak.<unix> instead of
// aborting, because the operator explicitly supplied the key. When the files
// already hold the recovered pair they are reused unchanged, so keeping the
// variable set across restarts does not rewrite or archive anything.
func persistRecoveredTAAKeyPair(keysDir string, priv *teecrypto.SM2PrivateKey) (*taaKeyPair, error) {
	cleanDir := normalizeKeysDir(keysDir)
	privPath := filepath.Join(cleanDir, defaultSM2PrivateKeyFile)
	pubPath := filepath.Join(cleanDir, defaultSM2PublicKeyFile)

	if existing, ok := matchingKeyPairOnDisk(privPath, pubPath, priv); ok {
		if err := ensureKeyPermissions(privPath, cleanDir); err != nil {
			return nil, err
		}
		log.Printf("%s matches the persisted TAA SM2 key pair in %s", taaSecretKeyEnv, cleanDir)
		return existing, nil
	}

	if err := os.MkdirAll(cleanDir, 0o700); err != nil {
		return nil, fmt.Errorf("create keys dir %s: %w", cleanDir, err)
	}

	stamp := time.Now().Unix()
	for _, path := range []string{privPath, pubPath} {
		_, err := os.Stat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("stat key file %s: %w", path, err)
		}
		backup := fmt.Sprintf("%s.bak.%d", path, stamp)
		if err := os.Rename(path, backup); err != nil {
			return nil, fmt.Errorf("archive key file %s to %s: %w", path, backup, err)
		}
		log.Printf("WARNING: archived key file %s to %s (%s takes precedence)", path, backup, taaSecretKeyEnv)
	}

	pubPEM, err := teecrypto.MarshalSM2PublicKeyPEM(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal recovered public key: %w", err)
	}
	privPEM, err := teecrypto.MarshalSM2PrivateKeyPEM(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal recovered private key: %w", err)
	}

	if err := writeKeyFileAtomic(privPath, privPEM, 0o600); err != nil {
		return nil, fmt.Errorf("persist recovered private key to %s: %w", privPath, err)
	}
	if err := writeKeyFileAtomic(pubPath, pubPEM, 0o644); err != nil {
		return nil, fmt.Errorf("persist recovered public key to %s: %w", pubPath, err)
	}

	log.Printf("recovered and persisted TAA SM2 key pair from %s to %s", taaSecretKeyEnv, cleanDir)
	return &taaKeyPair{PrivateKey: priv, PublicKeyPEM: string(pubPEM)}, nil
}

// matchingKeyPairOnDisk reports whether both key files exist, parse, and hold
// exactly the recovered key pair. Any read or parse failure returns false: the
// caller then archives whatever is there and rewrites it.
func matchingKeyPairOnDisk(privPath, pubPath string, want *teecrypto.SM2PrivateKey) (*taaKeyPair, bool) {
	privData, err := os.ReadFile(privPath)
	if err != nil {
		return nil, false
	}
	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, false
	}

	diskPriv, err := teecrypto.ParseSM2PrivateKeyPEM(privData)
	if err != nil {
		return nil, false
	}
	diskPub, err := teecrypto.ParseSM2PublicKeyPEM(pubData)
	if err != nil {
		return nil, false
	}

	if diskPriv.D.Cmp(want.D) != 0 ||
		diskPub.X.Cmp(want.PublicKey.X) != 0 ||
		diskPub.Y.Cmp(want.PublicKey.Y) != 0 {
		return nil, false
	}

	return &taaKeyPair{PrivateKey: want, PublicKeyPEM: string(pubData)}, true
}
