package mock

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	teecrypto "github.com/CipherSlinger/teeaudit/pkg/crypto"
)

// The workbench reproduces TAA's ciphertext ingress instead of handing the audit
// pipeline a plaintext archive. An upload is sealed to an SM2 public key this
// process generated for itself, and the audit runner opens the envelope with the
// matching private key right before extraction, so the workbench runs exactly
// the two-part decryption TAA runs on an import: unwrap the SM4 data key with
// SM2, then decrypt the body with that key.
//
// The wire shape is the one the platform delivers over a download URL, which is
// the shape a real import takes today:
//
//	body            [SM4FileVersion][nonce(12)][ciphertext][tag(16)]
//	dataKeyCipher   hex of the SM2 envelope over the 16-byte SM4 key (C1C3C2,
//	                with the 0x04 uncompressed-point prefix stripped)
//
// Keeping the data key out of the body is what makes the file area hold nothing
// but ciphertext while a repeat run still has everything it needs to open it.
const (
	// workbenchKeyFile is the persisted pair. It lives next to the file-area
	// entries because it exists to open them: a reset that deletes the archives
	// makes the key useless, and keeping the two together means a restart can
	// still decrypt every stored upload.
	workbenchKeyFile = "workbench-key.json"

	// workbenchSealMaxBytes bounds what an upload may encrypt. Sealing happens in
	// memory on both sides (the AEAD API offers no streaming), so the ceiling is
	// a memory guard for a development tool, not a protocol limit.
	workbenchSealMaxBytes = 512 << 20
)

// errWorkbenchKeysUnavailable reports a key pair that could not be created or
// loaded. Without it nothing can be sealed or opened, so submissions are refused
// rather than silently falling back to plaintext.
var errWorkbenchKeysUnavailable = errors.New("工作台 SM2 密钥对不可用")

// workbenchKeyState is the on-disk form of the pair.
type workbenchKeyState struct {
	PrivateKeyPEM string `json:"privateKeyPem"`
	PublicKeyHex  string `json:"publicKeyHex"`
}

// workbenchKeys is the workbench's own SM2 pair: generated locally on first use,
// persisted, and never exchanged with anything. The public half is only ever
// used by this process, which is what makes the workbench self-contained.
type workbenchKeys struct {
	path string

	mu   sync.RWMutex
	priv *teecrypto.SM2PrivateKey
	pub  *teecrypto.SM2PublicKey
}

// newWorkbenchKeys loads the pair from dir, generating it when the file is
// absent. A file that exists but cannot be parsed is replaced: unlike the
// platform pair, nothing outside this process has sealed anything to it, so
// regenerating costs at most the unreadable file-area entries that reference it.
func newWorkbenchKeys(dir string) *workbenchKeys {
	k := &workbenchKeys{path: filepath.Join(dir, workbenchKeyFile)}
	if err := k.load(); err != nil {
		log.Printf("workbench SM2 key load failed, generating a new one: %v", err)
		if err := k.generate(); err != nil {
			log.Printf("workbench SM2 key generation failed: %v", err)
			return k
		}
	}
	return k
}

func (k *workbenchKeys) load() error {
	data, err := os.ReadFile(k.path)
	if err != nil {
		return err
	}
	var state workbenchKeyState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}
	priv, err := teecrypto.ParseSM2PrivateKeyPEM([]byte(state.PrivateKeyPEM))
	if err != nil {
		return err
	}
	k.mu.Lock()
	k.priv = priv
	k.pub = &priv.PublicKey
	k.mu.Unlock()
	log.Printf("workbench SM2 key loaded from %s (%s)", k.path, k.fingerprint())
	return nil
}

func (k *workbenchKeys) generate() error {
	priv, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		return err
	}
	publicHex, err := teecrypto.MarshalSM2PublicKeyHex(&priv.PublicKey)
	if err != nil {
		return err
	}
	privatePEM, err := teecrypto.MarshalSM2PrivateKeyPEM(priv)
	if err != nil {
		return err
	}
	data, err := json.Marshal(workbenchKeyState{
		PrivateKeyPEM: string(privatePEM),
		PublicKeyHex:  publicHex,
	})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(k.path), 0o755); err != nil {
		return err
	}
	tmp := k.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, k.path); err != nil {
		return err
	}
	k.mu.Lock()
	k.priv = priv
	k.pub = &priv.PublicKey
	k.mu.Unlock()
	log.Printf("workbench SM2 key generated at %s (%s)", k.path, k.fingerprint())
	return nil
}

// ready reports whether the pair is usable.
func (k *workbenchKeys) ready() bool {
	if k == nil {
		return false
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.priv != nil && k.pub != nil
}

// fingerprint is an SM3 digest of the public key, truncated for display. The
// operator sees it in the console so a run's envelope can be tied to the pair
// that opened it, without the page ever carrying key material.
func (k *workbenchKeys) fingerprint() string {
	if !k.ready() {
		return ""
	}
	publicHex, err := teecrypto.MarshalSM2PublicKeyHex(k.pub)
	if err != nil {
		return ""
	}
	sum := teecrypto.SM3Sum([]byte(publicHex))
	return strings.ToUpper(hex.EncodeToString(sum[:8]))
}

// seal encrypts an archive and returns the ciphertext body and the hex envelope
// over its data key.
func (k *workbenchKeys) seal(plaintext []byte) ([]byte, string, error) {
	if !k.ready() {
		return nil, "", errWorkbenchKeysUnavailable
	}
	if len(plaintext) > workbenchSealMaxBytes {
		return nil, "", fmt.Errorf("打开文件过大：%d MiB，工作台加密上限为 %d MiB",
			len(plaintext)>>20, workbenchSealMaxBytes>>20)
	}
	env, err := teecrypto.SealSM2(k.pub, plaintext)
	if err != nil {
		return nil, "", fmt.Errorf("SM2+SM4-GCM 加密失败: %w", err)
	}
	// Mirror the platform's body layout byte for byte: a one-byte format version
	// in front of the nonce. TAA accepts both layouts, and delivering the
	// platform's means the workbench exercises the layout a real import carries.
	body := make([]byte, 0, len(env.Ciphertext)+1)
	body = append(body, teecrypto.SM4FileVersion)
	body = append(body, env.Ciphertext...)
	// The 112-byte C1C3C2 form is what the platform puts on the URL; the leading
	// 0x04 point prefix is restored by ParseWrappedDataKeyHex on the way back.
	return body, hex.EncodeToString(env.WrappedKey[1:]), nil
}

// open decrypts a body with the envelope over its data key. It is a line-for-line
// copy of TAA's decryptCiphertextWithDataKey: try the bare layout first, then the
// versioned one, and let the GCM tag decide between them.
func (k *workbenchKeys) open(body []byte, dataKeyCipher string) ([]byte, error) {
	if !k.ready() {
		return nil, errWorkbenchKeysUnavailable
	}
	if len(body) == 0 {
		return nil, errors.New("密文为空")
	}
	wrapped, err := teecrypto.ParseWrappedDataKeyHex(strings.TrimSpace(dataKeyCipher))
	if err != nil {
		return nil, err
	}
	dataKey, err := teecrypto.UnwrapKeySM2(k.priv, wrapped)
	if err != nil {
		return nil, err
	}
	plaintext, err := teecrypto.Decrypt(dataKey, body)
	if err != nil && body[0] == teecrypto.SM4FileVersion {
		// Reading a versioned body as the bare layout folds the version byte into
		// the nonce and every tag check fails. The first byte alone cannot settle
		// the layout (a random nonce starts with 0x01 one time in 256), so the
		// bare layout is tried first and the versioned one only after it fails.
		plaintext, err = teecrypto.Decrypt(dataKey, body[1:])
	}
	return plaintext, err
}

// openFile decrypts srcPath into dstPath. The ciphertext is read whole because
// the AEAD API has no streaming mode; callers bound the size at seal time.
func (k *workbenchKeys) openFile(srcPath, dstPath, dataKeyCipher string) (int64, error) {
	body, err := os.ReadFile(srcPath)
	if err != nil {
		return 0, fmt.Errorf("读取密文文件: %w", err)
	}
	plaintext, err := k.open(body, dataKeyCipher)
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(dstPath, plaintext, 0o600); err != nil {
		return 0, fmt.Errorf("写入解封后的明文: %w", err)
	}
	return int64(len(plaintext)), nil
}
