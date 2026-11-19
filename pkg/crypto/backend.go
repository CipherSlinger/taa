package crypto

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
)

// Backend names accepted by SelectBackend.
const (
	BackendBuiltin = "builtin"
	BackendHCT     = "hct"
)

// HCT acceleration backends accepted in HCTConfig.Accel.
const (
	HCTAccelSW  = "sw"
	HCTAccelCCP = "ccp"
)

// HCTDefaultVersion is the libhct release TAA is built and tested against.
// The helper is allowed to report a longer version string (for example
// "hct-3.0.10-2601d03-"); RequireVersion is matched as a prefix.
const HCTDefaultVersion = "3.0.10"

// HCTConfig describes how to reach the HCT helper process.
type HCTConfig struct {
	// HelperPath is the absolute path of the taa-hct-helper executable.
	HelperPath string
	// LoaderPath is the absolute path of the dynamic loader used to start the
	// helper with an explicit library search path.
	LoaderPath string
	// LibDir is the directory containing libhct.so.
	LibDir string
	// Accel selects the HCT backend: "sw" (software, CIS/AVX) or "ccp".
	Accel string
	// RequireVersion is the libhct version prefix the helper must report.
	RequireVersion string
}

// BackendConfig is the crypto section of the runtime configuration.
type BackendConfig struct {
	Backend string
	HCT     HCTConfig
}

// SM3Stream computes an SM3 digest incrementally. Write may be called with any
// chunk size; Sum finalises the digest and Close releases backend resources.
type SM3Stream interface {
	io.Writer
	Sum() ([sm3Size]byte, error)
	Close() error
}

// GCM mirrors the subset of crypto/cipher.AEAD TAA uses, so the existing
// nonce||ciphertext||tag layout code is shared by every backend. Unlike AEAD,
// Seal reports backend failures: returning a partial ciphertext would be
// indistinguishable from success at the caller.
type GCM interface {
	NonceSize() int
	Overhead() int
	Seal(dst, nonce, plaintext, aad []byte) ([]byte, error)
	Open(dst, nonce, ciphertext, aad []byte) ([]byte, error)
}

// Backend performs the cryptographic operations TAA delegates. Implementations
// must be safe for concurrent use.
type Backend interface {
	Name() string
	GenerateSM2KeyPair() (*SM2PrivateKey, error)
	EncryptSM2(pub *SM2PublicKey, plaintext []byte) ([]byte, error)
	DecryptSM2(priv *SM2PrivateKey, ciphertext []byte) ([]byte, error)
	SignSM2(priv *SM2PrivateKey, userID, msg []byte) (*big.Int, *big.Int, error)
	VerifySM2(pub *SM2PublicKey, userID, msg []byte, r, s *big.Int) bool
	SM3Sum(data []byte) ([sm3Size]byte, error)
	HMACSM3(key, data []byte) ([sm3Size]byte, error)
	NewSM3Stream() (SM3Stream, error)
	NewGCM(key []byte) (GCM, error)
}

type backendState struct {
	backend Backend
	closeFn func() error
	name    string
}

// ErrBackendUnavailable reports that the selected backend can no longer serve
// requests because its helper process died or a request timed out. Operations
// that return it have not changed any output, so the fallback backend replays
// them on the built-in implementation.
var ErrBackendUnavailable = errors.New("teecrypto: 密码后端不可用")

var (
	backendMu sync.Mutex
	active    atomic.Pointer[backendState]
)

// newHCTBackend is installed by backend_hct.go. Keeping it as a variable lets
// the package (and its tests) build without pulling in the helper client.
var newHCTBackend = func(HCTConfig) (Backend, func() error, error) {
	return nil, nil, errors.New("HCT 后端未编译进本二进制")
}

func init() {
	active.Store(&backendState{backend: builtinBackend{}, name: BackendBuiltin})
}

// SelectBackend installs the configured backend. An empty name selects the
// built-in one. Selecting HCT starts the helper, performs the handshake and
// runs the known-answer tests; any failure is returned and the previous
// backend stays installed, so the caller can refuse to start.
func SelectBackend(cfg BackendConfig) error {
	name := strings.ToLower(strings.TrimSpace(cfg.Backend))
	if name == "" {
		name = BackendBuiltin
	}

	backendMu.Lock()
	defer backendMu.Unlock()

	switch name {
	case BackendBuiltin:
		prev := active.Swap(&backendState{backend: builtinBackend{}, name: BackendBuiltin})
		if prev != nil && prev.closeFn != nil {
			return prev.closeFn()
		}
		return nil
	case BackendHCT:
		b, closeFn, err := newHCTBackend(cfg.HCT)
		if err != nil {
			return fmt.Errorf("teecrypto: HCT 后端初始化失败: %w", err)
		}
		// The helper is a separate process and can die at any time. Wrap it so
		// that an unavailable helper degrades to the built-in implementation
		// instead of taking TAA down or panicking in SM3Sum.
		wrapped := newFallbackBackend(b, closeFn)
		prev := active.Swap(&backendState{backend: wrapped, closeFn: closeFn, name: BackendHCT})
		if prev != nil && prev.closeFn != nil {
			_ = prev.closeFn()
		}
		return nil
	default:
		return fmt.Errorf("teecrypto: 未知的密码后端 %q (支持 %q、%q)",
			cfg.Backend, BackendBuiltin, BackendHCT)
	}
}

// backendChecker is implemented by backends that can be probed after startup.
type backendChecker interface {
	Check(context.Context) error
}

// backendVersioner is implemented by backends that can report the version of
// the library they run on (the HCT helper's libhct string).
type backendVersioner interface {
	Version() string
}

// BackendVersion reports the active backend's library version, or "" when the
// backend has none to report.
func BackendVersion() string {
	if v, ok := currentBackend().(backendVersioner); ok {
		return v.Version()
	}
	return ""
}

// CheckBackend re-probes the active backend. A built-in backend never fails.
func CheckBackend(ctx context.Context) error {
	if checker, ok := currentBackend().(backendChecker); ok {
		return checker.Check(ctx)
	}
	return nil
}

// CloseBackend releases the active backend and restores the built-in one.
func CloseBackend() error {
	backendMu.Lock()
	defer backendMu.Unlock()
	prev := active.Swap(&backendState{backend: builtinBackend{}, name: BackendBuiltin})
	if prev != nil && prev.closeFn != nil {
		return prev.closeFn()
	}
	return nil
}

// BackendName reports the active backend name ("builtin" or "hct").
func BackendName() string {
	return active.Load().name
}

func currentBackend() Backend {
	return active.Load().backend
}

// ─── Package-level delegation ────────────────────────────────────────

// SM3SumChecked computes the SM3 digest of data and reports backend failures
// instead of returning a zero digest that could be mistaken for a real one.
func SM3SumChecked(data []byte) ([sm3Size]byte, error) {
	return currentBackend().SM3Sum(data)
}

// HMACSM3Checked computes HMAC-SM3 and reports backend failures.
func HMACSM3Checked(key, data []byte) ([sm3Size]byte, error) {
	return currentBackend().HMACSM3(key, data)
}

// SM3Sum computes the SM3 digest of data. A backend failure panics: callers in
// the state-sealing and attestation paths cannot continue without a digest,
// and a zero digest there would be accepted as a real one.
func SM3Sum(data []byte) [sm3Size]byte {
	sum, err := SM3SumChecked(data)
	if err != nil {
		panic(fmt.Sprintf("teecrypto: SM3 摘要失败: %v", err))
	}
	return sum
}

// HMACSM3 computes HMAC-SM3. A backend failure panics for the same reason as
// SM3Sum: an all-zero MAC must never reach a comparison.
func HMACSM3(key, data []byte) [sm3Size]byte {
	sum, err := HMACSM3Checked(key, data)
	if err != nil {
		panic(fmt.Sprintf("teecrypto: HMAC-SM3 失败: %v", err))
	}
	return sum
}

// NewSM3Stream starts a streaming SM3 digest on the active backend.
func NewSM3Stream() (SM3Stream, error) {
	return currentBackend().NewSM3Stream()
}

func newGCM(key []byte) (GCM, error) {
	if len(key) != SM4KeySize {
		return nil, ErrInvalidKeySize
	}
	return currentBackend().NewGCM(key)
}
