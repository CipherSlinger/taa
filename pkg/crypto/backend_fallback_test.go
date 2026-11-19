package crypto

import (
	"bytes"
	"context"
	"errors"
	"log"
	"math/big"
	"strings"
	"testing"
)

// fakeHCTBackend forces availability failures without spawning a helper. Its
// "available" path delegates to the built-in implementation so tests can assert
// that the fallback produces the same bytes the software implementation does.
type fakeHCTBackend struct {
	unavailable   bool
	failWith      error  // a non-availability error to return instead
	streamFailsAt string // "init" or "write" for NewSM3Stream
	gcmPatch      bool   // make Seal/Open return ErrBackendUnavailable
}

func (f *fakeHCTBackend) fail() error {
	if f.failWith != nil {
		return f.failWith
	}
	if f.unavailable {
		return ErrBackendUnavailable
	}
	return nil
}

func (f *fakeHCTBackend) Name() string    { return BackendHCT }
func (f *fakeHCTBackend) Version() string { return "fake-3.0.10" }

func (f *fakeHCTBackend) Check(context.Context) error { return f.fail() }

func (f *fakeHCTBackend) GenerateSM2KeyPair() (*SM2PrivateKey, error) {
	if err := f.fail(); err != nil {
		return nil, err
	}
	return builtinBackend{}.GenerateSM2KeyPair()
}

func (f *fakeHCTBackend) EncryptSM2(pub *SM2PublicKey, plaintext []byte) ([]byte, error) {
	if err := f.fail(); err != nil {
		return nil, err
	}
	return builtinBackend{}.EncryptSM2(pub, plaintext)
}

func (f *fakeHCTBackend) DecryptSM2(priv *SM2PrivateKey, ciphertext []byte) ([]byte, error) {
	if err := f.fail(); err != nil {
		return nil, err
	}
	return builtinBackend{}.DecryptSM2(priv, ciphertext)
}

func (f *fakeHCTBackend) SignSM2(priv *SM2PrivateKey, userID, msg []byte) (*big.Int, *big.Int, error) {
	if err := f.fail(); err != nil {
		return nil, nil, err
	}
	return builtinBackend{}.SignSM2(priv, userID, msg)
}

func (f *fakeHCTBackend) VerifySM2(pub *SM2PublicKey, userID, msg []byte, r, s *big.Int) bool {
	if f.fail() != nil {
		return false
	}
	return builtinBackend{}.VerifySM2(pub, userID, msg, r, s)
}

func (f *fakeHCTBackend) SM3Sum(data []byte) ([sm3Size]byte, error) {
	var zero [sm3Size]byte
	if err := f.fail(); err != nil {
		return zero, err
	}
	return builtinBackend{}.SM3Sum(data)
}

func (f *fakeHCTBackend) HMACSM3(key, data []byte) ([sm3Size]byte, error) {
	var zero [sm3Size]byte
	if err := f.fail(); err != nil {
		return zero, err
	}
	return builtinBackend{}.HMACSM3(key, data)
}

func (f *fakeHCTBackend) NewSM3Stream() (SM3Stream, error) {
	if f.fail() != nil && f.streamFailsAt != "write" {
		return nil, f.fail()
	}
	if f.streamFailsAt == "write" {
		return failingStream{}, nil
	}
	return builtinBackend{}.NewSM3Stream()
}

func (f *fakeHCTBackend) NewGCM(key []byte) (GCM, error) {
	if err := f.fail(); err != nil {
		return nil, err
	}
	if f.gcmPatch {
		return failingGCM{key: append([]byte(nil), key...)}, nil
	}
	return builtinBackend{}.NewGCM(key)
}

// failingStream dies on its first write, like a helper that disappears
// mid-file.
type failingStream struct{}

func (failingStream) Write([]byte) (int, error)   { return 0, ErrBackendUnavailable }
func (failingStream) Sum() ([sm3Size]byte, error) { return [sm3Size]byte{}, ErrBackendUnavailable }
func (failingStream) Close() error                { return nil }

// failingGCM reports availability failure from both Seal and Open without
// touching dst, matching the real HCT object's all-or-nothing output.
type failingGCM struct{ key []byte }

func (failingGCM) NonceSize() int { return 12 }
func (failingGCM) Overhead() int  { return 16 }
func (failingGCM) Seal([]byte, []byte, []byte, []byte) ([]byte, error) {
	return nil, ErrBackendUnavailable
}
func (failingGCM) Open([]byte, []byte, []byte, []byte) ([]byte, error) {
	return nil, ErrBackendUnavailable
}

// installFakeHCT selects a fake HCT backend through the real SelectBackend
// path, including the fallback wrapper.
func installFakeHCT(t *testing.T, fake Backend) {
	t.Helper()
	orig := newHCTBackend
	newHCTBackend = func(HCTConfig) (Backend, func() error, error) {
		return fake, func() error { return nil }, nil
	}
	t.Cleanup(func() {
		newHCTBackend = orig
		_ = CloseBackend()
	})
	if err := SelectBackend(BackendConfig{Backend: BackendHCT}); err != nil {
		t.Fatalf("SelectBackend(hct) error = %v", err)
	}
}

// TestFallbackReplaysStatelessOperation pins the main contract: a helper that
// is gone does not fail the operation, it moves it to the software
// implementation and stays there.
func TestFallbackReplaysStatelessOperation(t *testing.T) {
	var buf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(origOut) })

	installFakeHCT(t, &fakeHCTBackend{unavailable: true})

	sum, err := SM3SumChecked([]byte("abc"))
	if err != nil {
		t.Fatalf("SM3SumChecked() error = %v, want the built-in result", err)
	}
	want, _ := builtinBackend{}.SM3Sum([]byte("abc"))
	if sum != want {
		t.Fatalf("SM3SumChecked() = %x, want %x", sum, want)
	}
	if got := BackendName(); got != BackendBuiltin {
		t.Fatalf("BackendName() = %q, want %q after degradation", got, BackendBuiltin)
	}
	if !strings.Contains(buf.String(), "degraded from hct to builtin") {
		t.Fatalf("log = %q, want the degradation to name the interface now in use", buf.String())
	}
}

func TestFallbackReplaysSM2AndGCM(t *testing.T) {
	installFakeHCT(t, &fakeHCTBackend{unavailable: true})

	priv, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair() error = %v", err)
	}
	ct, err := EncryptSM2(&priv.PublicKey, []byte("hello"))
	if err != nil {
		t.Fatalf("EncryptSM2() error = %v", err)
	}
	pt, err := DecryptSM2(priv, ct)
	if err != nil || !bytes.Equal(pt, []byte("hello")) {
		t.Fatalf("DecryptSM2() = %q, %v", pt, err)
	}
	r, s, err := SignSM2Signature(priv, nil, []byte("msg"))
	if err != nil {
		t.Fatalf("SignSM2Signature() error = %v", err)
	}
	if !VerifySM2Signature(&priv.PublicKey, nil, []byte("msg"), r, s) {
		t.Fatal("VerifySM2Signature() = false, want true")
	}

	key := bytes.Repeat([]byte{7}, SM4KeySize)
	g, err := newGCM(key)
	if err != nil {
		t.Fatalf("newGCM() error = %v", err)
	}
	nonce := bytes.Repeat([]byte{1}, 12)
	sealed, err := g.Seal(nil, nonce, []byte("payload"), nil)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	ref, _ := builtinBackend{}.NewGCM(key)
	wantSealed, _ := ref.Seal(nil, nonce, []byte("payload"), nil)
	if !bytes.Equal(sealed, wantSealed) {
		t.Fatalf("Seal() = %x, want %x", sealed, wantSealed)
	}
	opened, err := g.Open(nil, nonce, sealed, nil)
	if err != nil || !bytes.Equal(opened, []byte("payload")) {
		t.Fatalf("Open() = %q, %v", opened, err)
	}
}

// TestFallbackReplaysVerify probes the boolean-only path separately: a dead
// helper must not turn a valid signature into "rejected".
func TestFallbackReplaysVerify(t *testing.T) {
	priv, err := builtinBackend{}.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair() error = %v", err)
	}
	r, s, err := builtinBackend{}.SignSM2(priv, nil, []byte("msg"))
	if err != nil {
		t.Fatalf("SignSM2() error = %v", err)
	}

	installFakeHCT(t, &fakeHCTBackend{unavailable: true})
	if !VerifySM2Signature(&priv.PublicKey, nil, []byte("msg"), r, s) {
		t.Fatal("VerifySM2Signature() = false, want the built-in verification")
	}
	if got := BackendName(); got != BackendBuiltin {
		t.Fatalf("BackendName() = %q, want %q", got, BackendBuiltin)
	}
}

// TestFallbackStreamDegradesWithoutReplay documents the one operation that
// cannot be replayed: bytes already consumed by the helper are gone, so the
// stream fails, but the process moves to the software implementation.
func TestFallbackStreamDegradesWithoutReplay(t *testing.T) {
	installFakeHCT(t, &fakeHCTBackend{streamFailsAt: "write"})

	st, err := NewSM3Stream()
	if err != nil {
		t.Fatalf("NewSM3Stream() error = %v", err)
	}
	if _, err := st.Write([]byte("abc")); err == nil {
		t.Fatal("Write() = nil, want the stream to fail on the dead helper")
	}
	if got := BackendName(); got != BackendBuiltin {
		t.Fatalf("BackendName() = %q, want %q", got, BackendBuiltin)
	}
	if _, err := SM3SumChecked([]byte("abc")); err != nil {
		t.Fatalf("next SM3SumChecked() error = %v, want the built-in backend", err)
	}
}

func TestFallbackGCMReplaysWholeOperation(t *testing.T) {
	installFakeHCT(t, &fakeHCTBackend{gcmPatch: true})

	key := bytes.Repeat([]byte{9}, SM4KeySize)
	g, err := newGCM(key)
	if err != nil {
		t.Fatalf("newGCM() error = %v", err)
	}
	nonce := bytes.Repeat([]byte{2}, 12)
	sealed, err := g.Seal(nil, nonce, []byte("payload"), []byte("aad"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	opened, err := g.Open(nil, nonce, sealed, []byte("aad"))
	if err != nil || !bytes.Equal(opened, []byte("payload")) {
		t.Fatalf("Open() = %q, %v", opened, err)
	}
	if got := BackendName(); got != BackendBuiltin {
		t.Fatalf("BackendName() = %q, want %q", got, BackendBuiltin)
	}
}

// TestFallbackLeavesCryptoErrorsAlone is the fail-closed side: a rejected tag
// or a malformed response is a result, not an availability failure, and must
// never be retried on another implementation.
func TestFallbackLeavesCryptoErrorsAlone(t *testing.T) {
	cryptoErr := errors.New("tag mismatch")
	installFakeHCT(t, &fakeHCTBackend{failWith: cryptoErr})

	if _, err := SM3SumChecked([]byte("abc")); !errors.Is(err, cryptoErr) {
		t.Fatalf("SM3SumChecked() error = %v, want %v", err, cryptoErr)
	}
	if got := BackendName(); got != BackendHCT {
		t.Fatalf("BackendName() = %q, want %q after a crypto error", got, BackendHCT)
	}
}

// TestCheckBackendDegrades keeps the post-device-wait probe from turning a
// dead helper into a startup failure.
func TestCheckBackendDegrades(t *testing.T) {
	installFakeHCT(t, &fakeHCTBackend{unavailable: true})
	if err := CheckBackend(context.Background()); err != nil {
		t.Fatalf("CheckBackend() error = %v, want the fallback to absorb it", err)
	}
	if got := BackendName(); got != BackendBuiltin {
		t.Fatalf("BackendName() = %q, want %q", got, BackendBuiltin)
	}
}
