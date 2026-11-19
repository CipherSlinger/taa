package crypto

import (
	"context"
	"errors"
	"log"
	"math/big"
	"time"
)

// fallbackBackend keeps the HCT implementation in front and the built-in one
// behind it.
//
// The HCT helper is a separate process, so it can die (or stop answering) long
// after startup, including in the middle of a task. The deployment contract is
// that TAA keeps working on the original software implementation rather than
// refusing to serve, but never silently: every fallback is logged together with
// the interface now in use, so an operator can tell from the log whether the
// HCT interface or the gmsm software implementation is doing the work.
//
// Stateless operations are replayed on the built-in backend because their
// inputs are still in hand and no output has escaped. Streams cannot be
// replayed — the bytes already consumed by the helper are gone — so a stream
// that dies fails its own operation after triggering the degradation; the next
// operation runs on the built-in implementation.
type fallbackBackend struct {
	hct     Backend
	closeFn func() error
}

func newFallbackBackend(hct Backend, closeFn func() error) *fallbackBackend {
	return &fallbackBackend{hct: hct, closeFn: closeFn}
}

func (b *fallbackBackend) Name() string { return BackendHCT }

// Version reports the libhct version of the helper underneath.
func (b *fallbackBackend) Version() string {
	if v, ok := b.hct.(backendVersioner); ok {
		return v.Version()
	}
	return ""
}

// Accel reports the acceleration mode of the helper underneath. The wrapper is
// the active backend, so without this forwarding the startup log would fall back
// to the configured mode instead of the one the helper actually selected.
func (b *fallbackBackend) Accel() string {
	if v, ok := b.hct.(backendAccelReporter); ok {
		return v.Accel()
	}
	return ""
}

// Engines reports the per-operation engine map of the helper underneath.
func (b *fallbackBackend) Engines() string {
	if v, ok := b.hct.(backendEngineReporter); ok {
		return v.Engines()
	}
	return ""
}

// Check re-probes the helper. A failure degrades to the built-in backend and
// reports success, because the built-in backend is always usable.
func (b *fallbackBackend) Check(ctx context.Context) error {
	checker, ok := b.hct.(backendChecker)
	if !ok {
		return nil
	}
	if err := checker.Check(ctx); err != nil {
		b.degrade(err)
	}
	return nil
}

// degrade installs the built-in backend once, if the HCT backend is still the
// active one, and releases the helper. A crypto failure (for example a rejected
// authentication tag) is not an availability failure and must not degrade.
func (b *fallbackBackend) degrade(reason error) {
	backendMu.Lock()
	cur := active.Load()
	if cur == nil || cur.backend != Backend(b) {
		backendMu.Unlock()
		return
	}
	active.Store(&backendState{backend: builtinBackend{}, name: BackendBuiltin})
	closeFn := cur.closeFn
	backendMu.Unlock()

	log.Printf("crypto backend: degraded from hct to builtin (original software implementation, gmsm): %v", reason)
	if closeFn != nil {
		_ = closeFn()
	}
}

// noteUnavailable degrades when err means the helper is gone.
func (b *fallbackBackend) noteUnavailable(err error) {
	if errors.Is(err, ErrBackendUnavailable) {
		b.degrade(err)
	}
}

// ─── SM2 ────────────────────────────────────────────────────────────

func (b *fallbackBackend) GenerateSM2KeyPair() (*SM2PrivateKey, error) {
	priv, err := b.hct.GenerateSM2KeyPair()
	if err == nil {
		return priv, nil
	}
	if !errors.Is(err, ErrBackendUnavailable) {
		return nil, err
	}
	b.degrade(err)
	return builtinBackend{}.GenerateSM2KeyPair()
}

func (b *fallbackBackend) EncryptSM2(pub *SM2PublicKey, plaintext []byte) ([]byte, error) {
	out, err := b.hct.EncryptSM2(pub, plaintext)
	if err == nil {
		return out, nil
	}
	if !errors.Is(err, ErrBackendUnavailable) {
		return nil, err
	}
	b.degrade(err)
	return builtinBackend{}.EncryptSM2(pub, plaintext)
}

func (b *fallbackBackend) DecryptSM2(priv *SM2PrivateKey, ciphertext []byte) ([]byte, error) {
	out, err := b.hct.DecryptSM2(priv, ciphertext)
	if err == nil {
		return out, nil
	}
	if !errors.Is(err, ErrBackendUnavailable) {
		return nil, err
	}
	b.degrade(err)
	return builtinBackend{}.DecryptSM2(priv, ciphertext)
}

func (b *fallbackBackend) SignSM2(priv *SM2PrivateKey, userID, msg []byte) (*big.Int, *big.Int, error) {
	r, s, err := b.hct.SignSM2(priv, userID, msg)
	if err == nil {
		return r, s, nil
	}
	if !errors.Is(err, ErrBackendUnavailable) {
		return nil, nil, err
	}
	b.degrade(err)
	return builtinBackend{}.SignSM2(priv, userID, msg)
}

func (b *fallbackBackend) VerifySM2(pub *SM2PublicKey, userID, msg []byte, r, s *big.Int) bool {
	if b.hct.VerifySM2(pub, userID, msg, r, s) {
		return true
	}
	// VerifySM2 reports only a boolean, so a dead helper looks exactly like a
	// bad signature. Probe once: if the helper is gone, replay the verification
	// on the built-in implementation instead of rejecting a valid signature.
	// The probe is bounded well below the request timeout because a healthy
	// helper has just answered this verification; only silence needs waiting on.
	if checker, ok := b.hct.(backendChecker); ok {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err := checker.Check(ctx)
		cancel()
		if err != nil {
			if errors.Is(err, ErrBackendUnavailable) {
				b.degrade(err)
				return builtinBackend{}.VerifySM2(pub, userID, msg, r, s)
			}
		}
	}
	return false
}

// ─── SM3 / HMAC-SM3 ─────────────────────────────────────────────────

func (b *fallbackBackend) SM3Sum(data []byte) ([sm3Size]byte, error) {
	sum, err := b.hct.SM3Sum(data)
	if err == nil {
		return sum, nil
	}
	if !errors.Is(err, ErrBackendUnavailable) {
		return sum, err
	}
	b.degrade(err)
	return builtinBackend{}.SM3Sum(data)
}

func (b *fallbackBackend) HMACSM3(key, data []byte) ([sm3Size]byte, error) {
	sum, err := b.hct.HMACSM3(key, data)
	if err == nil {
		return sum, nil
	}
	if !errors.Is(err, ErrBackendUnavailable) {
		return sum, err
	}
	b.degrade(err)
	return builtinBackend{}.HMACSM3(key, data)
}

func (b *fallbackBackend) NewSM3Stream() (SM3Stream, error) {
	st, err := b.hct.NewSM3Stream()
	if err != nil {
		if !errors.Is(err, ErrBackendUnavailable) {
			return nil, err
		}
		b.degrade(err)
		return builtinBackend{}.NewSM3Stream()
	}
	return &fallbackStream{inner: st, owner: b}, nil
}

// fallbackStream observes a stream created on the HCT backend. It cannot replay
// a half-consumed stream, so it only makes the degradation visible in the log
// and lets the caller fail that one operation.
type fallbackStream struct {
	inner SM3Stream
	owner *fallbackBackend
}

func (s *fallbackStream) Write(p []byte) (int, error) {
	n, err := s.inner.Write(p)
	s.owner.noteUnavailable(err)
	return n, err
}

func (s *fallbackStream) Sum() ([sm3Size]byte, error) {
	sum, err := s.inner.Sum()
	s.owner.noteUnavailable(err)
	return sum, err
}

func (s *fallbackStream) Close() error {
	err := s.inner.Close()
	s.owner.noteUnavailable(err)
	return err
}

// ─── SM4-GCM ────────────────────────────────────────────────────────

func (b *fallbackBackend) NewGCM(key []byte) (GCM, error) {
	g, err := b.hct.NewGCM(key)
	if err != nil {
		return nil, err
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &fallbackGCM{inner: g, owner: b, key: k}, nil
}

// fallbackGCM replays a whole Seal/Open on the built-in backend when the helper
// is gone. Both calls either return the complete result or no output at all, so
// the retry cannot duplicate data the caller already saw.
type fallbackGCM struct {
	inner GCM
	owner *fallbackBackend
	key   []byte
}

func (g *fallbackGCM) NonceSize() int { return g.inner.NonceSize() }
func (g *fallbackGCM) Overhead() int  { return g.inner.Overhead() }

func (g *fallbackGCM) Seal(dst, nonce, plaintext, aad []byte) ([]byte, error) {
	out, err := g.inner.Seal(dst, nonce, plaintext, aad)
	if err == nil {
		return out, nil
	}
	if !errors.Is(err, ErrBackendUnavailable) {
		return nil, err
	}
	g.owner.degrade(err)
	builtin, err := (builtinBackend{}).NewGCM(g.key)
	if err != nil {
		return nil, err
	}
	return builtin.Seal(dst, nonce, plaintext, aad)
}

func (g *fallbackGCM) Open(dst, nonce, ciphertext, aad []byte) ([]byte, error) {
	out, err := g.inner.Open(dst, nonce, ciphertext, aad)
	if err == nil {
		return out, nil
	}
	if !errors.Is(err, ErrBackendUnavailable) {
		return nil, err
	}
	g.owner.degrade(err)
	builtin, err := (builtinBackend{}).NewGCM(g.key)
	if err != nil {
		return nil, err
	}
	return builtin.Open(dst, nonce, ciphertext, aad)
}
