//go:build hct && cgo && linux && amd64

package main

/*
#cgo LDFLAGS: -lhct
#include <stdlib.h>
#include <string.h>
#include <hct/cae.h>
#include <hct/hct_version.h>

static void hct_wipe(void *p, size_t n)
{
	explicit_bzero(p, n);
}

static SM2_SW_PKEY_CTX *hct_sm2_alloc(void)
{
	return (SM2_SW_PKEY_CTX *)calloc(1, sizeof(SM2_SW_PKEY_CTX));
}

static void hct_sm2_set_priv(SM2_SW_PKEY_CTX *c, const unsigned char *k, size_t n)
{
	memcpy(c->d_key, k, n);
}

static void hct_sm2_set_pub(SM2_SW_PKEY_CTX *c, const unsigned char *k, size_t n)
{
	memcpy(c->e_key, k, n);
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// hctEngine binds the engine interface to the CAE direct C API (hct_sw_*).
// Only the SW backend is implemented; there is no CCP device in a CSV2 guest.
// The engine is returned wrapped in a router even though it is the only route:
// the router is the seam a CCP engine will plug into, and it is what feeds the
// per-operation engine report in the handshake.
type hctEngine struct{}

func newEngine(accel string) (engine, error) {
	if accel == "" {
		accel = "sw"
	}
	if accel != "sw" {
		return nil, fmt.Errorf("unsupported HCT accel %q (only sw is available)", accel)
	}
	e := &hctEngine{}
	// Fail early if the library cannot even be queried.
	if e.Version() == "" {
		return nil, fmt.Errorf("libhct did not report a version")
	}
	return newRouter(accel, route{name: "sw", eng: e}), nil
}

func (e *hctEngine) Version() string {
	var buf [128]C.char
	C.hct_get_version(&buf[0])
	return C.GoString(&buf[0])
}

func (e *hctEngine) Close() {}

func ucharPtr(b []byte) *C.uchar {
	if len(b) == 0 {
		return nil
	}
	return (*C.uchar)(unsafe.Pointer(&b[0]))
}

func (e *hctEngine) KeyGen() ([]byte, []byte, error) {
	priv := make([]byte, sm2PrivSize)
	pub := make([]byte, sm2PubSize)
	rc := C.hct_sw_sm2_gen_keypair(ucharPtr(priv), C.size_t(len(priv)), ucharPtr(pub), C.size_t(len(pub)))
	if rc != 0 {
		clear(priv)
		clear(pub)
		return nil, nil, fmt.Errorf("hct_sw_sm2_gen_keypair rc=%d", int(rc))
	}
	return priv, pub, nil
}

// sm2Ctx allocates an SM2 context and runs fn with its private/public key set.
// The context (and the key copies inside it) is wiped before being freed.
func sm2Ctx(priv, pub []byte, fn func(*C.SM2_SW_PKEY_CTX) error) error {
	ctx := C.hct_sm2_alloc()
	if ctx == nil {
		return fmt.Errorf("out of memory")
	}
	defer func() {
		C.hct_wipe(unsafe.Pointer(ctx), C.sizeof_SM2_SW_PKEY_CTX)
		C.free(unsafe.Pointer(ctx))
	}()
	if rc := C.hct_sw_sm2_akcipher_init(ctx); rc != 0 {
		return fmt.Errorf("hct_sw_sm2_akcipher_init rc=%d", int(rc))
	}
	defer C.hct_sw_sm2_akcipher_cleanup(ctx)
	if len(priv) > 0 {
		if len(priv) != sm2PrivSize {
			return fmt.Errorf("SM2 private key must be %d bytes, got %d", sm2PrivSize, len(priv))
		}
		C.hct_sm2_set_priv(ctx, ucharPtr(priv), C.size_t(len(priv)))
	}
	if len(pub) > 0 {
		if len(pub) != sm2PubSize {
			return fmt.Errorf("SM2 public key must be %d bytes, got %d", sm2PubSize, len(pub))
		}
		C.hct_sm2_set_pub(ctx, ucharPtr(pub), C.size_t(len(pub)))
	}
	return fn(ctx)
}

func (e *hctEngine) SignDigest(priv, digest []byte) ([]byte, error) {
	if len(digest) != sm2DigestSize {
		return nil, fmt.Errorf("SM2 digest must be %d bytes, got %d", sm2DigestSize, len(digest))
	}
	var sig []byte
	err := sm2Ctx(priv, nil, func(ctx *C.SM2_SW_PKEY_CTX) error {
		sig = make([]byte, sm2SigSize)
		siglen := C.size_t(len(sig))
		rc := C.hct_sw_sm2_akcipher_sign(ctx, ucharPtr(digest), C.size_t(len(digest)),
			ucharPtr(sig), &siglen)
		if rc != 0 {
			return fmt.Errorf("hct_sw_sm2_akcipher_sign rc=%d", int(rc))
		}
		if int(siglen) != sm2SigSize {
			return fmt.Errorf("SM2 signature length %d, want %d", int(siglen), sm2SigSize)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func (e *hctEngine) VerifyDigest(pub, digest, sig []byte) (bool, error) {
	if len(digest) != sm2DigestSize || len(sig) != sm2SigSize {
		return false, fmt.Errorf("invalid SM2 verify input lengths")
	}
	var valid bool
	err := sm2Ctx(nil, pub, func(ctx *C.SM2_SW_PKEY_CTX) error {
		rc := C.hct_sw_sm2_akcipher_verify(ctx, ucharPtr(digest), C.size_t(len(digest)),
			ucharPtr(sig), C.size_t(len(sig)))
		// The SW backend returns 0 for a valid signature and a negative code
		// for an invalid one. Both mean "did not verify" to the caller; there
		// is no separate scheme for distinguishing them.
		valid = rc == 0
		return nil
	})
	return valid, err
}

func (e *hctEngine) Encrypt(pub, plaintext []byte) ([]byte, error) {
	var out []byte
	err := sm2Ctx(nil, pub, func(ctx *C.SM2_SW_PKEY_CTX) error {
		out = make([]byte, len(plaintext)+96)
		clen := C.size_t(len(out))
		rc := C.hct_sw_sm2_akcipher_encrypt(ctx, ucharPtr(plaintext), C.size_t(len(plaintext)),
			ucharPtr(out), &clen)
		if rc != 0 {
			return fmt.Errorf("hct_sw_sm2_akcipher_encrypt rc=%d", int(rc))
		}
		if int(clen) < 96 || int(clen) > len(out) {
			return fmt.Errorf("SM2 ciphertext length %d out of range", int(clen))
		}
		out = out[:clen]
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (e *hctEngine) Decrypt(priv, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 96 {
		return nil, fmt.Errorf("SM2 ciphertext too short: %d", len(ciphertext))
	}
	var out []byte
	err := sm2Ctx(priv, nil, func(ctx *C.SM2_SW_PKEY_CTX) error {
		out = make([]byte, len(ciphertext)-96)
		plen := C.size_t(len(out))
		rc := C.hct_sw_sm2_akcipher_decrypt(ctx, ucharPtr(ciphertext), C.size_t(len(ciphertext)),
			ucharPtr(out), &plen)
		if rc != 0 {
			return fmt.Errorf("hct_sw_sm2_akcipher_decrypt rc=%d", int(rc))
		}
		if int(plen) > len(out) {
			return fmt.Errorf("SM2 plaintext length %d out of range", int(plen))
		}
		out = out[:plen]
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

type hctSM3 struct {
	ctx  unsafe.Pointer
	hmac bool
}

func newSM3Ctx() (unsafe.Pointer, error) {
	p := C.calloc(1, C.sizeof_HCT_SM3_AUTH_CTX)
	if p == nil {
		return nil, fmt.Errorf("out of memory")
	}
	return p, nil
}

func (e *hctEngine) NewSM3() (sm3Stream, error) {
	p, err := newSM3Ctx()
	if err != nil {
		return nil, err
	}
	if rc := C.hct_sw_sm3_digest_init((*C.HCT_SM3_AUTH_CTX)(p)); rc != 0 {
		C.free(p)
		return nil, fmt.Errorf("hct_sw_sm3_digest_init rc=%d", int(rc))
	}
	return &hctSM3{ctx: p}, nil
}

func (e *hctEngine) NewHMACSM3(key []byte) (sm3Stream, error) {
	p, err := newSM3Ctx()
	if err != nil {
		return nil, err
	}
	if rc := C.hct_sw_sm3_hmac_digest_init((*C.HCT_SM3_AUTH_CTX)(p), ucharPtr(key), C.size_t(len(key))); rc != 0 {
		C.free(p)
		return nil, fmt.Errorf("hct_sw_sm3_hmac_digest_init rc=%d", int(rc))
	}
	return &hctSM3{ctx: p, hmac: true}, nil
}

func (e *hctEngine) SM3Sum(data []byte) ([]byte, error) {
	st, err := e.NewSM3()
	if err != nil {
		return nil, err
	}
	if len(data) > 0 {
		err = st.Write(data)
	}
	var sum []byte
	if err == nil {
		sum, err = st.Sum()
	}
	st.Free()
	return sum, err
}

func (s *hctSM3) Write(p []byte) error {
	if len(p) == 0 {
		// libhct rejects a zero-length update; skipping it is equivalent.
		return nil
	}
	var rc C.int
	if s.hmac {
		rc = C.hct_sw_sm3_hmac_digest_update((*C.HCT_SM3_AUTH_CTX)(s.ctx), unsafe.Pointer(&p[0]), C.size_t(len(p)))
	} else {
		rc = C.hct_sw_sm3_digest_update((*C.HCT_SM3_AUTH_CTX)(s.ctx), unsafe.Pointer(&p[0]), C.size_t(len(p)))
	}
	if rc != 0 {
		return fmt.Errorf("hct_sw_sm3_digest_update rc=%d", int(rc))
	}
	return nil
}

func (s *hctSM3) Sum() ([]byte, error) {
	out := make([]byte, sm3DigestSize)
	var rc C.int
	if s.hmac {
		rc = C.hct_sw_sm3_hmac_digest_final((*C.HCT_SM3_AUTH_CTX)(s.ctx), ucharPtr(out))
	} else {
		rc = C.hct_sw_sm3_digest_final((*C.HCT_SM3_AUTH_CTX)(s.ctx), ucharPtr(out))
	}
	if rc != 0 {
		return nil, fmt.Errorf("hct_sw_sm3_digest_final rc=%d", int(rc))
	}
	return out, nil
}

func (s *hctSM3) Free() {
	if s.ctx == nil {
		return
	}
	if s.hmac {
		C.hct_sw_sm3_hmac_digest_cleanup((*C.HCT_SM3_AUTH_CTX)(s.ctx))
	} else {
		C.hct_sw_sm3_digest_cleanup((*C.HCT_SM3_AUTH_CTX)(s.ctx))
	}
	C.hct_wipe(s.ctx, C.sizeof_HCT_SM3_AUTH_CTX)
	C.free(s.ctx)
	s.ctx = nil
}

type hctGCM struct {
	ctx unsafe.Pointer
	enc bool
}

func (e *hctEngine) NewGCM(key, iv []byte, enc bool) (gcmStream, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("SM4 key must be 16 bytes, got %d", len(key))
	}
	if len(iv) != gcmIVSize {
		return nil, fmt.Errorf("GCM IV must be %d bytes, got %d", gcmIVSize, len(iv))
	}
	// The SW GCM entry points take the plain cipher context; the library keeps
	// its GCM state behind sw_ctx. Passing a HCT_SM4_GCM_CIPHER_CTX here (as
	// the header's type suggests) does not work — verified in Phase 0.
	p := C.calloc(1, C.sizeof_HCT_SM4_CIPHER_CTX)
	if p == nil {
		return nil, fmt.Errorf("out of memory")
	}
	encInt := C.int(0)
	if enc {
		encInt = 1
	}
	if rc := C.hct_sw_sm4_gcm_init_key((*C.HCT_SM4_CIPHER_CTX)(p), ucharPtr(key), ucharPtr(iv), encInt); rc != 0 {
		C.free(p)
		return nil, fmt.Errorf("hct_sw_sm4_gcm_init_key rc=%d", int(rc))
	}
	return &hctGCM{ctx: p, enc: enc}, nil
}

func (g *hctGCM) AAD(p []byte) error {
	if len(p) == 0 {
		return nil
	}
	rc := C.hct_sw_sm4_gcm_cipher((*C.HCT_SM4_CIPHER_CTX)(g.ctx), nil, ucharPtr(p), C.size_t(len(p)))
	if int(rc) != len(p) {
		return fmt.Errorf("hct_sw_sm4_gcm_cipher(aad) rc=%d want %d", int(rc), len(p))
	}
	return nil
}

func (g *hctGCM) Update(dst, src []byte) error {
	if len(dst) != len(src) {
		return fmt.Errorf("GCM update buffer mismatch: dst %d src %d", len(dst), len(src))
	}
	if len(src) == 0 {
		return nil
	}
	rc := C.hct_sw_sm4_gcm_cipher((*C.HCT_SM4_CIPHER_CTX)(g.ctx), ucharPtr(dst), ucharPtr(src), C.size_t(len(src)))
	if int(rc) != len(src) {
		return fmt.Errorf("hct_sw_sm4_gcm_cipher(data) rc=%d want %d", int(rc), len(src))
	}
	return nil
}

func (g *hctGCM) Final() error {
	rc := C.hct_sw_sm4_gcm_cipher((*C.HCT_SM4_CIPHER_CTX)(g.ctx), nil, nil, 0)
	if rc != 0 {
		// On decrypt this is the tag verdict; on encrypt it is an internal
		// failure. The server maps errAuthFailed to StatusAuthFailed only for
		// decrypt; either way TAA fails closed.
		return errAuthFailed
	}
	return nil
}

func (g *hctGCM) SetTag(tag []byte) error {
	if len(tag) != gcmTagSize {
		return fmt.Errorf("GCM tag must be %d bytes, got %d", gcmTagSize, len(tag))
	}
	rc := C.hct_sw_sm4_gcm_ctrl((*C.HCT_SM4_CIPHER_CTX)(g.ctx),
		C.CTRL_GCM_AEAD_SET_TAG, C.int(len(tag)), unsafe.Pointer(&tag[0]))
	if rc < 0 {
		return fmt.Errorf("hct_sw_sm4_gcm_ctrl(SET_TAG) rc=%d", int(rc))
	}
	return nil
}

func (g *hctGCM) Tag() ([]byte, error) {
	out := make([]byte, gcmTagSize)
	rc := C.hct_sw_sm4_gcm_ctrl((*C.HCT_SM4_CIPHER_CTX)(g.ctx),
		C.CTRL_GCM_AEAD_GET_TAG, C.int(len(out)), unsafe.Pointer(&out[0]))
	if rc < 0 {
		return nil, fmt.Errorf("hct_sw_sm4_gcm_ctrl(GET_TAG) rc=%d", int(rc))
	}
	return out, nil
}

func (g *hctGCM) Free() {
	if g.ctx == nil {
		return
	}
	C.hct_sw_sm4_gcm_cleanup((*C.HCT_SM4_CIPHER_CTX)(g.ctx))
	C.hct_wipe(g.ctx, C.sizeof_HCT_SM4_CIPHER_CTX)
	C.free(g.ctx)
	g.ctx = nil
}
