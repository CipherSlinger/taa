//go:build hct && cgo && linux && amd64

package main

/*
#cgo LDFLAGS: -lhct
#include <stdlib.h>
#include <string.h>
#include <hct/cae.h>
#include <hct/hct_version.h>

static void ccp_wipe(void *p, size_t n)
{
	explicit_bzero(p, n);
}

static SM2_CCP_PKEY_CTX *ccp_sm2_alloc(void)
{
	return (SM2_CCP_PKEY_CTX *)calloc(1, sizeof(SM2_CCP_PKEY_CTX));
}

static void ccp_sm2_set_priv(SM2_CCP_PKEY_CTX *c, const unsigned char *k, size_t n)
{
	memcpy(c->d_key, k, n);
}

static void ccp_sm2_set_pub(SM2_CCP_PKEY_CTX *c, const unsigned char *k, size_t n)
{
	memcpy(c->e_key, k, n);
}

// ccp_sm3_sum runs a single-shot SM3 through the burst interface. The
// digest struct leaves the HMAC key NULL/zero-length, which is how the 3.0.10
// wrapper implements plain SM3 burst (hct_ccp_sm3_digest_burst delegates to
// the HMAC burst with an empty key). A zero-length input still needs a valid
// data pointer, hence the empty-string substitution.
//
// The context must be initialised first: a zeroed HCT_SM3_AUTH_CTX is
// rejected with -EINVAL (verified against hct_sw_sm3_digest_burst, which
// shares the wrapper). Initialising it costs one library call and keeps the
// burst contract explicit.
static int ccp_sm3_sum(const unsigned char *data, size_t n, unsigned char *md)
{
	struct sm3_digest_burst blk;
	HCT_SM3_AUTH_CTX ctx;
	int rc;

	memset(&blk, 0, sizeof(blk));
	memset(&ctx, 0, sizeof(ctx));
	rc = hct_ccp_sm3_digest_init(&ctx);
	if (rc != 0) {
		return rc;
	}
	blk.sm3_ctx = &ctx;
	blk.data = n > 0 ? data : (const unsigned char *)"";
	blk.count = (uint32_t)n;
	blk.first = 1;
	blk.final = 1;
	blk.md = md;
	rc = hct_ccp_sm3_digest_burst(&blk, 1);
	hct_ccp_sm3_digest_cleanup(&ctx);
	return rc;
}
*/
import "C"

import (
	"fmt"
	"math"
	"unsafe"
)

// ccpEngine binds the engine interface to the hardware CCP backend
// (hct_ccp_*). It is only constructed when hct_ccp_init succeeds; the router
// then sits in front of the software engine, which serves the operations the
// CCP header cannot do incrementally (HMAC-SM3 is burst-only).
type ccpEngine struct{}

func newCCPEngine() (engine, error) {
	// hct_ccp_init first opens /dev/ccp_share, the shared configuration the
	// accelerator manager publishes, and only then enumerates CCP devices. On
	// a machine without that device it fails with rc=-1 and logs
	// "fail to open /dev/ccp_share"; buildEngine turns that into a sw fallback.
	// 0 selects the library default DMA aperture, which is what the vendor
	// OpenSSL engine passes.
	if rc := C.hct_ccp_init(0); rc != 0 {
		return nil, fmt.Errorf("hct_ccp_init rc=%d (no usable CCP device?)", int(rc))
	}
	return &ccpEngine{}, nil
}

// Supports reports what the CCP API can do incrementally. SM2 and SM4-GCM are
// complete; SM3 has init/update/final, so it can stream and, through the burst
// call, also serve one-shot sums. HMAC-SM3 has no init/update/final at all,
// only a burst call, so claiming it would lie about the interface.
func (e *ccpEngine) Supports(c capability) bool {
	switch c {
	case capSM2Keygen, capSM2Encrypt, capSM2Decrypt, capSM2Sign, capSM2Verify,
		capSM3Stream, capSM3Sum, capGCM:
		return true
	case capHMACSM3:
		return false
	}
	return false
}

func (e *ccpEngine) Version() string {
	var buf [128]C.char
	C.hct_get_version(&buf[0])
	return C.GoString(&buf[0])
}

func (e *ccpEngine) Close() {
	C.hct_ccp_destroy()
}

func (e *ccpEngine) KeyGen() ([]byte, []byte, error) {
	priv := make([]byte, sm2PrivSize)
	pub := make([]byte, sm2PubSize)
	rc := C.hct_ccp_sm2_gen_keypair(ucharPtr(priv), C.size_t(len(priv)), ucharPtr(pub), C.size_t(len(pub)))
	if rc != 0 {
		clear(priv)
		clear(pub)
		return nil, nil, fmt.Errorf("hct_ccp_sm2_gen_keypair rc=%d", int(rc))
	}
	return priv, pub, nil
}

// ccpSM2Ctx allocates an SM2 context and runs fn with its private/public key
// set. The CCP build exports no key setters (they live behind CCP_ENABLE_GM),
// so the keys go into the same struct fields the software backend uses; the
// CCP sign/encrypt paths read d_key/e_key directly from the context.
func ccpSM2Ctx(priv, pub []byte, fn func(*C.SM2_CCP_PKEY_CTX) error) error {
	ctx := C.ccp_sm2_alloc()
	if ctx == nil {
		return fmt.Errorf("out of memory")
	}
	defer func() {
		C.ccp_wipe(unsafe.Pointer(ctx), C.sizeof_SM2_CCP_PKEY_CTX)
		C.free(unsafe.Pointer(ctx))
	}()
	if rc := C.hct_ccp_sm2_akcipher_init(ctx); rc != 0 {
		return fmt.Errorf("hct_ccp_sm2_akcipher_init rc=%d", int(rc))
	}
	defer C.hct_ccp_sm2_akcipher_cleanup(ctx)
	if len(priv) > 0 {
		if len(priv) != sm2PrivSize {
			return fmt.Errorf("SM2 private key must be %d bytes, got %d", sm2PrivSize, len(priv))
		}
		C.ccp_sm2_set_priv(ctx, ucharPtr(priv), C.size_t(len(priv)))
	}
	if len(pub) > 0 {
		if len(pub) != sm2PubSize {
			return fmt.Errorf("SM2 public key must be %d bytes, got %d", sm2PubSize, len(pub))
		}
		C.ccp_sm2_set_pub(ctx, ucharPtr(pub), C.size_t(len(pub)))
	}
	return fn(ctx)
}

func (e *ccpEngine) SignDigest(priv, digest []byte) ([]byte, error) {
	if len(digest) != sm2DigestSize {
		return nil, fmt.Errorf("SM2 digest must be %d bytes, got %d", sm2DigestSize, len(digest))
	}
	var sig []byte
	err := ccpSM2Ctx(priv, nil, func(ctx *C.SM2_CCP_PKEY_CTX) error {
		sig = make([]byte, sm2SigSize)
		siglen := C.size_t(len(sig))
		rc := C.hct_ccp_sm2_akcipher_sign(ctx, ucharPtr(digest), C.size_t(len(digest)),
			ucharPtr(sig), &siglen)
		if rc != 0 {
			return fmt.Errorf("hct_ccp_sm2_akcipher_sign rc=%d", int(rc))
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

func (e *ccpEngine) VerifyDigest(pub, digest, sig []byte) (bool, error) {
	if len(digest) != sm2DigestSize || len(sig) != sm2SigSize {
		return false, fmt.Errorf("invalid SM2 verify input lengths")
	}
	var valid bool
	err := ccpSM2Ctx(nil, pub, func(ctx *C.SM2_CCP_PKEY_CTX) error {
		rc := C.hct_ccp_sm2_akcipher_verify(ctx, ucharPtr(digest), C.size_t(len(digest)),
			ucharPtr(sig), C.size_t(len(sig)))
		// Same convention as the software backend: 0 means the signature is
		// valid, anything else means it did not verify.
		valid = rc == 0
		return nil
	})
	return valid, err
}

func (e *ccpEngine) Encrypt(pub, plaintext []byte) ([]byte, error) {
	var out []byte
	err := ccpSM2Ctx(nil, pub, func(ctx *C.SM2_CCP_PKEY_CTX) error {
		out = make([]byte, len(plaintext)+96)
		clen := C.size_t(len(out))
		rc := C.hct_ccp_sm2_akcipher_encrypt(ctx, ucharPtr(plaintext), C.size_t(len(plaintext)),
			ucharPtr(out), &clen)
		if rc != 0 {
			return fmt.Errorf("hct_ccp_sm2_akcipher_encrypt rc=%d", int(rc))
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

func (e *ccpEngine) Decrypt(priv, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 96 {
		return nil, fmt.Errorf("SM2 ciphertext too short: %d", len(ciphertext))
	}
	var out []byte
	err := ccpSM2Ctx(priv, nil, func(ctx *C.SM2_CCP_PKEY_CTX) error {
		out = make([]byte, len(ciphertext)-96)
		plen := C.size_t(len(out))
		rc := C.hct_ccp_sm2_akcipher_decrypt(ctx, ucharPtr(ciphertext), C.size_t(len(ciphertext)),
			ucharPtr(out), &plen)
		if rc != 0 {
			return fmt.Errorf("hct_ccp_sm2_akcipher_decrypt rc=%d", int(rc))
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

type ccpSM3 struct {
	ctx unsafe.Pointer
}

func (e *ccpEngine) NewSM3() (sm3Stream, error) {
	p := C.calloc(1, C.sizeof_HCT_SM3_AUTH_CTX)
	if p == nil {
		return nil, fmt.Errorf("out of memory")
	}
	if rc := C.hct_ccp_sm3_digest_init((*C.HCT_SM3_AUTH_CTX)(p)); rc != 0 {
		C.free(p)
		return nil, fmt.Errorf("hct_ccp_sm3_digest_init rc=%d", int(rc))
	}
	return &ccpSM3{ctx: p}, nil
}

// NewHMACSM3 is unreachable through the router: Supports rejects capHMACSM3,
// so the software engine serves it. Returning an error keeps the failure
// explicit if that routing ever changes.
func (e *ccpEngine) NewHMACSM3(key []byte) (sm3Stream, error) {
	return nil, fmt.Errorf("CCP HMAC-SM3 is burst-only and has no incremental interface")
}

func (e *ccpEngine) SM3Sum(data []byte) ([]byte, error) {
	if uint64(len(data)) > math.MaxUint32 {
		return nil, fmt.Errorf("SM3 sum input too large: %d bytes", len(data))
	}
	out := make([]byte, sm3DigestSize)
	rc := C.ccp_sm3_sum(ucharPtr(data), C.size_t(len(data)), ucharPtr(out))
	// The burst wrapper consumes partial batches internally and returns 0 when
	// the whole input went through; a negative code is a failure.
	if rc != 0 {
		return nil, fmt.Errorf("hct_ccp_sm3_digest_burst rc=%d", int(rc))
	}
	return out, nil
}

func (s *ccpSM3) Write(p []byte) error {
	if len(p) == 0 {
		// libhct rejects a zero-length update; skipping it is equivalent.
		return nil
	}
	if rc := C.hct_ccp_sm3_digest_update((*C.HCT_SM3_AUTH_CTX)(s.ctx), unsafe.Pointer(&p[0]), C.size_t(len(p))); rc != 0 {
		return fmt.Errorf("hct_ccp_sm3_digest_update rc=%d", int(rc))
	}
	return nil
}

func (s *ccpSM3) Sum() ([]byte, error) {
	out := make([]byte, sm3DigestSize)
	if rc := C.hct_ccp_sm3_digest_final((*C.HCT_SM3_AUTH_CTX)(s.ctx), ucharPtr(out)); rc != 0 {
		return nil, fmt.Errorf("hct_ccp_sm3_digest_final rc=%d", int(rc))
	}
	return out, nil
}

func (s *ccpSM3) Free() {
	if s.ctx == nil {
		return
	}
	C.hct_ccp_sm3_digest_cleanup((*C.HCT_SM3_AUTH_CTX)(s.ctx))
	C.ccp_wipe(s.ctx, C.sizeof_HCT_SM3_AUTH_CTX)
	C.free(s.ctx)
	s.ctx = nil
}

type ccpGCM struct {
	ctx unsafe.Pointer
	enc bool
}

// NewGCM uses the GCM context, not the plain cipher context the prototype's
// type suggests: hct_ccp_sm4_gcm_init_key casts its argument to
// HCT_SM4_GCM_CIPHER_CTX and keeps its own state behind gctx->ctx.
func (e *ccpEngine) NewGCM(key, iv []byte, enc bool) (gcmStream, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("SM4 key must be 16 bytes, got %d", len(key))
	}
	if len(iv) != gcmIVSize {
		return nil, fmt.Errorf("GCM IV must be %d bytes, got %d", gcmIVSize, len(iv))
	}
	p := C.calloc(1, C.sizeof_HCT_SM4_GCM_CIPHER_CTX)
	if p == nil {
		return nil, fmt.Errorf("out of memory")
	}
	encInt := C.int(0)
	if enc {
		encInt = 1
	}
	if rc := C.hct_ccp_sm4_gcm_init_key((*C.HCT_SM4_CIPHER_CTX)(p), ucharPtr(key), ucharPtr(iv), encInt); rc != 0 {
		C.free(p)
		return nil, fmt.Errorf("hct_ccp_sm4_gcm_init_key rc=%d", int(rc))
	}
	return &ccpGCM{ctx: p, enc: enc}, nil
}

func (g *ccpGCM) AAD(p []byte) error {
	if len(p) == 0 {
		return nil
	}
	rc := C.hct_ccp_sm4_gcm_cipher((*C.HCT_SM4_CIPHER_CTX)(g.ctx), nil, ucharPtr(p), C.size_t(len(p)))
	if int(rc) != len(p) {
		return fmt.Errorf("hct_ccp_sm4_gcm_cipher(aad) rc=%d want %d", int(rc), len(p))
	}
	return nil
}

func (g *ccpGCM) Update(dst, src []byte) error {
	if len(dst) != len(src) {
		return fmt.Errorf("GCM update buffer mismatch: dst %d src %d", len(dst), len(src))
	}
	if len(src) == 0 {
		return nil
	}
	rc := C.hct_ccp_sm4_gcm_cipher((*C.HCT_SM4_CIPHER_CTX)(g.ctx), ucharPtr(dst), ucharPtr(src), C.size_t(len(src)))
	if int(rc) != len(src) {
		return fmt.Errorf("hct_ccp_sm4_gcm_cipher(data) rc=%d want %d", int(rc), len(src))
	}
	return nil
}

func (g *ccpGCM) Final() error {
	rc := C.hct_ccp_sm4_gcm_cipher((*C.HCT_SM4_CIPHER_CTX)(g.ctx), nil, nil, 0)
	if rc != 0 {
		// On decrypt this is the tag verdict; on encrypt it is an internal
		// failure. The server maps errAuthFailed to StatusAuthFailed only for
		// decrypt; either way TAA fails closed.
		return errAuthFailed
	}
	return nil
}

func (g *ccpGCM) SetTag(tag []byte) error {
	if len(tag) != gcmTagSize {
		return fmt.Errorf("GCM tag must be %d bytes, got %d", gcmTagSize, len(tag))
	}
	rc := C.hct_ccp_sm4_gcm_ctrl((*C.HCT_SM4_CIPHER_CTX)(g.ctx),
		C.CTRL_GCM_AEAD_SET_TAG, C.int(len(tag)), unsafe.Pointer(&tag[0]))
	// Unlike the software backend, the CCP ctrl returns 1 on success and 0 for
	// a rejected argument, so a non-positive result is the failure signal.
	if rc <= 0 {
		return fmt.Errorf("hct_ccp_sm4_gcm_ctrl(SET_TAG) rc=%d", int(rc))
	}
	return nil
}

func (g *ccpGCM) Tag() ([]byte, error) {
	out := make([]byte, gcmTagSize)
	rc := C.hct_ccp_sm4_gcm_ctrl((*C.HCT_SM4_CIPHER_CTX)(g.ctx),
		C.CTRL_GCM_AEAD_GET_TAG, C.int(len(out)), unsafe.Pointer(&out[0]))
	if rc <= 0 {
		return nil, fmt.Errorf("hct_ccp_sm4_gcm_ctrl(GET_TAG) rc=%d", int(rc))
	}
	return out, nil
}

func (g *ccpGCM) Free() {
	if g.ctx == nil {
		return
	}
	C.hct_ccp_sm4_gcm_cleanup((*C.HCT_SM4_CIPHER_CTX)(g.ctx))
	C.ccp_wipe(g.ctx, C.sizeof_HCT_SM4_GCM_CIPHER_CTX)
	C.free(g.ctx)
	g.ctx = nil
}
