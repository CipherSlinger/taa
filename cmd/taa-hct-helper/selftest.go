package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Known-answer values for HCT 3.0.10's SW backend. They are the standard SM3
// and HMAC-SM3 vectors; the GCM vector was produced by the Phase 0 PoC and is
// asserted byte-for-byte against Go's crypto/cipher GCM by pkg/crypto tests.
var (
	katSM3abc, _  = hex.DecodeString("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")
	katHMACHi, _  = hex.DecodeString("12d66c84b4a40ad8035c263e419bd43c7e52fb438b930eba0c94e34cdb9b63f3")
	katGCMCT, _   = hex.DecodeString("e949365e14cf1277153f7433157d1b97fb7f480fd154bd08c1a7fd4f6a9b1abbc07f41fea69e7e17c696ea50225dce60ebee4405c1230d60107508a42675861c")
	katGCMTag, _  = hex.DecodeString("ccec422c74d3ecff0be081d5bc4e03cc")
	katGCMKey     = []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	katGCMIV      = make([]byte, gcmIVSize)
	katGCMSubject = bytes.Repeat([]byte{0x5a}, 64)
)

// runSelfTest exercises every operation TAA depends on. Any failure means the
// library on this host is not the one TAA was validated against, so startup
// must abort rather than run with a mismatched backend.
func runSelfTest(eng engine, out io.Writer) error {
	logf := func(format string, args ...any) {
		fmt.Fprintf(out, format+"\n", args...)
	}

	version := eng.Version()
	logf("version=%s", version)
	if !strings.Contains(version, "3.0.10") {
		return fmt.Errorf("libhct version %q is not 3.0.10", version)
	}

	// SM3
	sum, err := eng.SM3Sum([]byte("abc"))
	if err != nil {
		return fmt.Errorf("SM3: %w", err)
	}
	if !bytes.Equal(sum, katSM3abc) {
		return fmt.Errorf("SM3(abc) = %x", sum)
	}
	logf("sm3(abc)=%x", sum)

	// Streaming SM3, split at an awkward boundary.
	st, err := eng.NewSM3()
	if err != nil {
		return fmt.Errorf("SM3 stream init: %w", err)
	}
	for _, part := range [][]byte{{'a'}, {'b', 'c'}} {
		if err := st.Write(part); err != nil {
			st.Free()
			return fmt.Errorf("SM3 stream write: %w", err)
		}
	}
	sum, err = st.Sum()
	st.Free()
	if err != nil {
		return fmt.Errorf("SM3 stream final: %w", err)
	}
	if !bytes.Equal(sum, katSM3abc) {
		return fmt.Errorf("streaming SM3(abc) = %x", sum)
	}

	// HMAC-SM3
	key := bytes.Repeat([]byte{0x0b}, 16)
	hs, err := eng.NewHMACSM3(key)
	if err != nil {
		return fmt.Errorf("HMAC-SM3 init: %w", err)
	}
	if err := hs.Write([]byte("Hi There")); err != nil {
		hs.Free()
		return fmt.Errorf("HMAC-SM3 write: %w", err)
	}
	mac, err := hs.Sum()
	hs.Free()
	if err != nil {
		return fmt.Errorf("HMAC-SM3 final: %w", err)
	}
	if !bytes.Equal(mac, katHMACHi) {
		return fmt.Errorf("HMAC-SM3 = %x", mac)
	}
	logf("hmac-sm3=%x", mac)

	// SM4-GCM encrypt: byte-for-byte against the PoC vector.
	aad := bytes.Repeat([]byte{0xaa}, 20)
	enc, err := eng.NewGCM(katGCMKey, katGCMIV, true)
	if err != nil {
		return fmt.Errorf("GCM enc init: %w", err)
	}
	if err := enc.AAD(aad); err != nil {
		enc.Free()
		return fmt.Errorf("GCM enc aad: %w", err)
	}
	ct := make([]byte, len(katGCMSubject))
	if err := enc.Update(ct, katGCMSubject); err != nil {
		enc.Free()
		return fmt.Errorf("GCM enc update: %w", err)
	}
	if err := enc.Final(); err != nil {
		enc.Free()
		return fmt.Errorf("GCM enc final: %w", err)
	}
	tag, err := enc.Tag()
	enc.Free()
	if err != nil {
		return fmt.Errorf("GCM enc tag: %w", err)
	}
	if !bytes.Equal(ct, katGCMCT) || !bytes.Equal(tag, katGCMTag) {
		return fmt.Errorf("GCM vector mismatch: ct=%x tag=%x", ct, tag)
	}
	logf("gcm-ct=%x", ct)
	logf("gcm-tag=%x", tag)

	// SM4-GCM decrypt with the good tag.
	dec, err := eng.NewGCM(katGCMKey, katGCMIV, false)
	if err != nil {
		return fmt.Errorf("GCM dec init: %w", err)
	}
	if err := dec.SetTag(katGCMTag); err != nil {
		dec.Free()
		return fmt.Errorf("GCM dec set tag: %w", err)
	}
	if err := dec.AAD(aad); err != nil {
		dec.Free()
		return fmt.Errorf("GCM dec aad: %w", err)
	}
	pt := make([]byte, len(ct))
	if err := dec.Update(pt, ct); err != nil {
		dec.Free()
		return fmt.Errorf("GCM dec update: %w", err)
	}
	if err := dec.Final(); err != nil {
		dec.Free()
		return fmt.Errorf("GCM dec final: %w", err)
	}
	dec.Free()
	if !bytes.Equal(pt, katGCMSubject) {
		return fmt.Errorf("GCM decrypt mismatch")
	}

	// SM4-GCM decrypt with a tampered tag must fail.
	bad := append([]byte(nil), katGCMTag...)
	bad[0] ^= 1
	dec, err = eng.NewGCM(katGCMKey, katGCMIV, false)
	if err != nil {
		return fmt.Errorf("GCM bad-tag init: %w", err)
	}
	if err := dec.SetTag(bad); err != nil {
		dec.Free()
		return fmt.Errorf("GCM bad-tag set: %w", err)
	}
	if err := dec.AAD(aad); err != nil {
		dec.Free()
		return fmt.Errorf("GCM bad-tag aad: %w", err)
	}
	if err := dec.Update(pt, ct); err != nil {
		dec.Free()
		return fmt.Errorf("GCM bad-tag update: %w", err)
	}
	err = dec.Final()
	dec.Free()
	if !errors.Is(err, errAuthFailed) {
		return fmt.Errorf("GCM accepted a tampered tag (err=%v)", err)
	}
	logf("gcm-bad-tag=rejected")

	// SM2 sign/verify and encrypt/decrypt.
	priv, pub, err := eng.KeyGen()
	if err != nil {
		return fmt.Errorf("SM2 keygen: %w", err)
	}
	digest := make([]byte, sm2DigestSize)
	for i := range digest {
		digest[i] = byte(i)
	}
	sig, err := eng.SignDigest(priv, digest)
	if err != nil {
		return fmt.Errorf("SM2 sign: %w", err)
	}
	valid, err := eng.VerifyDigest(pub, digest, sig)
	if err != nil {
		return fmt.Errorf("SM2 verify: %w", err)
	}
	if !valid {
		return errors.New("SM2 signature did not verify")
	}
	badSig := append([]byte(nil), sig...)
	badSig[0] ^= 1
	valid, err = eng.VerifyDigest(pub, digest, badSig)
	if err != nil {
		return fmt.Errorf("SM2 bad verify: %w", err)
	}
	if valid {
		return errors.New("SM2 accepted a tampered signature")
	}
	logf("sm2-sign=ok")

	msg := []byte("TAA HCT selftest payload")
	ctSM2, err := eng.Encrypt(pub, msg)
	if err != nil {
		return fmt.Errorf("SM2 encrypt: %w", err)
	}
	if len(ctSM2) != len(msg)+96 {
		return fmt.Errorf("SM2 ciphertext length %d, want %d", len(ctSM2), len(msg)+96)
	}
	got, err := eng.Decrypt(priv, ctSM2)
	if err != nil {
		return fmt.Errorf("SM2 decrypt: %w", err)
	}
	if !bytes.Equal(got, msg) {
		return errors.New("SM2 round trip mismatch")
	}
	tampered := append([]byte(nil), ctSM2...)
	tampered[64] ^= 1 // C3
	if _, err := eng.Decrypt(priv, tampered); err == nil {
		return errors.New("SM2 decrypt accepted a tampered C3")
	}
	logf("sm2-decrypt=ok")
	return nil
}
