package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
)

var (
	katSM3ABC, _      = hex.DecodeString("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")
	katHMACHiThere, _ = hex.DecodeString("12d66c84b4a40ad8035c263e419bd43c7e52fb438b930eba0c94e34cdb9b63f3")
)

// runHCTKAT exercises the complete TAA→helper→libhct path before the backend
// becomes active. A failure here aborts startup: a backend that cannot prove
// these vectors would silently sign or encrypt with wrong semantics.
func runHCTKAT(b Backend) error {
	sum, err := b.SM3Sum([]byte("abc"))
	if err != nil {
		return fmt.Errorf("SM3: %w", err)
	}
	if !bytes.Equal(sum[:], katSM3ABC) {
		return fmt.Errorf("SM3(abc) = %x", sum)
	}

	mac, err := b.HMACSM3(bytes.Repeat([]byte{0x0b}, 16), []byte("Hi There"))
	if err != nil {
		return fmt.Errorf("HMAC-SM3: %w", err)
	}
	if !bytes.Equal(mac[:], katHMACHiThere) {
		return fmt.Errorf("HMAC-SM3 = %x", mac)
	}

	key := bytes.Repeat([]byte{0x11}, SM4KeySize)
	gcm, err := b.NewGCM(key)
	if err != nil {
		return fmt.Errorf("GCM init: %w", err)
	}
	nonce := bytes.Repeat([]byte{0x22}, gcm.NonceSize())
	msg := []byte("taa hct kat")
	sealed, err := gcm.Seal(nil, nonce, msg, nil)
	if err != nil {
		return fmt.Errorf("GCM seal: %w", err)
	}
	opened, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return fmt.Errorf("GCM open: %w", err)
	}
	if !bytes.Equal(opened, msg) {
		return errors.New("GCM round trip mismatch")
	}
	bad := append([]byte(nil), sealed...)
	bad[len(bad)-1] ^= 1
	if _, err := gcm.Open(nil, nonce, bad, nil); err == nil {
		return errors.New("GCM accepted a tampered tag")
	}

	priv, err := b.GenerateSM2KeyPair()
	if err != nil {
		return fmt.Errorf("SM2 keygen: %w", err)
	}
	digestMsg := []byte("taa hct kat message")
	r, s, err := b.SignSM2(priv, nil, digestMsg)
	if err != nil {
		return fmt.Errorf("SM2 sign: %w", err)
	}
	if !b.VerifySM2(&priv.PublicKey, nil, digestMsg, r, s) {
		return errors.New("SM2 signature did not verify")
	}
	if b.VerifySM2(&priv.PublicKey, nil, []byte("other"), r, s) {
		return errors.New("SM2 verified a signature over another message")
	}

	ct, err := b.EncryptSM2(&priv.PublicKey, msg)
	if err != nil {
		return fmt.Errorf("SM2 encrypt: %w", err)
	}
	pt, err := b.DecryptSM2(priv, ct)
	if err != nil {
		return fmt.Errorf("SM2 decrypt: %w", err)
	}
	if !bytes.Equal(pt, msg) {
		return errors.New("SM2 round trip mismatch")
	}
	tampered := append([]byte(nil), ct...)
	tampered[1+64] ^= 1 // C3 starts after 0x04||C1
	if _, err := b.DecryptSM2(priv, tampered); err == nil {
		return errors.New("SM2 decrypt accepted a tampered C3")
	}
	return nil
}
