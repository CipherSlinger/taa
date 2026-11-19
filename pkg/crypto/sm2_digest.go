package crypto

import (
	"errors"
	"math/big"
)

// sm2Digest computes the value an SM2 signature actually covers:
//
//	ZA = SM3(ENTLA || ID_A || a || b || xG || yG || xA || yA)
//	e  = SM3(ZA || M)
//
// It reproduces gmsm's ZA/msgHash byte for byte so a signature produced by one
// library verifies in the other. The HCT backend hashes here in Go and hands
// the helper only the 32-byte e; that keeps arbitrary user IDs working without
// depending on how libhct interprets its digest argument.
func sm2Digest(pub *SM2PublicKey, userID, msg []byte) ([32]byte, error) {
	var zero [sm3Size]byte
	if err := validateSM2PublicKey(pub); err != nil {
		return zero, err
	}

	uid := userID
	if len(uid) == 0 {
		uid = SM2DefaultUserID
	}
	if len(uid) >= 8192 {
		return zero, errors.New("teecrypto: SM2 用户标识过长")
	}

	params := sm2Curve.Params()
	a := new(big.Int).Sub(params.P, big.NewInt(3))

	entla := uint16(len(uid) * 8)

	zaStream, err := NewSM3Stream()
	if err != nil {
		return zero, err
	}
	defer zaStream.Close()

	writeAll := func(s SM3Stream, parts ...[]byte) error {
		for _, p := range parts {
			if len(p) == 0 {
				continue
			}
			if _, err := s.Write(p); err != nil {
				return err
			}
		}
		return nil
	}

	if err := writeAll(zaStream,
		[]byte{byte(entla >> 8), byte(entla)},
		uid,
		a.Bytes(),
		params.B.Bytes(),
		params.Gx.Bytes(),
		params.Gy.Bytes(),
		leftPad32(pub.X.Bytes()),
		leftPad32(pub.Y.Bytes()),
	); err != nil {
		return zero, err
	}
	za, err := zaStream.Sum()
	if err != nil {
		return zero, err
	}

	msgStream, err := NewSM3Stream()
	if err != nil {
		return zero, err
	}
	defer msgStream.Close()
	if err := writeAll(msgStream, za[:], msg); err != nil {
		return zero, err
	}
	return msgStream.Sum()
}
