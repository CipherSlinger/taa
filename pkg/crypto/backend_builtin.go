package crypto

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"fmt"
	"hash"
	"math/big"

	gmsmsm2 "github.com/tjfoc/gmsm/sm2"
	gmsmsm3 "github.com/tjfoc/gmsm/sm3"
	"github.com/tjfoc/gmsm/sm4"
)

// builtinBackend is the pure-Go implementation (gmsm) used everywhere HCT is
// not explicitly selected, including unit tests and the platform mock.
type builtinBackend struct{}

func (builtinBackend) Name() string { return BackendBuiltin }

func toGmsmPublicKey(pub *SM2PublicKey) *gmsmsm2.PublicKey {
	return &gmsmsm2.PublicKey{
		Curve: sm2Curve,
		X:     pub.X,
		Y:     pub.Y,
	}
}

func toGmsmPrivateKey(priv *SM2PrivateKey) *gmsmsm2.PrivateKey {
	return &gmsmsm2.PrivateKey{
		PublicKey: gmsmsm2.PublicKey{
			Curve: sm2Curve,
			X:     priv.PublicKey.X,
			Y:     priv.PublicKey.Y,
		},
		D: priv.D,
	}
}

func (builtinBackend) GenerateSM2KeyPair() (*SM2PrivateKey, error) {
	priv, err := gmsmsm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("teecrypto: 生成 SM2 密钥对失败: %w", err)
	}
	return &SM2PrivateKey{
		PublicKey: SM2PublicKey{X: priv.X, Y: priv.Y},
		D:         priv.D,
	}, nil
}

func (builtinBackend) EncryptSM2(pub *SM2PublicKey, plaintext []byte) ([]byte, error) {
	ciphertext, err := gmsmsm2.Encrypt(toGmsmPublicKey(pub), plaintext, rand.Reader, gmsmsm2.C1C3C2)
	if err != nil {
		return nil, fmt.Errorf("teecrypto: SM2 加密失败: %w", err)
	}
	return ciphertext, nil
}

func (builtinBackend) DecryptSM2(priv *SM2PrivateKey, ciphertext []byte) ([]byte, error) {
	plaintext, err := gmsmsm2.Decrypt(toGmsmPrivateKey(priv), ciphertext, gmsmsm2.C1C3C2)
	if err != nil {
		return nil, fmt.Errorf("teecrypto: SM2 解密失败: %w", err)
	}
	return plaintext, nil
}

func (builtinBackend) SignSM2(priv *SM2PrivateKey, userID, msg []byte) (*big.Int, *big.Int, error) {
	r, s, err := gmsmsm2.Sm2Sign(toGmsmPrivateKey(priv), msg, userID, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("teecrypto: SM2 签名失败: %w", err)
	}
	return r, s, nil
}

func (builtinBackend) VerifySM2(pub *SM2PublicKey, userID, msg []byte, r, s *big.Int) bool {
	return gmsmsm2.Sm2Verify(toGmsmPublicKey(pub), msg, userID, r, s)
}

func (builtinBackend) SM3Sum(data []byte) ([sm3Size]byte, error) {
	return toFixedSize(gmsmsm3.Sm3Sum(data)), nil
}

func (builtinBackend) HMACSM3(key, data []byte) ([sm3Size]byte, error) {
	h := hmac.New(gmsmsm3.New, key)
	h.Write(data)
	return toFixedSize(h.Sum(nil)), nil
}

func (builtinBackend) NewSM3Stream() (SM3Stream, error) {
	return &builtinSM3Stream{h: gmsmsm3.New()}, nil
}

func (builtinBackend) NewGCM(key []byte) (GCM, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("teecrypto: 初始化 SM4 失败: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("teecrypto: 初始化 GCM 失败: %w", err)
	}
	return builtinGCM{AEAD: gcm}, nil
}

type builtinSM3Stream struct {
	h hash.Hash
}

func (s *builtinSM3Stream) Write(p []byte) (int, error) {
	return s.h.Write(p)
}

func (s *builtinSM3Stream) Sum() ([sm3Size]byte, error) {
	return toFixedSize(s.h.Sum(nil)), nil
}

func (s *builtinSM3Stream) Close() error {
	return nil
}

type builtinGCM struct {
	cipher.AEAD
}

func (g builtinGCM) Seal(dst, nonce, plaintext, aad []byte) ([]byte, error) {
	return g.AEAD.Seal(dst, nonce, plaintext, aad), nil
}
