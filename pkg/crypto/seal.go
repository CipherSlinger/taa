package crypto

import (
	"errors"
	"fmt"
)

// ErrNilEnvelope 表示未提供待解开的信封。
var ErrNilEnvelope = errors.New("teecrypto: 信封为空")

// Envelope 表示一次信封加密的完整结果:
//
//   - WrappedKey 是被 SM2 公钥包裹的一次性数据密钥(密钥信封)。
//   - Ciphertext 是用该数据密钥经 SM4-GCM 加密后的密文。
//
// 接收方先用 SM2 私钥解开 WrappedKey 得到数据密钥,再用其解密 Ciphertext。
type Envelope struct {
	WrappedKey []byte
	Ciphertext []byte
}

// ─── SM2 信封加密 ────────────────────────────────────────────────────

func WrapKeySM2(pub *SM2PublicKey, dataKey []byte) ([]byte, error) {
	if len(dataKey) != SM4KeySize {
		return nil, ErrInvalidKeySize
	}
	wrapped, err := EncryptSM2(pub, dataKey)
	if err != nil {
		return nil, fmt.Errorf("teecrypto: 生成 SM2 密钥信封失败: %w", err)
	}
	return wrapped, nil
}

func UnwrapKeySM2(priv *SM2PrivateKey, envelope []byte) ([]byte, error) {
	if len(envelope) != SM2WrappedKeySize {
		return nil, fmt.Errorf("teecrypto: SM2 密钥信封长度无效: %d", len(envelope))
	}
	dataKey, err := DecryptSM2(priv, envelope)
	if err != nil {
		return nil, fmt.Errorf("teecrypto: 解开 SM2 密钥信封失败: %w", err)
	}
	if len(dataKey) != SM4KeySize {
		return nil, ErrInvalidKeySize
	}
	return dataKey, nil
}

func SealSM2(pub *SM2PublicKey, plaintext []byte) (*Envelope, error) {
	dataKey, err := GenerateSM4Key()
	if err != nil {
		return nil, err
	}
	wrappedKey, err := WrapKeySM2(pub, dataKey)
	if err != nil {
		return nil, err
	}
	ciphertext, err := Encrypt(dataKey, plaintext)
	if err != nil {
		return nil, err
	}
	return &Envelope{WrappedKey: wrappedKey, Ciphertext: ciphertext}, nil
}

func splitSM2Envelope(sealed []byte) (*Envelope, error) {
	if len(sealed) <= SM2WrappedKeySize {
		return nil, fmt.Errorf("teecrypto: SM2 密文长度无效: %d", len(sealed))
	}
	return &Envelope{
		WrappedKey: sealed[:SM2WrappedKeySize],
		Ciphertext: sealed[SM2WrappedKeySize:],
	}, nil
}

// SealSM2SM4GCM 将 SM2 密钥信封和 SM4-GCM 密文封装为单个字节切片。
//
// 返回格式为:
//
//	WrappedKey(SM2WrappedKeySize 字节) || Ciphertext(剩余字节)
func SealSM2SM4GCM(pub *SM2PublicKey, plaintext []byte) ([]byte, error) {
	dataKey, err := GenerateSM4Key()
	if err != nil {
		return nil, err
	}
	wrappedKey, err := WrapKeySM2(pub, dataKey)
	if err != nil {
		return nil, err
	}

	sealed := make([]byte, 0, len(wrappedKey)+len(plaintext)+sm4GCMSealedOverhead)
	sealed = append(sealed, wrappedKey...)
	return encryptGCM(sealed, dataKey, plaintext)
}

func OpenSM2(priv *SM2PrivateKey, env *Envelope) ([]byte, error) {
	if env == nil {
		return nil, ErrNilEnvelope
	}
	dataKey, err := UnwrapKeySM2(priv, env.WrappedKey)
	if err != nil {
		return nil, err
	}
	return Decrypt(dataKey, env.Ciphertext)
}

// OpenSM2SM4GCM 将 SM2WrappedKeySize 前缀的密文切分成密钥信封和 SM4-GCM 密文后解密。
func OpenSM2SM4GCM(priv *SM2PrivateKey, sealed []byte) ([]byte, error) {
	env, err := splitSM2Envelope(sealed)
	if err != nil {
		return nil, err
	}
	return OpenSM2(priv, env)
}
