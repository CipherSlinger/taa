package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/tjfoc/gmsm/sm4"
)

const (
	// SM4KeySize 是 SM4 密钥的字节长度。
	SM4KeySize = 16

	// sm4GCMSealedOverhead 是 Encrypt 输出中 nonce 与认证标签的总长度。
	sm4GCMSealedOverhead = 28
)

var (
	// ErrInvalidKeySize 表示传入的密钥长度不是 SM4 所要求的 16 字节。
	ErrInvalidKeySize = errors.New("teecrypto: SM4 密钥必须为 16 字节(SM4-128)")
	// ErrCiphertextTooShort 表示密文长度不足以包含 nonce 与认证标签。
	ErrCiphertextTooShort = errors.New("teecrypto: 密文长度不足,数据已损坏或格式错误")
)

// GenerateSM4Key 生成一个符合 SM4 要求的 16 字节随机密钥。
// 随机源为 crypto/rand,适用于密码学场景。
func GenerateSM4Key() ([]byte, error) {
	key := make([]byte, SM4KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("teecrypto: 生成 SM4 密钥失败: %w", err)
	}
	return key, nil
}

// Encrypt 使用指定的 SM4 密钥以 GCM 模式加密 plaintext。
//
// 返回的密文自包含随机 nonce 与认证标签,格式为:
//
//	nonce(12B) || ciphertext || tag(16B)
//
// 同一份明文每次加密都会因随机 nonce 而得到不同的密文。
// key 必须为 16 字节,否则返回 ErrInvalidKeySize。
func Encrypt(key, plaintext []byte) ([]byte, error) {
	return encryptGCM(nil, key, plaintext)
}

func encryptGCM(dst, key, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	nonceStart := len(dst)
	dst = append(dst, make([]byte, gcm.NonceSize())...)
	nonce := dst[nonceStart:]
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("teecrypto: 生成 nonce 失败: %w", err)
	}

	// Seal 将 nonce 作为前缀写入,并在末尾追加认证标签。
	return gcm.Seal(dst, nonce, plaintext, nil), nil
}

// Decrypt 使用指定的 SM4 密钥解密由 Encrypt 生成的密文。
//
// 若密钥错误、数据被篡改或格式不合法,GCM 的完整性校验会失败并返回错误,
// 不会返回任何明文。key 必须为 16 字节,否则返回 ErrInvalidKeySize。
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize+gcm.Overhead() {
		return nil, ErrCiphertextTooShort
	}

	nonce, sealed := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("teecrypto: 解密失败(密钥错误或数据被篡改): %w", err)
	}
	return plaintext, nil
}

// newGCM 校验密钥长度并构造 SM4-GCM 实例。
func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != SM4KeySize {
		return nil, ErrInvalidKeySize
	}
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("teecrypto: 初始化 SM4 失败: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("teecrypto: 初始化 GCM 失败: %w", err)
	}
	return gcm, nil
}
