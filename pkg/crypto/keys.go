package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// ErrRSAKeyTooShort 表示请求生成的 RSA 密钥位数低于安全下限(2048)。
// 与 aes.go 的 ErrInvalidKeySize 保持同一 sentinel 约定,供 errors.Is 判定。
var ErrRSAKeyTooShort = errors.New("teecrypto: RSA 密钥长度过短,至少 2048 位")

// GenerateRSAKeyPair 生成用于密钥信封的 RSA 密钥对。
//
// bits 建议至少 2048;生产环境常用 2048 或 3072。私钥仅应保存在解密方
// (通常是 TEE 内部),公钥可对外分发给加密方。
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, error) {
	if bits < 2048 {
		return nil, fmt.Errorf("%w(当前 %d 位)", ErrRSAKeyTooShort, bits)
	}
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("teecrypto: 生成 RSA 密钥对失败: %w", err)
	}
	return priv, nil
}

// ParseRSAPublicKeyPEM 从 PEM 编码解析 RSA 公钥。
//
// 同时支持两种常见格式:
//   - PKCS#1 ("RSA PUBLIC KEY")
//   - PKIX/SubjectPublicKeyInfo ("PUBLIC KEY",OpenSSL 默认)
func ParseRSAPublicKeyPEM(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("teecrypto: 无法解析 PEM 数据(公钥)")
	}

	// 优先尝试 PKIX 格式。
	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("teecrypto: PEM 中的公钥不是 RSA 类型")
		}
		return rsaPub, nil
	}

	// 回退到 PKCS#1 格式。
	rsaPub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("teecrypto: 解析 RSA 公钥失败: %w", err)
	}
	return rsaPub, nil
}

// ParseRSAPrivateKeyPEM 从 PEM 编码解析 RSA 私钥。
//
// 同时支持 PKCS#1 ("RSA PRIVATE KEY") 与 PKCS#8 ("PRIVATE KEY") 两种格式。
func ParseRSAPrivateKeyPEM(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("teecrypto: 无法解析 PEM 数据(私钥)")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("teecrypto: 解析 RSA 私钥失败: %w", err)
	}
	rsaPriv, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("teecrypto: PEM 中的私钥不是 RSA 类型")
	}
	return rsaPriv, nil
}

// MarshalRSAPublicKeyPEM 将 RSA 公钥编码为 PKIX/PEM 格式,便于分发。
func MarshalRSAPublicKeyPEM(pub *rsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("teecrypto: 编码 RSA 公钥失败: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// MarshalRSAPrivateKeyPEM 将 RSA 私钥编码为 PKCS#8/PEM 格式。
func MarshalRSAPrivateKeyPEM(priv *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("teecrypto: 编码 RSA 私钥失败: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
