// Package crypto 提供向后兼容的过渡垫片层，底层全部委托给 taa/pkg/crypto。
// 新增业务代码请直接导入 taa/pkg/crypto。
package crypto

import (
	"crypto/rsa"
	"hash"
	"io"
	"math/big"

	pkgcrypto "taa/pkg/crypto"
)

// 常量定义
const (
	SM4KeySize = pkgcrypto.SM4KeySize
)

// 错误变量导出
var (
	ErrInvalidKeySize     = pkgcrypto.ErrInvalidKeySize
	ErrCiphertextTooShort = pkgcrypto.ErrCiphertextTooShort
	ErrRSAKeyTooShort     = pkgcrypto.ErrRSAKeyTooShort
	ErrNilEnvelope        = pkgcrypto.ErrNilEnvelope
)

// 类型别名导出
type (
	SM2PublicKey  = pkgcrypto.SM2PublicKey
	SM2PrivateKey = pkgcrypto.SM2PrivateKey
	Envelope      = pkgcrypto.Envelope
)

// GenerateSM4Key 生成符合 SM4 要求的 16 字节随机密钥
func GenerateSM4Key() ([]byte, error) {
	return pkgcrypto.GenerateSM4Key()
}

// Encrypt 使用 SM4 密钥以 GCM 模式加密明文
func Encrypt(key, plaintext []byte) ([]byte, error) {
	return pkgcrypto.Encrypt(key, plaintext)
}

// Decrypt 使用 SM4 密钥解密 GCM 密文
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	return pkgcrypto.Decrypt(key, ciphertext)
}

// GenerateSM2KeyPair 生成 SM2 椭圆曲线非对称密钥对
func GenerateSM2KeyPair() (*SM2PrivateKey, error) {
	return pkgcrypto.GenerateSM2KeyPair()
}

// ParseSM2PublicKeyPEM 从 PEM 编码中解析 SM2 公钥
func ParseSM2PublicKeyPEM(pemData []byte) (*SM2PublicKey, error) {
	return pkgcrypto.ParseSM2PublicKeyPEM(pemData)
}

// ParseSM2PrivateKeyPEM 从 PEM 编码中解析 SM2 私钥
func ParseSM2PrivateKeyPEM(pemData []byte) (*SM2PrivateKey, error) {
	return pkgcrypto.ParseSM2PrivateKeyPEM(pemData)
}

// MarshalSM2PublicKeyPEM 将 SM2 公钥序列化为 PEM 格式
func MarshalSM2PublicKeyPEM(pub *SM2PublicKey) ([]byte, error) {
	return pkgcrypto.MarshalSM2PublicKeyPEM(pub)
}

// MarshalSM2PrivateKeyPEM 将 SM2 私钥序列化为 PEM 格式
func MarshalSM2PrivateKeyPEM(priv *SM2PrivateKey) ([]byte, error) {
	return pkgcrypto.MarshalSM2PrivateKeyPEM(priv)
}

// EncryptSM2 使用 SM2 公钥加密明文
func EncryptSM2(pub *SM2PublicKey, plaintext []byte) ([]byte, error) {
	return pkgcrypto.EncryptSM2(pub, plaintext)
}

// DecryptSM2 使用 SM2 私钥解密密文
func DecryptSM2(priv *SM2PrivateKey, ciphertext []byte) ([]byte, error) {
	return pkgcrypto.DecryptSM2(priv, ciphertext)
}

// SignSM2Signature 使用 SM2 私钥对消息执行国密数字签名
func SignSM2Signature(priv *SM2PrivateKey, userID, msg []byte) (*big.Int, *big.Int, error) {
	return pkgcrypto.SignSM2Signature(priv, userID, msg)
}

// VerifySM2Signature 使用 SM2 公钥校验国密数字签名
func VerifySM2Signature(pub *SM2PublicKey, userID, msg []byte, r, s *big.Int) bool {
	return pkgcrypto.VerifySM2Signature(pub, userID, msg, r, s)
}

// NewSM3 创建国密 SM3 杂凑实例
func NewSM3() hash.Hash {
	return pkgcrypto.NewSM3()
}

// SM3Sum 计算数据的 32 字节 SM3 杂凑摘要
func SM3Sum(data []byte) [32]byte {
	return pkgcrypto.SM3Sum(data)
}

// HMACSM3 计算基于 SM3 的 HMAC
func HMACSM3(key, data []byte) [32]byte {
	return pkgcrypto.HMACSM3(key, data)
}

// HashFileSM3 计算指定文件的 SM3 摘要及十六进制字符串
func HashFileSM3(path string) (size int64, hex string, err error) {
	return pkgcrypto.HashFileSM3(path)
}

// WrapKeySM2 使用 SM2 公钥封装对称密钥
func WrapKeySM2(pub *SM2PublicKey, dataKey []byte) ([]byte, error) {
	return pkgcrypto.WrapKeySM2(pub, dataKey)
}

// UnwrapKeySM2 使用 SM2 私钥解封对称密钥
func UnwrapKeySM2(priv *SM2PrivateKey, envelope []byte) ([]byte, error) {
	return pkgcrypto.UnwrapKeySM2(priv, envelope)
}

// SealSM2 对明文执行 SM2 + SM4 信封加密
func SealSM2(pub *SM2PublicKey, plaintext []byte) (*Envelope, error) {
	return pkgcrypto.SealSM2(pub, plaintext)
}

// SealSM2SM4GCM 对明文执行自包含 SM2 + SM4-GCM 封装
func SealSM2SM4GCM(pub *SM2PublicKey, plaintext []byte) ([]byte, error) {
	return pkgcrypto.SealSM2SM4GCM(pub, plaintext)
}

// OpenSM2 解封并解密信封数据
func OpenSM2(priv *SM2PrivateKey, env *Envelope) ([]byte, error) {
	return pkgcrypto.OpenSM2(priv, env)
}

// OpenSM2SM4GCM 解封并解密自包含二进制封装数据
func OpenSM2SM4GCM(priv *SM2PrivateKey, sealed []byte) ([]byte, error) {
	return pkgcrypto.OpenSM2SM4GCM(priv, sealed)
}

// GenerateRSAKeyPair 生成指定位数的 RSA 密钥对
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, error) {
	return pkgcrypto.GenerateRSAKeyPair(bits)
}

// ParseRSAPublicKeyPEM 从 PEM 编码中解析 RSA 公钥
func ParseRSAPublicKeyPEM(pemData []byte) (*rsa.PublicKey, error) {
	return pkgcrypto.ParseRSAPublicKeyPEM(pemData)
}

// ParseRSAPrivateKeyPEM 从 PEM 编码中解析 RSA 私钥
func ParseRSAPrivateKeyPEM(pemData []byte) (*rsa.PrivateKey, error) {
	return pkgcrypto.ParseRSAPrivateKeyPEM(pemData)
}

// MarshalRSAPublicKeyPEM 将 RSA 公钥序列化为 PEM 格式
func MarshalRSAPublicKeyPEM(pub *rsa.PublicKey) ([]byte, error) {
	return pkgcrypto.MarshalRSAPublicKeyPEM(pub)
}

// MarshalRSAPrivateKeyPEM 将 RSA 私钥序列化为 PEM 格式
func MarshalRSAPrivateKeyPEM(priv *rsa.PrivateKey) ([]byte, error) {
	return pkgcrypto.MarshalRSAPrivateKeyPEM(priv)
}

// CreateTarGzArchive 将多个源文件打包并压缩为 tar.gz
func CreateTarGzArchive(sources []string, outputPath string) error {
	return pkgcrypto.CreateTarGzArchive(sources, outputPath)
}

// CreateTarGzArchiveWriter 将多个源文件打包写入指定的 io.Writer
func CreateTarGzArchiveWriter(sources []string, w io.Writer) error {
	return pkgcrypto.CreateTarGzArchiveWriter(sources, w)
}

// ExtractTarGzArchive 将 tar.gz 归档解压到指定目录
func ExtractTarGzArchive(tarGzPath string, outputDir string) error {
	return pkgcrypto.ExtractTarGzArchive(tarGzPath, outputDir)
}

// ExtractTarGzReader 从 io.Reader 读取并解压 tar.gz 到指定目录
func ExtractTarGzReader(r io.Reader, outputDir string) error {
	return pkgcrypto.ExtractTarGzReader(r, outputDir)
}

// ExtractZipArchive 解压 zip 压缩包字节流到指定目录
func ExtractZipArchive(data []byte, outputDir string) error {
	return pkgcrypto.ExtractZipArchive(data, outputDir)
}
