package crypto

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	gmsmsm2 "github.com/tjfoc/gmsm/sm2"
)

const (
	sm2PointSize = 65
	// SM2WrappedKeySize 是 WrapKeySM2 输出的字节长度。
	// gmsm 的 SM2 密文格式为 0x04 || x1(32B) || y1(32B) || c3(32B) || c2(明文长度),
	// 因此对 16 字节数据密钥: 1 + 64 + 32 + 16 = 113。
	SM2WrappedKeySize = 1 + 64 + sm3Size + SM4KeySize
)

var (
	oidPublicKeyECDSA                = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidSM2Curve                      = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
	sm2Curve          elliptic.Curve = gmsmsm2.P256Sm2()
)

type SM2PublicKey struct {
	X *big.Int
	Y *big.Int
}

type SM2PrivateKey struct {
	PublicKey SM2PublicKey
	D         *big.Int
}

// ─── 类型桥接 ────────────────────────────────────────────────────────

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

// ─── 密钥生成 ────────────────────────────────────────────────────────

func GenerateSM2KeyPair() (*SM2PrivateKey, error) {
	priv, err := gmsmsm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("teecrypto: 生成 SM2 密钥对失败: %w", err)
	}
	return &SM2PrivateKey{
		PublicKey: SM2PublicKey{X: priv.X, Y: priv.Y},
		D:         priv.D,
	}, nil
}

// ─── PEM 序列化 ──────────────────────────────────────────────────────

func ParseSM2PublicKeyPEM(pemData []byte) (*SM2PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("teecrypto: 无法解析 PEM 数据(SM2 公钥)")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("teecrypto: PEM 类型不是 SM2 公钥: %s", block.Type)
	}

	var spki sm2SubjectPublicKeyInfo
	if _, err := asn1.Unmarshal(block.Bytes, &spki); err != nil {
		return nil, fmt.Errorf("teecrypto: 解析 SM2 公钥失败: %w", err)
	}
	if !isSM2Algorithm(spki.Algorithm) {
		return nil, errors.New("teecrypto: PEM 中的公钥不是 SM2 类型")
	}
	return parseSM2Point(spki.SubjectPublicKey.Bytes)
}

func ParseSM2PrivateKeyPEM(pemData []byte) (*SM2PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("teecrypto: 无法解析 PEM 数据(SM2 私钥)")
	}

	switch block.Type {
	case "PRIVATE KEY":
		return parseSM2PKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return parseSM2ECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("teecrypto: PEM 类型不是 SM2 私钥: %s", block.Type)
	}
}

func MarshalSM2PublicKeyPEM(pub *SM2PublicKey) ([]byte, error) {
	point, err := marshalSM2Point(pub)
	if err != nil {
		return nil, err
	}
	der, err := asn1.Marshal(sm2SubjectPublicKeyInfo{
		Algorithm:        sm2AlgorithmIdentifier(),
		SubjectPublicKey: asn1.BitString{Bytes: point, BitLength: len(point) * 8},
	})
	if err != nil {
		return nil, fmt.Errorf("teecrypto: 编码 SM2 公钥失败: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func MarshalSM2PrivateKeyPEM(priv *SM2PrivateKey) ([]byte, error) {
	if err := validateSM2PrivateKey(priv); err != nil {
		return nil, err
	}
	ecDer, err := asn1.Marshal(sm2ECPrivateKey{
		Version:    1,
		PrivateKey: sm2ScalarBytes(priv.D),
	})
	if err != nil {
		return nil, fmt.Errorf("teecrypto: 编码 SM2 私钥失败: %w", err)
	}
	der, err := asn1.Marshal(sm2PrivateKeyInfo{
		Version:             0,
		PrivateKeyAlgorithm: sm2AlgorithmIdentifier(),
		PrivateKey:          ecDer,
	})
	if err != nil {
		return nil, fmt.Errorf("teecrypto: 编码 SM2 私钥失败: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ─── SM2 加解密（委托 gmsm）───────────────────────────────────────────

// EncryptSM2 使用 SM2 公钥加密 plaintext。
// 输出格式: 0x04 || x1(32B) || y1(32B) || c3(32B) || c2(明文长度)。
func EncryptSM2(pub *SM2PublicKey, plaintext []byte) ([]byte, error) {
	if err := validateSM2PublicKey(pub); err != nil {
		return nil, err
	}
	if len(plaintext) == 0 {
		return nil, errors.New("teecrypto: SM2 明文不能为空")
	}
	ciphertext, err := gmsmsm2.Encrypt(toGmsmPublicKey(pub), plaintext, rand.Reader, gmsmsm2.C1C3C2)
	if err != nil {
		return nil, fmt.Errorf("teecrypto: SM2 加密失败: %w", err)
	}
	return ciphertext, nil
}

// DecryptSM2 使用 SM2 私钥解密由 EncryptSM2 生成的密文。
func DecryptSM2(priv *SM2PrivateKey, ciphertext []byte) ([]byte, error) {
	if err := validateSM2PrivateKey(priv); err != nil {
		return nil, err
	}
	plaintext, err := gmsmsm2.Decrypt(toGmsmPrivateKey(priv), ciphertext, gmsmsm2.C1C3C2)
	if err != nil {
		return nil, fmt.Errorf("teecrypto: SM2 解密失败: %w", err)
	}
	return plaintext, nil
}

// ─── SM2 签名（委托 gmsm）───────────────────────────────────────────

// SignSM2Signature 使用 SM2 私钥对 msg 生成数字签名。
// userID 为签名者标识,空值时使用默认值 "1234567812345678"。
func SignSM2Signature(priv *SM2PrivateKey, userID, msg []byte) (*big.Int, *big.Int, error) {
	if err := validateSM2PrivateKey(priv); err != nil {
		return nil, nil, err
	}
	r, s, err := gmsmsm2.Sm2Sign(toGmsmPrivateKey(priv), msg, userID, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("teecrypto: SM2 签名失败: %w", err)
	}
	return r, s, nil
}

// VerifySM2Signature 使用 SM2 公钥验证 SM2 数字签名。
func VerifySM2Signature(pub *SM2PublicKey, userID, msg []byte, r, s *big.Int) bool {
	if validateSM2PublicKey(pub) != nil || r == nil || s == nil {
		return false
	}
	return gmsmsm2.Sm2Verify(toGmsmPublicKey(pub), msg, userID, r, s)
}

// ─── PEM ASN.1 结构 ──────────────────────────────────────────────────

type sm2AlgorithmID struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type sm2SubjectPublicKeyInfo struct {
	Algorithm        sm2AlgorithmID
	SubjectPublicKey asn1.BitString
}

type sm2PrivateKeyInfo struct {
	Version             int
	PrivateKeyAlgorithm sm2AlgorithmID
	PrivateKey          []byte
}

type sm2ECPrivateKey struct {
	Version    int
	PrivateKey []byte
}

func parseSM2PKCS8PrivateKey(der []byte) (*SM2PrivateKey, error) {
	var keyInfo sm2PrivateKeyInfo
	if _, err := asn1.Unmarshal(der, &keyInfo); err != nil {
		return nil, fmt.Errorf("teecrypto: 解析 SM2 PKCS#8 私钥失败: %w", err)
	}
	if !isSM2Algorithm(keyInfo.PrivateKeyAlgorithm) {
		return nil, errors.New("teecrypto: PEM 中的私钥不是 SM2 类型")
	}
	return parseSM2ECPrivateKey(keyInfo.PrivateKey)
}

func parseSM2ECPrivateKey(der []byte) (*SM2PrivateKey, error) {
	var ecKey sm2ECPrivateKey
	if _, err := asn1.Unmarshal(der, &ecKey); err != nil {
		return nil, fmt.Errorf("teecrypto: 解析 SM2 EC 私钥失败: %w", err)
	}
	d := new(big.Int).SetBytes(ecKey.PrivateKey)
	if d.Sign() <= 0 || d.Cmp(sm2Curve.Params().N) >= 0 {
		return nil, errors.New("teecrypto: SM2 私钥标量无效")
	}
	x, y := sm2Curve.ScalarBaseMult(sm2ScalarBytes(d))
	if x == nil || y == nil {
		return nil, errors.New("teecrypto: SM2 私钥生成公钥失败")
	}
	return &SM2PrivateKey{PublicKey: SM2PublicKey{X: x, Y: y}, D: d}, nil
}

func sm2AlgorithmIdentifier() sm2AlgorithmID {
	return sm2AlgorithmID{
		Algorithm:  oidPublicKeyECDSA,
		Parameters: asn1RawOID(oidSM2Curve),
	}
}

func isSM2Algorithm(id sm2AlgorithmID) bool {
	if id.Algorithm.Equal(oidSM2Curve) {
		return true
	}
	if !id.Algorithm.Equal(oidPublicKeyECDSA) || len(id.Parameters.FullBytes) == 0 {
		return false
	}
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(id.Parameters.FullBytes, &oid); err != nil {
		return false
	}
	return oid.Equal(oidSM2Curve)
}

func asn1RawOID(oid asn1.ObjectIdentifier) asn1.RawValue {
	der, _ := asn1.Marshal(oid)
	return asn1.RawValue{FullBytes: der}
}

// ─── 校验与辅助函数 ──────────────────────────────────────────────────

func validateSM2PublicKey(pub *SM2PublicKey) error {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return errors.New("teecrypto: SM2 公钥为空")
	}
	if !sm2Curve.IsOnCurve(pub.X, pub.Y) {
		return errors.New("teecrypto: SM2 公钥不在曲线上")
	}
	return nil
}

func validateSM2PrivateKey(priv *SM2PrivateKey) error {
	if priv == nil || priv.D == nil {
		return errors.New("teecrypto: SM2 私钥为空")
	}
	if priv.D.Sign() <= 0 || priv.D.Cmp(sm2Curve.Params().N) >= 0 {
		return errors.New("teecrypto: SM2 私钥标量无效")
	}
	return validateSM2PublicKey(&priv.PublicKey)
}

func marshalSM2Point(pub *SM2PublicKey) ([]byte, error) {
	if err := validateSM2PublicKey(pub); err != nil {
		return nil, err
	}
	return marshalSM2PointUnchecked(pub.X, pub.Y), nil
}

func marshalSM2PointUnchecked(x, y *big.Int) []byte {
	point := make([]byte, sm2PointSize)
	point[0] = 4
	copy(point[1+32-len(x.Bytes()):33], x.Bytes())
	copy(point[33+32-len(y.Bytes()):], y.Bytes())
	return point
}

func parseSM2Point(point []byte) (*SM2PublicKey, error) {
	if len(point) != sm2PointSize || point[0] != 4 {
		return nil, errors.New("teecrypto: SM2 公钥点格式无效")
	}
	x := new(big.Int).SetBytes(point[1:33])
	y := new(big.Int).SetBytes(point[33:])
	pub := &SM2PublicKey{X: x, Y: y}
	if err := validateSM2PublicKey(pub); err != nil {
		return nil, err
	}
	return pub, nil
}

func sm2ScalarBytes(d *big.Int) []byte {
	return leftPad32(d.Bytes())
}

func leftPad32(in []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(in):], in)
	return out
}
