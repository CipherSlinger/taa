package crypto

import (
	"bytes"
	"testing"
)

func TestGenerateSM4Key(t *testing.T) {
	k1, err := GenerateSM4Key()
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	if len(k1) != SM4KeySize {
		t.Fatalf("密钥长度应为 %d,实际 %d", SM4KeySize, len(k1))
	}
	k2, _ := GenerateSM4Key()
	if bytes.Equal(k1, k2) {
		t.Fatal("两次生成的密钥不应相同")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key, _ := GenerateSM4Key()
	plaintext := []byte("可信数字空间 TEE — sensitive payload 42")

	ct, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	if bytes.Contains(ct, plaintext) {
		t.Fatal("密文中不应出现明文")
	}

	got, err := Decrypt(key, ct)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("解密结果不匹配: %q", got)
	}
}

func TestEncryptIsNondeterministic(t *testing.T) {
	key, _ := GenerateSM4Key()
	pt := []byte("same input")
	c1, _ := Encrypt(key, pt)
	c2, _ := Encrypt(key, pt)
	if bytes.Equal(c1, c2) {
		t.Fatal("相同明文两次加密应因随机 nonce 而不同")
	}
}

func TestDecryptWrongKeyFails(t *testing.T) {
	key, _ := GenerateSM4Key()
	other, _ := GenerateSM4Key()
	ct, _ := Encrypt(key, []byte("secret"))
	if _, err := Decrypt(other, ct); err == nil {
		t.Fatal("使用错误密钥解密应失败")
	}
}

func TestDecryptTamperedFails(t *testing.T) {
	key, _ := GenerateSM4Key()
	ct, _ := Encrypt(key, []byte("secret"))
	ct[len(ct)-1] ^= 0xFF // 篡改认证标签
	if _, err := Decrypt(key, ct); err == nil {
		t.Fatal("篡改后的密文应校验失败")
	}
}

func TestInvalidKeySize(t *testing.T) {
	if _, err := Encrypt([]byte("short"), []byte("x")); err != ErrInvalidKeySize {
		t.Fatalf("应返回 ErrInvalidKeySize,实际 %v", err)
	}
	if _, err := Decrypt(make([]byte, 15), make([]byte, 64)); err != ErrInvalidKeySize {
		t.Fatalf("应返回 ErrInvalidKeySize,实际 %v", err)
	}
}

func TestDecryptTooShort(t *testing.T) {
	key, _ := GenerateSM4Key()
	if _, err := Decrypt(key, []byte("tiny")); err != ErrCiphertextTooShort {
		t.Fatalf("应返回 ErrCiphertextTooShort,实际 %v", err)
	}
}


func TestSM3KnownDigests(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want []byte
	}{
		{
			name: "empty",
			want: []byte{0x1a, 0xb2, 0x1d, 0x83, 0x55, 0xcf, 0xa1, 0x7f, 0x8e, 0x61, 0x19, 0x48, 0x31, 0xe8, 0x1a, 0x8f, 0x22, 0xbe, 0xc8, 0xc7, 0x28, 0xfe, 0xfb, 0x74, 0x7e, 0xd0, 0x35, 0xeb, 0x50, 0x82, 0xaa, 0x2b},
		},
		{
			name: "abc",
			in:   []byte("abc"),
			want: []byte{0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2, 0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0},
		},
	}
	for _, tc := range cases {
		got := SM3Sum(tc.in)
		if !bytes.Equal(got[:], tc.want) {
			t.Fatalf("SM3 %s 摘要不匹配: %x", tc.name, got)
		}
	}
}

func TestSM2PEMRoundTrip(t *testing.T) {
	priv := newTestSM2Key(t)

	pubPEM, err := MarshalSM2PublicKeyPEM(&priv.PublicKey)
	if err != nil {
		t.Fatalf("编码 SM2 公钥失败: %v", err)
	}
	parsedPub, err := ParseSM2PublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("解析 SM2 公钥失败: %v", err)
	}
	if parsedPub.X.Cmp(priv.PublicKey.X) != 0 || parsedPub.Y.Cmp(priv.PublicKey.Y) != 0 {
		t.Fatal("SM2 公钥 PEM 往返不匹配")
	}

	privPEM, err := MarshalSM2PrivateKeyPEM(priv)
	if err != nil {
		t.Fatalf("编码 SM2 私钥失败: %v", err)
	}
	parsedPriv, err := ParseSM2PrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatalf("解析 SM2 私钥失败: %v", err)
	}
	if parsedPriv.D.Cmp(priv.D) != 0 || parsedPriv.PublicKey.X.Cmp(priv.PublicKey.X) != 0 || parsedPriv.PublicKey.Y.Cmp(priv.PublicKey.Y) != 0 {
		t.Fatal("SM2 私钥 PEM 往返不匹配")
	}
}

func TestSM2EncryptDecrypt(t *testing.T) {
	priv := newTestSM2Key(t)
	plaintext := []byte("SM2 key wrap payload")
	ciphertext, err := EncryptSM2(&priv.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("SM2 加密失败: %v", err)
	}
	if bytes.Contains(ciphertext, plaintext) {
		t.Fatal("SM2 密文中不应出现明文")
	}
	got, err := DecryptSM2(priv, ciphertext)
	if err != nil {
		t.Fatalf("SM2 解密失败: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("SM2 解密结果不匹配: %q", got)
	}
}

func TestSM2DecryptTamperedFails(t *testing.T) {
	priv := newTestSM2Key(t)
	ciphertext, err := EncryptSM2(&priv.PublicKey, []byte("secret"))
	if err != nil {
		t.Fatalf("SM2 加密失败: %v", err)
	}
	ciphertext[len(ciphertext)-1] ^= 0xFF
	if _, err := DecryptSM2(priv, ciphertext); err == nil {
		t.Fatal("篡改后的 SM2 密文应失败")
	}
}

func TestSealOpenSM2RoundTrip(t *testing.T) {
	priv := newTestSM2Key(t)
	plaintext := []byte("信封加密:对称加密数据 + SM2 保护数据密钥")
	env, err := SealSM2(&priv.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("SM2 Seal 失败: %v", err)
	}
	if len(env.WrappedKey) != SM2WrappedKeySize {
		t.Fatalf("SM2 密钥信封长度不匹配: %d", len(env.WrappedKey))
	}
	got, err := OpenSM2(priv, env)
	if err != nil {
		t.Fatalf("SM2 Open 失败: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("SM2 信封解密结果不匹配: %q", got)
	}
}

func TestSM2EncryptDecryptLargePlaintext(t *testing.T) {
	priv := newTestSM2Key(t)
	plaintext := bytes.Repeat([]byte("SM2-KDF-多轮"), 40)
	ciphertext, err := EncryptSM2(&priv.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("SM2 加密失败: %v", err)
	}
	got, err := DecryptSM2(priv, ciphertext)
	if err != nil {
		t.Fatalf("SM2 解密失败: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("跨多个 KDF 块的 SM2 解密结果不匹配")
	}
}

func TestSM2DecryptTamperedPointFails(t *testing.T) {
	priv := newTestSM2Key(t)
	ciphertext, err := EncryptSM2(&priv.PublicKey, []byte("secret"))
	if err != nil {
		t.Fatalf("SM2 加密失败: %v", err)
	}
	ciphertext[1] ^= 0xFF
	if _, err := DecryptSM2(priv, ciphertext); err == nil {
		t.Fatal("篡改 SM2 C1 点后解密应失败")
	}
}

func TestOpenSM2WrongKeyFails(t *testing.T) {
	priv := newTestSM2Key(t)
	other := newTestSM2Key(t)
	env, err := SealSM2(&priv.PublicKey, []byte("secret"))
	if err != nil {
		t.Fatalf("SM2 Seal 失败: %v", err)
	}
	if _, err := OpenSM2(other, env); err == nil {
		t.Fatal("使用错误 SM2 私钥解密应失败")
	}
}

func newTestSM2Key(t *testing.T) *SM2PrivateKey {
	t.Helper()
	priv, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("生成 SM2 密钥对失败: %v", err)
	}
	return priv
}

