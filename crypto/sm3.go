package crypto

import (
	"crypto/hmac"
	"hash"

	gmsmsm3 "github.com/tjfoc/gmsm/sm3"
)

const sm3Size = 32

// NewSM3 返回 SM3 哈希实现。
func NewSM3() hash.Hash {
	return gmsmsm3.New()
}

func toFixedSize(sum []byte) [sm3Size]byte {
	var out [sm3Size]byte
	copy(out[:], sum)
	return out
}

// SM3Sum 计算数据的 SM3 摘要。
func SM3Sum(data []byte) [sm3Size]byte {
	return toFixedSize(gmsmsm3.Sm3Sum(data))
}

// HMACSM3 使用指定密钥计算数据的 HMAC-SM3。
func HMACSM3(key, data []byte) [sm3Size]byte {
	h := hmac.New(gmsmsm3.New, key)
	h.Write(data)
	return toFixedSize(h.Sum(nil))
}
