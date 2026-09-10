package crypto

import (
	"crypto/hmac"
	"fmt"
	"hash"
	"io"
	"os"

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

// HashFileSM3 以流式方式计算文件的 SM3 摘要和大小。
func HashFileSM3(path string) (size int64, hex string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return 0, "", fmt.Errorf("stat %s: %w", path, err)
	}

	h := NewSM3()
	if _, err := io.Copy(h, f); err != nil {
		return 0, "", fmt.Errorf("hash %s: %w", path, err)
	}
	return st.Size(), fmt.Sprintf("%x", h.Sum(nil)), nil
}
