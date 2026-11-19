package crypto

import (
	"fmt"
	"hash"
	"io"
	"os"

	gmsmsm3 "github.com/tjfoc/gmsm/sm3"
)

const sm3Size = 32

// NewSM3 返回 SM3 哈希实现。
//
// It always uses the built-in implementation: it is a plain hash.Hash used by
// compatibility code (and tests) that cannot consume the streaming backend
// interface. Production paths that hash untrusted input use SM3Sum,
// HMACSM3 or NewSM3Stream so the selected backend is honoured.
func NewSM3() hash.Hash {
	return gmsmsm3.New()
}

func toFixedSize(sum []byte) [sm3Size]byte {
	var out [sm3Size]byte
	copy(out[:], sum)
	return out
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

	stream, err := NewSM3Stream()
	if err != nil {
		return 0, "", fmt.Errorf("hash %s: %w", path, err)
	}
	defer stream.Close()

	if _, err := io.Copy(stream, f); err != nil {
		return 0, "", fmt.Errorf("hash %s: %w", path, err)
	}
	sum, err := stream.Sum()
	if err != nil {
		return 0, "", fmt.Errorf("hash %s: %w", path, err)
	}
	return st.Size(), fmt.Sprintf("%x", sum[:]), nil
}
