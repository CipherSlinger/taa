package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"
)

// RandomHex 生成指定字节数的随机十六进制字符串。
func RandomHex(byteCount int) (string, error) {
	if byteCount <= 0 {
		return "", nil
	}
	buf := make([]byte, byteCount)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read secure random: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// RandomString 使用指定的字母表生成安全随机字符串。
func RandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	if length <= 0 {
		return ""
	}
	b := make([]byte, length)
	max := big.NewInt(int64(len(charset)))
	for i := range b {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			b[i] = charset[i%len(charset)]
			continue
		}
		b[i] = charset[n.Int64()]
	}
	return string(b)
}

// FormatBytes 将字节数转换为人类友好的可读字符串（B, KB, MB, GB, TB）。
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	units := []string{"KB", "MB", "GB", "TB", "PB"}
	return fmt.Sprintf("%.2f %s", float64(bytes)/float64(div), units[exp])
}

// FormatISO8601 格式化时间为标准的 ISO8601 / RFC3339 UTC 字符串。
func FormatISO8601(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// ParseISO8601 解析 ISO8601 / RFC3339 格式的时间字符串为 UTC 时间。
func ParseISO8601(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}
