package resource

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

const (
	// DefaultMaxDownloadBytes 资源下载最大上限 (10 GB)
	DefaultMaxDownloadBytes = 10 << 30
)

// DownloadToTempFile 从指定 URL 下载资源并写入安全临时文件，支持大小限制与配额校验
func DownloadToTempFile(resourceURL string, maxBytes int64) (string, int64, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxDownloadBytes
	}

	resp, err := http.Get(resourceURL)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > maxBytes {
		return "", 0, fmt.Errorf("资源过大: %d bytes, 上限 %d bytes", resp.ContentLength, maxBytes)
	}

	f, err := os.CreateTemp("", "taa-download-*")
	if err != nil {
		return "", 0, fmt.Errorf("创建临时文件失败: %w", err)
	}
	path := f.Name()

	reader := io.LimitReader(resp.Body, maxBytes+1)
	n, err := io.Copy(f, reader)
	f.Close()
	if err != nil {
		_ = os.Remove(path)
		return "", 0, fmt.Errorf("下载写入失败: %w", err)
	}
	if n > maxBytes {
		_ = os.Remove(path)
		return "", 0, fmt.Errorf("资源超过大小上限: %d bytes > %d bytes", n, maxBytes)
	}
	return path, n, nil
}
