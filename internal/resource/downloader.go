package resource

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

// DownloadToTempFile downloads resources from resourceURL to a temp file.
// The download is streamed to disk and is not bounded by a size limit.
func DownloadToTempFile(resourceURL string) (string, int64, error) {
	resp, err := http.Get(resourceURL)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	f, err := os.CreateTemp("", "taa-download-*")
	if err != nil {
		return "", 0, fmt.Errorf("创建临时文件失败: %w", err)
	}
	path := f.Name()

	n, err := io.Copy(f, resp.Body)
	f.Close()
	if err != nil {
		_ = os.Remove(path)
		return "", 0, fmt.Errorf("下载写入失败: %w", err)
	}
	return path, n, nil
}
