package resource

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
)

// DownloadToTempFile downloads resourceURL to a temp file using http.DefaultClient.
// The download is streamed to disk and is not bounded by a size limit.
func DownloadToTempFile(resourceURL string) (string, int64, error) {
	return DownloadToTempFileWithClient(context.Background(), http.DefaultClient, resourceURL)
}

// DownloadToTempFileWithClient streams resourceURL into a temp file using client,
// bounded by ctx. The download is not bounded by a size limit.
func DownloadToTempFileWithClient(ctx context.Context, client *http.Client, resourceURL string) (string, int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceURL, nil)
	if err != nil {
		return "", 0, err
	}
	resp, err := client.Do(req)
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
