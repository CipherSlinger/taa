package resource

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestDownloadToTempFile(t *testing.T) {
	data := strings.Repeat("a", 1024)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(data))
	}))
	defer ts.Close()

	path, size, err := DownloadToTempFile(ts.URL)
	if err != nil {
		t.Fatalf("DownloadToTempFile failed: %v", err)
	}
	defer os.Remove(path)

	if size != 1024 {
		t.Errorf("size = %d, want 1024", size)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if string(content) != data {
		t.Errorf("content does not match downloaded payload")
	}
}

// TestDownloadToTempFile_ChunkedLargeStream verifies that the streamed download
// is not truncated regardless of Content-Length presence or payload size.
func TestDownloadToTempFile_ChunkedLargeStream(t *testing.T) {
	const chunks, chunkSize = 64, 64 * 1024
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No Content-Length: chunked transfer.
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		for i := 0; i < chunks; i++ {
			_, _ = w.Write([]byte(strings.Repeat("b", chunkSize)))
			if ok {
				flusher.Flush()
			}
		}
	}))
	defer ts.Close()

	path, _, err := DownloadToTempFile(ts.URL)
	if err != nil {
		t.Fatalf("DownloadToTempFile failed: %v", err)
	}
	defer os.Remove(path)

	want := int64(chunks * chunkSize)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat downloaded file: %v", err)
	}
	if fi.Size() != want {
		t.Errorf("on-disk size = %d, want %d", fi.Size(), want)
	}
}
