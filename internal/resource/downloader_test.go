package resource

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	pkgerrors "taa/pkg/errors"
)

func TestDownloadToTempFile_UnderLimit(t *testing.T) {
	data := strings.Repeat("a", 1024)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(data))
	}))
	defer ts.Close()

	path, size, err := DownloadToTempFile(ts.URL, 2048)
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

func TestDownloadToTempFile_ContentLengthOverLimit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "2048")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("a", 2048)))
	}))
	defer ts.Close()

	_, _, err := DownloadToTempFile(ts.URL, 1024)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var coded *pkgerrors.Error
	if !errors.As(err, &coded) || coded.Code() != pkgerrors.CodeInvalidArgument {
		t.Errorf("expected CodeInvalidArgument (400), got: %v", err)
	}
	if !strings.Contains(err.Error(), "资源过大: 2048 bytes, 上限 1024 bytes") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDownloadToTempFile_ChunkedStreamOverLimit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Do not set Content-Length (chunked transfer)
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		for i := 0; i < 5; i++ {
			_, _ = w.Write([]byte(strings.Repeat("b", 300)))
			if ok {
				flusher.Flush()
			}
		}
	}))
	defer ts.Close()

	_, _, err := DownloadToTempFile(ts.URL, 500)
	if err == nil {
		t.Fatal("expected error for streaming over limit, got nil")
	}
	var coded *pkgerrors.Error
	if !errors.As(err, &coded) || coded.Code() != pkgerrors.CodeInvalidArgument {
		t.Errorf("expected CodeInvalidArgument (400), got: %v", err)
	}
	if !strings.Contains(err.Error(), "资源超过大小上限") {
		t.Errorf("unexpected error message: %v", err)
	}
}
