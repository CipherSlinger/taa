package resource

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResourceURLHasEncSuffix(t *testing.T) {
	tests := []struct {
		url      string
		expected bool
	}{
		{"http://example.com/data.tar.gz.enc", true},
		{"http://example.com/data.ENC", true},
		{"http://example.com/data.zip", false},
		{"https://example.com/path/to/archive.tar?token=123", false},
		{"https://example.com/path/to/archive.enc?token=123", true},
	}

	for _, tt := range tests {
		if got := ResourceURLHasEncSuffix(tt.url); got != tt.expected {
			t.Errorf("ResourceURLHasEncSuffix(%q) = %v; want %v", tt.url, got, tt.expected)
		}
	}
}

func TestSafeJoinWithBase(t *testing.T) {
	tmpDir := t.TempDir()
	baseAbs, err := filepath.Abs(tmpDir)
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}

	// 合法相对路径
	joined, err := SafeJoinWithBase(tmpDir, baseAbs, "sub/dir/file.txt")
	if err != nil {
		t.Fatalf("unexpected error for valid path: %v", err)
	}
	if !strings.HasPrefix(joined, baseAbs) {
		t.Fatalf("joined path %s does not have prefix %s", joined, baseAbs)
	}

	// Zip-Slip 路径逃逸测试
	_, err = SafeJoinWithBase(tmpDir, baseAbs, "../../etc/passwd")
	if err == nil {
		t.Fatal("expected error on path traversal, got nil")
	}

	// 绝对路径测试
	_, err = SafeJoinWithBase(tmpDir, baseAbs, "/root/evil")
	if err == nil {
		t.Fatal("expected error on absolute path, got nil")
	}
}

func TestExtractZipArchive(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	w, err := zw.Create("hello.txt")
	if err != nil {
		t.Fatalf("create zip entry: %v", err)
	}
	if _, err := w.Write([]byte("hello world")); err != nil {
		t.Fatalf("write zip content: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}

	dstDir := t.TempDir()
	if err := ExtractZipArchive(dstDir, buf.Bytes()); err != nil {
		t.Fatalf("ExtractZipArchive failed: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(dstDir, "hello.txt"))
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if string(content) != "hello world" {
		t.Fatalf("unexpected extracted content: %s", string(content))
	}
}

func TestExtractTarGzStream(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	content := []byte("tar stream content")
	hdr := &tar.Header{
		Name:     "script.sh",
		Mode:     0o644,
		Size:     int64(len(content)),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("write tar header: %v", err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatalf("write tar content: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}

	tarGzPath := filepath.Join(t.TempDir(), "pkg.tar.gz")
	if err := os.WriteFile(tarGzPath, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write tar.gz file: %v", err)
	}

	dstDir := filepath.Join(t.TempDir(), "extracted")
	if err := ExtractArchiveToDir(dstDir, tarGzPath); err != nil {
		t.Fatalf("ExtractArchiveToDir failed: %v", err)
	}

	outPath := filepath.Join(dstDir, "script.sh")
	outData, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if string(outData) != string(content) {
		t.Fatalf("unexpected extracted data: %s", string(outData))
	}

	// 验证 .sh 脚本自动加可执行权限 (ChmodScripts)
	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("stat script: %v", err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("expected script to have executable permissions, got %o", info.Mode())
	}
}

func TestWriteExtractedFileWithLimitExceeded(t *testing.T) {
	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "huge.bin")

	hugeData := bytes.Repeat([]byte("A"), 1024)
	limit := int64(512)

	_, err := WriteExtractedFileWithLimit(target, bytes.NewReader(hugeData), 0o644, limit)
	if err == nil {
		t.Fatal("expected quota exceeded error, got nil")
	}

	// 验证超额后自动清理了目标文件
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Fatalf("expected target file to be cleaned up, stat returned %v", statErr)
	}
}
