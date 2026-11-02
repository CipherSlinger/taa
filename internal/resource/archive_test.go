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

func TestWriteExtractedFileDoesNotTruncate(t *testing.T) {
	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "payload.bin")

	// 8 MiB of non-repeating data so a truncated copy cannot match by accident.
	payload := make([]byte, 8<<20)
	for i := range payload {
		payload[i] = byte(i * 7)
	}

	n, err := WriteExtractedFile(target, bytes.NewReader(payload), 0o644)
	if err != nil {
		t.Fatalf("WriteExtractedFile failed: %v", err)
	}
	if n != int64(len(payload)) {
		t.Fatalf("WriteExtractedFile wrote %d bytes; want %d", n, len(payload))
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat extracted file: %v", err)
	}
	if info.Size() != int64(len(payload)) {
		t.Fatalf("extracted file is %d bytes; want %d", info.Size(), len(payload))
	}
}

// extractedFiles returns every regular file under root, keyed by its slash
// path relative to root. Directories are deliberately left out: an empty
// metadata directory is still a defect, so the callers check for it by name.
func extractedFiles(t *testing.T, root string) map[string]bool {
	t.Helper()
	got := map[string]bool{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		got[filepath.ToSlash(rel)] = true
		return nil
	})
	if err != nil {
		t.Fatalf("walk extracted tree: %v", err)
	}
	return got
}

// assertOnlyContent checks that extraction kept the real source and dropped
// every packaging metadata entry, including a backslash-spelled one.
func assertOnlyContent(t *testing.T, dst string) {
	t.Helper()
	got := extractedFiles(t, dst)
	if len(got) != 1 || !got["train.py"] {
		t.Fatalf("extracted files = %v, want only train.py", got)
	}
	if _, err := os.Stat(filepath.Join(dst, "__MACOSX")); !os.IsNotExist(err) {
		t.Errorf("__MACOSX directory exists after extraction (err=%v), want it dropped", err)
	}
}

func TestExtractZipArchiveSkipsPackagingMetadata(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	entries := []struct{ name, content string }{
		{"train.py", "print('ok')\n"},
		{"__MACOSX/._train.py", "\x00\x05\x16\x07appledouble"},
		{"__MACOSX/sub/._train.py", "appledouble"},
		{"pkg/models/._weights.py", "appledouble"},
		{"pkg\\models\\._weights.py", "appledouble"},
		{".DS_Store", "finder"},
		{"pkg/.DS_Store", "finder"},
	}
	for _, e := range entries {
		w, err := zw.Create(e.name)
		if err != nil {
			t.Fatalf("create zip entry %q: %v", e.name, err)
		}
		if _, err := w.Write([]byte(e.content)); err != nil {
			t.Fatalf("write zip entry %q: %v", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}

	dst := t.TempDir()
	if err := ExtractZipArchive(dst, buf.Bytes()); err != nil {
		t.Fatalf("ExtractZipArchive: %v", err)
	}
	assertOnlyContent(t, dst)
}

func TestExtractTarStreamSkipsPackagingMetadata(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	entries := []struct {
		name     string
		mode     int64
		typeflag byte
		content  string
	}{
		{"__MACOSX/", 0o755, tar.TypeDir, ""},
		{"train.py", 0o644, tar.TypeReg, "print('ok')\n"},
		{"__MACOSX/._train.py", 0o644, tar.TypeReg, "\x00\x05\x16\x07appledouble"},
		{"pkg/models/._weights.py", 0o644, tar.TypeReg, "appledouble"},
		{".DS_Store", 0o644, tar.TypeReg, "finder"},
	}
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Mode:     e.mode,
			Size:     int64(len(e.content)),
			Typeflag: e.typeflag,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write tar header %q: %v", e.name, err)
		}
		if e.typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(e.content)); err != nil {
				t.Fatalf("write tar entry %q: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}

	dst := t.TempDir()
	if err := ExtractTarStream(dst, &buf); err != nil {
		t.Fatalf("ExtractTarStream: %v", err)
	}
	assertOnlyContent(t, dst)
}
