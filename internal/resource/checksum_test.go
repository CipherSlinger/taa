package resource

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHashFileSM3(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test.txt")
	content := []byte("hello sm3 test content")
	if err := os.WriteFile(tmpFile, content, 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	hex, err := HashFileSM3(tmpFile)
	if err != nil {
		t.Fatalf("HashFileSM3 failed: %v", err)
	}
	if len(hex) != 64 {
		t.Fatalf("expected 64 char hex string for SM3, got %d chars (%s)", len(hex), hex)
	}

	// 再次计算应保持幂等
	hex2, err := HashFileSM3(tmpFile)
	if err != nil {
		t.Fatalf("HashFileSM3 second run failed: %v", err)
	}
	if hex != hex2 {
		t.Fatalf("SM3 hash mismatch: %s != %s", hex, hex2)
	}
}

func TestBuildDirectoryChecksum(t *testing.T) {
	tmpDir := t.TempDir()

	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}

	if err := os.WriteFile(filepath.Join(tmpDir, "b.txt"), []byte("content b"), 0o644); err != nil {
		t.Fatalf("write b.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "a.txt"), []byte("content a"), 0o644); err != nil {
		t.Fatalf("write a.txt: %v", err)
	}

	// 创建一个指向外部文件的符号链接，验证其被安全忽略
	outsideFile := filepath.Join(t.TempDir(), "outside.txt")
	_ = os.WriteFile(outsideFile, []byte("outside"), 0o644)
	_ = os.Symlink(outsideFile, filepath.Join(tmpDir, "link.txt"))

	res, err := BuildDirectoryChecksum(tmpDir, "sm3")
	if err != nil {
		t.Fatalf("BuildDirectoryChecksum failed: %v", err)
	}

	if res["algorithm"] != "sm3" {
		t.Fatalf("unexpected algorithm: %v", res["algorithm"])
	}
	hashVal, ok := res["value"].(string)
	if !ok || len(hashVal) != 64 {
		t.Fatalf("unexpected hash value: %v", res["value"])
	}
	sizeVal, ok := res["size"].(int64)
	if !ok || sizeVal != int64(len("content b")+len("content a")) {
		t.Fatalf("unexpected total size: %v", res["size"])
	}

	// 空目录/不存在目录测试
	resEmpty, err := BuildDirectoryChecksum(filepath.Join(t.TempDir(), "nonexistent"), "sm3")
	if err != nil {
		t.Fatalf("BuildDirectoryChecksum nonexistent failed: %v", err)
	}
	if resEmpty["value"] != "N/A" || resEmpty["size"] != int64(0) {
		t.Fatalf("unexpected nonexistent dir result: %v", resEmpty)
	}
}
