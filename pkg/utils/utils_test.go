package utils

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSafeFilename(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"../../etc/passwd", "etc-passwd"},
		{"valid_file-name.123", "valid_file-name.123"},
		{"   ", "default"},
		{"foo*bar?baz", "foo-bar-baz"},
	}

	for _, c := range cases {
		got := SafeFilename(c.input)
		if got != c.expected {
			t.Errorf("SafeFilename(%q) = %q, expected %q", c.input, got, c.expected)
		}
	}
}

func TestFormatBytes(t *testing.T) {
	if got := FormatBytes(500); got != "500 B" {
		t.Errorf("expected '500 B', got %s", got)
	}
	if got := FormatBytes(1024); got != "1.00 KB" {
		t.Errorf("expected '1.00 KB', got %s", got)
	}
	if got := FormatBytes(1048576 * 5); got != "5.00 MB" {
		t.Errorf("expected '5.00 MB', got %s", got)
	}
}

func TestRandomString(t *testing.T) {
	s1 := RandomString(16)
	s2 := RandomString(16)
	if len(s1) != 16 || len(s2) != 16 {
		t.Fatalf("expected length 16")
	}
	if s1 == s2 {
		t.Fatalf("expected different random strings")
	}
}

func TestTimeParsing(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	formatted := FormatISO8601(now)
	parsed, err := ParseISO8601(formatted)
	if err != nil {
		t.Fatalf("ParseISO8601 failed: %v", err)
	}
	if !parsed.Equal(now) {
		t.Fatalf("expected %v, got %v", now, parsed)
	}
}

func TestCopyAndCleanDir(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pkg-utils-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	src := filepath.Join(tmpDir, "src")
	dst := filepath.Join(tmpDir, "dst")

	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "file.txt"), []byte("hello world"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := CopyDir(dst, src); err != nil {
		t.Fatalf("CopyDir failed: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(dst, "file.txt"))
	if err != nil || string(content) != "hello world" {
		t.Fatalf("copied content mismatch or error: %v", err)
	}

	if err := CleanDir(dst); err != nil {
		t.Fatalf("CleanDir failed: %v", err)
	}

	entries, err := os.ReadDir(dst)
	if err != nil || len(entries) != 0 {
		t.Fatalf("expected empty dir after clean, got len=%d", len(entries))
	}
}
