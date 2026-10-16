package fhe

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// sm3HexOf computes the SM3 digest of b the same way the cache does, by writing
// it to a file and hashing that file.
func sm3HexOf(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "blob")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatalf("write blob: %v", err)
	}
	_, hex, err := hashFileSM3(p)
	if err != nil {
		t.Fatalf("hash blob: %v", err)
	}
	return hex
}

func TestKeyCacheEnsureDownloadsAndVerifies(t *testing.T) {
	payload := []byte("eval-key-bytes")
	hash := sm3HexOf(t, payload)
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	c, err := NewKeyCache(t.TempDir(), DefaultMaxEvalKeyBytes)
	if err != nil {
		t.Fatalf("NewKeyCache: %v", err)
	}
	got, err := c.Ensure(hash, srv.URL+"/eval_context.bin")
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if got != filepath.Join(c.dir, hash, "eval_context.bin") {
		t.Errorf("Ensure path = %q", got)
	}
	if b, err := os.ReadFile(got); err != nil || string(b) != string(payload) {
		t.Fatalf("cached bytes = %q, err = %v", b, err)
	}
	if atomic.LoadInt64(&hits) != 1 {
		t.Fatalf("downloads = %d, want 1", hits)
	}

	// Second call must be served from the cache: the point of the cache is that a
	// repeat task for the same user never re-downloads several gigabytes.
	again, err := c.Ensure(hash, srv.URL+"/eval_context.bin")
	if err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	if again != got {
		t.Errorf("second Ensure path = %q, want %q", again, got)
	}
	if atomic.LoadInt64(&hits) != 1 {
		t.Errorf("downloads after a cache hit = %d, want 1", hits)
	}
}

func TestKeyCacheRejectsHashMismatchAndCleansUp(t *testing.T) {
	payload := []byte("real-bytes")
	wrong := sm3HexOf(t, []byte("other-bytes"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	dir := t.TempDir()
	c, err := NewKeyCache(dir, DefaultMaxEvalKeyBytes)
	if err != nil {
		t.Fatalf("NewKeyCache: %v", err)
	}
	_, err = c.Ensure(wrong, srv.URL+"/eval_context.bin")
	if err == nil {
		t.Fatal("Ensure with a mismatched hash = nil, want error")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("error %q does not mention a mismatch", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, wrong)); !os.IsNotExist(statErr) {
		t.Error("a rejected key was left in the cache")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("cache dir has %d entries after a rejection, want 0", len(entries))
	}
}

func TestKeyCacheRejectsInvalidHashBeforeAnyIO(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
	}))
	defer srv.Close()

	c, err := NewKeyCache(t.TempDir(), DefaultMaxEvalKeyBytes)
	if err != nil {
		t.Fatalf("NewKeyCache: %v", err)
	}
	for _, bad := range []string{"", "..", "../../etc", "short", strings.ToUpper(testHashA)} {
		if _, err := c.Ensure(bad, srv.URL); err == nil {
			t.Errorf("Ensure(%q) = nil, want error", bad)
		}
	}
	if atomic.LoadInt64(&hits) != 0 {
		t.Errorf("an invalid hash triggered %d downloads, want 0", hits)
	}
}

func TestKeyCacheRejectsOversizedDownload(t *testing.T) {
	payload := []byte(strings.Repeat("x", 4096))
	hash := sm3HexOf(t, payload)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	c, err := NewKeyCache(t.TempDir(), 1024)
	if err != nil {
		t.Fatalf("NewKeyCache: %v", err)
	}
	if _, err := c.Ensure(hash, srv.URL); err == nil {
		t.Fatal("Ensure of an oversized key = nil, want error")
	}
}

func TestKeyCacheRequiresAURLOnAMiss(t *testing.T) {
	c, err := NewKeyCache(t.TempDir(), DefaultMaxEvalKeyBytes)
	if err != nil {
		t.Fatalf("NewKeyCache: %v", err)
	}
	if _, err := c.Ensure(testHashA, "  "); err == nil {
		t.Fatal("Ensure with no url on a miss = nil, want error")
	}
}

func TestNewKeyCacheValidatesArguments(t *testing.T) {
	if _, err := NewKeyCache("", 1024); err == nil {
		t.Error("empty dir accepted, want error")
	}
	if _, err := NewKeyCache(t.TempDir(), 0); err == nil {
		t.Error("zero max bytes accepted, want error")
	}
}
