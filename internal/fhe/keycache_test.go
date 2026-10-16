package fhe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
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
	got, err := c.Ensure(context.Background(), hash, srv.URL+"/eval_context.bin")
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
	again, err := c.Ensure(context.Background(), hash, srv.URL+"/eval_context.bin")
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
	_, err = c.Ensure(context.Background(), wrong, srv.URL+"/eval_context.bin")
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
		if _, err := c.Ensure(context.Background(), bad, srv.URL); err == nil {
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
	if _, err := c.Ensure(context.Background(), hash, srv.URL); err == nil {
		t.Fatal("Ensure of an oversized key = nil, want error")
	}
}

// TestKeyCacheRequiresAURLOnAMiss pins the empty-url gate itself, not just "an
// error came back". A blank url used to be handed to http.Get("  "), which fails
// on its own, so asserting only err != nil left the gate untested: deleting it
// kept the suite green while the package attempted a request for a url that was
// never given.
func TestKeyCacheRequiresAURLOnAMiss(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
	}))
	defer srv.Close()

	c, err := NewKeyCache(t.TempDir(), DefaultMaxEvalKeyBytes)
	if err != nil {
		t.Fatalf("NewKeyCache: %v", err)
	}
	_, err = c.Ensure(context.Background(), testHashA, "  ")
	if err == nil {
		t.Fatal("Ensure with no url on a miss = nil, want error")
	}
	if !strings.Contains(err.Error(), "no download url") {
		t.Errorf("error %q is not the gate's: want it to say no download url was given", err)
	}
	if atomic.LoadInt64(&hits) != 0 {
		t.Errorf("the blank-url path sent %d requests, want 0", hits)
	}
}

// TestNewKeyCacheValidatesArguments covers the cache's own argument checks.
func TestNewKeyCacheValidatesArguments(t *testing.T) {
	if _, err := NewKeyCache("", 1024); err == nil {
		t.Error("empty dir accepted, want error")
	}
	if _, err := NewKeyCache(t.TempDir(), 0); err == nil {
		t.Error("zero max bytes accepted, want error")
	}
}

// TestKeyCacheEnsureDoesNotSerializeUnrelatedDigests is the regression test for
// the mutex that covered the whole download and the whole SM3 digest: one slow
// key made every other Ensure in the process wait for it (measured at 2.7s
// behind a 3s download). The cache is content-addressed and publication is an
// atomic rename, so a lookup is all the lock has to cover.
func TestKeyCacheEnsureDoesNotSerializeUnrelatedDigests(t *testing.T) {
	slowBytes := []byte("slow-key-bytes")
	slowHash := sm3HexOf(t, slowBytes)
	fastBytes := []byte("fast-key-bytes")
	fastHash := sm3HexOf(t, fastBytes)

	slowStarted := make(chan struct{})
	var once sync.Once
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(slowBytes[:4])
		flush(w)
		once.Do(func() { close(slowStarted) })
		time.Sleep(2 * time.Second)
		_, _ = w.Write(slowBytes[4:])
	}))
	defer slow.Close()
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(fastBytes)
	}))
	defer fast.Close()

	c, err := NewKeyCache(t.TempDir(), DefaultMaxEvalKeyBytes)
	if err != nil {
		t.Fatalf("NewKeyCache: %v", err)
	}

	slowDone := make(chan error, 1)
	go func() {
		_, err := c.Ensure(context.Background(), slowHash, slow.URL)
		slowDone <- err
	}()
	<-slowStarted

	start := time.Now()
	if _, err := c.Ensure(context.Background(), fastHash, fast.URL); err != nil {
		t.Fatalf("Ensure of an unrelated digest while a slow download runs: %v", err)
	}
	blocked := time.Since(start)
	if blocked > time.Second {
		t.Errorf("an unrelated Ensure waited %v for a 2s download: the cache lock must not cover the transfer", blocked)
	}
	if err := <-slowDone; err != nil {
		t.Fatalf("the slow Ensure: %v", err)
	}
}

// TestKeyCacheEnsureConcurrentSameDigest checks the claim that makes dropping the
// lock safe: two concurrent downloads of one digest are harmless because both
// verify the same bytes and the rename that publishes them is atomic. Neither may
// see the other's staging file, and both must end up with the verified key.
func TestKeyCacheEnsureConcurrentSameDigest(t *testing.T) {
	payload := []byte("eval-key-bytes")
	hash := sm3HexOf(t, payload)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	dir := t.TempDir()
	c, err := NewKeyCache(dir, DefaultMaxEvalKeyBytes)
	if err != nil {
		t.Fatalf("NewKeyCache: %v", err)
	}
	paths := make([]string, 2)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			paths[i], errs[i] = c.Ensure(context.Background(), hash, srv.URL)
		}(i)
	}
	wg.Wait()

	want := filepath.Join(dir, hash, "eval_context.bin")
	for i := 0; i < 2; i++ {
		if errs[i] != nil {
			t.Fatalf("concurrent Ensure #%d: %v", i, errs[i])
		}
		if paths[i] != want {
			t.Errorf("concurrent Ensure #%d path = %q, want %q", i, paths[i], want)
		}
	}
	b, err := os.ReadFile(want)
	if err != nil {
		t.Fatalf("read the cached key: %v", err)
	}
	if string(b) != string(payload) {
		t.Errorf("cached key = %q, want %q", b, payload)
	}
	entries, err := os.ReadDir(filepath.Dir(want))
	if err != nil {
		t.Fatalf("read the cache entry dir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "eval_context.bin" {
			t.Errorf("staging file %q was left behind in the cache entry", e.Name())
		}
	}
}

// TestMoveIntoCacheCrossDeviceFallback exercises the EXDEV path, which is the one
// the cache takes in production when the key is downloaded into os.TempDir() and
// the cache lives on a real disk. It needs two filesystems, so it skips where
// there is only one.
//
// The path is what a crash would corrupt: the staging file it writes must be
// unique (a fixed "<dst>.partial" lets two publishers truncate each other's
// bytes) and it must be gone whatever happens.
func TestMoveIntoCacheCrossDeviceFallback(t *testing.T) {
	srcDir := "/dev/shm"
	if _, err := os.Stat(srcDir); err != nil {
		t.Skipf("no second filesystem to cross: %v", err)
	}
	dstDir := t.TempDir()
	devOf := func(p string) uint64 {
		t.Helper()
		st, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		return st.Sys().(*syscall.Stat_t).Dev
	}
	if devOf(srcDir) == devOf(dstDir) {
		t.Skipf("%s and %s are one filesystem, so rename cannot fail with EXDEV", srcDir, dstDir)
	}

	src, err := os.CreateTemp(srcDir, "taa-key-*")
	if err != nil {
		t.Skipf("cannot write to %s: %v", srcDir, err)
	}
	payload := []byte("cross-device-key-bytes")
	if _, err := src.Write(payload); err != nil {
		t.Fatalf("write the key: %v", err)
	}
	if err := src.Close(); err != nil {
		t.Fatalf("close the key: %v", err)
	}
	defer os.Remove(src.Name())

	dst := filepath.Join(dstDir, "eval_context.bin")
	// Another publisher staged under the fixed name this used to use.
	fixed := dst + ".partial"
	if err := os.WriteFile(fixed, []byte("another-publisher-staging"), 0o600); err != nil {
		t.Fatalf("write the sentinel: %v", err)
	}

	if err := moveIntoCache(src.Name(), dst); err != nil {
		t.Fatalf("moveIntoCache across filesystems: %v", err)
	}
	b, err := os.ReadFile(dst)
	if err != nil || string(b) != string(payload) {
		t.Errorf("moved key = %q, err = %v", b, err)
	}
	if b, err := os.ReadFile(fixed); err != nil || string(b) != "another-publisher-staging" {
		t.Errorf("the staging file at %s = %q, err = %v: moveIntoCache wrote through a fixed staging name", fixed, b, err)
	}
	entries, err := os.ReadDir(dstDir)
	if err != nil {
		t.Fatalf("read the cache dir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".partial.") {
			t.Errorf("staging file %q was left behind", e.Name())
		}
	}
}

// TestMoveIntoCacheRemovesItsStagingFileOnFailure checks the failure path of the
// cross-device copy: a half-written key must not be left next to dst, where the
// next attempt - or an operator - could mistake it for a cache entry.
//
// The failure is arranged after the staging file exists, by handing the copy a
// directory as its source: reading it fails with EISDIR, so the copy dies with
// its staging file already in dst's directory.
func TestMoveIntoCacheRemovesItsStagingFileOnFailure(t *testing.T) {
	srcDir := "/dev/shm"
	dstDir := t.TempDir()
	devOf := func(p string) uint64 {
		t.Helper()
		st, err := os.Stat(p)
		if err != nil {
			t.Skipf("cannot stat %s: %v", p, err)
		}
		return st.Sys().(*syscall.Stat_t).Dev
	}
	if devOf(srcDir) == devOf(dstDir) {
		t.Skipf("%s and %s are one filesystem, so the cross-device copy is not reached", srcDir, dstDir)
	}
	src, err := os.MkdirTemp(srcDir, "taa-key-dir-*")
	if err != nil {
		t.Skipf("cannot write to %s: %v", srcDir, err)
	}
	defer os.RemoveAll(src)

	dst := filepath.Join(dstDir, "eval_context.bin")
	if err := moveIntoCache(src, dst); err == nil {
		t.Fatal("moveIntoCache with an unreadable source = nil, want error")
	}
	entries, err := os.ReadDir(dstDir)
	if err != nil {
		t.Fatalf("read the cache dir: %v", err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("cache dir holds %v after a failed move, want nothing", names)
	}
}

// TestDownloadKeyIsBoundedByTheCallerContext pins the bound the download itself
// has to have: a key server that sends headers and then stalls must not hold the
// caller open past its own cancellation.
func TestDownloadKeyIsBoundedByTheCallerContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("head"))
		flush(w)
		// A stall with an end, so a download that ignores the context fails the
		// bound below instead of hanging the suite.
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
		_, _ = w.Write([]byte("tail"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	tmp, err := downloadKey(ctx, srv.URL, DefaultMaxEvalKeyBytes)
	if err == nil {
		_ = os.Remove(tmp)
		t.Fatal("downloadKey with a cancelled context = nil, want error")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("downloadKey returned after %v, want it to stop at the caller's cancellation", elapsed)
	}
}
