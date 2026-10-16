package fhe

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"taa/internal/resource"
	teecrypto "taa/pkg/crypto"
	"taa/pkg/utils"
)

// hashFileSM3 is the digest used for every content-addressed name in this
// package: SM3, hex encoded.
func hashFileSM3(path string) (int64, string, error) {
	return teecrypto.HashFileSM3(path)
}

// KeyCache stores evaluation keys under <dir>/<sm3 hex>/eval_context.bin.
//
// The cache exists because a key is multi-gigabyte and a user's second task uses
// the same one: without it, every task would re-download 3.1 GiB and re-verify
// it. Because the directory name *is* the digest, a hit needs no re-verification
// - only bytes that hashed to that name can be sitting there.
//
// Entries are never evicted. Every cached key is a user, and dropping one costs
// another multi-gigabyte download; disk is sized for the expected user count
// instead.
type KeyCache struct {
	dir      string
	maxBytes int64
	mu       sync.Mutex
}

// NewKeyCache prepares the cache directory and returns it.
func NewKeyCache(dir string, maxBytes int64) (*KeyCache, error) {
	d := strings.TrimSpace(dir)
	if d == "" {
		return nil, fmt.Errorf("fhe key cache dir is empty")
	}
	if maxBytes <= 0 {
		return nil, fmt.Errorf("fhe max eval key bytes must be positive, got %d", maxBytes)
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return nil, fmt.Errorf("create fhe key cache dir %s: %w", d, err)
	}
	return &KeyCache{dir: d, maxBytes: maxBytes}, nil
}

// Dir returns the cache root.
func (c *KeyCache) Dir() string { return c.dir }

// Path returns the cache path of a digest, or an error when the digest is not a
// valid SM3 hex value. The digest becomes a directory name, so this check is what
// keeps a hostile value from escaping the cache directory.
func (c *KeyCache) Path(hash string) (string, error) {
	h := strings.TrimSpace(hash)
	if !ValidHash(h) {
		return "", fmt.Errorf("invalid eval key hash %q: want 64 lowercase hex characters", hash)
	}
	return filepath.Join(c.dir, h, evalKeyFileName), nil
}

// Ensure makes the key identified by hash available locally and returns its path.
// A cached key is returned as-is; a miss downloads from url, verifies the digest,
// and only then moves the file into place, so a partially written or rejected
// download can never be mistaken for a cached key.
func (c *KeyCache) Ensure(hash, url string) (string, error) {
	dst, err := c.Path(hash)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, err := os.Stat(dst); err == nil {
		return dst, nil
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("stat cached eval key %s: %w", dst, err)
	}

	if strings.TrimSpace(url) == "" {
		return "", fmt.Errorf("eval key %s is not cached and no download url was given", hash)
	}

	// The cap is this package's own, never the import cap: a real key is 3.101 GiB
	// and codeAudit.resultCheck.maxFileBytes defaults to 3 GiB.
	tmp, _, err := resource.DownloadToTempFile(url, c.maxBytes)
	if err != nil {
		return "", fmt.Errorf("download eval key: %w", err)
	}
	defer os.Remove(tmp)

	_, got, err := hashFileSM3(tmp)
	if err != nil {
		return "", fmt.Errorf("hash the downloaded eval key: %w", err)
	}
	if !strings.EqualFold(got, strings.TrimSpace(hash)) {
		return "", fmt.Errorf("eval key hash mismatch: declared %s, downloaded %s", hash, got)
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", fmt.Errorf("create eval key dir: %w", err)
	}
	if err := moveIntoCache(tmp, dst); err != nil {
		return "", fmt.Errorf("move eval key into the cache: %w", err)
	}
	return dst, nil
}

// moveIntoCache moves src onto dst, falling back to a copy when the two paths are
// on different filesystems.
//
// DownloadToTempFile writes under os.TempDir() - usually a tmpfs - while the
// cache normally lives on a real disk, and os.Rename refuses to cross that
// boundary (EXDEV). The fallback copies into a sibling of dst first so the final
// rename stays inside one filesystem and stays atomic: a half-copied key must
// never appear at dst, where a cache hit would trust it without re-hashing.
func moveIntoCache(src, dst string) error {
	err := os.Rename(src, dst)
	if err == nil {
		return nil
	}
	if !errors.Is(err, syscall.EXDEV) {
		return err
	}

	tmp := dst + ".partial"
	if copyErr := utils.CopyFile(tmp, src, 0o600); copyErr != nil {
		_ = os.Remove(tmp)
		return copyErr
	}
	if renameErr := os.Rename(tmp, dst); renameErr != nil {
		_ = os.Remove(tmp)
		return renameErr
	}
	return nil
}
