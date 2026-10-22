package fhe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	teecrypto "taa/pkg/crypto"
	pkgerrors "taa/pkg/errors"
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
//
// ctx bounds the download, and the caller's cancellation reaches it: a key
// server that accepted the connection and then said nothing must not hold the
// import goroutine that is waiting for this key open forever.
//
// The lock covers the cache lookup alone. It used to be held across the download
// and the digest - a multi-gigabyte transfer plus a multi-gigabyte SM3 - so one
// slow key serialized every other digest in the process. Nothing needs that:
// names are content-addressed and publication is an atomic rename, so two
// concurrent downloads of one digest verify the same bytes and publish the same
// file, and the second one's rename is a no-op in effect.
func (c *KeyCache) Ensure(ctx context.Context, hash, url string) (string, error) {
	dst, err := c.Path(hash)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	_, statErr := os.Stat(dst)
	c.mu.Unlock()
	if statErr == nil {
		return dst, nil
	}
	if !os.IsNotExist(statErr) {
		return "", fmt.Errorf("stat cached eval key %s: %w", dst, statErr)
	}

	if strings.TrimSpace(url) == "" {
		return "", fmt.Errorf("eval key %s is not cached and no download url was given", hash)
	}

	// The cap is this package's own, never the import cap: a real key is 3.101 GiB
	// and codeAudit.resultCheck.maxFileBytes is operator-configurable.
	tmp, err := downloadKey(ctx, url, c.maxBytes)
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

// keyHeaderTimeout bounds how long the key server may take to send response
// headers, which is the one thing a whole-request timeout cannot do here.
const keyHeaderTimeout = 30 * time.Second

// keyDownloadClient fetches eval keys.
//
// Its whole-request timeout is deliberately off, for the reason Client documents
// for its download client: http.Client.Timeout also covers reading the body, and
// a key is multi-gigabyte, so a timeout there aborts a healthy download
// mid-stream. The transfer is instead bounded by the caller's context - Execute
// hands Ensure the task's deadline - and by the header timeout, which stops a
// service that accepts the connection and then says nothing from holding the
// download open for the whole task budget.
//
// It follows redirects, unlike the API client. That difference is deliberate:
// what makes a redirect dangerous there is the tenant header riding on the
// request, and this request carries none. A key url is the deployment's own
// storage url, and this download used to go through http.Get, which follows
// redirects too - narrowing that here would turn a storage deployment that
// answers with a redirect into one whose keys can never be fetched.
var keyDownloadClient = func() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = keyHeaderTimeout
	return &http.Client{Transport: transport}
}()

// downloadKey streams url into a temp file, bounded by ctx and by maxBytes,
// which NewKeyCache has already checked is positive.
//
// resource.DownloadToTempFile does the same thing without a context - it calls
// http.Get - so a cancelled import could not stop it and a hung server could
// hold it forever. The same download is implemented here because this package
// may not change the resource package, and because a wrapper around it (a
// goroutine plus a select on ctx.Done) would leak the download it walked away
// from.
func downloadKey(ctx context.Context, url string, maxBytes int64) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("build the eval key download request for %s: %w", url, err)
	}
	resp, err := keyDownloadClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > maxBytes {
		return "", pkgerrors.Errorf(pkgerrors.CodeInvalidArgument,
			"eval key is %d bytes, over the %d byte cap", resp.ContentLength, maxBytes)
	}

	f, err := os.CreateTemp("", "taa-download-*")
	if err != nil {
		return "", fmt.Errorf("create the eval key temp file: %w", err)
	}
	path := f.Name()

	reader := io.LimitReader(resp.Body, maxBytes+1)
	n, err := io.Copy(f, reader)
	f.Close()
	if err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("write the eval key download to %s: %w", path, err)
	}
	if n > maxBytes {
		_ = os.Remove(path)
		return "", pkgerrors.Errorf(pkgerrors.CodeInvalidArgument,
			"eval key is over the %d byte cap: %d bytes", maxBytes, n)
	}
	return path, nil
}

// moveIntoCache moves src onto dst, falling back to a copy when the two paths are
// on different filesystems.
//
// DownloadToTempFile writes under os.TempDir() - usually a tmpfs - while the
// cache normally lives on a real disk, and os.Rename refuses to cross that
// boundary (EXDEV). The fallback copies into a sibling of dst first so the final
// rename stays inside one filesystem and stays atomic: a half-copied key must
// never appear at dst, where a cache hit would trust it without re-hashing.
//
// Both paths sync the bytes before the rename and the directory after it. This
// invariant is stronger than the one client.DownloadResult keeps for a result
// archive: a hit here skips verification entirely, so a name that exists but
// whose data never reached the disk would serve corrupt key bytes forever.
func moveIntoCache(src, dst string) error {
	dir := filepath.Dir(dst)
	if err := fsyncFile(src); err != nil {
		return fmt.Errorf("sync %s before moving it into the cache: %w", src, err)
	}
	if err := os.Rename(src, dst); err == nil {
		_ = fsyncDir(dir)
		return nil
	} else if !errors.Is(err, syscall.EXDEV) {
		return err
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	// The staging name is unique per attempt, so two publishers of one digest
	// cannot truncate each other's staging file.
	out, err := os.CreateTemp(dir, evalKeyFileName+".partial.*")
	if err != nil {
		return err
	}
	tmp := out.Name()
	copyErr := func() error {
		if _, err := io.Copy(out, in); err != nil {
			return err
		}
		if err := out.Sync(); err != nil {
			return err
		}
		return nil
	}()
	if copyErr != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return copyErr
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	_ = fsyncDir(dir)
	return nil
}
