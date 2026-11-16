package mock

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// auditFilesIndex is the metadata file inside the store directory. Keeping
	// the original names and sizes in an index means the files themselves can be
	// opaque ids on disk.
	auditFilesIndex = "index.json"
	// auditFilesMax bounds the store. The workbench is a development tool and
	// uploads can be large; keeping the newest entries is enough to re-run a
	// comparison, and an unbounded store would only fill the disk.
	auditFilesMax = 100
)

// auditFileEntry is one saved upload. Name is display metadata only: it never
// takes part in a path, so a name with slashes or control characters cannot
// escape the store directory.
//
// DataKeyCipher is the SM2 envelope over the SM4 key that encrypts the entry's
// bytes. It travels with the metadata, not with the file, which is the same
// split the platform uses when it puts the envelope on a download URL: the
// stored body is pure ciphertext, and the key that opens it is a small hex
// string in the index.
type auditFileEntry struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Size          int64     `json:"size"`
	UploadedAt    time.Time `json:"uploadedAt"`
	DataKeyCipher string    `json:"dataKeyCipher,omitempty"`
	// Encrypted says the bytes on disk are an envelope. An entry written before
	// the workbench encrypted uploads has none, and is still readable.
	Encrypted bool `json:"encrypted,omitempty"`
	// PlainSize is the archive's own size, which differs from Size once an
	// envelope adds its nonce and tag.
	PlainSize int64 `json:"plainSize,omitempty"`
}

// auditFileStore keeps the archives uploaded through the workbench so a run can
// be repeated without uploading the bytes again. The directory layout is
// `<dir>/<id>.bin` plus `<dir>/index.json`; both are owned by this type.
type auditFileStore struct {
	dir string

	mu      sync.Mutex
	entries []auditFileEntry // oldest first
}

func newAuditFileStore(dir string) *auditFileStore {
	s := &auditFileStore{dir: dir}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("audit file store unavailable at %s: %v", dir, err)
		return s
	}
	s.load()
	return s
}

// load rebuilds the in-memory list from index.json, dropping entries whose
// file disappeared or whose id is malformed.
func (s *auditFileStore) load() {
	data, err := os.ReadFile(filepath.Join(s.dir, auditFilesIndex))
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("audit file store index unreadable: %v", err)
		}
		return
	}
	var payload struct {
		Files []auditFileEntry `json:"files"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		log.Printf("audit file store index malformed, starting empty: %v", err)
		return
	}
	kept := make([]auditFileEntry, 0, len(payload.Files))
	for _, entry := range payload.Files {
		if !validAuditFileID(entry.ID) {
			continue
		}
		if _, err := os.Stat(filepath.Join(s.dir, entry.ID+".bin")); err != nil {
			continue
		}
		if entry.Name == "" {
			entry.Name = "archive"
		}
		kept = append(kept, entry)
	}
	if len(kept) > auditFilesMax {
		kept = kept[len(kept)-auditFilesMax:]
	}
	s.entries = kept
}

// list returns a newest-first copy; callers never see the internal slice.
func (s *auditFileStore) list() []auditFileEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]auditFileEntry, len(s.entries))
	for i, entry := range s.entries {
		out[len(s.entries)-1-i] = entry
	}
	return out
}

// saveFromFile copies an already staged archive into the store. The copy is
// what the file area serves from, so deleting the per-audit temp directory does
// not lose it.
//
// When keys is non-nil the stored bytes are an SM4-GCM envelope and the entry
// carries the SM2 envelope over its data key; the file area then holds nothing
// but ciphertext. A nil keys store is the plaintext form the tests use, and it
// is also what an unconfigured workbench falls back to refusing: see the submit
// handler, which never passes nil in production.
func (s *auditFileStore) saveFromFile(srcPath, originalName string, keys *workbenchKeys) (auditFileEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id, err := newAuditFileID()
	if err != nil {
		return auditFileEntry{}, err
	}
	dstPath := filepath.Join(s.dir, id+".bin")
	tmpPath := dstPath + ".tmp"

	entry := auditFileEntry{
		ID:         id,
		Name:       cleanAuditFileName(originalName),
		UploadedAt: time.Now().UTC(),
	}

	if keys != nil {
		plaintext, err := os.ReadFile(srcPath)
		if err != nil {
			return auditFileEntry{}, err
		}
		body, dataKeyCipher, err := keys.seal(plaintext)
		if err != nil {
			return auditFileEntry{}, err
		}
		entry.PlainSize = int64(len(plaintext))
		if err := os.WriteFile(tmpPath, body, 0o600); err != nil {
			_ = os.Remove(tmpPath)
			return auditFileEntry{}, err
		}
		if err := os.Rename(tmpPath, dstPath); err != nil {
			_ = os.Remove(tmpPath)
			return auditFileEntry{}, err
		}
		entry.Size = int64(len(body))
		entry.DataKeyCipher = dataKeyCipher
		entry.Encrypted = true
		s.entries = append(s.entries, entry)
		s.trimLocked()
		if err := s.persistLocked(); err != nil {
			log.Printf("audit file store index write failed: %v", err)
		}
		return entry, nil
	}

	src, err := os.Open(srcPath)
	if err != nil {
		return auditFileEntry{}, err
	}
	size, copyErr := copyToFile(tmpPath, src)
	closeErr := src.Close()
	if copyErr != nil {
		_ = os.Remove(tmpPath)
		return auditFileEntry{}, copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return auditFileEntry{}, closeErr
	}
	if err := os.Rename(tmpPath, dstPath); err != nil {
		_ = os.Remove(tmpPath)
		return auditFileEntry{}, err
	}

	entry.Size = size
	entry.PlainSize = size
	s.entries = append(s.entries, entry)
	s.trimLocked()
	if err := s.persistLocked(); err != nil {
		// The file and the in-memory row are usable; only the restart index is
		// stale, so log rather than fail an audit that could still run.
		log.Printf("audit file store index write failed: %v", err)
	}
	return entry, nil
}

// path resolves a stored id for a submission. The returned path is the stored
// archive the caller copies from.
func (s *auditFileStore) path(id string) (auditFileEntry, string, bool) {
	if !validAuditFileID(id) {
		return auditFileEntry{}, "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, entry := range s.entries {
		if entry.ID == id {
			return entry, filepath.Join(s.dir, id+".bin"), true
		}
	}
	return auditFileEntry{}, "", false
}

func (s *auditFileStore) delete(id string) bool {
	if !validAuditFileID(id) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, entry := range s.entries {
		if entry.ID != id {
			continue
		}
		s.entries = append(s.entries[:i], s.entries[i+1:]...)
		_ = os.Remove(filepath.Join(s.dir, id+".bin"))
		if err := s.persistLocked(); err != nil {
			log.Printf("audit file store index write failed: %v", err)
		}
		return true
	}
	return false
}

// trimLocked enforces auditFilesMax, oldest first.
func (s *auditFileStore) trimLocked() {
	for len(s.entries) > auditFilesMax {
		oldest := s.entries[0]
		s.entries = s.entries[1:]
		_ = os.Remove(filepath.Join(s.dir, oldest.ID+".bin"))
	}
}

// persistLocked writes the index through a temp file and a rename so a crash
// mid-write cannot leave a half-written index.
func (s *auditFileStore) persistLocked() error {
	payload := struct {
		Files []auditFileEntry `json:"files"`
	}{Files: s.entries}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	tmpPath := filepath.Join(s.dir, auditFilesIndex+".tmp")
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpPath, filepath.Join(s.dir, auditFilesIndex))
}

func newAuditFileID() (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func validAuditFileID(id string) bool {
	if len(id) != 16 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func cleanAuditFileName(name string) string {
	name = filepath.Base(strings.TrimSpace(name))
	if name == "" || name == "." || name == string(filepath.Separator) {
		return "archive"
	}
	if runes := []rune(name); len(runes) > 200 {
		name = string(runes[len(runes)-200:])
	}
	return name
}

// errAuditFileNotFound is returned when a stored id no longer resolves; the
// submit handler turns it into a 400 so the console can tell the operator the
// file area entry was removed.
var errAuditFileNotFound = errors.New("文件区域中找不到该文件")

// copyAuditFileTo stages a stored archive into a work directory. It is kept
// separate from copyToFile so the source is a path, not an io.Reader, which
// makes the missing-file case explicit.
func copyAuditFileTo(dstPath, srcPath string) (int64, error) {
	src, err := os.Open(srcPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, errAuditFileNotFound
		}
		return 0, err
	}
	defer src.Close()
	return copyToFile(dstPath, src)
}
