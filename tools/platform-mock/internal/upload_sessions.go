package mock

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Resumable uploads exist because a single large POST does not survive a slow
// link. Measuring a real 46 MiB upload over a VPN showed the request body
// stalling after a few tens of kilobytes and the browser abandoning it within
// milliseconds, while the same file delivered as a series of small requests
// always completed. Chunking is therefore the transport fix, not a timeout
// tweak: every individual request is short enough to finish, and the server
// remembering which chunks arrived means a transfer that dies halfway resumes
// where it stopped instead of starting over.
const (
	uploadSessionDirName  = ".upload-sessions"
	uploadSessionMetaName = "session.json"
)

// Chunk sizing. 4 MiB is the size a real transfer was measured to complete
// reliably on the link that stalls a 46 MiB request, and it keeps a retry
// cheap. The bounds stop a client from turning the endpoint into either a
// one-request upload (which defeats the purpose) or a flood of tiny requests.
const (
	defaultUploadChunkSize = 4 << 20
	minUploadChunkSize     = 256 << 10
	maxUploadChunkSize     = 32 << 20
)

// chunkOverheadBytes is the slack the chunk endpoint allows over the negotiated
// chunk size before refusing the body. A request may legitimately carry a
// little more than the chunk itself; anything beyond this is a client that
// ignored the negotiated size.
const chunkOverheadBytes = 1 << 20

// uploadSession is the durable half of a resumable upload: the file's identity
// plus the negotiation parameters. Every chunk on disk is named after its
// index, so the set of present chunks is itself the resume state and no
// separate index has to be kept in sync with the files.
type uploadSession struct {
	SessionID    string    `json:"sessionId"`
	OriginalName string    `json:"originalName"`
	Size         int64     `json:"size"`
	LastModified int64     `json:"lastModified"`
	ChunkSize    int64     `json:"chunkSize"`
	EncryptMode  string    `json:"encryptMode"`
	CreatedAt    time.Time `json:"createdAt"`
}

// uploadSessionView is what the console needs to drive, or to resume, one
// transfer. It is also the reply shape of every session and chunk request, so
// the client learns the current state from any step that succeeds.
type uploadSessionView struct {
	SessionID    string `json:"sessionId"`
	OriginalName string `json:"originalName"`
	Size         int64  `json:"size"`
	ChunkSize    int64  `json:"chunkSize"`
	TotalChunks  int    `json:"totalChunks"`
	Received     []int  `json:"received"`
}

type uploadSessionStore struct {
	root string

	// mu guards the lock map; each session has its own mutex so a chunk write
	// only contends with the same session's other writes, not with every
	// upload in flight.
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func newUploadSessionStore(uploadDir string) *uploadSessionStore {
	return &uploadSessionStore{
		root:  filepath.Join(uploadDir, uploadSessionDirName),
		locks: make(map[string]*sync.Mutex),
	}
}

// sessionIDFor derives the session name from the file's identity rather than
// from when the upload started. Re-selecting the same unchanged file after a
// reload therefore addresses the chunks already on disk, which is what makes
// an interrupted transfer resumable without the console holding any state.
func sessionIDFor(name string, size, lastModified int64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d\x00%d", name, size, lastModified)))
	return hex.EncodeToString(sum[:])
}

// validSessionID keeps a caller-supplied id from being a path. The ids this
// server hands out are always lowercase hex, so anything else is refused
// rather than resolved.
func validSessionID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, r := range id {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func (s *uploadSessionStore) dir(id string) string {
	return filepath.Join(s.root, id)
}

func (s *uploadSessionStore) lockFor(id string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, ok := s.locks[id]
	if !ok {
		lock = &sync.Mutex{}
		s.locks[id] = lock
	}
	return lock
}

func (s *uploadSessionStore) releaseLock(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.locks, id)
}

func clampChunkSize(size int64) int64 {
	switch {
	case size <= 0:
		return defaultUploadChunkSize
	case size < minUploadChunkSize:
		return minUploadChunkSize
	case size > maxUploadChunkSize:
		return maxUploadChunkSize
	default:
		return size
	}
}

func totalChunksFor(size, chunkSize int64) int {
	if size <= 0 || chunkSize <= 0 {
		return 0
	}
	return int((size + chunkSize - 1) / chunkSize)
}

// chunkBytesFor is the exact byte length chunk index is expected to carry. The
// final chunk is short whenever the file does not divide evenly, and that
// length is what a write is validated against.
func chunkBytesFor(size, chunkSize int64, index int) int64 {
	remaining := size - int64(index)*chunkSize
	if remaining <= 0 {
		return 0
	}
	if remaining > chunkSize {
		return chunkSize
	}
	return remaining
}

func chunkFileName(index int) string {
	return fmt.Sprintf("chunk-%08d", index)
}

func (s *uploadSessionStore) writeMeta(sess uploadSession) error {
	if err := os.MkdirAll(s.dir(sess.SessionID), 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	path := filepath.Join(s.dir(sess.SessionID), uploadSessionMetaName)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *uploadSessionStore) load(id string) (uploadSession, error) {
	data, err := os.ReadFile(filepath.Join(s.dir(id), uploadSessionMetaName))
	if err != nil {
		return uploadSession{}, err
	}
	var sess uploadSession
	if err := json.Unmarshal(data, &sess); err != nil {
		return uploadSession{}, err
	}
	return sess, nil
}

// receivedChunks lists the indexes already on disk. The file names are the
// state, so a chunk that was half-written is absent rather than counted: a
// chunk is only renamed into place once its full length has been written.
func (s *uploadSessionStore) receivedChunks(id string) ([]int, int64, error) {
	entries, err := os.ReadDir(s.dir(id))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, nil
		}
		return nil, 0, err
	}
	var chunks []int
	var present int64
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, "chunk-") {
			continue
		}
		index, convErr := strconv.Atoi(strings.TrimPrefix(name, "chunk-"))
		if convErr != nil {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			continue
		}
		chunks = append(chunks, index)
		present += info.Size()
	}
	sort.Ints(chunks)
	return chunks, present, nil
}

func (s *uploadSessionStore) view(sess uploadSession, chunks []int) uploadSessionView {
	// A fresh session has no chunks, and the reply must say [] rather than
	// null: every client treats the field as a list.
	if chunks == nil {
		chunks = []int{}
	}
	return uploadSessionView{
		SessionID:    sess.SessionID,
		OriginalName: sess.OriginalName,
		Size:         sess.Size,
		ChunkSize:    sess.ChunkSize,
		TotalChunks:  totalChunksFor(sess.Size, sess.ChunkSize),
		Received:     chunks,
	}
}

// begin creates the session, or returns the existing one for the same file
// identity. A stored session whose identity matches but whose negotiating
// parameters changed is rebuilt: the chunks on disk would be cut at the wrong
// boundaries, so keeping them would corrupt the reassembly.
func (s *uploadSessionStore) begin(name string, size, lastModified, chunkSize int64, encryptMode string) (uploadSessionView, error) {
	if size < 0 {
		return uploadSessionView{}, errors.New("文件大小无效")
	}
	chunkSize = clampChunkSize(chunkSize)
	id := sessionIDFor(name, size, lastModified)

	lock := s.lockFor(id)
	lock.Lock()
	defer lock.Unlock()

	existing, err := s.load(id)
	switch {
	case err == nil && existing.Size == size && existing.ChunkSize == chunkSize && existing.OriginalName == name:
		chunks, _, listErr := s.receivedChunks(id)
		if listErr != nil {
			return uploadSessionView{}, listErr
		}
		return s.view(existing, chunks), nil
	case err == nil:
		// Same identity, different shape: discard the stale chunks.
		if err := os.RemoveAll(s.dir(id)); err != nil {
			return uploadSessionView{}, err
		}
	case !os.IsNotExist(err):
		return uploadSessionView{}, err
	}

	sess := uploadSession{
		SessionID:    id,
		OriginalName: name,
		Size:         size,
		LastModified: lastModified,
		ChunkSize:    chunkSize,
		EncryptMode:  encryptMode,
		CreatedAt:    time.Now().UTC(),
	}
	if err := s.writeMeta(sess); err != nil {
		return uploadSessionView{}, err
	}
	return s.view(sess, nil), nil
}

// writeChunk streams one chunk to disk and only publishes it under its final
// name once the whole body has been written. A transfer that dies mid-chunk
// therefore leaves a .tmp file that the resume state ignores, rather than a
// short chunk that would be stitched into the file undetected.
func (s *uploadSessionStore) writeChunk(id string, index int, r io.Reader) (uploadSessionView, error) {
	if !validSessionID(id) {
		return uploadSessionView{}, errUploadSessionNotFound
	}
	lock := s.lockFor(id)
	lock.Lock()
	defer lock.Unlock()

	sess, err := s.load(id)
	if err != nil {
		if os.IsNotExist(err) {
			return uploadSessionView{}, errUploadSessionNotFound
		}
		return uploadSessionView{}, err
	}
	total := totalChunksFor(sess.Size, sess.ChunkSize)
	if index < 0 || index >= total {
		return uploadSessionView{}, fmt.Errorf("分片序号 %d 超出范围（共 %d 片）", index, total)
	}

	want := chunkBytesFor(sess.Size, sess.ChunkSize, index)
	dir := s.dir(id)
	tmpPath := filepath.Join(dir, chunkFileName(index)+".tmp")
	finalPath := filepath.Join(dir, chunkFileName(index))

	dst, err := os.Create(tmpPath)
	if err != nil {
		return uploadSessionView{}, err
	}
	written, copyErr := io.Copy(dst, io.LimitReader(r, want+1))
	syncErr := dst.Sync()
	closeErr := dst.Close()
	if copyErr != nil {
		_ = os.Remove(tmpPath)
		return uploadSessionView{}, copyErr
	}
	if syncErr != nil {
		_ = os.Remove(tmpPath)
		return uploadSessionView{}, syncErr
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return uploadSessionView{}, closeErr
	}
	// want+1 is read on purpose: a body longer than the chunk must be refused
	// here rather than truncated silently, or the reassembled file would differ
	// from what the browser holds.
	if written != want {
		_ = os.Remove(tmpPath)
		if written > want {
			return uploadSessionView{}, fmt.Errorf("分片 %d 携带 %d 字节，应为 %d", index, written, want)
		}
		return uploadSessionView{}, fmt.Errorf("分片 %d 只收到 %d/%d 字节", index, written, want)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return uploadSessionView{}, err
	}

	chunks, _, err := s.receivedChunks(id)
	if err != nil {
		return uploadSessionView{}, err
	}
	return s.view(sess, chunks), nil
}

// assembled is the result of stitching a session back together: the open file
// plus the header shape storeUploadedPayload expects. Keeping this type local
// to the session store is what lets the encryption, naming and sidecar rules
// stay in one place -- the chunked path ends exactly where the single-request
// path begins.
type assembledUpload struct {
	File    *os.File
	Header  *multipart.FileHeader
	Session uploadSession
}

func (a *assembledUpload) Close() error {
	if a == nil || a.File == nil {
		return nil
	}
	err := a.File.Close()
	_ = os.Remove(a.File.Name())
	return err
}

var errUploadSessionIncomplete = errors.New("分片尚未传完")
var errUploadSessionNotFound = errors.New("上传会话不存在或已过期")

// assemble materialises the complete file in the session directory and opens
// it. It refuses to run while any chunk is missing: a partial file that looked
// complete would be worse than a refusal, because the console would go on to
// encrypt and import it.
func (s *uploadSessionStore) assemble(id string) (*assembledUpload, error) {
	if !validSessionID(id) {
		return nil, errUploadSessionNotFound
	}
	lock := s.lockFor(id)
	lock.Lock()
	defer lock.Unlock()

	sess, err := s.load(id)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errUploadSessionNotFound
		}
		return nil, err
	}

	chunks, present, err := s.receivedChunks(id)
	if err != nil {
		return nil, err
	}
	total := totalChunksFor(sess.Size, sess.ChunkSize)
	if len(chunks) != total || present != sess.Size {
		missing := missingChunks(total, chunks)
		return nil, fmt.Errorf("%w: 已有 %d/%d 片，缺少 %v", errUploadSessionIncomplete, len(chunks), total, summarizeMissing(missing))
	}

	dir := s.dir(id)
	outPath := filepath.Join(dir, "assembled.bin")
	out, err := os.Create(outPath)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			out.Close()
			_ = os.Remove(outPath)
		}
	}()

	buf := make([]byte, 1<<20)
	for index := 0; index < total; index++ {
		part, openErr := os.Open(filepath.Join(dir, chunkFileName(index)))
		if openErr != nil {
			return nil, openErr
		}
		_, copyErr := io.CopyBuffer(out, part, buf)
		closeErr := part.Close()
		if copyErr != nil {
			return nil, copyErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
	}
	if err := out.Sync(); err != nil {
		return nil, err
	}
	if err := out.Close(); err != nil {
		return nil, err
	}
	ok = true

	// Reopen read-only: the caller only reads, and a write handle would let the
	// size change under the encryption step.
	file, err := os.Open(outPath)
	if err != nil {
		_ = os.Remove(outPath)
		return nil, err
	}
	return &assembledUpload{
		File:    file,
		Header:  &multipart.FileHeader{Filename: sess.OriginalName, Size: sess.Size},
		Session: sess,
	}, nil
}

// discard drops a session once its payload has been stored, and also when the
// console abandons it. It is best effort: a leftover directory costs disk but
// is invisible to the file listing.
func (s *uploadSessionStore) discard(id string) {
	if !validSessionID(id) {
		return
	}
	lock := s.lockFor(id)
	lock.Lock()
	defer lock.Unlock()
	if err := os.RemoveAll(s.dir(id)); err != nil && !os.IsNotExist(err) {
		// Deliberately not fatal: the upload already succeeded, and the next
		// session for the same file rebuilds its chunks from scratch anyway.
		_ = err
	}
	s.releaseLock(id)
}

func missingChunks(total int, present []int) []int {
	have := make(map[int]bool, len(present))
	for _, index := range present {
		have[index] = true
	}
	missing := make([]int, 0, total-len(present))
	for index := 0; index < total; index++ {
		if !have[index] {
			missing = append(missing, index)
		}
	}
	return missing
}

// summarizeMissing keeps the message readable for a transfer that has many
// holes: the first few indexes identify what to resend, and the count says how
// much is left.
func summarizeMissing(missing []int) string {
	const head = 8
	if len(missing) <= head {
		return fmt.Sprint(missing)
	}
	return fmt.Sprintf("%v…共 %d 片", missing[:head], len(missing))
}

// handleUploadSession answers the create-or-resume call. The client sends the
// file's identity; the reply says which chunks the server already holds, which
// is the entire resume protocol.
func handleUploadSession(store *uploadSessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeEnvelope(w, http.StatusMethodNotAllowed, "仅支持 POST 方法", nil, http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Name         string `json:"name"`
			Size         int64  `json:"size"`
			LastModified int64  `json:"lastModified"`
			ChunkSize    int64  `json:"chunkSize"`
			EncryptMode  string `json:"encryptMode"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
			writeEnvelope(w, http.StatusBadRequest, "解析上传会话请求失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.Name) == "" {
			writeEnvelope(w, http.StatusBadRequest, "缺少文件名", nil, http.StatusBadRequest)
			return
		}
		name := sanitizeUploadFilename(req.Name)

		view, err := store.begin(name, req.Size, req.LastModified, req.ChunkSize, req.EncryptMode)
		if err != nil {
			writeEnvelope(w, http.StatusInternalServerError, "创建上传会话失败: "+err.Error(), nil, http.StatusInternalServerError)
			return
		}
		writeEnvelope(w, http.StatusOK, "success", view, 0)
	}
}

// handleUploadChunk accepts one raw body as chunk index of the named session.
// The body is application/octet-stream rather than multipart so that the
// request carries no framing overhead and the size check is exact.
func handleUploadChunk(store *uploadSessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeEnvelope(w, http.StatusMethodNotAllowed, "仅支持 POST 方法", nil, http.StatusMethodNotAllowed)
			return
		}

		sessionID := strings.TrimSpace(r.URL.Query().Get("sessionId"))
		index, convErr := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("index")))
		if sessionID == "" || convErr != nil {
			writeEnvelope(w, http.StatusBadRequest, "缺少 sessionId 或 index 参数", nil, http.StatusBadRequest)
			return
		}

		limit := int64(maxUploadChunkSize + chunkOverheadBytes)
		view, err := store.writeChunk(sessionID, index, http.MaxBytesReader(w, r.Body, limit))
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, errUploadSessionNotFound) {
				status = http.StatusNotFound
			}
			writeEnvelope(w, status, "写入分片失败: "+err.Error(), nil, status)
			return
		}
		writeEnvelope(w, http.StatusOK, "success", view, 0)
	}
}

// handleUploadComplete stitches the session and hands the result to the same
// storage step the single-request upload uses, so encryption, file naming and
// the data-key sidecar behave identically on both paths.
func handleUploadComplete(store *uploadSessionStore, uploadDir, addr string, mgr *instanceManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeEnvelope(w, http.StatusMethodNotAllowed, "仅支持 POST 方法", nil, http.StatusMethodNotAllowed)
			return
		}

		b, resolveErr := mgr.resolveLenient(r)
		if writeInstanceError(w, resolveErr) {
			return
		}

		sessionID := strings.TrimSpace(r.URL.Query().Get("sessionId"))
		if sessionID == "" {
			writeEnvelope(w, http.StatusBadRequest, "缺少 sessionId 参数", nil, http.StatusBadRequest)
			return
		}

		uploadStarted := time.Now()
		assembled, err := store.assemble(sessionID)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, errUploadSessionNotFound) {
				status = http.StatusNotFound
			}
			writeEnvelope(w, status, "合并分片失败: "+err.Error(), nil, status)
			return
		}
		defer assembled.Close()

		encryptMode := resolveEncryptMode(r.FormValue("encryptMode"), r.FormValue("encrypt"), assembled.Session.EncryptMode)

		uploaded, err := storeUploadedPayload(uploadDir, addr, assembled.File, assembled.Header, encryptMode,
			b.register.get().TaaPublicKey, r.FormValue("publicKey"))
		if err != nil {
			status, message := uploadFailureStatus(err)
			writeEnvelope(w, status, message, nil, status)
			return
		}

		// Only a stored payload ends the session: a failure above leaves the
		// chunks in place so the console can retry the merge without
		// re-sending the file.
		store.discard(sessionID)

		writeEnvelope(w, http.StatusOK, "文件上传成功", map[string]any{
			"filename":      uploaded.Filename,
			"originalName":  uploaded.OriginalName,
			"size":          uploaded.Size,
			"url":           uploaded.URL,
			"encrypted":     uploaded.Encrypted,
			"dataKeyCipher": uploaded.DataKeyCipher,
			"uploadedAt":    uploaded.UploadedAt,
			"chunked":       true,
			"elapsedMs":     time.Since(uploadStarted).Milliseconds(),
		}, 0)
	}
}
