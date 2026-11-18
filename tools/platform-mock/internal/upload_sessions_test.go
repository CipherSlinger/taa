package mock

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

// newChunkedUploadServer wires the three resumable-upload routes beside the
// single-request one, plus the file listing and download mounts, so a test can
// compare the two paths end to end.
func newChunkedUploadServer(t *testing.T, uploadDir string) *httptest.Server {
	t.Helper()
	mgr := testManagerWith(t, "", nil)
	store := newUploadSessionStore(uploadDir)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/upload", uploadHandler("127.0.0.1:6001", uploadDir, mgr))
	mux.HandleFunc("/api/upload/session", handleUploadSession(store))
	mux.HandleFunc("/api/upload/chunk", handleUploadChunk(store))
	mux.HandleFunc("/api/upload/complete", handleUploadComplete(store, uploadDir, "127.0.0.1:6001", mgr))
	mux.HandleFunc("/api/uploads", uploadListHandler("127.0.0.1:6001", uploadDir))
	mux.Handle("/files/", http.StripPrefix("/files/", http.FileServer(http.Dir(uploadDir))))
	return httptest.NewServer(mux)
}

// testPayload builds deterministic, non-repeating bytes so a reassembly bug
// that duplicates or drops a region cannot go unnoticed.
func testPayload(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte((i*31 + i/251) % 251)
	}
	return data
}

func startUploadSession(t *testing.T, serverURL, name string, size, lastModified, chunkSize int64, encryptMode string) uploadSessionView {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"name":         name,
		"size":         size,
		"lastModified": lastModified,
		"chunkSize":    chunkSize,
		"encryptMode":  encryptMode,
	})
	resp, err := http.Post(serverURL+"/api/upload/session", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	defer resp.Body.Close()
	var api struct {
		Msg    string            `json:"msg"`
		Error  int               `json:"error"`
		Result uploadSessionView `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&api); err != nil {
		t.Fatalf("decode session response: %v", err)
	}
	if resp.StatusCode != http.StatusOK || api.Error != 0 {
		t.Fatalf("session = %d/%d msg=%s", resp.StatusCode, api.Error, api.Msg)
	}
	return api.Result
}

func putChunk(t *testing.T, serverURL, sessionID string, index int, data []byte) (int, string) {
	t.Helper()
	resp, err := http.Post(
		fmt.Sprintf("%s/api/upload/chunk?sessionId=%s&index=%d", serverURL, url.QueryEscape(sessionID), index),
		"application/octet-stream",
		bytes.NewReader(data),
	)
	if err != nil {
		t.Fatalf("send chunk %d: %v", index, err)
	}
	defer resp.Body.Close()
	var api struct {
		Msg   string `json:"msg"`
		Error int    `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&api)
	return resp.StatusCode, api.Msg
}

func completeUpload(t *testing.T, serverURL, sessionID string, fields map[string]string) (int, apiResponse) {
	t.Helper()
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	for k, v := range fields {
		if err := writer.WriteField(k, v); err != nil {
			t.Fatalf("write field %s: %v", k, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/api/upload/complete?sessionId=%s", serverURL, url.QueryEscape(sessionID)), body)
	if err != nil {
		t.Fatalf("create complete request: %v", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	defer resp.Body.Close()
	var api apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&api); err != nil {
		t.Fatalf("decode complete response: %v", err)
	}
	return resp.StatusCode, api
}

// sendAllChunks uploads every chunk of payload under sess in index order.
func sendAllChunks(t *testing.T, serverURL string, sess uploadSessionView, payload []byte) {
	t.Helper()
	for index := 0; index < sess.TotalChunks; index++ {
		start := int64(index) * sess.ChunkSize
		end := start + sess.ChunkSize
		if end > int64(len(payload)) {
			end = int64(len(payload))
		}
		if status, msg := putChunk(t, serverURL, sess.SessionID, index, payload[start:end]); status != http.StatusOK {
			t.Fatalf("chunk %d = %d msg=%s", index, status, msg)
		}
	}
}

// TestChunkedUploadReassemblesExactly is the core contract: the file the
// server stores must be byte-identical to the file the browser holds, with the
// awkward final short chunk included.
func TestChunkedUploadReassemblesExactly(t *testing.T) {
	uploadDir := filepath.Join(t.TempDir(), "uploads")
	server := newChunkedUploadServer(t, uploadDir)
	defer server.Close()

	// Deliberately not a multiple of the chunk size: the last chunk is short.
	payload := testPayload(10*1024*1024 + 4321)
	const chunkSize = 1024 * 1024
	session := startUploadSession(t, server.URL, "model.zip", int64(len(payload)), 1792982830000, chunkSize, "none")
	if session.TotalChunks != 11 {
		t.Fatalf("totalChunks = %d, want 11", session.TotalChunks)
	}

	sendAllChunks(t, server.URL, session, payload)

	status, api := completeUpload(t, server.URL, session.SessionID, nil)
	if status != http.StatusOK || api.Error != 0 {
		t.Fatalf("complete = %d/%d msg=%s", status, api.Error, api.Msg)
	}
	result := api.Result.(map[string]any)
	filename, _ := result["filename"].(string)
	if filename == "" {
		t.Fatalf("complete result lacks filename: %+v", result)
	}

	stored, err := os.ReadFile(filepath.Join(uploadDir, filename))
	if err != nil {
		t.Fatalf("read stored file: %v", err)
	}
	if len(stored) != len(payload) {
		t.Fatalf("stored %d bytes, want %d", len(stored), len(payload))
	}
	if sha256.Sum256(stored) != sha256.Sum256(payload) {
		t.Fatalf("stored content differs from the uploaded file")
	}

	// The session directory is spent once the payload is stored; a leftover
	// would keep the whole file on disk twice.
	if _, err := os.Stat(filepath.Join(uploadDir, uploadSessionDirName, session.SessionID)); !os.IsNotExist(err) {
		t.Fatalf("session directory survived a successful complete (err=%v)", err)
	}

	// The file listing has to show the stored payload, otherwise the console
	// would report success and then display nothing.
	resp, err := http.Get(server.URL + "/api/uploads")
	if err != nil {
		t.Fatalf("list uploads: %v", err)
	}
	defer resp.Body.Close()
	files := readUploadList(t, resp)
	found := false
	for _, f := range files {
		if f.Filename == filename {
			found = true
		}
	}
	if !found {
		t.Fatalf("stored file %q missing from the listing: %+v", filename, files)
	}
}

// TestChunkedUploadResumesAfterMissingChunks is the reason this path exists: a
// transfer that dies partway must come back to the chunks already on disk
// rather than demanding the whole file again.
func TestChunkedUploadResumesAfterMissingChunks(t *testing.T) {
	uploadDir := filepath.Join(t.TempDir(), "uploads")
	server := newChunkedUploadServer(t, uploadDir)
	defer server.Close()

	payload := testPayload(4 * 1024 * 1024)
	const chunkSize = 1024 * 1024
	const lastModified = 1792982830000

	first := startUploadSession(t, server.URL, "resume.bin", int64(len(payload)), lastModified, chunkSize, "none")
	// Send chunks 0 and 1, then "lose the connection".
	for index := 0; index < 2; index++ {
		start := index * chunkSize
		if status, msg := putChunk(t, server.URL, first.SessionID, index, payload[start:start+chunkSize]); status != http.StatusOK {
			t.Fatalf("chunk %d = %d msg=%s", index, status, msg)
		}
	}

	// A completing request now must refuse rather than store a truncated file.
	status, api := completeUpload(t, server.URL, first.SessionID, nil)
	if status == http.StatusOK || api.Error == 0 {
		t.Fatalf("complete on a partial session succeeded: %d/%d", status, api.Error)
	}
	if _, err := os.Stat(filepath.Join(uploadDir, uploadSessionDirName, first.SessionID)); err != nil {
		t.Fatalf("a refused complete discarded the session: %v", err)
	}

	// Re-selecting the same unchanged file must address the same session and
	// report the two chunks already held.
	second := startUploadSession(t, server.URL, "resume.bin", int64(len(payload)), lastModified, chunkSize, "none")
	if second.SessionID != first.SessionID {
		t.Fatalf("session id changed on resume: %s vs %s", second.SessionID, first.SessionID)
	}
	if len(second.Received) != 2 || second.Received[0] != 0 || second.Received[1] != 1 {
		t.Fatalf("resume reported received=%v, want [0 1]", second.Received)
	}

	for index := 2; index < second.TotalChunks; index++ {
		start := index * chunkSize
		if status, msg := putChunk(t, server.URL, second.SessionID, index, payload[start:start+chunkSize]); status != http.StatusOK {
			t.Fatalf("chunk %d = %d msg=%s", index, status, msg)
		}
	}
	status, api = completeUpload(t, server.URL, second.SessionID, nil)
	if status != http.StatusOK || api.Error != 0 {
		t.Fatalf("complete after resume = %d/%d msg=%s", status, api.Error, api.Msg)
	}
	result := api.Result.(map[string]any)
	stored, err := os.ReadFile(filepath.Join(uploadDir, result["filename"].(string)))
	if err != nil {
		t.Fatalf("read stored file: %v", err)
	}
	if sha256.Sum256(stored) != sha256.Sum256(payload) {
		t.Fatalf("resumed upload stored different content")
	}
}

// TestChunkedUploadAcceptsADuplicateChunk matters because the console retries a
// chunk whose response was lost. The retry arrives with the same bytes, and it
// must leave the session resumable rather than wedged.
func TestChunkedUploadAcceptsADuplicateChunk(t *testing.T) {
	uploadDir := filepath.Join(t.TempDir(), "uploads")
	server := newChunkedUploadServer(t, uploadDir)
	defer server.Close()

	const chunkSize = 1024 * 1024
	payload := testPayload(2 * chunkSize)
	session := startUploadSession(t, server.URL, "retry.bin", int64(len(payload)), 5, chunkSize, "none")

	if status, msg := putChunk(t, server.URL, session.SessionID, 0, payload[:chunkSize]); status != http.StatusOK {
		t.Fatalf("first chunk = %d msg=%s", status, msg)
	}
	if status, msg := putChunk(t, server.URL, session.SessionID, 0, payload[:chunkSize]); status != http.StatusOK {
		t.Fatalf("retried chunk = %d msg=%s", status, msg)
	}
	if status, msg := putChunk(t, server.URL, session.SessionID, 1, payload[chunkSize:]); status != http.StatusOK {
		t.Fatalf("final chunk = %d msg=%s", status, msg)
	}

	status, api := completeUpload(t, server.URL, session.SessionID, nil)
	if status != http.StatusOK || api.Error != 0 {
		t.Fatalf("complete = %d/%d msg=%s", status, api.Error, api.Msg)
	}
	stored, err := os.ReadFile(filepath.Join(uploadDir, api.Result.(map[string]any)["filename"].(string)))
	if err != nil {
		t.Fatalf("read stored file: %v", err)
	}
	if sha256.Sum256(stored) != sha256.Sum256(payload) {
		t.Fatalf("a retried chunk changed the stored content")
	}
}

// TestChunkedUploadRefusesAShortChunk pins the guard that keeps a truncated
// request from being stitched into the file: the chunk is validated against the
// length its index implies, not against whatever arrived.
func TestChunkedUploadRefusesAShortChunk(t *testing.T) {
	uploadDir := filepath.Join(t.TempDir(), "uploads")
	server := newChunkedUploadServer(t, uploadDir)
	defer server.Close()

	const chunkSize = 1024 * 1024
	payload := testPayload(2 * chunkSize)
	session := startUploadSession(t, server.URL, "short.bin", int64(len(payload)), 1, chunkSize, "none")

	status, msg := putChunk(t, server.URL, session.SessionID, 0, payload[:chunkSize/2])
	if status == http.StatusOK {
		t.Fatalf("a half-length chunk was accepted")
	}
	if msg == "" {
		t.Fatalf("refusal carried no message")
	}
	chunks, _, err := newUploadSessionStore(uploadDir).receivedChunks(session.SessionID)
	if err != nil {
		t.Fatalf("list chunks: %v", err)
	}
	if len(chunks) != 0 {
		t.Fatalf("refused chunk was recorded as received: %v", chunks)
	}
}

// TestChunkedUploadSeparatesFilesWithTheSameName is the identity contract: two
// different files that happen to share a name must not share chunks.
func TestChunkedUploadSeparatesFilesWithTheSameName(t *testing.T) {
	uploadDir := filepath.Join(t.TempDir(), "uploads")
	server := newChunkedUploadServer(t, uploadDir)
	defer server.Close()

	const chunkSize = 1024 * 1024
	first := startUploadSession(t, server.URL, "same.zip", int64(chunkSize), 111, chunkSize, "none")
	second := startUploadSession(t, server.URL, "same.zip", int64(chunkSize), 222, chunkSize, "none")
	if first.SessionID == second.SessionID {
		t.Fatalf("files with different mtimes shared a session")
	}

	payload := testPayload(chunkSize)
	if status, msg := putChunk(t, server.URL, first.SessionID, 0, payload); status != http.StatusOK {
		t.Fatalf("chunk = %d msg=%s", status, msg)
	}
	resumed := startUploadSession(t, server.URL, "same.zip", int64(chunkSize), 111, chunkSize, "none")
	if len(resumed.Received) != 1 {
		t.Fatalf("first file's chunk was lost: received=%v", resumed.Received)
	}
	other := startUploadSession(t, server.URL, "same.zip", int64(chunkSize), 222, chunkSize, "none")
	if len(other.Received) != 0 {
		t.Fatalf("second file saw the first file's chunks: %v", other.Received)
	}
}

// TestChunkedUploadCarriesTheEncryptModeFromTheSession pins the fallback the
// complete endpoint relies on: the console does not resend the mode, so the
// session's record has to drive the storage step.
func TestChunkedUploadCarriesTheEncryptModeFromTheSession(t *testing.T) {
	uploadDir := filepath.Join(t.TempDir(), "uploads")
	server := newChunkedUploadServer(t, uploadDir)
	defer server.Close()

	content := []byte("plaintext stays plaintext")
	const chunkSize = 256 * 1024
	session := startUploadSession(t, server.URL, "plain.bin", int64(len(content)), 9, chunkSize, "none")
	sendAllChunks(t, server.URL, session, content)
	// An empty encryptMode field must defer to the session, not force encryption.
	status, api := completeUpload(t, server.URL, session.SessionID, map[string]string{"encryptMode": ""})
	if status != http.StatusOK || api.Error != 0 {
		t.Fatalf("complete = %d/%d msg=%s", status, api.Error, api.Msg)
	}
	result := api.Result.(map[string]any)
	if encrypted, _ := result["encrypted"].(bool); encrypted {
		t.Fatalf("a session negotiated as plaintext was stored encrypted")
	}
	stored, err := os.ReadFile(filepath.Join(uploadDir, result["filename"].(string)))
	if err != nil {
		t.Fatalf("read stored file: %v", err)
	}
	if !bytes.Equal(stored, content) {
		t.Fatalf("stored = %q, want the plaintext bytes", stored)
	}
}

// TestChunkedUploadRefusesUnknownSession keeps a fabricated session id from
// creating directories on demand.
func TestChunkedUploadRefusesUnknownSession(t *testing.T) {
	uploadDir := filepath.Join(t.TempDir(), "uploads")
	server := newChunkedUploadServer(t, uploadDir)
	defer server.Close()

	fake := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	status, _ := putChunk(t, server.URL, fake, 0, []byte("x"))
	if status != http.StatusNotFound {
		t.Fatalf("unknown session chunk = %d, want 404", status)
	}

	status, _ = putChunk(t, server.URL, "../../etc", 0, []byte("x"))
	if status != http.StatusNotFound {
		t.Fatalf("path-shaped session id = %d, want 404", status)
	}
	if _, err := os.Stat(filepath.Join(uploadDir, uploadSessionDirName, fake)); !os.IsNotExist(err) {
		t.Fatalf("a refused chunk created a session directory (err=%v)", err)
	}
}

// TestChunkedUploadRefusesAnOutOfRangeIndex stops an index past the end from
// being written: it would be counted by the resume state but never used by the
// reassembly, leaving a session that can neither complete nor clean up.
func TestChunkedUploadRefusesAnOutOfRangeIndex(t *testing.T) {
	uploadDir := filepath.Join(t.TempDir(), "uploads")
	server := newChunkedUploadServer(t, uploadDir)
	defer server.Close()

	const chunkSize = 256 * 1024
	session := startUploadSession(t, server.URL, "range.bin", 1000, 3, chunkSize, "none")
	if status, _ := putChunk(t, server.URL, session.SessionID, 5, []byte("x")); status == http.StatusOK {
		t.Fatalf("an index past the end was accepted")
	}
	if status, _ := putChunk(t, server.URL, session.SessionID, -1, []byte("x")); status == http.StatusOK {
		t.Fatalf("a negative index was accepted")
	}
}

// TestSingleUploadPathStillWorks guards the refactor that moved encryptMode
// resolution into resolveEncryptMode: the one-request path must behave exactly
// as before for both the legacy and the explicit field.
func TestSingleUploadPathStillWorks(t *testing.T) {
	uploadDir := filepath.Join(t.TempDir(), "uploads")
	server := newUploadTestServer(t, uploadDir)
	defer server.Close()

	// encryptMode=none keeps the old behaviour: the plaintext lands as-is.
	status, api := postMultipartUploadWithFields(t, server.URL+"/api/upload", "plain.txt", []byte("hello"),
		map[string]string{"encryptMode": "none"})
	if status != http.StatusOK || api.Error != 0 {
		t.Fatalf("plain upload = %d/%d msg=%s", status, api.Error, api.Msg)
	}
	result := api.Result.(map[string]any)
	if encrypted, _ := result["encrypted"].(bool); encrypted {
		t.Fatalf("encryptMode=none stored an encrypted file")
	}

	// The legacy encrypt=true spelling still selects the envelope layout. It
	// needs a public key; without one the request must be refused rather than
	// silently stored as plaintext.
	status, api = postMultipartUploadWithFields(t, server.URL+"/api/upload", "legacy.txt", []byte("hello"),
		map[string]string{"encrypt": "true"})
	if status == http.StatusOK && api.Error == 0 {
		if encrypted, _ := api.Result.(map[string]any)["encrypted"].(bool); !encrypted {
			t.Fatalf("legacy encrypt=true was stored without encryption")
		}
	}
}

func TestResolveEncryptMode(t *testing.T) {
	cases := []struct {
		mode, legacy, fallback, want string
	}{
		{"urlkey", "", "", "urlkey"},
		{"envelope", "", "", "envelope"},
		{"none", "", "envelope", "none"},
		{"URLKEY", "", "", "urlkey"},
		{"", "true", "", "envelope"},
		{"", "1", "", "envelope"},
		{"", "on", "", "envelope"},
		{"", "false", "urlkey", "none"},
		{"", "", "urlkey", "urlkey"},
		{"", "", "envelope", "envelope"},
		{"", "", "", "none"},
		{"bogus", "", "urlkey", "urlkey"},
	}
	for _, c := range cases {
		if got := resolveEncryptMode(c.mode, c.legacy, c.fallback); got != c.want {
			t.Errorf("resolveEncryptMode(%q, %q, %q) = %q, want %q", c.mode, c.legacy, c.fallback, got, c.want)
		}
	}
}

func TestChunkSizeBounds(t *testing.T) {
	cases := []struct {
		in   int64
		want int64
	}{
		{0, defaultUploadChunkSize},
		{-1, defaultUploadChunkSize},
		{1, minUploadChunkSize},
		{defaultUploadChunkSize, defaultUploadChunkSize},
		{1 << 30, maxUploadChunkSize},
	}
	for _, c := range cases {
		if got := clampChunkSize(c.in); got != c.want {
			t.Errorf("clampChunkSize(%d) = %d, want %d", c.in, got, c.want)
		}
	}

	if got := totalChunksFor(10, 4); got != 3 {
		t.Errorf("totalChunksFor(10, 4) = %d, want 3", got)
	}
	if got := chunkBytesFor(10, 4, 2); got != 2 {
		t.Errorf("chunkBytesFor(10, 4, 2) = %d, want 2", got)
	}
	if got := chunkBytesFor(10, 4, 3); got != 0 {
		t.Errorf("chunkBytesFor out of range = %d, want 0", got)
	}
	if got := totalChunksFor(0, 4); got != 0 {
		t.Errorf("totalChunksFor(0, 4) = %d, want 0", got)
	}
}
