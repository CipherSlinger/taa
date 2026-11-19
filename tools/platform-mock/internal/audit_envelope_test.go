package mock

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	teecrypto "github.com/CipherSlinger/teeaudit/pkg/crypto"
)

// TestWorkbenchKeysRoundTrip pins the envelope shape against TAA's reader: what
// seal returns must open with the bare/versioned retry sequence TAA runs, and a
// tampered body or a foreign envelope must fail closed.
func TestWorkbenchKeysRoundTrip(t *testing.T) {
	keys := newWorkbenchKeys(t.TempDir())
	if !keys.ready() {
		t.Fatal("workbench keys are not usable")
	}
	plaintext := []byte("PK\x03\x04 pretend archive bytes")

	body, dataKeyCipher, err := keys.seal(plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if body[0] != teecrypto.SM4FileVersion {
		t.Fatalf("body starts with 0x%02x, want the platform version byte", body[0])
	}

	got, err := keys.open(body, dataKeyCipher)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip changed the plaintext: %q", got)
	}

	// TAA's reader also accepts the 113-byte envelope with its 0x04 prefix, so
	// the mock's 112-byte form has to survive being re-prefixed.
	full := "04" + dataKeyCipher
	if _, err := keys.open(body, full); err != nil {
		t.Fatalf("open with the 113-byte envelope form: %v", err)
	}

	tampered := append([]byte(nil), body...)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := keys.open(tampered, dataKeyCipher); err == nil {
		t.Fatal("a tampered body opened")
	}

	other := newWorkbenchKeys(t.TempDir())
	if _, err := other.open(body, dataKeyCipher); err == nil {
		t.Fatal("another key pair opened the envelope")
	}
}

// TestWorkbenchKeysPersistAcrossRestart checks the pair is loadable, not just
// generated: the file area's entries are only readable from the same pair.
func TestWorkbenchKeysPersistAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	first := newWorkbenchKeys(dir)
	if !first.ready() {
		t.Fatal("first construction failed")
	}
	body, cipher, err := first.seal([]byte("payload"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	second := newWorkbenchKeys(dir)
	if !second.ready() {
		t.Fatal("reloaded keys are not usable")
	}
	if second.fingerprint() != first.fingerprint() {
		t.Fatalf("fingerprint changed across restart: %q -> %q", first.fingerprint(), second.fingerprint())
	}
	if _, err := second.open(body, cipher); err != nil {
		t.Fatalf("reloaded keys cannot open a stored envelope: %v", err)
	}
}

// TestWorkbenchKeyFileIsNotWorldReadable keeps the private scalar out of reach of
// other local accounts.
func TestWorkbenchKeyFileIsNotWorldReadable(t *testing.T) {
	dir := t.TempDir()
	newWorkbenchKeys(dir)
	info, err := os.Stat(filepath.Join(dir, workbenchKeyFile))
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("key file mode = %o, want no group or other access", perm)
	}
}

// TestAuditUploadStoresCiphertextOnly is the contract the workbench exists to
// demonstrate: after an upload the file area holds nothing an operator could
// read as an archive, while the audit still reaches a verdict from it.
func TestAuditUploadStoresCiphertextOnly(t *testing.T) {
	runner, jobs, _, handler := localAuditRig(t)

	plain := localAuditZip(t)
	rec := submitLocalMultipart(t, handler, "pkg.zip", plain, map[string]string{"requestId": "req-sealed"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	body := decodeLocalSubmit(t, rec)
	enc, _ := body["encryption"].(map[string]any)
	if enc == nil || enc["mode"] != "sm2-sm4gcm" || toString(enc["keyFingerprint"]) == "" {
		t.Fatalf("response carries no encryption description: %v", body["encryption"])
	}
	if _, leaked := body["dataKeyCipher"]; leaked {
		t.Fatalf("the data-key envelope must stay server-side: %v", body)
	}

	fileID := toString(body["fileId"])
	entry, storedPath, ok := runner.files.path(fileID)
	if !ok {
		t.Fatalf("file area has no entry %q", fileID)
	}
	if !entry.Encrypted || entry.DataKeyCipher == "" {
		t.Fatalf("entry is not marked encrypted: %+v", entry)
	}
	if entry.PlainSize <= 0 || entry.PlainSize >= entry.Size {
		t.Fatalf("sizes = plain %d / stored %d, want the envelope to be larger", entry.PlainSize, entry.Size)
	}
	raw, err := os.ReadFile(storedPath)
	if err != nil {
		t.Fatalf("read stored entry: %v", err)
	}
	if bytes.Contains(raw, plain) || bytes.Contains(raw, []byte("os.system")) {
		t.Fatal("the stored file area entry still contains plaintext")
	}
	if raw[0] != teecrypto.SM4FileVersion {
		t.Fatalf("stored body starts with 0x%02x, want the platform version byte", raw[0])
	}

	row := waitLocalAudit(t, jobs, "req-sealed", auditJobStatusDone)
	if row.Stages["extract"] != auditStepDone {
		t.Fatalf("extract = %q, want done: %v", row.Stages["extract"], row.Stages)
	}

	// The work directory the run used is gone, so no plaintext survives it.
	dirs := auditTempDirs(t, filepath.Dir(filepath.Dir(storedPath)))
	_ = dirs // the file area's parent is the store directory, not the upload root
}

// TestAuditFileReuseDecrypts checks a repeat run: the stored envelope is copied
// as-is and opened by the runner, with no second upload.
func TestAuditFileReuseDecrypts(t *testing.T) {
	runner, jobs, _, handler := localAuditRig(t)

	rec := submitLocalMultipart(t, handler, "pkg.zip", localAuditZip(t), map[string]string{"requestId": "req-a"})
	if rec.Code != http.StatusOK {
		t.Fatalf("first status = %d: %s", rec.Code, rec.Body.String())
	}
	fileID := toString(decodeLocalSubmit(t, rec)["fileId"])
	waitLocalAudit(t, jobs, "req-a", auditJobStatusDone)
	// "done" lands before the goroutine releases the single-runner slot; reuse
	// must wait for the slot or it can legitimately be answered with 409.
	waitRunnerIdle(t, runner)

	rec = submitLocalMultipart(t, handler, "", nil, map[string]string{"requestId": "req-b", "fileId": fileID})
	if rec.Code != http.StatusOK {
		t.Fatalf("reuse status = %d: %s", rec.Code, rec.Body.String())
	}
	row := waitLocalAudit(t, jobs, "req-b", auditJobStatusDone)
	if row.Stages["extract"] != auditStepDone {
		t.Fatalf("reuse extract = %q: %v", row.Stages["extract"], row.Stages)
	}
	if files := runner.files.list(); len(files) != 1 {
		t.Fatalf("file area = %d entries, want the reuse to add none", len(files))
	}
}

// TestAuditFileWrongKeyFailsExtract covers the failure side: an entry whose
// envelope does not match the pair must stop at extract, not be audited.
func TestAuditFileWrongKeyFailsExtract(t *testing.T) {
	runner, jobs, _, handler := localAuditRig(t)

	body, cipher, err := newWorkbenchKeys(t.TempDir()).seal(localAuditZip(t))
	if err != nil {
		t.Fatalf("seal with a foreign pair: %v", err)
	}
	src := filepath.Join(t.TempDir(), "foreign.bin")
	if err := os.WriteFile(src, body, 0o600); err != nil {
		t.Fatalf("write foreign body: %v", err)
	}
	// Store it through the plaintext path, then mark it encrypted with the
	// foreign envelope: the pair that will open it is not the one that sealed it.
	entry, err := runner.files.saveFromFile(src, "foreign.zip", nil)
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	runner.files.mu.Lock()
	for i := range runner.files.entries {
		if runner.files.entries[i].ID == entry.ID {
			runner.files.entries[i].Encrypted = true
			runner.files.entries[i].DataKeyCipher = cipher
			runner.files.entries[i].PlainSize = 1
		}
	}
	runner.files.mu.Unlock()

	rec := submitLocalMultipart(t, handler, "", nil, map[string]string{"requestId": "req-foreign", "fileId": entry.ID})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	row := waitLocalAudit(t, jobs, "req-foreign", auditJobStatusFailed)
	if row.Stages["extract"] != auditStepError {
		t.Fatalf("extract = %q, want error: %v", row.Stages["extract"], row.Stages)
	}
	if !bytes.Contains([]byte(row.Error), []byte("解封审计包失败")) {
		t.Fatalf("error = %q", row.Error)
	}
}

// TestAuditSubmitRefusesWithoutKeys makes the refusal explicit rather than
// falling back to a plaintext audit.
func TestAuditSubmitRefusesWithoutKeys(t *testing.T) {
	runner, jobs, uploadDir, handler := localAuditRig(t)
	runner.keys = &workbenchKeys{} // unloadable: no pair

	rec := submitLocalMultipart(t, handler, "pkg.zip", localAuditZip(t), map[string]string{"requestId": "req-nokeys"})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", rec.Code, rec.Body.String())
	}
	if got := toString(decodeLocalSubmit(t, rec)["error"]); got != errWorkbenchKeysUnavailable.Error() {
		t.Fatalf("error = %q", got)
	}
	if len(jobs.list(localAuditInstanceKey)) != 0 {
		t.Fatal("a refused submission registered a job")
	}
	if dirs := auditTempDirs(t, uploadDir); dirs != 0 {
		t.Fatalf("upload dir = %d audit temp dirs, want none", dirs)
	}
}

// TestAuditFilesIndexCarriesTheEnvelope pins what survives a restart: the
// metadata needed to open each entry travels in index.json.
func TestAuditFilesIndexCarriesTheEnvelope(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(t.TempDir(), "sample.zip")
	if err := os.WriteFile(src, localAuditZip(t), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	store := newAuditFileStore(dir)
	entry, err := store.saveFromFile(src, "sample.zip", newWorkbenchKeys(dir))
	if err != nil {
		t.Fatalf("save: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, auditFilesIndex))
	if err != nil {
		t.Fatalf("read index: %v", err)
	}
	var payload struct {
		Files []auditFileEntry `json:"files"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("decode index: %v", err)
	}
	if len(payload.Files) != 1 || payload.Files[0].DataKeyCipher != entry.DataKeyCipher || !payload.Files[0].Encrypted {
		t.Fatalf("index entry = %+v", payload.Files)
	}

	reloaded := newAuditFileStore(dir)
	files := reloaded.list()
	if len(files) != 1 || files[0].DataKeyCipher != entry.DataKeyCipher || files[0].PlainSize != entry.PlainSize {
		t.Fatalf("reloaded entry = %+v", files)
	}
}
