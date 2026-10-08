package controller

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

func TestImportDepsRejectsEmptyResourceURL(t *testing.T) {
	_, server := setupTestServer(t)

	resp := postJSON(t, server.URL+"/v1/taa/importDeps", map[string]any{
		"resourceUrl": "",
		"requestId":   "req-1",
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestImportDepsRejectsMissingTaskAndRequestID(t *testing.T) {
	_, server := setupTestServer(t)

	resp := postJSON(t, server.URL+"/v1/taa/importDeps", map[string]any{
		"resourceUrl": "http://127.0.0.1:1/deps.tar.gz",
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestImportDepsRejectsNonPost(t *testing.T) {
	_, server := setupTestServer(t)

	resp, err := http.Get(server.URL + "/v1/taa/importDeps")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
}

// waitForDepsSlotRelease polls until the task slot taken by importDeps is fully released.
// Both fields are checked because release() clears them together under a single lock hold; a
// leaked slot (a dropped release() call) leaves CurrentOp pinned at "deps_importing" and would
// otherwise turn every later import into a permanent 409 with no test noticing.
// It does not reuse waitForIdle, which only inspects CurrentOp.
func waitForDepsSlotRelease(t *testing.T, state *TAAState) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		state.mu.RLock()
		released := state.CurrentOp == "idle" && state.ActiveTaskID == ""
		state.mu.RUnlock()
		if released {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for the importDeps task slot to be released")
}

// TestImportDepsDownloadFailureReleasesTaskSlot covers the one synchronous path the other tests
// skip: the request passes parameter validation and acquires the task slot, then the download
// fails. The handler must answer 500 and still hand the slot back.
func TestImportDepsDownloadFailureReleasesTaskSlot(t *testing.T) {
	state, server := setupTestServer(t)

	// Loopback is exempt from ProxyFromEnvironment and port 1 refuses immediately, so the
	// download fails at once with an error carrying no pkgerrors code, giving the handler's
	// 500 branch.
	resp := postJSON(t, server.URL+"/v1/taa/importDeps", map[string]any{
		"resourceUrl": "http://127.0.0.1:1/deps.tar.gz",
		"requestId":   "req-download-failure",
	})
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (msg=%q)", resp.StatusCode, api.Msg)
	}

	waitForDepsSlotRelease(t, state)
}

// TestImportDepsSuccessReleasesTaskSlot covers the happy path end to end against a local file
// server: 200, the expected message, and the slot released afterwards.
func TestImportDepsSuccessReleasesTaskSlot(t *testing.T) {
	state, server := setupTestServer(t)

	archive := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("fake wheelhouse bytes"))
	}))
	t.Cleanup(archive.Close)

	resp := postJSON(t, server.URL+"/v1/taa/importDeps", map[string]any{
		"resourceUrl": archive.URL + "/deps.tar.gz",
		"requestId":   "req-success",
	})
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (msg=%q)", resp.StatusCode, api.Msg)
	}
	if api.Msg != "依赖包已接收，处理中" {
		t.Fatalf("msg = %q, want %q", api.Msg, "依赖包已接收，处理中")
	}

	// The envelope is written before runAsyncSafe launches the goroutine, so the slot may
	// still be held here; poll rather than assert immediately.
	waitForDepsSlotRelease(t, state)
}

// TestProcessImportedDepsInstallsAndRecords drives the pipeline against a stub installer: the
// decrypted plaintext archive is validated, "installed" into DEPS_DIR/<sm3>, the state fields
// are set, and the audit marker reaches disk.
//
// Security.ScanEnabled=false makes auditAndReportDeps take the existing short-circuit and pass,
// so no audit hook has to be substituted -- the same technique the model-import tests use.
func TestProcessImportedDepsInstallsAndRecords(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.ScanEnabled = false

	origInstall := depsInstallFunc
	t.Cleanup(func() { depsInstallFunc = origInstall })

	var installedTarget string
	depsInstallFunc = func(wheelhouse, target string) error {
		installedTarget = target
		return os.MkdirAll(target, 0o755)
	}

	archive := buildTestDepsArchive(t)

	req := depsImportRequest{ResourceURL: "http://x/deps.tar.gz", RequestID: "req-d", TaskID: "task-d"}
	state.processImportedDeps(req, 1, archive)

	if !state.DepsImported {
		t.Fatal("DepsImported = false after a successful pipeline run")
	}
	if installedTarget != state.currentDepsDir() {
		t.Fatalf("install target = %q, want %q", installedTarget, state.currentDepsDir())
	}
	if _, err := os.Stat(filepath.Join(installedTarget, depsAuditMarker)); err != nil {
		t.Fatalf("audit marker missing: %v", err)
	}
}

// TestProcessImportedDepsSkipsWhenAlreadyAudited verifies idempotency: when the same hash is
// already marked, the installer must not be called again.
func TestProcessImportedDepsSkipsWhenAlreadyAudited(t *testing.T) {
	state, _ := setupTestState(t)

	origInstall := depsInstallFunc
	t.Cleanup(func() { depsInstallFunc = origInstall })

	calls := 0
	depsInstallFunc = func(wheelhouse, target string) error {
		calls++
		return os.MkdirAll(target, 0o755)
	}

	archive := buildTestDepsArchive(t)
	req := depsImportRequest{ResourceURL: "http://x/deps.tar.gz", RequestID: "req-i", TaskID: "task-i"}

	state.processImportedDeps(req, 1, buildTestDepsArchive(t))
	state.clearDepsState()
	state.processImportedDeps(req, 1, archive)

	if calls != 1 {
		t.Fatalf("installer called %d times, want 1 (second run must reuse the audited dir)", calls)
	}
}

// TestProcessImportedDepsRejectsArchiveWithoutWheel verifies that archive content validation
// happens inside the asynchronous pipeline.
func TestProcessImportedDepsRejectsArchiveWithoutWheel(t *testing.T) {
	state, _ := setupTestState(t)

	// The installer is stubbed to succeed so that ValidateWheelhouse is the only thing left
	// that can reject this archive. With the real installer a wheel-less wheelhouse also fails
	// at pip (no candidates under --no-index), and that independent failure would keep this
	// test green even if the content check were deleted -- it would then assert nothing.
	origInstall := depsInstallFunc
	t.Cleanup(func() { depsInstallFunc = origInstall })
	depsInstallFunc = func(wheelhouse, target string) error { return os.MkdirAll(target, 0o755) }

	archive := buildTestArchive(t, map[string]string{"requirements.txt": "torch\n"})
	req := depsImportRequest{ResourceURL: "http://x/bad.tar.gz", RequestID: "req-b", TaskID: "task-b"}

	state.processImportedDeps(req, 1, archive)

	if state.DepsImported {
		t.Fatal("DepsImported = true for an archive without any .whl")
	}
	assertDepsRootEmpty(t, state)
}

// TestProcessImportedDepsRejectsZipSlip verifies that a malicious archive's `../` entry is
// rejected and that nothing is written outside the wheelhouse.
//
// The traversal is deliberately only ONE level deep. That still leaves the unpack directory
// (whose parent is the deps root, see processImportedDeps), it just leaves it into a path the
// test can still observe. A deeper traversal such as "../../../../../../../../pwned" escapes
// all the way to "/pwned", where it is refused by the kernel (EACCES for a non-root runner)
// instead of by the guard under test: the extraction fails, the pipeline fails closed, and the
// test passes even with the guard deleted -- it would prove nothing. Keep the depth shallow:
// the escape target has to stay inside the test's own tree for the test to be discriminating.
func TestProcessImportedDepsRejectsZipSlip(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.ScanEnabled = false

	origInstall := depsInstallFunc
	t.Cleanup(func() { depsInstallFunc = origInstall })
	depsInstallFunc = func(wheelhouse, target string) error { return os.MkdirAll(target, 0o755) }

	// The escape target lives in the deps root, one level above the temp unpack dir, so a
	// guard that lets it through leaves a file the assertions below can see.
	escaped := filepath.Join(state.Security.GetDepsDir(), "pwned")
	archive := buildTestArchive(t, map[string]string{
		"requirements.txt":             "torch\n",
		"a-1.0-py3-none-any.whl":       "x",
		"../" + filepath.Base(escaped): "pwned",
	})

	req := depsImportRequest{ResourceURL: "http://x/evil.tar.gz", RequestID: "req-z", TaskID: "task-z"}
	state.processImportedDeps(req, 1, archive)

	if state.DepsImported {
		t.Fatal("DepsImported = true for an archive with a path-traversal entry")
	}
	if _, err := os.Stat(escaped); !os.IsNotExist(err) {
		t.Fatalf("zip-slip escaped the wheelhouse: %s exists", escaped)
	}
	assertDepsRootEmpty(t, state)
}

// TestProcessImportedDepsInstallFailureKeepsWorkingBinding covers the failure semantics spec 6
// correction 2 stresses most: a newcomer whose install fails must not unseat the dependency set
// that is already bound and working.
func TestProcessImportedDepsInstallFailureKeepsWorkingBinding(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.ScanEnabled = false

	origInstall := depsInstallFunc
	t.Cleanup(func() { depsInstallFunc = origInstall })

	depsInstallFunc = func(wheelhouse, target string) error { return os.MkdirAll(target, 0o755) }
	state.processImportedDeps(depsImportRequest{ResourceURL: "http://x/a.tar.gz", RequestID: "req-a", TaskID: "task-a"}, 1, buildTestDepsArchive(t))
	if !state.DepsImported {
		t.Fatal("first import did not bind; the rest of this test would be vacuous")
	}
	boundHash, boundDir := state.DepsHash, state.currentDepsDir()

	// The stub mirrors the real installer's documented contract -- it creates the target
	// before running pip, so a failure leaves the target partially populated -- which is
	// exactly why the pipeline, not pip, has to own the cleanup.
	depsInstallFunc = func(wheelhouse, target string) error {
		if err := os.MkdirAll(target, 0o755); err != nil {
			return err
		}
		return errors.New("pip exploded")
	}
	// The second archive must differ byte-for-byte from the first: an identical one hashes to
	// the same SM3 and therefore the same directory, and the idempotence check would short
	// circuit before the install branch this test exists to cover.
	other := buildTestArchive(t, map[string]string{
		"requirements.txt":            "torch\n",
		"second-1.0-py3-none-any.whl": "y",
	})
	state.processImportedDeps(depsImportRequest{ResourceURL: "http://x/b.tar.gz", RequestID: "req-b", TaskID: "task-b"}, 1, other)

	if !state.DepsImported || state.DepsHash != boundHash {
		t.Fatalf("binding changed after a failed newcomer: DepsImported=%v DepsHash=%q want %q",
			state.DepsImported, state.DepsHash, boundHash)
	}
	if _, err := os.Stat(filepath.Join(boundDir, depsAuditMarker)); err != nil {
		t.Fatalf("bound directory lost its audit marker: %v", err)
	}
	assertDepsRootContainsOnly(t, state, filepath.Base(boundDir))
}

// TestProcessImportedDepsKeepsBindingWhenNewAuditFails is the same requirement on the audit
// path. The audit stub refuses every set, so the second import cannot rebind -- and that is
// what makes this test pin the fail-closed stub down.
func TestProcessImportedDepsKeepsBindingWhenNewAuditFails(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.ScanEnabled = false

	origInstall := depsInstallFunc
	t.Cleanup(func() { depsInstallFunc = origInstall })

	depsInstallFunc = func(wheelhouse, target string) error { return os.MkdirAll(target, 0o755) }
	state.processImportedDeps(depsImportRequest{ResourceURL: "http://x/a.tar.gz", RequestID: "req-a2", TaskID: "task-a2"}, 1, buildTestDepsArchive(t))
	if !state.DepsImported {
		t.Fatal("first import did not bind; the rest of this test would be vacuous")
	}
	boundHash, boundDir := state.DepsHash, state.currentDepsDir()

	state.Security.ScanEnabled = true
	other := buildTestArchive(t, map[string]string{
		"requirements.txt":           "torch\n",
		"third-1.0-py3-none-any.whl": "z",
	})
	state.processImportedDeps(depsImportRequest{ResourceURL: "http://x/c.tar.gz", RequestID: "req-c", TaskID: "task-c"}, 1, other)

	if !state.DepsImported || state.DepsHash != boundHash {
		t.Fatalf("a failed audit unseated the working binding: DepsImported=%v DepsHash=%q want %q",
			state.DepsImported, state.DepsHash, boundHash)
	}
	assertDepsRootContainsOnly(t, state, filepath.Base(boundDir))
}

// TestProcessImportedDepsInstallFailureClearsBindingWhenItsDirectoryIsGone covers the mirror
// case. Deleting the marker makes the idempotence check miss, so the pipeline re-runs over the
// directory that is currently bound, destroys it, and then fails to rebuild it. The binding
// must not survive its own directory -- a bit pointing at a missing directory is the same
// silent degradation with the two halves swapped.
func TestProcessImportedDepsInstallFailureClearsBindingWhenItsDirectoryIsGone(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.ScanEnabled = false

	origInstall := depsInstallFunc
	t.Cleanup(func() { depsInstallFunc = origInstall })

	depsInstallFunc = func(wheelhouse, target string) error { return os.MkdirAll(target, 0o755) }
	req := depsImportRequest{ResourceURL: "http://x/a.tar.gz", RequestID: "req-d", TaskID: "task-d"}
	state.processImportedDeps(req, 1, buildTestDepsArchive(t))
	if !state.DepsImported {
		t.Fatal("first import did not bind; the rest of this test would be vacuous")
	}

	if err := os.Remove(filepath.Join(state.currentDepsDir(), depsAuditMarker)); err != nil {
		t.Fatalf("remove audit marker: %v", err)
	}
	depsInstallFunc = func(wheelhouse, target string) error {
		if err := os.MkdirAll(target, 0o755); err != nil {
			return err
		}
		return errors.New("pip exploded")
	}
	state.processImportedDeps(req, 1, buildTestDepsArchive(t))

	if state.DepsImported || state.DepsHash != "" {
		t.Fatalf("binding outlived its directory: DepsImported=%v DepsHash=%q", state.DepsImported, state.DepsHash)
	}
	assertDepsRootEmpty(t, state)
}

// TestAuditMarkerVersionGate pins the content of the audit marker: only the current policy
// version is trusted, so a marker written by another policy (or by hand) cannot short-circuit
// the pipeline.
func TestAuditMarkerVersionGate(t *testing.T) {
	dir := t.TempDir()
	if auditMarkerExists(dir) {
		t.Fatal("absent marker must not be trusted")
	}
	if err := os.WriteFile(filepath.Join(dir, depsAuditMarker), []byte("audited\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if auditMarkerExists(dir) {
		t.Fatal("foreign-content marker must not be trusted")
	}
	if err := writeAuditMarker(dir); err != nil {
		t.Fatal(err)
	}
	if !auditMarkerExists(dir) {
		t.Fatal("fresh marker must be trusted")
	}
}

// TestProcessImportedDepsReauditsForeignMarkerDir verifies the version gate end to end: a
// dependency directory that carries a marker whose content is not the current policy's must be
// rebuilt rather than reused.
//
// Security.ScanEnabled=false is deliberate here: it lets the pipeline reach the marker write
// (see auditAndReportDeps), which is what gives the test a real marker to overwrite with a
// foreign one.
func TestProcessImportedDepsReauditsForeignMarkerDir(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.ScanEnabled = false

	origInstall := depsInstallFunc
	t.Cleanup(func() { depsInstallFunc = origInstall })

	calls := 0
	depsInstallFunc = func(wheelhouse, target string) error {
		calls++
		return os.MkdirAll(target, 0o755)
	}

	req := depsImportRequest{ResourceURL: "http://x/a.tar.gz", RequestID: "req-f", TaskID: "task-f"}
	state.processImportedDeps(req, 1, buildTestDepsArchive(t))
	if calls != 1 {
		t.Fatalf("setup: installer calls=%d, want 1", calls)
	}
	if err := os.WriteFile(filepath.Join(state.currentDepsDir(), depsAuditMarker), []byte("audited\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The archive must be rebuilt: processImportedDeps removes the ciphertext path it is given,
	// so reusing the same file would fail before reaching the installer.
	state.processImportedDeps(req, 1, buildTestDepsArchive(t))

	if calls != 2 {
		t.Fatalf("installer called %d times, want 2: a foreign marker must not short-circuit", calls)
	}
}

// ── test helpers ─────────────────────────────────────────

// buildTestDepsArchive builds a minimal valid dependency package: requirements.txt plus one
// empty .whl.
func buildTestDepsArchive(t *testing.T) string {
	t.Helper()
	return buildTestArchive(t, map[string]string{
		"requirements.txt":                    "torchvision==0.28.0\n",
		"torchvision-0.28.0-py3-none-any.whl": "not-a-real-wheel\n",
	})
}

// buildTestArchive packs name->content into a tar.gz on disk and returns the file path.
func buildTestArchive(t *testing.T, files map[string]string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "deps.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names) // stable write order, so failures reproduce

	for _, name := range names {
		content := files[name]
		hdr := &tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("write body %s: %v", name, err)
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return path
}

// assertDepsRootEmpty asserts that no leftover directory remains under the content-addressed root.
func assertDepsRootEmpty(t *testing.T, state *TAAState) {
	t.Helper()
	entries, err := os.ReadDir(state.Security.GetDepsDir())
	if err != nil {
		t.Fatalf("read deps root: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("deps root is not empty, %d leftover entries: %v", len(entries), entries)
	}
}

// assertDepsRootContainsOnly fails unless the deps root holds exactly one entry with the
// given base name. Asserting what remains -- rather than that nothing errored -- is what
// makes the "a failing newcomer must not unseat the working set" tests discriminating.
func assertDepsRootContainsOnly(t *testing.T, state *TAAState, wantName string) {
	t.Helper()
	entries, err := os.ReadDir(state.Security.GetDepsDir())
	if err != nil {
		t.Fatalf("read deps root: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if len(names) != 1 || names[0] != wantName {
		t.Fatalf("deps root holds %v, want exactly [%s]", names, wantName)
	}
}
