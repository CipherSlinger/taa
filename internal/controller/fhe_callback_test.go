package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── /v1/taa/fheCallback ──────────────────────────────────────────────────

// postCallback drives fheCallbackHandler the way the FHE service does: a POST
// from loopback with no credentials.
func postCallback(t *testing.T, s *TAAState, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/taa/fheCallback", strings.NewReader(body))
	// The handler accepts loopback sources only, so the request must originate
	// there; httptest would otherwise default to 192.0.2.1.
	req.RemoteAddr = "127.0.0.1:54321"
	rec := httptest.NewRecorder()
	s.fheCallbackHandler(rec, req)
	return rec
}

// envelopeMsg decodes the unified response envelope and returns its message.
func envelopeMsg(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var api apiResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &api); err != nil {
		t.Fatalf("decode response body %q: %v", rec.Body.String(), err)
	}
	return api.Msg
}

// TestFHECallbackRejectsNonLoopbackSources pins the compensating control for the
// missing token: the callback address is loopback, so a request from anywhere
// else is not the FHE service and must not be able to resolve a task.
func TestFHECallbackRejectsNonLoopbackSources(t *testing.T) {
	s, _ := setupTestState(t)
	s.SetFHERunner(newStubRunner(t))

	for _, remote := range []string{
		"192.0.2.1:1234",
		"10.0.0.7:1234",
		"::1:1234", // not a valid host:port, so it must fail closed
		"",
	} {
		req := httptest.NewRequest(http.MethodPost, "/v1/taa/fheCallback",
			strings.NewReader(`{"task_id":"t1","status":"completed"}`))
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		s.fheCallbackHandler(rec, req)
		// 404 rather than 401: a caller must not learn that this endpoint exists.
		if rec.Code != http.StatusNotFound {
			t.Errorf("RemoteAddr %q: status = %d, want 404", remote, rec.Code)
		}
	}

	// A loopback source is accepted, so a handler that answered 404 to
	// everything would not pass the loop above.
	if rec := postCallback(t, s, `{"task_id":"t1","status":"completed"}`); rec.Code != http.StatusOK {
		t.Errorf("loopback source: status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

func TestFHECallbackIsAbsentOnTEEInstance(t *testing.T) {
	s, _ := setupTestState(t) // a tee boot: buildFHERunner installs no runner

	rec := postCallback(t, s, `{"task_id":"t1","status":"completed"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 on a tee instance: %s", rec.Code, rec.Body.String())
	}
}

func TestFHECallbackRejectsMalformedBody(t *testing.T) {
	s, _ := setupTestState(t)
	s.SetFHERunner(newStubRunner(t))

	for _, body := range []string{
		`{"status":"completed"}`, // no task id
		`{"task_id":"t1"}`,       // no status
		`{"task_id":"t1","status":"   "}`,
		`{`, // not JSON at all
	} {
		rec := postCallback(t, s, body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %q: status = %d, want 400: %s", body, rec.Code, rec.Body.String())
		}
	}
}

// TestFHECallbackAcceptsUnknownTasksAndIsIdempotent pins the answer the service
// gets for a task this instance does not track.
//
// The service retries at 0/1/4/16 s, so a non-2xx would make it keep retrying a
// task that is already resolved. There is nothing to resolve here, and that must
// still be answered 200.
func TestFHECallbackAcceptsUnknownTasksAndIsIdempotent(t *testing.T) {
	s, _ := setupTestState(t)
	s.SetFHERunner(newStubRunner(t))

	for i := 0; i < 4; i++ {
		rec := postCallback(t, s, `{"task_id":"t1","status":"completed"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("delivery %d: status = %d, want 200: %s", i+1, rec.Code, rec.Body.String())
		}
	}
}

// TestFHECallbackResolvesAnInFlightRunAndItsRetriesStayIdempotent walks the
// callback's real job: the run its importer is waiting on is advanced by the
// POST, and the retries that follow change nothing and are still answered 200.
func TestFHECallbackResolvesAnInFlightRunAndItsRetriesStayIdempotent(t *testing.T) {
	env := newFHETestEnv(t)
	// The service never reports a terminal state on its own here: only the
	// callback can end this run.
	env.stub.setTaskStatus("running")
	env.importModel()
	zipPath, _ := writeTestZip(t, t.TempDir(), map[string]string{"case": "input"})

	done := make(chan struct{})
	go func() {
		defer close(done)
		env.runData(zipPath)
	}()
	waitForInFlightFHETask(t, env)

	body := `{"task_id":"task-data","status":"completed"}`
	if rec := postCallback(t, env.state, body); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the callback did not resolve the run its importer was waiting on")
	}

	for i := 0; i < 3; i++ {
		if rec := postCallback(t, env.state, body); rec.Code != http.StatusOK {
			t.Fatalf("retry %d of an already resolved task: status = %d, want 200", i+1, rec.Code)
		}
	}
}

// TestFHECallbackIsRegisteredOnTheRouteTable covers the registration itself:
// the endpoint is only reachable if router.go lists it, and a missing route makes
// ServeMux answer with its own plain-text 404 rather than this handler's envelope.
func TestFHECallbackIsRegisteredOnTheRouteTable(t *testing.T) {
	state, _ := setupTestState(t)
	state.SetFHERunner(newStubRunner(t))

	mux := http.NewServeMux()
	RegisterRoutes(mux, state)

	req := httptest.NewRequest(http.MethodPost, "/v1/taa/fheCallback",
		strings.NewReader(`{"task_id":"t1","status":"completed"}`))
	req.RemoteAddr = "127.0.0.1:54321"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || envelopeMsg(t, rec) != "ok" {
		t.Fatalf("status = %d, body = %q; want the callback handler's 200 envelope", rec.Code, rec.Body.String())
	}
}

// ── stopTraining on an FHE instance ──────────────────────────────────────

// postStopTraining drives the real handler, so the mapping under test is the one
// the platform's request takes.
func postStopTraining(t *testing.T, s *TAAState) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	s.stopTrainingHandler(rec, httptest.NewRequest(http.MethodPost, "/v1/taa/stopTraining", nil))
	return rec
}

// waitForInFlightFHETask blocks until state and runner agree that task-data is
// running: the state has to report it as the active FHE task, and the service has
// to have been asked to create it.
//
// The second condition is not redundant. setFHEActiveTask runs before Execute,
// and the runner registers the run inside Execute's prepare, so right after the
// first condition holds there is a window in which a stop finds no run to cancel.
// Waiting for the create call - which happens after that registration - makes the
// test start from a state where the run is genuinely in flight.
func waitForInFlightFHETask(t *testing.T, env *fheTestEnv) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if env.state.fheActiveTask() == "task-data" && len(env.stub.createdTasks()) > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("task-data never became an in-flight FHE task: active=%q, created=%d",
		env.state.fheActiveTask(), len(env.stub.createdTasks()))
}

// waitForPoll blocks until the run has polled the service at least once, which
// with holdPolls installed means it is parked inside that poll.
func waitForPoll(t *testing.T, env *fheTestEnv) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if env.stub.pollCount() > 0 {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("the run never reached its first poll")
}

// TestStopTrainingCancelsTheRunningFHETaskThroughTheService is the gap this task
// closes: a stop during an in-flight FHE task has to reach the service, because
// the service is the only thing that can stop the run. The run is a real one, so
// the active-task wiring that carries the id from the import path to the handler
// is part of what the test proves.
func TestStopTrainingCancelsTheRunningFHETaskThroughTheService(t *testing.T) {
	env := newFHETestEnv(t)
	// The task stays in flight until it is cancelled, so nothing but the stop can
	// end it.
	env.stub.setTaskStatus("running")
	env.importModel()
	zipPath, _ := writeTestZip(t, t.TempDir(), map[string]string{"case": "input"})

	done := make(chan struct{})
	go func() {
		defer close(done)
		env.runData(zipPath)
	}()
	waitForInFlightFHETask(t, env)

	rec := postStopTraining(t, env.state)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if msg := envelopeMsg(t, rec); msg != "FHE 任务已取消" {
		t.Errorf("msg = %q, want the FHE stop confirmation", msg)
	}

	want := "POST /api/v1/tasks/task-data/cancel"
	if got := env.stub.cancelCalls(); len(got) != 1 || got[0] != want {
		t.Errorf("the service received %v, want exactly [%s]", got, want)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the run did not return after its task was cancelled")
	}
	if got := env.state.fheActiveTask(); got != "" {
		t.Errorf("fheActiveTask() after the cancelled run = %q, want empty", got)
	}
}

// TestStopTrainingDoesNotCallAFailedStopOnAFinishedFHETask covers the race the
// platform actually hits: the task ends on its own just before the stop arrives.
//
// The run is parked inside its poll while a callback resolves it, which is the
// state a stop lands in when it arrives between "the run is finished" and "the
// importer noticed and let go".
func TestStopTrainingDoesNotCallAFailedStopOnAFinishedFHETask(t *testing.T) {
	env := newFHETestEnv(t)
	env.stub.setTaskStatus("running")
	env.stub.holdPolls() // installed before the run starts, so its first poll parks
	// Released on every exit path: a parked poll holds the stub server's Close
	// open, so a failing assertion above would otherwise hang the test instead of
	// reporting it.
	t.Cleanup(env.stub.releasePolls)
	env.importModel()
	zipPath, _ := writeTestZip(t, t.TempDir(), map[string]string{"case": "input"})

	done := make(chan struct{})
	go func() {
		defer close(done)
		env.runData(zipPath)
	}()
	waitForInFlightFHETask(t, env)
	waitForPoll(t, env)

	// The callback ends the run while its importer is still parked: the task is
	// finished, the state still reports it in flight, and the runner still holds it.
	if rec := postCallback(t, env.state, `{"task_id":"task-data","status":"completed"}`); rec.Code != http.StatusOK {
		t.Fatalf("callback status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	rec := postStopTraining(t, env.state)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a task that finished on its own: %s", rec.Code, rec.Body.String())
	}
	if msg := envelopeMsg(t, rec); msg != "FHE 任务已结束" {
		t.Errorf("msg = %q, want the already-finished confirmation", msg)
	}
	// Nothing may be sent to the service: the run is over, and the only cancel TAA
	// could send for it is the tenant-less one the service answers 2xx to without
	// matching the task.
	if got := env.stub.cancelCalls(); len(got) != 0 {
		t.Errorf("the service received %v, want no cancel request for a finished task", got)
	}

	env.stub.releasePolls()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the run did not return after its poll was released")
	}
}

// waitForDownload blocks until the run has asked the service for its result,
// which with holdDownloads installed means it is parked inside CopyResult - after
// Execute has already returned and dropped the task from the runner's table.
func waitForDownload(t *testing.T, env *fheTestEnv) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if env.stub.downloadCount() > 0 {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("the run never asked for its result")
}

// TestStopTrainingOnAFinishedFHETaskWhoseResultIsStillLanding covers the window
// the finished-task test above does not reach.
//
// Execute drops the run from the runner's in-flight table before it returns, so
// from that moment Runner.Cancel refuses the id - and it refuses it deliberately,
// because a task it does not track is one it cannot scope to a tenant. The state,
// however, kept the task marked active for the whole of the result landing (a
// multi-gigabyte copy or download) and the platform reporting, so a stop arriving
// in that window was answered 500 for a task that in fact succeeded. Reporting a
// failure for a stop that has nothing left to stop is exactly what the
// already-finished branch exists to avoid.
func TestStopTrainingOnAFinishedFHETaskWhoseResultIsStillLanding(t *testing.T) {
	env := newFHETestEnv(t)
	env.importModel()
	// The result is never written into the shared directory, so it has to be
	// fetched - and that fetch is the landing the stop lands in.
	env.stub.holdDownloads()
	// Released on every exit path: a parked download holds the stub server's Close
	// open, so a failing assertion above would otherwise hang the test instead of
	// reporting it.
	t.Cleanup(env.stub.releaseDownloads)

	zipPath, _ := writeTestZip(t, t.TempDir(), map[string]string{"case": "input"})
	done := make(chan struct{})
	go func() {
		defer close(done)
		env.runData(zipPath)
	}()
	waitForDownload(t, env)

	rec := postStopTraining(t, env.state)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a run that already finished: %s", rec.Code, rec.Body.String())
	}
	if msg := envelopeMsg(t, rec); msg != "不存在训练任务" {
		t.Errorf("msg = %q, want the no-task message: a task this instance no longer tracks is not a failed stop", msg)
	}
	// Nothing may be sent to the service: the run is over, and the only cancel TAA
	// could send for it is the tenant-less one the service answers 2xx to without
	// matching the task.
	if got := env.stub.cancelCalls(); len(got) != 0 {
		t.Errorf("the service received %v, want no cancel request for a finished task", got)
	}

	env.stub.releaseDownloads()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the run did not return after its download was released")
	}
}

// TestStopTrainingReportsATaskThisInstanceDoesNotTrack covers the other side of
// the same call: a task the runner never had cannot be cancelled, and reporting
// that as a success would tell the platform a stop happened that never did.
func TestStopTrainingReportsATaskThisInstanceDoesNotTrack(t *testing.T) {
	s, _ := setupTestState(t)
	s.SetFHERunner(newStubRunner(t))
	s.setFHEActiveTask("task-not-in-flight")

	rec := postStopTraining(t, s)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", rec.Code, rec.Body.String())
	}
	if msg := envelopeMsg(t, rec); msg != "取消 FHE 任务失败" {
		t.Errorf("msg = %q, want the cancel failure message", msg)
	}
}

// TestStopTrainingOnAnIdleFHEInstanceStillReportsNoTask pins the branch's guard:
// with nothing in flight the handler has to fall through to the training check, so
// a stop on an idle FHE instance keeps answering what it always did.
func TestStopTrainingOnAnIdleFHEInstanceStillReportsNoTask(t *testing.T) {
	s, _ := setupTestState(t)
	s.SetFHERunner(newStubRunner(t))

	rec := postStopTraining(t, s)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if msg := envelopeMsg(t, rec); msg != "不存在训练任务" {
		t.Errorf("msg = %q, want the no-task message", msg)
	}
}
