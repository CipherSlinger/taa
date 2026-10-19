package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"taa/internal/fhe"
)

// fheLogFixture is one poller's two peers: a service whose task log the test
// can rewrite, and a platform that records what reaches modelLog.
type fheLogFixture struct {
	mu       sync.Mutex
	body     string
	reads    int
	failNext int
	batches  []modelLogRequest

	service  *httptest.Server
	platform *httptest.Server
	state    *TAAState
}

func newFHELogFixture(t *testing.T) *fheLogFixture {
	t.Helper()
	fx := &fheLogFixture{}
	fx.service = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-User-Id"); got != validEvalKeyHash {
			t.Errorf("X-User-Id = %q, want %q", got, validEvalKeyHash)
		}
		if got := r.URL.Query().Get("follow"); got != "false" {
			t.Errorf("follow = %q, want false", got)
		}
		fx.mu.Lock()
		fx.reads++
		body := fx.body
		fx.mu.Unlock()
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(fx.service.Close)

	fx.platform = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != modelLogEndpoint {
			t.Errorf("reported to %q, want %q", r.URL.Path, modelLogEndpoint)
		}
		var batch modelLogRequest
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Errorf("decode modelLog body: %v", err)
		}
		fx.mu.Lock()
		if fx.failNext > 0 {
			fx.failNext--
			fx.mu.Unlock()
			http.Error(w, "platform is down", http.StatusInternalServerError)
			return
		}
		fx.batches = append(fx.batches, batch)
		fx.mu.Unlock()
		_, _ = w.Write([]byte(`{"result":{"received":true},"error":0}`))
	}))
	t.Cleanup(fx.platform.Close)

	fx.state, _ = setupTestState(t)
	return fx
}

func (fx *fheLogFixture) setBody(body string) {
	fx.mu.Lock()
	defer fx.mu.Unlock()
	fx.body = body
}

func (fx *fheLogFixture) setFailNext(n int) {
	fx.mu.Lock()
	defer fx.mu.Unlock()
	fx.failNext = n
}

func (fx *fheLogFixture) entries() []ModelLogEntry {
	fx.mu.Lock()
	defer fx.mu.Unlock()
	var out []ModelLogEntry
	for _, batch := range fx.batches {
		out = append(out, batch.Entries...)
	}
	return out
}

// newFHELogPoller builds a poller against the fixture. The fixture is what the
// poller talks to, so no runner is involved.
func (fx *fheLogFixture) newFHELogPoller(t *testing.T) *fheLogPoller {
	t.Helper()
	client, err := fhe.NewClient(fx.service.URL, 2*time.Second)
	if err != nil {
		t.Fatalf("fhe.NewClient: %v", err)
	}
	return &fheLogPoller{
		state:        fx.state,
		client:       client,
		platformAddr: fx.platform.URL,
		dockerID:     "test-docker-001",
		requestID:    "req-data",
		taskID:       "task-1",
		userID:       validEvalKeyHash,
		nextSeq:      1,
	}
}

// TestFHELogPollerReportsEachLineOnce pins the replay semantics: every poll
// returns the whole log, so only the suffix beyond what was already accounted
// for may be reported, and an unterminated tail waits for the next replay -
// unless it is the final one.
func TestFHELogPollerReportsEachLineOnce(t *testing.T) {
	fx := newFHELogFixture(t)
	p := fx.newFHELogPoller(t)
	ctx := context.Background()

	fx.setBody("one\n")
	p.poll(ctx, false)
	assertMessages(t, fx.entries(), []string{"one"})

	// The same log again: nothing new may be reported.
	p.poll(ctx, false)
	assertMessages(t, fx.entries(), []string{"one"})

	// The tail has no terminator yet, so it is not a line; the next replay
	// finishes it.
	fx.setBody("one\ntwo\nhal")
	p.poll(ctx, false)
	assertMessages(t, fx.entries(), []string{"one", "two"})

	fx.setBody("one\ntwo\nhalf")
	p.poll(ctx, true)
	assertMessages(t, fx.entries(), []string{"one", "two", "half"})

	for i, entry := range fx.entries() {
		if want := uint64(i + 1); entry.Seq != want {
			t.Errorf("entries[%d].seq = %d, want %d", i, entry.Seq, want)
		}
		if entry.Component != "fhe" {
			t.Errorf("entries[%d].component = %q, want fhe", i, entry.Component)
		}
	}
}

// TestFHELogPollerSplitsCarriageReturnProgress covers the progress bar: the
// service redraws it with carriage returns, and each redraw is a line of its
// own for the platform's log view.
func TestFHELogPollerSplitsCarriageReturnProgress(t *testing.T) {
	fx := newFHELogFixture(t)
	p := fx.newFHELogPoller(t)
	fx.setBody("case-00 [####      ] 40%\rcase-00 [##########] 100%\r")

	p.poll(context.Background(), false)
	assertMessages(t, fx.entries(), []string{
		"case-00 [####      ] 40%",
		"case-00 [##########] 100%",
	})
}

// TestFHELogPollerRestartsWhenTheLogShrinks covers a continue re-run: the
// service starts the log over for the same task id, so a shorter replay is a
// new log rather than a read that may resume at the old offset.
func TestFHELogPollerRestartsWhenTheLogShrinks(t *testing.T) {
	fx := newFHELogFixture(t)
	p := fx.newFHELogPoller(t)
	ctx := context.Background()

	fx.setBody("first run\n")
	p.poll(ctx, false)
	fx.setBody("second run\n")
	p.poll(ctx, false)

	assertMessages(t, fx.entries(), []string{"first run", "second run"})
}

// TestFHELogPollerRetriesAFailedBatchWithTheSameSeq pins the queue on failure:
// an entry is only dropped once the platform accepted it, so a retry carries
// the same sequence numbers and leaves no hole in the platform's seq stream.
func TestFHELogPollerRetriesAFailedBatchWithTheSameSeq(t *testing.T) {
	fx := newFHELogFixture(t)
	p := fx.newFHELogPoller(t)
	ctx := context.Background()

	fx.setBody("one\ntwo\n")
	fx.setFailNext(1)
	p.poll(ctx, false)
	if got := fx.entries(); len(got) != 0 {
		t.Fatalf("entries after a failed report = %d, want 0", len(got))
	}

	p.poll(ctx, false)
	entries := fx.entries()
	assertMessages(t, entries, []string{"one", "two"})
	if entries[0].Seq != 1 || entries[1].Seq != 2 {
		t.Errorf("retried seqs = [%d %d], want [1 2]", entries[0].Seq, entries[1].Seq)
	}
}

// TestStartFHELogPollerNeedsAPlatform pins the guard: with nowhere to report,
// the poller is not started at all.
func TestStartFHELogPollerNeedsAPlatform(t *testing.T) {
	state, _ := setupTestState(t)
	state.mu.Lock()
	state.PlatformIP = ""
	state.mu.Unlock()

	runner, err := fhe.New(fhe.Config{
		Endpoint:        "http://127.0.0.1:1",
		DataDir:         t.TempDir(),
		KeyCacheDir:     t.TempDir(),
		CallbackBaseURL: "http://127.0.0.1:6001",
		MaxEvalKeyBytes: fhe.DefaultMaxEvalKeyBytes,
		PollInterval:    fhe.DefaultPollInterval,
		RequestTimeout:  fhe.DefaultRequestTimeout,
		TaskTimeout:     fhe.DefaultTaskTimeout,
	}, nil)
	if err != nil {
		t.Fatalf("fhe.New: %v", err)
	}

	stop := state.startFHELogPoller(runner, "req-data", "task-1", validEvalKeyHash)
	stop() // must not block or panic
}

func assertMessages(t *testing.T, entries []ModelLogEntry, want []string) {
	t.Helper()
	if len(entries) != len(want) {
		t.Fatalf("reported %d entries %v, want %d %v", len(entries), messagesOf(entries), len(want), want)
	}
	for i, entry := range entries {
		if entry.Message != want[i] {
			t.Errorf("entries[%d].message = %q, want %q", i, entry.Message, want[i])
		}
	}
}

func messagesOf(entries []ModelLogEntry) []string {
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		out = append(out, entry.Message)
	}
	return out
}
