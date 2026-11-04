package mock

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fakeLLM is a minimal teellm-service: the three platform-facing endpoints and
// nothing else. It records what the poller asked for so the tests can assert the
// cursor, not only the rendered state.
type fakeLLM struct {
	mu           sync.Mutex
	model        string
	uptime       int64
	dockerID     string
	entries      []llmLogPullEntry
	lastSinceSeq uint64
	heartbeats   int
	logPulls     int
	attestations int
}

func (f *fakeLLM) setUptime(seconds int64) {
	f.mu.Lock()
	f.uptime = seconds
	f.mu.Unlock()
}

func (f *fakeLLM) setDockerID(id string) {
	f.mu.Lock()
	f.dockerID = id
	f.mu.Unlock()
}

func (f *fakeLLM) setEntries(entries []llmLogPullEntry) {
	f.mu.Lock()
	f.entries = entries
	f.mu.Unlock()
}

func (f *fakeLLM) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/llm/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.heartbeats++
		model, uptime, dockerID := f.model, f.uptime, f.dockerID
		f.mu.Unlock()
		writeFakeEnvelope(w, dockerID, map[string]any{"alive": true, "model": model, "uptimeSeconds": uptime})
	})
	mux.HandleFunc("/v1/llm/log", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			SinceSeq uint64 `json:"sinceSeq"`
			Limit    int    `json:"limit"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		f.logPulls++
		f.lastSinceSeq = req.SinceSeq
		dockerID := f.dockerID
		var out []llmLogPullEntry
		var latest uint64
		for _, entry := range f.entries {
			// sinceSeq is inclusive: return it and everything newer.
			if entry.Seq >= req.SinceSeq {
				out = append(out, entry)
			}
			if entry.Seq > latest {
				latest = entry.Seq
			}
		}
		f.mu.Unlock()
		if out == nil {
			out = []llmLogPullEntry{}
		}
		writeFakeEnvelope(w, dockerID, map[string]any{"entries": out, "latestSeq": latest, "dropped": false})
	})
	mux.HandleFunc("/v1/llm/getAttestation", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.attestations++
		dockerID := f.dockerID
		f.mu.Unlock()
		writeFakeEnvelope(w, dockerID, map[string]any{
			"requestId":         "req-1",
			"verifiedPass":      true,
			"attestation":       base64.StdEncoding.EncodeToString([]byte("report-bytes")),
			"attestationValues": `{"chipId":"c1"}`,
		})
	})
	return mux
}

func writeFakeEnvelope(w http.ResponseWriter, dockerID string, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"msg":      "success",
		"result":   result,
		"error":    0,
		"dockerId": dockerID,
	})
}

func newPollTestRig(t *testing.T) (*fakeLLM, *llmPoller, *llmStateStore, *taaLogStore) {
	t.Helper()
	fake := &fakeLLM{model: "qwen2.5-coder:3b", uptime: 600, dockerID: "teellm-1000000001"}
	srv := httptest.NewServer(fake.handler())
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	state := newLLMStateStore(dir)
	logs := newTaaLogStoreAt(filepath.Join(dir, "llm-log-state.json"), 100)
	poller := newLLMPoller(Config{LLMTarget: srv.URL, LLMPollSeconds: 10}, state, logs)
	return fake, poller, state, logs
}

func TestLLMPollerRecordsHeartbeatAndLogs(t *testing.T) {
	fake, poller, state, logs := newPollTestRig(t)
	fake.setEntries([]llmLogPullEntry{
		{Seq: 1, Message: "[t] [INFO] [teellm] one"},
		{Seq: 2, Message: "[t] [WARN] [teellm] two"},
	})

	poller.PollOnce(context.Background())

	got := state.get()
	if !got.Reachable {
		t.Fatalf("reachable = false, error %q", got.LastError)
	}
	if got.Model != "qwen2.5-coder:3b" || got.UptimeSeconds != 600 {
		t.Errorf("model/uptime = %q/%d", got.Model, got.UptimeSeconds)
	}
	if got.DockerID != "teellm-1000000001" {
		t.Errorf("dockerId = %q, want the id from the heartbeat envelope", got.DockerID)
	}
	if got.Heartbeats != 1 || got.LastHeartbeatAt == "" {
		t.Errorf("heartbeats = %d, at %q", got.Heartbeats, got.LastHeartbeatAt)
	}
	if got.LastError != "" {
		t.Errorf("lastError = %q", got.LastError)
	}
	if got.LogCursor != 2 || got.LogEntries != 2 {
		t.Errorf("cursor/entries = %d/%d, want 2/2", got.LogCursor, got.LogEntries)
	}
	if entries := logs.get().Entries; len(entries) != 2 {
		t.Fatalf("stored %d log entries, want 2", len(entries))
	}
}

func TestLLMPollerResumesFromStoredCursor(t *testing.T) {
	fake, poller, _, _ := newPollTestRig(t)
	fake.setEntries([]llmLogPullEntry{{Seq: 1, Message: "one"}, {Seq: 2, Message: "two"}})

	poller.PollOnce(context.Background())
	poller.PollOnce(context.Background())

	fake.mu.Lock()
	lastSince := fake.lastSinceSeq
	pulls := fake.logPulls
	fake.mu.Unlock()
	if pulls != 2 {
		t.Fatalf("log pulls = %d, want 2", pulls)
	}
	if lastSince != 3 {
		t.Errorf("second pull used sinceSeq=%d, want the stored cursor 2 plus one", lastSince)
	}
}

func TestLLMPollerResetsCursorWhenDockerIDChanges(t *testing.T) {
	fake, poller, state, logs := newPollTestRig(t)
	fake.setEntries([]llmLogPullEntry{{Seq: 1, Message: "old one"}, {Seq: 2, Message: "old two"}})
	poller.PollOnce(context.Background())
	before := len(logs.get().Entries)

	// A rebuild: same address, same uptime shape, a new process id.
	fake.setDockerID("teellm-2000000002")
	fake.setEntries([]llmLogPullEntry{{Seq: 1, Message: "new one"}, {Seq: 2, Message: "new two"}})
	poller.PollOnce(context.Background())

	fake.mu.Lock()
	lastSince := fake.lastSinceSeq
	fake.mu.Unlock()
	if lastSince != 1 {
		t.Errorf("pull after rebuild used sinceSeq=%d, want 1 (cursor 0 plus one)", lastSince)
	}
	if got := len(logs.get().Entries); got != before+2 {
		t.Errorf("stored %d entries, want %d", got, before+2)
	}
	if got := state.get().DockerID; got != "teellm-2000000002" {
		t.Errorf("dockerId = %q, want the new instance id", got)
	}
}

// An instance that does not report a dockerId still gets restart detection from
// the uptime-quantized fallback.
func TestLLMPollerResetsCursorWhenTheInstanceRestarted(t *testing.T) {
	fake, poller, state, logs := newPollTestRig(t)
	fake.setDockerID("")
	fake.setEntries([]llmLogPullEntry{{Seq: 1, Message: "old one"}, {Seq: 2, Message: "old two"}})
	poller.PollOnce(context.Background())
	before := len(logs.get().Entries)

	// A restart: the same seq numbering starts over and the uptime is small.
	// Truncating the derived start time can land on either side of a boundary,
	// so the new run is a full resolution window past the old one.
	fake.setUptime(5)
	fake.setEntries([]llmLogPullEntry{{Seq: 1, Message: "new one"}, {Seq: 2, Message: "new two"}})
	poller.PollOnce(context.Background())

	fake.mu.Lock()
	lastSince := fake.lastSinceSeq
	fake.mu.Unlock()
	if lastSince != 1 {
		t.Errorf("pull after restart used sinceSeq=%d, want 1 (cursor 0 plus one)", lastSince)
	}
	if got := len(logs.get().Entries); got != before+2 {
		t.Errorf("stored %d entries, want %d", got, before+2)
	}
	if got := state.get().LogCursor; got != 2 {
		t.Errorf("cursor = %d, want 2", got)
	}
}

func TestLLMPollerRecordsDiscoveryFailure(t *testing.T) {
	dir := t.TempDir()
	state := newLLMStateStore(dir)
	logs := newTaaLogStoreAt(filepath.Join(dir, "llm-log-state.json"), 10)
	// No LLMTarget and no pod name: discovery has nothing to ask kubectl for.
	poller := newLLMPoller(Config{}, state, logs)

	poller.PollOnce(context.Background())

	got := state.get()
	if got.Reachable {
		t.Fatal("reachable = true without an address")
	}
	if got.LastError == "" {
		t.Fatal("expected an explanatory lastError")
	}
}

func TestLLMPollerRecordsHeartbeatFailure(t *testing.T) {
	dir := t.TempDir()
	state := newLLMStateStore(dir)
	logs := newTaaLogStoreAt(filepath.Join(dir, "llm-log-state.json"), 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()
	poller := newLLMPoller(Config{LLMTarget: srv.URL}, state, logs)

	poller.PollOnce(context.Background())

	got := state.get()
	if got.Reachable {
		t.Fatal("reachable = true after a 404")
	}
	if got.LastError == "" {
		t.Fatal("expected lastError")
	}
	// The stale address is dropped so the next poll rediscovers instead of
	// retrying a dead Pod IP forever.
	poller.mu.Lock()
	cached := poller.addr
	poller.mu.Unlock()
	if cached != "" {
		t.Errorf("cached address = %q, want cleared", cached)
	}
}

func TestLLMFetchAttestationStoresTheReport(t *testing.T) {
	fake, poller, state, _ := newPollTestRig(t)

	got, err := poller.FetchAttestation(context.Background())
	if err != nil {
		t.Fatalf("FetchAttestation failed: %v", err)
	}
	if !got.VerifiedPass || got.RequestID != "req-1" {
		t.Errorf("verified/request = %v/%q", got.VerifiedPass, got.RequestID)
	}
	if got.AttestationSize != len("report-bytes") {
		t.Errorf("size = %d", got.AttestationSize)
	}
	stored := state.get().Attestation
	if stored.FetchedAt == "" || stored.AttestationValues != `{"chipId":"c1"}` {
		t.Errorf("stored attestation = %+v", stored)
	}
	fake.mu.Lock()
	calls := fake.attestations
	fake.mu.Unlock()
	if calls != 1 {
		t.Errorf("getAttestation calls = %d, want 1", calls)
	}
}

func TestLLMRunIDChangesWithRestartAndIgnoresJitter(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	first := llmRunID(start, 3600)
	// A poll one second later reports one second more uptime: same run.
	if second := llmRunID(start.Add(time.Second), 3601); second != first {
		t.Errorf("jitter changed the run id: %s != %s", second, first)
	}
	if restarted := llmRunID(start.Add(time.Hour), 5); restarted == first {
		t.Error("restart did not change the run id")
	}
}
