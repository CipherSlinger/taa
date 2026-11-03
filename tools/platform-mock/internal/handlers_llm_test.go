package mock

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLLMRegisterAcceptsPlaintext(t *testing.T) {
	store := newLLMStateStore(t.TempDir())
	handler := llmRegisterHandler(store)

	body := `{"dockerId":"taa-teellm","authInfo":null,"taaPublicKey":"-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----\n","attestationValues":"{\"userdata\":\"aa\",\"mnonce\":\"bb\",\"digest\":\"cc\",\"chipId\":\"CHIP\"}","timestamp":"1730000000","verifiedPass":true,"attestation":"AQID"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/llm/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	state := store.get()
	if !state.Register.Received || state.Register.DockerID != "taa-teellm" {
		t.Fatalf("register state = %+v", state.Register)
	}
	if !state.Register.VerifiedPass {
		t.Error("verifiedPass was not recorded")
	}
	if state.Register.AttestationSize != 3 {
		t.Errorf("attestationSize = %d, want 3", state.Register.AttestationSize)
	}
}

func TestLLMHeartbeatRecordsLiveness(t *testing.T) {
	store := newLLMStateStore(t.TempDir())
	handler := llmHeartbeatHandler(store)

	req := httptest.NewRequest(http.MethodPost, "/v1/llm/heartbeat", strings.NewReader(`{"dockerId":"taa-teellm","timestamp":"1730000030"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	state := store.get()
	if state.Heartbeat.DockerID != "taa-teellm" || state.Heartbeat.Count != 1 {
		t.Fatalf("heartbeat state = %+v", state.Heartbeat)
	}
}

func TestLLMLogAcceptsPlaintextEntries(t *testing.T) {
	logStore := newTaaLogStoreAt(t.TempDir()+"/llm-log-state.json", 2000)
	stateStore := newLLMStateStore(t.TempDir())
	handler := llmLogHandler(logStore, stateStore)

	body := `{"dockerId":"taa-teellm","requestId":"system","seqStart":1,"entries":[{"seq":1,"message":"[2026-11-02 10:00:00] [INFO] [teellm] ready"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/llm/log", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := logStore.get().TotalCount; got != 1 {
		t.Fatalf("totalCount = %d, want 1", got)
	}
}

func TestLLMRegisterRejectsMissingDockerID(t *testing.T) {
	store := newLLMStateStore(t.TempDir())
	handler := llmRegisterHandler(store)

	req := httptest.NewRequest(http.MethodPost, "/v1/llm/register", strings.NewReader(`{"attestation":"AQID"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
}

func TestLLMEndpointsRecordSources(t *testing.T) {
	store := newLLMStateStore(t.TempDir())
	logs := newTaaLogStoreAt(t.TempDir()+"/llm-log-state.json", 2000)

	register := llmRegisterHandler(store)
	req := httptest.NewRequest(http.MethodPost, "/v1/llm/register",
		strings.NewReader(`{"dockerId":"taa-teellm","attestation":"AQID"}`))
	rec := httptest.NewRecorder()
	register(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("register status = %d, body = %s", rec.Code, rec.Body.String())
	}

	heartbeat := llmHeartbeatHandler(store)
	req = httptest.NewRequest(http.MethodPost, "/v1/llm/heartbeat",
		strings.NewReader(`{"dockerId":"taa-teellm","timestamp":"1730000030"}`))
	rec = httptest.NewRecorder()
	heartbeat(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("heartbeat status = %d, body = %s", rec.Code, rec.Body.String())
	}

	logHandler := llmLogHandler(logs, store)
	body := `{"dockerId":"taa-teellm","requestId":"system","entries":[{"seq":1,"message":"ready"}]}`
	req = httptest.NewRequest(http.MethodPost, "/v1/llm/log", strings.NewReader(body))
	rec = httptest.NewRecorder()
	logHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("log status = %d, body = %s", rec.Code, rec.Body.String())
	}

	sources := store.get().Sources
	if len(sources) != 1 {
		t.Fatalf("sources = %+v, want one entry", sources)
	}
	if sources[0].Registers != 1 || sources[0].Heartbeats != 1 || sources[0].Logs != 1 {
		t.Fatalf("source counters = %+v", sources[0])
	}
	if sources[0].LastEvent != llmEventLog {
		t.Errorf("lastEvent = %q, want %q", sources[0].LastEvent, llmEventLog)
	}
}

func TestLLMStatusReportsSources(t *testing.T) {
	store := newLLMStateStore(t.TempDir())
	logs := newTaaLogStoreAt(t.TempDir()+"/llm-log-state.json", 2000)
	store.recordHeartbeat(llmHeartbeatState{DockerID: "taa-teellm", Count: 1})

	req := httptest.NewRequest(http.MethodGet, "/api/llm/status", nil)
	rec := httptest.NewRecorder()
	llmStatusHandler(store, logs)(rec, req)

	var resp struct {
		Sources []llmSource `json:"sources"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not JSON: %v, body = %s", err, rec.Body.String())
	}
	if len(resp.Sources) != 1 || resp.Sources[0].DockerID != "taa-teellm" {
		t.Fatalf("sources = %+v", resp.Sources)
	}
}

func TestLLMResetClearsLogsAndSources(t *testing.T) {
	store := newLLMStateStore(t.TempDir())
	logs := newTaaLogStoreAt(t.TempDir()+"/llm-log-state.json", 2000)
	logs.addEntries("taa-teellm", "system", "", []taaLogEntry{{Seq: 1, Message: "ready"}})
	store.setRegister(llmRegisterState{Received: true, DockerID: "taa-teellm"})

	req := httptest.NewRequest(http.MethodPost, "/api/llm/reset", nil)
	rec := httptest.NewRecorder()
	llmResetHandler(store, logs)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if state := store.get(); state.Register.Received || len(state.Sources) != 0 {
		t.Fatalf("state after reset = %+v", state)
	}
	if got := logs.get().TotalCount; got != 0 {
		t.Fatalf("log totalCount after reset = %d, want 0", got)
	}
}
