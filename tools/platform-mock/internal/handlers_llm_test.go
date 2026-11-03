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
	handler := llmLogHandler(logStore)

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
