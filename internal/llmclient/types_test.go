package llmclient

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGenerateRequestSerialization(t *testing.T) {
	req := GenerateRequest{
		ProtocolVersion: CurrentProtocolVersion,
		RequestID:       "verify-1",
		Model:           "qwen2.5-coder:3b",
		Prompt:          "hello",
		Options:         map[string]any{"temperature": 0},
	}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	for _, want := range []string{`"protocolVersion"`, `"requestId"`, `"model"`, `"prompt"`, `"options"`, `"temperature":0`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("payload missing %s: %s", want, raw)
		}
	}
}

func TestGenerateRequestOmitsEmptyModel(t *testing.T) {
	raw, err := json.Marshal(GenerateRequest{ProtocolVersion: CurrentProtocolVersion, RequestID: "r", Prompt: "p"})
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if strings.Contains(string(raw), `"model"`) {
		t.Fatalf("empty model must be omitted: %s", raw)
	}
}

func TestGenerateResponseDecode(t *testing.T) {
	var resp GenerateResponse
	body := `{"protocolVersion":"teellm-protocol/v1","requestId":"r","status":"SUCCESS","model":"m","text":"answer"}`
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if resp.Status != StatusSuccess || resp.Text != "answer" || resp.Model != "m" {
		t.Fatalf("decoded = %+v", resp)
	}
}
