package mock

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// writeLLMResponse answers with the same {msg, result, error} envelope TAA
// routes use, so one decoder on the caller side handles both.
func writeLLMResponse(w http.ResponseWriter, status int, msg string, result any, errorCode int) {
	writeEnvelope(w, status, msg, result, errorCode)
}

// llmRegisterHandler accepts the plaintext registration an LLM instance sends.
// There is no envelope here on purpose: the LLM's proof of identity is the
// attestation report plus the certificate whose key it binds, and the mock
// records both verbatim so they can be compared by hand.
func llmRegisterHandler(store *llmStateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeLLMResponse(w, http.StatusMethodNotAllowed, "仅支持 POST 方法", nil, http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		if err != nil {
			writeLLMResponse(w, http.StatusBadRequest, "读取请求体失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}

		var req struct {
			DockerID          string `json:"dockerId"`
			TaaPublicKey      string `json:"taaPublicKey"`
			AttestationValues string `json:"attestationValues"`
			Timestamp         string `json:"timestamp"`
			VerifiedPass      bool   `json:"verifiedPass"`
			Attestation       string `json:"attestation"`
			Certificate       string `json:"certificate"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			writeLLMResponse(w, http.StatusBadRequest, "解析 application/json 失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.DockerID) == "" {
			writeLLMResponse(w, http.StatusBadRequest, "缺少 dockerId", nil, http.StatusBadRequest)
			return
		}

		state := llmRegisterState{
			Received:          true,
			ReceivedAt:        time.Now().Format(time.RFC3339),
			DockerID:          req.DockerID,
			TaaPublicKey:      req.TaaPublicKey,
			AttestationValues: req.AttestationValues,
			Timestamp:         req.Timestamp,
			VerifiedPass:      req.VerifiedPass,
			AttestationBase64: req.Attestation,
			Certificate:       req.Certificate,
		}
		if req.Attestation != "" {
			attBytes, decodeErr := base64.StdEncoding.DecodeString(req.Attestation)
			if decodeErr != nil {
				writeLLMResponse(w, http.StatusBadRequest, "attestation Base64 解码失败: "+decodeErr.Error(), nil, http.StatusBadRequest)
				return
			}
			state.AttestationSize = len(attBytes)
		}

		store.setRegister(state)
		writeLLMResponse(w, http.StatusOK, "success", map[string]any{"received": true}, 0)
	}
}

// llmHeartbeatHandler records liveness only.
func llmHeartbeatHandler(store *llmStateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeLLMResponse(w, http.StatusMethodNotAllowed, "仅支持 POST 方法", nil, http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			DockerID  string `json:"dockerId"`
			Timestamp string `json:"timestamp"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
			writeLLMResponse(w, http.StatusBadRequest, "解析 JSON 失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.DockerID) == "" {
			writeLLMResponse(w, http.StatusBadRequest, "缺少 dockerId", nil, http.StatusBadRequest)
			return
		}

		previous := store.get().Heartbeat
		store.recordHeartbeat(llmHeartbeatState{
			DockerID:   req.DockerID,
			Timestamp:  req.Timestamp,
			ReceivedAt: time.Now().Format(time.RFC3339),
			Count:      previous.Count + 1,
		})
		writeLLMResponse(w, http.StatusOK, "success", map[string]any{"received": true}, 0)
	}
}

// llmLogHandler accepts batched run logs in plaintext.
func llmLogHandler(store *taaLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeLLMResponse(w, http.StatusMethodNotAllowed, "仅支持 POST 方法", nil, http.StatusMethodNotAllowed)
			return
		}

		var req taaLogRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			writeLLMResponse(w, http.StatusBadRequest, "解析 JSON 失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.DockerID) == "" {
			writeLLMResponse(w, http.StatusBadRequest, "缺少 dockerId", nil, http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.RequestID) == "" {
			writeLLMResponse(w, http.StatusBadRequest, "缺少 requestId", nil, http.StatusBadRequest)
			return
		}
		if len(req.Entries) == 0 {
			writeLLMResponse(w, http.StatusBadRequest, "entries 不能为空", nil, http.StatusBadRequest)
			return
		}

		store.addEntries(req.DockerID, req.RequestID, req.TaskID, req.Entries)
		writeLLMResponse(w, http.StatusOK, "success", map[string]any{"received": true}, 0)
	}
}

// llmStatusHandler exposes what the LLM instance last reported.
func llmStatusHandler(state *llmStateStore, logs *taaLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		writeJSON(w, http.StatusOK, map[string]any{
			"register":  state.get().Register,
			"heartbeat": state.get().Heartbeat,
			"logs":      logs.get(),
		})
	}
}

// llmResetHandler clears the record so a test can start from a clean panel.
func llmResetHandler(state *llmStateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeLLMResponse(w, http.StatusMethodNotAllowed, "仅支持 POST 方法", nil, http.StatusMethodNotAllowed)
			return
		}
		state.reset()
		writeLLMResponse(w, http.StatusOK, "success", map[string]any{"reset": true}, 0)
	}
}
