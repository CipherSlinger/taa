package mock

import (
	"context"
	"net/http"
	"time"
)

// writeLLMResponse answers with the same {msg, result, error} envelope TAA
// routes use, so one decoder on the caller side handles both.
func writeLLMResponse(w http.ResponseWriter, status int, msg string, result any, errorCode int) {
	writeEnvelope(w, status, msg, result, errorCode)
}

// llmStatusHandler exposes what the mock has learned by polling. Everything in
// state is a platform observation, not a self-report. pollSeconds is included so
// the panel can call an instance offline after three missed polls instead of
// hard-coding a cadence the deployment may have changed.
func llmStatusHandler(poller *llmPoller, state *llmStateStore, logs *taaLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		writeJSON(w, http.StatusOK, map[string]any{
			"state":       state.get(),
			"logs":        logs.get(),
			"pollSeconds": poller.pollSeconds(),
		})
	}
}

// llmAttestationHandler pulls the report on demand. It is a button, not a
// timer: the instance's report is a hardware call and changes only on restart.
func llmAttestationHandler(poller *llmPoller) http.HandlerFunc {
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

		ctx, cancel := context.WithTimeout(r.Context(), 3*llmRequestTimeout)
		defer cancel()

		attestation, err := poller.FetchAttestation(ctx)
		if err != nil {
			writeLLMResponse(w, http.StatusBadGateway, "获取远程证明失败: "+err.Error(), nil, http.StatusBadGateway)
			return
		}
		writeLLMResponse(w, http.StatusOK, "success", attestation, 0)
	}
}

// llmResetHandler clears the record so a test can start from a clean panel.
// The log store is part of what the panel shows, so leaving it behind would
// contradict the button's meaning; the poller re-reads the instance from seq 0
// on the next poll.
func llmResetHandler(state *llmStateStore, logs *taaLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeLLMResponse(w, http.StatusMethodNotAllowed, "仅支持 POST 方法", nil, http.StatusMethodNotAllowed)
			return
		}
		state.reset()
		logs.reset()
		writeLLMResponse(w, http.StatusOK, "success", map[string]any{"reset": true}, 0)
	}
}

// llmPollNowHandler runs one poll on demand, so the panel's refresh button does
// not have to wait for the next tick.
func llmPollNowHandler(poller *llmPoller) http.HandlerFunc {
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
		ctx, cancel := context.WithTimeout(r.Context(), 3*llmRequestTimeout)
		defer cancel()
		poller.PollOnce(ctx)
		writeLLMResponse(w, http.StatusOK, "success", map[string]any{"polled": true, "at": time.Now().Format(time.RFC3339)}, 0)
	}
}
