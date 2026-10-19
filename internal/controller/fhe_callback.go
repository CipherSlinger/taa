package controller

import (
	"io"
	"net"
	"net/http"

	"taa/internal/fhe"
	pkgerrors "taa/pkg/errors"
)

// maxFHECallbackBytes bounds a callback body. The real payload is a small JSON
// document listing cases; the bound exists so a caller cannot make TAA allocate
// without limit.
const maxFHECallbackBytes = 4 << 20

// isLoopbackRequest reports whether the request originated on this host's
// loopback interface.
func isLoopbackRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// fheCallbackHandler receives the FHE service's terminal-state notification.
//
// The endpoint is not authenticated. It accepts only loopback sources as a
// compensating control: the callback address TAA hands out is 127.0.0.1, so the
// FHE service always reaches it over loopback, while a process elsewhere on the
// network cannot forge a task's terminal state. Loopback filtering cannot tell
// processes on this host apart; that is the deliberate trade for dropping the
// shared token.
//
// The service posts the same payload up to four times (0/1/4/16s backoff), so
// this endpoint is idempotent by construction: only the delivery that resolves
// the task does anything, and every delivery answers 200 - a non-2xx would keep
// the service retrying a task that is already finished.
func (s *TAAState) fheCallbackHandler(w http.ResponseWriter, r *http.Request) {
	runner := s.fheRunner()
	if runner == nil {
		// A tee instance has no FHE tasks. Answering 404 rather than 400 also keeps
		// this endpoint invisible on instances that do not serve it.
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if !isLoopbackRequest(r) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxFHECallbackBytes+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, pkgerrors.Wrap(pkgerrors.CodeInvalidArgument, "读取回调请求体失败", err))
		return
	}
	if len(body) > maxFHECallbackBytes {
		writeErr(w, http.StatusBadRequest, pkgerrors.New(pkgerrors.CodeInvalidArgument, "回调请求体过大"))
		return
	}

	payload, err := fhe.ParseCallback(body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, pkgerrors.Wrap(pkgerrors.CodeInvalidArgument, err.Error(), err))
		return
	}

	if runner.Deliver(payload) {
		s.Logs.Add(LogInfo, "fhe", "收到 FHE 任务终态回调: taskId=%s, status=%s", payload.TaskID, payload.Status)
	}
	writeEnvelope(w, http.StatusOK, "ok", nil, 0)
}
