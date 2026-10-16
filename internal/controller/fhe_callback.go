package controller

import (
	"io"
	"net/http"

	"taa/internal/fhe"
	pkgerrors "taa/pkg/errors"
)

// maxFHECallbackBytes bounds a callback body. The real payload is a small JSON
// document listing cases; the bound exists so a caller holding the token cannot
// make TAA allocate without limit.
const maxFHECallbackBytes = 4 << 20

// fheCallbackHandler receives the FHE service's terminal-state notification.
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
	if !runner.Config().TokenMatches(r.URL.Query().Get("token")) {
		// 404, not 401: a caller that does not hold the token must not learn that
		// this endpoint exists.
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
