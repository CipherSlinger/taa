package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"taa/internal/resource"
	"taa/internal/runtime"
	teecrypto "taa/pkg/crypto"
	pkgerrors "taa/pkg/errors"
)

// depsInstallFunc is the swappable installer hook. Production binds it to
// runtime.InstallWheelhouse; tests substitute a stub so CI never shells out to pip.
var depsInstallFunc = func(wheelhouse, target string) error {
	return runtime.InstallWheelhouse(context.Background(), wheelhouse, target)
}

// depsImportRequest is the request body for /v1/taa/importDeps.
// It deliberately does not reuse importRequest: that type's publicKey and runtimeConfig mean
// nothing for a dependency archive and would be dead weight on the type.
type depsImportRequest struct {
	ResourceURL string `json:"resourceUrl"`
	RequestID   string `json:"requestId"`
	TaskID      string `json:"taskId"`
}

// ── Handler: /v1/taa/importDeps ──────────────────────────

func (s *TAAState) depsImportHandler(w http.ResponseWriter, r *http.Request) {
	var req depsImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, pkgerrors.Wrap(pkgerrors.CodeInvalidArgument, fmt.Sprintf("请求解析失败: %v", err), err))
		return
	}
	req.ResourceURL = strings.TrimSpace(req.ResourceURL)
	req.RequestID = strings.TrimSpace(req.RequestID)
	req.TaskID = strings.TrimSpace(req.TaskID)

	// resourceUrl is mandatory: dependencies are content-addressed, and letting an empty value
	// mean "reuse the current set" would make it impossible to infer which dependency set is
	// actually in effect.
	if req.ResourceURL == "" {
		writeErr(w, http.StatusBadRequest, pkgerrors.New(pkgerrors.CodeInvalidArgument, "resourceUrl 不能为空"))
		return
	}
	if req.RequestID == "" && req.TaskID == "" {
		writeErr(w, http.StatusBadRequest, pkgerrors.New(pkgerrors.CodeInvalidArgument, "requestId 和 taskId 不能同时为空"))
		return
	}

	release, err := s.tryAcquireTaskTyped(req.TaskID, req.RequestID, "deps_importing", "deps_import")
	if err != nil {
		s.Logs.Add(LogWarn, "importDeps", "拒绝并发的依赖导入请求: %v", err)
		writeErr(w, http.StatusConflict, err)
		return
	}

	s.mu.RLock()
	phase := s.CurrentPhase
	s.mu.RUnlock()

	s.Logs.Add(LogInfo, "importDeps", "收到依赖包 import 请求: taskId=%s, requestId=%s, phase=%d",
		req.TaskID, req.RequestID, phase)

	s.Logs.Add(LogInfo, "importDeps", "开始下载依赖包: %s", req.ResourceURL)
	ciphertextPath, size, err := s.downloadToTempFile(req.ResourceURL)
	if err != nil {
		release()
		s.Logs.Add(LogError, "importDeps", "下载依赖包失败: %v", err)
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.Logs.Add(LogInfo, "importDeps", "依赖包下载完成 (%d bytes) -> %s", size, ciphertextPath)

	writeEnvelope(w, http.StatusOK, "依赖包已接收，处理中", nil, 0)

	s.runAsyncSafe("processImportedDeps", release, func() {
		s.processImportedDeps(req, phase, ciphertextPath)
	})
}

// processImportedDeps is the asynchronous dependency import pipeline:
//
//	decrypt -> SM3 content addressing -> unpack into a temporary wheelhouse -> package layout
//	validation -> offline install into DEPS_DIR/<sm3> -> combined fail-closed audit over this
//	set and the model code -> roll back this side only when it came out implicated -> set state
//	-> report
//
// This pipeline is deliberately NOT idempotent: re-delivering the same archive re-unpacks,
// re-installs and re-audits it. The audit verdict now depends on which model code the set was
// scanned together with, and a content address captures only the set itself, so no stored
// artifact -- a marker keyed on the hash in particular -- can stand in for a verdict.
//
// A failure path rolls back only when the combined audit implicated this side. A failing audit
// whose findings all sit on the model side still reports code=1, but it is not a failure of
// this pipeline: the binding is left in place and the delivery stays successful.
func (s *TAAState) processImportedDeps(req depsImportRequest, phase int, ciphertextPath string) {
	defer os.Remove(ciphertextPath)

	s.setCurrentOp("decrypting")
	plaintextPath, isDecrypted, err := s.resolvePlaintextResource(req.ResourceURL, ciphertextPath, "importDeps")
	if err != nil {
		s.setCurrentOp("idle")
		s.reportDepsFailure(req, fmt.Sprintf("解密依赖包失败: %v", err))
		return
	}
	if isDecrypted {
		defer os.Remove(plaintextPath)
	}

	size, hash, err := teecrypto.HashFileSM3(plaintextPath)
	if err != nil {
		s.setCurrentOp("idle")
		s.reportDepsFailure(req, fmt.Sprintf("计算依赖包哈希失败: %v", err))
		return
	}
	checksum := map[string]any{"size": size, "algorithm": "sm3", "value": hash}
	depsDir := s.depsDirForHash(hash)
	s.Logs.Add(LogInfo, "importDeps", "依赖包 SM3=%s (%d bytes) -> %s", hash, size, depsDir)

	// No idempotency short-circuit here. A stored marker could only record this side's hash,
	// but the audit verdict also depends on which model code the set is scanned with, and that
	// is not captured by the content address. Every delivery re-unpacks, re-installs and
	// re-audits (see the pipeline comment above).

	s.setCurrentOp("deps_installing")

	// Unpack into a temporary wheelhouse: extracting the outer archive needs zip-slip
	// protection against a base directory of its own, so it must not write into the
	// content-addressed directory; expanding the wheels themselves is pip's job.
	// The temp dir sits under the deps root rather than the system temp dir because a
	// wheelhouse can be gigabytes and the container's root partition cannot hold it
	// (spec 2.5); the deps root is the volume sized for exactly this.
	wheelhouse, err := os.MkdirTemp(s.Security.GetDepsDir(), "taa-deps-wh-*")
	if err != nil {
		s.setCurrentOp("idle")
		s.reportDepsFailure(req, fmt.Sprintf("创建临时依赖目录失败: %v", err))
		return
	}
	defer os.RemoveAll(wheelhouse)

	if err := resource.ExtractArchiveToDir(wheelhouse, plaintextPath); err != nil {
		s.setCurrentOp("idle")
		s.reportDepsFailure(req, fmt.Sprintf("解压依赖包失败: %v", err))
		return
	}
	if err := resource.ValidateWheelhouse(wheelhouse); err != nil {
		s.setCurrentOp("idle")
		s.reportDepsFailure(req, err.Error())
		return
	}

	// Clear any leftover directory of the same name before installing: pip --target merges into
	// a populated target instead of replacing it, so a half-built leftover from an earlier failed
	// attempt -- or the currently bound directory itself, since this pipeline clears and rebuilds
	// every delivery -- would otherwise be merged into this attempt's result and bound as if its
	// content were this set's. (The failure-path removals below do not depend on this call;
	// os.RemoveAll is already idempotent on a missing path.)
	if err := os.RemoveAll(depsDir); err != nil {
		// RemoveAll failing may have partially destroyed a directory that is currently bound
		// (see rollbackDepsImport), so this branch must make the state decision too.
		s.rollbackDepsImport(depsDir)
		s.setCurrentOp("idle")
		s.reportDepsFailure(req, fmt.Sprintf("清理依赖目录失败: %v", err))
		return
	}
	if err := depsInstallFunc(wheelhouse, depsDir); err != nil {
		s.rollbackDepsImport(depsDir)
		s.setCurrentOp("idle")
		s.reportDepsFailure(req, fmt.Sprintf("安装依赖包失败: %v", err))
		return
	}
	s.Logs.Add(LogInfo, "importDeps", "依赖包安装完成: %s", depsDir)

	// One combined audit over the delivered set and the model code it will run against.
	// Only this side is this pipeline's to remove: findings on the model side leave this
	// delivery successful and are reported, not acted on (see combined_audit.go).
	result := s.runCombinedAudit(
		codeAuditRequest{RequestID: req.RequestID, TaskID: req.TaskID},
		codeAuditTriggerDeps, depsDir)
	if !result.TriggerClean {
		// "依赖包审计未通过" is the pre-existing user-visible string and was already the generic
		// bucket for both "the audit failed" and "the audit could not run". Do not narrow it.
		s.rollbackDepsImport(depsDir)
		s.setCurrentOp("idle")
		s.reportDepsFailure(req, "依赖包审计未通过")
		return
	}

	s.saveDepsSuccess(hash, checksum)
	s.reportDepsSuccess(req, checksum)
	s.setCurrentOp("idle")
	s.Logs.Add(LogInfo, "importDeps", "阶段%d: 依赖包导入完成: hash=%s, taskId=%s", phase, hash, req.TaskID)
}

// rollbackDepsImport discards the directory of a dependency import that failed, and clears the
// binding only when that very set is the one currently in effect.
//
// The invariant it enforces, together with saveDepsSuccess, is that the binding never outlives
// the directory it points at. Both halves of that invariant are reachable, and each has its own
// silent degradation:
//
//   - A rejected newcomer must not unseat a dependency set that is already working. The binding
//     is overwritten on success only (see saveDepsSuccess), so a failed import leaves the
//     previous set active and training keeps running on it; clearing unconditionally would
//     degrade a working configuration to "no dependencies" and surface later as an unrelated
//     ImportError during training.
//   - Conversely, the binding must not outlive its own directory. This pipeline is not
//     idempotent (see processImportedDeps): re-delivering an already-bound set clears the
//     directory in use and rebuilds it every time, so a rebuild that fails must clear the
//     binding too -- a binding left behind would point at a directory that no longer exists,
//     training would inject a stale TAA_DEPS_DIR and fail with that same ImportError, with the
//     two halves swapped.
//
// That is why every failure path in processImportedDeps routes through here rather than calling
// os.RemoveAll directly: the removal and the state decision must not be separable.
//
// The comparison and the clearing are two separate lock acquisitions, so in general they could
// be interleaved by a concurrent writer. They are safe here because tryAcquireTaskTyped
// single-flights dependency imports: the pipeline is the only runtime writer of this state,
// and no second deps_import can be admitted while one is in flight (the startup restore,
// app.go, runs before the server accepts requests).
//
// Every removal this pipeline performs happens here, and the state decision with it. The
// combined audit (combined_audit.go) physically removes nothing -- it only reports -- so
// nothing else can clean up the delivered side; this function is the single place that owns
// both the removal and the decision, precisely because the audit no longer deletes anything.
func (s *TAAState) rollbackDepsImport(depsDir string) {
	_ = os.RemoveAll(depsDir)
	// currentDepsDir() already encodes "imported && hash non-empty", and depsDirForHash
	// builds its result the same way, so equality means this failed set is the bound one.
	// (saveDepsSuccess is what binds a set and it runs only after a clean audit, so the
	// audit path normally reaches here for a set that is not yet bound; the guard also
	// covers a re-delivery of the set that is currently bound, which the pipeline clears
	// and rebuilds on every delivery.)
	if s.currentDepsDir() == depsDir {
		s.clearDepsState()
	}
}

// reportDepsSuccess reports a successful dependency import to the platform.
func (s *TAAState) reportDepsSuccess(req depsImportRequest, checksum map[string]any) {
	s.reportDepsAsync(req.RequestID, req.TaskID, 0, "依赖包导入成功", checksum)
}

// reportDepsFailure logs and reports a failed dependency import to the platform.
func (s *TAAState) reportDepsFailure(req depsImportRequest, reason string) {
	s.Logs.Add(LogError, "importDeps", "依赖包导入失败: %s", reason)
	s.reportDepsAsync(req.RequestID, req.TaskID, 1, reason)
}

// reportDepsAsync reports the dependency import result to the platform asynchronously. A failed
// report is only logged; it does not change the pipeline's own outcome.
func (s *TAAState) reportDepsAsync(requestID, taskID string, code int, msg string, checksum ...map[string]any) {
	s.mu.RLock()
	platformIP, dockerID := s.PlatformIP, s.DockerID
	s.mu.RUnlock()

	var cs map[string]any
	if len(checksum) > 0 {
		cs = checksum[0]
	}

	go func() {
		if err := ReportDeps(context.Background(), platformIP, dockerID, requestID, taskID, code, msg, cs); err != nil {
			s.Logs.Add(LogWarn, "importDeps", "上报依赖包导入结果失败: requestId=%s taskId=%s code=%d err=%v",
				requestID, taskID, code, err)
		} else {
			s.Logs.Add(LogInfo, "importDeps", "上报依赖包导入结果成功: requestId=%s taskId=%s code=%d",
				requestID, taskID, code)
		}
	}()
}
