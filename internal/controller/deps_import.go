package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
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
//	decrypt -> SM3 content addressing -> idempotency check -> unpack into a temporary wheelhouse
//	-> package layout validation -> offline install into DEPS_DIR/<sm3> -> fail-closed audit
//	-> write the audit marker -> set state -> report
//
// Every failure path rolls back: it clears the state and removes DEPS_DIR/<sm3>, never leaving
// a half-built directory behind.
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

	// Idempotency: a directory with the same hash that already passed the audit is reused
	// as-is, without unpacking or installing again.
	if auditMarkerExists(depsDir) {
		s.Logs.Add(LogInfo, "importDeps", "依赖包 %s 已审计通过，复用现有目录", hash)
		s.saveDepsSuccess(hash, checksum)
		s.reportDepsSuccess(req, checksum)
		s.setCurrentOp("idle")
		return
	}

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

	// Clear any leftover directory of the same name before installing, so the removal on the
	// failure paths below is idempotent.
	if err := os.RemoveAll(depsDir); err != nil {
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

	if !s.auditAndReportDeps(req, depsDir) {
		s.rollbackDepsImport(depsDir)
		s.reportDepsFailure(req, "依赖包审计未通过")
		s.setCurrentOp("idle")
		return
	}

	if err := writeAuditMarker(depsDir); err != nil {
		s.rollbackDepsImport(depsDir)
		s.setCurrentOp("idle")
		s.reportDepsFailure(req, fmt.Sprintf("写入审计标记失败: %v", err))
		return
	}

	s.saveDepsSuccess(hash, checksum)
	s.reportDepsSuccess(req, checksum)
	s.setCurrentOp("idle")
	s.Logs.Add(LogInfo, "importDeps", "阶段%d: 依赖包导入完成: hash=%s, taskId=%s", phase, hash, req.TaskID)
}

// depsAuditMarker is the sentinel file written into a dependency directory once its audit has
// passed. It is a regular file rather than a directory so its presence is unambiguous.
const depsAuditMarker = ".taa_audit_ok"

func auditMarkerExists(depsDir string) bool {
	info, err := os.Stat(filepath.Join(depsDir, depsAuditMarker))
	return err == nil && !info.IsDir()
}

func writeAuditMarker(depsDir string) error {
	return os.WriteFile(filepath.Join(depsDir, depsAuditMarker), []byte("audited\n"), 0o644)
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
//   - Conversely, the binding must not outlive its own directory. Re-importing a set whose
//     audit marker was deleted by hand makes the idempotence check miss, so the pipeline clears
//     the directory in use, and if the rebuild then fails, a binding left behind would point at
//     a directory that no longer exists -- training would inject a stale TAA_DEPS_DIR and fail
//     with the same ImportError, with the two halves swapped.
//
// That is why every failure path in processImportedDeps routes through here rather than calling
// os.RemoveAll directly: the removal and the state decision must not be separable.
//
// runDepsAudit also removes the directory on every path that returns false (deps_audit.go),
// so the removal here is normally a no-op. It is kept so that this pipeline's own
// "no half-built directory survives a failure" guarantee does not hinge on a side effect
// of a function whose job is to audit.
func (s *TAAState) rollbackDepsImport(depsDir string) {
	_ = os.RemoveAll(depsDir)
	// currentDepsDir() already encodes "imported && hash non-empty", and depsDirForHash
	// builds its result the same way, so equality means this failed set is the bound one.
	// (The marker is written before saveDepsSuccess, so normally the audit path is only
	// reached for a set that is not yet bound; the guard also covers a re-import whose
	// marker was deleted by hand.)
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

// reportDepsAsync reports a dependency import result to the platform.
// This stub only logs; Task 7 replaces it with the real platform callback.
func (s *TAAState) reportDepsAsync(requestID, taskID string, code int, msg string, checksum ...map[string]any) {
	s.Logs.Add(LogInfo, "importDeps", "deps import report: request=%s task=%s code=%d msg=%s",
		requestID, taskID, code, msg)
}

// auditAndReportDeps runs the fail-closed audit over the installed dependency directory.
// It reports the audit result itself, with scope "deps" (see deps_audit.go). The import
// pipeline's own terminal reportDeps callback is NOT its job: that one belongs to
// processImportedDeps, which must still fire code=1 when this returns false.
func (s *TAAState) auditAndReportDeps(req depsImportRequest, depsDir string) bool {
	if !s.Security.ScanEnabled {
		s.Logs.Add(LogInfo, "audit", "安全扫描未启用，跳过依赖包审计")
		return true
	}
	return s.runDepsAudit(req, depsDir)
}

// runDepsAudit runs the fail-closed dependency audit.
//
// This placeholder refuses every dependency set. It originally returned true so that tests
// could drive the pipeline with scanning enabled, but that is fail-OPEN, not fail-closed:
// security scanning defaults to on (config.EnableSecurityScan), the /v1/taa/importDeps route is
// mounted, so an unaudited set would pass, a real audit marker would be written at the end of
// processImportedDeps, and code=0 would be reported. The idempotence check only tests whether
// that marker exists, so Task 8's real audit would then be short-circuited by the marker for
// good. Refusing is the only honest answer while no audit exists (spec 3, decision 5: same
// engine, same policy, fail-closed).
//
// Task 8 replaces this with the real audit, which also owns removing the directory on every
// path that returns false.
func (s *TAAState) runDepsAudit(req depsImportRequest, depsDir string) bool {
	s.Logs.Add(LogError, "audit", "依赖包审计尚未实现，按 fail-closed 拒绝")
	return false
}
