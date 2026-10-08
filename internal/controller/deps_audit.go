package controller

import (
	"context"
	"os"

	"taa/internal/codeaudit"
)

// runDepsAudit audits an installed dependency directory with the same engine and the same
// policy as the model code audit, and reports the result with scope="deps". When the audit
// does not pass, the dependency directory is deleted from disk: under fail-closed semantics a
// rejected dependency set must not survive the request that rejected it.
//
// The audit state is set and cleared the way startModelAuditAsync (import_processing.go) does
// it: the four fields are written here under the lock, and clearAuditState resets them on the
// way out. This function does NOT call setLastAudit: that holds the model audit's verdict for
// /v1/taa/status, and a dependency audit overwriting it would report the wrong thing.
//
// Known blind spots -- a passing audit is not the same as a trusted dependency set:
//
//  1. The scan reads the unpacked wheel *contents*. The engine skips compiled artifacts by
//     extension (internal/codeaudit/scanner.go, hasMatchingExtension; the semgrep engine applies
//     the same check in internal/codeaudit/semgrep_engine.go), so supply-chain risk carried
//     inside a .so or .pyd binary is outside what this audit can see.
//  2. Integrity is SM3 content addressing only. There is no publisher signature and no
//     signature verification; the trust model is the same one the platform side already
//     assumes.
//  3. Therefore "audit passed" means "no rule of this static policy matched", not "these
//     dependencies are safe". The mitigations (an audit allowlist, signature verification)
//     are left to a later spec.
//
// There is deliberately no test hook here. The model audit (auditAndReportModelImport) has
// none either: its tests hand the real engine a rule-matching train.py and assert on the
// report (audit_model_import_test.go). The dependency audit is tested the same way, so one
// assertion covers the engine call, the auditReportJSON projection and the scope=deps report
// together; a hook would skip exactly those three and leave only the directory removal
// covered.
func (s *TAAState) runDepsAudit(req depsImportRequest, depsDir string) bool {
	s.mu.Lock()
	s.ActiveAuditTaskID = req.TaskID
	s.ActiveAuditRequestID = req.RequestID
	s.CurrentAuditOp = "auditing"
	s.AuditRunning = true
	s.mu.Unlock()
	defer s.clearAuditState()

	cfg := s.Security.LLM
	llmClient := newLLMClient(cfg)

	// fail-closed: when the LLM is enabled and configured to block on unavailability, probe it
	// first and fail outright if it is down, rather than silently degrading to a static-only
	// scan that lets the set through. The policy matches the model code audit exactly.
	if cfg.Enabled && cfg.FailClosed && !isLLMServiceAvailable(llmClient, cfg.Endpoint, cfg.Model) {
		s.Logs.Add(LogError, "audit", "LLM 服务不可用，依赖审计按 fail-closed 上报失败: endpoint=%s model=%s", cfg.Endpoint, cfg.Model)
		_ = os.RemoveAll(depsDir)
		s.reportAuditScopedAsync(req.RequestID, req.TaskID, 2, "LLM 服务不可用，按 fail-closed 策略上报失败", "", "deps")
		return false
	}

	audit, err := codeaudit.GenerateAuditReport(context.Background(), depsDir, s.Security.Engine, cfg, llmClient)
	if err != nil {
		s.Logs.Add(LogError, "audit", "依赖包审计执行失败: %v", err)
		_ = os.RemoveAll(depsDir)
		s.reportAuditScopedAsync(req.RequestID, req.TaskID, 2, "依赖包审计失败: "+err.Error(), "", "deps")
		return false
	}

	code := 0
	if !audit.Conclusion.Passed {
		code = 1
		_ = os.RemoveAll(depsDir)
	}
	s.Logs.Add(LogInfo, "audit", "依赖包审计完成: passed=%v, riskLevel=%s, totalFindings=%d",
		audit.Conclusion.Passed, audit.Conclusion.RiskLevel, audit.Conclusion.Statistics.Total())

	s.reportAuditScopedAsync(req.RequestID, req.TaskID, code, audit.Conclusion.Summary, auditReportJSON(audit), "deps")
	return audit.Conclusion.Passed
}
