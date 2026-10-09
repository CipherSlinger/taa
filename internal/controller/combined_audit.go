package controller

import (
	"context"
	"fmt"
	"os"

	"taa/internal/codeaudit"
)

// The two sides a combined audit can be triggered by. The token names which side of
// the delivery the audit is for; it is not the scope that goes on the wire, which
// auditScopeForTrigger derives from it.
const (
	// codeAuditTriggerModel is a trigger from /v1/taa/importModel: a model archive
	// was just unpacked into Security.ModelDir.
	codeAuditTriggerModel = "model"
	// codeAuditTriggerDeps is a trigger from /v1/taa/importDeps: a dependency archive
	// was just installed into <depsDir>/<sm3>.
	codeAuditTriggerDeps = "deps"
)

// codeAuditRequest carries the identifiers a reportAudit callback is addressed to.
// Both import pipelines spell these two fields the same way, so the executor takes
// them through a type of its own rather than depending on either pipeline's request
// struct and having to be changed whenever one of those grows a field.
type codeAuditRequest struct {
	RequestID string
	TaskID    string
}

// combinedAuditResult is the outcome of one combined audit.
type combinedAuditResult struct {
	// Passed is the audit's own verdict over the combined root set, which is what the
	// platform reads as `code`: a run whose only failures sit on the side that was
	// not delivered is still a failed audit.
	Passed bool

	// TriggerClean reports whether the root this request delivered came out of the
	// audit unimplicated, and is the only field a caller may act on: it decides
	// whether the delivered side is cleared.
	TriggerClean bool

	// Executed is false when the ScanEnabled=false short-circuit skipped the audit
	// entirely. No report is emitted in that case and TriggerClean is true, because
	// an audit that never ran implicates no root.
	Executed bool

	// Report is the audit report; nil on every path that did not complete the audit.
	Report  *codeaudit.AuditReport
	Summary string
}

// auditScopeForTrigger maps a trigger side onto the reportAudit scope value the
// platform already accepts. Both values are unchanged -- "" for a model trigger and
// "deps" for a dependency trigger -- but they now name the triggering side rather
// than the audited directory, because the two triggers audit the same roots.
//
// Anything unrecognized maps to "" rather than to a value of its own: the platform
// accepts only this pair, and inventing a third would turn a caller's typo into a
// report the platform drops instead of one an operator can see.
func auditScopeForTrigger(triggerSide string) string {
	if triggerSide == codeAuditTriggerDeps {
		return "deps"
	}
	return ""
}

// dirExists reports whether dir names an existing directory.
//
// Every candidate root is checked with this before the audit is handed the list,
// because the scan stats each root up front and fails the whole run on a missing
// one: passing a directory that is not there does not skip that root, it turns the
// audit into an execution failure, and under fail-closed that rejects a delivery
// that was legitimate. "Dependencies first, model second" is the path that reaches
// it in practice.
func dirExists(dir string) bool {
	if dir == "" {
		return false
	}
	info, err := os.Stat(dir)
	return err == nil && info.IsDir()
}

// combinedAuditRoots returns the roots a combined audit covers for this trigger:
// the code this request delivered, plus the other side as currently in effect.
// A root enters only when it is in effect -- the model root needs ModelImported,
// the dependency root needs its directory to exist -- because handing a missing
// directory to the audit fails the walk and, under fail-closed, rejects a delivery
// that was legitimate.
//
// The model root comes first whenever it is in effect. Position is not cosmetic:
// AuditTarget.Directory names dirs[0], and the CPG enrichment builds its symbol
// index from the same root, so a run that scanned the model while naming the
// dependency tree as primary would attribute the model's own files to the other
// tree.
func (s *TAAState) combinedAuditRoots(triggerSide, triggerDir string) []string {
	s.mu.RLock()
	modelImported := s.ModelImported
	s.mu.RUnlock()

	roots := make([]string, 0, 2)
	if modelImported && dirExists(s.Security.ModelDir) {
		roots = append(roots, s.Security.ModelDir)
	}

	switch triggerSide {
	case codeAuditTriggerDeps:
		// The directory this delivery installed, not currentDepsDir(): DepsHash is
		// only updated once the audit has passed (saveDepsSuccess), so while this
		// runs the binding still names the previous set.
		if dirExists(triggerDir) {
			roots = append(roots, triggerDir)
		}

	default:
		// A model trigger. The other side is the dependency set as bound, and it
		// enters only when it is both bound and present.
		if depsDir := s.currentDepsDir(); dirExists(depsDir) {
			roots = append(roots, depsDir)
		}
	}

	if len(roots) == 0 {
		// Nothing is in effect. Audit a caller bug rather than an empty list: on a
		// model trigger this is where an import flag that was never set lands, and on
		// a dependency trigger it is a directory the pipeline believed it had just
		// installed. An empty list would be rejected by the audit as a caller error
		// before it looked at anything, which leaves the delivered side unjudged;
		// naming that directory instead keeps the failure on the side that owns it,
		// where the caller's rollback can act on it.
		s.Logs.Add(LogError, "audit", "合并审计没有生效根，按交付目录审计: trigger=%s dir=%s", triggerSide, triggerDir)
		roots = append(roots, triggerDir)
	}
	return roots
}

// runCombinedAudit audits every root combinedAuditRoots returns, reports the result
// exactly once under the scope for the triggering side, and reports back which side
// came out clean. Both triggers file through it, so the two paths cannot drift in
// what they clear, what they report, or what they leave behind in the audit state.
//
// It owns the audit-state bookkeeping (ActiveAuditTaskID / ActiveAuditRequestID /
// CurrentAuditOp / AuditRunning), setting it on entry and clearing it on every exit
// including the short-circuit. A caller that also maintained those fields could
// leave one set on a path it did not anticipate, and a stuck AuditRunning is not a
// cosmetic leak: isAuditBusyLocked reads it, and the next model or dependency
// delivery would be refused for good.
//
// Known blind spots -- a passing audit is not the same as a trusted delivery, and
// they apply to the combined root set as a whole:
//
//  1. The scan reads source file contents. The engine skips compiled artifacts by
//     extension (internal/codeaudit/scanner.go, hasMatchingExtension; the semgrep engine
//     applies the same check in internal/codeaudit/semgrep_engine.go), so supply-chain
//     risk carried inside a .so or .pyd binary is outside what this audit can see.
//  2. Integrity is SM3 content addressing only. There is no publisher signature and no
//     signature verification; the trust model is the same one the platform side already
//     assumes.
//  3. Therefore "audit passed" means "no rule of this static policy matched", not "these
//     dependencies are safe" -- nor "this model code is safe". The mitigations (an audit
//     allowlist, signature verification) are left to a later spec.
//
// There is deliberately no test hook here, for either trigger. The model path has none
// either: its tests hand the real engine a rule-matching train.py and assert on the
// report (audit_model_import_test.go), and the dependency path is tested the same way
// (deps_import_test.go). One assertion therefore covers the engine call, the
// auditReportJSON projection and the scope report together; a hook would skip exactly
// those three and leave only the side's rollback covered.
func (s *TAAState) runCombinedAudit(req codeAuditRequest, triggerSide, triggerDir string) combinedAuditResult {
	s.mu.Lock()
	s.ActiveAuditTaskID = req.TaskID
	s.ActiveAuditRequestID = req.RequestID
	s.CurrentAuditOp = "auditing"
	s.AuditRunning = true
	s.mu.Unlock()
	defer s.clearAuditState()

	if !s.Security.ScanEnabled {
		// Fail-closed has exactly one exception and this is it: with scanning off the
		// audit is skipped whole, reports nothing, and clears nothing. TriggerClean is
		// true rather than false because an audit that never ran implicates no root,
		// and a caller reading false here would delete a delivery nothing had judged.
		s.Logs.Add(LogInfo, "audit", "安全扫描未启用，跳过代码审计")
		return combinedAuditResult{Passed: true, TriggerClean: true, Executed: false}
	}

	cfg := s.Security.LLM
	scope := auditScopeForTrigger(triggerSide)
	roots := s.combinedAuditRoots(triggerSide, triggerDir)

	StepSeparator("Code Audit")
	s.Logs.Add(LogInfo, "audit", "开始代码审计: engine=%s, trigger=%s, roots=%v, llmEnabled=%v, policy=%s, failClosed=%v",
		engineName(s.Security.Engine), triggerSide, roots, cfg.Enabled, cfg.Policy, cfg.FailClosed)

	llmClient := newLLMClient(cfg)

	// fail-closed: when the LLM is enabled and configured to block on unavailability,
	// probe it first and fail outright if it is down, rather than silently degrading
	// to a static-only scan that lets the delivery through.
	if cfg.Enabled && cfg.FailClosed && !isLLMServiceAvailable(llmClient, cfg.Endpoint, cfg.Model) {
		s.Logs.Add(LogError, "audit", "LLM 服务不可用，按 fail-closed 策略上报失败: endpoint=%s model=%s", cfg.Endpoint, cfg.Model)
		s.reportAuditScopedAsync(req.RequestID, req.TaskID, 2, "LLM 服务不可用，按 fail-closed 策略上报失败", "", scope)
		return combinedAuditResult{Executed: true, Summary: "LLM 服务不可用，按 fail-closed 策略上报失败"}
	}

	audit, err := codeaudit.GenerateAuditReportForDirs(context.Background(), roots, s.Security.Engine, cfg, llmClient)
	if err != nil {
		msg := fmt.Sprintf("代码审计失败: %v", err)
		s.Logs.Add(LogError, "audit", "%s", msg)
		s.reportAuditScopedAsync(req.RequestID, req.TaskID, 2, msg, "", scope)
		return combinedAuditResult{Executed: true, Summary: msg}
	}

	// LastAudit is written here, on the success path, rather than by each caller. The
	// combined audit covers the model root whenever the model is in effect, so both
	// triggers now produce a report a training report can carry, and the field no
	// longer means "the last model audit" -- it means the last audit, from whichever
	// side asked for it.
	s.setLastAudit(audit)

	code := 0
	if !audit.Conclusion.Passed {
		code = 1
	}

	// A failing audit implicates the delivered root when the failure cannot be
	// attributed away from it. Attribution alone is not enough, and that is the whole
	// point: Conclusion.Passed is forced false by a scan that did not prove it looked
	// (audit.go), and a truncated scan keeps whichever findings its cap allowed. When
	// the visible findings all sit under the other root, attribution says this root is
	// clean while the scan in fact never reached part of the input -- and reading that
	// as clean would let a truncated scan pass a delivery that today's code rejects by
	// clearing both sides. ScanProvedClean is the term that closes it.
	implicated := !audit.Conclusion.Passed &&
		(!audit.ScanMetadata.ScanProvedClean || codeaudit.ReportHasFindingsUnder(audit, triggerDir))
	triggerClean := !implicated

	s.Logs.Add(LogInfo, "audit", "审计完成: passed=%v, triggerClean=%v, code=%d, riskLevel=%s, totalFindings=%d, roots=%v",
		audit.Conclusion.Passed, triggerClean, code, audit.Conclusion.RiskLevel, audit.Conclusion.Statistics.Total(), roots)

	s.reportAuditScopedAsync(req.RequestID, req.TaskID, code, audit.Conclusion.Summary, auditReportJSON(audit), scope)
	return combinedAuditResult{
		Passed:       audit.Conclusion.Passed,
		TriggerClean: triggerClean,
		Executed:     true,
		Report:       audit,
		Summary:      audit.Conclusion.Summary,
	}
}
