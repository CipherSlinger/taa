package codeaudit

import (
	"context"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	"taa/teellm"
)

// VerifyReport runs the LLM verifier on a static scan report.
// It enriches each finding with LLM verdict/reason/risk.
// Returns the enriched report. If policy is "gate", it recalculates Passed.
func VerifyReport(ctx context.Context, report *Report, cfg LLMConfig, client LLMClient) (*Report, error) {
	if !cfg.Enabled || client == nil || report == nil {
		return report, nil
	}
	if len(report.Findings) == 0 {
		return report, nil
	}

	limit := cfg.MaxFindings
	if limit <= 0 || limit > len(report.Findings) {
		limit = len(report.Findings)
	}

	var hasInferenceFailure bool

	for i := 0; i < limit; i++ {
		if ctx.Err() != nil {
			for j := i; j < len(report.Findings); j++ {
				rem := &report.Findings[j]
				if rem.LLMVerdict == "" {
					rem.LLMVerdict = "UNCERTAIN"
					rem.LLMReason = fmt.Sprintf("SERVICE_UNAVAILABLE: %v", ctx.Err())
				}
			}
			hasInferenceFailure = true
			break
		}

		f := &report.Findings[i]

		req := &teellm.RequestEnvelope{
			ProtocolVersion: teellm.CurrentProtocolVersion,
			RequestID:       fmt.Sprintf("verify-%d", time.Now().UnixNano()),
			Timestamp:       time.Now().Unix(),
			Action:          teellm.ActionVerifyFinding,
			FindingPayload: &teellm.FindingPayload{
				RuleID:      f.RuleID,
				Category:    f.Category,
				Severity:    f.Severity,
				Description: f.Description,
				Target: teellm.CodeTarget{
					FilePath:      f.File,
					Line:          f.Line,
					CodeSnippet:   f.CodeSnippet,
					ContextBefore: f.ContextBefore,
					ContextAfter:  f.ContextAfter,
				},
			},
			Policy: teellm.PolicyOptions{
				Mode: cfg.Policy,
			},
		}
		if cfg.Model != "" {
			req.ModelRef = &teellm.ModelReference{Name: cfg.Model}
		}

		resp, err := client.VerifyFinding(ctx, req)
		if err != nil || resp == nil || resp.Status != teellm.StatusSuccess {
			f.LLMVerdict = "UNCERTAIN"
			if errors.Is(err, teellm.ErrCircuitOpen) {
				f.LLMReason = "SERVICE_UNAVAILABLE: circuit breaker open"
			} else if err != nil {
				f.LLMReason = fmt.Sprintf("SERVICE_UNAVAILABLE: %v", err)
			} else if resp != nil {
				f.LLMReason = fmt.Sprintf("SERVICE_UNAVAILABLE: %s", resp.Status)
			} else {
				f.LLMReason = "SERVICE_UNAVAILABLE: nil response"
			}
			hasInferenceFailure = true
			continue
		}

		if resp.Decision == nil {
			f.LLMVerdict = "UNCERTAIN"
			f.LLMReason = "SERVICE_UNAVAILABLE: empty decision payload"
			hasInferenceFailure = true
			continue
		}

		f.LLMVerdict = resp.Decision.Verdict
		f.LLMReason = resp.Decision.Explanation
		f.LLMRisk = resp.Decision.RiskLevel
		if f.LLMRisk == "" && resp.Decision.SuggestedRemediation != "" {
			f.LLMRisk = resp.Decision.SuggestedRemediation
		}
	}

	// Unconditional LLMDegraded setting on inference failure
	if hasInferenceFailure {
		report.LLMDegraded = true
	}

	// Fail-closed / Gate arbitration
	if cfg.Policy == "gate" {
		if hasInferenceFailure {
			if cfg.FailClosed {
				failedClosed := false
				for _, f := range report.Findings {
					if (f.Severity == SeverityHigh || f.Severity == SeverityMedium) && f.LLMVerdict != teellm.VerdictBenign {
						failedClosed = true
						break
					}
				}
				recalculatePassed(report)
				if failedClosed {
					report.Passed = false
				}
			} else {
				recalculateStaticPassed(report)
			}
		} else {
			recalculatePassed(report)
		}
	} else {
		recalculateStaticPassed(report)
	}

	return report, nil
}

// recalculatePassed re-evaluates Report.Passed when LLM gate policy is active.
// A HIGH finding is considered "downgraded" if LLM verdict is BENIGN.
// All other verdicts (MALICIOUS, SUSPICIOUS, UNCERTAIN) still block.
func recalculatePassed(report *Report) {
	highCount := 0
	mediumCount := 0
	for _, f := range report.Findings {
		switch f.Severity {
		case SeverityHigh:
			if f.LLMVerdict == teellm.VerdictBenign {
				// Downgraded: no longer blocks.
				continue
			}
			highCount++
		case SeverityMedium:
			mediumCount++
		}
	}
	report.HighCount = highCount
	report.MediumCount = mediumCount
	report.Passed = highCount == 0
}

// CheckImportWithLLM is the high-level gate function that combines
// static scanning with optional LLM verification.
func CheckImportWithLLM(ctx context.Context, dir string, cfg LLMConfig) (bool, *Report, error) {
	if dir == "" {
		return true, nil, nil
	}

	report, err := DefaultScanner().ScanDirectory(dir)
	if err != nil {
		return false, nil, err
	}

	if !cfg.Enabled || len(report.Findings) == 0 {
		return report.Passed, report, nil
	}

	if cfg.Endpoint == "" {
		return report.Passed, report, nil
	}

	client, err := NewInferenceClient(cfg)
	if err != nil {
		if cfg.FailClosed {
			return false, report, fmt.Errorf("create inference client: %w", err)
		}
		log.Printf("create inference client failed (non-fatal): %v", err)
		return report.Passed, report, nil
	}
	defer client.Close()

	report, err = VerifyReport(ctx, report, cfg, client)
	if err != nil {
		if cfg.FailClosed {
			return false, report, fmt.Errorf("LLM verifier failed: %w", err)
		}
		log.Printf("LLM verifier failed (non-fatal): %v", err)
		return report.Passed, report, nil
	}

	// In assist mode, LLM results are informational only.
	// The static scan's original pass/fail is preserved.
	if cfg.Policy == "assist" {
		recalculateStaticPassed(report)
	}

	return report.Passed, report, nil
}

// recalculateStaticPassed restores the static-scan-only pass decision,
// ignoring LLM verdicts. Used in "assist" mode.
func recalculateStaticPassed(report *Report) {
	highCount := 0
	mediumCount := 0
	for _, f := range report.Findings {
		switch f.Severity {
		case SeverityHigh:
			highCount++
		case SeverityMedium:
			mediumCount++
		}
	}
	report.HighCount = highCount
	report.MediumCount = mediumCount
	report.Passed = highCount == 0
}

// SummarizeLLMVerdicts returns a human-readable summary of LLM results.
func SummarizeLLMVerdicts(report *Report) string {
	if report == nil {
		return ""
	}
	counts := map[string]int{}
	for _, f := range report.Findings {
		if f.LLMVerdict != "" {
			counts[f.LLMVerdict]++
		}
	}
	if len(counts) == 0 {
		return "无 LLM 分析"
	}
	parts := make([]string, 0, len(counts))
	for v, c := range counts {
		parts = append(parts, fmt.Sprintf("%s=%d", v, c))
	}
	return strings.Join(parts, ", ")
}

// ── File-level analysis ───────────────────────────────────

const fileAnalysisPromptTemplate = `你是一个严谨的代码安全审计专家，请分析以下 Python 代码文件是否存在恶意后门、敏感数据外传或攻击行为。

## 文件信息
文件: %s (共 %d 行)
静态规则扫描提示 (%d 处需确认点): %s

## 文件内容（节选）
` + "```python" + `
%s
` + "```" + `

## 判定基准
1. 正常的模型构建、前向推理、反向传播、权重保存、性能指标计算与打印（如 acc、auc、loss、dataset 标签与分隔符等）、训练结果导出（如混淆矩阵、ROC 曲线等）属于良性科研与训练逻辑，风险等级为 LOW，chained 为 false，exfiltration 为 false。
2. 只有当代码中确凿存在未经授权的网络外发、系统后门、动态恶意执行或将敏感原始数据伪装外传时，才可判定 risk_level 为 HIGH/MEDIUM，并标记 chained 或 exfiltration 为 true。
3. 严禁将常规的模型评估、指标打印或数据集名称输出误判为数据外传或攻击链。

## 请严格按以下 JSON 格式输出，不要包含其他内容:
{"risk_level":"HIGH/MEDIUM/LOW","summary":"一句话安全结论(中文)","chained":false,"exfiltration":false}`

// GenerateAuditReport is the high-level entry point that performs a full
// security audit: static scan → finding-level LLM → file-level LLM → aggregate.
func GenerateAuditReport(ctx context.Context, dir string, cfg LLMConfig, client LLMClient) (*AuditReport, error) {
	startTime := time.Now()

	if dir == "" {
		return nil, fmt.Errorf("audit directory is empty")
	}

	// Phase 1: Static scan with line counts.
	scanReport, lineCounts, err := DefaultScanner().ScanDirectoryWithLines(dir)
	if err != nil {
		return nil, fmt.Errorf("static scan: %w", err)
	}

	// Phase 2: Finding-level LLM verification (reuse existing VerifyReport).
	if cfg.Enabled && client != nil && len(scanReport.Findings) > 0 {
		scanReport, err = VerifyReport(ctx, scanReport, cfg, client)
		if err != nil {
			log.Printf("LLM finding verification failed (non-fatal): %v", err)
		}
	}

	// Phase 3: Group findings by file + file-level LLM analysis.
	fileGroups := GroupFindingsByFile(scanReport.Findings)
	var fileReports []FileReport

	for filePath, findings := range fileGroups {
		fr := BuildFileReport(filePath, findings)

		// Enrich findings with suggestions (Go-side, not LLM).
		for i := range fr.Findings {
			fr.Findings[i].LLMRisk = firstNonEmpty(fr.Findings[i].LLMRisk, "")
		}

		if cfg.Enabled && client != nil {
			summary := analyzeFileWithLLM(ctx, client, filePath, findings, lineCounts)
			fr.RiskLevel = summary.RiskLevel
			fr.Summary = summary.Summary
			fr.Chained = summary.Chained
			fr.HasExfiltrationPattern = summary.Exfiltration
		}

		fileReports = append(fileReports, fr)
	}

	// Phase 4: Assemble the full audit report (Go-side aggregation).
	audit := AssembleAuditReport(dir, scanReport, fileReports, lineCounts, cfg, time.Since(startTime))
	return audit, nil
}

// analyzeFileWithLLM calls the LLM for a file-level security summary.
func analyzeFileWithLLM(ctx context.Context, client LLMClient, filePath string, findings []Finding, lineCounts map[string]int) FileSummary {
	if fa, ok := client.(FileAnalyzer); ok {
		maxLines := 80
		code := ReadFileForAnalysis(filePath, maxLines)
		lineCount := lineCounts[filePath]
		if lineCount == 0 {
			lineCount = CountFileLines(filePath)
		}
		summary := BuildFindingsSummary(findings)

		prompt := fmt.Sprintf(fileAnalysisPromptTemplate,
			filepath.Base(filePath), lineCount,
			len(findings), summary,
			code,
		)

		result, err := fa.AnalyzeFile(ctx, prompt)
		if err != nil {
			log.Printf("LLM file analysis error for %s: %v", filepath.Base(filePath), err)
			return FileSummary{
				RiskLevel: "UNCERTAIN",
				Summary:   fmt.Sprintf("LLM 分析失败: %v", err),
			}
		}
		return result
	}

	// Synthesize a FileSummary from findings when client does not implement FileAnalyzer.
	return synthesizeFileSummary(filePath, findings)
}

// synthesizeFileSummary derives a FileSummary from finding severities and categories.
func synthesizeFileSummary(filePath string, findings []Finding) FileSummary {
	if len(findings) == 0 {
		return FileSummary{
			RiskLevel:    "LOW",
			Summary:      "未发现安全风险",
			Chained:      false,
			Exfiltration: false,
		}
	}

	hasHigh := false
	hasMedium := false
	hasExfil := false
	categories := make(map[string]struct{})

	for _, f := range findings {
		if strings.ToUpper(strings.TrimSpace(f.LLMVerdict)) == "BENIGN" {
			continue
		}
		risk := ClassifyFindingRisk(f)
		if risk == "HIGH" || strings.ToUpper(f.LLMVerdict) == "MALICIOUS" {
			hasHigh = true
		} else if risk == "MEDIUM" || strings.ToUpper(f.LLMVerdict) == "SUSPICIOUS" {
			hasMedium = true
		}
		if f.RuleID == "EXF_001" || strings.Contains(f.Category, "外传") || strings.Contains(f.Category, "网络") {
			hasExfil = true
		}
		categories[f.Category] = struct{}{}
	}

	riskLevel := "LOW"
	if hasHigh {
		riskLevel = "HIGH"
	} else if hasMedium {
		riskLevel = "MEDIUM"
	}

	chained := len(categories) > 1 && (hasHigh || hasMedium)

	var summary string
	switch riskLevel {
	case "HIGH":
		summary = fmt.Sprintf("发现 %d 处高危或恶意风险项，需重点关注", len(findings))
	case "MEDIUM":
		summary = fmt.Sprintf("发现 %d 处中危或可疑风险项，建议人工审查", len(findings))
	default:
		summary = fmt.Sprintf("共 %d 处低风险或良性提示项", len(findings))
	}

	return FileSummary{
		RiskLevel:    riskLevel,
		Summary:      summary,
		Chained:      chained,
		Exfiltration: hasExfil,
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
