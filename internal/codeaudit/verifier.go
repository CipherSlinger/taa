package codeaudit

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"
)

const analysisPromptTemplate = `你是一个代码安全审计专家。请分析以下代码片段是否存在窃取数据、外传数据或其他恶意行为。

## 代码片段
文件: %s (第 %d 行)
` + "```python" + `
%s
>>> %s   ← 触发规则的代码
%s
` + "```" + `

## 触发的规则
规则ID: %s
类别: %s
严重度: %s
规则说明: %s

## 判定优先级
1. 只有在上下文表明读取的是密钥、令牌、密码、证书、私钥、敏感文件或外传/持久化载荷时，才判为 MALICIOUS 或 SUSPICIOUS。
2. 如果只是正常配置读取、训练参数、日志统计、报告导出、路径封装或框架常见 API 的良性用法，判为 BENIGN。
3. 如果证据不足、上下文不完整或语义无法确认，必须返回 UNCERTAIN。

## 请回答
1. verdict: MALICIOUS(恶意) / SUSPICIOUS(可疑) / BENIGN(正常) / UNCERTAIN(不确定)
2. reason: 一句话说明理由（中文）
3. risk: 如果恶意，数据会怎样被利用

请严格按以下 JSON 格式回答，不要包含其他内容:
{"verdict": "...", "reason": "...", "risk": "..."}
`

// buildPrompt constructs the LLM prompt for a single finding.
func buildPrompt(f Finding) string {
	return fmt.Sprintf(analysisPromptTemplate,
		f.File, f.Line,
		f.ContextBefore, f.CodeSnippet, f.ContextAfter,
		f.RuleID, f.Category, f.Severity, f.Description,
	)
}

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

	for i := 0; i < limit; i++ {
		f := &report.Findings[i]
		prompt := buildPrompt(*f)

		decision, err := client.VerifyFinding(ctx, prompt)
		if err != nil {
			log.Printf("LLM verifier error for %s:%d [%s]: %v", f.File, f.Line, f.RuleID, err)
			f.LLMVerdict = "UNCERTAIN"
			f.LLMReason = fmt.Sprintf("LLM 调用失败: %v", err)
			continue
		}

		f.LLMVerdict = decision.Verdict
		f.LLMReason = decision.Reason
		f.LLMRisk = decision.Risk
	}

	// Recalculate pass/fail based on policy.
	if cfg.Policy == "gate" {
		recalculatePassed(report)
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
			if f.LLMVerdict == "BENIGN" {
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

	var client LLMClient
	if cfg.Endpoint != "" {
		client = NewOllamaClient(cfg.Endpoint, cfg.Model, cfg.Timeout)
	} else {
		return report.Passed, report, nil
	}

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

const fileAnalysisPromptTemplate = `分析此 Python 文件的安全性。

文件: %s (%d 行)
发现 %d 个可疑点: %s

` + "```python" + `
%s
` + "```" + `

判断:
1. risk_level: HIGH/MEDIUM/LOW
2. summary: 一句话安全结论(中文)
3. chained: 多个可疑点是否构成攻击链(true/false)
4. exfiltration: 是否有数据外传(true/false)

严格按 JSON 回答:
{"risk_level":"...","summary":"...","chained":true,"exfiltration":true}`

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
			// We don't have a Suggestion field on Finding yet, but the
			// ruleSuggestionMap is available for consumers via SuggestionForRule.
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

	result, err := client.AnalyzeFile(ctx, prompt)
	if err != nil {
		log.Printf("LLM file analysis error for %s: %v", filepath.Base(filePath), err)
		return FileSummary{
			RiskLevel: "UNCERTAIN",
			Summary:   fmt.Sprintf("LLM 分析失败: %v", err),
		}
	}
	return result
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
