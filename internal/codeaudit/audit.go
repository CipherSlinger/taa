package codeaudit

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ── Audit Report Types ────────────────────────────────────

// AuditReport is the comprehensive security audit result for a code directory.
type AuditReport struct {
	ReportID     string          `json:"report_id"`
	AuditTime    string          `json:"audit_time"`
	Target       AuditTarget     `json:"target"`
	Conclusion   AuditConclusion `json:"conclusion"`
	Statistics   AuditStatistics `json:"statistics"`
	FileReports  []FileReport    `json:"file_reports"`
	ScanMetadata AuditMetadata   `json:"scan_metadata"`
	// Roots is the per-root breakdown of the audit, always populated — a
	// single-root audit carries one entry. It sits at the report top level
	// rather than under Target because the platform-facing projections of this
	// report select a few top-level keys, and a verdict nested below one of them
	// would not reach the platform that has to disambiguate a failure.
	Roots []RootReport `json:"roots"`
}

// RootReport is the audit result for one root. A merged report has to let a
// reader tell which root a failure came from without inferring it from the file
// paths inside file_reports, which is the inference that gets a two-root report
// misread.
type RootReport struct {
	Directory     string `json:"directory"`
	FilesScanned  int    `json:"files_scanned"`
	FindingsCount int    `json:"findings_count"`
	// Passed mirrors the audit's own policy verdict for this root: it is the
	// overall conclusion when the overall conclusion passed, and otherwise true
	// only for a root that carries no finding and whose scan ran to completion.
	//
	// It is not simply "no finding under this root". Conclusion.Passed is keyed
	// on the blocking severity, so a root carrying only LOW findings does not
	// fail the audit; a verdict that called that root failed would put
	// passed:false next to a passing code and leave a reader unable to tell
	// whether anything was actually wrong — which defeats the reason the
	// breakdown exists. The scan-completeness term keeps the other direction
	// honest: a truncated scan cannot clear any root, including one whose
	// visible findings happen to be zero, because the finding that would have
	// failed it may be the one that was dropped.
	Passed bool `json:"passed"`
}

// AuditTarget describes what was audited.
type AuditTarget struct {
	Directory         string `json:"directory"`
	FilesScanned      int    `json:"files_scanned"`
	TotalLines        int    `json:"total_lines"`
	FilesWithFindings int    `json:"files_with_findings"`
}

// AuditConclusion is the final audit verdict.
type AuditConclusion struct {
	Passed         bool   `json:"passed"`
	RiskLevel      string `json:"risk_level"` // CRITICAL / HIGH / MEDIUM / LOW / NONE
	Summary        string `json:"summary"`
	Recommendation string `json:"recommendation"`
	Statistics     AuditStatistics `json:"statistics"`
}

// AuditStatistics holds aggregated finding counts classified into high, medium, and low risk by the LLM.
type AuditStatistics struct {
	High         int `json:"high"`
	Medium       int `json:"medium"`
	Low          int `json:"low"`
	CrossFile    int `json:"cross_file,omitempty"`
	Microservice int `json:"microservice,omitempty"`
}

// Total returns the total number of findings across all risk categories.
func (s AuditStatistics) Total() int {
	return s.High + s.Medium + s.Low
}

// FileReport is the analysis result for a single source file.
type FileReport struct {
	File                   string    `json:"file"`
	FilePath               string    `json:"file_path"`
	FindingsCount         int       `json:"findings_count"`
	HighCount             int       `json:"high_count"`
	MediumCount           int       `json:"medium_count"`
	RiskLevel             string    `json:"risk_level"`  // LLM or inferred
	Summary               string    `json:"summary"`     // LLM or inferred
	HasExfiltrationPattern bool     `json:"has_exfiltration_pattern"` // LLM
	Chained               bool      `json:"chained"`     // LLM
	Findings              []Finding `json:"findings"`
}

// AuditMetadata records scan configuration and timing.
type AuditMetadata struct {
	ScannerVersion string `json:"scanner_version"`
	RulesCount     int    `json:"rules_count"`
	LLMModel       string `json:"llm_model"`
	LLMEnabled     bool   `json:"llm_enabled"`
	Policy         string `json:"policy"`
	ScanDurationMs int64  `json:"scan_duration_ms"`
	LLMDegraded    bool   `json:"llm_degraded,omitempty"`

	// Provenance and completeness of the Tier 1 scan. These are copied from the
	// scan report so that the report leaving the process states which engine
	// produced it and whether that scan ran to completion. A passed audit of a
	// truncated or incomplete scan is not the same claim as a passed audit of a
	// complete one, and without these fields the two are indistinguishable to
	// a reader.
	Engine          string `json:"engine"`
	EngineVersion   string `json:"engine_version,omitempty"`
	ScanComplete    bool   `json:"scan_complete"`
	ParserErrors    int    `json:"parser_errors"`
	Truncated       bool   `json:"truncated"`
	UnsupportedExts int    `json:"unsupported_extensions"`
	ProcessExitCode int    `json:"process_exit_code"`

	// ScanProvedClean is ProvesCleanScan()'s verdict, assembled here so that a
	// reader need not re-derive it from the five fields above. It is separate
	// from Conclusion.Passed because the two answer different questions: Passed
	// is the policy verdict on the findings, this is whether the scan that
	// produced them finished. A caller deciding what to do about a failure needs
	// both.
	//
	// It is the completeness verdict alone, not Passed AND the completeness
	// verdict. Folding Passed in would make a scan that finished but found
	// something on one root read as "did not prove a clean scan", which is the
	// distinction the rollback rule turns on: a side that carries no finding of
	// its own must not be rolled back because the other side does. What this
	// withholds is clearing anything on the evidence of a scan that was
	// truncated or otherwise incomplete — there, the findings the scan kept can
	// all fall on the side that is not being judged, so that side looks clean
	// while the input it did not reach is invisible.
	ScanProvedClean bool `json:"scan_proved_clean"`
}

// FileSummary is the LLM response for file-level analysis.
type FileSummary struct {
	RiskLevel    string `json:"risk_level"`
	Summary      string `json:"summary"`
	Chained      bool   `json:"chained"`
	Exfiltration bool   `json:"exfiltration"`
}

// ── Rule suggestion map ───────────────────────────────────

// ruleSuggestionMap provides fix suggestions keyed by rule ID.
// Hardcoded in Go (not generated by LLM) for reliability.
var ruleSuggestionMap = map[string]string{
	"NET_001": "移除网络请求，或限制为仅发送模型指标",
	"NET_002": "移除原始 Socket 连接",
	"CMD_001": "移除子进程调用，使用安全的替代方案",
	"OBF_001": "移除编码/反序列化操作，使用安全的替代方案",
	"DYN_001": "移除 eval/exec，使用安全的替代方案",
	"FIL_001": "移除敏感文件读取",
	"ENV_001": "使用配置文件替代环境变量读取",
	"PER_001": "移除持久化机制",
	"EXF_001": "移除数据编码和发送操作",
	"EMB_001": "不要将原始数据写入输出文件",
	"EMB_002": "不要将数据复制到输出目录",
	"EMB_003": "避免在日志中打印原始数据",
	"EMB_004": "不要将数据编码后嵌入模型权重",
}

// SuggestionForRule returns the fix suggestion for a given rule ID.
func SuggestionForRule(ruleID string) string {
	if s, ok := ruleSuggestionMap[ruleID]; ok {
		return s
	}
	return "审查该代码片段并确认其安全性"
}

// ── Core aggregation functions ────────────────────────────

// GroupFindingsByFile groups findings by their file path.
func GroupFindingsByFile(findings []Finding) map[string][]Finding {
	groups := make(map[string][]Finding)
	for _, f := range findings {
		groups[f.File] = append(groups[f.File], f)
	}
	return groups
}

// BuildFileReport constructs a FileReport from findings (Go-computed fields only).
// LLM fields (RiskLevel, Summary, Chained, HasExfiltrationPattern) are left empty
// and should be filled by analyzeFileWithLLM.
func BuildFileReport(filePath string, findings []Finding) FileReport {
	highCount := 0
	mediumCount := 0
	for _, f := range findings {
		switch f.Severity {
		case SeverityHigh:
			highCount++
		case SeverityMedium:
			mediumCount++
		}
	}

	fr := FileReport{
		File:            filepath.Base(filePath),
		FilePath:        filePath,
		FindingsCount:  len(findings),
		HighCount:      highCount,
		MediumCount:    mediumCount,
		Findings:       findings,
	}

	// If no LLM, infer risk level from static data.
	fr.RiskLevel = InferRiskLevel(highCount, mediumCount)
	fr.Summary = "仅静态扫描，未进行语义分析"

	return fr
}

// InferRiskLevel determines risk level from static finding counts.
func InferRiskLevel(highCount, mediumCount int) string {
	if highCount > 0 {
		return "HIGH"
	}
	if mediumCount > 0 {
		return "MEDIUM"
	}
	return "LOW"
}

// isTestFile returns true if the file path indicates a test script, helper, or fixture.
func isTestFile(path string) bool {
	if path == "" {
		return false
	}
	base := strings.ToLower(filepath.Base(path))
	if strings.HasPrefix(base, "test_") || strings.HasSuffix(base, "_test.py") || strings.HasSuffix(base, "_test.go") {
		return true
	}
	cleaned := filepath.ToSlash(strings.ToLower(path))
	if strings.Contains(cleaned, "/tests/") || strings.Contains(cleaned, "/test/") ||
		strings.HasPrefix(cleaned, "tests/") || strings.HasPrefix(cleaned, "test/") {
		return true
	}
	return false
}

// ClassifyFindingRisk determines the final risk level (HIGH, MEDIUM, LOW) of a finding,
// prioritized by the LLM's evaluation and falling back to static scan severity.
func ClassifyFindingRisk(f Finding) string {
	switch strings.ToUpper(strings.TrimSpace(f.LLMRisk)) {
	case "HIGH", "CRITICAL":
		return "HIGH"
	case "MEDIUM":
		return "MEDIUM"
	case "LOW", "NONE":
		return "LOW"
	}

	switch strings.ToUpper(strings.TrimSpace(f.LLMVerdict)) {
	case "MALICIOUS":
		return "HIGH"
	case "SUSPICIOUS":
		return "MEDIUM"
	case "BENIGN":
		return "LOW"
	case "UNCERTAIN":
		if f.Severity == SeverityHigh {
			return "HIGH"
		}
		// Benign metadata logging or findings located in test fixtures are downgraded to LOW when uncertain.
		if f.RuleID == "EMB_003" || isTestFile(f.File) {
			return "LOW"
		}
		return "MEDIUM"
	}

	switch f.Severity {
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		// Benign metadata logging or findings located in test fixtures are downgraded to LOW in static fallback.
		if f.RuleID == "EMB_003" || isTestFile(f.File) {
			return "LOW"
		}
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// ComputeStatistics aggregates finding counts categorized into high, medium, low by LLM evaluation.
func ComputeStatistics(findings []Finding) AuditStatistics {
	stats := AuditStatistics{}
	for _, f := range findings {
		switch ClassifyFindingRisk(f) {
		case "HIGH":
			stats.High++
		case "MEDIUM":
			stats.Medium++
		case "LOW":
			stats.Low++
		}
		if f.IsCrossFile {
			stats.CrossFile++
		}
		if f.IsMicroservice {
			stats.Microservice++
		}
	}
	return stats
}

// ConclusionContext carries additional audit context for conclusion generation.
type ConclusionContext struct {
	LLMDegraded  bool
	HasLLMBenign bool
	ScanPassed   *bool
	FailClosed   bool
}

// ComputeConclusion determines the audit conclusion from statistics and policy.
// Retained for backward compatibility.
func ComputeConclusion(stats AuditStatistics, fileReports []FileReport, policy string) AuditConclusion {
	return ComputeConclusionContext(stats, fileReports, policy, ConclusionContext{
		HasLLMBenign: true,
	})
}

// ComputeConclusionContext determines the audit conclusion from statistics, policy, and scan context.
func ComputeConclusionContext(stats AuditStatistics, fileReports []FileReport, policy string, ctx ConclusionContext) AuditConclusion {
	riskLevel := "NONE"

	if stats.High > 0 {
		riskLevel = "CRITICAL"
	} else if stats.Medium > 0 {
		riskLevel = "MEDIUM"
	} else if stats.Low > 0 {
		riskLevel = "LOW"
	}

	var passed bool
	switch policy {
	case "gate":
		// Gate mode: block on High and Medium risk findings. Low (benign) findings pass.
		passed = stats.High == 0 && stats.Medium == 0
	default:
		// Assist mode (default): block on High risk findings.
		passed = stats.High == 0
	}

	if ctx.ScanPassed != nil && !*ctx.ScanPassed {
		passed = false
	}

	summary := buildSummaryTextExt(stats, riskLevel, passed, ctx.LLMDegraded, ctx.HasLLMBenign)
	recommendation := buildRecommendation(fileReports)

	return AuditConclusion{
		Passed:         passed,
		RiskLevel:      riskLevel,
		Summary:        summary,
		Recommendation: recommendation,
		Statistics:     stats,
	}
}

// ── Report assembly ───────────────────────────────────────

// AssembleAuditReport combines all components into the final AuditReport.
func AssembleAuditReport(
	dir string,
	scanReport *Report,
	fileReports []FileReport,
	fileLineCounts map[string]int,
	cfg LLMConfig,
	duration time.Duration,
) *AuditReport {
	stats := ComputeStatistics(scanReport.Findings)

	// Sort file reports: HIGH risk first, then by findings count.
	sort.Slice(fileReports, func(i, j int) bool {
		ri, rj := riskOrder(fileReports[i].RiskLevel), riskOrder(fileReports[j].RiskLevel)
		if ri != rj {
			return ri < rj // lower order = higher risk, comes first
		}
		return fileReports[i].FindingsCount > fileReports[j].FindingsCount
	})

	var hasLLMBenign bool
	var scanPassed *bool
	var scanProvedClean bool
	var llmDegraded bool
	if scanReport != nil {
		// ScanPassed is the channel that forces failure under both policies, so
		// it carries the completeness precondition as well as the finding-based
		// decision. Without it a scan that dropped findings, or never finished,
		// would reach ComputeConclusionContext as a pass and the only trace of
		// the unexamined input would be a metadata field nobody reads.
		sp := scanReport.Passed && scanReport.ProvesCleanScan()
		scanPassed = &sp
		// ScanProvedClean is the completeness verdict alone: whether the scan
		// looked, not whether what it found blocks. See the field's comment.
		scanProvedClean = scanReport.ProvesCleanScan()
		llmDegraded = scanReport.LLMDegraded
		for _, f := range scanReport.Findings {
			if strings.EqualFold(strings.TrimSpace(f.LLMVerdict), "BENIGN") {
				hasLLMBenign = true
				break
			}
		}
	}

	conclusion := ComputeConclusionContext(stats, fileReports, cfg.Policy, ConclusionContext{
		LLMDegraded:  llmDegraded,
		HasLLMBenign: hasLLMBenign,
		ScanPassed:   scanPassed,
		FailClosed:   cfg.FailClosed,
	})

	totalLines := 0
	for _, count := range fileLineCounts {
		totalLines += count
	}

	// Provenance and completeness travel with the report, so that a reader can
	// tell a complete scan from a partial one without treating the absence of
	// evidence as evidence of absence.
	var (
		engine          string
		engineVersion   string
		scanComplete    bool
		parserErrors    int
		truncated       bool
		unsupportedExts int
		processExitCode int
	)
	if scanReport != nil {
		engine = scanReport.Engine
		engineVersion = scanReport.EngineVersion
		scanComplete = scanReport.ScanComplete
		parserErrors = scanReport.ParserErrors
		truncated = scanReport.Truncated
		unsupportedExts = scanReport.UnsupportedExts
		processExitCode = scanReport.ProcessExitCode
	}

	return &AuditReport{
		ReportID:  GenerateReportID(),
		AuditTime: time.Now().Format(time.RFC3339),
		Target: AuditTarget{
			Directory:         dir,
			FilesScanned:      scanReport.FilesCount,
			TotalLines:        totalLines,
			FilesWithFindings: len(fileReports),
		},
		Conclusion:  conclusion,
		Statistics:  stats,
		FileReports: fileReports,
		Roots:       buildRootReports(reportRoots(dir, scanReport), scanReport, fileLineCounts, conclusion.Passed, scanProvedClean),
		ScanMetadata: AuditMetadata{
			ScannerVersion: "1.0.0",
			RulesCount:     len(DefaultRules()),
			LLMModel:       cfg.Model,
			LLMEnabled:     cfg.Enabled,
			Policy:         cfg.Policy,
			ScanDurationMs: duration.Milliseconds(),
			LLMDegraded:    scanReport != nil && scanReport.LLMDegraded,

			Engine:          engine,
			EngineVersion:   engineVersion,
			ScanComplete:    scanComplete,
			ParserErrors:    parserErrors,
			Truncated:       truncated,
			UnsupportedExts: unsupportedExts,
			ProcessExitCode: processExitCode,
			ScanProvedClean: scanProvedClean,
		},
	}
}

// reportRoots is the root list a report's per-root breakdown is built from: the
// scan's own list when it was a merged scan, and the single audit directory
// otherwise. The single-root fallback is why a caller that passed one directory
// still gets one RootReport rather than an empty list — the breakdown is always
// populated so that "no roots" can never be read as "this report cannot say what
// it covered".
func reportRoots(dir string, scanReport *Report) []string {
	if scanReport != nil && len(scanReport.Directories) > 0 {
		return scanReport.Directories
	}
	return []string{dir}
}

// buildRootReports attributes the scan's files and findings to each root.
//
// The attribution runs through ScanRoots so that the longest-match and
// separator rules are the same ones ReportHasFindingsUnder uses; two different
// answers to "is this finding under that root" would make the breakdown and the
// rollback decision disagree about the same report.
//
// A root's Passed is the audit's own policy verdict when that verdict passed,
// and otherwise a per-root check: no finding under the root and a scan that ran
// to completion. Both terms earn their place. Conclusion.Passed is keyed on the
// blocking severity, so under the default assist policy a root carrying only LOW
// findings does not fail the audit, and the breakdown has to say so rather than
// report passed:false beside a passing code. The completeness term is what keeps
// a root from being cleared by a scan that did not finish: a truncated scan
// drops findings, and the finding that would have failed a root may be exactly
// the one that was dropped, so no root can be declared passed on its evidence.
func buildRootReports(roots []string, scanReport *Report, lineCounts map[string]int, conclusionPassed, scanProvedClean bool) []RootReport {
	var findings []Finding
	if scanReport != nil {
		findings = scanReport.Findings
	}

	sr := NewScanRoots(roots)
	reports := make([]RootReport, 0, len(roots))
	for _, root := range roots {
		rr := RootReport{Directory: root}
		cleanRoot := cleanAbs(root)

		for path := range lineCounts {
			if got, ok := sr.RootOf(path); ok && got == cleanRoot {
				rr.FilesScanned++
			}
		}
		for _, f := range findings {
			if got, ok := sr.RootOf(f.File); ok && got == cleanRoot {
				rr.FindingsCount++
			}
		}

		rr.Passed = conclusionPassed || (scanProvedClean && rr.FindingsCount == 0)
		reports = append(reports, rr)
	}
	return reports
}

// ── Helper functions ──────────────────────────────────────

// GenerateReportID creates a unique audit report identifier.
func GenerateReportID() string {
	ts := time.Now().Format("20060102-150405")
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return fmt.Sprintf("audit-%s-%x", ts, b)
}

// BuildFindingsSummary creates a compact summary of findings for the LLM prompt.
// e.g. "NET_001(网络请求,HIGH), CMD_001(命令执行,HIGH)"
func BuildFindingsSummary(findings []Finding) string {
	if len(findings) == 0 {
		return "无"
	}
	parts := make([]string, 0, len(findings))
	seen := make(map[string]bool)
	for _, f := range findings {
		key := f.RuleID
		if seen[key] {
			continue
		}
		seen[key] = true
		parts = append(parts, fmt.Sprintf("%s(%s,%s)", f.RuleID, f.Category, f.Severity))
	}
	return strings.Join(parts, ", ")
}

// ReadFileForAnalysis reads a source file and returns up to maxLines lines.
func ReadFileForAnalysis(path string, maxLines int) string {
	f, err := os.Open(path)
	if err != nil {
		return "// 无法读取文件"
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() && len(lines) < maxLines {
		lines = append(lines, scanner.Text())
	}

	if len(lines) == 0 {
		return "// 文件为空"
	}

	code := strings.Join(lines, "\n")
	if scanner.Scan() {
		// More lines exist — add truncation notice.
		code += fmt.Sprintf("\n// ... (截断，文件超过 %d 行)", maxLines)
	}
	return code
}

// CountFileLines returns the number of lines in a file.
func CountFileLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		count++
	}
	return count
}

// ── Internal helpers ──────────────────────────────────────

func buildSummaryText(stats AuditStatistics, riskLevel string) string {
	passed := riskLevel != "CRITICAL" && riskLevel != "HIGH"
	return buildSummaryTextExt(stats, riskLevel, passed, false, true)
}

func buildSummaryTextExt(stats AuditStatistics, riskLevel string, passed bool, llmDegraded bool, hasLLMBenign bool) string {
	if stats.Total() == 0 {
		return "未发现安全问题，代码通过审计"
	}

	parts := []string{}
	if stats.High > 0 {
		parts = append(parts, fmt.Sprintf("发现 %d 处高危风险代码", stats.High))
	}
	if stats.Medium > 0 {
		parts = append(parts, fmt.Sprintf("发现 %d 处中危风险代码", stats.Medium))
	}
	if stats.Low > 0 {
		if len(parts) > 0 {
			parts = append(parts, fmt.Sprintf("%d 处低危/良性提示项", stats.Low))
		} else if llmDegraded {
			parts = append(parts, fmt.Sprintf("发现 %d 处低危/良性提示项（大模型服务降级，按规则评估）", stats.Low))
		} else if hasLLMBenign {
			parts = append(parts, fmt.Sprintf("发现 %d 处低危/良性提示项（大模型确认为正常）", stats.Low))
		} else {
			parts = append(parts, fmt.Sprintf("发现 %d 处低危/良性提示项", stats.Low))
		}
	}

	if len(parts) == 0 {
		return fmt.Sprintf("发现 %d 处安全提示项", stats.Total())
	}

	summary := "审计结论: " + strings.Join(parts, "，")

	if !passed {
		if riskLevel == "CRITICAL" || riskLevel == "HIGH" {
			summary += "。存在数据泄露风险，建议阻断导入"
		} else {
			summary += "。触发 fail-closed 阻断策略，禁止导入"
		}
	} else if riskLevel == "CRITICAL" || riskLevel == "HIGH" {
		summary += "。存在数据泄露风险，建议阻断导入"
	} else if riskLevel == "LOW" || riskLevel == "NONE" {
		summary += "。代码符合安全规范，准予导入"
	}
	return summary
}

func buildRecommendation(fileReports []FileReport) string {
	// Collect unique rule IDs from high/medium risk findings.
	ruleIDs := make(map[string]bool)
	for _, fr := range fileReports {
		for _, f := range fr.Findings {
			risk := ClassifyFindingRisk(f)
			if risk == "HIGH" || risk == "MEDIUM" {
				ruleIDs[f.RuleID] = true
			}
		}
	}

	if len(ruleIDs) == 0 {
		return "无需修复"
	}

	var suggestions []string
	for ruleID := range ruleIDs {
		s := SuggestionForRule(ruleID)
		suggestions = append(suggestions, fmt.Sprintf("%s: %s", ruleID, s))
	}
	sort.Strings(suggestions)

	return "建议修复: " + strings.Join(suggestions, "; ")
}

func riskOrder(level string) int {
	switch level {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	case "NONE":
		return 4
	default:
		return 5
	}
}
