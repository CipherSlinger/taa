package codeaudit

import (
	"context"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/CipherSlinger/teellm"
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

		ctxAfter := f.ContextAfter
		if f.CPGEvidence != "" {
			ctxAfter = f.CPGEvidence
		}

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
					ContextAfter:  ctxAfter,
				},
			},
			Policy: teellm.PolicyOptions{
				Mode:        cfg.Policy,
				Temperature: cfg.Temperature,
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
				recalculateGatePassed(report)
				if failedClosed {
					report.Passed = false
				}
			} else {
				recalculateStaticPassed(report)
			}
		} else {
			recalculateGatePassed(report)
		}
	} else {
		recalculateStaticPassed(report)
		if hasInferenceFailure && cfg.FailClosed {
			// In assist mode with fail-closed enabled, if all findings failed inference (e.g. service down or circuit open),
			// block the audit rather than silently passing via static fallback.
			allFailed := len(report.Findings) > 0
			for _, f := range report.Findings {
				if f.LLMVerdict != "" && f.LLMVerdict != "UNCERTAIN" {
					allFailed = false
					break
				}
			}
			if allFailed {
				report.Passed = false
			}
		}
	}

	return report, nil
}

// recomputeReportPassed is the single implementation behind both report-level
// pass decisions. honorExoneration is the only difference between them, and it
// is a real difference rather than two spellings of one rule:
//
//   - honorExoneration true: a static HIGH whose LLM verdict is BENIGN stops
//     blocking. Every other verdict, UNCERTAIN included, leaves it blocking.
//   - honorExoneration false: verdicts are ignored, so any static HIGH blocks.
func recomputeReportPassed(report *Report, honorExoneration bool) {
	highCount := 0
	mediumCount := 0
	for _, f := range report.Findings {
		switch f.Severity {
		case SeverityHigh:
			if honorExoneration && f.LLMVerdict == teellm.VerdictBenign {
				// Exonerated: no longer blocks.
				continue
			}
			highCount++
		case SeverityMedium:
			mediumCount++
		}
	}
	report.HighCount = highCount
	report.MediumCount = mediumCount
	// The completeness precondition is folded in here rather than at the call
	// sites or in the scanner, because this is the one function both policies
	// recompute through. Put anywhere else it would be a rule that a later
	// recalculation could drop: recalculateStaticPassed recomputes Passed from
	// the findings alone, so a check applied before it would be overwritten by
	// the same code that is supposed to preserve it.
	report.Passed = highCount == 0 && report.ProvesCleanScan()
}

// recalculateGatePassed recomputes Report.Passed for the gate policy, honoring
// LLM exoneration. MEDIUM never blocks this value.
//
// It is deliberately not the whole gate decision. AssembleAuditReport copies it
// into ConclusionContext.ScanPassed, and ComputeConclusionContext ANDs it with
// the policy check over the classified statistics (audit.go), which does block
// on MEDIUM. That check is keyed on the classified severity and this one on the
// static severity, so the same word "gate" names two different tests on
// purpose: the AND of them is the decision.
func recalculateGatePassed(report *Report) {
	recomputeReportPassed(report, true)
}

// recalculateStaticPassed recomputes Report.Passed from the static severities
// alone, ignoring every LLM verdict. This is the assist-mode value and it is
// load-bearing rather than vestigial: it is the only thing that blocks a static
// HIGH the LLM downgraded to SUSPICIOUS or BENIGN. Dropping it in favor of the
// classified check would turn those samples into misses; see
// gate_semantics_test.go and models/audit/audit-results/engine-compare/REPORT.md
// section 7.5.
func recalculateStaticPassed(report *Report) {
	recomputeReportPassed(report, false)
}

// CheckImportWithLLM is the high-level gate function that combines
// static scanning with optional LLM verification.
func CheckImportWithLLM(ctx context.Context, dir string, engine StaticEngine, cfg LLMConfig) (bool, *Report, error) {
	if dir == "" {
		return true, nil, nil
	}
	if engine == nil {
		return false, nil, fmt.Errorf("static engine is not configured")
	}

	report, err := engine.ScanDirectory(dir)
	if err != nil {
		return false, nil, err
	}

	// A report that cannot prove both that its scan ran to completion and that
	// it dropped nothing is not evidence of absence, so it must not pass on any
	// of the paths below. The folds inside recomputeReportPassed carry the same
	// precondition, so the recalculations further down cannot restore a pass
	// this clears.
	if !report.ProvesCleanScan() {
		report.Passed = false
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
	// The static scan's original pass/fail is preserved, unless fail-closed has rejected the report.
	if cfg.Policy == "assist" {
		if !(cfg.FailClosed && report.LLMDegraded && !report.Passed) {
			recalculateStaticPassed(report)
		}
	}

	return report.Passed, report, nil
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

// binaryFileAnalysisPromptTemplate is the file-level prompt for a file whose
// content is not source.
//
// It is separate from the source prompt rather than parameterised into it,
// because the two tell the model different things about the same slot. The
// source prompt says "here is Python"; this one says "here is a listing of
// extracted evidence, each line numbered and tagged with where it came from",
// and a model given the first while shown the second answers a question nobody
// asked. The evidence block is a bounded excerpt of the same indexed listing the
// finding-level prompt's context is drawn from, and its numbers are that
// listing's indices: because they come from Finalize, a line the model names by
// number is a line the report carries. The finding-level context renders the
// same lines without the number, so it can name a source and its content but not
// a line.
//
// The listing is an excerpt and the prompt says so: rubric item 4 tells the
// model the listing has a ceiling and that a missing line is not an absent fact,
// and the renderer appends the number of lines it left out. A model that
// believed it had seen everything would treat the absence of a signal as
// evidence of its absence, which is the same mistake the completeness fields in
// the report exist to prevent.
const binaryFileAnalysisPromptTemplate = `你是二进制代码安全审计专家。以下是一个二进制文件的证据清单，请判断它是否包含恶意行为、数据外传或后门。

## 文件信息
文件: %s (类型: %s, 大小: %d 字节, 证据行数: %d)
静态规则命中 (%d 处需确认点): %s

## 证据说明
每一行是一条证据，格式为「序号	[来源] 内容」，来源含义：
- dynsym：该二进制从动态库导入的符号，即它能够调用的能力（stripped 二进制仅存此类证据）
- needed：DT_NEEDED，加载器会载入的依赖库
- strings：从文件中提取的可打印字符串
- section / entropy：节区构成与香农熵；可执行节区熵接近 8 说明代码被压缩或加密，运行前必须先解包
- member：压缩包成员
- pickle：pickle 流要求反序列化器解析的「模块.属性」，加载即执行
- notice：文件自身属性（解释器、格式说明）

## 证据清单（节选）
%s

## 判定基准
1. 模型权重、张量数据、数学库依赖（libc/libm/libstdc++/libgomp）、框架运行库导入属于正常模型包的构成，风险等级为 LOW，chained 与 exfiltration 均为 false。
2. 只有当证据确凿指向未授权的网络外发（socket/connect + 外联库）、命令执行（system/execve/popen）、内存中落地并执行（memfd_create/fexecve）、pickle 反序列化执行（posix.system 等），或可执行节区被加壳时，才判定 risk_level 为 HIGH/MEDIUM，并相应标记 chained 或 exfiltration。
3. 严禁仅凭「导入了某个库」就判定为恶意：一个普通加速库导入 dlopen 或 mmap 是正常的，必须结合证据链判断。
4. 证据清单是有上限的节选；清单未出现某项证据不等于该证据不存在。

## 请严格按以下 JSON 格式输出，不要包含其他内容:
{"risk_level":"HIGH/MEDIUM/LOW","summary":"一句话安全结论(中文)","chained":false,"exfiltration":false}`

// AuditConfig is the configuration of one audit run: the two things an audit can
// be told to do differently.
//
// The binary channel is configured here rather than on the Tier 1 engine because
// it is not part of any engine: it runs for whichever one the deployment chose.
// Putting it on the engine's config would tie binary coverage to the source
// engine selection, which is the coupling the channel exists to avoid.
type AuditConfig struct {
	// LLM configures the Tier 2 verifier.
	LLM LLMConfig
	// Binary configures the binary channel. Enabled false leaves the audit
	// byte-identical to the one produced before the channel existed.
	Binary BinaryConfig
}

// GenerateAuditReport is the high-level entry point that performs a full
// security audit: static scan → finding-level LLM → file-level LLM → aggregate.
func GenerateAuditReport(ctx context.Context, dir string, engine StaticEngine, cfg AuditConfig, client LLMClient) (*AuditReport, error) {
	startTime := time.Now()
	llmCfg := cfg.LLM

	if dir == "" {
		return nil, fmt.Errorf("audit directory is empty")
	}
	// A nil engine is a configuration error, not a scan that finds nothing. Left
	// to the call below it would be a nil interface dereference, which a
	// fail-closed control should never do: it turns a missing configuration into
	// a crash instead of a rejection.
	if engine == nil {
		return nil, fmt.Errorf("static engine is not configured")
	}

	// Phase 1: Static scan with line counts.
	scanReport, lineCounts, err := engine.ScanDirectoryWithLines(dir)
	if err != nil {
		return nil, fmt.Errorf("static scan: %w", err)
	}

	// Phase 1b: the binary channel. It runs after the source scan and before the
	// LLM phases so that the findings it produces are adjudicated by the same
	// verifier, in the same pass, as the source findings - a separate pass would
	// need a second quota and a second failure mode.
	//
	// It returns no error, and that is the point rather than an oversight: see
	// runBinaryChannel. A binary-channel failure is a gap the report records and
	// ProvesCleanScan refuses on, not a second way for the audit to return an
	// error - the caller turns any error into a refusal that skips the report
	// (internal/controller/import_processing.go:651-656), which is the outcome
	// this channel exists to make accurate rather than to make easy.
	binaryRes := runBinaryChannel(dir, cfg.Binary)

	// Phase 1c: merge.
	if binaryRes != nil {
		MergeBinaryFindings(scanReport, binaryRes)
	}

	// Whether the LLM has anything to do here, and whether it can actually do it,
	// are decided once and reused by all three places below. Written out longhand,
	// the degrade decision and the two phase guards are three spellings of one
	// condition, and a later edit to any one of them silently breaks the pairing
	// the rest of this function depends on: marking a run degraded that in fact
	// ran the LLM, or skipping a phase while reporting a full one.
	llmWanted := llmCfg.Enabled && len(scanReport.Findings) > 0
	llmActive := llmWanted && client != nil

	// A deployment that asked for the LLM and got no client has produced a
	// static-only verdict while the report says otherwise. Both phases below are
	// skipped, so nothing downstream can tell this apart from an audit the LLM
	// actually adjudicated — and under fail-closed, skipping the adjudication is
	// the silent allow the policy exists to prevent.
	//
	// llmWanted rather than llmActive is the point: with no findings the LLM would
	// not have been called even if it were reachable — VerifyReport returns early on
	// an empty finding list, and Phase 3 only visits files that produced findings —
	// so calling such a run degraded would be a false statement, and failing it
	// closed a rejection of a package the static scan examined completely.
	if llmWanted && !llmActive {
		if llmCfg.FailClosed {
			return nil, fmt.Errorf("llm enabled with fail-closed but no inference client: %d finding(s) would go unadjudicated",
				len(scanReport.Findings))
		}
		scanReport.LLMDegraded = true
	}

	// Phase 2: Finding-level LLM verification (reuse existing VerifyReport).
	if llmActive {
		scanReport, err = VerifyReport(ctx, scanReport, llmCfg, client)
		if err != nil {
			log.Printf("LLM finding verification failed (non-fatal): %v", err)
		}
	}

	// Phase 3: Group findings by file + file-level LLM analysis.
	fileGroups := GroupFindingsByFile(scanReport.Findings)
	var fileReports []FileReport
	var binaryEvidence map[string]*EvidenceSet
	if binaryRes != nil {
		binaryEvidence = binaryRes.Evidence
	}

	for filePath, findings := range fileGroups {
		fr := BuildFileReport(filePath, findings)

		if llmActive {
			summary := analyzeFileWithLLM(ctx, client, filePath, findings, lineCounts, binaryEvidence)
			fr.RiskLevel = summary.RiskLevel
			fr.Summary = summary.Summary
			fr.Chained = summary.Chained
			fr.HasExfiltrationPattern = summary.Exfiltration
		}

		fileReports = append(fileReports, fr)
	}

	// Phase 4: Assemble the full audit report (Go-side aggregation).
	audit := AssembleAuditReport(dir, scanReport, fileReports, lineCounts, llmCfg, time.Since(startTime))
	return audit, nil
}

// runBinaryChannel runs the binary pass when it is enabled, and returns nil when
// it is not.
//
// Nil rather than an empty result is the signal the rest of the function keys on:
// an empty result would be indistinguishable from a pass that examined a package
// with no binary files in it, and the report's metadata would then claim a
// channel ran that never did.
//
// It deliberately returns no error, and the reason is the caller's failure path
// rather than this function's convenience. GenerateAuditReport's caller turns any
// error into a refusal that skips the report entirely (Task 11a removed the
// package deletion that used to be here; what remains is that the audit returns
// before any report exists), so an error returned here decides the import before
// the report it belongs to exists - with nothing recorded about which file, or
// which channel, or why. A per-file failure is already the scanner's own business:
// it is counted as Incomplete and withholds the pass through ProvesCleanScan. A
// whole-pass failure is recorded the same way, as Errored: the fact travels as
// errored: true in the in-process summary, and the reason - a matcher that would
// not build, or a scan that would not run - travels only in the log line its
// branch below writes, not in anything the report carries.
func runBinaryChannel(dir string, binCfg BinaryConfig) *BinaryScanResult {
	if !binCfg.Enabled {
		return nil
	}
	matcher, err := NewBinaryMatcher()
	if err != nil {
		log.Printf("binary channel: matcher build failed, pass withheld: %v", err)
		return &BinaryScanResult{Summary: BinaryScanSummary{Errored: true}}
	}
	res, err := NewBinaryScanner(matcher, binCfg).ScanDirectory(dir)
	if err != nil {
		log.Printf("binary channel: scan failed, pass withheld: %v", err)
		return &BinaryScanResult{Summary: BinaryScanSummary{Errored: true}}
	}
	return res
}

// analyzeFileWithLLM calls the LLM for a file-level security summary.
//
// A file the binary channel examined takes the binary prompt and the listing the
// channel already produced; everything else takes the source prompt and a read
// of the file. The listing is used rather than re-read from disk for two
// reasons: a binary file read as text is noise, and re-running the extraction
// here would read a possibly-large file a second time on the import path.
//
// Both branches are behind the FileAnalyzer assertion above, and the binary one
// is reachable today only through a client that implements that interface. The
// production client does not: it is teellm.Client (LLMClient above), whose
// interface declares VerifyFinding, HealthCheck and Close and no AnalyzeFile,
// and newLLMClient returns that value unchanged. The only AnalyzeFile
// implementation in the tree is a test mock. So in production a binary file
// falls through to synthesizeFileSummary - which is the same situation the
// source file path has been in all along, so this is not a regression the
// binary channel introduces; the file-level prompt is exercised by the mock
// rather than by the deployed pipeline. This function does not change that, and
// its tests do not claim otherwise.
func analyzeFileWithLLM(ctx context.Context, client LLMClient, filePath string, findings []Finding, lineCounts map[string]int, binaryEvidence map[string]*EvidenceSet) FileSummary {
	fa, ok := client.(FileAnalyzer)
	if !ok {
		// Synthesize a FileSummary from findings when client does not implement FileAnalyzer.
		return synthesizeFileSummary(filePath, findings)
	}

	if ev := binaryEvidence[filePath]; ev != nil {
		return analyzeBinaryFileWithLLM(ctx, fa, ev, findings)
	}

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

// binaryFilePromptMaxLines bounds the excerpt handed to the model. It is a
// separate number from the source prompt's 80 lines because the two budgets
// measure different things. The source budget is whole file lines; this one has
// to hold every reserved structural line - the sections, entropy verdicts and
// DT_NEEDED entries a judgement is built on - and still leave a useful number of
// imports, which dominate the listing at the densities this channel meets: a
// single libstdc++ carries more than two hundred dynamic imports. 120 is the
// budget that fits both. RenderExcerpt guarantees the structural sources are
// reserved ahead of the rest rather than merely sorted first, which is where a
// symbol-dense file would otherwise bury them.
const binaryFilePromptMaxLines = 120

// analyzeBinaryFileWithLLM asks the model about a file the binary channel read.
func analyzeBinaryFileWithLLM(ctx context.Context, fa FileAnalyzer, ev *EvidenceSet, findings []Finding) FileSummary {
	prompt := fmt.Sprintf(binaryFileAnalysisPromptTemplate,
		filepath.Base(ev.File), ev.Kind, ev.Size, len(ev.Lines),
		len(findings), BuildFindingsSummary(findings),
		ev.RenderExcerpt(binaryFilePromptMaxLines),
	)

	result, err := fa.AnalyzeFile(ctx, prompt)
	if err != nil {
		log.Printf("LLM binary file analysis error for %s: %v", filepath.Base(ev.File), err)
		return FileSummary{
			RiskLevel: "UNCERTAIN",
			Summary:   fmt.Sprintf("LLM 分析失败: %v", err),
		}
	}
	return result
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
