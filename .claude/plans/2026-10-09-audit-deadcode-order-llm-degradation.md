# 修复代码审计链路的三条缺陷（死代码 / 报告顺序不确定 / LLM 降级不可辨）

**日期**：2026-10-09
**范围**：`internal/codeaudit`（+ 测试）。不动平台载荷契约、不动结论文案。

## Context

对现有代码审计链路（`GenerateAuditReport`：静态扫描 → finding 级 LLM → 文件级 LLM → 汇总）做整体步骤审查后，确认了三条独立的缺陷。它们都不改变"扫描是否发现恶意代码"这层语义，但各自让报告或代码本身变得不可信：

1. **#6 死代码**：`verifier.go:356-359` 有一段注释声称"Enrich findings with suggestions"的循环，实际是恒等 no-op——`firstNonEmpty(x, "")` 返回 `x` 本身，而 `Finding`（`rules.go:25-57`）**根本没有建议字段**，这段"补建议"从未有落点。它让读者以为 finding 带了修复建议。
2. **#7 报告顺序不确定**：`file_reports` 的输入顺序来自 map 迭代（`verifier.go:353`），排序用非稳定的 `sort.Slice` 且无最终 tie-break（`audit.go:336-343`）→ 同 `(risk_level, findings_count)` 的文件每次运行顺序可能不同，同一份代码两次审计的报告字节不同。本仓对"报告可比较"有明确要求（见 `cpg_analysis.go:226-230` 的 `sortFindings` 注释）。
3. **#5 LLM 降级不可辨**：`cfg.Enabled==true` 但 `client==nil`（endpoint 为空或构造失败）时 Phase 2/3 全被跳过，报告却仍写 `LLMEnabled=true`、`LLMDegraded=false`——**纯静态结论与"LLM 参与过"不可区分**。在 `FailClosed` 下这是一条静默放行路径，这正是本次要堵的洞。

   **（2026-10-09 复核更正）** 本条初稿还声称"`models/audit/tools/gate_rescore.py:191` 用 `scan_metadata.llm_enabled` 判定，会被这个假字段误导"。这条论据**不成立**：全树 `grep` 确认 Go 侧只在测试里**读** `audit_report.json`（`audit_test.go:596`、`corpus_parity_test.go:192`、`gate_semantics_production_test.go:149`），从不写；该文件由 Python 基准工具链自己产出（`audit_benchmark_eval.py` 写入 `llm_enabled=(llm_backend != "none")`）。且 `models/` 下**零处**读取 `llm_degraded`。

   不过 `gate_rescore.py:185-191` 的注释恰好写着同一个担忧——"没有模型时报告里的 level 只是静态占位（`infer_risk_level`），把它当作文件级风险会让静态 HIGH 看起来像被检出的攻击链"——说明这两套代码共享同一个语义盲点，只是今天不交换该字段。值得日后对齐（把 Python 侧判据改为 `llm_enabled and not llm_degraded`，或在 `audit.go:415` 注明两种含义），但**不构成本次改动的理由**。

## 决定

| 项 | 决定 |
| :--- | :--- |
| #6 修法 | **删除** `verifier.go:356-359` 的循环与仅此一处调用的 `firstNonEmpty`（`verifier.go:468`）。规则级修复建议已由 `buildRecommendation`（`audit.go:553`）+ `SuggestionForRule` 在结论层聚合，per-finding 重复无意义。符合本仓"不留死代码"惯例 |
| #7 修法 | 抽出具名函数 `sortFileReports`，比较器补 **`FilePath` 字典序升序**作最终 tie-break，使顺序全序、与输入顺序无关。用 `FilePath` 而非 `File`：后者是 basename，不同目录的同名文件会撞 |
| #5 修法 | 扫描后判定 `cfg.Enabled && client == nil && len(scanReport.Findings) > 0`；`FailClosed` 时返回 error，否则置 `scanReport.LLMDegraded = true` |
| #5 门槛为何要 `len(Findings) > 0` | 0 finding 时 LLM 即使可用也不会被调用（`VerifyReport` 在空 finding 早返回；Phase 3 只遍历有 finding 的文件），此时标"降级"是**假陈述**、拒绝是**新增误拦** |
| `LLMEnabled` 语义 | **不变**（= 部署要求了 LLM）；"是否真的跑了"由 `LLMDegraded` 表达。两者配对才构成完整陈述 |
| 不做的 | 不把 `scan_metadata` / `llm_degraded` 加进上报 JSON（平台载荷契约，另有契约测试钉住）；不改 `conclusion.summary` 文案（有 3 处测试钉死）。见"后续项" |

## 改动

### #6 `internal/codeaudit/verifier.go`

删除 `GenerateAuditReport` Phase 3 中的：

```go
// Enrich findings with suggestions (Go-side, not LLM).
for i := range fr.Findings {
    fr.Findings[i].LLMRisk = firstNonEmpty(fr.Findings[i].LLMRisk, "")
}
```

并删除文件末尾的 `firstNonEmpty`（`:468-475`）。全仓库确认只有这一个调用点（无测试、无其它包；函数包私有）。

### #7 `internal/codeaudit/audit.go`

把 `AssembleAuditReport` 内的匿名 `sort.Slice` 换成具名函数，风格对齐 `cpg_analysis.go:231` 的 `sortFindings`：

```go
// sortFileReports orders the file reports for the report that leaves the process:
// highest risk first, then most findings, then path.
//
// The order has to be total, not merely plausible. The reports arrive from a map
// iteration in GenerateAuditReport, so a comparator that leaves ties unresolved
// hands the run's ordering back to the map seed, and two audits of the same code
// emit file_reports in different orders. Anyone diffing, hashing or eyeballing two
// reports is then reading noise.
//
// The final key is FilePath rather than File: File is a base name, and two files
// in different directories — src/model.py and tests/model.py — would collide on
// it, leaving exactly the tie this key exists to break.
func sortFileReports(fileReports []FileReport) {
	sort.Slice(fileReports, func(i, j int) bool {
		ri, rj := riskOrder(fileReports[i].RiskLevel), riskOrder(fileReports[j].RiskLevel)
		if ri != rj {
			return ri < rj // lower order = higher risk, comes first
		}
		if fileReports[i].FindingsCount != fileReports[j].FindingsCount {
			return fileReports[i].FindingsCount > fileReports[j].FindingsCount
		}
		return fileReports[i].FilePath < fileReports[j].FilePath
	})
}
```

调用点 `audit.go:337` 改为 `sortFileReports(fileReports)`。

### #5 `internal/codeaudit/verifier.go`

在 Phase 1 之后、Phase 2 之前：

```go
llmWanted := cfg.Enabled && len(scanReport.Findings) > 0
llmActive := llmWanted && client != nil

if llmWanted && !llmActive {
	if cfg.FailClosed {
		return nil, fmt.Errorf("llm enabled with fail-closed but no inference client: %d finding(s) would go unadjudicated",
			len(scanReport.Findings))
	}
	scanReport.LLMDegraded = true
}

// Phase 2 与 Phase 3 的守卫一并改用 llmActive
```

判据抽成 `llmWanted` / `llmActive` 两个变量（初稿是三处各自展开写），否则"判定降级"与"是否真的跑了 Phase 2/3"是同一个条件的三种拼法，任一处日后被改动都会静默破坏二者的配对。

Phase 3 的守卫本可保持 `cfg.Enabled && client != nil`（循环体只在有 finding 的文件组上执行，`len > 0` 条件是空转的），一并改用 `llmActive` 是为可读性，行为不变。

`CheckImportWithLLM`（`verifier.go:247-254`）已有"client 构造失败 + FailClosed → 返回 error"的先例，本次与之对齐，不引入新的哨兵错误类型。

**这一改动的真实行为变化**（值得写进提交信息）：`Enabled=true` 且 `NewInferenceClient` 构造失败但 endpoint 本身可达时，控制器的探活（`import_processing.go:760-772` 的 `llmAvailable` 回退）会放行到 `GenerateAuditReport`，此时 `client==nil`——旧行为是静默纯静态通过，新行为是 `FailClosed` 下阻断。这正是本次要堵的洞。

`LLMDegraded` 经 `audit.go:356` → `ConclusionContext` → 结论文案，以及 `audit.go:418` → `AuditMetadata`，无需额外接线。

## 测试

三个改动此前都**零覆盖**（`AuditMetadata.LLMEnabled`/`LLMDegraded` 全仓无断言），故每个都补测试，注释按本仓风格说明"为什么这个字段重要"（参照 `failclosed_test.go` / `report_fields_test.go`）。

| 改动 | 测试 | 断言要点 |
| :--- | :--- | :--- |
| #5 | `TestAuditWithoutAClientIsRejectedUnderFailClosed` | `Enabled=true, client=nil, 有 finding, FailClosed=true` → 返回 error 且 report 为 nil |
| #5 | `TestAuditWithoutAClientIsMarkedDegraded` | 同上但 `FailClosed=false` → 无 error；`ScanMetadata.LLMEnabled==true` 且 `ScanMetadata.LLMDegraded==true` |
| #5 | `TestAuditWithNothingToAdjudicateIsNotDegraded` | `Enabled=true, client=nil, 0 finding` → 无 error 且 `LLMDegraded==false`（钉住"仅在有活可干时才算降级"） |
| #7 | `TestFileReportOrderIsTotalAndRunIndependent` | 构造多个 `(risk_level, findings_count)` 完全相同的 FileReport，用不同排列多次调用 `AssembleAuditReport`，断言 `FilePath` 顺序一致且与输入顺序无关 |
| #6 | 无需新测试 | 删除的是 no-op，行为不变；已有 `TestSuggestionForRule`（`audit_test.go:215`）继续覆盖结论层建议 |

## 验证

本仓 `go test ./...` 不可用（`models/audit/holdout-sources/` 有伪装成 `.go` 的 semgrep YAML 且无 `go.mod`），一律按包、`-p 1`：

```
go build ./cmd/taa && go build ./tools/platform-mock/cmd/platform-mock
go vet ./cmd/... ./internal/... ./pkg/... ./tools/...
go test -p 1 ./internal/codeaudit/...      # 含 cpg 子包
go test -p 1 ./internal/controller/...     # 注意既有的 TestConcurrency_DataImportAllowedWhileAuditing flake
go test -p 1 ./internal/app/taa/... ./internal/config/...
```

前端与平台载荷不变，platform-mock 无需改动。

## 落地结果（2026-10-09）

严格 TDD：先写测试 → 逐条确认以预期原因失败 → 再写实现 → 转绿。

RED 证据（实现前）：

- `TestAuditWithoutAClientIsRejectedUnderFailClosed`：返回了 report 而非 error。
- `TestAuditWithoutAClientIsMarkedDegraded`：`LLMDegraded = false`，一个有 finding 的纯静态审计被标成 LLM 参与过。
- `TestFileReportOrderIsTotalAndRunIndependent`：输入排列 `[2 1 0]` / `[1 2 0]` / `[2 0 1]` 三者各自原样输出，第 1 个排列恰好通过 —— 正说明并列项未定序，顺序完全由输入决定。

`TestAuditWithNothingToAdjudicateIsNotDegraded` 是唯一写完后立刻通过的测试，故额外用"去掉 `len(Findings) > 0` 门槛"的朴素实现验证其判别力：该版本确实失败，且报错文案自相矛盾（`0 finding(s) would go unadjudicated`）。补上门槛后转绿。该测试因此确有约束力，不是恒真断言。

`TestAuditWithoutAClientIsRejectedUnderFailClosed` 额外断言错误文案含 `client`，避免测试退化成"只要报错就行"。

验证结果：

| 项 | 结果 |
| :--- | :--- |
| `go build ./cmd/taa` / `go build ./tools/platform-mock/cmd/platform-mock` | OK |
| `go vet ./cmd/... ./internal/... ./pkg/... ./tools/...` | 无输出 |
| `go test -p 1 ./internal/codeaudit/...` | ok（46.0s）+ `codeaudit/cpg` ok（4.1s） |
| `go test -p 1 ./internal/controller/...` | ok（18.7s，本次未触发既有 flake） |
| `go test -p 1 ./internal/app/taa/... ./internal/config/...` | ok |
| `grep -rn firstNonEmpty --include='*.go' .` | 零命中 |

注：构建时若用 `go build ./cmd/taa`（不带 `-o`）会在仓库根落下二进制，需按 CLAUDE.md 用 `-o bin/taa`。

### 独立评审的两条结论

设计另经一次独立评审（只读，核对全部相关调用点）。两条被采纳：

- **`llmWanted` / `llmActive` 谓词抽取**（见"改动"节）——评审指出降级判据与 Phase 守卫是三处重复拼写，存在漂移风险。已按此重构，重构后全量测试仍绿。
- **`gate_rescore.py` 论据更正**（见 Context #3）——初稿的论据不成立，已删改。

两条被**明确判定超出范围**、只记录不改：

- 让结论文案在 `stats.Low == 0` 时也提及降级（`buildSummaryTextExt`）。用户已决定本次不改结论文案，且该处有 3 处测试钉死。
- 控制器探活改为 finding-aware。评审确认探活的 finding-agnostic 行为**被既有测试钉住**：`TestAuditAndReportModelImportFailClosed`（`audit_model_import_test.go:229-273`）用 0 finding 的干净模型目录 + 宕机 endpoint + `FailClosed` 断言 `code == 2`；若改由库层判定，新 #5 门槛会看到 0 finding 而放行，该测试即失败。`TestPhase1ModelAuditFailureAbortsTraining/fail-closed aborts training`（`import_flow_new_test.go:155-180`）同理。故探活**必须**保持 finding-agnostic，二者的宽严差异是有意为之。

## 后续项（本次不做，仅记录）

1. **`scan_metadata` 不上报**：`projectCodeAuditSection`（`internal/controller/codeaudit_projection.go:29-32`）只发 `{conclusion, file_reports}`，故 `Engine` / `ScanComplete` / `Truncated` / `llm_enabled` / `llm_degraded` 这些"报告自证来源与完整性"的字段**在控制台上报路径上全部被丢弃**，且有契约测试钉住（`import_processing_report_test.go:109-120`）。这与 `audit.go:82-94`、`rules.go:107-135` 里"溯源随报告同行"的立场相矛盾，是既有缺口。Python 证据工具链（`models/audit/tools/gate_rescore.py:191` 等）读的是全量 audit_report.json，不受影响。`internal/coordinator/flow_model.go:97` 虽然全量 marshal，但该包**无人 import**（已核实），故无生产影响。

   **本条直接限制了 #5 的可见性**：`LLMDegraded` 因此只在进程内的 `AuditReport` / `ConclusionContext` 上生效，控制台上报的 `codeaudit` 段看不到。本次已按此取舍（只做拦截 + 报告对象内标记），若日后要让平台侧也看见降级，需先动载荷契约。
2. **控制器探活与本次 #5 门槛不一致**：`import_processing.go:625-632` 的 fail-closed 探活**不分有无 finding** 就拦；本次 #5 在有 finding 时才拦。这是有意为之（探活是启动期策略，本改动是库层精确化），但两处宽严不同，值得记一笔。
3. **`AssembleAuditReport` 对 nil scanReport 不安全**：`audit.go:334` 与 `:404` 会解引用 `scanReport`，而 `failclosed_test.go:66` 的注释声称"有些路径传 nil scan report"。目前无活路径传 nil，属潜在缺陷。
4. **`CheckImportWithLLM` 与 #5 判据不一致（本次未动）**：`verifier.go:243-245` 在 `cfg.Endpoint == ""` 时**直接返回 pass**，即使 `Enabled && FailClosed` 也照样放行。本次 #5 只改了 `GenerateAuditReport`，于是同一个包的两个公开入口在同一种配置下给出相反结论。该函数**无生产调用方**（仅 `llm_test.go`），故为潜在问题。未一并修复：它不在本次三条范围内，且无测试覆盖"endpoint 空 + FailClosed"这一格，改它需要先补测试、确认没有别处依赖"空 endpoint = 不启用 LLM"的宽松语义。**建议单独处理。**
5. **`internal/coordinator` 是休眠的第二调用方**：该包无人 import（已复核），但若日后复活，`flow_model.go:83-86` 只用 `NewOllamaClient` 且**完全忽略 `FailClosed`**，其 `GenerateAuditReport` 等价调用在新 #5 下的行为（`FailClosed && Endpoint == "" && findings > 0` 硬失败）与它自身的宽松逻辑并不一致。当前无影响，记录以免日后误判。
6. **`buildSummaryTextExt` 的降级文案是有条件的**：`audit.go:521-531` 只在 `stats.Low > 0` 分支输出"大模型服务降级"字样。若一次降级运行的 finding **全是** HIGH/MEDIUM（`stats.Low == 0`），结论文案不会提到降级——本次新增的 `TestAuditWithoutAClientIsMarkedDegraded` 夹具正好是这个形状（1 个 MEDIUM、0 个 LOW）。**这是有意保留的现状**：用户已明确本次"不改结论文案"（有 3 处测试钉死）。故本次降级的可辨识性**仅存在于进程内的 `AuditReport`**，控制台上报路径看不到——这与后续项 1 是同一个根因。
