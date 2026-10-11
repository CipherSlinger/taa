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
| LLM | **与源码同路径走 LLM**（finding 级复用 `VerifyReport`，文件级用二进制专用 prompt） | finding 级天然复用；文件级必须换 prompt，因为现有 prompt 明写"Python 代码文件"并用 ```python``` 包裹 |

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
| `internal/codeaudit/audit.go` | `AuditMetadata` 增二进制字段；`ruleSuggestionMap` 增 3 条；`AssembleAuditReport` 从 `scanReport.Binary` 抄元数据 |
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
9. **合并两个通道的 finding 时不再二次限流**。源码臂保有自己的 200，二进制臂保有自己的 50，合并列表不设上限（见 Task 11）。**代价明确**：极端情况下 Tier 2 的 LLM 调用上界从 200 变成 250。这个上界换的是别的东西：共享配额会让大源码臂按路径字典序挤掉二进制 finding，并且——因为触顶即 `Truncated`、`Truncated` 即 `ProvesCleanScan()` 为假、为假即删包——会把一个本来能导入的包变成被删的包。已入库语料的实测最大 finding 数是单样本 7、整语料 80，两个上限都远未接近，所以保护模型的从来是那个阻断，不是配额。
10. **tar 不被解析**。`models/audit/holdout-sources/sr.tgz` 是 gzip 包 tar（解压后 10.66 MB、4933 个条目，一整个 `semgrep-rules-develop` 检出），解压后的字节会被读取并扫过 strings 通道，所以其中的字面量可见。**代价明确**：tar 的结构全部丢失——没有按成员归属、没有按成员分类（tar 里的 ELF 拿不到节区与导入符号证据）、也不会递归进 tar 里的归档；并且 tar 字节不会命中 pickle 门控（第 7 条），pickle 解释器不跑在它上面，tar 里的 pickle opcode 只有恰好构成可打印串时才以 strings 证据出现。
11. **嵌套归档只递归一层**。`models/examples/Retina-DKD/Retina-DKD-code.zip` 把 `net_001.pth`/`net_005.pth` 作为成员携带，它们分类为 `KindArchive`；`collectArchive` 只对分类为 ELF 或 pickle 的成员下钻，因此这两个 checkpoint 不会被打开，其 `data.pkl` 永远到不了 pickle 解释器。**代价明确**：只装在 zip 里的 checkpoint 既不产出成员证据也不产出 pickle 目标；这一条现在由第 7 条的门控放大——解释器只跑在被声明为 pickle 的流上，而嵌套归档里那条流既没被声明、也没被下钻，没有第二次机会被发现；跳过是静默的（成员名与大小进了证据列表，但不置 `Bounded`）。
12. **`.xlsx` 就是 zip**。语料里的 14 个 `.xlsx` 中 13 个是普通 zip（最坏压缩比 22.91，无炸弹形状，成员均分类为非可执行），第 14 个 `models/examples/Retina-DKD/Retina-DKD/test_result.xlsx` 是 OLE2 老式 `.xls` 顶着 `.xlsx` 名，不匹配任何魔数，落到 `KindRaw`。**代价明确**：当作 zip 的那 13 个只按普通容器处理（成员头嗅探 + 成员名/大小），内部的 XML 不进任何结构化解析；当 OLE2 的那一个只拿 strings 证据，不会因为扩展名被当成 zip 打开。

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
	// MaxSectionBytes bounds one ELF section read.
	MaxSectionBytes int64
	// MaxArchiveMembers bounds how many container members are examined.
	MaxArchiveMembers int
	// MaxArchiveMemberBytes bounds the bytes of the ELF/pickle members read whole
	// across one container: the container's own total decompressed size is not
	// bounded, because a member that is neither an ELF nor a pickle is classified
	// and skipped without being read into memory.
	MaxArchiveMemberBytes int64
	// MaxFindings caps findings across the whole binary pass.
	//
	// It is deliberately not the source scanner's cap. The two channels are capped
	// separately and the merge re-truncates neither, because a shared ceiling
	// couples them in the one direction that costs a model package: reaching a cap
	// sets Truncated, Truncated fails ProvesCleanScan, and a failed scan has the
	// package deleted. A shared 200 would let a source arm carrying 190 findings
	// and a binary arm carrying 20 push a package that used to import into that
	// state, and would choose which findings to drop by path order rather than by
	// importance. Nothing recorded comes near either cap - the highest finding
	// count in any stored report in this repository is 7 for one sample and 80 for
	// a whole 100-sample corpus - so the ceiling that protects the model is the
	// blocking, not the cap.
	//
	// 50 rather than 200 because the evidence families number ten
	// (NET_002/CMD_001/DYN_001/BIN_001/BIN_002/PKL_001/FIL_001/PER_001/ENV_001/
	// OBF_001): fifty findings is five instances of every family, far past the
	// point where another instance changes the verdict. Worst case LLM calls go
	// from 200 to 250, and only when both arms saturate - a state that already
	// blocks and deletes regardless of how many calls it costs.
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
		MaxSectionBytes:       16 * 1024 * 1024,
		MaxArchiveMembers:     4096,
		MaxArchiveMemberBytes: 256 * 1024 * 1024,
		// Not DefaultConfig().MaxFindings: the two channels are capped
		// independently and the merge re-truncates neither. See the field comment.
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
	if cfg.MaxSectionBytes <= 0 {
		cfg.MaxSectionBytes = def.MaxSectionBytes
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
}
```

在文件顶部 import 块补 `"bytes"`、`"math"`。

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

追加到 `binary_evidence_test.go`（import 块补 `archive/zip`、`encoding/binary`、`io`；`os`/`strings`/`testing` 已在 Task 2 引入）：

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
// cannot depend on where the reads split. The fixtures above all fit in one 64
// KiB chunk, so this test must run at several sizes; it is what would catch a
// boundary bug that the real file (one chunk) cannot.
func TestPickleInterpreterIsChunkInvariant(t *testing.T) {
	data := []byte{0x80, 0x04}
	data = append(data, pickleBinUnicode(strings.Repeat("data\x63\n", 400))...)
	data = append(data, pickleGlobal("os", "system")...)
	data = append(data, 0x8c, 0x03)
	data = append(data, "abc"...)
	data = append(data, 0x8c, 0x03)
	data = append(data, "def"...)
	data = append(data, 0x93, 0x2e)

	want := "os.system,abc.def"
	for _, size := range []int{1, 2, 3, 5, 8, 64, 1024, 64 * 1024} {
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
// Write implements io.Writer. All parse state crosses calls, so the result is
// independent of where the chunk boundaries fall; a boundary inside an operand and
// a boundary on an opcode are the same thing to this loop.
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

// step consumes as much of one opcode as b holds and returns the number of bytes
// consumed, or 0 when it needs more. It reports the absolute offset of the opcode
// it is executing because that, not the operand's offset, is what an evidence line
// carries.
func (p *pickleScanner) step(b []byte, absOff int64) int {
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
		return n
	}
	return 0
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

继续追加栈效应与目标产出：

```go
func (p *pickleScanner) push(s pickSlot) { p.stack = append(p.stack, s) }

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
}

// elfFixtureBytes builds a minimal but well-formed ELF64 little-endian shared
// object with exactly the sections the extractor reads: .text, .dynstr, .dynsym,
// .dynamic and .shstrtab, and (optionally) one PT_INTERP program header.
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
//	.dynstr               a leading NUL, then each name once, NUL-terminated
//	.dynsym               24-byte entries; entry 0 is the null symbol (omitted when stripped)
//	.dynamic              16-byte entries; DT_NEEDED..., [DT_SONAME], then DT_NULL
//	.shstrtab             section names
//	section headers       64 bytes each, 6 of them (index 0 is the required SHT_NULL)
//
// One layout hazard is worth stating because the failure mode is a crash rather
// than a test failure: debug/elf's getSymbols64 slices off the first 24 bytes
// unconditionally, so a SHT_DYNSYM section with sh_size == 0 panics with
// "slice bounds out of range [24:0]". A present .dynsym must therefore always
// carry at least the 24-byte null entry.
func elfFixtureBytes(t *testing.T, spec elfSpec) []byte {
	t.Helper()

	const (
		ehSize     = 64
		phEntSize  = 56 // Elf64_Phdr: 2 uint32 + 6 uint64
		shEntSize  = 64
		symEntSize = 24
		dynEntSize = 16
		shNum      = 6 // index 0 null, 1..5 the five real sections
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
	// the imports start at entry one. A stripped file has no .dynsym at all.
	var dynsym []byte
	if !spec.stripped {
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
	nDynstr := shName(".dynstr")
	nDynsym := shName(".dynsym")
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
	dynstrOff := off
	off = align8(off + len(dynstr))
	dynsymOff := off
	off = align8(off + len(dynsym))
	dynamicOff := off
	off = align8(off + len(dynamic))
	shstrtabOff := off
	off = align8(off + len(shstrtab))
	shoff := off

	buf := make([]byte, shoff+shEntSize*shNum)

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
	le.PutUint16(buf[60:62], uint16(shNum)) // e_shnum
	le.PutUint16(buf[62:64], 5)             // e_shstrndx: .shstrtab is section 5

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

	textFlags := uint64(elf.SHF_ALLOC)
	if spec.textExec {
		textFlags |= uint64(elf.SHF_EXECINSTR)
	}
	sh(1, nText, elf.SHT_PROGBITS, textFlags, uint64(textOff), uint64(len(spec.text)), 0, 0, 8, 0)
	sh(2, nDynstr, elf.SHT_STRTAB, uint64(elf.SHF_ALLOC), uint64(dynstrOff), uint64(len(dynstr)), 0, 0, 1, 0)
	if !spec.stripped {
		sh(3, nDynsym, elf.SHT_DYNSYM, uint64(elf.SHF_ALLOC), uint64(dynsymOff), uint64(len(dynsym)), 2, 1, 8, symEntSize)
	}
	sh(4, nDynamic, elf.SHT_DYNAMIC, uint64(elf.SHF_ALLOC), uint64(dynamicOff), uint64(len(dynamic)), 2, 0, 8, dynEntSize)
	sh(5, nShstrtab, elf.SHT_STRTAB, 0, uint64(shstrtabOff), uint64(len(shstrtab)), 0, 0, 1, 0)

	copy(buf[textOff:], spec.text)
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

	var notices []string
	for _, l := range set.Lines {
		if l.Source == SourceNotice {
			notices = append(notices, l.Text)
		}
	}
	if !containsString(notices, "no dynamic symbol table (stripped or static)") {
		t.Errorf("no stripped/static notice; got notices %v", notices)
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

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
```

- [ ] **Step 3: 跑测试确认失败**

```bash
go test ./internal/codeaudit/ -run 'TestELFFixture|TestCollectELF' 2>&1 | head -20
```

预期：`TestELFFixtureIsReadByTheStandardLibrary` PASS（夹具本身正确），`TestCollectELFEvidence` 编译失败 `undefined: collectELF`。

> 若夹具测试就失败，按 `debug/elf` 的报错逐个字段核对：最常见的是 `e_shstrndx` 与 `./shstrtab` 的节索引不一致（本文档中为 5），或 `sh_link` 未指向 `.dynstr`（本文档中为 2）。

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
// The parse is bounded per section, not per file: a section that cannot be read
// within MaxSectionBytes is a structural bound, and for a format that executes
// that withholds a clean verdict rather than being shrugged off.
func collectELF(path string, set *EvidenceSet, cfg BinaryConfig) error {
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
	syms, err := ef.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return fmt.Errorf("read dynamic symbols of %s: %w", path, err)
	}
	for _, s := range syms {
		if s.Section != elf.SHN_UNDEF || elf.ST_BIND(s.Info) != elf.STB_GLOBAL {
			continue
		}
		set.addStructured(SourceDynsym, s.Name)
	}
	if errors.Is(err, elf.ErrNoSymbols) {
		set.addStructured(SourceNotice, "no dynamic symbol table (stripped or static)")
	}

	for _, sec := range ef.Sections {
		executable := sec.Flags&elf.SHF_EXECINSTR != 0
		set.addStructured(SourceSection, fmt.Sprintf("%s size=%d executable=%t", sec.Name, sec.Size, executable))
		if !executable || sec.Size == 0 {
			continue
		}
		data, bounded, readErr := readBoundedSection(sec, cfg.MaxSectionBytes)
		if readErr != nil {
			// A section that cannot be read is a gap in the evidence, not a
			// reason to abandon the file: the symbols already gathered are still
			// evidence, and the bound records the gap.
			set.markStructural(fmt.Sprintf("section %s unreadable: %v", sec.Name, readErr))
			continue
		}
		if bounded {
			set.markStructural(fmt.Sprintf("section %s exceeds MaxSectionBytes", sec.Name))
		}
		if line, ok := entropyVerdict(sec.Name, data, cfg); ok {
			set.addStructured(SourceEntropy, line)
		}
	}
	return nil
}

// readBoundedSection reads at most limit bytes of one section, reporting whether
// the read was cut. The bound exists because a section can declare any size it
// likes, and a report that tried to hold a declared gigabyte would be the denial
// of service the audit is supposed to be part of preventing.
func readBoundedSection(sec *elf.Section, limit int64) (data []byte, bounded bool, err error) {
	reader := sec.Open()
	if limit > 0 && sec.Size > uint64(limit) {
		bounded = true
	}
	data, err = io.ReadAll(io.LimitReader(reader, limit))
	if err != nil {
		return nil, bounded, err
	}
	return data, bounded, nil
}
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
go test ./internal/codeaudit/ -run 'TestELF|TestCollectELF' -v
```

预期全 PASS。

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

- [ ] **Step 1: 写失败测试**

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
```

文件顶部 import 块补 `"archive/zip"`、`"compress/gzip"`、`"fmt"`。

- [ ] **Step 2: 跑测试确认失败**

```bash
go test ./internal/codeaudit/ -run 'TestCollectArchive|TestCollectCompressed' 2>&1 | head -10
```

预期：编译失败，`undefined: collectArchive`。

- [ ] **Step 3: 实现**

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
		// not look inside.
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
// It exists because four call sites need exactly this loop - a pickle member, an
// ELF member, a decompressed gzip stream, and a whole file - and the bound has to
// be enforced identically in all of them. The reason is not brevity. The bound is
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

- [ ] **Step 4: 把 `collectELF` 拆出 reader 版本**

`collectELF(path, ...)` 与 `collectELFMember` 需要共用同一段解析逻辑，所以把 Task 5 的实现体抽到一个以 `io.ReaderAt` 为入口的内核上，`collectELF` 变成薄封装。修改 `binary_evidence.go` 中 Task 5 写的 `collectELF`：

```go
// collectELF reads a file's ELF structure into evidence.
func collectELF(path string, set *EvidenceSet, cfg BinaryConfig) error {
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
// There is no size parameter: the parse bounds itself per section through
// readBoundedSection, and a size the body never read would be a parameter that
// only invites the assumption that something is bounds-checked elsewhere.
func collectELFReader(r io.ReaderAt, set *EvidenceSet, cfg BinaryConfig, name string) error {
	ef, err := elf.NewFile(r)
	if err != nil {
		return fmt.Errorf("parse elf %s: %w", name, err)
	}
	defer ef.Close()
	// ... (Task 5 的解析体原样搬到这里，把 path 换成 name)
}
```

- [ ] **Step 5: 跑测试确认通过**

```bash
go test ./internal/codeaudit/ -run 'TestCollect|TestELF|TestPickle|TestString|TestStream|TestShannon|TestEntropy|TestClassify' -v
```

预期全 PASS。

- [ ] **Step 6: 提交**

```bash
gofmt -l internal/codeaudit/ ; go vet ./internal/codeaudit/
git add internal/codeaudit/binary_evidence.go internal/codeaudit/binary_evidence_test.go
git commit -m "feat(audit): read zip and gzip containers, recursing into member evidence"
```

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
	}{
		{"elf", "lib.so", elfFixtureBytes(t, elfSpec{imports: []string{"connect"}}), KindELF},
		{"archive", "m.pt", zipFixture(t, map[string][]byte{"a": []byte("x")}, []string{"a"}), KindArchive},
		{"pickle", "m.pkl", []byte("\x80\x04cposix\nsystem\n."), KindPickle},
		{"raw", "w.bin", []byte("data\x00literal_here"), KindRaw},
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
			// isExecutableKind is what decides whether that bound blocks; this
			// asserts the same predicate the scanner folds on.
			if got := isExecutableKind(tc.kind); got != tc.wantBlocked {
				t.Errorf("isExecutableKind(%s) = %t, want %t", tc.kind, got, tc.wantBlocked)
			}
		})
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

```bash
go test ./internal/codeaudit/ -run TestCollectEvidence 2>&1 | head -10
```

预期：编译失败，`undefined: CollectEvidence`。

- **Step 3: 实现**

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
// that was not examined has to reach the report, not stop it.
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
func TestBinaryRulesBorrowSharedFamilies(t *testing.T) {
	byID := map[string]Rule{}
	for _, r := range DefaultRules() {
		byID[r.ID] = r
	}
	binary, err := NewBinaryMatcher()
	if err != nil {
		t.Fatalf("NewBinaryMatcher: %v", err)
	}
	for _, r := range binary.Rules() {
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
		{SourceStrings, "/etc/passwd", "FIL_001"},
		{SourceStrings, "/root/.ssh/id_rsa", "FIL_001"},
		{SourceStrings, "(/etc/cron.d/backdoor)", "PER_001"},
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
```

- [ ] **Step 2: 跑测试确认失败**

```bash
go test ./internal/codeaudit/ -run 'TestBinaryRules|TestBinaryOnly|TestMatchEvidence|TestSymbolRules' 2>&1 | head -10
```

预期：编译失败，`undefined: NewBinaryMatcher`。

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
var binaryOnlyRules = map[string]Rule{
	"BIN_001": {
		ID:       "BIN_001",
		Category: "加壳载荷",
		Severity: SeverityMedium,
		Description: "可执行节区或整个文件熵接近随机 — 代码已被压缩或加密，运行前必须先解包",
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
// that matches owns the line. A line that two families could describe is
// therefore counted once, which is what keeps the statistics from
// double-weighting one defect.
var binaryFamilies = []binaryFamily{
	{
		// memfd_create and fexecve come before the general command family so
		// that the more specific family names the finding.
		ID:       "BIN_002",
		Sources:  []EvidenceSource{SourceDynsym},
		Patterns: compilePatterns(`^(memfd_create|fexecve)$`),
	},
	{
		ID:      "CMD_001",
		Sources: []EvidenceSource{SourceDynsym, SourceStrings},
		Patterns: compilePatterns(
			`^(system|execve|execv|execvp|execl|execlp|execle|popen|posix_spawn|posix_spawnp|forkpty|WinExec|ShellExecuteA|ShellExecuteW|CreateProcessA|CreateProcessW)$`,
			`^/bin/(sh|bash|dash|zsh)$`,
			`^(bash|sh) -c\b`,
			`\b(curl|wget) -[a-zA-Z]*O?\b.*https?://`,
		),
	},
	{
		ID:      "NET_002",
		Sources: []EvidenceSource{SourceDynsym, SourceNeeded},
		Patterns: compilePatterns(
			`^(socket|connect|bind|listen|accept|send|sendto|sendmsg|recv|recvfrom|recvmsg|getaddrinfo|gethostbyname|gethostbyaddr|inet_addr|inet_pton|WSAStartup|WSASocketA)$`,
			`^libcurl\.so`,
			`^libssl\.so`,
		),
	},
	{
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
		ID:      "PER_001",
		Sources: []EvidenceSource{SourceStrings},
		Patterns: compilePatterns(
			`^crontab`,
			`/etc/cron[a-z.]*`,
			`(?:^|/)\.bashrc$`,
			`(?:^|/)\.bash_profile$`,
			`systemctl (enable|start)`,
			`/etc/systemd/system`,
			`/etc/init\.d`,
		),
	},
	{
		ID:      "FIL_001",
		Sources: []EvidenceSource{SourceStrings},
		Patterns: compilePatterns(
			`/etc/(?:passwd|shadow|sudoers)`,
			`(?:^|/)\.ssh/(?:id_[a-z]+|authorized_keys|config)`,
			`(?:^|/)\.aws/credentials`,
			`(?:^|/)\.kube/config`,
			`/proc/self/environ`,
		),
	},
	{
		ID:      "ENV_001",
		Sources: []EvidenceSource{SourceStrings},
		Patterns: compilePatterns(
			`(?i)^(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|API_KEY|SECRET_KEY|ACCESS_TOKEN|PRIVATE_KEY|GITHUB_TOKEN)$`,
		),
	},
	{
		ID:      "BIN_001",
		Sources: []EvidenceSource{SourceEntropy},
		Patterns: compilePatterns(`^high-entropy-`),
	},
	{
		ID:      "OBF_001",
		Sources: []EvidenceSource{SourceStrings},
		Patterns: compilePatterns(
			// A long base64 blob left in a code slot. The length floor is what
			// keeps this from firing on padded text.
			`^[A-Za-z0-9+/]{120,}={0,2}$`,
		),
	},
}

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
// quota are computed from, and one evidence line is one observation. A line that
// two families could describe - memfd_create is both an execution capability and
// a dynamic-loading one - is reported under the more specific family, which is
// why the table order is the precedence and is asserted by a test.
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

`internal/codeaudit/audit.go` 的 `ruleSuggestionMap` 目前只有源码臂的 13 个 id。二进制通道的 `BIN_001`、`BIN_002`、`PKL_001` 不在其中，落到 `SuggestionForRule` 的兜底文案上——报告会给出一条毫无指向的修复建议。补进去：

```go
	"EMB_004": "不要将数据编码后嵌入模型权重",
	"BIN_001": "确认该二进制段是否经过加壳/加密；若无需动态解包，改用未加壳的构建产物",
	"BIN_002": "确认该二进制为何需要敏感能力；移除不必要的敏感符号引用",
	"PKL_001": "不要反序列化不可信 pickle；改用 weights_only=True 或 safetensors 等纯数据格式",
}
```

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
go test ./internal/codeaudit/ -run 'TestBinaryRules|TestBinaryOnly|TestMatchEvidence|TestSymbolRules|TestEveryBinaryRuleHasASuggestion' -v 2>&1 | tail -20
```

预期全 PASS。若 `TestBinaryOnlyFamiliesDoNotCollide` 报 `BIN_001` 之类的 id 冲突，说明 `binaryOnlyRules` 里写了与共享表相同的 id——修正 id 而不是放宽断言。

- [ ] **Step 7: 提交**

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
func TestBinaryScannerClaimsOnlyBinaryFiles(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", "import os\n")
	writeTestFile(t, dir, "notes.txt", "just prose\n")
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

// TestBinaryScannerIsDeterministic pins the ordering. The finding cap keeps the
// first N, so an order that varied between runs would make a truncated scan keep
// a different set each time and two reports of the same package would stop being
// comparable.
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

func TestBinaryScannerCapsAndRecordsTruncation(t *testing.T) {
	dir := t.TempDir()
	writeTestBytes(t, dir, "libevil.so", elfFixtureBytes(t, elfSpec{
		imports:  []string{"socket", "connect", "system", "popen", "dlopen", "memfd_create"},
		textExec: true,
		text:     uniformBytes(512),
	}))
	// A literal that adds a distinct evidence line per rule, so the cap is
	// reachable without a synthetic file.
	writeTestBytes(t, dir, "extra.bin", []byte("data\x00/etc/passwd\x00/etc/shadow\x00"))

	cfg := DefaultBinaryConfig()
	cfg.MaxFindings = 2
	s, err := newTestBinaryScanner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	if len(res.Findings) != 2 {
		t.Errorf("len(Findings) = %d, want the cap of 2", len(res.Findings))
	}
	if !res.Summary.Truncated {
		t.Error("Summary.Truncated = false after the finding cap fired; the dropped findings are invisible")
	}
	// The cap is carried into the summary so the report can say what it was
	// truncated at. A reader who sees truncated with no number has to go find the
	// configuration that produced it, and by then it may have changed.
	if res.Summary.MaxFindings != 2 {
		t.Errorf("Summary.MaxFindings = %d, want 2", res.Summary.MaxFindings)
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
	// Incomplete counts files that could not be examined at all.
	Incomplete int `json:"incomplete,omitempty"`
	// Truncated records that the finding cap was reached.
	Truncated bool `json:"truncated,omitempty"`
	// MaxFindings is the cap this pass ran under, carried into the report so that
	// a reader who sees truncated can tell what it was truncated at without
	// re-reading the scanner's configuration. It is provenance, not a second
	// ceiling: MergeBinaryFindings does not reapply it to the joined list.
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
	// its cap: the cap keeps the first N, so a varying order would make a
	// truncated pass keep a different set each time.
	sortFindings(res.Findings)
	if len(res.Findings) > s.cfg.MaxFindings {
		res.Findings = res.Findings[:s.cfg.MaxFindings]
		res.Summary.Truncated = true
	}
	return res, nil
}

// classify reads a file's head and decides how it should be read.
func (s *BinaryScanner) classify(path string) (BinaryKind, error) {
	f, err := os.Open(path)
	if err != nil {
		return KindText, err
	}
	defer f.Close()

	head := make([]byte, sniffBytes)
	n, err := f.Read(head)
	if err != nil && n == 0 {
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
go test ./internal/codeaudit/ -run TestBinaryScanner -v 2>&1 | tail -20
```

预期全 PASS。

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
		{"a bounded executable withholds", BinaryScanSummary{FilesCount: 3, BoundedExecutable: 1}, false},
		{"an unexamined file withholds", BinaryScanSummary{FilesCount: 3, Incomplete: 1}, false},
		{"the finding cap withholds", BinaryScanSummary{FilesCount: 3, Truncated: true}, false},
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
	// BoundedData is deliberately not read. A tensor blob whose listing was
	// capped is a file that was read; a shared object whose sections were not is
	// a file that was not, and only the second is a look that did not happen.
	if b := r.Binary; b != nil {
		if b.BoundedExecutable > 0 || b.Incomplete > 0 || b.Truncated {
			return false
		}
	}
	return true
}
```

- [ ] **Step 4: 跑测试确认通过**

```bash
go test ./internal/codeaudit/ -run 'TestProvesCleanScan|TestFailClosed|TestReportFields' -v 2>&1 | tail -20
```

预期全 PASS。已有的 fail-closed 测试必须保持通过——它们是这次改动的回归网。

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
// recomputed from the joined list, and the binary summary reaches the report so
// that ProvesCleanScan can read it.
func TestMergeBinaryFindingsAppendsAndRecomputes(t *testing.T) {
	report := &Report{
		ScanComplete: true,
		FilesCount:   1,
		Findings: []Finding{
			{File: "/m/clean.py", Line: 1, RuleID: "NET_001", Severity: SeverityHigh},
		},
	}
	recomputeReportPassed(report, false)
	if report.Passed {
		t.Fatal("fixture is wrong: a HIGH finding must already block")
	}

	res := &BinaryScanResult{
		Claimed: []string{"/m/libevil.so"},
		Findings: []Finding{
			{File: "/m/libevil.so", Line: 4, RuleID: "NET_002", Severity: SeverityHigh, Engine: EngineNameBinary},
		},
		Summary: BinaryScanSummary{FilesCount: 1, BoundedExecutable: 1},
	}

	MergeBinaryFindings(report, res)

	if len(report.Findings) != 2 {
		t.Fatalf("len(Findings) = %d, want 2", len(report.Findings))
	}
	if report.Binary == nil {
		t.Fatal("report.Binary is nil; the completeness summary did not reach the report")
	}
	if report.Passed {
		t.Error("Passed = true, want false: the binary scan was bounded and BoundedExecutable withholds the pass")
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
			{File: "/m/evil.py", Line: 1, RuleID: "BIN_001", Severity: SeverityMedium, Engine: EngineNameBinary},
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
// couple them: it would let a large source arm evict binary findings by path
// order, and - because reaching a cap sets Truncated, and Truncated fails
// ProvesCleanScan - it would newly block and delete a package that passed before
// the binary channel existed. The fixture is the smallest one that shows the
// difference: three source findings, one binary finding, and a source arm whose
// own cap was three.
func TestMergeBinaryFindingsKeepsBothChannelsFindings(t *testing.T) {
	report := &Report{ScanComplete: true, FilesCount: 3}
	for i := 0; i < 3; i++ {
		report.Findings = append(report.Findings, Finding{
			File: "/m/a.py", Line: i + 1, RuleID: "CMD_001", Severity: SeverityMedium,
		})
	}
	res := &BinaryScanResult{
		Findings: []Finding{
			{File: "/m/z.so", Line: 1, RuleID: "NET_002", Severity: SeverityHigh, Engine: EngineNameBinary},
		},
		Summary: BinaryScanSummary{FilesCount: 2},
	}

	MergeBinaryFindings(report, res)

	if len(report.Findings) != 4 {
		t.Errorf("len(Findings) = %d, want 4: the merge applied a ceiling to the joined list", len(report.Findings))
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

// TestMergeBinaryFindingsSurfacesTheBinaryCap pins the other half: when the
// binary arm did drop findings, that drop has to reach the report's own Truncated
// and not only the summary. scan_metadata.truncated is copied from Truncated, and
// a reader who checks only the metadata must not be told nothing was dropped.
func TestMergeBinaryFindingsSurfacesTheBinaryCap(t *testing.T) {
	report := &Report{ScanComplete: true}
	res := &BinaryScanResult{
		Summary: BinaryScanSummary{FilesCount: 1, Truncated: true},
	}

	MergeBinaryFindings(report, res)

	if !report.Truncated {
		t.Error("Truncated = false after the binary arm capped itself; the drop is invisible to scan_metadata")
	}
	if report.Passed {
		t.Error("Passed = true although the binary pass dropped findings")
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
// costs a model package. Reaching a cap sets Truncated, Truncated fails
// ProvesCleanScan, and a scan that cannot prove it looked has the package
// deleted. A shared ceiling would let a source arm carrying 190 findings and a
// binary arm carrying 20 push a package that used to import into that state, and
// it would choose which findings to drop by path order rather than by importance.
// The ceiling that protects the model is the blocking, not the cap.
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

	// The binary arm's own cap is folded into the report's Truncated rather than
	// left on the summary alone. ProvesCleanScan reads both, so the pass decision
	// is right either way - but scan_metadata.truncated is copied from this field,
	// and a report whose metadata says nothing was dropped while a channel dropped
	// fifty findings is the confusion the provenance fields exist to remove.
	if res.Summary.Truncated {
		report.Truncated = true
	}

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
- Modify: `internal/codeaudit/verifier.go`, `internal/codeaudit/audit.go`, `internal/codeaudit/llm_test.go`, `internal/controller/import_processing.go`
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
		engine, err := NewEngine(EngineConfig{Name: name, SemgrepRulesPath: DefaultSemgrepRulesPath})
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

> 注：semgrep 用例在未安装 semgrep CLI 的环境会失败。在 `internal/codeaudit/engine_select_test.go` 的 import 块补 `"os/exec"`，并在子测试开头加：

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
	binaryRes, err := runBinaryChannel(dir, cfg.Binary)
	if err != nil {
		// The binary channel's failure is a failure of the audit. Continuing
		// would report a verdict reached without it, and under fail-closed that
		// is the silent allow the policy exists to prevent.
		return nil, fmt.Errorf("binary scan: %w", err)
	}

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
func runBinaryChannel(dir string, binCfg BinaryConfig) (*BinaryScanResult, error) {
	if !binCfg.Enabled {
		return nil, nil
	}
	matcher, err := NewBinaryMatcher()
	if err != nil {
		return nil, err
	}
	return NewBinaryScanner(matcher, binCfg).ScanDirectory(dir)
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
		s.Logs.Add(LogInfo, "audit", "二进制审计: files=%d kinds=%v boundedExecutable=%d boundedData=%d incomplete=%d truncated=%v",
			b.FilesCount, b.Kinds, b.BoundedExecutable, b.BoundedData, b.Incomplete, b.Truncated)
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

- [ ] **Step 1: 让 mock 捕获 prompt**

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

- [ ] **Step 2: 写失败测试**

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

- [ ] **Step 3: 跑测试确认失败**

```bash
go test ./internal/codeaudit/ -run 'TestBinaryFilePrompt|TestSourceFilePrompt' 2>&1 | head -20
```

预期：`TestBinaryFilePromptCarriesEvidenceAndNotRawBytes` FAIL（prompt 里是 Python 框架与原始字节）。

- [ ] **Step 4: 实现**

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

- [ ] **Step 5: 跑测试确认通过**

```bash
go test ./internal/codeaudit/ -run 'TestBinaryFilePrompt|TestSourceFilePrompt|TestGenerateAuditReport' -v 2>&1 | tail -20
```

预期全 PASS。

- [ ] **Step 6: 提交**

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

```go
// TestBinaryAuditConfigDefaultsAndOverrides pins the switch that makes this
// feature reversible: the channel is on unless a deployment says otherwise, and
// every limit can be moved without touching code.
func TestBinaryAuditConfigDefaultsAndOverrides(t *testing.T) {
	t.Run("absent means enabled with the adapter's defaults", func(t *testing.T) {
		path := writeTestConfig(t, t.TempDir(), `{"security":{"codeScanEngine":"regex"}}`)
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
		path := writeTestConfig(t, t.TempDir(), `{"security":{"binaryAudit":{"enabled":false}}}`)
		cfg, err := LoadStartupConfig(path)
		if err != nil {
			t.Fatalf("LoadStartupConfig: %v", err)
		}
		if cfg.BinaryAuditEnabled {
			t.Error("BinaryAuditEnabled = true after an explicit false")
		}
	})

	t.Run("limits are read", func(t *testing.T) {
		path := writeTestConfig(t, t.TempDir(),
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
		path := writeTestConfig(t, t.TempDir(), `{"security":{"binaryAudit":{"maxArchiveMembers":-1}}}`)
		if _, err := LoadStartupConfig(path); err == nil {
			t.Error("a negative limit was accepted; it would be normalised to the default and the operator would never know")
		}
	})

	t.Run("the full-scan threshold is carried through", func(t *testing.T) {
		path := writeTestConfig(t, t.TempDir(), `{"security":{"binaryAudit":{"maxFullScanBytes":134217728}}}`)
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

追加到 `internal/app/taa/app_test.go`（在 `TestBuildSecurityConfig` 末尾的断言之后）：

```go
	// The binary channel's configuration is carried through rather than dropped:
	// a value that reaches the config struct and not the controller is a setting
	// an operator can write and cannot observe.
	if !sec.Binary.Enabled {
		t.Error("SecurityConfig.Binary.Enabled = false, want the default of true")
	}
	if sec.Binary.MaxArchiveMembers != codeaudit.DefaultBinaryConfig().MaxArchiveMembers {
		t.Errorf("SecurityConfig.Binary.MaxArchiveMembers = %d, want the codeaudit default %d",
			sec.Binary.MaxArchiveMembers, codeaudit.DefaultBinaryConfig().MaxArchiveMembers)
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
	// BinaryAuditMaxFindings bounds findings from the binary pass. Zero means the
	// codeaudit default.
	BinaryAuditMaxFindings int
	// BinaryAuditMaxFullScanBytes is the size above which a file is read at its
	// two ends instead of end to end. Zero means the codeaudit default. It is
	// exposed rather than fixed because it is the one limit whose right value
	// depends on the deployment's package sizes: raising it buys a complete pass
	// over a large pickle at a cost of about 3 microseconds per kibibyte.
	BinaryAuditMaxFullScanBytes int
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
}
```

在 `validateCodeScanEngine` 调用点附近（`LoadStartupConfig` 内的校验序列中）追加：

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
// from one that wrote nothing. Rejecting at load time turns it into a startup
// error instead of an audit that quietly ran with a different budget.
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
	if cfg.BinaryAuditHighEntropyThreshold < 0 || cfg.BinaryAuditHighEntropyThreshold > 8 {
		return fmt.Errorf("security.binaryAudit.highEntropyThreshold must be within [0,8] bits per byte, got %v",
			cfg.BinaryAuditHighEntropyThreshold)
	}
	return nil
}
```

在 `DefaultStartupConfig` 的返回值里，`CodeScanEngine: "semgrep",` 之后追加：

```go
		BinaryAuditEnabled: true,
```

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
		imports: []string{"socket", "connect", "memfd_create"},
		needed:  []string{"libcurl.so.4"},
		text:    uniformBytes(512),
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
			Enabled:         true,
			MaxSectionBytes: 16, // smaller than .text, so the executable section cannot be read
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
		t.Error("Passed = true after an executable section could not be read; the gap did not reach the verdict")
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
- **判定**：证据行按规则表匹配，产出 `Finding` 并标记 `binary_kind` / `evidence_source` / `binary_offset`；共享规则（`NET_002`/`CMD_001`/`DYN_001`/`FIL_001`/`PER_001`/`ENV_001`/`OBF_001`）的严重级从源码规则表读取，不另立一套。二进制专有规则：`BIN_001`（加壳载荷，MEDIUM）、`BIN_002`（`memfd_create`/`fexecve`，HIGH）、`PKL_001`（pickle 反序列化执行，HIGH）。
- **复核**：二进制 finding 与源码 finding 走同一条 LLM 路径；文件级分析使用二进制专用 prompt（现有 prompt 面向 Python 源码，不适用）。
- **完整性**：`scan_metadata.binary` 记录 `files_count` / `kinds` / `bounded_executable` / `bounded_data` / `incomplete` / `truncated`。可执行格式的结构抽取被截断、文件无法读取、finding 触顶，任一项都会使 `ProvesCleanScan()` 为假——fail-closed 下即阻断导入；纯数据文件（张量、npy）的证据截断只记录、不阻断。
- **配置**：`security.binaryAudit.enabled`（默认 `true`）、`maxArchiveMembers`、`highEntropyThreshold`、`maxFindings`（默认 50，独立于源码臂的 200）、`maxFullScanBytes`（默认 64 MiB）。关闭它即回滚，审计行为与引入该通道之前逐字节一致。
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
- [ ] `go test ./internal/codeaudit/ -run 'TestGenerateAuditReport' -v` 中，`regex` 与 `semgrep` 两个子用例都通过（本机装有 semgrep 时真跑）。
- [ ] `git grep -n "Co-Authored-By\|anthropic\|Claude" -- '*.go'` 无命中（提交信息同样不得出现）。
- [ ] 用一个真实模型包（含 `.pt` 与任意 `.so`）在容器里跑一次导入，确认 `auditReportJSON` 里出现 `binary_kind`/`evidence_source` 字段，且 `scan_metadata.binary.files_count > 0`。
- [ ] 确认 `target.files_scanned` 与 `scan_metadata.binary.files_count` 不互相矛盾——后者是前者的子集，前者不小于后者。
- [ ] 确认二进制臂触顶时 `scan_metadata.truncated` 为 `true`（不只是 `scan_metadata.binary.truncated`），否则只看元数据这一层的读者会以为没有丢东西。
- [ ] 把 `security.binaryAudit.enabled` 设为 `false` 再跑一次，确认 `scan_metadata.binary` 缺失且结论与改动前一致（回滚可用）。
- [ ] 确认 `UnsupportedExts` 仍恒为 0——本计划**不**动它，任何让它非零的改动都会使每个真实包被判定为非完整扫描。

## 5. 已知风险与对策

| 风险 | 对策 |
| --- | --- |
| `elfFixtureBytes` 的字节布局写错，Task 5–15 全部建立其上 | `TestELFFixtureIsReadByTheStandardLibrary` 先于一切断言检查夹具本身；失败时按 `debug/elf` 的报错逐字段核对 |
| 大模型包（数 GB）的 `.pt` 让导入变慢 | 证据流式读取，无整文件驻留；容器成员按需解压且有总额预算；超过 `MaxFullScanBytes`（默认 64 MiB）的文件只读首尾各 1 MiB，把单文件成本钉在约 190 ms |
| 加壳判定对 UPX 打包的合法库误报 | `BIN_001` 定为 MEDIUM：assist 策略下不阻断，gate 策略下阻断并交由 operator 判定，这是两种策略本就存在的分歧点 |
| 二进制 finding 挤占 LLM 配额 | 两臂各自限流（源码 200、二进制 50），合并列表不再二次截断。**Tier 2 调用上界由 200 变为 250**，且只在两臂同时饱和时可达——那个状态本来就已阻断并删包，多出的调用不改变结论。反过来，共享配额会让大源码臂按路径序挤掉二进制 finding，并把一个原本可导入的包推到 `Truncated` 而被删除 |
| 二进制通道让原本能导入的包被误阻断 | 这是本设计最贵的失败模式（`ProvesCleanScan` 为假 → `cleanDirContents` 删包），所以：`Truncated` 只由各臂自己的上限触发；纯数据文件的证据截断只记录、不阻断；`BIN_001` 定为 MEDIUM，assist 下不阻断；`security.binaryAudit.enabled=false` 是逐字节回滚。已入库语料实测最大 finding 数为单样本 7、整语料 80，离两个上限都有一个数量级 |
| 与 semgrep 非劣性证据的交互 | 二进制通道在**两个臂之外**运行且合并发生在引擎报告之后，两臂的引擎级报告逐字节不变；`corpus_parity_test.go` 会证明这一点 |
| pickle 解释器的门控开错方向 | 两个方向都是故障，所以各有一个测试钉住：**跑宽了**（对非 pickle 也跑解释器）会让任意字节能被读成 opcode，未知 opcode 直接置 `Bound.Structural`，而 `KindELF`/`KindPickle`/`KindArchive`/`KindCompressed` 都是可执行类型，于是每个 `.pt`/`.whl`/`.so` 都被阻断、原本能导入的包被删——`TestCollectEvidenceDoesNotInterpretNonPicklesAsPickles` 用一个良性 ELF 夹具断言既不 `Err` 也无 `Bound.Structural`、无 `SourcePickle` 行；**跑窄了**（该跑的没跑）会丢掉 pickle 证据——`TestPickleInterpreterReadsTheRealCheckpoint` 断言真 checkpoint 仍产出目标。门控规则（只跑在 `KindPickle` 的整文件/容器成员、以及解压后头部嗅探为 pickle 的 gzip 流上）写在 Task 4 Step 4，不得"简化"掉 |
| 二进制通道无法被取消 | `GenerateAuditReport` 由 `internal/controller/import_processing.go:642` 以 `context.Background()` 调用，新增的 `runBinaryChannel`/`ScanDirectory` 都不收 context，所以**单个文件**的工作量被 `BinaryConfig` 的上限钉住，而**总**工作量随文件数线性增长，且没有任何东西能中断它。这是既有的形状而不是新引入的类别——`engine.ScanDirectoryWithLines` 同样不收 context——所以这里只当作一个已知边界记录：一次导入的二进制臂时长与文件数成正比，超时与否只能由调用方在整条审计之外控制，本计划不新增逐文件的取消路径 |
