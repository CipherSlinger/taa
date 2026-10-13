# Semgrep GA-11 语言规则矩阵覆盖规范（2026-10-13）

- **状态**：PROPOSED
- **前置**：`2026-09-30-cpg-multilang-production-integration-design.md`（APPROVED，已交付）。那份规范建立了
  「多语言规则目录 + `languages:` 分发」机制并落地 python/go/c/java/shell 五个包；**本规范是它的语言集扩充，
  不重写它**。
- **前提变化**：`2026-10-13-model-audit-advisory-verdict-design.md`（已交付，`b3d4775`）把审计裁决改为
  **仅供参考**——错规则不再能阻断导入，只影响报告质量。这**解除了**「未验证规则不得接入」的约束，但把要求
  转移到「报告准确性可测、可调、可标注」。

---

## 1. 目标与非目标

**目标**：把 TAA 的 Semgrep 规则矩阵从 5 门语言扩到 semgrep **GA 档 11 门**，且每门语言的语义族覆盖与该语言的
能力边界**明确一致**（见 §3 矩阵）。

**非目标**：
- 不做 semgrep 全部 47 门（Beta/Alpha/Develop 档不在范围内；用户已裁定）。
- 不改动盘上已有的 `c/`（`c,cpp`，Alpha）与 `shell/`（`bash,sh`，Alpha）两个包——它们超出 GA 集，保留原样。
- 不改动 audit 的 advisory 语义。

---

## 2. 现状差

| 语言 | semgrep 档 | 扩展名 | 现状 | 本次动作 |
| :--- | :--- | :--- | :--- | :--- |
| Python | GA | `.py .pyi` | 13 条 | 不动（基准） |
| Go | GA | `.go` | 6 条 | 补齐到 13 |
| Java | GA | `.java` | 1 条 | 补齐到 13 |
| C# | GA | `.cs` | — | 新建 13 |
| JavaScript | GA | `.cjs .js .jsx .mjs` | — | 新建 13 |
| TypeScript | GA | `.ts .tsx` | — | 新建 13 |
| PHP | GA | `.php .tpl .phtml` | — | 新建 13 |
| Ruby | GA | `.rb` | — | 新建 13 |
| Scala | GA | `.scala` | — | 新建 13 |
| Terraform | GA | `.tf .tofu .hcl .tfvars` | — | 新建 5（见 §3） |
| JSON | GA | `.json .ipynb` | — | 新建 2（见 §3） |
| C / C++ | Alpha | `.c .cpp .cu .h .hpp` | 1 条 | 不动（超范围） |
| Bash / sh | Alpha | `.sh` | 3 条 | 不动（超范围） |

注：semgrep 的 stable 写规则 key 是 `python`（非 `python2`/`python3`，后两者在 Develop 档）；现有 python 包
`languages: [python]` 已是稳定路径。

---

## 3. 13 个语义族 × 语言能力矩阵

Python 包的 13 族（`models/audit/semgrep/rules/python/rules.yaml`）：

| # | family | rule id 后缀 | 语义 | semgrep severity |
| :--- | :--- | :--- | :--- | :--- |
| 1 | CMD | `cmd-exec` | 命令执行 | ERROR |
| 2 | NET_GENERAL | `net-general` | 通用网络出站 | ERROR |
| 3 | NET_SOCKET | `net-socket` | 原始 socket | ERROR |
| 4 | DYN | `dyn-eval` | 动态求值 | WARNING |
| 5 | FIL | `fil-probe` | 文件探测/读取 | WARNING |
| 6 | ENV | `env-secret` | 环境变量取密 | WARNING |
| 7 | OBF | `obf-exec` | 混淆后执行 | ERROR |
| 8 | EXF | `secret-exfiltration` | 涉密外传（`mode: taint`） | ERROR |
| 9 | PER | `per-backdoor` | 持久化后门 | ERROR |
| 10 | EMB_DATA_DUMP | `emb-data-dump` | 嵌入期数据落盘 | ERROR |
| 11 | EMB_COPY_EXPORT | `emb-copy-export` | 嵌入期拷贝外带 | ERROR |
| 12 | EMB_LOG_DUMP | `emb-log-dump` | 嵌入期日志倒出 | WARNING |
| 13 | EMB_STEGO_WEIGHT | `emb-stego-weight` | 权重隐写 | ERROR |

**覆盖矩阵**（`✓` = 该语言可映射，`—` = 结构性 N/A，附理由）：

| family | 8 门通用语言¹ | Terraform | JSON |
| :--- | :---: | :---: | :---: |
| CMD | ✓ | ✓ `provisioner "local-exec"/"remote-exec"` | — |
| NET_GENERAL | ✓ | ✓ `data "http"` | — |
| NET_SOCKET | ✓ | — 无 socket 原语 | — |
| DYN | ✓ | — 无求值语义 | — |
| FIL | ✓ | — 由 EMB_DATA_DUMP 承载 | — |
| ENV | ✓ | ✓ `variable`/`provider` 硬编码凭据 | ✓ 配置内硬编码密钥 |
| OBF | ✓ | — 无混淆执行语义 | — |
| EXF | ✓ | ✓ 涉密 variable 流向 `local-exec` | — |
| PER | ✓ | — 无进程生命周期原语 | — |
| EMB_DATA_DUMP | ✓ | ✓ `local_file` | — |
| EMB_COPY_EXPORT | ✓ | — | — |
| EMB_LOG_DUMP | ✓ | — | — |
| EMB_STEGO_WEIGHT | ✓ | — | — |
| **小计** | **13** | **5** | **2** |

¹ 通用语言 = C#、Go、Java、JavaScript、TypeScript、PHP、Ruby、Scala。

**关键结论**：你的第 2 条要求「每门语言与 Python 保持一致」在 8 门通用语言上**可以逐族满足**；在 Terraform 与
JSON 上**不可机械满足**——那 8 个 `—` 格里没有对应原语，硬写只会产出永不命中的死规则。因此一致性判据定义为
**「每门语言覆盖其矩阵内的全集」**，而非「每门语言都有 13 条」。

**JSON 与 `.ipynb`**：Jupyter notebook 是 JSON，恶意模型包里带 notebook 是真实场景（`!pip install`、`%run`、
单元格内 `subprocess`）。但 semgrep 的 `json` 语言只能 `pattern-regex` 匹配 JSON 文本，**看不到单元格内代码的
结构**。本规范先按文本匹配覆盖；把 notebook 单元格抽出来当 Python 扫（引擎改动）列为 §7 的独立待决项。

---

## 4. 规则包布局与加载机制

布局沿用既有约定，新增 8 个目录：

```text
models/audit/semgrep/rules/
├── python/rules.yaml      # 13（基准，不动）
├── go/rules.yaml          # 6 → 13
├── java/rules.yaml        # 1 → 13
├── csharp/rules.yaml      # 新建 13
├── javascript/rules.yaml  # 新建 13
├── typescript/rules.yaml  # 新建 13
├── php/rules.yaml         # 新建 13
├── ruby/rules.yaml        # 新建 13
├── scala/rules.yaml       # 新建 13
├── terraform/rules.yaml   # 新建 5
├── json/rules.yaml        # 新建 2
├── c/rules.yaml           # 既有（Alpha，不动）
└── shell/rules.yaml       # 既有（Alpha，不动）
```

**加载机制**：`internal/codeaudit/semgrep_engine.go:336` 把 `rulesPath` 作为 `--config` 传给 semgrep，而该字段
的注释已写明「the semgrep rules file **or directory**」。因为每个包都正确声明了 `languages:` 且**没有任何
`paths:` 过滤**，把 `--config` 指向规则目录即可让 semgrep 自身按语言分发，**不需要按语言分别调用**。

改动：`DefaultSemgrepRulesPath`（`:48`）由单文件改为目录。

**风险（必须处理）**：目录化后 semgrep 会校验**全部**规则文件，任一个包语法错误会让整次扫描失败 →
`reportAudit` code=2。advisory 语义下这不再阻断导入，但仍会让审计整体失去结论。缓解：加一个启动期/测试期
「加载全部规则目录」的校验用例。

**JS/TS 合并**：semgrep 规则可声明多个语言（既有 `c/rules.yaml` 的 `languages: [c, cpp]` 与 `shell/rules.yaml`
的 `[bash, sh]` 就是先例）。JS 与 TS 的大量模式相同，可评估用一个 `languages: [js, ts]` 包承载公共族、TS 包只
留类型注解相关的差异——**需先实测 TS 语法在 `js` 文法下是否解析**，故列为实施步骤而非既定设计。

---

## 5. 引擎改动

| 位置 | 现状 | 改为 |
| :--- | :--- | :--- |
| `semgrep_engine.go:305` `isSourceFile` | 硬编码 `.py .go .c .cpp .cu .h .hpp .java .sh` | 扩到 GA-11 全集：补 `.cs .cjs .js .jsx .mjs .php .tpl .phtml .rb .scala .tf .tofu .hcl .tfvars .ts .tsx .pyi .ipynb` |
| `semgrep_engine.go:48` `DefaultSemgrepRulesPath` | `.../rules/python/rules.yaml` | `.../rules`（目录） |
| `scanner.go:24` `SkipDirs` | `.git __pycache__ .idea .vscode node_modules venv .venv` | 补 `vendor`（Go）、`target`（Maven/Scala）、`dist`、`build`、`.tox`、`bower_components`、`Pods` |

**注意**：`isSourceFile` 扩容后，之前扫不到的 GA 语言文件会**第一次进入扫描**。这是本次改动的主要行为变化。

---

## 6. 验证策略

**盘上已有的非 Python 样本**（来自上游 `holdout-sources/semgrep-rules-develop` 与 `codeql`）：

| 语言 | 样本数 | 语言 | 样本数 |
| :--- | ---: | :--- | ---: |
| Go | 248 | C# | 49 |
| JavaScript | 200 | TypeScript | 28 (+21 tsx) |
| Java | 135 | Scala | 23 |
| Ruby | 94 | Kotlin | 14（超范围） |
| PHP | 66 | | |

**这批是上游规则的测试夹具，不是 benchmark**：文件小、部分刻意合成，只能做**冒烟**（证明规则能加载、能在真实
该语言代码上跑通、不报错），不能支撑非劣判定。

要达 PyPI benchmark 的对等标准，需逐语言从对应生态取真实包（npm / Maven / RubyGems / Packagist / NuGet /
Go modules），建 holdout manifest。这是与 §3 规则编写**同等重要**的产出，不是附属工作。

**过渡期姿态**：advisory 语义下新语言包可先接入观测（不会阻断任何东西），但报告需标注「该语言暂无 benchmark
背书」，避免读者把冒烟通过误读为已验证。

---

## 7. CPG 跨语言：分期与待决

CPG 六层中 **L3/L5/L6 是图通用层**，跨语言可白跟随；**L1/L2/L4 是每语言重写的**：

| 层 | 现状 | 跨语言代价 |
| :--- | :--- | :--- |
| L1 AST | `ast_bridge.go:187` 用 `python3 -c` + stdlib `ast` | 需每语言一个解析前端。`CGO_ENABLED=0` 排除 go-tree-sitter |
| L2 符号 | `resolver.go` 是 Python 导入语义（`.py`/`__init__`/相对导入 `level`） | Go packages、Java classpath、C headers、node_modules 互不相通，逐语言重写 |
| L4 微服务 | `microservice.go` 是 `requests/httpx/urllib` + Flask/FastAPI | 换语言 = 换整套框架知识 |
| L3/L5/L6 | 图通用 | 白跟随 |

**L1 的三条路**：
1. 每语言一个外部 AST dumper（现 Python 路径的推广）——但 C#/Java/JS 没有 stdlib 对等物；
2. semgrep 自身的 AST dump（`AST_generic`）——**有损**且 schema 不承诺稳定，不适合当 CPG 的承重接口；
3. 手写解析器——每语言一个项目。

**Go 是唯一零成本的起点**：`go/parser` + `go/ast` 在标准库里，TAA 本身用 Go 构建，无需 cgo、无需外部进程。
第一门语言选 Go 可以把 `SourceParser` 这道缝打通而几乎不花解析器成本。

**建议**：规则矩阵先行（§1–6），CPG 单独立项，先以 Go 打通缝再谈其余 9 门。这条不建议与规则矩阵同批做——
量级不同。

---

## 8. 待决项

1. **JS/TS 是否合并**为一个 `languages: [js, ts]` 包（需实测）。
2. **逐语言 benchmark 的取样来源与规模**：是否本轮就建，还是先冒烟接入、benchmark 后补。
3. **`.ipynb` 单元格抽取**是否作为引擎改动纳入（而非仅 JSON 文本匹配）。
4. **CPG 的 L1 路线选型**（§7 三条路）与首门语言。
