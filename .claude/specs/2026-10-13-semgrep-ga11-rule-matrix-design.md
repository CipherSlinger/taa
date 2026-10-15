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

布局沿用既有约定，新增 7 个目录（`go`/`java` 是补族，不是新建；原方案的 `typescript/` 已按下方实测结论并入
`javascript/`）：

```text
models/audit/semgrep/rules/
├── python/rules.yaml      # 13（基准，不动）
├── go/rules.yaml          # 6 → 13
├── java/rules.yaml        # 1 → 13
├── csharp/rules.yaml      # 新建 13
├── javascript/rules.yaml  # 新建 13（languages: [js, ts]，不再单列 typescript 包，见下）
├── php/rules.yaml         # 新建 13
├── ruby/rules.yaml        # 新建 13
├── scala/rules.yaml       # 新建 13
├── terraform/rules.yaml   # 新建 5
├── json/rules.yaml        # 新建 2（rule 级 paths 过滤到 *.ipynb）
├── c/rules.yaml           # 既有（Alpha，不动）
└── shell/rules.yaml       # 既有（Alpha，不动）
```

**加载机制**：`semgrepEngine.semgrepArgs`（`semgrep_engine.go`）把 `rulesPath` 作为 `--config` 传给 semgrep，而
该字段的注释已写明「the semgrep rules file **or directory**」。因为每个包都正确声明了 `languages:`，把
`--config` 指向规则目录即可让 semgrep 自身按语言分发，**不需要按语言分别调用**。

改动：`DefaultSemgrepRulesPath`（`semgrep_engine.go`）由单文件改为目录。

**风险（必须处理）**：目录化后 semgrep 会校验**全部**规则文件，任一个包语法错误会让整次扫描失败 →
`reportAudit` code=2。advisory 语义下这不再阻断导入，但仍会让审计整体失去结论。缓解：加一个启动期/测试期
「加载全部规则目录」的校验用例。

**JS/TS 合并（已实测，取代原「新建 typescript 包」方案）**：semgrep 规则可声明多个语言（既有 `c/rules.yaml`
的 `languages: [c, cpp]` 与 `shell/rules.yaml` 的 `[bash, sh]` 就是先例）。实测 `languages: [js, ts]` 的探针
规则**同时命中 `.js` 与 `.ts`**（semgrep 1.177.0）。TypeScript 的运行时面就是 JavaScript 的：类型标注、接口、
泛型不携带安全语义，所以第二个包要么在 `.ts` 上重复每一条命中，要么逐族与此包完全同义。**故只保留
`javascript/` 一个包，不建 `typescript/` 目录**；`isSourceFile` 仍纳管 `.ts/.tsx` 作为扩展名。

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

**盘上已有的非 Python 样本**（来自上游 `holdout-sources/semgrep-rules-develop` 与 `codeql`）。下表为 2026-10-15
实测的**按扩展名计数**；「子树」列是冒烟测试实际扫描的目录（该语言自己的 `lang/` 子树）内的纳管文件数：

| 语言 | 全树计数 | 子树扫描数 | 语言 | 全树计数 | 子树扫描数 |
| :--- | ---: | ---: | :--- | ---: | ---: |
| Go | 248 | 89 | C# | 49 | 48 |
| JavaScript | 200 | 159 | TypeScript | 28 (+21 tsx) | 10 (+5 jsx) |
| Java | 135 | 116 | Scala | 23 | 23 |
| Ruby | 94 | 85 | Terraform | 366 | 366 |
| PHP | 66 | 65 | Kotlin | 14（超范围） | — |
| Python（`codeql/`，CWE 夹具） | 102 | — | `.ipynb` | 0 | 0 |

**这批是上游规则的测试夹具，不是 benchmark**：文件小、部分刻意合成，只能做**冒烟**（证明规则能加载、能在真实
该语言代码上跑通、不报错），不能支撑非劣判定。

**冒烟必须证明它真的扫了文件（2026-10-15 实测，这是本节最容易踩的坑）**：上游夹具树自带
`.gitignore` 与 `.semgrepignore`，把目录直接交给 semgrep 会**静默扫 0 个文件并退出码 0**
（`results=0, errors=[]`——一次"干净"的空扫描）。加 `--no-git-ignore` 后同一目录得到 26 条命中。
引擎不受影响（它传**显式文件清单**且已带 `--no-git-ignore`，并断言 `paths.scanned` 覆盖每个 target）；
但冒烟测试与任何手工验证都必须带上这个 flag，或断言语料文件数 > 0，否则"通过"二字没有内容。

**成本已测**：约 **0.85 s/文件**（89 个 Go 夹具 76 s）。terraform 子树 366 个文件会超过
`DefaultSemgrepTimeout`（5 分钟），故冒烟用例显式放宽期限，并且只在设置了语料根环境变量时运行。

**冒烟实测结果**（2026-10-15 最终一次，总 907.8 s，每一门 `truncated=false`）：

| 语言 | 扫描文件 | 命中 | 命中的族（族:命中数） | 耗时 |
| :--- | ---: | ---: | :--- | ---: |
| python | 102 | 103 | CMD 20 / DYN 4 / NET 47 / NET_SOCKET 30 / OBF 2 | 1m25s |
| csharp | 48 | 79 | CMD 12 / NET 61 / OBF 6 | 43s |
| go | 89 | 26 | CMD 11 / NET 9 / OBF 6 | 1m15s |
| java | 116 | 186 | CMD 19 / DYN 77 / ENV 2 / NET 49 / NET_SOCKET 9 / OBF 30 | 1m38s |
| javascript（含 ts/tsx/jsx 子树） | 174 | 91 | CMD 26 / DYN 33 / EMB_DATA_DUMP 6 / EMB_LOG_DUMP 3 / ENV 8 / NET 8 / NET_SOCKET 1 / OBF 5 / PER 1 | 2m23s |
| php | 65 | 49 | CMD 20 / DYN 9 / NET 11 / OBF 9 | 57s |
| ruby | 85 | 104 | CMD 41 / DYN 19 / ENV 5 / NET 9 / OBF 30 | 1m14s |
| scala | 23 | 45 | CMD 16 / DYN 13 / NET 16 | 24s |
| terraform | 366 | 7 | CMD 1 / ENV 6 | 5m10s |

**这张表证明的是"每包能在别人的真实代码上加载、跑通、读到每个文件、并且至少命中一行"，不是逐族覆盖**：
go 在 89 个夹具上只点亮 3 族、terraform 只点亮 2 族，这里缺的族**不能**读成失效——这些是上游规则的测试文件，
里面本来就没有那些 sink（`cmd-exec`/`net-general` 之所以四处开花，正是因为它们的规则对实参没有谓词）。

**没有变化的地方不要写成有变化**：go 一行与上一次运行**逐位相同**（26 命中、OBF 6），而
`grep -r go:linkname` 在整个 `holdout-sources` 下**命中 0**——上游夹具里一条 `//go:linkname` 都没有，
所以那条 arm 的修正**不可能**在这批语料上体现，冒烟对它零证据。它的证据在样本里：`positive.go:18` 的
`//go:linkname runtimeNanos runtime.nanotime` 现在命中（修前带注释守卫的 arm 只可能命中把它写进字符串
字面量的代码，那正是唯一不是指令的写法）。javascript 的 174 = 159 js + 10 ts + 5 tsx/jsx，即两种扩展名的
子树合起来扫——这是 `languages: [js, ts]` 在真实语料上的旁证，而不只是探针规则的结论。

**每门语言的正/反例**（不依赖语料，永远运行）内嵌在 `internal/codeaudit/semgrep_multilang_test.go`：
正例覆盖该语言全部族、反例必须零命中。上游夹具是**别人**规则的测试文件，不保证含 TAA 目标模式，
所以"在夹具上零命中"不能被读成"规则正确"。

**反例必须是 near-miss，不能只是"普通代码"**：反例文件含该语言**所有能收窄的族**的 sink 调用形状，只是实参
刻意不满足该族的谓词（`os.Open` 换成普通路径、`System.getenv` 换成非涉密变量……）。理由是这类规则的风险
形态是**谓词被放宽或删掉**——若反例里根本没有那个 sink，把 `taa-fil-probe-<lang>` 的路径谓词删成"匹配任意
`os.Open`"之后，反例仍然零命中、测试仍然绿，规则却已经静默变宽。初版把 csharp/java/go 的反例写成纯数学/
列表 helper，正是踩了这个坑：删掉谓词测不出来。

**但有几个族压根没有谓词可删**：`cmd-exec`、`net-general`、`net-socket`、`dyn-eval`、`obf-exec` 在设计上就是
"原语出现即命中"（`Runtime.getRuntime().exec(...)`、`new Socket(...)`、`Class.forName(...)`、
`Base64.getDecoder().decode(...)`……），与 Python 基准包同构。对它们**不存在**"良性实参"，因此反例里不能写这些
sink，写了就是一条 finding。这是一个结构性的边界而非样本偷懒：**这几族的回归证据只能来自正例**——正例证明
"能命中"，但没有反例能证明"不会误命中"。java 反例因此只覆盖 8 个能收窄的族，文件头注释逐族点名了缺哪五个。

**near-miss 是测出来的，不是声明出来的（2026-10-15 变异测量）**：把三个包里每条收窄型规则的谓词
（`metavariable-regex` / `metavariable-pattern`）剥掉、把 taint 规则退化成"裸 sink 即命中"，再用剥后的**单规则**
配置去扫对应反例，要求它从零命中变成命中。实测：**java 6/6 命中、csharp 6/7、go 5/6**。唯一静默的是 csharp 与
go 的 `secret-exfiltration`，原因正是上一条——这两包里 EXF 的 sink 是 NET_001 无谓词分支的子集，反例里根本
不能出现该形状，所以它静默是结构性的、与反例的取舍一致；**java 的 EXF 变异命中（`negative.java:122`）**，因为
Java 的 EXF sink（`$OUT.write($DATA)`）不在 NET 的分支里，那一族因此有真实的反例背书。两点如实说明：(1) 这个
变异是**一次性测量**（脚本在 `/tmp`，未入库），所以"删谓词即变红"这条性质不会在每次 `go test` 里被重新验证——
改动任一反例文件后需要手工重跑；(2) 行内合取型的两族（`emb-stego-weight`、`per-backdoor` 的文本分支）没有被
变异覆盖，因为它们的"谓词"是同一行的两个字面词，剥掉的等价操作不是删元变量而是删词。

**正例同样会漏 arm，而且漏了不会变红**：`taa-fil-probe-go` 有两条 arm——`os.ReadFile($PATH)` 配涉密路径谓词，与
`filepath.Join($DIR, $BASE)` 配涉密 `$BASE`。原先 `positive.go` 只有一条**三参数** `filepath.Join(HOME, ".ssh",
"id_rsa")` 的调用，它只能匹配第一条 arm（三参数的调用不匹配二参数 pattern），于是第二条 arm 的命中证据**只剩
变异测量**，而族级覆盖率断言照样通过——因为族已经被第一条 arm 点亮了。已补一条二参数 join（`positive.go:54`），
两条 arm 现在各自有正例背书。**这是"族覆盖"与"arm 覆盖"的差别：断言写在族上，arm 死了看不出来。**

**三门语言没有样本行，缺口写在这里而不是留白**：`python` 是基准包，其逐族对等由
`TestGoEngineMatchesBenchmarkRegexArm`（`TAA_CORPUS_PARITY=1`）在真实语料上端到端把守，手写样本只会给出
更弱的重述；`c` 与 `shell` 是本次不动的两个 Alpha 包（1 条与 3 条规则），由
`TestSemgrepEngine_MultiLanguageRules` 覆盖。矩阵表里没有它们，因此**这三门的某一族失效不会被样本集抓到**。

**规则 id 与族的绑定本身也是一种断言**：引擎读 `rule_family:` 元数据去 `DefaultRules()` 取 severity 与
category，所以"规则名写着 A 族、元数据指着 B 族"是**一次静默的 severity 变更**。校验用例因此不只数规则条数，
还逐条解析 `- id:` 块，断言 id 形如 `taa-<family>-<lang>` 且 `rule_family` 正是该 family 的 TAA id；semgrep
自身的 `found 0 configuration error(s), and N rule(s)` 汇总中的 N 也必须等于盘上规则的实数（115）。

**规则文件里的 `severity:` 也被钉住**：引擎从不读它（severity 一律来自 `DefaultRules()`），所以它写错只会
**骗过读规则文件的人**、骗不过引擎——go 包就曾把两个 family 写成 `ERROR` 而表里是 medium。正因为它不会让任何
扫描失败，唯一的守卫只能是测试：校验用例现在把每条规则的 `severity:` 与该 family 在表里的 severity 逐条比对
（`HIGH→ERROR`、`MEDIUM/LOW→WARNING`）。这条断言加进来时正好抓到 go 包那两处漂移。

要达 PyPI benchmark 的对等标准，需逐语言从对应生态取真实包（npm / Maven / RubyGems / Packagist / NuGet /
Go modules），建 holdout manifest。这是与 §3 规则编写**同等重要**的产出，不是附属工作。

**过渡期姿态**：advisory 语义下新语言包可先接入观测（不会阻断任何东西），但报告需标注「该语言暂无 benchmark
背书」，避免读者把冒烟通过误读为已验证。

### 6.1 本轮实测到的 semgrep 行为（写规则时必须遵守）

| 事实 | 影响 |
| :--- | :--- |
| 字符串字面量元变量在不同语言里**绑定形式不同**：C# 不带引号绑定，Java 带引号绑定，Terraform 同为 HCL 却**块标签不带引号、属性值带引号** | 路径/名称谓词一律**不带引号**书写（点号不会出现在标识符里，两种绑定下都成立）；带引号的写法在 C# 上会匹配不到任何东西，且**静默**——该族直接消失 |
| 引擎**没有按行去重**：每条 semgrep 结果都变成一条 finding | 同一规则的多个分支不得匹配同一行；否则该族计数被自身翻倍 |
| `mode: taint` 对 **terraform 是静默空操作**（source 与 sink 在同一节点也不命中，且不报错） | terraform 的 EXF 是**结构性近似**，包内注释已声明它不追踪取值 |
| 规则级 `paths: include: ["*.ipynb"]` 在 target 以**显式文件**传入时依然生效 | json 包用它把覆盖限定在 notebook，`isSourceFile` 则把 `.json` 挡在行走之外；两侧互为保险 |
| 被 `paths` 过滤掉的文件**不进入 `paths.scanned`**：只把 `decoy.json` 交给 semgrep，得到 `scanned=[] results=[] errors=[]`（2026-10-15 实测） | 「把它交给 semgrep、看它零命中」这个断言**本身是空的**——零命中说的是一个没被读的文件。有效的做法是**同字节换扩展名**的对照：`decoy.json` 与逐字节相同的 `decoy.ipynb`，前者不被读、后者被读且两个规则都命中。反过来，引擎自身的一致性检查（每个 target 必须出现在 `paths.scanned` 里）把"walk 放进来的数据文件被 pack 过滤掉"变成**一次失败的扫描**，而不是一次干净的空扫描——两半于是互为硬约束，而不是两个碰巧一致的设置 |
| 行文本规则惯用的 `^(?![ \t]*//)` 守卫会把它**想抓的**注释型指令一并排除 | Go 的 `//go:linkname` 只能以行注释形式生效，而那条 arm 带着这个守卫，于是**永远不可能匹配真正的指令**，只可能匹配到写了这个词的字符串字面量（正是唯一不是指令的写法）——一条永不命中的死 arm。实测确认后改为锚定指令本身（`^[ \t]*//go:linkname\b`，**不带**守卫）。写文本规则时先问一句"我要抓的东西，会不会正好被我的注释守卫排除" |
| 引擎的 finding 上限（`Config.MaxFindings`，默认 200）是**整次扫描的、排序之后**的截断，且 semgrep 是**每条匹配一条 finding**而非每条规则一条 | 多种语言的样本放进一次扫描会被截断，且切掉的是排序后的**尾部**：实测 20 个样本文件 → 200 条 finding、`Truncated=true`，尾部正好是字典序最后的三门语言（ruby 只剩前 3 族、scala 与 terraform 归零），扫描**照样报成功**。于是"族失效"和"被上限切掉"在结果上无法区分——冒烟与回归必须**按语言分次扫描**，并断言 `Truncated` 为假 |

最后一条对生产也有含义：GA-11 把命中面从 1 门语言扩到 10 门（13 族 × 10 + terraform 5 + json 2），
同一个包过去远低于 200 条上限，现在会**更早触到**，`Truncated` 因此从边角状态变成常见状态——
报告消费方若不读这个标记，就会把被截断的报告当成完整的。

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
