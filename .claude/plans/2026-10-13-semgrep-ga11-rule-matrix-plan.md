# Semgrep GA-11 语言规则矩阵实施计划（2026-10-13）

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 TAA 的 Semgrep 规则矩阵从 5 门语言扩到 GA 档 11 门，并让引擎真正纳管这些语言的源文件。

**规范:** `.claude/specs/2026-10-13-semgrep-ga11-rule-matrix-design.md`

**前置事实（已核）:**
- 审计裁决已改为**仅供参考**（`b3d4775`）：错规则不阻断导入，只影响报告。
- 规则目录机制已在 `2026-09-30` 规范中交付，`--config` 已支持目录；每包声明 `languages:`，无 `paths:` 过滤。
- 当前规则包：python 13 / go 6 / java 1 / c 1 / shell 3。

**关键约束:** 与并发会话共用同一检出——**禁止变异共享文件、禁止并行跑测试**；提交用显式 pathspec；
`.claude/` 在 `.gitignore` 内，spec/plan 需 `git add -f`。

---

## 阶段规划概览

| 阶段 | 目标 | 核心输出 |
| :--- | :--- | :--- |
| **Phase 0** | 引擎前置：目录化加载 + 扩展名纳管 + SkipDirs | `semgrep_engine.go`, `scanner.go` |
| **Phase 1** | 存量包补齐：go 6→13、java 1→13 | `go/rules.yaml`, `java/rules.yaml` |
| **Phase 2** | 新建 6 门通用语言包 | `csharp/ javascript/ php/ ruby/ scala/`（5 个，见 Phase 2 说明） |
| **Phase 3** | 新建 Terraform(5) 与 JSON(2) 包 | `terraform/rules.yaml`, `json/rules.yaml` |
| **Phase 4** | 冒烟验证（上游夹具）+ 报告标注 | `semgrep_multilang_test.go` |
| **Phase 5**（后补） | 逐语言真实语料 benchmark | holdout manifests |

---

## Phase 0: 引擎前置

**Files:**
- Modify: `internal/codeaudit/semgrep_engine.go`
- Modify: `internal/codeaudit/scanner.go`
- Test: `internal/codeaudit/semgrep_multilang_test.go`

- [x] **Step 1: 写失败测试**——断言 `isSourceFile` 对 GA-11 全集扩展名返回 true：
  `.cs .cjs .js .jsx .mjs .php .tpl .phtml .rb .scala .tf .tofu .hcl .tfvars .ts .tsx .pyi`，
  且对权重/二进制后缀（`.pt .bin .safetensors .onnx`）返回 false。
- [x] **Step 2: 跑测试确认失败**：`go test ./internal/codeaudit/ -run TestIsSourceFileGA11`
- [x] **Step 3: 扩 `isSourceFile`**（`semgrep_engine.go:305` 的 switch）。
- [x] **Step 4: 改 `DefaultSemgrepRulesPath`**（`:48`）为规则目录，并更新其注释说明目录分发依赖各包的
  `languages:` 声明。
- [x] **Step 5: 补 SkipDirs**（`scanner.go:24`）：加 `vendor target dist build .tox bower_components Pods`。
  写测试断言这些目录名被跳过。
- [x] **Step 6: 加"全量规则目录可加载"的校验**——遍历 `rules/*/rules.yaml`，断言每包可解析、`languages:`
  非空、rule id 以 `taa-` 开头且唯一。这是 §4 风险（一个包写错拖垮整次扫描）的护栏。
  - 实现时这条断言长成了 `TestRulePacksAreWellFormed` + `TestRulePacksValidateWithSemgrep` 两条，覆盖四件事：
    (1) 每个 `- id:` 块**恰好一条** `rule_family`（按块切片比对，而不是比总数——两条互相抵消的编辑看不出来，
    而"没有 family 的规则"会让整次扫描失败）；(2) id 形如 `taa-<family>-<lang>` 且与 `rule_family` 指向同一
    族（引擎按 family 取 severity/category，名实不符 = 一次静默的 severity 变更）；(3) 规则文件里的
    `severity:` 必须等于该 family 在 `DefaultRules()` 里的 severity；(4) semgrep 自己的
    `found 0 configuration error(s), and N rule(s)` 里 N 必须等于盘上规则实数（115），因为真正读这些文件的
    是 semgrep，不是这段文本 lint。
- [x] **Step 7: 跑测试 + 提交**——已入 `4d652a2 feat(codeaudit): admit the GA-11 extensions and load the whole
  rules tree`（消息与本节拟定的不同：该提交把扩展名纳管与整棵规则树加载并在了一起）。

> **注意**：Step 3 之后，此前扫不到的 GA 语言文件会第一次进入扫描。这是本阶段的主要行为变化。

---

## Phase 1: 存量包补齐到 13 族

**Files:**
- Modify: `models/audit/semgrep/rules/go/rules.yaml`（+7）
- Modify: `models/audit/semgrep/rules/java/rules.yaml`（+12）

- [x] **Step 1: 对照 Python 包逐族列缺口**。go 缺：`obf-exec`、`secret-exfiltration`、`per-backdoor`、
  `emb-data-dump`、`emb-copy-export`、`emb-log-dump`、`emb-stego-weight`。java 缺 12 族。
- [x] **Step 2: 补 Go 包**——`go:linkname`/`plugin.Open`（OBF）、taint 模式（EXF）、`os/user` +
  写 `~/.bashrc`/cron（PER）、`os.WriteFile` 落盘（EMB_*）。
  - **`go:linkname` 那条 arm 原本永远不会命中**：它写成 `^(?![ \t]*//)[^\n]*go:linkname`，而该指令只能以
    行注释形式生效，守卫恰好把唯一有效写法排除，剩下的匹配面只有"把 `go:linkname` 写进字符串字面量"——唯一
    不是指令的写法（实测确认）。已改为 `^[ \t]*//go:linkname\b`（**不带**注释守卫），并在包内注释写明为什么
    这一族是"注释行本身即 finding"的例外。修正后 go 冒烟夹具上的 OBF 命中数上升。
- [x] **Step 3: 补 Java 包**——`Class.forName` + `defineClass`/`ScriptEngine`（DYN/OBF）、`Files.*`
  （FIL/EMB_*）、`System.getenv`（ENV）、`Base64` + `defineClass`（OBF）、taint（EXF）、
  `Runtime.addShutdownHook`/cron（PER）。
- [x] **Step 4: 每族 severity 与 Python 包对齐**（见规范 §3 表）。
  - **实测推翻了一处"已对齐"的假设**：go 包的 `taa-dyn-eval-go` 与 `taa-fil-probe-go` 写的是 `ERROR`，而表里
    两族都是 medium（python 包写的是 WARNING）。引擎从不读规则文件的 severity，所以这处漂移**不会被任何扫描
    发现**——它只骗读文件的人。已改为 WARNING，并把"规则文件的 severity 必须等于该 family 在表里的 severity"
    做成校验用例的断言（此后 12 个包全部通过）。
- [x] **Step 5: 校验测试 + 提交**——已入 `0acf0e4 feat(audit): fill the go and java rule packs to family
  parity`。

---

## Phase 2: 6 门通用语言新包（各 13 族）

**Files:** `models/audit/semgrep/rules/{csharp,javascript,php,ruby,scala}/rules.yaml`

> **与本节拟定不符之处（实测裁定，规范 §4 已记）**：原定 6 个包，实际 5 个。Step 1 测出
> `languages: [js, ts]` 一个包同时命中 `.js` 与 `.ts`，且文法通用（`positive.ts` 13/13、`positive.js`
> 5/5），于是**不再单列 `typescript/` 包**；TS 没有需要独立成包的差异，多一个包只会多一份要同步维护的
> 副本。`javascript/rules.yaml` 因此声明两种语言。

- [x] **Step 1: 先定 JS/TS 合并策略**（规范 §8 待决项 1）。实测一个 `languages: [js, ts]` 的试探规则能否
  同时命中 `.js` 与 `.ts`；能则公共族合并为一个包，TS 包只留类型相关差异。**先测再写**，不要先写 26 条
  再发现文法不通用。
- [x] **Step 2: 按语言补 sink 表**，每族一个 `pattern-either`：
  - C#：`Process.Start`、`HttpClient`、`Socket`、`Activator.CreateInstance`/`Reflection.Emit`、`File.*`、
    `Environment.GetEnvironmentVariable`、`Convert.FromBase64String`+`Assembly.Load`、
    `Microsoft.Win32.Registry` Run 键（PER）。
  - JS/TS：`child_process.*`、`fetch`/`axios`/`http.request`、`net.Socket`、`eval`/`new Function`/`vm.*`、
    `fs.*`、`process.env`、`Buffer.from(..,'base64')`、`setInterval`/`cron`。
  - PHP：`system`/`exec`/`shell_exec`/`popen`/反引号、`curl_exec`、`fsockopen`、
    `eval`/`assert`/`create_function`、`file_get_contents`、`getenv`/`$_ENV`、`base64_decode`+`eval`。
  - Ruby：反引号/`system`/`Open3`/`%x`、`Net::HTTP`、`TCPSocket`、`eval`/`instance_eval`、`File.read`、
    `ENV[]`、`Base64.decode64`+`eval`。
  - Scala：`scala.sys.process`、`java.net.*` 互操作、`scala.io.Source`、`sys.env`、`scala.reflect`。
- [x] **Step 3: EXF 族用 `mode: taint`**，source/sink/sanitizer 三件套与 Python 包同构（这是 Python 包里
  唯一用 taint 模式的一条，`rules.yaml:223`）。
- [x] **Step 4: 每条规则写注释说明**「为什么这么写、对过哪个样本」——这是 Python 包的既有体例（386 行 / 13 条），
  也是后续调参的唯一依据。
- [x] **Step 5: 校验测试 + 提交**——已入 `f64fd12 feat(audit): add the csharp, javascript, php, ruby,
  scala, terraform and json packs`。**与 Phase 3 合成一个提交**：两阶段产出的是同一种东西（新增规则包），
  拆开只会得到"7 个包，其中 2 个在下一个提交里"这种没有读者的切法。

---

## Phase 3: Terraform(5) 与 JSON(2)

**Files:** `models/audit/semgrep/rules/{terraform,json}/rules.yaml`

- [x] **Step 1: Terraform 5 族**——CMD=`provisioner "local-exec"/"remote-exec"`、
  NET_GENERAL=`data "http"`、ENV=硬编码凭据、EXF=涉密 variable→local-exec、EMB_DATA_DUMP=`local_file`。
  其余 8 族按规范 §3 标为结构性 N/A，**不写死规则**。
- [x] **Step 2: JSON 2 族**——ENV=配置内硬编码密钥、及 `.ipynb` 文本匹配。
- [x] **Step 3: 在包内注释写明 N/A 理由**，让后续读者知道缺失是有意的而非遗漏。
- [x] **Step 4: 校验测试 + 提交**——已入 `f64fd12`（与 Phase 2 同一提交，见上）。

---

## Phase 4: 冒烟验证

**Files:** `internal/codeaudit/semgrep_multilang_test.go`

- [x] **Step 1: 用盘上上游夹具建冒烟集**——`holdout-sources/semgrep-rules-develop` 与 `codeql` 下的
  js 200 / go 248 / java 135 / rb 94 / php 66 / cs 49 / ts 49 / scala 23。**只做冒烟**（规则能加载、
  能在真实该语言代码上跑通、不 panic、不报错）。
  - 最终一次跑（907.8 s，9 门全 PASS、全 `truncated=false`）的逐语言命中与族分布已记入规范 §6 的表。
    两点必须照实读：go 只点亮 3 族、terraform 只点亮 2 族是**语料没有那些 sink**，不是规则失效；go 一行与
    上一次运行逐位相同，因为上游夹具里一条 `//go:linkname` 都没有（`grep` 命中 0），所以那条 arm 的修正
    在冒烟上零证据，其证据在样本 `positive.go:18`。
- [x] **Step 2: 为每门语言各写至少一条正例与一条反例**，断言命中/不命中——上游夹具是别人规则的测试文件，
  不保证含 TAA 目标模式。
  - **反例必须是 near-miss，这条是评审改出来的**：初版 csharp/java/go 三条反例是纯数学/列表 helper，
    一个该语言包监视的 API 都没调过，于是"删掉某条规则的谓词"测不出来（反例照样零命中、测试照样绿）。
    三条反例已重写为 near-miss：每个能收窄的族都有它的 sink 形状，实参刻意不满足该族的谓词；文件头逐族点名
    说明失败了哪条谓词、以及哪几个族**结构上无法**出现在反例里（`cmd-exec`/`net-*`/`dyn-eval`/`obf-exec`
    的规则对实参没有任何谓词，出现即命中）。
  - **near-miss 是变异测出来的**：剥掉每条收窄规则的谓词（taint 规则退化为"裸 sink 即命中"）再扫反例，
    要求从零命中变命中——实测 java 6/6、csharp 6/7、go 5/6；静默的两个都是 `secret-exfiltration`，因为
    这两包里 EXF 的 sink 是 NET_001 无谓词分支的子集，反例里不能出现该形状（java 的 EXF 变异命中
    `negative.java:122`）。**该变异脚本在 `/tmp`，未入库**，改动反例后需手工重跑。
  - **decoy 检查也重写过**：原断言是"把 `decoy.json` 交给 semgrep，`paths.scanned` 必须为 1"，实测**不成立**
    ——被 `paths` 过滤掉的文件根本不进 `paths.scanned`，于是"零命中"是在说一个没被读的文件。改为**同字节换
    扩展名**的对照：`json/decoy.json` 与 `jsonfilter/decoy.ipynb` 逐字节相同，前者不被读、后者被读且两个规则
    都命中；并断言引擎的一致性检查会把"被过滤掉的 target"变成一次失败扫描而非干净的空扫描。
- [x] **Step 3: 在报告里标注语言级覆盖状态**——哪些语言有 benchmark 背书、哪些只过了冒烟。规范 §6 要求读者
  不能把冒烟通过误读为已验证。
- [x] **Step 4: 提交**——已入 `d2e40d8 test(audit): make the GA-11 samples discriminate, and scan them
  per language`。

---

## Phase 5（后补）: 逐语言真实语料 benchmark

- [ ] 逐语言从对应生态取真实包（npm / Maven / RubyGems / Packagist / NuGet / Go modules），
  建 holdout manifest，与 PyPI benchmark 对等。
- [ ] 按「证据先于接入，0 容差非劣判定」跑一次非劣判定，再把该语言从「仅冒烟」升级为「已验证」。

---

## CPG 跨语言（独立立项，不与本计划同批）

规范 §7 已列 L1 三条路与 L2/L4 的逐语言代价。建议起点是 **Go**（`go/parser` + `go/ast` 在标准库，
零 cgo、零外部进程），先打通 `SourceParser` 缝再谈其余 9 门。**待用户裁定 L1 路线后再立计划。**
