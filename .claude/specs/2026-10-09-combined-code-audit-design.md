# 合并代码审计：模型代码 + 当前依赖集（2026-10-09）

## 1. 触发

TAA 今天的代码审计是**两条彼此独立的链路**：

| 触发 | 审计目录 | `reportAudit` 的 `scope` |
| :--- | :--- | :--- |
| `/v1/taa/importModel` 解压完成后 | `Security.ModelDir` | `""` |
| `/v1/taa/importDeps` 安装完成后 | `<depsDir>/<sm3>` | `"deps"` |

两条链路各扫各的目录、各出一份报告、各上报一次。后果是：**「模型代码 + 它实际加载的依赖」作为一个整体从未被审计过。**

这不是形式问题。训练运行时把依赖目录注入为 `TAA_DEPS_DIR` 并**前插**到 `PYTHONPATH`
（`internal/controller/deps_env.go:19-36`），所以模型代码里的 `import numpy` 解析到的是
`<depsDir>/<sm3>/numpy`。跨这两者的数据流——依赖侧提供污染的符号、模型代码把它外发——
**不在任何一次扫描的视野里**：模型审计看不见依赖目录，依赖审计看不见调用方。
依赖审计自己的注释也把「静态扫描对 wheel 内 `.so`/`.pyd` 无效」列为盲区
（`internal/controller/deps_audit.go:20-31`），但真正的缺口比这更大：它连纯 Python 层面的
跨目录污点都覆盖不到，因为符号索引只在一个 root 上建。

本方案要求：**无论下发模型还是下发依赖，都重新触发一次覆盖「完整模型代码 + 当前依赖集」的
合并审计，然后重新上报一次 `/v1/taa/reportAudit`。**

## 2. 现状事实（已核对）

### 2.1 审计引擎是单根的

- 入口 `GenerateAuditReport(ctx, dir string, engine, cfg, client)`
  —— `internal/codeaudit/verifier.go:320`，`dir` 是**单值 string**，无重载、无 slice 变体。
- 遍历由引擎完成：`StaticEngine` 接口的三个方法
  `ScanDirectory(dir)` / `ScanDirectoryWithLines(dir)` / `Name()`
  —— `internal/codeaudit/engine.go:27-38`，全部单目录。
  实现只有两个：`regexEngine`（`engine.go:46`）与 `semgrepEngine`（`semgrep_engine.go:74`）。
- 全仓 `ScanDirectory*` 的调用点都是单目录，**没有任何多目标先例**。

### 2.2 semgrep 侧天然能容纳多 target，Go 侧不能

- `semgrepArgs`（`semgrep_engine.go:333-350`）本来就是 `append(args, targets...)`，
  且**从不把目录交给 semgrep**——它自己 walk 出显式文件路径再传（`semgrep_engine.go:69-73`
  说明了理由：目录 target 会下钻 `venv/`、`__pycache__/`）。传多个路径对 `semgrep scan` 合法。
- 完成度校验按 `cleanAbs` 归一后比对 `paths.scanned` 与 targets
  （`semgrep_engine.go:385-398`），对任意 target 集合成立。
- **真正的障碍在 Go 侧**：`enrichFindingsWithCPG(dir, targets, findings)`
  （`semgrep_engine.go:232`）与 `NewSymbolResolver(dir)`（`cpg_analysis.go:169-172`）
  都以**单一 root** 建符号索引。

### 2.3 符号链接合成根目录走不通

`filepath.Walk` / `filepath.WalkDir` 用 `os.Lstat`，**不跟随符号链接**
（`scanner.go:76`、`scanner.go:270`、`semgrep_engine.go:277`、`cpg/resolver.go:50`）。
一个指向模型/依赖目录的**目录** symlink 会被当成非目录直接跳过，两个引擎都扫不到。
只有往合成根里放**真实文件**（复制或硬链接）才可行，那对 GB 级 wheel 不成立。

### 2.4 既有的两道清理闸门

- 模型审计失败：`cleanDirContents(s.Security.ModelDir)`
  （`import_processing.go:631`、`:641`、`:654`）——清内容、**保留目录本身**
  （`import_helpers.go:74-77` → `utils.CleanDir`，`pkg/utils/file.go:107-122`）。
- 依赖审计失败：`rollbackDepsImport(depsDir)`（`deps_import.go:275-285`）——删掉这个
  `<sm3>` 目录，**且仅当它正是当前绑定的那一套时才清绑定**。

### 2.5 依赖的幂等标记

`<depsDir>/<sm3>/.taa_audit_ok`，内容必须是 `depsAuditMarkerVersion`
（`deps_import.go:209`、`:224`）。命中即短路：不解包、不安装、不审计，直接置状态并
`reportDeps` 成功（`deps_import.go:120-128`）。只在真跑过并通过对时写
（`deps_import.go:186-199`），`ScanEnabled=false` 的跳过**不写**
（`deps_import.go:330-333`）。

### 2.6 并发闸门

`tryAcquireTaskTyped`（`route.go:631-718`）：训练忙则拒绝一切；`model_import` 与
`deps_import` **共用同一个审计槽**（`route.go:645-654`，与 `isAuditBusyLocked`），
因此两者互斥；`isModelDataPair`（`route.go:620-626`）**不**把 `deps_import` 与任何任务配对。
推论：一次合并审计执行期间，不可能有第二次模型/依赖下发，也不可能有训练在进行。

## 3. 语义契约

### 3.1 审计范围 = 触发方本次交付的代码 ∪ 当前生效的另一侧

| 触发 | 审计根（按序） |
| :--- | :--- |
| `importModel` | `Security.ModelDir`（本次刚解压的） ＋ 当前绑定依赖目录（若已绑定且目录存在） |
| `importDeps` | `<depsDir>/<本次 sm3>`（本次刚安装的**候选**目录） ＋ `Security.ModelDir`（若模型已导入且目录存在） |

- **「所有依赖」＝仅当前生效的那一套**，即 `filepath.Join(GetDepsDir(), DepsHash)`
  （`deps_state.go:54-61`）。磁盘上历史遗留的 `<depsDir>/<旧 sm3>` 目录**不在范围内**：
  它们永久存在且无 GC（`deps_import.go:63-64` 承认这一点），但不在 `sys.path` 上，
  审计它们只会增加耗时并审到实际未生效的内容。
- 注意触发方是**候选**而非当前绑定：依赖触发的审计必须审本次刚装出来的
  `<depsDir>/<新 sm3>`，而不是 `currentDepsDir()`（`DepsHash` 要到审计通过后
  `saveDepsSuccess` 才更新）。
- 一个根只在**生效**时进入：模型根要求 `ModelImported`，依赖根要求目录 `os.Stat` 成功。
  这是为了保住「先下发依赖、后下发模型」这条既有可用路径——把不存在的目录交给审计会让
  walk 报错，进而 `code=2`，在 fail-closed 下等于把合法的依赖下发拒掉。
- 模型根恒排在前面，`AuditTarget.Directory` 取它。

### 3.2 `scope` 的取值不变，语义变了

`""` / `"deps"` 两个线上取值**一个都不动**（platform-mock 的校验
`tools/platform-mock/internal/handlers_taa.go:542-544` 不变），但含义从「审计了什么」
变成「**是谁触发的**」。两条路径的审计范围现在完全相同，`scope` 只剩溯源作用。

### 3.3 `code` = 合并审计的整体结论

`0` 通过 / `1` 未通过 / `2` 执行失败或按 fail-closed 判定 LLM 不可用。
`code` 描述的是**这一次合并审计**，不是触发方那一侧的局部结论。
因此会出现 `code=1` 而 TAA 什么都没清除、触发方任务仍然成功的情形——由 §3.4 的分根结论消歧。

### 3.4 报告新增分根结论

`AuditReport.Target` 增加 `directories []string`（本次实际覆盖了哪几个根），
并新增按根的分项列表，每项含 `directory` / `files_scanned` / `findings_count` / `passed`。
这样 `code=1` 的报文里，平台能直接看出**是哪个根出的问题**，不必靠
`file_reports[].file_path` 的前缀自行推断。

这是**纯新增**：`report` 字段在 `reportAudit` 里是不透明字符串，在训练报告里是
`codeaudit` 对象，两者都只增键；既有字段的含义一个都不改。

### 3.5 回滚：只回滚触发方那一侧，且只在触发方被牵连时

合并审计跑完后，**唯一会发生的清除是触发方自己的那一个根**：

- 触发方 = 模型 → `cleanDirContents(Security.ModelDir)`
- 触发方 = 依赖 → `rollbackDepsImport(候选目录)`

判据：`code == 2`（整体没跑成，无从区分哪一侧有问题），**或**报告里存在归属于触发方
那个根的 finding。若 findings 全在另一侧：报告与 `code` 如实反映失败，但**不删任何东西、
本次导入判成功**。

### 3.6 幂等短路取消，审计标记机制删除

- 删掉 `deps_import.go:120-128` 的短路：每次下发依赖都重新解包、重新安装、重新审计。
- 删掉 `.taa_audit_ok` 整套机制（`deps_import.go:207-240`）。
  **理由是标记本身已经不成立**：它记录的是「这套依赖目录通过了审计」，而审计结论现在
  取决于「与哪份模型代码一起扫」。标记只按依赖侧 hash 存放，模型变了它不会失效——
  `deps_import.go:219-224` 的注释自己就承认版本号是唯一的失效手柄，而版本号与模型无关。
  短路取消后 `auditMarkerExists` 没有调用方，`writeAuditMarker` 写的文件没人读。
- 磁盘上已存在的 `.taa_audit_ok` 文件**不做迁移**——无人读，无害。
- 模型侧本来就没有标记，每次都重审，不变。

### 3.7 资源闸门不动

`MaxFindings = 200`（`scanner.go:23`）与 `DefaultSemgrepTimeout = 5min`
（`semgrep_engine.go:24`）保持原值。理由与代价见 §5。

## 4. 与既有 spec 的关系

### 4.1 推翻 `2026-10-08-model-dependency-delivery-design.md:61-62`

该处写着：

> 把依赖放在 `ModelDir` **同级**的内容寻址目录，a/b/c/d 四者同时消失：
> **无需改审计范围**、无需改校验和、无需改解包流程。

「无需改审计范围」是那次设计的前提之一，本方案**直接推翻它**。需要说明的是，
它推翻的只是「审计范围不变」这一条，而**不是**「依赖放同级」这个决定——
本方案仍然要求依赖与模型目录同级（`internal/config/config.go:269-291`
`validateDepsDirPlacement` 继续强制），仍然不往 `ModelDir` 里塞任何东西。
区别只在**审计时同时看两个根**。

因此该 spec §2.4 的约束——

> `internal/codeaudit` 没有任何"忽略路径/前缀"机制，只有按扩展名的 `UnsupportedExts` 跳过。
> 这是 §2.3 中选择"同级目录"而非"目录内 + 排除"的第二个理由。

——在本方案下**不再是约束**：本方案不需要路径排除能力，因为依赖根本不在 `ModelDir` 里。
这条约束当初是为了排除「把依赖解压进 `ModelDir` 再排除掉」的方案，而该方案在本方案里
同样被否掉（理由不同：解压进 `ModelDir` 会让模型的内容校验和与 `cleanDirContents`
的清理范围都变错）。

### 4.2 订正 `scope` 取值漂移

同一份 spec `:292` 写的是：

> 在该接口新增可选字段 `scope`（`model` | `deps`，缺省 `model`，向后兼容）

而实现与 `docs/api-design.md:458` 用的是 **`""` | `"deps"`**。三方漂移，实现与文档一致、
spec 是错的。platform-mock 会**拒绝** `scope="model"`（`server_test.go:2754`）。
本次一并订正为 `""` | `"deps"`，且语义按 §3.2 改为「触发源」。

## 5. 不变量与已接受的代价

1. **非触发方的 findings 不产生任何动作**——包括**模型侧的问题不会阻止训练启动**。
   若一次依赖下发触发的合并审计发现模型代码有问题，模型照旧留在原地、照旧可训练，
   改动只是把结论写进报告并上报 `code=1`。这是「不跨侧清除」的直接推论，
   **是本次改动里唯一一处安全姿态实际放宽的地方**。若要收紧，应当另开一个显式闸门
   （例如「最近一次合并审计未通过则拒绝 startTraining」），不在本次范围。
2. **重复下发同一依赖集会被重复审计。** 结合既有观测
   （未改动的良性代码在 LLM 审查下约每 10 条误判 1 条 MALICIOUS 并 fail-closed 阻断），
   取消幂等意味着**同一份依赖重投有可观测概率被自己拒掉**。这是「每次都重审」的既定代价。
3. **合并扫描抬高截断/超时概率。** 合并后输入约为原先的两倍，越过 `MaxFindings=200` 的
   概率上升，而截断会让 `Report.ProvesCleanScan()` 返回 false（`rules.go:126`）→
   `AssembleAuditReport` 把 `scanPassed=false`（`audit.go:354`）→ 在 fail-closed 下
   **整份报告阻断**。用户明确选择不调大阈值，因此这是既定代价；实现时不得顺手调大，
   也不得让新增的多根路径静默吞掉 `Truncated`。
4. **fail-closed 姿态不变**：`ScanEnabled=false` 仍然整段跳过审计
   （`deps_import.go:330-333`、`import_processing.go:613-616`），跳过时不写任何标记
   （标记机制删除后此点自动成立）。

## 6. 已知盲区

1. 依赖不得改变模型审计范围这一**原始前提已被推翻**，因此依赖侧的失败语义
   （`DepsImported=false` 只适用于首次导入失败、旧绑定不动）需要在新语义下重新走一遍：
   合并审计中依赖侧被牵连时才回滚，规则不变。
2. fail-closed 静态扫描对 wheel 内的 `.so`/`.pyd` 二进制仍然无效
   （引擎按扩展名跳过），二进制层面的供应链风险未被覆盖；完整性上只有 SM3，无签名验签。
   本方案不改变这一点。
3. **跨根数据流能否真正检测到，取决于 CPG 符号解析的改造**（见 §7）。
4. 模型侧 findings 不阻止训练（§5.1）。

## 7. CPG 符号解析的改造要求

`enrichFindingsWithCPG(dir, targets, findings)`（`semgrep_engine.go:232`）与
`NewSymbolResolver(dir)`（`cpg_analysis.go:169-172`）目前都以单一 root 建符号索引。

依赖根必须以「**模块搜索路径**」的身份进入解析，而不是被当成第二个独立工程——
因为模型代码 `import numpy` 时，`numpy` 实际来自 `<depsDir>/<sm3>/numpy`，
正是训练运行时通过 `PYTHONPATH` 注入的那一条（`deps_env.go:19-36`）。

- **首选**：给 `NewSymbolResolver` 增加一个可选的附加搜索根，模型根作主根、依赖根作搜索路径。
- **退化**：若该改动无法在 `cpg/resolver.go` 里做到最小化（该文件同时被本检出里另一个
  参与者的未合并 `feat(cpg)` 分支改动），则每个根各建一个 resolver、各自 enrich、
  findings 取并集，`cpg/resolver.go` 一行不动。此时保真度损失是
  **跨根数据流（模型代码 → 依赖模块）检测不到**——而那恰恰是选择「真·单次审计」
  而非「两次扫描取合取」的理由。因此退化方案**必须**回写进本节作为已知盲区，
  不得静默降级。

实现者必须先读 `internal/codeaudit/cpg/resolver.go` 再定，并把选定结论与理由回写本节。

## 8. 验收判据

1. 只下发模型（无依赖）→ 一次 `reportAudit(scope="", code=0)`，
   `report.directories == [modelDir]`。
2. 再下发一套干净依赖 → 一次 `reportAudit(scope="deps", code=0)`，
   `report.directories` 含两个根，两处分项 `passed` 均为 true。
3. 重投**同一个**依赖包 → install 与 audit **再次发生**（对照 2 的日志），`code` 仍为 0。
   这一条直接证明幂等短路确实没了。
4. findings 只在模型侧时下发依赖 → `reportAudit(scope="deps", code=1)` 且分根结论指向
   模型根，`reportDeps(code=0)`，**模型与依赖目录都没有被删**。
5. findings 在依赖侧时下发依赖 → `reportAudit(code=1)` + `reportDeps(code=1)`，
   依赖目录被删、绑定按既有规则处理，**模型目录原样**。
6. `ScanEnabled=false` → 跳过审计，`reportAudit` 不发出，依赖正常绑定，不留任何标记文件。
