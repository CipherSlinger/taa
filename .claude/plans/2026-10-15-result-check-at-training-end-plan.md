# 把结果泄露检查移到训练结束、导出改读判定

## Context

远程 pod 上 `/v1/taa/export` 连续四次失败:

```
10:51:55 [export] 收到导出请求
10:53:15 [export] 结果安全检查通过 (warnings=0)      ← 80 秒
10:53:19 [export] 明文导出: 大小=89341376 bytes
10:53:19 导出明文结果失败: write tcp ...: write: broken pipe
```

根因:导出接口在写第一个字节之前先把结果泄露检查跑完(80 秒)+ 打包 zip(4~5 秒),这 84 秒响应上一个字节都没有;调用方响应超时远小于 84 秒,先关了连接,TAA 再写就收到 RST。80 秒来自 `internal/codeaudit/result_checker.go:234` —— 对**每个**数据文件都用 `bytes.Contains` 重扫整份结果内容,O(数据文件数 × 结果大小);实测 89MiB 扫一遍 19.4ms,对应约 4000 次重复扫描。

**用户定稿的三点:** 训练一结束就做这次 bytes.contains 检查 → 保留检测结果 → 导出时读该结果决定拒绝或同意导出。

**明确不做**(用户更正过):不与 LLM 代码审计结论做 AND,审计返回结果与本次检查无关;不改任何返回字段(报告 schema、审计 summary、API 响应一律不动)。

顺带效果:导出不再空转 80 秒,broken pipe 一并消失。

## 方案

### 1. 训练结束跑检查(非致命)

`internal/controller/import_processing.go`,插在第 544 行(取消判断之后)与 `StepSeparator("Build & Upload Report")`(:545)之间:

- 受 `s.Security.ResultCheck` 开关控制,关掉则整段跳过(与现状字节级一致);
- 放在取消判断之后 —— `CheckDirectory` 无法中断,已取消的任务不该白付这 80 秒;
- **非致命且不 panic**:`executeTraining` 跑在 `runAsyncSafe` 里(:169),这里 panic 会被当成训练崩溃写失败报告,把一次成功的训练变成失败。所有错误只记日志、继续走;
- 用现有构造:`codeaudit.NewResultChecker(s.Security.DataDir, s.Security.GetMaxFileBytes())` + `CheckDirectory(trainOutputDir)`(必须用 `GetMaxFileBytes()`,它喂 `ResultChecker.limit()`,换值会改变大小异常判定);
- 新增 `internal/controller/result_check.go` 里的 `runResultCheck(dir) *ResultCheckVerdict`:检查执行失败也返回裁决(`Error` 字段填错因),把"查了但检查本身失败"和"从没查过"区分开;高危项按老格式 `[check] detail` 收进 `Details`,保证 400 文案与现在完全一致。

### 2. 判定持久化到导入索引记录

判定存进 `resource.ImportIndexRecord`(`internal/resource/index_store.go:17-24`)—— 导出本来就查这条记录拿 `ResultDir`(`handler_export.go:51-61`),同一把钥匙;落盘后重启不丢(索引在 `ResultDir/import-index.json`)。

类型放 `internal/resource`(不能引 `internal/codeaudit`:那边会拖进 `codeaudit/cpg`,是反向依赖):

```go
type ResultCheckVerdict struct {
	Passed    bool     `json:"passed"`
	Error     string   `json:"error,omitempty"`     // 检查本身执行失败
	Details   []string `json:"details,omitempty"`   // 高危项 "[check] detail"
	CheckedAt string   `json:"checkedAt,omitempty"` // RFC3339 UTC
}

// ImportIndexRecord 新增:
ResultCheck *ResultCheckVerdict `json:"resultCheck,omitempty"`
```

`ImportIndexStore` 目前只写一次(`Commit` 追加),新增 `SetResultCheck(requestID, taskID string, verdict *ResultCheckVerdict) error`:

- 把 `Lookup` 里内联的匹配规则抽成 `lookupLocked`(:289-301),`Lookup` 与 `SetResultCheck` 共用,免得两处规则漂移;
- 四个持有者必须同步改:`records` 切片(`saveLocked` 从它序列化)、`byRequestID`、`byTaskID`(导出读这张表)、`latestRecord`(必须**替换指针**而不是就地改 pointee,否则回滚快照 `oldLatest` 也一起变了);
- 落盘失败按 `Commit`(:190-217)整体回滚;`pendingReqIDs/pendingTaskIDs` 不参与,不用快照;
- `sameImportIndexRecord`(:438)**绝对不要加新字段**:指针 `==` 比的是地址,重新加载后 `latestRecord` 与 `records` 里的裁决指针不同,`Purge` 的"最近记录"判定(:370)会失效。加一行注释说明故意排除。

### 3. 导出改读判定

`internal/controller/handler_export.go`:删掉 :85-108 的扫描块,原地换成读 `record.ResultCheck`。**同一位置**保留错误优先级(缺 `training_report.json` 的 404 仍然先于判定);`maxBytes` 留着给后面的大小上限判断;`:12` 的 `codeaudit` import 随之变成未使用,必须一起删,否则编译不过。

| 情况 | 行为 |
| --- | --- |
| 开关关着 | 直接导出,与现状一致 |
| 判定通过 | 正常导出,日志记 `checkedAt` |
| 判定不通过 | 400 + `导出结果安全检查未通过，存在高危数据泄露隐患: ...`(文案与现状逐字一致) |
| 检查执行失败(`Error` 非空) | 500 + `结果安全检查执行失败，拒绝导出: ...` |
| 开关开着但无判定 | 500 + `结果安全检查裁决缺失，拒绝导出（fail-closed）` |

后两种用 500(与旧的"检查执行失败 500"一致),与泄露的 400 区分开。命门是:开关开着就必须有判定,没判定等于没证据,宁可拒。

## 需要写进提交信息/文档的三处行为变化

1. **扫描范围少了一个文件**:检查现在跑在写 `training_report.json` 之前(:998 才写),所以报告本身不再被扫。这是安全的 —— `AttachResultFiles` 本来就为这个原因关掉了 preview(`result_files.go:11-19`),而且去掉了一个误报源;训练命令产出的 `training_result.json` 仍然被扫。
2. **崩溃/自愈路径的导出从 200 变 fail-closed 500**:进程内 panic 路径(`route.go:947-948`)会把失败报告写进记录目录,现在没有判定 → 500。正常失败路径不受影响(它写 `ResultDir/train`,导出的 stat 先 404)。
3. **老记录迁移**:判定字段引入前提交的记录没有裁决;开关为 true 时它们的导出会 500,直到重新训练。这是 fail-closed 的必然代价,写进 README 配置表和提交信息。

## 涉及文件

- `internal/resource/index_store.go` — 新类型/新字段/`lookupLocked`/`SetResultCheck`
- `internal/controller/result_check.go` — 新增 `runResultCheck`
- `internal/controller/import_processing.go` — :544 处插入检查步骤并落判定
- `internal/controller/handler_export.go` — 删扫描块与 `codeaudit` import,改读判定
- `README.md`(:383-384 配置表)、`docs/api-design.md`(4.6 节)、`CHANGELOG.md` — 文档同步

## 测试

- `internal/resource/index_store_test.go`(已有 3 个测试,照 `TestImportIndexStoreBasic` 的 `t.TempDir()` + `LoadImportIndexStore` 写法新增):`SetResultCheck` 后 `Lookup`/`LookupByTaskID`/`Latest` 三处都带裁决(只改一张表会漏);重新 `Load` 后仍在(证明走了 `records`/`saveLocked`);传 `nil` 能清除;未知记录报错且状态不变;requestId/taskId 命中不同记录时报冲突错;写入失败时回滚。
- `internal/controller/handler_test.go:1612-1636` 现有子测试(全仓库唯一打开 `ResultCheck` 的测试)会失效,拆成三个:`无判定 → 500 fail-closed`、`落一条不通过判定且**不写** leak.csv → 400 + 老文案`(证明导出不再扫描)、`判定带 Error → 500 且文案不含"未通过"`。
- `internal/controller/import_flow_new_test.go`:给 `phase1FlowCase`/`runPhase1FlowCase` 加 `resultCheck` 与导出断言字段,新增端到端用例 —— 训练命令往 `$TAA_OUTPUT_DIR` 多写一个含 `id,label,image` 的 `leak.csv`,断言:训练仍算成功、报告照常上传(证明非致命)、记录里判定为不通过、导出 400。干净产物则导出 200。
- 默认 `ResultCheck:false` 的既有测试(`TestExportResultCheck`、两处 flow 导出断言、`import_param_validation_test.go`)预期不受影响,跑一遍确认。

## 验证

1. `go test ./...`(并发会话共用同一检出,不要并行跑测试)。
2. `go test ./internal/controller/ -run 'Export|Phase1' -v`、`go test ./internal/resource/ -run IndexStore -v`。
3. `CGO_ENABLED=0 GOOS=linux go build -o bin/taa ./cmd/taa`。
4. 端到端(可选,需 178):训练结束后在日志里应看到 `resultcheck` 那行,`import-index.json` 里该任务带上 `resultCheck`;随后导出应立即开始传字节(不再有 84 秒空转)。

## 备注

- 本次不动 `result_checker.go` 那个 O(D×N) 扫描本身,80 秒仍在,只是挪到训练结束时发生(会让训练报告晚约 80 秒上传)。后续可单独优化。
- 按 CLAUDE.md,本计划副本放进仓库 `.claude/plans/`(`.claude/` 在 .gitignore 里,需 `git add -f`);提交信息用英文 Conventional Commits。
