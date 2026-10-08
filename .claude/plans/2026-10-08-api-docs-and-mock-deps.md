# 接口文档补全 + platform-mock 依赖链路测试支持

> 承接 `.claude/plans/2026-10-08-model-dependency-delivery.md`。该计划收尾时登记了两项延后：
> spec §11 阶段 3（接口文档落地 `docs/api-design.md`）与 spec §12 端到端判据不可满足
> （platform-mock 无任何依赖端点）。本计划闭合这两项。

**目标：** 把已实现的依赖下发接口写进仓库 API 文档，并让 platform-mock 能收、能发、能观测依赖链路。

**范围外：** 不改 TAA 侧任何生产代码；不改 `tools/csv2-vm/`；不碰 `teellm/`。

---

## 事实基线（均已在 HEAD 上核实）

TAA 侧新增/扩展的对外面：

| # | 端点 | 方向 | 性质 |
|---|---|---|---|
| 1 | `POST /v1/taa/importDeps` | 平台 → TAA | 新增，请求体 3 字段 `resourceUrl`/`requestId`/`taskId` |
| 2 | `POST /v1/taa/reportDeps` | TAA → 平台 | 新增回调，`code` 0/1，成功带 `checksum{size,algorithm,value}` |
| 3 | `POST /v1/taa/reportAudit` | TAA → 平台 | 新增可选 `scope`，取值 `""`（模型）或 `"deps"` |
| 4 | `POST /v1/taa/status` | 平台 → TAA | 新增 `depsImported`(bool) / `depsHash`(string) |
| 5 | `reportRes` 的 `training_task` | TAA → 平台 | 新增 `deps_checksum`，无依赖时该键不出现 |
| 6 | 配置 `storage.depsDir` | — | 默认 `/opt/taa/model-deps`，不得嵌在 `modelDir` 内 |

关键语义（写文档时必须准确）：
- `importDeps` 同步阶段只做 解析 → 校验 → 并发占用 → 下载，随即返回 200
  `{"msg":"依赖包已接收，处理中","result":null,"error":0}`；**200 不代表导入成功**，终态只能靠 `reportDeps`。
- 同步错误码：400 解析失败 / 400 `resourceUrl 不能为空` / 400 `requestId 和 taskId 不能同时为空` / 409 并发冲突 / 500 下载失败。
- 异步失败时 `reportDeps.code=1`，且审计失败**同时**发 `reportAudit(scope=deps,code=1)` 与 `reportDeps(code=1)`。
- `reportAudit(scope=deps)` 的 `code`：0 通过 / 1 未通过 / 2 执行失败或按 fail-closed 判定 LLM 不可用。
- `depsImported=true` 只表示「有一套依赖已安装并绑定」，**不代表通过审计**。
- 幂等：`<depsDir>/<sm3>` 内容寻址且永久；目录内 `.taa_audit_ok` 内容等于 `depsAuditMarkerVersion` 才复用。

---

## Task 1：`docs/api-design.md` 补全接口描述

**Files:**
- Modify: `docs/api-design.md`（仅此一个文件）

落位（沿用文档既有编号，不重排既有小节）：
- 目录：新增 §3.10、§4.7 两行
- §2.1.1 表格：`reportDeps` 追加为第 8 行
- §2.1.2 表格：`importDeps` 追加为第 8 行
- 新增 **§3.10 TAA 上报依赖包导入结果（/v1/taa/reportDeps）**，紧随 §3.9 之后
- 新增 **§4.7 下发依赖包资源（/v1/taa/importDeps）**，紧随 §4.6 之后
- §3.6 `reportAudit`：参数表新增 `scope` 行 + 说明空串等价于模型审计（向后兼容）
- §3.4 `reportRes`：`training_task` 字段块（含 `model_checksum` 处）新增 `deps_checksum`，注明无依赖时键不出现
- §5.2 `status`：结果字段表新增 `depsImported` / `depsHash`

**验收：**
- 新章节结构与本文件既有 §3.x/§4.x 一致（触发时机 / 参数表 / 请求示例 jsonc / 响应内容类型 / 响应参数 / 响应结果字段 / 成功与失败响应示例）
- 上文「事实基线」中每一条语义都能在文档里找到对应文字
- 文中不出现 TAA 侧内部实现细节（函数名、变量名）；只描述线格式
- 目录锚点与实际小节标题一致

---

## Task 2：platform-mock 支持依赖链路

**Files（全部在 `tools/platform-mock/` 内）：**
- Modify: `internal/store.go` — `reportState` 增 `Scope`；`reportRequest` 增 `Scope`
- Modify: `internal/handlers_taa.go` — 新增 `reportDepsHandler`；`reportAuditHandler` 采集并校验 `scope`；
  `isValidModelChecksum` 更名 `isValidChecksum`（唯一调用点在 `reportModelImportHandler`）
- Modify: `internal/handlers_api.go` — 新增 `taaImportDepsHandler`；`dashboardStatusHandler` 增 `deps`；
  `reportStateResult` 增 `scope`
- Modify: `internal/server.go` — 注册 `/v1/taa/reportDeps`、`/api/reportDeps/status`、`/api/reportDeps/reset`、
  `/api/taa/importDeps`；新建 `reportDepsStore`（`reportDeps-state.json`）
- Modify: `internal/static/index.html` — 新增 `card-importDeps` 卡片
- Modify: `internal/static/js/app.js` — 新增 `testImportDeps()`、回填随机 requestId/taskId、结果标签与交互记录
- Modify: `internal/server_test.go` — 新增/更新测试

**行为要求：**
1. `POST /v1/taa/reportDeps` 接收并落盘；校验 `dockerId`/`requestId` 非空、`code` ∈ {0,1}、
   `code==0` 时 `checksum` 必须含 `size`>0 / `algorithm` 非空 / `value` 非空。与 `reportModelImport` 同构。
2. `reportAudit` 的 `scope` 采集下来并在 `/api/reportAudit/status` 回显；取值只接受 `""` 与 `"deps"`，其余 400。
3. `POST /api/taa/importDeps` 转发请求体到 TAA `/v1/taa/importDeps`，把 TAA 的响应原样透传（状态码 + 体）。
   TAA 地址未配置时回 502；非 POST 回 405。
4. 控制台：新卡片包含 `resourceUrl`/`requestId`/`taskId` 三个输入、触发按钮、状态点、返回查看按钮，
   与 `card-importModel` 的交互方式一致；点击后经 `/api/taa/importDeps` 走通。
5. **不新增 JS 文件**——`server.go` 的 `init()` 按固定清单拼接前端 bundle，新增文件需同步改清单，不值得。

**验收：**
- `go test ./tools/platform-mock/... -count=1` 全绿
- `go build -o bin/platform-mock ./tools/platform-mock/cmd/platform-mock` 成功
- 新增测试覆盖：reportDeps 接收/校验/落盘/status/reset；scope 采集与拒绝非法值；
  importDeps 转发（用 httptest 假 TAA 断言请求体与透传状态码）；控制台卡片存在
- 既有 UI 结构测试（`TestIndexHTMLModalTabsAndLegacySectionRemoval`、
  `TestConsolidatedCardsAndRemovedHints`、`TestDashboardAggregatedStatus` 等）若因新增卡片而失败，
  按新事实更新断言，不得为了让它们过而删卡片

---

## 执行顺序与并发

两任务文件足迹完全不相交（`docs/api-design.md` vs `tools/platform-mock/**`），Task 1 不跑测试，
故可并行；上限 2，正好两个。**为避免共享 git index 竞态，两个实现者都不执行任何 git 命令**，
由控制方在两侧完成后按显式路径分两次提交。

---

## 收尾：终审发现与处置（2026-10-08）

终审判定「需要修改」。全部结论都经**实测或逐字读码**复核，无一条采信推演。

### 一条 Important（超出本计划范围，经用户裁定后修）

审查者推断（**自称未实测**）：全新实例上 `training_task.deps_checksum` 会输出 `{}`。
用临时探针实测证实：`RESULT: training_task.deps_checksum present=true value=map[string]interface {}{}`。

根因：`internal/store/sealed_state.go:156-164` 把 `ModelChecksum` / `DataChecksum` / `DepsChecksum`
都初始化为**非 nil 空 map**，而 `internal/runtime/report.go` 只判 `!= nil`，该守卫在全新实例上永不命中。

为何只有依赖这一路会真正暴露：model / data 的 `{}` 分支在真实训练里不可达（训练必有模型与数据），
而**依赖本来就是可选的**，于是「没导依赖 → 报 `{}`」是常态路径，违背 spec 的
「未导入依赖的训练会话，报告应与改动前逐字节一致」。

处置（用户裁定「改代码」）：`report.go` 改用 `len(depsChecksum) > 0`，与该函数上方 metrics 的写法一致；
新增 `TestBuildTrainingReportOmitsEmptyDepsChecksum` 覆盖冷启动形态。变异回 `!= nil` 后该用例
以预期断言失败（`got map[string]interface {}{}`），证明它有判别力；未动 model / data 的既有行为。

### 四条 Minor（均在本计划范围内，已修）

| 项 | 复核结论 | 处置 |
|---|---|---|
| §4.7 的 409 示例 `msg` 是杜撰 | 实测 `route.go:639/652/666` 三种真实文案，无一条与文档相符 | 改用真实模板，并列出三种形态，注明只按 `error=409` 判定 |
| §3.10「两条回调」窄化成只讲 `code=1` | 实测 `deps_audit.go` 两条 `code=2` 路径均 `return false`，调用方随即发 `reportDeps(code=1)` | 扩写为「审计未通过**或审计无法完成**」 |
| 回调中 `taskId` 恒非空 | 实测 `reporter.go:124-127` 用 `requestId` 回填空 `taskId` | 参数表补注 |
| `TestDashboardAggregatedStatus` 的 `Deps.Received` 断言空转 | 实测：删掉 dashboard 的 `"deps"` 键，类型化解码仍得零值 `false`，断言照过 | 增补 raw key 存在性断言；按行号变异键名验证其判别力 |

> 复核过程中一度用 `sed` 按空格模式变异，**未匹配成功**，测试「原样通过」——
> 这类假阴性什么也证明不了。改为按行号精确变异后重做，才得到可信结论。

### §5.1 / §5.2 既有 doc/code 不一致（已决，2026-10-08）

文档列了 `dataImported` / `trainingDataImported` / `trainingDone`，而 `handler_system.go` 实际返回
`trainingRunning`。已核实为**改动前既有**（HEAD 上即如此，本分支未触碰）。

用户裁定**以代码为准**（代码是最新的）。归因也支持这一裁定：
`docs/superpowers/specs/2026-09-14-training-state-machine-design.md:195` 明确写着
「`/health` 和 `/status` 不返回 `dataImported`、`trainingDone`，返回 `trainingRunning`」——
即那次状态机重构改了 spec 与实现，**唯独漏改了 `docs/api-design.md`**。

已按代码重写两节的字段表与示例，并用脚本比对「从 handler 提取的键」与「从文档表格提取的键」，
两节均**逐字一致**。`currentOp` 的取值清单也重新核定：文档原写的 `decrypting` 等确实存在，
但漏了 `analyzing` / `deps_importing` / `deps_installing` / `staging` / `reporting` / `auditing`；
另核实 `extracting` **只存在于 coordinator**，`status` 读不到，故未列入。

### 新发现的同类残留（未处理，待定）

`docs/state-persistence-and-self-healing.md:60-76` 的 `PersistentState` 结构定义已过期：
声明 `Version` 固定为 `"1.3"`（代码是 `DefaultStateVersion = "1.4"`），且仍含已删除的
`DataImported` / `TrainingDataImported`，并缺 `DepsChecksum` / `DepsImported` / `DepsHash` / `TrainingRunning`。
该文件性质是**设计文档**（非接口契约），是否同步需另行判断，未擅自改。
