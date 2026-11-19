# 每实例独立 TAA 日志终端 — 设计

日期：2026-11-19
范围：`tools/platform-mock` 前端（`internal/static/`）+ 相应测试与文档。后端不改。

## 问题

TAA 运行日志原本是页面底部的一张卡片，内容跟随"当前选中实例"。这带来两个错误：

1. **日志是实例的属性，不是页面选中项的属性。** 切换选中行会把正在看的日志整个换成另一个实例的，而操作者往往是在同时对照两个实例。
2. **控件状态是全局的。** 暂停、级别过滤、搜索关键字、自动滚动锁都是页面级变量，无法对 A 实例暂停的同时盯着 B 实例。

实例列表已经按 dockerId 汇总了每个实例的日志条数（`instanceSummary.TaaLogCount`），日志接口也已按 `?dockerId=` 解析到各自的 store（每实例容量 2000 行，重复拉取为替换而非追加）。缺的只是把 UI 变成每实例一份。

## 形态

- 实例行操作区最前面新增 `日志 (N)` 按钮，N 取该实例的 `taaLogCount`。点击 **不改变当前选中实例**，只在该行下方（同一 `.instance-row` 内换行，`flex-basis: 100%`）展开一个深色终端；多个实例可同时展开。
- 终端头：`taa-syslog · <dockerId>`、状态点 + 文本（等待 / 正常 / 错误）、`共 N 行 · seq M`、刷新、暂停/继续、清空。
- 工具条：`全部 / INFO / WARN / ERROR` 四级过滤 + 搜索框（匹配计数与上/下跳），行为沿用原卡片。
- 终端固定高 240px，可滚动。默认跟随到底部；用户滚离底部即只对该终端锁定跟随，其他终端不受影响。
- 收起终端 = 停止轮询并保留缓存与全部 UI 状态；再次展开立即可见原内容并恢复轮询。

## 状态模型

前端新增一张按 dockerId 索引的状态表，与选中实例解耦：

```js
taaTerminals = new Map(); // dockerId -> {
//   expanded, paused, level, keyword, autoScroll,
//   entries, total, lastSeq, error, fetchedAt
// }
```

`taaTerminalState(id)` 惰性创建。所有终端 UI 只读写自己的这一份；页面级不再存在 `taaLogPaused` / `currentLogFilter` / `currentSearchKeyword` / `autoScrollLocked` 这些 TAA 日志变量。

## 数据流

- 拉取固定走 `fetch('/api/taaLog/status?dockerId=' + encodeURIComponent(id))`，**不经** `mockFetch`/`withDockerId`——那是"当前选中实例"的语义，正是本次要摆脱的东西。结果只写回该 id 的状态。
- 清空固定走 `POST /api/taaLog/reset?dockerId=...`（不带 dockerId 会清空**所有**实例，所以必须显式带），成功后清空该实例的 `entries/total/lastSeq`。
- 轮询挂到现有中频层（2000 ms）：只遍历 `expanded && !paused` 的终端，`Promise.allSettled` 并发；展开瞬间立即拉一次。
- 收起或暂停的终端不再产生请求。

## 生命周期与重绘

- 行继续由 `buildInstanceRow` 用 DOM 调用构建（dockerId 是宿主输入，必须保持文本）。展开时在 `row` 追加 `div.instance-terminal`，按钮与控件的事件闭包只绑本行 id，不读选中状态。
- 列表重绘（选中变化或签名变化）后，从状态表重建已展开的终端：缓存 entries 立即回填，过滤/搜索/暂停/跟随状态原样恢复，滚动按 `autoScroll` 恢复到底部或原位置。
- 行上 `日志 (N)` 的计数在 `applyInstanceList` 尾部**就地更新**，**不加入重绘签名**。若加入，每来一条新日志都会触发整表重建，打断正在输入的搜索框，并让展开中的终端闪一下。展开中的终端由自己的轮询更新该计数。
- 过滤 / 搜索 / 高亮从全局变量改为以终端根节点为参数的 `applyTaaTerminalView(root, state)`；复用 `parseStructuredLevel`、`renderTaaLogEntry`、`highlightSearchMatches`，把它们改成接收容器参数而非按全局 id 查找。

## 迁移与清理

- 删除底部 `#card-taaLog` 整块。
- 删除 `.log-panels-grid` / `.log-panels-col` 及其响应式规则；`#card-modelLog` 保持原位、整行全宽，仍跟随选中实例（模型日志本来就是"选中实例的模型"这一语义，本次不动）。
- 删除 `fetchTaaLogs`、`toggleTaaLogPause`、`clearTaaLogs`、`resetLogPauseForInstanceChange` 中的 TAA 日志分支，以及 `refreshInstancePanels` 里对 TAA 日志的调用。
- `/` 快捷键改为聚焦"当前选中实例且已展开"的终端搜索框；该实例未展开时什么都不做（不再有唯一的全局搜索框）。

## 失败处理

- 拉取失败：该终端状态点变红、显示错误文本，已缓存行不清空；下一次轮询成功后自动恢复。失败不会影响其他终端。
- 未知或已消失的 dockerId：显示空态「该实例暂无 TAA 日志」，不视为错误。
- 清空失败：保留原内容并显示错误文本。

## 测试

- 重写 `TestTaaLogConsoleRendering`（`internal/server_test.go`）：
  - `id="card-taaLog"` 不再出现在页面里；
  - 前端 bundle 含 `buildTaaTerminal`、`taaTerminalState`、`fetchTaaLogsFor`；
  - 日志请求显式带 `dockerId=`，且不出现 `withDockerId('/api/taaLog/status')` 这类选中项语义；
  - 轮询只遍历 `expanded` 且未暂停的终端；
  - `/api/taaLog/status`、`/api/taaLog/reset` 仍然被引用（后端契约未丢）。
- 新增源码级独立性断言：状态存于按 id 的 Map；页面级 `taaLogPaused`、`currentSearchKeyword`、`autoScrollLocked` 已不存在。
- `internal/server_test.go` 中把 `id="card-taaLog"` 当作分节边界的断言改用 `card-modelLog`（或下一个稳定标记）。
- 手工验证：同时展开两个实例，分别设不同级别过滤与关键字、各自暂停其一，确认互不影响；收起一个不影响另一个；切换选中行后两个终端内容不变；清空其一，另一不受影响；在 116 上部署后实测。

## 文档

- `tools/platform-mock/README.md`：实例列表与日志章节改为"每实例行内日志终端"；说明计数来源与轮询策略。
- `CHANGELOG.md`：新增条目，写明 why——日志是实例的属性而非页面选中项的属性；旧底部卡片在切行时会把操作者正在看的日志换掉，且暂停/过滤/搜索都是全局的，做不到并行对照。

## 明确不做

- 不改后端接口与存储；不新增全局日志聚合视图；不做日志持久化导出；模型日志卡片的行为不变。
