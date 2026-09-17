# Platform Mock 请求体记录模块移除与弹窗 Tab 迁移设计文档

## 1. 概述与背景

在当前的 `platform-mock`（TAA 平台模拟器）控制台中：
- 页面底部包含一个独立的“平台发往 TAA 的请求体记录”模块（`tee-request-payloads`），通过轮询和前端时序日志栈展示平台发出的请求体。
- 用户在上方卡片（如“下发模型”、“下发数据”、“导出结果”、“检查连通性”等）触发操作后，若想核对发给 TAA 的请求参数，需要滚动到页面下方翻找日志，操作路径割裂。
- 与此同时，各功能卡片均有“查看返回”或“查看结果”按钮，点击后通过全局弹窗（`#bodyModal`）查看接口响应。

为了提升联调效率、优化界面信息流结构，本方案将底部的“请求体记录”独立模块彻底删除，并将所有请求体数据就近迁移至各接口对应的“查看返回/查看结果”弹窗中，通过顶部 Tab（`[ 返回内容 ]` / `[ 请求体 ]` 或 `[ 平台应答 ]` / `[ 上报内容 ]`）实现无缝切换查看。

## 2. 目标与非目标

### 2.1 目标
1. **移除旧独立模块**：从 `internal/app/mock/index.html` 移除底部的“平台发往 TAA 的请求体记录”卡片 DOM、样式及相关的前端高频轮询代码（`fetchRequestLogs`）。
2. **Tab 增强型弹窗**：改造全局通用弹窗 `#bodyModal`，在头部添加轻量 Tab 切换栏：
   - 平台发往 TAA 的主动请求：展示 `[ 返回内容 ]` 与 `[ 请求体 ]`，默��打开激活“返回内容”Tab。
   - TAA 回调平台的上报请求：展示 `[ 上报内容 (TAA请求体) ]` 与 `[ 平台应答 ]`，默认激活“上报内容”。
3. **结构化交互数据管理**：前端引入统一的交互存储器 `interactionStore`，将每一次的主动请求与响应（或收到的回调上报与平台应答）成对绑定，支持 JSON 高亮、排版及一键复制当前 Tab 内容。
4. **覆盖全部接口卡片**：
   - 健康检查 (`/v1/taa/health`)
   - 远程证明报告 (`/v1/taa/getAttestation`)
   - 阶段切换 (`/v1/taa/switch`)
   - 资源信息获取 (`/v1/taa/getResourceInfo`)
   - 文件上传 (`/api/upload`)
   - 下发模型 (`/v1/taa/importModel`)
   - 下发数据 (`/v1/taa/import`)
   - 导出结果 (`/v1/taa/export`)
   - 中止训练 (`/v1/taa/stopTraining`)
   - 平台注册回调 (`/v1/taa/register`)
   - 模型导入结果上报回调 (`/v1/taa/reportModelImport`)
   - 代码安全审计结果上报回调 (`/v1/taa/reportAudit`)
   - 训练结果上报回调 (`/v1/taa/reportRes`)
5. **后端向下兼容**：保留 Go 后端 `/api/request-logs/status` 和 `/api/request-logs/reset` 路由与结构，确保 Go 单元测试不受破坏。

### 2.2 非目标
- 不重构后端的 TAA 代理逻辑或存储架构。
- 不引入第三方前端框架（如 React/Vue），继续保持单文件无依赖的纯 HTML/CSS/Vanilla JS 架构。

---

## 3. 详细设计

### 3.1 UI 结构与样式调整 (`internal/app/mock/index.html`)

#### 1) 移除独立卡片与轮询
删除以下节点及对应代码：
- `<h2>平台发往 TAA 的请求体记录</h2>`
- 包含 `id="requestLogStatusDot"`, `id="requestLogOutput"`, `id="requestLogEndpointFilter"` 等的 `<section class="card">`。
- JS 中的 `fetchRequestLogs` 定时器（`setInterval(fetchRequestLogs, 2000)`）及相关 DOM 渲染函数。

#### 2) 全局弹窗 (`#bodyModal`) 增强
在 `#bodyModalTitle` 旁新增胶囊式 Tab 栏：

```html
<div id="bodyModal" class="modal-overlay" aria-hidden="true" onclick="if (event.target === this) closeBodyModal();">
  <div class="modal" role="dialog" aria-modal="true" aria-labelledby="bodyModalTitle">
    <div class="modal-head">
      <div style="display:flex; align-items:center; gap:12px; flex-wrap:wrap;">
        <h3 id="bodyModalTitle">接口详情</h3>
        <div id="modalTabsBar" class="phase-switch-bar" style="display:inline-flex; padding:2px; gap:2px;">
          <button type="button" class="phase-switch-btn active" id="modalTabPrimary" onclick="switchModalTab('primary')">返回内容</button>
          <button type="button" class="phase-switch-btn" id="modalTabSecondary" onclick="switchModalTab('secondary')">请求体</button>
        </div>
      </div>
      <div class="modal-actions">
        <button class="secondary" onclick="copyBodyModal(this)">复制</button>
        <button class="secondary" onclick="closeBodyModal()">关闭</button>
      </div>
    </div>
    <div id="bodyModalBadge" style="display:none; margin:10px 14px 0; padding:10px 14px; border-radius:8px; font-size:13px; font-weight:600; background:rgba(127,127,127,.08); border:1px solid var(--line);"></div>
    <pre id="bodyModalContent" class="modal-body"></pre>
  </div>
</div>
```

#### 3) Tab 样式复用
直接复用现有 `.phase-switch-bar` 和 `.phase-switch-btn` 样式类，保证深色/浅色模式无缝自适应，无需���增冗余 CSS。

---

### 3.2 前端状态管理设计 (`interactionStore`)

引入全局管理对象：

```javascript
const interactionStore = {
  // 结构定义：
  // key: {
  //   title: string,
  //   primaryLabel: string,     // 默认 Tab 标签（如“返回内容”或“上报内容 (TAA请求体)”）
  //   secondaryLabel: string,   // 次级 Tab 标签（如“请求体”或“平台应答”）
  //   primaryContent: any,      // primary Tab 对应的原始对象或文本
  //   secondaryContent: any,    // secondary Tab 对应的原始对象或文本
  //   badgeData: any,           // 用于渲染 bodyModalBadge 的元数据
  //   badgeType: string         // 'modelImport' | 'audit' | null
  // }
};
```

#### 辅助函数设计：
1. `recordInteraction(key, data)`：
   合并更新指定 key 的交互数据（保留已有字段，更新最新请求或返回内容）。
2. `openInteractionModal(key, preferredTab = 'primary')`：
   - 提取对应 key 的数据；
   - 填充标题 `#bodyModalTitle`；
   - 设定两个 Tab 按钮的文本标签；
   - 根据 `badgeType` 渲染或隐藏 `#bodyModalBadge`；
   - 调用 `switchModalTab(preferredTab)`，高亮显示文本并设定当前激活 Tab；
   - 打开弹窗。
3. `switchModalTab(tabType)`：
   - 更新 Tab 按钮激活类（`.active`）；
   - 根据 `tabType === 'primary'` 提取对应内容并经 `formatModalBody` 格式化；
   - 更新当前可复制内容 `currentModalBody`；
   - 若内容为有效 JSON，调用 `highlightJSON` 进行语法高亮展示；否则纯文本输出；
   - 重置滚动条至顶部。

---

### 3.3 各模块迁移与对接规范

| 模块 Key | 主动方 / 类型 | Primary Tab 内容（默认） | Secondary Tab 内容 | 触发入口与交互 |
| :--- | :--- | :--- | :--- | :--- |
| `health` | 平台 → TAA | **返回内容**：HTTP 状态码及健康检查响应 JSON | **请求体**：`{}` | 连通性检查旁的“查看结果”按钮 |
| `attestation` | 平台 → TAA | **返回内容**：HTTP 状态码及报告摘要信息 | **请求体**：`{ "requestId": "..." }` | 远程证明操作栏/内联“查看返回” |
| `switch` | 平台 → TAA | **返回内容**：HTTP 状态码及切换应答 JSON | **请求体**：`{ "phase": N }` | 阶段切换旁的“查看返回”按钮 |
| `resourceInfo` | 平台 → TAA | **返回内容**：目录树解析 JSON 或原始文本 | **请求体**：`{ "resourceUrl": "..." }` | 结果区域中的“查看返回”按钮 |
| `upload` | 平台前端 → Mock | **返回内容**：上传成功返回（URL、文件大小、加密标记等） | **请求体**：文件名、文件大小、加密开关、公钥配置详情 | 上传卡片头部的“查看返回”按钮 |
| `importModel` | 平台 → TAA | **返回内容**：TAA HTTP 响应 JSON | **请求体**：包含 resourceUrl, requestId, taskId, publicKey, runtimeConfig 的完整 JSON | 卡片头部“查看返回”按钮 |
| `import` | 平台 → TAA | **返回内容**：TAA HTTP 响应 JSON | **请求体**：包含 resourceUrl, requestId, taskId 的完整 JSON | 卡片头部“查看返回”按钮 |
| `export` | 平台 → TAA | **返回内容**：下载及解密结果汇总信息（文件名、大小、加密状态等） | **请求体**：包含 requestId, taskId, publicKey 的请求体 JSON | 卡片头部“查看返回”按钮 |
| `stopTraining` | 平台 → TAA | **返回内容**：TAA HTTP 响应 JSON | **请求体**：`{}` | 状态提示旁新增/联动“查看返回”入口 |
| `register` | TAA → 平台 (回调) | **上报内容 (TAA请求体)**：TAA 注册上报数据 (dockerId, taaPublicKey等) | **平台应答**：平台回执 `HTTP 200 { error: 0, msg: "ok" }` | 顶部“查看注册返回”按钮 |
| `reportModelImport` | TAA → 平台 (回调) | **上报内容 (TAA请求体)**：模型导入上报完整数据及 checksum 校验徽章 | **平��应答**：平台回执 `HTTP 200 { error: 0, msg: "ok" }` | “导入上报”按钮 |
| `reportAudit` | TAA → 平台 (回调) | **上报内容 (TAA请求体)**：代码安全审计上报数据及高低危统计徽章 | **平台应答**：平台回执 `HTTP 200 { error: 0, msg: "ok" }` | “审计上报”按钮 |
| `reportRes` | TAA → 平台 (回调) | **上报内容 (TAA请求体)**：训练结果上报完整数据 | **平台应答**：平台回执 `HTTP 200 { error: 0, msg: "ok" }` | “查看返回”按钮（“查看报告”保持专门展示格式化报告） |

---

## 4. 测试与验证策略

1. **编译检查**：
   - 执行 `go build -o bin/platform-mock ./cmd/platform-mock` 确保无编译错误。
2. **单元测试与回归**：
   - 执行 `go test ./...` 确保所有后端服务（包括 `server_test.go`）通过。
3. **HTML / 前端结构自动化断言测试**：
   - 编写或更新单元测试验证 `internal/app/mock/index.html`：
     - 断言不再包含 `平台发往 TAA 的请求体记录` 字符串。
     - 断言不再包含 `requestLogOutput` 元素。
     - 断言包含 `modalTabsBar`、`switchModalTab` 及 `interactionStore`。
4. **人工端到端验证流程**：
   - 点击“检查连通性” -> 点击“查看结果” -> 验证默认展示返回内容，点击“请求体”展示 `{}`。
   - 点击“发送测试”（下发模型） -> 点击“查看返回” -> 验证展示 TAA 返回，点击“请求体”展示下发的完整配置 JSON。
   - 点击“复制”按钮，验证复制内容与当前 Tab 视图保持一致。
   - 切换阶段 -> 点击“查看返回” -> 验证切换至弹窗且支持请求体/返回体 Tab。
