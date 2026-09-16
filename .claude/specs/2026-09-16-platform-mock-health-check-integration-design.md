# Platform Mock 服务连接与环境检查迁入平台注册设计文档

## 1. 概述与背景

在当前的 `platform-mock` 页面布局中，顶部采用了双列 Grid（`top-dashboard-grid`）：
- 左侧列（420px）：变窄的“平台注册”板块（`#card-attestation`）。
- 右侧列（1fr）：独立的“服务连接与环境检查”面板（`#card-service-env`），其中环境检查的结果是通过卡片底部的 `<pre id="healthDetailContent">` 内联折叠/展开显示的。

为了优化页面空间利用率，减少垂直留白，并将 TAA 的基础网络配置、环境状态探针、平台注册及远程证明流转串联成统一的操作上下文，需要将“服务连接与环境检查”板块完全合并迁入“平台注册”模块中。同时，将原有的内联展开“查看结果”调整为复用全局模态弹窗，以结构化高亮 JSON 形式展示接口响应。

## 2. 目标与范围

- **UI 布局重构**：
  - 移除 `.top-dashboard-grid` 双列布局及相关媒体查询规则。
  - 删除独立的 `#card-service-env` 卡片与内联 `#healthDetail` 容器。
  - 统一由顶部通栏的“平台注册”卡片承载：服务地址输入配置、环境状态指示、连通性检查、查看结果弹窗入口、注册状态监测、公钥展示与复制、远程证明操作集合。
- **弹窗展示 JSON**：
  - 废弃 `toggleHealthDetail()`。
  - 新增 `openHealthResultModal()`，调用全局 `openBodyModal`。
  - 弹窗展示 `/v1/taa/health` 的完整格式化 JSON 响应数据（支持语法高亮与一键复制）。
  - “查看结果”按钮在检查未执行时禁用，检查执行完成后激活。
- **兼容性**：
  - 维持现有 DOM ID（如 `#taaAddr`, `#healthDot`, `#healthLabel`, `#dot`, `#statusText`, `#registerPublicKey` 等），确保原有 JS 轮询、赋值逻辑与端到端行为无缝衔接。

## 3. 详细设计

### 3.1 DOM 结构调整 (`internal/app/mock/index.html`)

```html
<!-- 顶部统一：平台注册与服务连接控制面板 -->
<section class="card" id="card-attestation" style="display:flex; flex-direction:column; margin-bottom:24px;">
  <!-- 第一行：服务连接配置与环境状态监测 -->
  <div class="card-head" style="margin-bottom:12px; padding-bottom:10px; flex-wrap:wrap; gap:12px;">
    <div style="display:flex; align-items:center; gap:12px; flex-wrap:wrap;">
      <h2 style="margin:0;">平台注册</h2>
      <div class="status" style="font-size:13.5px;"><span id="dot" class="dot"></span><span id="statusText">等待 TAA 注册请求</span></div>
    </div>
    <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
      <button id="registerBodyBtn" class="secondary" onclick="openRegisterBodyModal()" disabled>查看注册返回</button>
      <button class="secondary" onclick="refreshStatus()">刷新状态</button>
      <button class="secondary" onclick="resetStatus()">清空接收记录</button>
    </div>
  </div>

  <!-- 第二行：TAA 服务地址与连通性检查工具条 -->
  <div style="display:flex; align-items:center; justify-content:space-between; gap:12px; background:var(--panel-sub); border:1px solid var(--line); border-radius:10px; padding:10px 14px; margin-bottom:12px; flex-wrap:wrap;">
    <div style="display:flex; align-items:center; gap:10px; flex:1; min-width:280px;">
      <label for="taaAddr" style="font-size:13px; font-weight:650; white-space:nowrap; margin:0;">TAA 服务地址</label>
      <input id="taaAddr" value="" placeholder="自动检测中..." style="flex:1; min-width:180px; padding:6px 10px; font-size:13px; border-radius:6px; border:1px solid var(--line); background:var(--bg);">
    </div>
    <div style="display:flex; align-items:center; gap:12px; flex-wrap:wrap;">
      <div style="display:flex; align-items:center; gap:8px;">
        <span style="font-size:13px; font-weight:650;">环境状态</span>
        <span id="healthDot" class="dot" title="未检查"></span>
        <span id="healthLabel" class="muted" style="font-size:13px;">未检查</span>
      </div>
      <div style="display:flex; align-items:center; gap:8px;">
        <button type="button" onclick="testHealth()" style="padding:6px 14px; font-size:13px;">检查连通性</button>
        <button type="button" id="healthResultBtn" class="secondary" onclick="openHealthResultModal()" style="padding:6px 12px; font-size:13px;" disabled>查看结果</button>
      </div>
    </div>
  </div>

  <!-- 第三行：公钥展示与远程证明操作 -->
  <div class="card-compact" style="min-height:auto;">
    <p id="registerSummary" class="card-note" style="margin:0 0 8px;">完整返回体仅在弹窗中展示。</p>
    <div id="registerPublicKeyBox" hidden style="margin-top:4px;">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:5px;">
        <label for="registerPublicKey" style="margin:0; font-size:12.5px; font-weight:650;">TAA 注册公钥</label>
        <button type="button" id="copyPubKeyBtn" class="icon-btn-compact" onclick="copyRegisterPublicKey(this)" title="复制公钥" aria-label="复制公钥">
          <svg class="copy-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
          </svg>
          <svg class="check-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="display:none; color:var(--ok);">
            <polyline points="20 6 9 17 4 12"></polyline>
          </svg>
        </button>
      </div>
      <textarea id="registerPublicKey" readonly style="min-height:80px; font-size:11.5px; font-family:ui-monospace,Menlo,monospace; line-height:1.45; cursor:text; background:rgba(37,99,235,.04); border-radius:8px; margin:0;" onclick="this.select();"></textarea>
    </div>
    <input type="hidden" id="attestRequestId" value="req-mock-attest-001">
    <div id="attestationResult" class="test-result" style="display:none;"></div>
    <div class="actions" style="margin-top:12px; display:flex; gap:8px; flex-wrap:wrap;">
      <button onclick="testGetAttestation()">获取远程证明报告</button>
      <button id="saveReportBtn" class="success" onclick="saveAttestationReport()" disabled>保存报告文件</button>
    </div>
    <p class="muted" style="margin:8px 0 0; font-size:12px;">最后刷新：<span id="lastRefresh">-</span></p>
  </div>
</section>
```

### 3.2 CSS 清理

- 移除 `.top-dashboard-grid` 样式类及其响应式规则。
- 保证输入框在移动端/窄屏环境下（`< 720px`）自适应换行堆叠。

### 3.3 交互逻辑变更 (`internal/app/mock/index.html` 内 `<script>`)

1. **响应数据缓存与变量定义**：
   - 增加全局变量 `let lastHealthData = null;`。
2. **`setHealthState` 重构**：
   - 简化 `setHealthState(className, title, labelText, labelColor)`，更新 `#healthDot` 与 `#healthLabel` 的视觉表现。
   - 不再依赖已删除的 `#healthDetailContent`。
3. **`testHealth` 逻辑增强**：
   - 发起请求前：`healthResultBtn.disabled = true;`，更新状态为“检查中...”。
   - 响应成功 (`status === 200 && data.error === 0`)：
     - `lastHealthData = r.data;`
     - 更新状态为“连通正常”。
     - `healthResultBtn.disabled = false;`
   - 响应失败（HTTP 状态码异常或抛出网络异常/超时）：
     - 将错误信息包装为 JSON 对象存入 `lastHealthData`，例如：
       ```json
       {
         "error": -1,
         "status": r ? r.status : 0,
         "msg": "连通异常或服务不可达",
         "detail": errorDetails
       }
       ```
     - 更新状态为“连通异常”或“不可达”。
     - `healthResultBtn.disabled = false;`
4. **新增 `openHealthResultModal` 函数**：
   - 检查 `lastHealthData` 是否有值，将其转换为带缩进的 JSON 字符串：`JSON.stringify(lastHealthData, null, 2)`。
   - 调用 `openBodyModal('健康检查返回结果 (GET /v1/taa/health)', formattedJSON)`。
   - `openBodyModal` 将自动触发 `highlightJSON` 高亮着色，并在弹窗内提供“复制”和“关闭”功能。
5. **清理冗余函数与引用**：
   - 删除废弃的 `toggleHealthDetail()`。

## 4. 测试与验证

1. **静态编译测试**：
   - 运行 `go test ./...` 确保全部单测通过。
   - 运行 `go build -o bin/platform-mock ./cmd/platform-mock` 确保编译无误。
2. **UI 交互验证**：
   - 页面加载时，“查看结果”按钮处于禁用状态，环境状态为“未检查”。
   - 点击“检查连通性”：
     - 在 TAA 正常启动时，状态指示变为绿色“连通正常”，“查看结果”按钮激活。
     - 点击“查看结果”，弹出模态弹窗，展示彩色高亮的 JSON 字段（包含 `error`, `msg`, `result.phase`, `result.modelImported` 等），点击复制按钮提示“已复制!”。
     - 在 TAA 未启动时，状态指示变为红色“不可达”，“查看结果”激活，点击弹窗展示错误信息 JSON。
   - 平台注册功能测试：TAA 向 platform-mock 发送注册请求，注册状态正常更新，公钥展示与复制功能正常，获取远程证明报告正常。
