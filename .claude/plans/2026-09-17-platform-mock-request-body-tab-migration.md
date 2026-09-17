# Platform Mock 请求体记录模块移除与弹窗 Tab 迁移实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 删除 platform-mock 中底部的“平台发往 TAA 的请求体记录”独立模块，将所有请求体迁移至各接口“查看返回/查看结果”弹窗中，通过 Tab 切换查看请求体与返回内容。

**Architecture:** 改造全局模态弹窗 `#bodyModal`，在头部添加胶囊式双 Tab（`[ 返回内容 ]` / `[ 请求体 ]` 或 `[ 上报内容 (TAA请求体) ]` / `[ 平台应答 ]`）；在前端引入统一的 `interactionStore` 状态机记录所有成对的请求/响应；从 `index.html` 中移除旧卡片 DOM 及 `fetchRequestLogs` 定时器；保留 Go 后端接口确保测试兼容。

**Tech Stack:** Go 1.22+, Vanilla JavaScript, HTML5/CSS3 (无外部依赖单文件控制台), standard library `testing`, `httptest`.

---

### Task 1: 编写前端结构自动化回归测试

**Files:**
- Modify: `internal/app/mock/server_test.go`

- [ ] **Step 1: 编写针对 indexHTML 结构与 Tab 规范的失败测试**

在 `internal/app/mock/server_test.go` 末尾添加测试函数 `TestIndexHTMLModalTabsAndLegacySectionRemoval`：

```go
func TestIndexHTMLModalTabsAndLegacySectionRemoval(t *testing.T) {
	if strings.Contains(indexHTML, "平台发往 TAA 的请求体记录") {
		t.Errorf("indexHTML should not contain legacy section '平台发往 TAA 的请求体记录'")
	}
	if strings.Contains(indexHTML, "id=\"requestLogOutput\"") {
		t.Errorf("indexHTML should not contain legacy element 'id=\"requestLogOutput\"'")
	}
	requiredSubstrings := []string{
		"id=\"modalTabsBar\"",
		"id=\"modalTabPrimary\"",
		"id=\"modalTabSecondary\"",
		"switchModalTab(",
		"openInteractionModal(",
		"interactionStore",
	}
	for _, s := range requiredSubstrings {
		if !strings.Contains(indexHTML, s) {
			t.Errorf("indexHTML missing required element/function: %q", s)
		}
	}
}
```

- [ ] **Step 2: 运行测试验证其失败**

Run: `go test -v ./internal/app/mock -run TestIndexHTMLModalTabsAndLegacySectionRemoval`
Expected: FAIL，因为目前 `index.html` 尚未添加 `modalTabsBar` 且仍包含旧模块。

- [ ] **Step 3: 保持测试代码，准备在后续任务中使测试通过**

确保测试代码可编译并准备好作为回归守护。

---

### Task 2: 移除 `index.html` 中的旧请求体记录卡片与定时轮询

**Files:**
- Modify: `internal/app/mock/index.html`

- [ ] **Step 1: 删除底部请求体记录卡片 HTML**

在 `internal/app/mock/index.html` 中找到并删除以下 HTML 片段（大约在第 1326 行至 1363 行）：
```html
  <!-- 平台发往 TAA 的请求体记录 -->
  <h2>平台发往 TAA 的请求体记录</h2>
  <section class="card">
    <div style="display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:12px; flex-wrap:wrap;">
      <div class="status" style="font-size:16px;">
        <span id="requestLogStatusDot" class="dot"></span>
        <span id="requestLogStatusText">等待发送请求...</span>
      </div>
      <div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
        <label style="margin:0; font-size:13px;">接口过滤</label>
        <select id="requestLogEndpointFilter" style="width:auto; padding:4px 8px;" onchange="renderRequestLogs()">
          <option value="">全部接口</option>
          <option value="/v1/taa/importModel">/v1/taa/importModel（下发模型）</option>
          <option value="/v1/taa/import">/v1/taa/import（下发数据）</option>
          <option value="/v1/taa/switch">/v1/taa/switch（阶段切换）</option>
          <option value="/v1/taa/export">/v1/taa/export（导出结果）</option>
          <option value="/v1/taa/stopTraining">/v1/taa/stopTraining（中止任务）</option>
          <option value="/v1/taa/getResourceInfo">/v1/taa/getResourceInfo（资源信息）</option>
          <option value="/v1/taa/getAttestation">/v1/taa/getAttestation（远程证明报告）</option>
          <option value="/v1/taa/health">/v1/taa/health（健康检查）</option>
        </select>
        <button class="secondary" onclick="clearRequestLogs()" style="padding:6px 12px; font-size:13px;">清空记录</button>
        <span class="muted" id="requestLogCount" style="font-size:13px;">0 条请求体</span>
      </div>
    </div>
    <div class="terminal-shell">
      <div class="terminal-bar">
        <div class="terminal-dots">
          <span class="t-dot red"></span>
          <span class="t-dot yellow"></span>
          <span class="t-dot green"></span>
        </div>
        <span class="terminal-title">tee-request-payloads</span>
        <span class="muted" style="font-size:11px;">JSON / REST</span>
      </div>
      <div id="requestLogOutput" class="log-window" style="min-height:260px; max-height:550px; overflow-y:auto; font-size:13px; line-height:1.6; padding:14px; margin:0;"></div>
    </div>
  </section>
```

- [ ] **Step 2: 删除前端对应的日志记录与轮询逻辑**

在 `index.html` 的 `<script>` 标签中：
1. 删除 `formatRequestBody`, `formatRequestLogTime`, `getFilteredRequestLogs`, `buildRequestLogHTML`, `recordTaaRequest`, `renderRequestLogs`, `copyTaaRequestBody`, `fetchRequestLogs`, `clearRequestLogs` 函数实现。
2. 在 `testStopTraining` 中删除 `finally` 块中的 `await fetchRequestLogs();`。
3. 在 `taaFetch` 函数中：
   ```javascript
   function taaFetch(endpoint, body, timeoutMs) {
     const reqId = genId('taa-req');
     const opts = {
       method: 'POST',
       headers: {
         'Content-Type': 'application/json',
         'X-Mock-Req-Id': reqId,
       },
       body: JSON.stringify(body),
     };
     if (timeoutMs) {
       const ctrl = new AbortController();
       opts.signal = ctrl.signal;
       setTimeout(() => ctrl.abort(), timeoutMs);
     }
     return fetch(getTaaAddr() + endpoint, opts);
   }
   ```
4. 在脚本底部的初始化区域中，删除：
   ```javascript
   renderRequestLogs();
   fetchRequestLogs();
   // 以及
   setInterval(fetchRequestLogs, 2000);
   ```

- [ ] **Step 3: 运行全量测试验证无语法错误**

Run: `go test ./...`
Expected: 编译正常，除 Task 1 尚未添加的 Tab 外，其余旧测试全部通过。

- [ ] **Step 4: 提交代码**

```bash
git add internal/app/mock/index.html internal/app/mock/server_test.go
git commit -m "refactor(mock): remove legacy request logs section and polling"
```

---

### Task 3: 改造 `#bodyModal` 弹窗与引入 `interactionStore`

**Files:**
- Modify: `internal/app/mock/index.html`

- [ ] **Step 1: 改造 `#bodyModal` DOM 添加胶囊式 Tab 栏**

修改 `#bodyModal` 为：
```html
<div id="bodyModal" class="modal-overlay" aria-hidden="true" onclick="if (event.target === this) closeBodyModal();">
  <div class="modal" role="dialog" aria-modal="true" aria-labelledby="bodyModalTitle">
    <div class="modal-head">
      <div style="display:flex; align-items:center; gap:12px; flex-wrap:wrap;">
        <h3 id="bodyModalTitle" style="margin:0;">返回 body</h3>
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

- [ ] **Step 2: 编写 `interactionStore` 及状态管理核心逻辑**

在 `<script>` 中定义：
```javascript
const interactionStore = {};
let currentModalKey = null;
let currentModalTab = 'primary'; // 'primary' | 'secondary'

function recordInteraction(key, patch) {
  if (!interactionStore[key]) {
    interactionStore[key] = {
      title: '接口详情',
      primaryLabel: '返回内容',
      secondaryLabel: '请求体',
      primaryContent: null,
      secondaryContent: null,
      badgeBuilder: null,
    };
  }
  Object.assign(interactionStore[key], patch);
  // 若当前打开的弹窗正是当前 key，则刷新视图
  const modal = document.getElementById('bodyModal');
  if (modal && modal.classList.contains('open') && currentModalKey === key) {
    updateModalView();
  }
}

function updateModalView() {
  const item = interactionStore[currentModalKey];
  if (!item) return;

  document.getElementById('bodyModalTitle').textContent = item.title || '接口详情';
  const tabPrimary = document.getElementById('modalTabPrimary');
  const tabSecondary = document.getElementById('modalTabSecondary');
  if (tabPrimary) tabPrimary.textContent = item.primaryLabel || '返回内容';
  if (tabSecondary) tabSecondary.textContent = item.secondaryLabel || '请求体';

  if (currentModalTab === 'secondary') {
    if (tabSecondary) tabSecondary.classList.add('active');
    if (tabPrimary) tabPrimary.classList.remove('active');
  } else {
    if (tabPrimary) tabPrimary.classList.add('active');
    if (tabSecondary) tabSecondary.classList.remove('active');
  }

  // 渲染 Badge
  const badge = document.getElementById('bodyModalBadge');
  if (badge) {
    if (typeof item.badgeBuilder === 'function') {
      item.badgeBuilder(badge, item);
    } else {
      badge.innerHTML = '';
      badge.style.display = 'none';
    }
  }

  // 渲染内容
  const rawContent = currentModalTab === 'secondary' ? item.secondaryContent : item.primaryContent;
  const isSecondary = currentModalTab === 'secondary';
  const defaultEmptyMsg = isSecondary ? '/* 尚未发送请求体 */' : '/* 暂无返回内容 */';
  currentModalBody = formatModalBody(rawContent != null && rawContent !== '' ? rawContent : defaultEmptyMsg);

  const contentEl = document.getElementById('bodyModalContent');
  const trimmed = currentModalBody.trim();
  if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
    contentEl.innerHTML = highlightJSON(currentModalBody);
  } else {
    contentEl.textContent = currentModalBody;
  }
  contentEl.scrollTop = 0;
}

function openInteractionModal(key, preferredTab = 'primary') {
  currentModalKey = key;
  currentModalTab = preferredTab || 'primary';
  updateModalView();
  const modal = document.getElementById('bodyModal');
  modal.classList.add('open');
  modal.setAttribute('aria-hidden', 'false');
}

function switchModalTab(tabType) {
  currentModalTab = tabType;
  updateModalView();
}
```

保持 `openBodyModal(title, body)` 作为轻量兼容包装：
```javascript
function openBodyModal(title, body) {
  recordInteraction('legacy', {
    title: title || '返回 body',
    primaryLabel: '返回内容',
    secondaryLabel: '请求体',
    primaryContent: body,
    secondaryContent: null,
  });
  openInteractionModal('legacy', 'primary');
}
```

- [ ] **Step 3: 运行自动化回归测试**

Run: `go test -v ./internal/app/mock -run TestIndexHTMLModalTabsAndLegacySectionRemoval`
Expected: PASS，验证 `modalTabsBar`, `switchModalTab`, `interactionStore` 等均已存在且旧模块已删除。

- [ ] **Step 4: 提交代码**

```bash
git add internal/app/mock/index.html internal/app/mock/server_test.go
git commit -m "feat(mock): add modal tabs bar and interaction store"
```

---

### Task 4: 迁移主动请求类接口至 Tab 交互模型

**Files:**
- Modify: `internal/app/mock/index.html`

针对所有平台发往 TAA 的主动请求，记录其请求体并在对应的“查看返回/查看结果”中绑定 `openInteractionModal`：

- [ ] **Step 1: 迁移健康检查 (`health`)**
  - 在 `testHealth()` 中：
    ```javascript
    recordInteraction('health', {
      title: '健康检查 (GET /v1/taa/health)',
      primaryLabel: '返回内容',
      secondaryLabel: '请求体',
      secondaryContent: '{}',
    });
    ```
  - 响应后：
    ```javascript
    recordInteraction('health', { primaryContent: lastHealthData });
    ```
  - `openHealthResultModal()` 调整为：`openInteractionModal('health', 'primary');`。

- [ ] **Step 2: 迁移下发模型 (`importModel`) 与下发数据 (`import`)**
  - 在 `testImportModel()` 中记录 `buildImportBody(...)` 到 `interactionStore.importModel.secondaryContent`。
  - 响应后记录 `formatResp(r)` 到 `primaryContent`。
  - `showResult('importModelResult', ...)` 触发时更新按钮回调为 `openInteractionModal('importModel', 'primary')`。
  - 同理在 `testImport()` 中记录下发数据请求体与返回体，绑定 `openInteractionModal('import', 'primary')`。

- [ ] **Step 3: 迁移阶段切换 (`switch`) 与中止训练 (`stopTraining`)**
  - 在 `quickSwitchPhase(phase)` 中记录 `{ phase: Number(phase) }` 与响应。
  - 将 `phaseSwitchDetailBtn` 绑定改为 `openInteractionModal('switch', 'primary')`，移除或精简旧有的内联展开。
  - 在 `testStopTraining()` 中记录 `{}` 与返回内容。在中止状态提示处增加“查看返回”入口或将其存入 `stopTraining` interaction。

- [ ] **Step 4: 迁移导出结果 (`export`)、资源信息 (`resourceInfo`) 与远程证明 (`attestation`)**
  - 在 `testExport()` 中��录 `{ requestId, taskId, publicKey }` 与导出摘要/解密状态。
  - 在 `testGetResourceInfo()` 中记录 `{ resourceUrl }` 与解析结果。
  - 在 `testGetAttestation()` 中记录 `{ requestId }` 与返回证明文本。
  - 对应卡片上的“查看返回”按钮统一指向 `openInteractionModal(key, 'primary')`。

- [ ] **Step 5: 迁移文件上传 (`upload`)**
  - 在 `uploadFile()` 中记录当前上传文件的元数据（文件名、大小、是否加密、公钥）到 `secondaryContent`。
  - 上传成功或失败后将返回结果记入 `primaryContent`。
  - `uploadBodyBtn` 绑定调用 `openInteractionModal('upload', 'primary')`。

- [ ] **Step 6: 运行全量测试验证**

Run: `go test ./...`
Expected: 全部测试 PASS。

- [ ] **Step 7: 提交代码**

```bash
git add internal/app/mock/index.html
git commit -m "feat(mock): migrate outbound request payloads to modal tabs"
```

---

### Task 5: 迁移 TAA 回调上报接口至 Tab 交互模型

**Files:**
- Modify: `internal/app/mock/index.html`

针对所有 TAA 回调上报给平台的接口（平台注册、模型导入结果上报、代码审计上报、训练结果上报），展示 `[ 上报内容 (TAA请求体) ]` 与 `[ 平台应答 ]`：

- [ ] **Step 1: 平台注册 (`register`)**
  - 在 `renderRegister(data)` 中：
    ```javascript
    recordInteraction('register', {
      title: '平台注册详情',
      primaryLabel: '上报内容 (TAA请求体)',
      secondaryLabel: '平台应答',
      primaryContent: data,
      secondaryContent: { code: 0, msg: "ok", result: { accepted: data && data.accepted } },
    });
    ```
  - `openRegisterBodyModal()` 调整为 `openInteractionModal('register', 'primary')`。

- [ ] **Step 2: 模型导入结果上报 (`reportModelImport`)**
  - 在 `renderReportModelImport(data)` 中记录上报体与平台回执 `HTTP 200 { error: 0, msg: "ok" }`。
  - 配置 `badgeBuilder` 支持渲染 checksum 完整性校验信息。
  - `openReportModelImportBodyModal()` 调整为 `openInteractionModal('reportModelImport', 'primary')`。

- [ ] **Step 3: 代码安全审计上报 (`reportAudit`)**
  - 在 `renderReportAudit(data)` 中记录审计上报体与平台回执。
  - 配置 `badgeBuilder` 支持渲染风险等级与高/中/低危统计数据。
  - `openReportAuditBodyModal()` 调整为 `openInteractionModal('reportAudit', 'primary')`。

- [ ] **Step 4: 训练结果上报 (`reportRes`)**
  - 在 `renderReportRes(data)` 中记录训练结果上报体与平台应答。
  - `openReportResBodyModal()` 调整为 `openInteractionModal('reportRes', 'primary')`。
  - “查看报告” (`openReportResReportModal`) 保持展示提取后的美化 report。

- [ ] **Step 5: 运行全量测试**

Run: `go test -v ./...`
Expected: 全部测试通过。

- [ ] **Step 6: 构建二进制并验证**

Run: `go build -o bin/platform-mock ./cmd/platform-mock`
Expected: 构建成功，无任何编译警告与错误。

- [ ] **Step 7: 提交代码**

```bash
git add internal/app/mock/index.html
git commit -m "feat(mock): migrate inbound callback payloads to modal tabs"
```

---

### Task 6: 全链路回归与端到端验证

**Files:**
- Modify: `internal/app/mock/server_test.go`

- [ ] **Step 1: 扩充自动化测试用例，覆盖各个接口交互记录绑定的完整性**

在 `server_test.go` 中验证所有关键接口 key 在 `indexHTML` 中均存在成对的 `recordInteraction` 绑定调用：
- `health`
- `importModel`
- `import`
- `export`
- `switch`
- `resourceInfo`
- `attestation`
- `register`
- `reportModelImport`
- `reportAudit`
- `reportRes`

- [ ] **Step 2: 运行全量测试**

Run: `go test -v -race ./...`
Expected: PASS，无数据竞争与错误。

- [ ] **Step 3: 运行构建命令**

Run: `go build -o bin/platform-mock ./cmd/platform-mock`
Expected: PASS

- [ ] **Step 4: 最终提交**

```bash
git add internal/app/mock/server_test.go
git commit -m "test(mock): verify complete interaction modal bindings"
```
