# Platform Mock 服务连接与环境检查迁入平台注册实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将 platform-mock 前端页面的“服务连接与环境检查”板块合并迁入顶层通栏的“平台注册”模块中，并将“查看结果”按钮调整为点击弹出模态弹窗以结构化高亮 JSON 展示健康检查完整响应。

**Architecture:** 将原 `.top-dashboard-grid` 双列卡片结构（平台注册 + 服务连接与环境检查）简化为单卡片通栏布局（`#card-attestation`），在卡片顶部内联集成 TAA 服务地址与环境健康指示栏；在 JavaScript 中引入 `lastHealthData` 缓存完整响应并在点击【查看结果】时调用已有的 `openBodyModal` 弹窗展示高亮 JSON，废弃旧的内联折叠展开逻辑。

**Tech Stack:** HTML5, CSS3 (CSS Variables, Flexbox), Vanilla JavaScript (ES6+), Go 1.26 (for embedded mock server and tests).

---

### Task 1: 编写测试用例验证 HTML 结构与弹窗交互元素

**Files:**
- Modify: `internal/app/mock/server_test.go`

- [ ] **Step 1: 编写失败测试**

在 `internal/app/mock/server_test.go` 中新增测试函数 `TestHealthCheckIntegratedIntoRegistration`：
- 验证 `card-service-env` 与 `toggleHealthDetail`、`healthDetailContent` 不再出现在 `indexHTML` 中。
- 验证 `card-attestation` 中包含 `taaAddr`, `healthDot`, `healthLabel`, `testHealth`, `healthResultBtn`, `openHealthResultModal`。

```go
func TestHealthCheckIntegratedIntoRegistration(t *testing.T) {
	// 旧的独立卡片与旧函数应被移除
	for _, unwanted := range []string{
		`id="card-service-env"`,
		"toggleHealthDetail",
		`id="healthDetailContent"`,
		"top-dashboard-grid",
	} {
		if strings.Contains(indexHTML, unwanted) {
			t.Fatalf("indexHTML should not contain %q after integration", unwanted)
		}
	}

	// 整合后的新元素与函数应存在
	for _, want := range []string{
		`id="card-attestation"`,
		`id="taaAddr"`,
		`id="healthDot"`,
		`id="healthLabel"`,
		"testHealth()",
		`id="healthResultBtn"`,
		"openHealthResultModal",
		"lastHealthData",
	} {
		if !strings.Contains(indexHTML, want) {
			t.Fatalf("indexHTML missing integrated element or function %q", want)
		}
	}
}
```

- [ ] **Step 2: 运行测试以确认测试失败**

运行测试：
```bash
/usr/local/go/bin/go test -run TestHealthCheckIntegratedIntoRegistration ./internal/app/mock/... -v
```
预期结果：FAIL，提示 `indexHTML should not contain "id=\"card-service-env\"" after integration`。

- [ ] **Step 3: 提交初始测试用例**

```bash
git add internal/app/mock/server_test.go
git commit -m "test(mock): add test for integrated health check and registration UI"
```

---

### Task 2: 调整 HTML 结构与 CSS 样式（迁移合并 DOM 板块）

**Files:**
- Modify: `internal/app/mock/index.html`

- [ ] **Step 1: 清理 CSS 中的 `.top-dashboard-grid` 样式**

在 `internal/app/mock/index.html` 中：
1. 移除媒体查询中的 `.top-dashboard-grid { grid-template-columns: 1fr !important; }`。
2. 移除 CSS 规则 `.top-dashboard-grid { display: grid; grid-template-columns: 420px 1fr; gap: 16px; margin-bottom: 24px; align-items: stretch; }`。

- [ ] **Step 2: 重构 `#card-attestation` 并删除 `#card-service-env`**

在 `internal/app/mock/index.html` 中，将原 `<div class="top-dashboard-grid">` 替换为单张通栏卡片：
```html
  <!-- 顶部通栏：平台注册与服务连接控制面板 -->
  <section class="card" id="card-attestation" style="display:flex; flex-direction:column; margin-bottom:24px;">
    <!-- 第一行：平台注册状态与全局记录操作 -->
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

- [ ] **Step 3: 运行测试检查进度**

运行：
```bash
/usr/local/go/bin/go test -run TestHealthCheckIntegratedIntoRegistration ./internal/app/mock/... -v
```
预期结果：FAIL，虽然 HTML 结构已更新，但 JS 中的 `openHealthResultModal` 和 `lastHealthData` 尚未定义，且旧的 `toggleHealthDetail` 仍在 JS 中。

- [ ] **Step 4: 提交 HTML 与样式结构修改**

```bash
git add internal/app/mock/index.html
git commit -m "feat(mock): merge service connection and env check into registration card"
```

---

### Task 3: 调整 JavaScript 交互逻辑与弹窗显示 JSON 功能

**Files:**
- Modify: `internal/app/mock/index.html`

- [ ] **Step 1: 新增 `lastHealthData` 状态变量并调整 `setHealthState`**

在 `<script>` 顶部附近声明 `let lastHealthData = null;`。
重构 `setHealthState`：
```javascript
function setHealthState(className, title, labelText, labelColor) {
  const dot = document.getElementById('healthDot');
  const label = document.getElementById('healthLabel');
  if (dot) {
    dot.className = className;
    dot.title = title;
  }
  if (label) {
    label.textContent = labelText;
    label.style.color = labelColor || '';
  }
}
```

- [ ] **Step 2: 更新 `testHealth` 函数并添加 `openHealthResultModal`**

更新 `testHealth`：
```javascript
async function testHealth() {
  const btn = document.getElementById('healthResultBtn');
  if (btn) btn.disabled = true;
  setHealthState('dot', '检查中', '检查中...', '');
  try {
    const r = await postToTAA('/v1/taa/health', {}, 10000);
    const ok = r.status === 200 && r.data && r.data.error === 0;
    lastHealthData = r.data != null ? r.data : { status: r.status, raw: r };
    setHealthState('dot ' + (ok ? 'ok' : 'bad'), ok ? '连通正常' : '连通异常', ok ? '连通正常' : 'HTTP ' + r.status, ok ? 'var(--ok)' : 'var(--bad)');
  } catch (e) {
    const msg = e.name === 'AbortError'
      ? '请求超时（10s）：TAA 服务响应过慢或不可达。\n请确认：\n1. TAA 服务地址是否正确\n2. TAA 服务是否已启动\n3. 浏览器能否直接访问该地址'
      : '请求失败: ' + e.message;
    lastHealthData = {
      error: -1,
      msg: e.message || '网络请求异常',
      detail: msg
    };
    setHealthState('dot bad', '不可达', '不可达', 'var(--bad)');
  } finally {
    if (btn) btn.disabled = false;
  }
}

function openHealthResultModal() {
  if (!lastHealthData) {
    openBodyModal('健康检查返回结果 (GET /v1/taa/health)', '暂未执行健康检查，请先点击【检查连通性】。');
    return;
  }
  openBodyModal('健康检查返回结果 (GET /v1/taa/health)', JSON.stringify(lastHealthData, null, 2));
}
```

删除废弃的 `toggleHealthDetail()`。

- [ ] **Step 3: 运行测试验证**

运行：
```bash
/usr/local/go/bin/go test -run TestHealthCheckIntegratedIntoRegistration ./internal/app/mock/... -v
```
预期结果：PASS。

- [ ] **Step 4: 运行全部 package 测试**

运行：
```bash
/usr/local/go/bin/go test ./internal/app/mock/... -v
```
预期结果：全部 PASS。

- [ ] **Step 5: 提交 JavaScript 逻辑变更**

```bash
git add internal/app/mock/index.html
git commit -m "feat(mock): add json modal display for health check results"
```

---

### Task 4: 构建并验证完整应用

**Files:**
- None (build and run verification)

- [ ] **Step 1: 构建 platform-mock 与 TAA 二进制**

```bash
/usr/local/go/bin/go build -o bin/platform-mock ./cmd/platform-mock
/usr/local/go/bin/go build -o bin/taa ./cmd/taa
```
预期结果：无编译告警，退出码为 0，成功生成 `bin/platform-mock` 与 `bin/taa`。

- [ ] **Step 2: 运行整个工程全部单元测试**

```bash
/usr/local/go/bin/go test ./...
```
预期结果：所有测试通过。

- [ ] **Step 3: 启动 platform-mock 验证端点与 HTML 返回**

使用临时端口启动并 curl 根路径检查：
```bash
MOCK_PORT=19999 ./bin/platform-mock &
PID=$!
sleep 1
curl -s http://127.0.0.1:19999/ | grep -q 'openHealthResultModal' && echo "MODAL FOUND"
curl -s http://127.0.0.1:19999/ | grep -q 'card-service-env' || echo "CARD REMOVED"
kill $PID
```
预期结果：输出 `MODAL FOUND` 和 `CARD REMOVED`。
