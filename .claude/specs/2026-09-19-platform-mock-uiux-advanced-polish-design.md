# Platform-Mock 控制台高级 UI/UX 美化与交互增强设计方案

## 1. 概述与设计目标

### 1.1 背景
在前期架构拆分中，TAA Platform-Mock 已完成前端静态资源物理解耦（CSS 拆分为 `variables.css`、`layout.css`、`components.css`，JS 拆分为 `drawer.js`、`api.js`、`crypto.js`、`tree.js`、`logs.js`、`app.js`），并引入了基础状态胶囊、带斑马纹的训练进度条、抽屉式侧边交互面板以及轻量 JSON 语法高亮。

为了将该模拟器从“可用原型”进一步提升为“工业级安全沙箱运维/测试控制台”，现针对用户明确指定的四个维度（方向 2-5）进行系统级 UI/UX 深度升级：
1. **代码审计结果可视化仪表盘（Visual Audit Security Dashboard）**
2. **仿真终端级实时日志视窗（Terminal-grade Live Log Viewer）**
3. **全局堆叠式 Toast 提示与交互微动效（Micro-interactions & Toast System）**
4. **生命周期阶段流水线步进器（Pipeline Stage Stepper）**

### 1.2 核心设计原则
1. **渐进增强与零破坏（Zero-breakage & Strict Backward Compatibility）**：所有旧版 DOM ID、按钮点击回调函��、旧版模态框降级逻辑保持 100% 兼容，现有单元测试全部继续通过。
2. **纯原生无第三方重型依赖（Zero External Heavy Dependencies）**：坚持 Vanilla JS + 原生 CSS Variables + SVG 图标，不引入 Node/npm 构建链路或第三方重型 UI 库，保证 `embed.FS` 嵌入打包的绝对轻量化与秒级启动。
3. **高内聚低耦合模块化（Modular Extension）**：新增独立模块 `toast.js`，日志增强内聚于 `logs.js`，审计可视化与步进器与 `app.js` 优雅编排，样式统一扩展于 `components.css`。

---

## 2. 系统架构与模块职责划分

### 2.1 模块目录与文件结构
```
internal/app/mock/
├── server.go                 # go:embed 静态资源打包，注册静态路由与 frontendBundle 串联
├── server_test.go            # 单元测试（校验所有新旧组件 DOM 与 JS 函数签名）
└── static/
    ├── index.html            # 主控制台模板：新增 Stepper 挂载点、Toast 容器挂载点
    ├── css/
    │   ├── variables.css     # 设计令牌：补充 Toast、Stepper、Terminal 过滤器色值
    │   ├── layout.css        # 页面布局骨架
    │   └── components.css    # 核心组件样式：新增 Stepper、Toast、Audit Findings、Log Toolbar
    └── js/
        ├── toast.js          # [新增] 全局浮动堆叠 Toast 提示管理器
        ├── drawer.js         # 抽屉面板交互、JSON 语法高亮、cURL 生成器
        ├── api.js            # 后端 API 封装与请求包装器
        ├── crypto.js         # 国密/非对称公私钥生成与文本解析
        ├── tree.js           # 资源目录树交互与渲染
        ├── logs.js           # [升级] 仿真终端增强（日志级别过滤、即时高亮搜索、滚屏锁定）
        └── app.js            # [升级] 仪表盘主控：步进器状态机同步、可视化审计面板渲染
```

### 2.2 数据流拓扑图
```
                        /api/dashboard/status (Fast/Medium Tier)
                                     │
                                     ▼
                          ┌───────────────────────┐
                          │    PollingManager     │
                          │   (Page Visibility)   │
                          └──────────┬────────────┘
                                     │
         ┌───────────────────────────┼───────────────────────────┐
         ▼                           ▼                           ▼
┌──────────────────┐       ┌──────────────────┐       ┌──────────────────┐
│ Pipeline Stepper │       │ Audit Dashboard  │       │  Terminal Viewer │
│ 节点状态机驱动   │       │ 漏洞分级与折叠卡 │       │ 过滤/高亮/滚动锁 │
└──────────────────┘       └──────────────────┘       └──────────────────┘
         │                           │                           │
         └───────────────────────────┼───────────────────────────┘
                                     ▼
                           ┌──────────────────┐
                           │   Toast System   │
                           │ 异步消息全局通知 │
                           └──────────────────┘
```

---

## 3. 详细设计方案

### 3.1 方向五：生命周期阶段流水线步进器（Pipeline Stage Stepper）

#### 3.1.1 业务流程与节点定义
流水线步进器将 TAA 核心交互抽象为 4 个串行生命周期阶段：
1. **节点注册与证明（Node Register & Attestation）**：TAA 发起公钥注册，获取并验证 CSV/TEE 远程证明报告。
2. **代码审计与模型下发（Code Audit & Model Import）**：平台下发模型包，TAA 执行静态与大模型协同代码审计并导入。
3. **密态训练与进度监控（Secure Training & Progress）**：平台下发数据并触发训练，TAA 实时上报训练迭代百分比与状态。
4. **训练完成与产物导出（Completion & Delivery）**：训练达到 100% 或触发中止，导出模型产物与审计日志。

#### 3.1.2 节点状态与视觉表现
每个节点具有 4 种状态：
- `pending`（等待中）：灰色圆环底色，灰色文本，连接线置灰。
- `active`（进行中）：蓝色高亮，外圈带有 `@keyframes pulseGlow` 呼吸流光动效，连接线为蓝色渐变脉冲。
- `completed`（已完成）：翠绿色实心圆，内部带有白色勾选 SVG 图标，后置连接线为绿色。
- `failed`（异常/中止）：珊瑚红底色，内部带有叹号图标。

#### 3.1.3 HTML 结构设计 (`index.html`)
```html
<nav class="pipeline-stepper" id="pipelineStepper" aria-label="训练全生命周期流水线">
  <div class="stepper-step completed" id="stepNodeRegister" onclick="scrollToSection('card-health')">
    <div class="stepper-icon">
      <svg class="step-check" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg>
      <span class="step-num">1</span>
    </div>
    <div class="stepper-meta">
      <span class="step-title">节点鉴权与证明</span>
      <span class="step-desc" id="stepDescRegister">已注册</span>
    </div>
  </div>
  <div class="stepper-line" id="line1to2"></div>
  <div class="stepper-step active" id="stepNodeAudit" onclick="scrollToSection('card-importModel')">
    <div class="stepper-icon">
      <svg class="step-check" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg>
      <span class="step-num">2</span>
    </div>
    <div class="stepper-meta">
      <span class="step-title">代码审计与下发</span>
      <span class="step-desc" id="stepDescAudit">审计通过 (LOW)</span>
    </div>
  </div>
  <div class="stepper-line" id="line2to3"></div>
  <div class="stepper-step pending" id="stepNodeTraining" onclick="scrollToSection('card-import')">
    <div class="stepper-icon">
      <svg class="step-check" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg>
      <span class="step-num">3</span>
    </div>
    <div class="stepper-meta">
      <span class="step-title">密态训练监控</span>
      <span class="step-desc" id="stepDescTraining">等待下发</span>
    </div>
  </div>
  <div class="stepper-line" id="line3to4"></div>
  <div class="stepper-step pending" id="stepNodeExport" onclick="scrollToSection('card-taaLog')">
    <div class="stepper-icon">
      <svg class="step-check" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg>
      <span class="step-num">4</span>
    </div>
    <div class="stepper-meta">
      <span class="step-title">产物与审计日志</span>
      <span class="step-desc" id="stepDescExport">准备就绪</span>
    </div>
  </div>
</nav>
```

#### 3.1.4 状态自动同步逻辑 (`app.js`)
在 `renderDashboardStatus(res)` 周期性触发：
- 若 `res.register.received` 为 true，Step 1 标为 `completed`。
- 若 `res.modelImport.received` 为 true：
  - 检查 `res.audit.report` 中的风险结论，若 `passed === true` 则 Step 2 标为 `completed`；若未通过则标为 `failed`。
- 若 `res.progress.received` 为 true：
  - 若 `percent > 0 && percent < 100`，Step 3 标为 `active`；
  - 若 `percent >= 100`，Step 3 标为 `completed`，Step 4 标为 `completed`。

---

### 3.2 方向二：代码审计结果可视化仪表盘（Visual Audit Security Dashboard）

#### 3.2.1 数据模型解析
从 `result.audit.report` 反序列化得到的对象包含：
- `conclusion`: `{ passed: boolean, risk_level: "LOW"|"MEDIUM"|"HIGH", summary: string, statistics: { high: 0, medium: 0, low: 5 } }`
- `file_reports`: 数组，每个元素包含 `file`, `findings_count`, `findings`: 包含 `line`, `rule_id`, `category`, `severity`, `description`, `code_snippet`, `llm_verdict`, `llm_reason`。

#### 3.2.2 视觉布局与交互设计
1. **风险分布摘要条（Risk Bar）**：
   - 包含三种色块的水平堆叠条：高危（红色 `#ef4444`）、中危（黄色 `#f59e0b`）、低危/良性（蓝色 `#3b82f6`）。
   - 顶部显示总漏洞数与整体风险等级大号 Badge。
2. **漏洞按文件折叠手风琴（Findings Accordion）**：
   - 列表头显示文件名（如 `test_fusion.py`）及命中数徽章。
   - 点击文件展开详细 Findings 卡片：
     - **行号与类别**：`Line 308` · `[EMB_003] 结果嵌入数据`
     - **代码上下文视窗**：深色背景微框，展示 `code_snippet`。
     - **LLM 协同裁决结论**：突出显示绿色/黄色徽章（如 `UNCERTAIN` / `CONFIRMED`），并附带 `llm_reason`。
3. **集成入口**：
   - 在卡片内提供直观的嵌入式迷你摘要面板（嵌入在 `card-importModel`）。
   - 点击“审计详情 / 审计上报”时，直接在右侧抽屉（`appDrawer`）以结构化可交互仪表盘呈现，并提供“切换为原始 JSON”按键，保证双模查看。

---

### 3.3 方向三：仿真终端级实时日志视窗（Terminal-grade Live Log Viewer）

#### 3.3.1 控制栏增强（Terminal Toolbar）
在 `.terminal-bar` 增加操作功能群：
1. **日志级别过滤器（Filter Badges）**：
   - `ALL`、`INFO`、`WARN`、`ERROR`、`DEBUG` 胶囊按钮。
   - 点击过滤时，对当前终端视窗中的日志行即时隐藏/显示（基于 `data-level` 属性）。
2. **实时关键词高亮搜索框**：
   - 输入文本时，动态在日志行内搜索，匹配文字包裹 `<mark class="hl-match">`，并统计命中次数（如 `3 matches`）。
3. **吸底滚动锁（Auto-scroll Lock）**：
   - 状态为 `Lock` 时，新日志追加自动保持滚动条在最下方；
   - 用户鼠标向上滚动超过 40px 时，自动解除锁定并弹出“已暂停吸底 · 点击回到底部”悬浮按钮。

#### 3.3.2 行渲染微格式化（Log Line Formatter）
优化 `renderLogLines(logs)`：
- 识别 ISO 时间戳 `\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}`，渲染为灰度时间戳 `<span class="log-ts">`。
- 识别日志等级 `[INFO]`、`[WARN]`、`[ERROR]`、`level=error`，赋予不同背景/前景色胶囊。
- 识别堆栈关键路径 `/root/taa/...`，赋予轻微下划线与等宽加亮。

---

### 3.4 方向四：全局堆叠式 Toast 提示与交互微动效（Micro-interactions & Modern Toast System）

#### 3.4.1 Toast 管理器设计 (`toast.js`)
设计自包含的轻量级单例对象 `Toast`：
```javascript
const Toast = {
  container: null,
  init() {
    if (!this.container) {
      this.container = document.createElement('div');
      this.container.id = 'toastContainer';
      this.container.className = 'toast-container';
      document.body.appendChild(this.container);
    }
  },
  show({ title, message, type = 'info', duration = 3000 }) {
    this.init();
    const item = document.createElement('div');
    item.className = `toast-item toast-${type}`;
    // icon, title, message, close button, progress bar
    // automatic dismissal with slide-out animation
  }
};
window.showToast = (opts) => Toast.show(opts);
```

#### 3.4.2 消息类型与动效
- **四种语义类型**：`success`（绿色）、`error`（红色）、`warning`（琥珀色）、`info`（主题蓝）。
- **动效规范**：
  - 弹出：`cubic-bezier(0.16, 1, 0.3, 1)` 右侧滑入，附带微阴影。
  - 倒计时进度条：底部 2px 进度线 `linear` 缩短。
  - 销毁：透明度淡出同时高度收缩至 0，平滑挤压下方 Toast。
- **业务操作接入**：
  - 复制公钥、复制 cURL、复制返回体：由原本修改按钮文本升级为 `showToast({ type: 'success', title: '复制成功', message: '已复制到剪贴板' })`。
  - 阶段切换、测试发送、训练中止：均派发对应的 Toast 状态反馈。

#### 3.4.3 交互微动效（Micro-interactions）
- **按键微动效**：按钮悬浮亮化、点击轻微内缩（`active: scale(0.98)`）。
- **卡片微抬升**：主操作卡片在鼠标悬停时平滑产生 4px 抬升并增强边框微光。
- **快捷键徽章（Kbd）**：在抽屉面板关闭按钮、日志搜索框中加入 `<kbd>Esc</kbd>`、`<kbd>/</kbd>` 视觉标识。

---

## 4. 关键代码设计与实现细节

### 4.1 新增 `static/js/toast.js` 完整实现骨架
```javascript
// ── Global Toast Notification Manager ──
(function (global) {
  let container = null;

  function ensureContainer() {
    if (!container || !document.body.contains(container)) {
      container = document.createElement('div');
      container.id = 'toastContainer';
      container.className = 'toast-container';
      document.body.appendChild(container);
    }
    return container;
  }

  function getIcon(type) {
    switch (type) {
      case 'success':
        return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>';
      case 'error':
        return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>';
      case 'warning':
        return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>';
      default:
        return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>';
    }
  }

  function showToast(options) {
    const opts = typeof options === 'string' ? { message: options } : (options || {});
    const type = opts.type || 'info';
    const title = opts.title || (type === 'success' ? '操作成功' : (type === 'error' ? '操作失败' : '提示'));
    const message = opts.message || '';
    const duration = typeof opts.duration === 'number' ? opts.duration : 3000;

    const cont = ensureContainer();
    const toast = document.createElement('div');
    toast.className = `toast-item toast-${type}`;

    toast.innerHTML = `
      <div class="toast-icon-wrap">${getIcon(type)}</div>
      <div class="toast-body">
        <div class="toast-title">${title}</div>
        ${message ? `<div class="toast-msg">${message}</div>` : ''}
      </div>
      <button type="button" class="toast-close" aria-label="Close">&times;</button>
      <div class="toast-progress" style="animation-duration: ${duration}ms;"></div>
    `;

    const closeBtn = toast.querySelector('.toast-close');
    let timer = null;

    function removeToast() {
      if (timer) clearTimeout(timer);
      toast.classList.add('toast-hide');
      toast.addEventListener('transitionend', () => {
        if (toast.parentNode) toast.parentNode.removeChild(toast);
      }, { once: true });
    }

    if (closeBtn) closeBtn.onclick = removeToast;
    if (duration > 0) timer = setTimeout(removeToast, duration);

    cont.appendChild(toast);
    requestAnimationFrame(() => toast.classList.add('toast-show'));
  }

  global.Toast = { show: showToast };
  global.showToast = showToast;
})(window);
```

### 4.2 `static/css/components.css` 核心样式扩展
```css
/* ── Stepper Pipeline ── */
.pipeline-stepper {
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: var(--card-bg, #ffffff);
  border: 1px solid var(--line, #e2e8f0);
  border-radius: 12px;
  padding: 14px 20px;
  margin-bottom: 20px;
  gap: 12px;
  overflow-x: auto;
  box-shadow: var(--shadow-sm);
}

.stepper-step {
  display: flex;
  align-items: center;
  gap: 10px;
  cursor: pointer;
  user-select: none;
  transition: opacity 0.2s ease;
}

.stepper-icon {
  width: 28px;
  height: 28px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 12px;
  font-weight: 700;
  background: var(--bg-muted, #f1f5f9);
  color: var(--text-muted, #64748b);
  border: 2px solid var(--line, #cbd5e1);
  transition: all 0.25s ease;
}

.stepper-step.active .stepper-icon {
  background: var(--accent, #2563eb);
  color: #fff;
  border-color: var(--accent, #2563eb);
  box-shadow: 0 0 0 4px rgba(37, 99, 235, 0.2);
  animation: pulseGlow 1.8s infinite;
}

.stepper-step.completed .stepper-icon {
  background: var(--ok, #10b981);
  color: #fff;
  border-color: var(--ok, #10b981);
}

.stepper-line {
  flex: 1;
  height: 2px;
  background: var(--line, #cbd5e1);
  min-width: 24px;
  transition: background 0.3s ease;
}

.stepper-line.completed {
  background: var(--ok, #10b981);
}

/* ── Toast Notifications ── */
.toast-container {
  position: fixed;
  top: 20px;
  right: 20px;
  z-index: 10000;
  display: flex;
  flex-direction: column;
  gap: 10px;
  pointer-events: none;
  max-width: 360px;
  width: 100%;
}

.toast-item {
  position: relative;
  display: flex;
  align-items: flex-start;
  gap: 12px;
  background: var(--card-bg, #ffffff);
  border: 1px solid var(--line, #e2e8f0);
  border-radius: 10px;
  padding: 12px 14px;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.12);
  pointer-events: auto;
  opacity: 0;
  transform: translateX(40px) scale(0.96);
  transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
  overflow: hidden;
}

.toast-item.toast-show {
  opacity: 1;
  transform: translateX(0) scale(1);
}

.toast-item.toast-hide {
  opacity: 0;
  transform: translateX(60px) scale(0.9);
}

.toast-progress {
  position: absolute;
  bottom: 0;
  left: 0;
  height: 3px;
  background: var(--accent, #2563eb);
  width: 100%;
  animation: toastProgress linear forwards;
}

@keyframes toastProgress {
  from { width: 100%; }
  to { width: 0%; }
}
```

---

## 5. 测试与验证策略

### 5.1 自动化测试 (`server_test.go`)
1. **静态资源完整性断言**：
   - 验证 `static/js/toast.js` 存在且被打包进 `frontendBundle`。
   - 验证 `index.html` 包含 `#pipelineStepper`、`#toastContainer` 挂载及对应脚本引用。
   - 验证 `components.css` 包含 `.pipeline-stepper`、`.toast-container`、`.audit-dashboard`、`.log-filter-btn` 相关选择器。
2. **函数与接口契约断言**：
   - 验证 `frontendBundle` 中包含 `showToast`、`renderAuditDashboard`、`syncStepperState`、`setLogFilter`。
3. **回归测试全量验证**：
   - 运行 `go test -count=1 ./...`，确保全部测试包通过。

### 5.2 交互与端到端验证
1. **部署验证**：
   - 重新执行 `./deploy.sh docker platform-mock`，验证编译无 warning，服务正常拉起。
2. **控制台体验验证**：
   - 访问 `http://127.0.0.1:18080/`：
     - 点击复制按钮，观察右上角是否优雅弹出绿色 Toast。
     - 切换阶段，观察流水线步进器是否同步流转。
     - 查看代码审计，展开 Findings 卡片查看漏洞上下文与 LLM 裁决结论。
     - 在终端日志区切换 `ERROR` 过滤器并输入关键词，观察即时过滤与高亮。
