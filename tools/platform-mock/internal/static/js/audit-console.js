// ── Code audit workspace: job history, findings explorer, engine status ──
//
// The second top-level tab of the platform mock. It is an operator view over the
// audit projection TAA reports after a model import: nothing here re-runs a scan
// or enforces a verdict. The platform shows the evidence it received and labels
// the TEE-LLM gateway as one security engine module, not as the page's subject.
//
// Everything this file owns is either the #tabPanelAudit subtree or the audit
// namespace on window. Reusable helpers (escapeHtml, showToast, responseResult,
// postToTAA, buildImportBody, the instance selector) belong to the scripts
// loaded before it and are taken from there, with local fallbacks when absent.
(function () {
  'use strict';

  // ── Constants ──
  const USER_KEY = 'pm.audit.user';             // localStorage: remembered username only
  const DOCKER_KEY = 'pm.audit.dockerId';       // localStorage: last selected instance
  const TAB_KEY = 'pm.audit.tab';               // sessionStorage: last active tab
  const POLL_MS = 5000;                         // job list + gateway status cadence
  const SUBMIT_POLL_MS = 1000;                  // post-submit job discovery cadence
  const SUBMIT_POLL_WINDOW_MS = 900000;         // a CPU-only AI adjudication can take minutes
  const REQUEST_TIMEOUT_MS = 15000;
  const GENERATE_TIMEOUT_MS = 130000;           // server allows a ~120s cold model load
  const ATTEST_TIMEOUT_MS = 120000;             // report fetch plus a handshake

  const VIEWS = ['jobs', 'findings', 'engine', 'settings'];
  const VIEW_IDS = {
    jobs: 'auditViewJobs',
    findings: 'auditViewFindings',
    engine: 'auditViewEngine',
    settings: 'auditViewSettings',
  };

  const MONO_FONT = 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';

  // Exact palette from the product brief. The bars and badges carry their colour
  // inline so the workspace reads correctly even before the stylesheet lands.
  const TONES = {
    high:   { cls: 'bad',     color: '#dc2626', bg: 'rgba(220, 38, 38, 0.12)',  border: 'rgba(220, 38, 38, 0.30)' },
    bad:    { cls: 'bad',     color: '#dc2626', bg: 'rgba(220, 38, 38, 0.12)',  border: 'rgba(220, 38, 38, 0.30)' },
    medium: { cls: 'running', color: '#d97706', bg: 'rgba(217, 119, 6, 0.12)',  border: 'rgba(217, 119, 6, 0.30)' },
    warn:   { cls: 'running', color: '#d97706', bg: 'rgba(217, 119, 6, 0.12)',  border: 'rgba(217, 119, 6, 0.30)' },
    low:    { cls: 'running', color: '#2563eb', bg: 'rgba(37, 99, 235, 0.12)',  border: 'rgba(37, 99, 235, 0.30)' },
    info:   { cls: 'running', color: '#2563eb', bg: 'rgba(37, 99, 235, 0.12)',  border: 'rgba(37, 99, 235, 0.30)' },
    ok:     { cls: 'ok',      color: '#059669', bg: 'rgba(5, 150, 105, 0.12)',  border: 'rgba(5, 150, 105, 0.30)' },
    muted:  { cls: 'pending', color: '#6b7280', bg: 'rgba(100, 116, 139, 0.10)', border: 'rgba(100, 116, 139, 0.25)' },
  };

  const SETTINGS_HINT = '审计在本控制台进程内执行，提示词与 TLS 设置只影响后续审计；'
    + '服务重启后回到默认值。';

  // ── Module state ──
  const state = {
    booted: false,
    tab: 'platform',
    view: 'jobs',

    // Authentication
    user: null,
    expiresAt: '',
    sessionChecking: false,
    dropping: false,
    loginBusy: false,
    loginCountdown: null,

    // Instances
    dockerId: '',
    instances: [],
    instanceSignature: '',
    publicKeys: {},

    // Jobs and findings
    jobs: [],
    jobsTotal: 0,
    file: null,
    // storedFile is an entry from the file area. Exactly one of file and
    // storedFile is set: a local pick sends the bytes, a stored pick sends its id.
    storedFile: null,
    files: [],
    taskId: '',
    requestId: '',
    submitBusy: false,
    selectedJobId: '',
    currentJob: null,
    findings: [],
    severity: 'all',
    verdict: 'all',
    search: '',

    // Engine / gateway
    llm: null,
    logs: [],
    logsTotal: 0,
    logPaused: false,
    logAutoScroll: true,
    promptBusy: false,
    settings: null,
    tlsMode: 'permissive',
    tlsSkip: true,

    // Timers and in-flight guards
    pollTimer: null,
    polling: false,
    submitPollTimer: null,
    submitToken: 0,
  };

  // ── Missing-helper fallbacks ──
  // These mirror the shared helpers by contract. They are used only when the
  // earlier scripts did not define the real one, and the console warns once.
  let warnedFallback = false;
  function warnFallbacks(names) {
    if (warnedFallback) return;
    warnedFallback = true;
    console.warn('[audit-console] shared helpers unavailable, using local fallbacks:', names.join(', '));
  }

  function esc(value) {
    if (typeof escapeHtml === 'function') return escapeHtml(value);
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function toast(options) {
    if (typeof showToast === 'function') {
      showToast(options);
      return;
    }
    const message = typeof options === 'string' ? options : ((options && options.message) || '');
    console.warn('[audit-console][toast]', message);
  }

  function unwrap(data) {
    if (typeof responseResult === 'function') return responseResult(data);
    return data && data.result !== undefined ? data.result : data;
  }

  // ── DOM helpers ──
  function $(id) {
    return document.getElementById(id);
  }

  function setText(id, value) {
    const el = $(id);
    if (!el) return;
    const text = value == null ? '' : String(value);
    if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') el.value = text;
    else el.textContent = text;
  }

  function showElement(el, visible) {
    if (el) el.style.display = visible ? '' : 'none';
  }

  function setDisplayed(id, visible) {
    showElement($(id), visible);
  }

  function replaceChildren(el) {
    if (el) el.replaceChildren();
  }

  function monoNode(text) {
    const span = document.createElement('span');
    span.className = 'audit-mono';
    span.textContent = text == null ? '—' : String(text);
    span.style.fontFamily = MONO_FONT;
    return span;
  }

  function badge(label, tone) {
    const span = document.createElement('span');
    const t = TONES[tone] || TONES.muted;
    span.className = 'status-pill ' + t.cls;
    span.style.color = t.color;
    span.style.background = t.bg;
    span.style.borderColor = t.border;
    span.textContent = label == null ? '—' : String(label);
    return span;
  }

  // paintPill writes into an existing status element. The element keeps its
  // markup identity, and only the tone classes this module owns are reset.
  function paintPill(id, label, tone) {
    const el = $(id);
    if (!el) return;
    const t = TONES[tone] || TONES.muted;
    el.classList.add('status-pill');
    el.classList.remove('ok', 'bad', 'pending', 'running');
    el.classList.add(t.cls);
    el.style.color = t.color;
    el.textContent = label == null ? '—' : String(label);
  }

  function makeCell(value, opts) {
    const options = opts || {};
    const td = document.createElement('td');
    if (value instanceof Node) {
      td.appendChild(value);
    } else {
      const text = value == null || value === '' ? '—' : String(value);
      td.textContent = text;
      if (options.title !== false) td.title = text;
    }
    if (options.mono) {
      td.classList.add('audit-mono');
      td.style.fontFamily = MONO_FONT;
    }
    if (options.nowrap) td.style.whiteSpace = 'nowrap';
    return td;
  }

  // emptyStateBox is the icon + caption block shared by table empty rows and
  // the findings summary placeholder.
  function emptyStateBox(text, kind) {
    const box = document.createElement('div');
    box.className = 'audit-empty-cell';

    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('width', '22');
    svg.setAttribute('height', '22');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '1.6');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    svg.setAttribute('aria-hidden', 'true');
    if (kind === 'search') {
      const lens = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      lens.setAttribute('cx', '11');
      lens.setAttribute('cy', '11');
      lens.setAttribute('r', '7');
      const handle = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      handle.setAttribute('d', 'm20 20-3.6-3.6');
      svg.appendChild(lens);
      svg.appendChild(handle);
    } else {
      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('cx', '12');
      circle.setAttribute('cy', '12');
      circle.setAttribute('r', '8');
      const dash = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      dash.setAttribute('d', 'M9 12h6');
      svg.appendChild(circle);
      svg.appendChild(dash);
    }

    const label = document.createElement('span');
    label.textContent = text;

    box.appendChild(svg);
    box.appendChild(label);
    return box;
  }

  function emptyRow(tbody, colspan, text) {
    if (!tbody) return;
    const tr = document.createElement('tr');
    tr.className = 'audit-empty-row';
    const td = document.createElement('td');
    td.colSpan = colspan;
    td.appendChild(emptyStateBox(text));
    tr.appendChild(td);
    tbody.appendChild(tr);
  }

  // fillFieldList renders label/value pairs into a tbody (or a div container).
  // Values are set with textContent or appended as pre-built nodes; nothing is
  // interpolated into HTML.
  function fillFieldList(host, rows) {
    if (!host) return;
    const isTable = host.tagName === 'TBODY' || host.tagName === 'TABLE';
    const body = host.tagName === 'TABLE' ? (host.tBodies[0] || host) : host;
    body.replaceChildren();

    rows.forEach((row) => {
      const label = row[0];
      const value = row[1];
      const opts = row[2] || {};
      const display = (target) => {
        if (value instanceof Node) target.appendChild(value);
        else target.textContent = value == null || value === '' ? '—' : String(value);
        if (opts.mono) {
          target.classList.add('audit-mono');
          target.style.fontFamily = MONO_FONT;
        }
      };

      if (isTable) {
        const tr = document.createElement('tr');
        const th = document.createElement('td');
        th.className = 'audit-field-label';
        th.textContent = label;
        th.style.color = 'var(--muted, #6b7280)';
        th.style.padding = '7px 10px';
        th.style.whiteSpace = 'nowrap';
        const td = document.createElement('td');
        td.className = 'audit-field-value';
        td.style.padding = '7px 10px';
        display(td);
        tr.append(th, td);
        body.appendChild(tr);
      } else {
        const div = document.createElement('div');
        div.className = 'audit-field-row';
        const k = document.createElement('span');
        k.className = 'audit-field-label';
        k.textContent = label;
        k.style.color = 'var(--muted, #6b7280)';
        const v = document.createElement('span');
        v.className = 'audit-field-value';
        display(v);
        div.append(k, v);
        body.appendChild(div);
      }
    });
  }

  // ── Safe storage ──
  function storeGet(store, key) {
    try { return store.getItem(key); } catch (_) { return null; }
  }
  function storeSet(store, key, value) {
    try { store.setItem(key, value); } catch (_) {}
  }
  function storeRemove(store, key) {
    try { store.removeItem(key); } catch (_) {}
  }

  // ── Formatting ──
  function toNumber(value) {
    const n = Number(value);
    return Number.isFinite(n) ? n : 0;
  }

  function fmtDuration(ms) {
    const n = Number(ms);
    if (!Number.isFinite(n) || n < 0) return '—';
    if (n < 1000) return Math.round(n) + ' ms';
    return (n / 1000).toFixed(1) + ' s';
  }

  function fmtSeconds(seconds) {
    const s = Math.max(0, Math.round(Number(seconds) || 0));
    if (s < 60) return s + ' 秒';
    if (s < 3600) return Math.floor(s / 60) + ' 分';
    if (s < 86400) return Math.floor(s / 3600) + ' 小时 ' + Math.floor((s % 3600) / 60) + ' 分';
    return Math.floor(s / 86400) + ' 天 ' + Math.floor((s % 86400) / 3600) + ' 小时';
  }

  function fmtTime(iso) {
    if (!iso) return '—';
    const t = Date.parse(iso);
    if (Number.isNaN(t)) return String(iso);
    return new Date(t).toLocaleString('zh-CN', { hour12: false });
  }

  function shortId(id) {
    const text = String(id || '');
    return text.length > 8 ? text.slice(0, 8) + '…' : (text || '—');
  }

  // statusOf is the lifecycle axis, separate from the verdict: a job the console
  // just dispatched is pending until TAA's reportAudit callback turns it into
  // done (or failed, when the dispatch did not survive).
  function statusOf(job) {
    const status = String((job && job.status) || 'done').toLowerCase();
    if (status === 'pending') return { key: 'pending', label: '审计中', tone: 'info' };
    if (status === 'failed') return { key: 'failed', label: '未完成', tone: 'bad' };
    return { key: 'done', label: '已完成', tone: 'ok' };
  }

  function verdictOf(job) {
    if (!job) return { label: '—', tone: 'muted' };
    if (statusOf(job).key === 'pending') return { label: '待定', tone: 'muted' };
    if (statusOf(job).key === 'failed') return { label: '—', tone: 'muted' };
    if (toNumber(job.code) === 2) return { label: 'AI 不可用', tone: 'warn' };
    return job.passed ? { label: '通过', tone: 'ok' } : { label: '未通过', tone: 'bad' };
  }

  function riskLabel(level) {
    const text = String(level || '').toUpperCase();
    if (!text || text === 'NONE') return '无';
    return text;
  }

  function riskTone(level) {
    switch (String(level || '').toUpperCase()) {
      case 'CRITICAL':
      case 'HIGH':
        return 'high';
      case 'MEDIUM':
        return 'medium';
      case 'LOW':
        return 'low';
      case 'NONE':
        return 'ok';
      default:
        return 'muted';
    }
  }

  function severityTone(level) {
    switch (String(level || '').toUpperCase()) {
      case 'HIGH':
      case 'CRITICAL':
        return 'high';
      case 'MEDIUM':
        return 'medium';
      case 'LOW':
        return 'low';
      default:
        return 'muted';
    }
  }

  function aiVerdictTone(verdict) {
    switch (String(verdict || '').toUpperCase()) {
      case 'MALICIOUS':
        return 'bad';
      case 'SUSPICIOUS':
        return 'warn';
      case 'BENIGN':
        return 'ok';
      case 'UNCERTAIN':
      case '':
      default:
        return 'muted';
    }
  }

  function aiVerdictLabel(verdict) {
    const text = String(verdict || '').toUpperCase();
    if (!text) return '未判定';
    if (text === 'MALICIOUS') return '恶意';
    if (text === 'SUSPICIOUS') return '可疑';
    if (text === 'BENIGN') return '良性';
    if (text === 'UNCERTAIN') return '不确定';
    return text;
  }

  // ── HTTP wrapper ──
  // Same-origin credentials are mandatory; a 401 while signed in is the single
  // exit back to the login gate; network failures are tagged so callers can tell
  // a timeout from a server answer.
  async function requestJSON(path, options) {
    const opts = Object.assign({}, options || {});
    const timeoutMs = opts.timeoutMs || REQUEST_TIMEOUT_MS;
    delete opts.timeoutMs;
    opts.credentials = 'same-origin';
    if (!opts.cache) opts.cache = 'no-store';

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    if (!opts.signal) opts.signal = controller.signal;

    let res;
    try {
      res = await fetch(path, opts);
    } catch (err) {
      clearTimeout(timer);
      const timedOut = err && (err.name === 'AbortError' || err.name === 'TimeoutError');
      const wrapped = new Error(timedOut ? '请求超时' : '无法连接服务器');
      wrapped.timeout = timedOut;
      wrapped.network = true;
      throw wrapped;
    }
    clearTimeout(timer);

    let data = null;
    try { data = await res.json(); } catch (_) { data = null; }

    // The login call legitimately answers 401 for bad credentials; only an
    // authenticated caller can lose a session.
    if (res.status === 401 && state.user) {
      dropToLogin('会话已过期，请重新登录');
      const expired = new Error('会话已过期');
      expired.unauthorized = true;
      expired.status = 401;
      throw expired;
    }
    return { status: res.status, ok: res.ok, data: data };
  }

  function auditUrl(path) {
    if (!state.dockerId) return path;
    const sep = path.indexOf('?') === -1 ? '?' : '&';
    return path + sep + 'dockerId=' + encodeURIComponent(state.dockerId);
  }

  // ── Session / login gate ──
  function showAppView(visible) {
    showElement($('auditAppView'), visible);
    showElement($('auditLoginView'), !visible);
  }

  function showLoginError(message) {
    const el = $('auditLoginError');
    if (!el) return;
    el.textContent = message || '';
    el.style.display = message ? '' : 'none';
  }

  function setCapsWarning(on) {
    const el = $('auditLoginCapsWarn');
    if (el) el.style.display = on ? '' : 'none';
  }

  function toggleCapsWarning(input) {
    if (!input || typeof input.getModifierState !== 'function') return;
    setCapsWarning(!!input.getModifierState('CapsLock'));
  }

  function restoreLoginForm() {
    const saved = storeGet(localStorage, USER_KEY);
    if (!saved) return;
    const userEl = $('auditLoginUser');
    if (userEl && !userEl.value) userEl.value = saved;
    const remember = $('auditLoginRemember');
    if (remember) remember.checked = true;
  }

  function stopLoginCountdown() {
    if (state.loginCountdown) {
      clearInterval(state.loginCountdown);
      state.loginCountdown = null;
    }
  }

  function startLoginCountdown(seconds) {
    stopLoginCountdown();
    let left = Math.max(1, Math.floor(Number(seconds) || 60));
    const btn = $('auditLoginSubmit');
    const paint = () => {
      showLoginError('尝试次数过多，请等待 ' + left + ' 秒');
      if (btn) btn.disabled = left > 0;
    };
    paint();
    state.loginCountdown = setInterval(() => {
      left -= 1;
      if (left <= 0) {
        stopLoginCountdown();
        showLoginError('');
        if (btn) btn.disabled = false;
        return;
      }
      paint();
    }, 1000);
  }

  // The session refreshes on every authenticated call, so a countdown would
  // only add noise. The pill carries the state word and its dot stays outside
  // the text node.
  function renderSessionPill() {
    const text = $('auditSessionText');
    if (text) text.textContent = state.user ? '会话有效' : '';
  }

  function stopPollers() {
    if (state.pollTimer) {
      clearInterval(state.pollTimer);
      state.pollTimer = null;
    }
    state.submitToken += 1;
    if (state.submitPollTimer) {
      clearTimeout(state.submitPollTimer);
      state.submitPollTimer = null;
    }
  }

  function resetAppData() {
    state.jobs = [];
    state.jobsTotal = 0;
    state.files = [];
    state.file = null;
    state.storedFile = null;
    state.selectedJobId = '';
    state.currentJob = null;
    state.findings = [];
    state.llm = null;
    state.settings = null;
    state.logs = [];
    state.logsTotal = 0;
    state.logPaused = false;
    state.logAutoScroll = true;

    [
      'auditRecentRows', 'auditJobsRows', 'auditFindingsRows', 'auditRiskChart',
      'engineStaticFields', 'engineLLMFields', 'engineAttestFields',
      'engineHandshakeFields', 'engineLogOutput', 'auditFileList',
    ].forEach((id) => replaceChildren($(id)));
    setText('auditFilesCount', '0 个文件');
    const select = $('auditFindingsJobSelect');
    if (select) {
      select.replaceChildren();
      delete select.dataset.sig;
    }
    paintPill('auditFindingsVerdict', '—', 'muted');
    paintPill('engineStaticStatus', '暂无任务', 'muted');
    paintPill('engineLLMStatus', '未连接', 'muted');
    setText('auditLatestSummary', '暂无审计结论。');
    renderFindingsHeader(null);
    setText('auditJobsCount', '共 0 条，显示 0 条');
    setText('auditFindingStats', '命中 0 条');
    setText('engineLogCount', '0 条日志');
    setText('enginePromptReply', '');
    setText('enginePromptMeta', '');
    setText('auditSubmitHint', '');
    setText('auditSettingsHint', '');
    setText('auditEndpointValue', '—');
    setText('auditLLMEndpointValue', '—');
  }

  function showLoginView() {
    state.user = null;
    state.dropping = false;
    stopPollers();
    showAppView(false);
    restoreLoginForm();
    const pwd = $('auditLoginPassword');
    if (pwd) pwd.value = '';
    if (state.tab === 'audit') {
      const userEl = $('auditLoginUser');
      if (userEl && !userEl.value) userEl.focus();
    }
  }

  // dropToLogin is the one way an authenticated view falls back to the gate.
  // It clears pollers and in-memory data so the next operator never inherits the
  // previous one's findings.
  function dropToLogin(message) {
    const already = state.dropping;
    stopPollers();
    stopLoginCountdown();
    state.dropping = true;
    state.user = null;
    state.expiresAt = '';
    resetAppData();
    showAppView(false);
    restoreLoginForm();
    const pwd = $('auditLoginPassword');
    if (pwd) pwd.value = '';
    showLoginError(message || '');
    if (!already && message) toast('会话已过期，请重新登录');
    if (state.tab === 'audit') {
      const userEl = $('auditLoginUser');
      if (userEl) userEl.focus();
    }
  }

  function enterApp(user, expiresAt) {
    state.user = user || { name: '' };
    state.expiresAt = expiresAt || '';
    state.dropping = false;
    stopLoginCountdown();
    setText('auditUserName', state.user.name || '—');
    setText('auditUserRole', state.user.role || '');
    setText('auditSettingsUser', [state.user.name, state.user.role].filter(Boolean).join(' · ') || '—');
    showAppView(true);
    showLoginError('');
    setCapsWarning(false);
    renderSessionPill();
    applyView(VIEWS.indexOf(state.view) === -1 ? 'jobs' : state.view);
    bootstrapApp();
  }

  async function checkSession() {
    if (state.sessionChecking) return;
    state.sessionChecking = true;
    try {
      const res = await requestJSON('/api/console/session', { timeoutMs: 10000 });
      const data = unwrap(res.data) || {};
      if (res.ok && data.authenticated) {
        enterApp(data.user || { name: '' }, data.expiresAt || '');
      } else {
        showLoginView();
      }
    } catch (err) {
      // Boot is the one place an unreachable server stays silent: the login form
      // is the retry surface, and the page still has to render.
      if (!err.unauthorized) showLoginView();
    } finally {
      state.sessionChecking = false;
    }
  }

  async function auditConsoleLogin(event) {
    if (event && event.preventDefault) event.preventDefault();
    if (state.loginBusy) return;

    const userEl = $('auditLoginUser');
    const pwdEl = $('auditLoginPassword');
    const btn = $('auditLoginSubmit');
    const rememberEl = $('auditLoginRemember');
    const username = userEl ? userEl.value.trim() : '';
    const password = pwdEl ? pwdEl.value : '';

    if (!username || !password) {
      showLoginError('请输入用户名和口令');
      return;
    }

    state.loginBusy = true;
    if (btn) {
      btn.disabled = true;
      btn.classList.add('loading');
    }
    showLoginError('');

    try {
      const res = await requestJSON('/api/console/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username, password: password }),
      });
      const data = unwrap(res.data) || {};

      if (res.ok && data.ok !== false) {
        // Remember-me stores the username only; a password in local storage is
        // readable by any script on the origin.
        if (rememberEl && rememberEl.checked) storeSet(localStorage, USER_KEY, username);
        else storeRemove(localStorage, USER_KEY);
        if (pwdEl) pwdEl.value = '';
        enterApp(data.user || { name: username }, data.expiresAt || '');
        return;
      }

      if (res.status === 429) {
        startLoginCountdown(Math.max(1, Math.floor(Number(data.retryAfterSeconds) || 60)));
        return;
      }

      if (res.status === 401) {
        const left = Number(data.attemptsLeft);
        showLoginError(Number.isFinite(left) && left > 0
          ? '用户名或口令错误，还可尝试 ' + left + ' 次'
          : '用户名或口令错误');
      } else {
        showLoginError(data.error || data.msg || ('登录失败（HTTP ' + res.status + '）'));
      }
    } catch (err) {
      if (!err.unauthorized) {
        showLoginError(err.timeout
          ? '登录请求超时，请稍后重试'
          : '无法连接服务器，请检查网络后重试');
      }
    } finally {
      state.loginBusy = false;
      if (btn) {
        btn.classList.remove('loading');
        // A 429 countdown owns the disabled state.
        if (!state.loginCountdown) btn.disabled = false;
      }
    }
  }

  async function auditConsoleLogout() {
    try {
      await requestJSON('/api/console/logout', { method: 'POST', timeoutMs: 10000 });
    } catch (_) {
      // Best effort: the local session is dropped regardless.
    }
    state.dropping = false;
    state.user = null;
    state.expiresAt = '';
    stopPollers();
    stopLoginCountdown();
    resetAppData();
    showAppView(false);
    showLoginError('');
    restoreLoginForm();
    toast({ type: 'info', title: '已退出登录', message: '本机会话已清除' });
  }

  function auditConsoleTogglePwd(event) {
    if (event && event.preventDefault) event.preventDefault();
    const pwd = $('auditLoginPassword');
    const btn = $('auditLoginTogglePwd');
    if (!pwd) return;
    const reveal = pwd.type === 'password';
    pwd.type = reveal ? 'text' : 'password';
    if (btn) {
      btn.classList.toggle('on', reveal);
      btn.setAttribute('aria-pressed', reveal ? 'true' : 'false');
      btn.setAttribute('title', reveal ? '隐藏口令' : '显示口令');
    }
    pwd.focus();
  }

  // ── Tabs and views ──
  function tabFromLocation() {
    if (location.hash === '#audit') return 'audit';
    return storeGet(sessionStorage, TAB_KEY) === 'audit' ? 'audit' : 'platform';
  }

  function replaceHash(tab) {
    try {
      const base = location.pathname + location.search;
      const target = tab === 'audit' ? base + '#audit' : base;
      if (base + location.hash !== target) history.replaceState(null, '', target);
    } catch (_) {}
  }

  function auditTabSwitch(tab) {
    const next = tab === 'audit' ? 'audit' : 'platform';
    state.tab = next;

    setDisplayed('tabPanelPlatform', next === 'platform');
    setDisplayed('tabPanelAudit', next === 'audit');

    document.querySelectorAll('#tabBar .tab-btn').forEach((btn) => {
      const on = btn.dataset.tab === next;
      btn.classList.toggle('active', on);
      btn.setAttribute('aria-selected', on ? 'true' : 'false');
    });

    storeSet(sessionStorage, TAB_KEY, next);
    replaceHash(next);

    if (next === 'audit') {
      if (!state.user) checkSession();
      else syncPoller(true);
    } else {
      syncPoller(false);
    }
  }

  function applyView(view) {
    const next = VIEWS.indexOf(view) === -1 ? 'jobs' : view;
    state.view = next;

    VIEWS.forEach((name) => setDisplayed(VIEW_IDS[name], name === next));

    document.querySelectorAll('.audit-nav-item[data-audit-view]').forEach((btn) => {
      const on = btn.dataset.auditView === next;
      btn.classList.toggle('active', on);
      btn.setAttribute('aria-selected', on ? 'true' : 'false');
    });
  }

  function auditConsoleSwitchView(view) {
    if (!state.user) {
      showLoginView();
      return;
    }
    applyView(view);
    refreshVisibleView();
  }

  async function refreshVisibleView() {
    if (!state.user) return;
    switch (state.view) {
      case 'jobs':
        await refreshJobs(false);
        await refreshAuditFiles(true);
        break;
      case 'findings':
        await refreshFindings(false);
        break;
      case 'engine':
        await refreshEngine();
        break;
      case 'settings':
        await refreshSettings(false);
        break;
      default:
        break;
    }
  }

  async function bootstrapApp() {
    await loadInstances();
    if (state.tab === 'audit') await refreshVisibleView();
    syncPoller(false);
  }

  // ── Instance selection ──
  function instanceKind(kind) {
    if (kind === 'tee') return 'TEE';
    if (kind === 'fhe') return 'FHE';
    return '未知';
  }

  function fillInstanceSelect(list, defaultId) {
    const sel = $('auditInstanceSelect');
    if (!sel) return;

    const signature = list
      .map((item) => (item.dockerId || '') + '|' + (item.kind || '') + '|' + (item.accepted ? '1' : '0'))
      .join(',') + '#' + (defaultId || '');

    if (signature !== state.instanceSignature) {
      state.instanceSignature = signature;
      const previous = sel.value || state.dockerId;
      sel.replaceChildren();
      if (!list.length) {
        const opt = document.createElement('option');
        opt.value = '';
        opt.textContent = '（暂无已注册实例）';
        sel.appendChild(opt);
      } else {
        list.forEach((item) => {
          const id = item.dockerId || '';
          if (!id) return;
          const opt = document.createElement('option');
          opt.value = id;
          opt.textContent = instanceKind(item.kind) + ' · ' + shortId(id);
          opt.title = id;
          sel.appendChild(opt);
        });
      }
      if (previous && list.some((item) => item.dockerId === previous)) {
        sel.value = previous;
      } else if (defaultId && list.some((item) => item.dockerId === defaultId)) {
        sel.value = defaultId;
      }
    }
    if (!sel.value && sel.options.length && sel.options[0].value) sel.value = sel.options[0].value;
    state.dockerId = sel.value || '';
    updateEndpointDisplay();
  }

  async function loadInstances() {
    try {
      const res = await requestJSON('/api/instances', { timeoutMs: 10000 });
      if (!res.ok) return;
      const payload = unwrap(res.data) || {};
      const list = Array.isArray(payload.instances) ? payload.instances : [];
      state.instances = list;
      const stored = storeGet(localStorage, DOCKER_KEY) || '';
      fillInstanceSelect(list, payload.defaultDockerId || stored || '');
      if (state.dockerId) storeSet(localStorage, DOCKER_KEY, state.dockerId);
    } catch (err) {
      if (err.unauthorized) return;
      // Transient: the selector keeps its last state.
    }
  }

  function updateEndpointDisplay() {
    const current = state.instances.find((item) => item.dockerId === state.dockerId);
    let address = current ? (current.taaTarget || current.address || '') : '';
    if (!address && typeof getTaaAddr === 'function') address = getTaaAddr();
    setText('auditEndpointValue', address || '—');
  }

  async function onInstanceChanged() {
    const sel = $('auditInstanceSelect');
    state.dockerId = sel ? sel.value : '';
    if (state.dockerId) storeSet(localStorage, DOCKER_KEY, state.dockerId);
    updateEndpointDisplay();

    state.selectedJobId = '';
    state.currentJob = null;
    state.findings = [];
    const jobSelect = $('auditFindingsJobSelect');
    if (jobSelect) delete jobSelect.dataset.sig;

    await refreshJobs(false);
    if (state.view === 'findings') await refreshFindings(false);
    if (state.view === 'engine') await refreshEngine();
    if (state.view === 'settings') await refreshSettings(false);
  }


  // ── Jobs ──
  async function refreshJobs(silent) {
    if (!state.user) return;
    try {
      const res = await requestJSON(auditUrl('/api/audit/console/jobs?limit=50'), { timeoutMs: REQUEST_TIMEOUT_MS });
      if (!res.ok) {
        if (!silent) toast({ type: 'warning', title: '任务列表刷新失败', message: 'HTTP ' + res.status });
        return;
      }
      const data = unwrap(res.data) || {};
      state.jobs = Array.isArray(data.jobs) ? data.jobs : [];
      state.jobsTotal = data.total != null ? toNumber(data.total) : state.jobs.length;
      renderJobsTable();
      fillFindingsJobSelect();
      // Restore the rail from the newest local job so a page reload still shows
      // where the last audit ended. A submission in flight owns the rail.
      if (!state.submitBusy) {
        renderStepper(state.jobs.find((job) => job && job.stages) || null);
      }
    } catch (err) {
      if (err.unauthorized || silent) return;
      toast({ type: 'warning', title: '任务列表刷新失败', message: err.message });
    }
  }

  function filteredJobs() {
    const filterEl = $('auditJobsFilter');
    const filter = filterEl ? filterEl.value : 'all';
    if (filter === 'pending') return state.jobs.filter((job) => statusOf(job).key === 'pending');
    if (filter === 'passed') {
      return state.jobs.filter((job) => statusOf(job).key === 'done' && !!job.passed);
    }
    if (filter === 'failed') {
      return state.jobs.filter((job) => statusOf(job).key === 'failed'
        || (statusOf(job).key === 'done' && !job.passed));
    }
    return state.jobs.slice();
  }

  // renderJobMetrics feeds the four counters above the workbench from the job
  // list already in memory; it never issues another request.
  function renderJobMetrics() {
    const jobs = Array.isArray(state.jobs) ? state.jobs : [];
    let passed = 0;
    let failed = 0;
    let latest = null;

    jobs.forEach((job) => {
      const key = statusOf(job).key;
      if (key === 'failed') {
        failed += 1;
        return;
      }
      if (key !== 'done') return;
      if (job.passed) passed += 1;
      else failed += 1;
      const at = Date.parse(job.at || '') || 0;
      if (!latest || at > latest.at) latest = { at: at, job: job };
    });

    setText('auditMetricTotal', String(Math.max(state.jobsTotal || 0, jobs.length)));
    setText('auditMetricPassed', String(passed));
    setText('auditMetricFailed', String(failed));
    setText('auditMetricDuration', latest && latest.job.durationMs != null
      ? fmtDuration(latest.job.durationMs)
      : '—');
  }

  function renderJobsTable() {
    const tbody = $('auditJobsRows');
    if (!tbody) return;
    tbody.replaceChildren();

    const rows = filteredJobs();
    const total = Math.max(state.jobsTotal, state.jobs.length);
    setText('auditJobsCount', '共 ' + total + ' 条，显示 ' + rows.length + ' 条');
    renderJobMetrics();

    if (!rows.length) {
      const text = state.jobs.length
        ? '当前筛选条件下没有任务。'
        : '暂无审计任务。在上方选择文件并启动一次审计。';
      emptyRow(tbody, 9, text);
      return;
    }

    rows.forEach((job) => {
      const status = statusOf(job);
      const verdict = verdictOf(job);
      const pending = status.key === 'pending';
      const tr = document.createElement('tr');
      if (pending) tr.classList.add('audit-row-pending');
      tr.dataset.jobId = job.id || '';
      tr.dataset.status = status.key;

      // A finished row opens its findings on click, matching the card hint.
      // The inline buttons stop propagation so they keep their own behaviour.
      if (!pending) {
        tr.classList.add('audit-row-clickable');
        tr.tabIndex = 0;
        tr.setAttribute('role', 'button');
        tr.title = '打开「审计结果」查看逐条发现';
        const openRow = () => {
          if (status.key === 'failed') {
            toast({
              type: 'error',
              title: '任务未完成',
              message: job.error || '审计未返回结论，请检查原因后重新提交。',
            });
            return;
          }
          auditLoadJob(job.id);
        };
        tr.addEventListener('click', openRow);
        tr.addEventListener('keydown', (ev) => {
          if (ev.key === 'Enter' || ev.key === ' ') {
            ev.preventDefault();
            openRow();
          }
        });
      }

      tr.appendChild(makeCell(fmtTime(job.at), { nowrap: true }));
      tr.appendChild(idCell(job));
      tr.appendChild(makeCell(badge(verdict.label, verdict.tone)));
      tr.appendChild(makeCell(badge(status.label, status.tone)));

      if (pending) {
        const dots = document.createElement('span');
        dots.className = 'audit-pending-dots';
        dots.textContent = stepLabel(job.stage);
        tr.appendChild(makeCell(dots));
        tr.appendChild(makeCell('—', { title: false }));
        tr.appendChild(makeCell(String(toNumber(job.files) || 1)));
        tr.appendChild(makeCell('进行中', { nowrap: true }));
      } else if (status.key === 'failed') {
        tr.appendChild(makeCell('—', { title: false }));
        tr.appendChild(makeCell('—', { title: false }));
        tr.appendChild(makeCell(String(toNumber(job.files))));
        tr.appendChild(makeCell('—', { nowrap: true }));
      } else {
        tr.appendChild(makeCell(badge(riskLabel(job.riskLevel), riskTone(job.riskLevel))));
        tr.appendChild(makeCell(toNumber(job.high) + ' / ' + toNumber(job.medium) + ' / ' + toNumber(job.low), { mono: true }));
        tr.appendChild(makeCell(String(toNumber(job.files))));
        tr.appendChild(makeCell(fmtDuration(job.durationMs), { nowrap: true }));
      }

      const actions = document.createElement('div');
      actions.className = 'audit-row-actions';

      const action = document.createElement('button');
      action.type = 'button';
      action.className = 'secondary';
      if (pending) {
        action.textContent = '等待';
        action.disabled = true;
      } else if (status.key === 'failed') {
        action.textContent = '详情';
        action.addEventListener('click', (ev) => {
          ev.stopPropagation();
          toast({
            type: 'error',
            title: '任务未完成',
            message: job.error || '审计未返回结论，请检查原因后重新提交。',
          });
        });
      } else {
        action.textContent = '查看';
        action.addEventListener('click', (ev) => {
          ev.stopPropagation();
          auditLoadJob(job.id);
        });
      }
      actions.appendChild(action);

      // A running row cannot be deleted: the runner still writes to it.
      if (!pending) {
        const del = document.createElement('button');
        del.type = 'button';
        del.className = 'secondary audit-danger-btn';
        del.textContent = '删除';
        del.addEventListener('click', (ev) => {
          ev.stopPropagation();
          armRowDelete(del, job);
        });
        actions.appendChild(del);
      }
      tr.appendChild(makeCell(actions, { title: false }));

      tbody.appendChild(tr);
    });
  }

  // stepLabel names the step a pending job is on, using the server's `stage`.
  function stepLabel(key) {
    switch (key) {
      case 'receive': return '接收审计包…';
      case 'extract': return '解压归档…';
      case 'static': return '静态扫描…';
      case 'binary': return '二进制检查…';
      case 'ai': return 'AI 判定…';
      case 'conclude': return '汇总结论…';
      case 'done': return '已完成';
      default: return '执行中…';
    }
  }

  // ── Row deletion ──
  // The first click arms the button for a few seconds; the second click sends
  // the DELETE. Disarming on timeout keeps a stray click from removing a record.
  const pendingRowDeletes = new Map();

  function armRowDelete(btn, job) {
    const id = job.id || job.requestId;
    if (!id) return;
    if (btn.dataset.armed === '1') {
      clearTimeout(pendingRowDeletes.get(id));
      pendingRowDeletes.delete(id);
      auditDeleteJob(job);
      return;
    }
    btn.dataset.armed = '1';
    btn.textContent = '确认删除';
    btn.classList.add('is-armed');
    const timer = setTimeout(() => {
      pendingRowDeletes.delete(id);
      if (!btn.isConnected) return;
      btn.dataset.armed = '0';
      btn.textContent = '删除';
      btn.classList.remove('is-armed');
    }, 4000);
    pendingRowDeletes.set(id, timer);
  }

  async function auditDeleteJob(job) {
    const id = job.id || job.requestId;
    if (!state.user || !id) return;
    try {
      const res = await requestJSON(auditUrl('/api/audit/console/jobs/' + encodeURIComponent(id)), {
        method: 'DELETE',
        timeoutMs: REQUEST_TIMEOUT_MS,
      });
      const data = unwrap(res.data) || {};
      if (!res.ok || data.ok === false) {
        const message = data.error || data.msg || ('HTTP ' + res.status);
        toast({ type: 'warning', title: '删除失败', message: message });
        return;
      }
      state.jobs = state.jobs.filter((row) => (row.id || row.requestId) !== id);
      if (state.selectedJobId === id) {
        state.selectedJobId = '';
        state.currentJob = null;
        state.findings = [];
      }
      renderJobsTable();
      fillFindingsJobSelect();
      toast({ type: 'success', title: '已删除', message: '任务记录已从列表移除' });
    } catch (err) {
      if (!err.unauthorized) toast({ type: 'warning', title: '删除失败', message: err.message });
    }
  }

  function fillFindingsJobSelect() {
    const sel = $('auditFindingsJobSelect');
    if (!sel) return;

    // Only a completed job has findings to explore; a pending one has no report
    // yet and a failed one never produced any.
    const completed = state.jobs.filter((job) => statusOf(job).key === 'done');
    const signature = completed
      .map((job) => (job.id || '') + '|' + (job.at || '') + '|' + (job.passed ? '1' : '0'))
      .join(',');
    if (sel.dataset.sig !== signature) {
      sel.dataset.sig = signature;
      sel.replaceChildren();
      if (!completed.length) {
        const opt = document.createElement('option');
        opt.value = '';
        opt.textContent = '（暂无已完成的审计任务）';
        sel.appendChild(opt);
      } else {
        completed.forEach((job) => {
          const verdict = verdictOf(job);
          const opt = document.createElement('option');
          opt.value = job.id || '';
          opt.textContent = fmtTime(job.at) + ' · ' + shortID(job.requestId || job.id || '—') + ' · ' + verdict.label;
          opt.title = job.requestId || job.id || '';
          sel.appendChild(opt);
        });
      }
    }

    if (state.selectedJobId && Array.from(sel.options).some((opt) => opt.value === state.selectedJobId)) {
      sel.value = state.selectedJobId;
    }
  }

  // ── Audit submission ──
  function setHint(id, ok, message) {
    const el = $(id);
    if (!el) return;
    el.textContent = message || '';
    el.style.color = ok ? 'var(--ok, #059669)' : 'var(--bad, #dc2626)';
  }

  function genRequestId() {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
      return 'audit-' + crypto.randomUUID();
    }
    return 'audit-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);
  }

  // shortID keeps a long request id readable in a table cell or a select
  // option. The full value stays in the element's title and the detail header.
  function shortID(id) {
    const text = String(id == null ? '' : id);
    return text.length > 26 ? text.slice(0, 24) + '…' : text;
  }

  // idCell is the request-id cell shared by both job tables: the visible text
  // is shortened, the full id stays in the tooltip.
  function idCell(job) {
    const full = String(job.requestId || job.id || '');
    const td = makeCell(shortID(full) || '—', { mono: true, title: false });
    if (full) td.title = full;
    return td;
  }

  function humanSize(bytes) {
    const n = Number(bytes);
    if (!Number.isFinite(n) || n <= 0) return '—';
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    if (n < 1024 * 1024 * 1024) return (n / (1024 * 1024)).toFixed(1) + ' MB';
    return (n / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
  }

  function fileKind(file) {
    const name = String((file && file.name) || '').toLowerCase();
    if (/\.(tar|tar\.gz|tgz|tar\.bz2|tbz2|tar\.xz)$/.test(name)) return '归档包';
    if (/\.zip$/.test(name)) return 'ZIP 包';
    if (/\.gz$/.test(name)) return 'GZIP 包';
    return '文件';
  }

  // Short badge shown beside a file-area entry's name.
  function kindOfName(name) {
    const lower = String(name || '').toLowerCase();
    if (/\.zip$/.test(lower)) return 'ZIP';
    if (/\.(tar|tar\.gz|tgz|tar\.bz2|tbz2|tar\.xz)$/.test(lower)) return 'TAR';
    if (/\.gz$/.test(lower)) return 'GZ';
    return 'ARCHIVE';
  }

  // ── Audit submission ──
  //
  // The browser posts the plaintext archive to the mock and the mock runs the
  // whole audit in its own process, following the same design TAA uses: unpack,
  // Tier 1 static scan, the binary channel, optional Tier 2 adjudication and the
  // conclusion. The submission answers as soon as the job is recorded, so the
  // returned row is `pending` and this view polls the job's `stages` until the
  // verdict arrives. Only one audit runs at a time; the server answers 409.
  function renderStepper(job) {
    const host = $('auditStepper');
    if (!host) return;
    const steps = host.querySelectorAll('.audit-stepper-step');
    if (!steps.length) return;

    const stages = job && job.stages && typeof job.stages === 'object' ? job.stages : null;

    const states = [];
    steps.forEach((item) => {
      const key = item.dataset.step || '';
      let state = stages ? stages[key] : '';
      if (!state) state = 'pending';
      states.push(state);
      item.dataset.state = state;
      item.classList.toggle('is-active', state === 'active');
      item.classList.toggle('is-done', state === 'done');
      item.classList.toggle('is-skipped', state === 'skipped');
      item.classList.toggle('is-error', state === 'error');
    });

    // The rail's header answers "where is this run" at a glance; the bar under
    // it fills as steps settle, so a long AI step still shows progress.
    const settled = states.filter((state) => state === 'done' || state === 'skipped').length;
    const percent = steps.length ? Math.round((settled / steps.length) * 100) : 0;
    const bar = $('auditRunProgressBar');
    if (bar) bar.style.width = percent + '%';
    const progress = document.querySelector('.audit-run-progress');
    if (progress) progress.setAttribute('aria-valuenow', String(percent));

    let tone = 'idle';
    let label = job ? '未开始' : '空闲';
    if (states.includes('error')) {
      tone = 'error';
      label = '执行失败';
    } else if (states.includes('active')) {
      tone = 'active';
      label = '执行中';
    } else if (job && settled === steps.length && settled > 0) {
      tone = 'done';
      label = '已完成';
    }
    const status = $('auditRunStatus');
    if (status) status.dataset.tone = tone;
    setText('auditRunStatusText', label);
  }

  function setUploadProgress(fraction, stageText) {
    const pct = Math.max(0, Math.min(100, Math.round((Number(fraction) || 0) * 100)));
    const bar = $('auditUploadBar');
    if (bar) bar.style.width = pct + '%';
    setText('auditUploadPercent', pct + '%');
    if (stageText != null) setText('auditUploadStage', stageText);
  }

  function showUploadProgress(visible, running) {
    const el = $('auditUploadProgress');
    if (!el) return;
    el.style.display = visible ? '' : 'none';
    // Running mode turns the determinate transfer bar into an indeterminate
    // stripe: once the archive is accepted the percentage stops meaning anything.
    el.classList.toggle('is-running', !!running);
  }

  // showChosen paints the selected-file strip for either a local File or a file
  // area entry; both carry `name` and `size`.
  function showChosen(picked, typeText) {
    const meta = $('auditFileMeta');
    const clearBtn = $('auditFileClearBtn');
    const drop = $('auditFileDrop');

    setText('auditFileName', picked.name);
    setText('auditFileSize', humanSize(picked.size));
    setText('auditFileTypeText', typeText);
    if (meta) meta.style.display = '';
    if (clearBtn) clearBtn.style.display = '';
    if (drop) drop.classList.add('has-file');
    setText('auditDropTitle', '拖拽其他归档到此，或点击更换');
    setHint('auditSubmitHint', true, '已选择 ' + picked.name + '，点击「上传并启动审计」开始。');
  }

  function hideChosen() {
    const meta = $('auditFileMeta');
    const clearBtn = $('auditFileClearBtn');
    const drop = $('auditFileDrop');
    if (meta) meta.style.display = 'none';
    if (clearBtn) clearBtn.style.display = 'none';
    if (drop) drop.classList.remove('has-file');
    setText('auditDropTitle', '拖拽文件到此处，或点击选择');
    setText('auditFileName', '');
    setText('auditFileSize', '');
    setText('auditFileTypeText', '在本机解压后审计');
  }

  function setChosenFile(file) {
    state.file = file || null;
    state.storedFile = null;
    if (!file) {
      hideChosen();
      renderAuditFiles();
      return;
    }
    showChosen(file, fileKind(file));
    renderAuditFiles();
  }

  // chooseStoredFile selects an entry from the file area. The archive is
  // already on the server, so submission sends its id instead of the bytes.
  function chooseStoredFile(entry) {
    state.file = null;
    state.storedFile = entry || null;
    const input = $('auditFileInput');
    if (input) input.value = '';
    if (!entry) {
      hideChosen();
      renderAuditFiles();
      return;
    }
    showChosen(entry, '文件区域 · 可重复审计');
    renderAuditFiles();
  }

  function clearChosenFile() {
    const input = $('auditFileInput');
    if (input) input.value = '';
    state.file = null;
    state.storedFile = null;
    hideChosen();
    renderAuditFiles();
    setHint('auditSubmitHint', true, '');
  }

  // ── File area ──
  //
  // Every accepted upload is kept server-side. The list is newest first; a drag
  // from an item to the launcher selects it by id, so repeating a run re-uses
  // the stored archive instead of uploading it again.
  const ARCHIVE_ICON = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H7a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7z"></path><path d="M14 2v5h5"></path><path d="M10 9h1M10 12h1M10 15h1"></path></svg>';

  async function refreshAuditFiles(silent) {
    if (!state.user) return;
    try {
      const res = await requestJSON('/api/audit/console/files', { timeoutMs: REQUEST_TIMEOUT_MS });
      if (!res.ok) {
        if (!silent) toast({ type: 'warning', title: '文件区域刷新失败', message: 'HTTP ' + res.status });
        return;
      }
      const data = unwrap(res.data) || {};
      state.files = Array.isArray(data.files) ? data.files : [];
      renderAuditFiles();
    } catch (err) {
      if (err.unauthorized || silent) return;
      toast({ type: 'warning', title: '文件区域刷新失败', message: err.message });
    }
  }

  function renderAuditFiles() {
    const host = $('auditFileList');
    if (!host) return;
    host.replaceChildren();
    setText('auditFilesCount', state.files.length + ' 个文件');

    if (!state.files.length) {
      const empty = document.createElement('li');
      empty.className = 'audit-file-empty';
      empty.textContent = '暂无文件。上传一个归档后会自动保存在这里。';
      host.appendChild(empty);
      return;
    }

    state.files.forEach((entry) => {
      const item = document.createElement('li');
      item.className = 'audit-file-item';
      item.dataset.fileId = entry.id;
      item.draggable = true;
      item.title = '拖拽到上方「发起代码审计」窗口，或点击选用';
      if (state.storedFile && state.storedFile.id === entry.id) item.classList.add('is-selected');

      const icon = document.createElement('span');
      icon.className = 'audit-file-icon';
      icon.innerHTML = ARCHIVE_ICON;
      item.appendChild(icon);

      const body = document.createElement('span');
      body.className = 'audit-file-body';
      const head = document.createElement('span');
      head.className = 'audit-file-head';
      const name = document.createElement('span');
      name.className = 'audit-file-name';
      name.textContent = entry.name || 'archive';
      const kind = document.createElement('span');
      kind.className = 'audit-file-kind';
      kind.textContent = kindOfName(entry.name || '');
      head.appendChild(name);
      head.appendChild(kind);
      const sub = document.createElement('span');
      sub.className = 'audit-file-sub';
      const shortID = (entry.id || '').slice(0, 6);
      sub.textContent = humanSize(entry.size) + ' · ' + fmtTime(entry.uploadedAt)
        + (shortID ? ' · #' + shortID : '');
      body.appendChild(head);
      body.appendChild(sub);
      item.appendChild(body);

      const actions = document.createElement('span');
      actions.className = 'audit-file-actions';

      const use = document.createElement('button');
      use.type = 'button';
      use.className = 'secondary audit-file-use';
      use.textContent = '选用';
      use.addEventListener('click', (ev) => {
        ev.stopPropagation();
        chooseStoredFile(entry);
      });
      actions.appendChild(use);

      const del = document.createElement('button');
      del.type = 'button';
      del.className = 'secondary audit-danger-btn';
      del.textContent = '删除';
      del.addEventListener('click', (ev) => {
        ev.stopPropagation();
        armFileDelete(del, entry);
      });
      actions.appendChild(del);
      item.appendChild(actions);

      item.addEventListener('dragstart', (ev) => {
        if (!ev.dataTransfer) return;
        ev.dataTransfer.effectAllowed = 'copy';
        ev.dataTransfer.setData('application/x-taa-audit-file', entry.id);
        ev.dataTransfer.setData('text/plain', entry.name || '');
      });
      item.addEventListener('click', (ev) => {
        if (ev.target.closest('button')) return;
        chooseStoredFile(entry);
      });

      host.appendChild(item);
    });
  }

  // Two clicks to delete, same as a job row: the first arms for four seconds.
  const pendingFileDeletes = new Map();

  function armFileDelete(btn, entry) {
    const id = entry.id;
    if (pendingFileDeletes.has(id)) {
      clearTimeout(pendingFileDeletes.get(id));
      pendingFileDeletes.delete(id);
      deleteAuditFile(entry);
      return;
    }
    btn.textContent = '确认删除';
    btn.classList.add('is-armed');
    const timer = setTimeout(() => {
      pendingFileDeletes.delete(id);
      btn.textContent = '删除';
      btn.classList.remove('is-armed');
    }, 4000);
    pendingFileDeletes.set(id, timer);
  }

  async function deleteAuditFile(entry) {
    try {
      const res = await requestJSON(auditUrl('/api/audit/console/files/' + encodeURIComponent(entry.id)), {
        method: 'DELETE',
        timeoutMs: REQUEST_TIMEOUT_MS,
      });
      const data = unwrap(res.data) || {};
      if (!res.ok || data.ok === false) {
        throw new Error(data.error || data.msg || ('HTTP ' + res.status));
      }
      state.files = state.files.filter((item) => item.id !== entry.id);
      if (state.storedFile && state.storedFile.id === entry.id) {
        state.storedFile = null;
        hideChosen();
      }
      renderAuditFiles();
      setHint('auditSubmitHint', true, '已从文件区域删除 ' + (entry.name || '文件') + '。');
    } catch (err) {
      if (err.unauthorized) return;
      toast({ type: 'warning', title: '删除失败', message: err.message });
      renderAuditFiles();
    }
  }

  function rotateTaskId() {
    const now = new Date();
    const stamp = now.toISOString().slice(0, 19).replace(/[-:T]/g, '');
    state.taskId = 'audit-' + stamp;
    state.requestId = genRequestId();
    setText('auditTaskIdPreview', state.taskId);
  }

  function uploadAuditPackage(formData, onProgress) {
    return new Promise((resolve, reject) => {
      let xhr;
      try {
        xhr = new XMLHttpRequest();
      } catch (err) {
        reject(new Error('浏览器不支持文件上传'));
        return;
      }

      xhr.open('POST', auditUrl('/api/audit/console/submit'), true);
      xhr.withCredentials = true;
      // No client-side deadline: the package size is not capped, and a fixed
      // timeout would only turn a large upload over a slow link into a failure.

      if (xhr.upload) {
        xhr.upload.addEventListener('progress', (ev) => {
          if (ev.lengthComputable && ev.total > 0) onProgress(ev.loaded / ev.total);
        });
      }

      xhr.onload = () => {
        let data = null;
        try { data = JSON.parse(xhr.responseText); } catch (_) { data = null; }
        resolve({ status: xhr.status, ok: xhr.status >= 200 && xhr.status < 300, data: data });
      };
      xhr.onerror = () => reject(new Error('无法连接服务器'));
      xhr.ontimeout = () => {
        const err = new Error('上传超时');
        err.timeout = true;
        reject(err);
      };
      xhr.onabort = () => reject(new Error('上传已取消'));
      xhr.send(formData);
    });
  }

  function optimisticPendingJob(data, file) {
    return {
      id: data.jobId || state.requestId,
      dockerId: 'local',
      requestId: data.requestId || state.requestId,
      taskId: data.taskId || state.taskId,
      at: data.at || new Date().toISOString(),
      status: 'pending',
      stage: data.stage || 'receive',
      stages: data.stages || null,
      code: 0,
      passed: false,
      riskLevel: '',
      high: 0,
      medium: 0,
      low: 0,
      durationMs: 0,
      files: 0,
      findings: 0,
      originalName: data.originalName || (file && file.name) || '',
      size: data.size || (file && file.size) || 0,
    };
  }

  async function auditSubmitAudit() {
    if (!state.user) return;
    if (state.submitBusy) return;

    const btn = $('auditSubmitBtn');
    const file = state.file;
    const stored = state.storedFile;
    const picked = stored || file;

    if (!picked) {
      setHint('auditSubmitHint', false, '请先选择待审计的模型包或代码包。');
      return;
    }
    if (file && file.size <= 0) {
      setHint('auditSubmitHint', false, '文件为空，请重新选择。');
      return;
    }

    state.submitBusy = true;
    if (btn) btn.disabled = true;

    const requestId = state.requestId || genRequestId();
    state.requestId = requestId;

    showUploadProgress(true);
    setUploadProgress(stored ? 0.9 : 0, stored ? '正在启动本地审计…' : '正在上传文件…');
    renderStepper(null);
    setHint('auditSubmitHint', true, stored ? '正在复用文件区域中的归档…' : '正在上传明文归档…');
    setText('auditRunFile', picked.name);

    try {
      const form = new FormData();
      if (stored) {
        form.append('fileId', stored.id);
      } else {
        form.append('file', file, file.name);
      }
      form.append('requestId', requestId);
      form.append('taskId', state.taskId || '');

      const res = await uploadAuditPackage(form, (fraction) => {
        // The upload owns the first 90% of the bar; the rest is the archive
        // sniff, job record and the asynchronous start.
        setUploadProgress(fraction * 0.9, '正在上传 ' + Math.round(fraction * 100) + '%…');
      });

      if (res.status === 401) {
        dropToLogin('会话已过期，请重新登录');
        return;
      }

      const data = unwrap(res.data) || {};
      if (!res.ok || data.ok === false) {
        const message = data.error || data.msg || ('HTTP ' + res.status);
        throw new Error(message);
      }

      setUploadProgress(1, '已接收，正在本机执行审计…');

      const pending = optimisticPendingJob(data, picked);
      state.jobs = [pending].concat(state.jobs.filter((job) => job.requestId !== pending.requestId));
      renderJobsTable();
      fillFindingsJobSelect();
      renderStepper(pending);
      refreshAuditFiles(true);

      const dispatchedTaskId = data.taskId || state.taskId;
      rotateTaskId();
      clearChosenFile();
      setHint('auditSubmitHint', true, '已接收审计任务 ' + dispatchedTaskId + '，本地审计执行中。');

      await waitForSubmittedJob(pending.requestId);
    } catch (err) {
      if (err.unauthorized) return;
      // The failed requestId is spent: a retry must carry a fresh one, or a
      // later begin with the same id would be deduplicated against the failed row.
      rotateTaskId();
      const reason = err.timeout ? '请求超时，请稍后重试。' : String(err.message || '提交失败');
      showUploadProgress(false);
      setHint('auditSubmitHint', false, '提交失败：' + reason);
      toast({ type: 'error', title: '审计任务提交失败', message: reason });
    } finally {
      state.submitBusy = false;
      if (btn) btn.disabled = false;
    }
  }

  async function waitForSubmittedJob(requestId) {
    const token = ++state.submitToken;
    const started = Date.now();

    return new Promise((resolve) => {
      const tick = async () => {
        if (token !== state.submitToken || !state.user) {
          resolve();
          return;
        }

        let found = null;
        try {
          const res = await requestJSON(auditUrl('/api/audit/console/jobs?limit=50'), { timeoutMs: 10000 });
          if (res.ok) {
            const data = unwrap(res.data) || {};
            const jobs = Array.isArray(data.jobs) ? data.jobs : [];
            state.jobs = jobs;
            state.jobsTotal = data.total != null ? toNumber(data.total) : jobs.length;
            renderJobsTable();
            fillFindingsJobSelect();
            found = jobs.find((job) => job.requestId === requestId) || null;
            if (found) {
              renderStepper(found);
              if (String(found.status || '') === 'pending') {
                showUploadProgress(true, true);
                setUploadProgress(1, stepLabel(found.stage));
              }
            }
          }
        } catch (err) {
          if (err.unauthorized) {
            resolve();
            return;
          }
        }

        if (found && String(found.status || '') !== 'pending') {
          // The stepper carries the outcome; the transfer bar has no meaning
          // once the job has settled.
          showUploadProgress(false);
          const verdict = verdictOf(found);
          // Green only for a pass; a blocked verdict is a finished audit, not an error.
          const ok = found.status !== 'failed' && !!found.passed;
          setHint('auditSubmitHint', ok, '审计结束：' + verdict.label
            + (found.status === 'failed' && found.error ? '（' + found.error + '）' : ''));
          resolve();
          return;
        }

        if (Date.now() - started >= SUBMIT_POLL_WINDOW_MS) {
          showUploadProgress(false);
          setHint('auditSubmitHint', true, '审计仍在执行，稍后可在任务列表查看结果。');
          resolve();
          return;
        }

        state.submitPollTimer = setTimeout(tick, SUBMIT_POLL_MS);
      };
      tick();
    });
  }

  // ── Findings explorer ──
  function auditLoadJob(id) {
    if (!state.user) {
      showLoginView();
      return;
    }
    const jobId = String(id == null ? '' : id);
    if (!jobId) return;
    state.selectedJobId = jobId;
    applyView('findings');
    refreshFindings(false);
  }

  async function refreshFindings(silent) {
    if (!state.user) return;

    await refreshJobs(silent);
    fillFindingsJobSelect();

    if (!state.jobs.length) {
      state.currentJob = null;
      state.findings = [];
      renderFindingsHeader(null);
      renderFindingsTable();
      return;
    }

    const select = $('auditFindingsJobSelect');
    const id = state.selectedJobId
      || (select ? select.value : '')
      || (state.jobs[0] && state.jobs[0].id)
      || '';
    if (!id) {
      state.currentJob = null;
      state.findings = [];
      renderFindingsHeader(null);
      renderFindingsTable();
      return;
    }

    state.selectedJobId = id;
    if (select && Array.from(select.options).some((opt) => opt.value === id)) select.value = id;
    await loadJobDetail(id, silent);
  }

  async function loadJobDetail(id, silent) {
    try {
      const res = await requestJSON(
        auditUrl('/api/audit/console/jobs/' + encodeURIComponent(id)),
        { timeoutMs: REQUEST_TIMEOUT_MS },
      );
      if (res.status === 404) {
        state.currentJob = null;
        state.findings = [];
        renderFindingsHeader(null);
        renderFindingsTable();
        if (!silent) toast({ type: 'warning', title: '任务不存在', message: '审计任务不存在' });
        return;
      }
      if (!res.ok) {
        if (!silent) toast({ type: 'warning', title: '结果加载失败', message: 'HTTP ' + res.status });
        return;
      }
      const data = unwrap(res.data) || {};
      const job = data.job || data;
      state.currentJob = job || null;
      state.selectedJobId = (job && job.id) || id;
      state.findings = flattenFindings(job);
      renderStepper(job);
      renderFindingsHeader(job);
      renderFindingsTable();
      fillFindingsJobSelect();
    } catch (err) {
      if (err.unauthorized || silent) return;
      toast({ type: 'warning', title: '结果加载失败', message: err.message });
    }
  }

  function reportListOf(job) {
    if (!job) return [];
    if (Array.isArray(job.fileReports)) return job.fileReports;
    if (Array.isArray(job.file_reports)) return job.file_reports;
    if (typeof job.raw === 'string' && job.raw.trim()) {
      try {
        const parsed = JSON.parse(job.raw);
        if (Array.isArray(parsed.file_reports)) return parsed.file_reports;
        if (Array.isArray(parsed.fileReports)) return parsed.fileReports;
      } catch (_) {}
    }
    return [];
  }

  function flattenFindings(job) {
    const out = [];
    reportListOf(job).forEach((report) => {
      const findings = Array.isArray(report.findings) ? report.findings : [];
      findings.forEach((finding) => {
        const item = Object.assign({}, finding);
        if (!item.file && report.file) item.file = report.file;
        if (!item.file_path && report.file_path) item.file_path = report.file_path;
        out.push(item);
      });
    });
    return out;
  }

  // displayPath strips the console's own extraction root so a finding shows the
  // path inside the archive. The full path stays available via the cell title.
  function displayPath(value) {
    const text = String(value == null ? '' : value);
    const match = text.match(/^(?:.*\/)?local-audit-[^/]*\/src\/(.+)$/);
    if (match) return match[1];
    const marker = '/src/';
    const idx = text.indexOf(marker);
    return idx >= 0 ? text.slice(idx + marker.length) : text;
  }

  function conclusionOf(job) {
    if (!job) return { summary: '', recommendation: '' };
    let summary = job.summaryText || '';
    let recommendation = job.recommendation || '';
    if ((!summary || !recommendation) && typeof job.raw === 'string' && job.raw.trim()) {
      try {
        const parsed = JSON.parse(job.raw);
        const conclusion = parsed && parsed.conclusion;
        if (conclusion) {
          if (!summary) summary = conclusion.summary || '';
          if (!recommendation) recommendation = conclusion.recommendation || '';
        }
      } catch (_) {}
    }
    return { summary: summary, recommendation: recommendation };
  }

  function renderFindingsHeader(job) {
    if (!job) {
      paintPill('auditFindingsVerdict', '—', 'muted');
      const emptyHost = $('auditFindingsSummary');
      if (emptyHost) {
        emptyHost.replaceChildren(emptyStateBox('尚未选择审计任务。选择上方的任务后，这里显示结论摘要与逐条发现。', 'search'));
      }
      return;
    }

    const verdict = verdictOf(job);
    const status = statusOf(job);
    paintPill('auditFindingsVerdict', verdict.label + ' · ' + riskLabel(job.riskLevel), verdict.tone);

    const host = $('auditFindingsSummary');
    if (!host) return;
    const conclusion = conclusionOf(job);
    host.replaceChildren();

    if (status.key === 'done') {
      const stats = document.createElement('div');
      stats.className = 'audit-findings-stats';
      [
        ['发现', job.findings, ''],
        ['高危', job.high, 'is-high'],
        ['中危', job.medium, 'is-medium'],
        ['低危', job.low, 'is-low'],
      ].forEach(([label, value, tone]) => {
        const item = document.createElement('span');
        item.className = 'audit-findings-stat' + (tone ? ' ' + tone : '');
        const num = document.createElement('b');
        num.textContent = String(toNumber(value));
        item.appendChild(num);
        item.appendChild(document.createTextNode(label));
        stats.appendChild(item);
      });
      host.appendChild(stats);
    }

    const summary = document.createElement('div');
    summary.className = 'audit-findings-summary-text';
    if (status.key === 'pending') {
      summary.textContent = '审计仍在进行中（当前步骤：' + stepLabel(job.stage)
        + '），完成后这里会显示结论摘要与逐条发现。';
    } else if (status.key === 'failed') {
      summary.textContent = '本次审计未完成：' + (job.error || '未返回原因');
    } else {
      summary.textContent = conclusion.summary || '该任务没有返回结论摘要。';
    }
    host.appendChild(summary);

    if (status.key === 'done' && conclusion.recommendation) {
      const rec = document.createElement('div');
      rec.className = 'audit-findings-recommendation';
      rec.textContent = '建议：' + conclusion.recommendation;
      rec.style.color = 'var(--muted, #6b7280)';
      rec.style.marginTop = '6px';
      host.appendChild(rec);
    }

    const meta = document.createElement('div');
    meta.className = 'audit-findings-meta';
    meta.style.cssText = 'margin-top:6px;font-size:12px;color:var(--muted, #6b7280);';
    meta.textContent = [
      'requestId ' + (job.requestId || '—'),
      'taskId ' + (job.taskId || '—'),
      '上报 ' + fmtTime(job.at),
      status.key === 'pending' ? '当前步骤 ' + stepLabel(job.stage) : '耗时 ' + fmtDuration(job.durationMs),
      '文件 ' + toNumber(job.files),
    ].join(' · ');
    host.appendChild(meta);
  }

  function currentFilteredFindings() {
    const severity = state.severity;
    const verdict = state.verdict;
    const keyword = state.search.trim().toLowerCase();

    return state.findings.filter((finding) => {
      if (severity !== 'all' && String(finding.severity || '').toLowerCase() !== severity) return false;

      if (verdict !== 'all') {
        const ai = String(finding.llm_verdict || '').toUpperCase();
        if (verdict === 'none') {
          if (ai) return false;
        } else if (ai !== verdict) {
          return false;
        }
      }

      if (keyword) {
        const haystack = [
          finding.file, finding.file_path, finding.rule_id, finding.description,
          finding.line == null ? '' : String(finding.line), finding.category,
        ].map((value) => String(value == null ? '' : value).toLowerCase()).join(' ');
        if (haystack.indexOf(keyword) === -1) return false;
      }
      return true;
    });
  }

  function renderFindingsTable() {
    const tbody = $('auditFindingsRows');
    if (!tbody) return;
    tbody.replaceChildren();

    if (!state.currentJob && !state.findings.length) {
      setText('auditFindingStats', '命中 0 条');
      emptyRow(tbody, 7, '暂无审计结果。请先在「审计任务」发起一次。');
      return;
    }

    const rows = currentFilteredFindings();
    const high = rows.filter((f) => String(f.severity || '').toUpperCase() === 'HIGH').length;
    const medium = rows.filter((f) => String(f.severity || '').toUpperCase() === 'MEDIUM').length;
    const low = rows.filter((f) => String(f.severity || '').toUpperCase() === 'LOW').length;
    const aiCount = rows.filter((f) => String(f.llm_verdict || '').trim()).length;

    setText('auditFindingStats',
      '命中 ' + rows.length + ' 条 / 高 ' + high + ' 中 ' + medium + ' 低 ' + low
      + ' / AI 判定 ' + aiCount + ' 条');

    if (!rows.length) {
      const text = state.findings.length
        ? '当前筛选条件下没有命中。'
        : '该任务未命中任何规则。';
      emptyRow(tbody, 7, text);
      return;
    }

    rows.forEach((finding) => {
      const tr = document.createElement('tr');
      tr.style.cursor = 'pointer';

      const sevCell = makeCell(badge(riskLabel(finding.severity), severityTone(finding.severity)));
      sevCell.classList.add('audit-col-sev');
      tr.appendChild(sevCell);

      const ruleCell = makeCell(finding.rule_id || finding.engine_rule_id || '—', { mono: true });
      ruleCell.classList.add('audit-col-rule');
      tr.appendChild(ruleCell);

      const fullPath = String(finding.file || finding.file_path || '未知文件')
        + ':' + (finding.line == null ? '?' : finding.line);
      const fileCell = makeCell(displayPath(finding.file || finding.file_path || '未知文件')
        + ':' + (finding.line == null ? '?' : finding.line), { mono: true });
      fileCell.classList.add('audit-col-file');
      fileCell.title = fullPath;
      tr.appendChild(fileCell);

      const descCell = makeCell(finding.description || '—');
      descCell.classList.add('audit-col-desc');
      tr.appendChild(descCell);

      tr.appendChild(makeCell(badge(aiVerdictLabel(finding.llm_verdict), aiVerdictTone(finding.llm_verdict))));

      // llm_risk carries the model's free-form risk sentence, not a level, so
      // it is shown as clamped prose instead of a pill.
      const riskCell = document.createElement('td');
      riskCell.classList.add('audit-col-risk');
      if (finding.llm_risk) {
        const riskText = document.createElement('div');
        riskText.className = 'audit-risk-text';
        riskText.textContent = String(finding.llm_risk);
        riskCell.title = String(finding.llm_risk);
        riskCell.appendChild(riskText);
      } else {
        riskCell.textContent = '—';
      }
      tr.appendChild(riskCell);

      const action = document.createElement('button');
      action.type = 'button';
      action.className = 'secondary';
      action.textContent = '详情';
      action.addEventListener('click', (ev) => {
        ev.stopPropagation();
        openFindingDetail(finding);
      });
      const actionCell = makeCell(action, { title: false });
      actionCell.classList.add('audit-col-action');
      tr.appendChild(actionCell);

      tr.addEventListener('click', () => openFindingDetail(finding));
      tbody.appendChild(tr);
    });
  }

  // ── Finding detail drawer ──
  function openFindingDetail(finding) {
    const panel = $('auditFindingDetail');
    if (!panel) return;

    const title = $('auditFindingDetailTitle');
    if (title) {
      title.textContent = (finding.rule_id || finding.engine_rule_id || '未命名规则')
        + ' · ' + displayPath(finding.file || finding.file_path || '未知文件')
        + ':' + (finding.line == null ? '?' : finding.line);
      title.title = (finding.rule_id || finding.engine_rule_id || '未命名规则')
        + ' · ' + (finding.file || finding.file_path || '未知文件')
        + ':' + (finding.line == null ? '?' : finding.line);
    }

    const backdrop = $('auditFindingBackdrop');
    if (backdrop) backdrop.hidden = false;

    const body = $('auditFindingDetailBody');
    if (body) {
      body.replaceChildren();
      body.appendChild(buildFindingDetailBody(finding));
    }

    panel.hidden = false;
    panel.classList.add('open');
    panel.setAttribute('aria-hidden', 'false');
  }

  function closeFindingDetail() {
    const panel = $('auditFindingDetail');
    if (!panel) return;
    panel.hidden = true;
    panel.classList.remove('open');
    panel.setAttribute('aria-hidden', 'true');
    const backdrop = $('auditFindingBackdrop');
    if (backdrop) backdrop.hidden = true;
  }

  function detailSection(titleText) {
    const section = document.createElement('div');
    section.className = 'audit-detail-section';
    section.style.marginTop = '14px';
    const heading = document.createElement('div');
    heading.className = 'audit-detail-heading';
    heading.textContent = titleText;
    heading.style.cssText = 'font-weight:650;font-size:13.5px;margin-bottom:6px;';
    section.appendChild(heading);
    return section;
  }

  function buildFindingDetailBody(finding) {
    const wrap = document.createElement('div');
    wrap.className = 'audit-finding-detail-body';

    const meta = detailSection('命中信息');
    fillFieldList(meta, [
      ['严重级别', badge(riskLabel(finding.severity), severityTone(finding.severity))],
      ['规则', finding.rule_id || finding.engine_rule_id || '—', { mono: true }],
      ['规则族', finding.rule_family || '—'],
      ['类别', finding.category || '—'],
      ['文件', displayPath(finding.file_path || finding.file || '—'), { mono: true }],
      ['行号', finding.line == null ? '—' : String(finding.line), { mono: true }],
      ['AI 判定', badge(aiVerdictLabel(finding.llm_verdict), aiVerdictTone(finding.llm_verdict))],
      // llm_risk is prose, not a level, so keep it as wrapping text.
      ['AI 风险', finding.llm_risk ? String(finding.llm_risk) : '—'],
      ['跨文件', finding.is_cross_file ? '是' : '否'],
      ['微服务', finding.is_microservice ? '是' : '否'],
    ]);
    wrap.appendChild(meta);

    const description = detailSection('描述');
    const desc = document.createElement('div');
    desc.textContent = finding.description || '—';
    description.appendChild(desc);
    wrap.appendChild(description);

    if (finding.code_snippet || finding.context_before || finding.context_after || finding.context) {
      const codeSection = detailSection('代码片段（命中行已高亮）');
      codeSection.appendChild(buildCodeBlock(finding));
      wrap.appendChild(codeSection);
    }

    if (finding.llm_reason) {
      const reasonSection = detailSection('AI 理由');
      const reason = document.createElement('div');
      reason.className = 'audit-detail-reason';
      reason.style.cssText = 'white-space:pre-wrap;line-height:1.6;';
      reason.textContent = finding.llm_reason;
      reasonSection.appendChild(reason);
      wrap.appendChild(reasonSection);
    }

    if (finding.cpg_evidence) {
      const cpgSection = detailSection('CPG 证据');
      const pre = document.createElement('pre');
      pre.className = 'audit-detail-code';
      pre.style.cssText = 'font-family:' + MONO_FONT + ';white-space:pre-wrap;word-break:break-all;'
        + 'background:var(--panel-sub, #f1f5f9);padding:10px;border-radius:8px;margin:0;';
      pre.textContent = typeof finding.cpg_evidence === 'string'
        ? finding.cpg_evidence
        : JSON.stringify(finding.cpg_evidence, null, 2);
      cpgSection.appendChild(pre);
      wrap.appendChild(cpgSection);
    }

    if (finding.taint_trace != null) {
      const taintSection = detailSection('污点追踪');
      const pre = document.createElement('pre');
      pre.className = 'audit-detail-code';
      pre.style.cssText = 'font-family:' + MONO_FONT + ';white-space:pre-wrap;word-break:break-all;'
        + 'background:var(--panel-sub, #f1f5f9);padding:10px;border-radius:8px;margin:0;';
      pre.textContent = typeof finding.taint_trace === 'string'
        ? finding.taint_trace
        : JSON.stringify(finding.taint_trace, null, 2);
      taintSection.appendChild(pre);
      wrap.appendChild(taintSection);
    }

    const rawSection = detailSection('原始字段');
    const details = document.createElement('details');
    const summary = document.createElement('summary');
    summary.textContent = '展开 JSON';
    summary.style.cursor = 'pointer';
    const rawPre = document.createElement('pre');
    rawPre.className = 'audit-detail-code';
    rawPre.style.cssText = 'font-family:' + MONO_FONT + ';white-space:pre-wrap;word-break:break-all;'
      + 'background:var(--panel-sub, #f1f5f9);padding:10px;border-radius:8px;margin:6px 0 0;';
    rawPre.textContent = JSON.stringify(finding, null, 2);
    details.append(summary, rawPre);
    rawSection.appendChild(details);
    wrap.appendChild(rawSection);

    return wrap;
  }

  function appendCodeLines(pre, text, className) {
    if (!text) return;
    String(text).split('\n').forEach((line) => {
      const span = document.createElement('div');
      span.className = className;
      span.textContent = line;
      pre.appendChild(span);
    });
  }

  function buildCodeBlock(finding) {
    const pre = document.createElement('pre');
    pre.className = 'audit-detail-code';
    pre.style.cssText = 'font-family:' + MONO_FONT + ';white-space:pre-wrap;word-break:break-all;'
      + 'background:var(--panel-sub, #f1f5f9);padding:10px;border-radius:8px;margin:0;line-height:1.5;';

    const before = finding.context_before;
    const hit = finding.code_snippet || finding.code || finding.context || '';
    const after = finding.context_after;

    if (before) appendCodeLines(pre, before, 'audit-code-context');
    if (hit) {
      String(hit).split('\n').forEach((line) => {
        const span = document.createElement('div');
        span.className = 'audit-code-hit';
        span.textContent = line;
        span.style.cssText = 'background:rgba(220,38,38,0.14);display:block;';
        pre.appendChild(span);
      });
    }
    if (after) appendCodeLines(pre, after, 'audit-code-context');

    ['audit-code-context'].forEach((cls) => {
      pre.querySelectorAll('.' + cls).forEach((el) => {
        el.style.color = 'var(--muted, #6b7280)';
      });
    });

    return pre;
  }

  // ── Findings export ──
  function exportFindings() {
    if (!state.currentJob) {
      toast({ type: 'info', title: '暂无可导出内容', message: '先选择一个审计任务' });
      return;
    }
    const rows = currentFilteredFindings();
    if (!rows.length) {
      toast({ type: 'info', title: '暂无可导出内容', message: '当前筛选条件下没有命中' });
      return;
    }

    const conclusion = conclusionOf(state.currentJob);
    const payload = {
      exportedAt: new Date().toISOString(),
      note: '平台只展示审计结论投影，规则明细与证据附在 file_reports 中。',
      dockerId: state.dockerId,
      job: {
        id: state.currentJob.id,
        requestId: state.currentJob.requestId,
        taskId: state.currentJob.taskId,
        at: state.currentJob.at,
        passed: state.currentJob.passed,
        riskLevel: state.currentJob.riskLevel,
        summary: conclusion.summary,
        recommendation: conclusion.recommendation,
        statistics: state.currentJob.statistics || null,
      },
      filter: {
        severity: state.severity,
        verdict: state.verdict,
        search: state.search,
      },
      findings: rows,
    };

    const text = JSON.stringify(payload, null, 2);
    const requestId = String(state.currentJob.requestId || state.currentJob.id || 'job');
    const filename = 'audit-' + requestId.replace(/[^A-Za-z0-9._-]+/g, '_') + '.json';

    try {
      if (typeof URL === 'undefined' || typeof URL.createObjectURL !== 'function') {
        throw new Error('当前环境不支持 Blob 下载');
      }
      const blob = new Blob([text], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      toast({ type: 'success', title: '已导出', message: rows.length + ' 条命中 · ' + filename });
    } catch (err) {
      showExportFallback(text, filename, err);
    }
  }

  function showExportFallback(text, filename, err) {
    const panel = $('auditFindingDetail');
    if (!panel) {
      toast({ type: 'warning', title: '导出失败', message: (err && err.message) || '浏览器阻止了下载' });
      return;
    }
    setText('auditFindingDetailTitle', '导出内容 · ' + filename);
    const body = $('auditFindingDetailBody');
    if (body) {
      body.replaceChildren();
      const note = document.createElement('div');
      note.textContent = '浏览器或沙箱阻止了文件下载，请复制下面的 JSON（' + ((err && err.message) || '下载被拦截') + '）。';
      note.style.cssText = 'color:var(--muted, #6b7280);margin-bottom:8px;';
      const pre = document.createElement('pre');
      pre.style.cssText = 'font-family:' + MONO_FONT + ';white-space:pre-wrap;word-break:break-all;'
        + 'user-select:all;background:var(--panel-sub, #f1f5f9);padding:10px;border-radius:8px;';
      pre.textContent = text;
      body.append(note, pre);
    }
    panel.hidden = false;
    panel.classList.add('open');
    panel.setAttribute('aria-hidden', 'false');
    toast({ type: 'warning', title: '下载被拦截', message: 'JSON 已放入详情区，可手动复制' });
  }

  // ── Security engine ──
  async function refreshEngine() {
    await refreshStaticEngine();
    await refreshLLMOverview(false);
    await refreshLogs(false);
  }

  async function refreshStaticEngine() {
    if (!state.jobs.length) await refreshJobs(true);
    const job = state.jobs[0] || null;

    if (!job) {
      paintPill('engineStaticStatus', '暂无任务', 'muted');
      fillFieldList($('engineStaticFields'), [
        ['状态', '尚未收到任何审计结果'],
        ['数据范围', '平台只收到审计结论投影，引擎名称与规则明细留在 TEE 内。'],
      ]);
      return;
    }

    const verdict = verdictOf(job);
    paintPill('engineStaticStatus', verdict.label + ' · ' + riskLabel(job.riskLevel), verdict.tone);

    fillFieldList($('engineStaticFields'), [
      ['结论', badge(verdict.label, verdict.tone)],
      ['风险级别', badge(riskLabel(job.riskLevel), riskTone(job.riskLevel))],
      ['耗时', fmtDuration(job.durationMs)],
      ['文件数', String(toNumber(job.files))],
      ['命中数', String(toNumber(job.findings))],
      ['高 / 中 / 低', toNumber(job.high) + ' / ' + toNumber(job.medium) + ' / ' + toNumber(job.low)],
      ['requestId', job.requestId || '—', { mono: true }],
      ['taskId', job.taskId || '—', { mono: true }],
      ['上报时间', fmtTime(job.at)],
      ['数据范围', '平台只收到结论投影，引擎名称与规则明细留在 TEE 内。'],
    ]);
  }

  async function refreshLLMOverview(silent) {
    if (!state.user) return;
    try {
      const res = await requestJSON('/api/llm/console/overview', { timeoutMs: REQUEST_TIMEOUT_MS });
      if (!res.ok) {
        if (!silent) toast({ type: 'warning', title: '安全引擎状态刷新失败', message: 'HTTP ' + res.status });
        return;
      }
      renderLLMOverview(unwrap(res.data) || {});
    } catch (err) {
      if (err.unauthorized || silent) return;
      toast({ type: 'warning', title: '安全引擎状态刷新失败', message: err.message });
    }
  }

  function renderLLMOverview(data) {
    state.llm = data;
    const inst = data.instance || {};
    const tls = data.teeTLS || {};
    const hs = tls.lastHandshake || {};
    const online = !!inst.reachable && !inst.lastError;

    paintPill('engineLLMStatus',
      online ? '在线' : (inst.lastError ? '异常' : '离线'),
      online ? 'ok' : 'bad');

    fillFieldList($('engineLLMFields'), [
      ['网关地址', inst.address || '—', { mono: true }],
      ['模型', inst.model || '—'],
      ['实例', inst.dockerId || '—', { mono: true }],
      ['运行时长', inst.uptimeSeconds != null ? fmtSeconds(inst.uptimeSeconds) : '—'],
      ['最近握手', hs && hs.at
        ? (hs.ok ? '成功' : '失败')
          + ' · ' + (hs.elapsedMs != null ? hs.elapsedMs + ' ms' : '—')
          + ' · ' + fmtTime(hs.at)
        : '暂无握手记录'],
      ['TLS 端点', tls.endpoint || '—', { mono: true }],
      ['证明模式', tls.mode || '—'],
      ['最近错误', inst.lastError || '—'],
    ]);
  }

  let attestBusy = false;

  async function runAttestation() {
    if (!state.user || attestBusy) return;
    attestBusy = true;
    const verifyBtn = $('engineVerifyTLSBtn');
    const fetchBtn = $('engineFetchAttestBtn');
    if (verifyBtn) verifyBtn.disabled = true;
    if (fetchBtn) fetchBtn.disabled = true;

    try {
      // The console endpoint returns {msg, result, error, teeTLS}; teeTLS is the
      // bare handshake here, while /overview nests it as lastHandshake. Accept
      // both shapes.
      const res = await requestJSON('/api/llm/console/attestation', {
        method: 'POST',
        timeoutMs: ATTEST_TIMEOUT_MS,
      });
      const payload = res.data || {};
      const result = unwrap(payload) || {};
      const tls = payload.teeTLS || result.teeTLS || {};
      const hs = tls.lastHandshake || tls;

      renderHandshake(tls, hs);
      renderAttestation(result, hs);

      if (res.ok) {
        toast({ type: 'success', title: '已获取证据', message: '平台只展示证据，不强制校验' });
      } else {
        toast({
          type: 'warning',
          title: '获取证据失败',
          message: payload.msg || payload.error || result.error || ('HTTP ' + res.status),
        });
      }
    } catch (err) {
      if (!err.unauthorized) {
        renderHandshake({}, { ok: false, error: err.message });
        toast({ type: 'warning', title: '获取证据失败', message: err.message });
      }
    } finally {
      attestBusy = false;
      if (verifyBtn) verifyBtn.disabled = false;
      if (fetchBtn) fetchBtn.disabled = false;
    }
  }

  function renderHandshake(tls, hs) {
    const handshake = hs || {};
    const rows = [];
    if (tls && tls.endpoint) rows.push(['endpoint', tls.endpoint, { mono: true }]);
    if (tls && tls.mode) rows.push(['模式', tls.mode]);
    if (tls && tls.skipChainVerify != null) rows.push(['跳过链校验', tls.skipChainVerify ? '是' : '否']);
    rows.push(
      ['握手', badge(handshake.ok ? '成功' : '失败', handshake.ok ? 'ok' : 'bad')],
      ['耗时', handshake.elapsedMs != null ? handshake.elapsedMs + ' ms' : '—'],
      ['测量值', handshake.measurementHex || '—', { mono: true }],
      ['公钥绑定', handshake.publicKeyBound ? '已绑定' : '未绑定'],
      ['证书主体', handshake.certSubject || '—', { mono: true }],
      ['时间', handshake.at ? fmtTime(handshake.at) : '—'],
      ['错误', handshake.error || '—'],
    );
    fillFieldList($('engineHandshakeFields'), rows);
  }

  function renderAttestation(result, hs) {
    const att = result || {};
    const handshake = hs || {};
    fillFieldList($('engineAttestFields'), [
      ['实例自检', badge(att.verifiedPass ? '通过' : '未通过', att.verifiedPass ? 'ok' : 'bad')],
      ['测量值', handshake.measurementHex || '—', { mono: true }],
      ['公钥绑定', handshake.publicKeyBound ? '已绑定' : '未绑定'],
      ['证书主体', handshake.certSubject || '—', { mono: true }],
      ['握手耗时', handshake.elapsedMs != null ? handshake.elapsedMs + ' ms' : '—'],
      ['requestId', att.requestId || '—', { mono: true }],
      ['证明大小', att.attestationSize != null ? att.attestationSize + ' B' : '—'],
      ['获取时间', att.fetchedAt ? fmtTime(att.fetchedAt) : '—'],
      ['错误', att.error || handshake.error || '—'],
    ]);
  }

  async function auditPromptSend() {
    if (!state.user || state.promptBusy) return;
    const input = $('enginePromptInput');
    const prompt = input ? input.value : '';
    if (!prompt.trim()) {
      setPromptMeta('请输入提示词后再发送。', 'warn');
      toast({ type: 'warning', title: '提示词为空', message: '请输入要发送的内容' });
      if (input) input.focus();
      return;
    }

    state.promptBusy = true;
    const btn = $('enginePromptSend');
    if (btn) btn.disabled = true;
    const reply = $('enginePromptReply');
    if (reply) reply.textContent = '';
    setPromptMeta('请求中，冷加载模型可能需要较长时间…', 'muted');

    const requestId = genRequestId();
    const started = Date.now();
    try {
      const res = await requestJSON('/api/llm/console/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt: prompt, requestId: requestId }),
        timeoutMs: GENERATE_TIMEOUT_MS,
      });
      const data = unwrap(res.data) || {};

      if (res.ok && data.text != null) {
        if (reply) reply.textContent = String(data.text);
        setPromptMeta([
          data.status || 'SUCCESS',
          (data.elapsedMs != null ? data.elapsedMs : (Date.now() - started)) + ' ms',
          data.model || '',
          data.requestId || requestId,
        ].filter(Boolean).join(' · '), 'ok');
      } else {
        if (reply) reply.textContent = data.error || data.errorMessage || data.msg || '推理失败';
        setPromptMeta('失败 · ' + (data.status || ('HTTP ' + res.status)), 'bad');
      }
    } catch (err) {
      if (!err.unauthorized) {
        if (reply) {
          reply.textContent = err.timeout
            ? '请求超时（130s）。冷加载模型可能超过 120 秒，请确认模型已驻留后重试。'
            : err.message;
        }
        setPromptMeta(err.timeout ? '超时（110s 以上属冷加载）' : '请求失败', 'bad');
      }
    } finally {
      state.promptBusy = false;
      if (btn) btn.disabled = false;
    }
  }

  function setPromptMeta(message, tone) {
    const el = $('enginePromptMeta');
    if (!el) return;
    el.textContent = message || '';
    el.style.color = (TONES[tone] && TONES[tone].color) || '';
  }

  // ── Gateway logs ──
  async function refreshLogs(silent) {
    if (!state.user) return;
    try {
      // /api/llm/status nests the poller's log snapshot under `logs`; the poller
      // itself owns the sinceSeq cursor, so this view renders the collected tail.
      const res = await requestJSON('/api/llm/status', { timeoutMs: 10000 });
      if (!res.ok) {
        if (!silent) toast({ type: 'warning', title: '网关日志刷新失败', message: 'HTTP ' + res.status });
        return;
      }
      const payload = unwrap(res.data) || {};
      const logs = payload.logs || {};
      const entries = Array.isArray(logs.entries) ? logs.entries : [];
      state.logs = entries;
      state.logsTotal = logs.totalCount != null ? toNumber(logs.totalCount) : entries.length;
      setText('engineLogCount', state.logsTotal + ' 条日志');
      if (!state.logPaused) renderLogs();
    } catch (err) {
      if (err.unauthorized || silent) return;
      toast({ type: 'warning', title: '网关日志刷新失败', message: err.message });
    }
  }

  function renderLogs() {
    const out = $('engineLogOutput');
    if (!out) return;
    out.replaceChildren();

    if (!state.logs.length) {
      const empty = document.createElement('div');
      empty.className = 'audit-log-empty';
      empty.textContent = '暂无网关日志。mock 尚未从实例拉到日志，或日志已被清空。';
      empty.style.cssText = 'color:var(--muted, #6b7280);padding:10px;';
      out.appendChild(empty);
      return;
    }

    const fragment = document.createDocumentFragment();
    state.logs.forEach((entry) => {
      const line = document.createElement('div');
      line.className = 'audit-log-line';
      line.style.cssText = 'font-family:' + MONO_FONT + ';font-size:12px;white-space:pre-wrap;word-break:break-all;';
      const seq = entry && entry.seq != null ? '[' + entry.seq + '] ' : '';
      line.textContent = seq + ((entry && entry.message) || '');
      fragment.appendChild(line);
    });
    out.appendChild(fragment);

    if (state.logAutoScroll) out.scrollTop = out.scrollHeight;
  }

  function toggleLogPause() {
    state.logPaused = !state.logPaused;
    const btn = $('engineLogPauseBtn');
    if (btn) {
      btn.textContent = state.logPaused ? '继续' : '暂停';
      btn.classList.toggle('active', state.logPaused);
    }
    if (!state.logPaused) refreshLogs(false);
  }

  async function clearLogs() {
    try {
      const res = await requestJSON('/api/llm/logs/clear', { method: 'POST', timeoutMs: 10000 });
      if (!res.ok) {
        toast({ type: 'warning', title: '清空失败', message: 'HTTP ' + res.status });
        return;
      }
      const data = unwrap(res.data) || {};
      state.logs = [];
      state.logsTotal = 0;
      setText('engineLogCount', '0 条日志');
      renderLogs();
      toast({ type: 'success', title: '已清空', message: '已清空 ' + (data.cleared != null ? data.cleared : 0) + ' 条日志' });
    } catch (err) {
      if (!err.unauthorized) toast({ type: 'warning', title: '清空失败', message: err.message });
    }
  }

  // ── Settings ──
  async function refreshSettings(silent) {
    if (!state.user) return;
    if (!state.instances.length) await loadInstances();
    await refreshAuditPrompt(silent);
    try {
      const res = await requestJSON('/api/llm/console/settings', { timeoutMs: REQUEST_TIMEOUT_MS });
      if (!res.ok) {
        if (!silent) toast({ type: 'warning', title: '设置读取失败', message: 'HTTP ' + res.status });
        return;
      }
      renderSettings(unwrap(res.data) || {});
    } catch (err) {
      if (err.unauthorized || silent) return;
      toast({ type: 'warning', title: '设置读取失败', message: err.message });
    }
  }

  // The audit prompt lives in the server process, next to the other console
  // settings. The textarea is the authority while it holds focus; a reload of
  // the settings view re-reads whatever the runner would use for the next audit.
  async function refreshAuditPrompt(silent) {
    if (!state.user) return;
    try {
      const res = await requestJSON('/api/audit/console/prompt', { timeoutMs: REQUEST_TIMEOUT_MS });
      if (!res.ok) {
        if (!silent) setPromptMeta('读取失败 · HTTP ' + res.status, 'bad');
        return;
      }
      const data = unwrap(res.data) || {};
      const input = $('auditPromptInput');
      if (input && document.activeElement !== input) input.value = data.prompt || '';
      renderPromptState(!!data.custom);
      setPromptMeta(data.custom
        ? '已加载自定义提示词（下次审计生效）'
        : '当前为内置默认提示词，可直接修改后保存', 'muted');
    } catch (err) {
      if (err.unauthorized || silent) return;
      setPromptMeta('读取失败：' + err.message, 'bad');
    }
  }

  function setPromptMeta(text, tone) {
    const el = $('auditPromptMeta');
    if (!el) return;
    el.textContent = text || '';
    el.style.color = tone === 'bad' ? 'var(--bad, #dc2626)'
      : tone === 'ok' ? 'var(--ok, #059669)'
        : '';
  }

  // renderPromptState paints the badge and the live character count whenever
  // the textarea changes or a new effective prompt is loaded.
  function renderPromptState(custom) {
    const badge = $('auditPromptBadge');
    if (badge) {
      badge.dataset.state = custom ? 'custom' : 'default';
      badge.textContent = custom ? '自定义生效中' : '内置默认';
    }
    updatePromptCount();
  }

  function updatePromptCount() {
    const input = $('auditPromptInput');
    const el = $('auditPromptCount');
    if (!input || !el) return;
    el.textContent = input.value.length + ' 字';
  }

  // putAuditPrompt writes one prompt value. An empty value restores the
  // built-in default; the server answers with the effective text either way, so
  // the textarea always shows what the next audit would send.
  async function putAuditPrompt(text, announce) {
    if (!state.user) return;
    const input = $('auditPromptInput');
    const btn = $('auditPromptSaveBtn');
    if (btn) btn.disabled = true;
    setPromptMeta('保存中…', 'muted');
    try {
      const res = await requestJSON('/api/audit/console/prompt', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt: text }),
        timeoutMs: REQUEST_TIMEOUT_MS,
      });
      const data = unwrap(res.data) || {};
      if (!res.ok || data.ok === false) {
        throw new Error(data.error || data.msg || ('HTTP ' + res.status));
      }
      if (input) input.value = data.prompt || '';
      renderPromptState(!!data.custom);
      setPromptMeta(data.custom ? '已保存 · 下次审计生效' : '已恢复内置默认提示词', 'ok');
      if (announce) {
        toast({
          type: 'success',
          title: data.custom ? '提示词已保存' : '已恢复默认提示词',
          message: '下一次审计生效',
        });
      }
    } catch (err) {
      if (err.unauthorized) return;
      setPromptMeta('保存失败：' + err.message, 'bad');
      if (announce) toast({ type: 'warning', title: '提示词保存失败', message: err.message });
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function saveAuditPrompt() {
    const input = $('auditPromptInput');
    await putAuditPrompt(input ? input.value : '', true);
  }

  async function clearAuditPrompt() {
    await putAuditPrompt('', true);
  }

  function ensureOptions(select, values) {
    const have = Array.from(select.options).map((opt) => opt.value);
    values.forEach((value) => {
      if (have.indexOf(value) !== -1) return;
      const opt = document.createElement('option');
      opt.value = value;
      opt.textContent = value;
      select.appendChild(opt);
    });
  }

  function renderSettings(data) {
    state.settings = data || {};
    const tls = state.settings.teeTLS || {};
    state.tlsMode = tls.mode || 'permissive';
    state.tlsSkip = tls.skipChainVerify != null ? !!tls.skipChainVerify : true;

    const endpoint = state.settings.endpoint || state.settings.plaintextEndpoint || '';
    setText('auditLLMEndpointValue', endpoint || '—');

    const modeEl = $('auditTLSModeSelect');
    if (modeEl) {
      if (modeEl.tagName === 'SELECT') {
        ensureOptions(modeEl, ['permissive', 'strict']);
        if (state.tlsMode && !Array.from(modeEl.options).some((opt) => opt.value === state.tlsMode)) {
          ensureOptions(modeEl, [state.tlsMode]);
        }
        modeEl.value = state.tlsMode;
      } else {
        modeEl.textContent = state.tlsMode;
      }
    }

    const skipEl = $('auditTLSSkipChain');
    if (skipEl) {
      if (skipEl.type === 'checkbox') skipEl.checked = state.tlsSkip;
      else skipEl.textContent = state.tlsSkip ? '是' : '否';
    }

    const timeoutEl = $('auditTLSTimeout');
    if (timeoutEl) {
      if (timeoutEl.tagName === 'INPUT') {
        timeoutEl.value = tls.timeoutSeconds != null ? String(tls.timeoutSeconds) : '';
      } else {
        timeoutEl.textContent = tls.timeoutSeconds != null ? tls.timeoutSeconds + ' 秒（固定）' : '—';
      }
    }

    updateEndpointDisplay();
    setText('auditSettingsHint', SETTINGS_HINT);
  }

  async function saveSettings() {
    if (!state.user) return;
    const btn = $('auditSaveSettingsBtn');
    const modeEl = $('auditTLSModeSelect');
    const skipEl = $('auditTLSSkipChain');
    const mode = modeEl && modeEl.tagName === 'SELECT' ? modeEl.value : state.tlsMode;
    const skip = skipEl && skipEl.type === 'checkbox' ? !!skipEl.checked : state.tlsSkip;

    if (btn) btn.disabled = true;
    try {
      const res = await requestJSON('/api/llm/console/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ teeTLS: { mode: mode, skipChainVerify: skip } }),
        timeoutMs: REQUEST_TIMEOUT_MS,
      });
      const data = unwrap(res.data) || {};
      if (res.ok) {
        renderSettings(data);
        setHint('auditSettingsHint', true, '设置已保存，新的 TLS 参数从下一次请求生效。');
        toast({ type: 'success', title: '设置已保存', message: '新的 TLS 参数从下一次请求生效' });
      } else {
        const message = data.error || data.msg || ('HTTP ' + res.status);
        setHint('auditSettingsHint', false, '保存失败：' + message);
        toast({ type: 'warning', title: '保存失败', message: message });
      }
    } catch (err) {
      if (!err.unauthorized) {
        setHint('auditSettingsHint', false, '保存失败：' + err.message);
        toast({ type: 'warning', title: '保存失败', message: err.message });
      }
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  // ── Polling ──
  // Runs only while the audit tab is visible, the operator is signed in, and the
  // document is on screen. Switching away, logging out or hiding the page tears
  // the timer down; nothing polls in the background.
  function syncPoller(runNow) {
    const shouldPoll = state.tab === 'audit' && !!state.user && !document.hidden && !state.dropping;
    if (shouldPoll && !state.pollTimer) {
      state.pollTimer = setInterval(pollTick, POLL_MS);
      if (runNow !== false) pollTick();
    } else if (!shouldPoll && state.pollTimer) {
      clearInterval(state.pollTimer);
      state.pollTimer = null;
    } else if (shouldPoll && runNow) {
      pollTick();
    }
  }

  async function pollTick() {
    if (!state.user || state.tab !== 'audit' || document.hidden || state.polling) return;
    state.polling = true;
    try {
      await Promise.allSettled([
        refreshJobs(true),
        refreshLLMOverview(true),
      ]);
      if (state.view === 'engine') await refreshLogs(true);
    } finally {
      state.polling = false;
    }
  }

  // ── Event wiring ──
  function bindIfNoInline(id, handler) {
    const el = $(id);
    if (!el || el.getAttribute('onclick') || el.dataset.auditBound === '1') return;
    el.dataset.auditBound = '1';
    el.addEventListener('click', handler);
  }

  function wireTabs() {
    document.querySelectorAll('#tabBar .tab-btn').forEach((btn) => {
      if (btn.getAttribute('onclick')) return;
      btn.addEventListener('click', () => auditTabSwitch(btn.dataset.tab));
    });
  }

  function wireNav() {
    document.querySelectorAll('.audit-nav-item[data-audit-view]').forEach((btn) => {
      if (btn.getAttribute('onclick')) return;
      btn.addEventListener('click', () => auditConsoleSwitchView(btn.dataset.auditView));
    });
  }

  function wireLogin() {
    const form = $('auditLoginForm');
    if (form) {
      // Inline `onsubmit` is the markup's own binding; adding ours would submit twice.
      if (!form.getAttribute('onsubmit') && form.dataset.auditBound !== '1') {
        form.dataset.auditBound = '1';
        form.addEventListener('submit', auditConsoleLogin);
      }
    } else {
      ['auditLoginUser', 'auditLoginPassword'].forEach((id) => {
        const el = $(id);
        if (!el) return;
        el.addEventListener('keydown', (ev) => {
          if (ev.key === 'Enter') {
            ev.preventDefault();
            auditConsoleLogin(ev);
          }
        });
      });
    }

    const pwd = $('auditLoginPassword');
    if (pwd) {
      const onCaps = () => toggleCapsWarning(pwd);
      pwd.addEventListener('keydown', onCaps);
      pwd.addEventListener('keyup', onCaps);
      pwd.addEventListener('blur', () => setCapsWarning(false));
    }

    bindIfNoInline('auditLoginTogglePwd', auditConsoleTogglePwd);
    bindIfNoInline('auditLogoutBtn', auditConsoleLogout);

    const remember = $('auditLoginRemember');
    if (remember) {
      remember.addEventListener('change', () => {
        const userEl = $('auditLoginUser');
        const name = userEl ? userEl.value.trim() : '';
        if (remember.checked && name) storeSet(localStorage, USER_KEY, name);
        else if (!remember.checked) storeRemove(localStorage, USER_KEY);
      });
    }
  }

  function wireJobs() {
    const filter = $('auditJobsFilter');
    if (filter) filter.addEventListener('change', renderJobsTable);
    bindIfNoInline('auditSubmitBtn', auditSubmitAudit);

    const input = $('auditFileInput');
    const drop = $('auditFileDrop');
    const pick = $('auditFilePickBtn');
    const clear = $('auditFileClearBtn');

    if (input && input.dataset.auditBound !== '1') {
      input.dataset.auditBound = '1';
      input.addEventListener('change', () => {
        const file = input.files && input.files[0];
        if (file) setChosenFile(file);
      });
    }

    if (pick && pick.dataset.auditBound !== '1') {
      pick.dataset.auditBound = '1';
      pick.addEventListener('click', (ev) => {
        ev.preventDefault();
        ev.stopPropagation();
        if (input) input.click();
      });
    }

    if (clear && clear.dataset.auditBound !== '1') {
      clear.dataset.auditBound = '1';
      clear.addEventListener('click', (ev) => {
        ev.preventDefault();
        ev.stopPropagation();
        clearChosenFile();
      });
    }

    if (drop && drop.dataset.auditBound !== '1') {
      drop.dataset.auditBound = '1';
      drop.addEventListener('click', (ev) => {
        // Clicks on the buttons inside the zone are handled above; anywhere
        // else in the zone means "open the picker".
        if (ev.target.closest('button')) return;
        if (input) input.click();
      });

      ['dragenter', 'dragover'].forEach((name) => {
        drop.addEventListener(name, (ev) => {
          ev.preventDefault();
          ev.stopPropagation();
          drop.classList.add('is-dragover');
        });
      });
      ['dragleave', 'drop'].forEach((name) => {
        drop.addEventListener(name, (ev) => {
          ev.preventDefault();
          ev.stopPropagation();
          drop.classList.remove('is-dragover');
        });
      });
      drop.addEventListener('drop', (ev) => {
        // A drag from the file area carries the stored id, not a File: select it
        // so a repeat run reuses the archive already on the server.
        const storedId = ev.dataTransfer && ev.dataTransfer.getData('application/x-taa-audit-file');
        if (storedId) {
          const entry = state.files.find((item) => item.id === storedId);
          if (entry) chooseStoredFile(entry);
          return;
        }
        const file = ev.dataTransfer && ev.dataTransfer.files && ev.dataTransfer.files[0];
        if (!file) return;
        if (input) {
          try {
            const dt = new DataTransfer();
            dt.items.add(file);
            input.files = dt.files;
          } catch (_) {}
        }
        setChosenFile(file);
      });
    }

    if (!state.taskId) rotateTaskId();
    renderStepper(null);
  }

  function wireFindings() {
    const select = $('auditFindingsJobSelect');
    if (select) {
      select.addEventListener('change', () => {
        state.selectedJobId = select.value;
        if (state.selectedJobId) loadJobDetail(state.selectedJobId, false);
      });
    }

    const severity = $('auditSeverityFilter');
    if (severity) {
      severity.querySelectorAll('[data-severity]').forEach((btn) => {
        if (btn.getAttribute('onclick')) return;
        btn.addEventListener('click', () => {
          state.severity = btn.dataset.severity || 'all';
          severity.querySelectorAll('[data-severity]').forEach((other) => {
            const on = other === btn;
            other.classList.toggle('active', on);
            other.setAttribute('aria-pressed', on ? 'true' : 'false');
          });
          renderFindingsTable();
        });
      });
    }

    const verdict = $('auditVerdictFilter');
    if (verdict) {
      verdict.addEventListener('change', () => {
        state.verdict = verdict.value || 'all';
        renderFindingsTable();
      });
    }

    const search = $('auditFindingsSearch');
    if (search) {
      search.addEventListener('input', () => {
        state.search = search.value || '';
        renderFindingsTable();
      });
    }

    bindIfNoInline('auditExportBtn', exportFindings);
    bindIfNoInline('auditFindingDetailClose', closeFindingDetail);
    bindIfNoInline('auditFindingBackdrop', closeFindingDetail);

    const panel = $('auditFindingDetail');
    if (panel) {
      // The drawer may start visible in markup; the module owns its state.
      if (panel.dataset.auditWired !== '1') {
        panel.dataset.auditWired = '1';
      }
    }

    document.addEventListener('keydown', (ev) => {
      if (ev.key === 'Escape') {
        const drawer = $('auditFindingDetail');
        if (drawer && (!drawer.hidden || drawer.classList.contains('open'))) closeFindingDetail();
      }
    });
  }

  function wireEngine() {
    bindIfNoInline('engineVerifyTLSBtn', runAttestation);
    bindIfNoInline('engineFetchAttestBtn', runAttestation);
    bindIfNoInline('enginePromptSend', auditPromptSend);
    bindIfNoInline('engineLogPauseBtn', toggleLogPause);
    bindIfNoInline('engineLogClearBtn', clearLogs);

    const out = $('engineLogOutput');
    if (out) {
      out.addEventListener('scroll', () => {
        state.logAutoScroll = out.scrollHeight - out.scrollTop - out.clientHeight <= 40;
      });
    }

    const input = $('enginePromptInput');
    if (input) {
      input.addEventListener('keydown', (ev) => {
        if (ev.key === 'Enter' && (ev.ctrlKey || ev.metaKey)) {
          ev.preventDefault();
          auditPromptSend();
        }
      });
    }

    // Seed the pause button label from the module default.
    const pause = $('engineLogPauseBtn');
    if (pause && !pause.textContent.trim()) pause.textContent = '暂停';
  }

  function wireSettings() {
    bindIfNoInline('auditSaveSettingsBtn', saveSettings);
    bindIfNoInline('auditPromptSaveBtn', saveAuditPrompt);
    bindIfNoInline('auditPromptResetBtn', clearAuditPrompt);

    const promptInput = $('auditPromptInput');
    if (promptInput) promptInput.addEventListener('input', updatePromptCount);
  }

  function wireTopbar() {
    bindIfNoInline('auditLogoutBtn', auditConsoleLogout);
    bindIfNoInline('auditTopRefreshBtn', async () => {
      if (!state.user) return;
      renderSessionPill();
      await loadInstances();
      await refreshVisibleView();
    });

    const instance = $('auditInstanceSelect');
    if (instance) {
      instance.addEventListener('change', onInstanceChanged);
    }
  }

  function wireVisibility() {
    document.addEventListener('visibilitychange', () => syncPoller(true));
  }

  function wireAll() {
    wireTabs();
    wireNav();
    wireLogin();
    wireJobs();
    wireFindings();
    wireEngine();
    wireSettings();
    wireTopbar();
    wireVisibility();
  }

  // ── Boot ──
  function init() {
    if (state.booted) return;
    state.booted = true;

    const missing = [];
    if (typeof escapeHtml !== 'function') missing.push('escapeHtml');
    if (typeof showToast !== 'function') missing.push('showToast');
    if (typeof responseResult !== 'function') missing.push('responseResult');
    if (typeof postToTAA !== 'function') missing.push('postToTAA');
    if (typeof buildImportBody !== 'function') missing.push('buildImportBody');
    if (missing.length) warnFallbacks(missing);

    wireAll();
    restoreLoginForm();

    // Restore the tab before the session call so a #audit deep link never flashes
    // the platform panel.
    state.tab = tabFromLocation();
    auditTabSwitch(state.tab);
    checkSession();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // ── Exported surface ──
  // Only the namespace and the inline handlers named by the contract leave this
  // IIFE; every other helper stays private.
  window.AuditConsole = {
    init: init,
    showTab: auditTabSwitch,
    switchView: auditConsoleSwitchView,
    isAuthenticated: () => !!state.user,
  };
  window.auditTabSwitch = auditTabSwitch;
  window.auditConsoleLogin = auditConsoleLogin;
  window.auditConsoleLogout = auditConsoleLogout;
  window.auditConsoleTogglePwd = auditConsoleTogglePwd;
  window.auditConsoleSwitchView = auditConsoleSwitchView;
  window.auditSubmitAudit = auditSubmitAudit;
  window.auditPromptSend = auditPromptSend;
  window.auditLoadJob = auditLoadJob;
})();
