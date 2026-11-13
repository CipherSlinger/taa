// ── TEE-LLM Console controller ──
//
// A logged-in console layered over the platform-mock page. It is deliberately
// self-contained: every helper it can reuse (escapeHtml, showToast, responseResult,
// llmRelativeTime/llmTimeOfDay/llmDuration) is taken from the globally loaded
// scripts, and everything else lives inside this IIFE so the page keeps its
// existing globals untouched.
//
// The platform is a *display* for evidence, not an enforcement point. Several
// labels below say so on purpose: "verified" here means the instance's own
// self-check reported pass, never that this console validated a hardware quote.
(function () {
  'use strict';

  // ── Constants ──
  const TAB_KEY = 'pm.llm.tab';               // sessionStorage: last active tab
  const USER_KEY = 'pm.llm.user';             // localStorage: remembered username only
  const SESSION_KEY = 'pm.llm.session';       // sessionStorage: cached user (never the password)
  const POLL_MS = 5000;                       // one cadence for overview + logs
  const GENERATE_TIMEOUT_MS = 130000;         // cold model load is allowed ~120s server-side
  const DEFAULT_TIMEOUT_MS = 15000;
  const CHAR_WARN = 8000;                     // prompt length warning threshold
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const TWO_STEP_MS = 3000;

  const VIEWS = ['overview', 'workbench', 'attest', 'logs', 'settings'];
  const VIEW_IDS = {
    overview: 'llmViewOverview',
    workbench: 'llmViewWorkbench',
    attest: 'llmViewAttest',
    logs: 'llmViewLogs',
    settings: 'llmViewSettings',
  };

  // ── Module state ──
  // One object, never a bag of globals. `user` is the authentication gate: every
  // poll and every session-scoped call checks it first.
  const state = {
    user: null,
    expiresAt: '',
    tab: 'platform',
    view: 'overview',
    booted: false,
    pollTimer: null,
    loginBusy: false,
    loginCountdown: null,
    inFlight: false,
    elapsedTimer: null,
    chat: [],
    logPaused: false,
    logAutoScroll: true,
    logLevels: new Set(),   // empty set means "all levels"
    logKeyword: '',
  };

  // ── Small helpers ──
  function $(id) {
    return document.getElementById(id);
  }

  function setText(id, value) {
    const el = $(id);
    if (el) el.textContent = value == null ? '' : String(value);
  }

  // Safe storage: private windows and blocked site data throw on access, and a
  // console that cannot remember a tab must still render.
  function storeGet(store, key) {
    try { return store.getItem(key); } catch (_) { return null; }
  }
  function storeSet(store, key, value) {
    try { store.setItem(key, value); } catch (_) {}
  }
  function storeRemove(store, key) {
    try { store.removeItem(key); } catch (_) {}
  }

  function unwrap(data) {
    if (typeof responseResult === 'function') return responseResult(data);
    return data && data.result !== undefined ? data.result : data;
  }

  function esc(value) {
    if (typeof escapeHtml === 'function') return escapeHtml(value);
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function toast(options) {
    if (typeof showToast === 'function') showToast(options);
  }

  function durationText(seconds) {
    if (typeof llmDuration === 'function') return llmDuration(seconds);
    const s = Number(seconds) || 0;
    return s < 60 ? s + 's' : Math.floor(s / 60) + 'm';
  }

  function relativeText(iso) {
    if (typeof llmRelativeTime === 'function') return llmRelativeTime(iso);
    return iso || '';
  }

  function timeText(iso) {
    if (typeof llmTimeOfDay === 'function') return llmTimeOfDay(iso);
    const t = Date.parse(iso);
    return Number.isNaN(t) ? '—' : new Date(t).toLocaleTimeString('zh-CN', { hour12: false });
  }

  function levelOf(message) {
    if (typeof detectLogLevel === 'function') {
      try {
        const detected = detectLogLevel(message);
        // The shared detector can return DEBUG from a structured prefix; this
        // console's filter row only exposes INFO/WARN/ERROR, so fold it in
        // rather than leaving rows that no filter can select.
        return detected === 'DEBUG' ? 'INFO' : detected;
      } catch (_) {}
    }
    const upper = String(message || '').toUpperCase();
    if (upper.indexOf('ERROR') !== -1 || upper.indexOf('FATAL') !== -1 ||
        upper.indexOf('PANIC') !== -1 || upper.indexOf('FAIL') !== -1) return 'ERROR';
    if (upper.indexOf('WARN') !== -1) return 'WARN';
    return 'INFO';
  }

  function highlight(safeText, keyword) {
    if (!keyword) return safeText;
    if (typeof highlightSearchMatches === 'function') {
      try { return highlightSearchMatches(safeText, keyword); } catch (_) {}
    }
    const escaped = keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return safeText.replace(new RegExp('(' + escaped + ')', 'gi'), '<mark class="hl-match">$1</mark>');
  }

  function copyText(text, label) {
    const value = String(text == null ? '' : text);
    if (!value || value === '—') {
      toast({ type: 'info', title: '无可复制内容', message: label || '' });
      return;
    }
    const done = () => toast({ type: 'success', title: '已复制', message: label || '' });
    const fallback = () => {
      const ta = document.createElement('textarea');
      ta.value = value;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); done(); } catch (_) {
        toast({ type: 'warning', title: '复制失败', message: '请手动选择文本' });
      }
      document.body.removeChild(ta);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(done).catch(fallback);
    } else {
      fallback();
    }
  }

  // ── HTTP wrapper ──
  // Every console call goes through here for three reasons: same-origin cookies
  // are mandatory, a hung request must not wedge a poll, and any 401 while the
  // app is open has to drop to the login gate in exactly one place.
  function timeoutSignal(ms) {
    if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') {
      return AbortSignal.timeout(ms);
    }
    const controller = new AbortController();
    setTimeout(() => controller.abort(), ms);
    return controller.signal;
  }

  async function llmApi(path, opts) {
    const options = Object.assign({}, opts || {});
    const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
    delete options.timeoutMs;
    options.credentials = 'same-origin';
    if (!options.cache) options.cache = 'no-store';
    if (!options.signal) options.signal = timeoutSignal(timeoutMs);

    let res;
    try {
      res = await fetch(path, options);
    } catch (err) {
      const timedOut = err && (err.name === 'TimeoutError' || err.name === 'AbortError');
      const wrapped = new Error(timedOut ? '请求超时' : '无法连接服务器');
      wrapped.timeout = timedOut;
      wrapped.network = true;
      throw wrapped;
    }

    let data = null;
    try { data = await res.json(); } catch (_) { data = null; }

    // A 401 on the login endpoint is a credential answer, not an expired session.
    if (res.status === 401 && state.user) {
      dropToLogin('会话已过期，请重新登录');
      const expired = new Error('会话已过期');
      expired.unauthorized = true;
      expired.status = 401;
      throw expired;
    }
    return { status: res.status, ok: res.ok, data: data };
  }

  // ── Tabs ──
  function tabFromLocation() {
    if (location.hash === '#llm') return 'llm';
    return storeGet(sessionStorage, TAB_KEY) === 'llm' ? 'llm' : 'platform';
  }

  function replaceHash(tab) {
    try {
      const base = location.pathname + location.search;
      const target = tab === 'llm' ? base + '#llm' : base;
      if (base + location.hash !== target) history.replaceState(null, '', target);
    } catch (_) {}
  }

  function llmTabSwitch(tab) {
    const next = tab === 'llm' ? 'llm' : 'platform';
    state.tab = next;

    const platform = $('tabPanelPlatform');
    const llm = $('tabPanelLLM');
    if (platform) platform.style.display = next === 'platform' ? '' : 'none';
    if (llm) llm.style.display = next === 'llm' ? '' : 'none';

    const bar = $('tabBar');
    if (bar) {
      bar.querySelectorAll('.tab-btn').forEach((btn) => {
        btn.classList.toggle('active', btn.dataset.tab === next);
      });
    }

    storeSet(sessionStorage, TAB_KEY, next);
    replaceHash(next);
    syncPoller();
    if (next === 'llm') refreshVisibleView();
  }

  function wireTabs() {
    const bar = $('tabBar');
    if (!bar) return;
    bar.querySelectorAll('.tab-btn').forEach((btn) => {
      // The contract's inline llmTabSwitch(tab) owns the button when present;
      // binding again would run the switch twice.
      if (btn.getAttribute('onclick')) return;
      btn.addEventListener('click', () => llmTabSwitch(btn.dataset.tab));
    });
  }

  // The poller exists only while the tab is visible, the user is logged in, and
  // the document is on screen. Anything else is background traffic the operator
  // cannot see.
  function syncPoller() {
    const shouldPoll = state.tab === 'llm' && !!state.user && !document.hidden;
    if (shouldPoll && !state.pollTimer) {
      state.pollTimer = setInterval(pollTick, POLL_MS);
      pollTick();
    } else if (!shouldPoll && state.pollTimer) {
      clearInterval(state.pollTimer);
      state.pollTimer = null;
    }
  }

  async function pollTick() {
    if (!state.user || state.tab !== 'llm') return;
    if (state.view === 'overview') { await refreshOverview(true); return; }
    if (state.view === 'logs') { await refreshLogs(); }
  }

  // ── Session / login gate ──
  function showAppView(show) {
    const app = $('llmAppView');
    const login = $('llmLoginView');
    if (app) app.style.display = show ? '' : 'none';
    if (login) login.style.display = show ? 'none' : '';
  }

  function showLoginError(message) {
    const el = $('llmLoginError');
    if (!el) return;
    el.textContent = message || '';
    el.style.display = message ? '' : 'none';
  }

  function setCapsWarning(on) {
    const el = $('llmLoginCapsWarn');
    if (el) el.style.display = on ? '' : 'none';
  }

  function toggleCapsWarning(input) {
    if (!input || typeof input.getModifierState !== 'function') return;
    setCapsWarning(!!input.getModifierState('CapsLock'));
  }

  function renderSessionPill() {
    const pill = $('llmSessionPill');
    if (!pill) return;
    if (!state.expiresAt) { pill.textContent = '已登录'; return; }
    const left = Math.round((Date.parse(state.expiresAt) - Date.now()) / 1000);
    pill.textContent = Number.isNaN(left) ? '已登录' : (left > 0 ? '会话剩余 ' + durationText(left) : '会话即将过期');
  }

  function restoreLoginForm() {
    const saved = storeGet(localStorage, USER_KEY);
    const userEl = $('llmLoginUser');
    const remember = $('llmLoginRemember');
    if (!saved) return;
    if (userEl && !userEl.value) userEl.value = saved;
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
    let left = Math.max(1, Math.floor(seconds));
    const btn = $('llmLoginSubmit');
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

  function enterApp(user, expiresAt) {
    state.user = user || { name: '' };
    state.expiresAt = expiresAt || '';
    stopLoginCountdown();
    storeSet(sessionStorage, SESSION_KEY, JSON.stringify({ user: state.user, expiresAt: state.expiresAt }));
    setText('llmUserName', state.user.name || '—');
    setText('llmUserRole', state.user.role || '');
    renderSessionPill();
    showAppView(true);
    showLoginError('');
    setCapsWarning(false);
    llmConsoleSwitchView(state.view || 'overview');
    // The model catalog lives in settings, not the overview. Fetch it silently
    // so the workbench select is populated before the operator opens it.
    refreshSettings(true);
    syncPoller();
  }

  function showLoginView() {
    state.user = null;
    showAppView(false);
    restoreLoginForm();
    syncPoller();
    const pwd = $('llmLoginPassword');
    if (pwd) pwd.value = '';
    if (state.tab === 'llm') {
      const userEl = $('llmLoginUser');
      if (userEl && !userEl.value) userEl.focus();
    }
  }

  // dropToLogin is the single exit from an authenticated app view (logout,
  // session expiry, boot failure). It clears in-memory conversation content so a
  // different operator never inherits the previous one's prompts.
  function dropToLogin(message) {
    state.user = null;
    state.expiresAt = '';
    stopLoginCountdown();
    storeRemove(sessionStorage, SESSION_KEY);
    state.chat = [];
    renderChat();
    resetAttestationView();
    showAppView(false);
    restoreLoginForm();
    syncPoller();
    showLoginError(message || '');
    if (state.tab === 'llm') {
      const userEl = $('llmLoginUser');
      if (userEl) userEl.focus();
    }
  }

  async function checkSession() {
    try {
      const res = await llmApi('/api/llm/console/session');
      const data = unwrap(res.data) || {};
      if (res.ok && data.authenticated && data.user) {
        enterApp(data.user, data.expiresAt);
      } else {
        showLoginView();
      }
    } catch (err) {
      // Boot is the one place a network error is silent: the login form itself
      // is the retry surface, and an offline page still has to render.
      showLoginView();
    }
  }

  async function llmConsoleLogin(event) {
    if (event && event.preventDefault) event.preventDefault();
    if (state.loginBusy) return;

    const userEl = $('llmLoginUser');
    const pwdEl = $('llmLoginPassword');
    const btn = $('llmLoginSubmit');
    const rememberEl = $('llmLoginRemember');
    const username = userEl ? userEl.value.trim() : '';
    const password = pwdEl ? pwdEl.value : '';

    if (!username || !password) {
      showLoginError('请输入用户名和口令');
      return;
    }

    state.loginBusy = true;
    if (btn) { btn.disabled = true; btn.classList.add('loading'); }
    showLoginError('');

    try {
      const res = await llmApi('/api/llm/console/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username, password: password }),
      });
      const data = unwrap(res.data) || {};

      if (res.ok && data.ok !== false) {
        // Remember-me stores the username only. A password in local storage is
        // readable by any script on the origin, so it never goes there.
        if (rememberEl && rememberEl.checked) storeSet(localStorage, USER_KEY, username);
        else storeRemove(localStorage, USER_KEY);
        if (pwdEl) pwdEl.value = '';
        enterApp(data.user || { name: username }, data.expiresAt);
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
        showLoginError(data.error || data.msg || '登录失败（HTTP ' + res.status + '）');
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
        // A 429 countdown owns the disabled state; do not undo it here.
        if (!state.loginCountdown) btn.disabled = false;
      }
    }
  }

  function llmConsoleLogout() {
    // Best-effort server logout: a failed call still drops the local session,
    // because the operator asked to leave.
    llmApi('/api/llm/console/logout', { method: 'POST' }).catch(() => {});
    dropToLogin('');
    toast({ type: 'info', title: '已退出登录', message: '本机会话已清除' });
  }

  function llmConsoleTogglePwd(event) {
    if (event && event.preventDefault) event.preventDefault();
    const pwd = $('llmLoginPassword');
    const btn = $('llmLoginTogglePwd');
    if (!pwd) return;
    const show = pwd.type === 'password';
    pwd.type = show ? 'text' : 'password';
    if (btn) {
      btn.classList.toggle('on', show);
      btn.setAttribute('aria-pressed', show ? 'true' : 'false');
      btn.setAttribute('title', show ? '隐藏口令' : '显示口令');
    }
    pwd.focus();
  }

  function wireLogin() {
    const form = $('llmLoginForm');
    if (form) {
      form.addEventListener('submit', llmConsoleLogin);
    } else {
      // Without a form element, Enter must still submit; bind it on both inputs.
      ['llmLoginUser', 'llmLoginPassword'].forEach((id) => {
        const el = $(id);
        if (!el) return;
        el.addEventListener('keydown', (e) => {
          if (e.key === 'Enter') { e.preventDefault(); llmConsoleLogin(e); }
        });
      });
    }

    const pwd = $('llmLoginPassword');
    if (pwd) {
      const onCaps = () => toggleCapsWarning(pwd);
      pwd.addEventListener('keydown', onCaps);
      pwd.addEventListener('keyup', onCaps);
      pwd.addEventListener('blur', () => setCapsWarning(false));
    }

    bindIfNoInline('llmLoginTogglePwd', llmConsoleTogglePwd);
    const remember = $('llmLoginRemember');
    if (remember) {
      remember.addEventListener('change', () => {
        const userEl = $('llmLoginUser');
        if (remember.checked && userEl && userEl.value.trim()) {
          storeSet(localStorage, USER_KEY, userEl.value.trim());
        } else if (!remember.checked) {
          storeRemove(localStorage, USER_KEY);
        }
      });
    }
  }

  // bindIfNoInline leaves a control alone when the markup wired it with the
  // inline function the contract names; adding a listener would double-fire.
  function bindIfNoInline(id, handler) {
    const el = $(id);
    if (!el || el.getAttribute('onclick')) return;
    el.addEventListener('click', handler);
  }

  // ── View switching ──
  function llmConsoleSwitchView(view) {
    const next = VIEWS.indexOf(view) !== -1 ? view : 'overview';
    state.view = next;

    VIEWS.forEach((name) => {
      const el = $(VIEW_IDS[name]);
      if (el) el.style.display = name === next ? '' : 'none';
    });

    // Highlight every item, including inline-wired ones; only click binding is
    // conditional (see wireNav).
    document.querySelectorAll('.llm-nav-item[data-llm-view]').forEach((btn) => {
      btn.classList.toggle('active', btn.dataset.llmView === next);
    });

    refreshVisibleView();
  }

  function refreshVisibleView() {
    if (!state.user) return;
    switch (state.view) {
      case 'overview':
        refreshOverview(false);
        break;
      case 'logs':
        refreshLogs();
        break;
      case 'settings':
        refreshSettings(false);
        break;
      // Workbench has nothing to fetch; attestation is an explicit hardware call
      // behind its button, so entering the view keeps the last render.
      default:
        break;
    }
  }

  function wireNav() {
    document.querySelectorAll('.llm-nav-item[data-llm-view]').forEach((btn) => {
      if (btn.getAttribute('onclick')) return;
      btn.addEventListener('click', () => llmConsoleSwitchView(btn.dataset.llmView));
    });
  }

  // ── Overview ──
  async function refreshOverview(silent) {
    if (!state.user) return;
    try {
      const res = await llmApi('/api/llm/console/overview');
      if (!res.ok) {
        if (!silent) toast({ type: 'warning', title: '概览刷新失败', message: 'HTTP ' + res.status });
        return;
      }
      const data = unwrap(res.data) || {};
      renderOverview(data);
    } catch (err) {
      if (err.unauthorized || silent) return;
      toast({ type: 'warning', title: '概览刷新失败', message: err.message });
    }
  }

  // The KPI markup is owned by the HTML file, so resolve the value slot
  // adaptively: a .llm-kpi-value child when present, the card itself when the
  // contract ID names the value, otherwise a slot created before .llm-kpi-sub.
  function setKpi(id, valueText, subText, tone) {
    const el = $(id);
    if (!el) return;

    let value = el.querySelector('.llm-kpi-value');
    if (!value && el.children.length === 0) value = el;
    if (!value) {
      value = document.createElement('span');
      value.className = 'llm-kpi-value';
      const sub = el.querySelector('.llm-kpi-sub');
      el.insertBefore(value, sub || el.firstChild);
    }
    value.textContent = valueText == null ? '—' : String(valueText);
    if (tone === 'ok' || tone === 'bad') {
      value.dataset.tone = tone;
      value.classList.add(tone);
    } else {
      delete value.dataset.tone;
      value.classList.remove('ok', 'bad');
    }

    let sub = el.querySelector('.llm-kpi-sub');
    if (!sub && el.parentElement) sub = el.parentElement.querySelector('.llm-kpi-sub');
    if (sub) sub.textContent = subText || '';
  }

  function renderOverview(data) {
    const inst = data.instance || {};
    const metrics = data.metrics || {};
    const lat = metrics.latencyMs || {};
    const total = Number(metrics.requests) || 0;
    const success = Number(metrics.success) || 0;
    const failures = Number(metrics.failures) || 0;
    const online = !!inst.reachable && !inst.lastError;

    setKpi('llmKpiStatus', online ? '在线' : '离线',
      inst.lastError ? '最近一次轮询报错'
        : (inst.heartbeatAt ? '心跳 ' + relativeText(inst.heartbeatAt) : '暂无心跳'),
      online ? 'ok' : 'bad');
    setKpi('llmKpiModel', inst.model || '—', inst.dockerId || '实例 ID 未知');
    setKpi('llmKpiUptime',
      inst.reachable && inst.uptimeSeconds != null ? durationText(inst.uptimeSeconds) : '—',
      inst.heartbeatAt ? '上次心跳 ' + timeText(inst.heartbeatAt) : '实例离线时无运行时长');
    setKpi('llmKpiLatency',
      lat.p95 != null ? Math.round(lat.p95) + ' ms' : '—',
      lat.p50 != null
        ? 'p50 ' + Math.round(lat.p50) + ' ms · 平均 ' + Math.round(lat.avg || 0) + ' ms'
        : '仅在成功请求上统计');
    setKpi('llmKpiSuccess',
      total > 0 ? ((success / total) * 100).toFixed(1) + '%' : '—',
      total > 0 ? '成功 ' + success + ' · 失败 ' + failures : '暂无请求');
    setKpi('llmKpiRequests', String(total),
      inst.pollSeconds != null ? '每 ' + inst.pollSeconds + 's 轮询' : '请求总数');

    fillFieldList($('llmInstanceFields'), [
      ['地址', inst.address || '—', { mono: true }],
      ['实例 ID', inst.dockerId || '—', { mono: true }],
      ['模型', inst.model || '—'],
      ['状态', inst.reachable ? '可达' : '不可达'],
      ['运行时长', inst.uptimeSeconds != null ? durationText(inst.uptimeSeconds) : '—'],
      ['最近心跳', inst.heartbeatAt ? timeText(inst.heartbeatAt) + '（' + relativeText(inst.heartbeatAt) + '）' : '—'],
      ['轮询间隔', inst.pollSeconds != null ? inst.pollSeconds + 's' : '—'],
      ['最近错误', inst.lastError || '—'],
    ]);

    const warn = $('llmOverviewWarn');
    if (warn) {
      const parts = [];
      if (!inst.reachable) parts.push('实例当前不可达，以下数据取自最后一次成功采样。');
      if (inst.lastError) parts.push('最近错误：' + inst.lastError);
      warn.textContent = parts.join(' ');
      warn.style.display = parts.length ? '' : 'none';
    }

    ensureModelOption(inst.model);
    renderSparkline(data.recentLatencies);
  }

  function resetAttestationView() {
    ['llmAttestFields', 'llmHandshakeFields'].forEach((id) => {
      const host = $(id);
      if (host) host.replaceChildren();
    });
    setText('llmRawAttestation', '—');
    setText('llmAttestFetchedAt', '—');
    const pill = $('llmAttestVerifyPill');
    if (pill) { pill.textContent = '未检测'; pill.dataset.tone = ''; }
  }

  // ── Latency sparkline ──
  // Built with SVG DOM, not innerHTML: the sample timestamps come from the
  // instance and an innerHTML path would turn a crafted value into markup. The
  // chart is fully replaced on every render, so no nodes or listeners survive a
  // poll.
  function svgElement(tag, attrs) {
    const el = document.createElementNS(SVG_NS, tag);
    if (attrs) {
      Object.keys(attrs).forEach((key) => el.setAttribute(key, attrs[key]));
    }
    return el;
  }

  function svgText(x, y, text, anchor, mono) {
    const el = svgElement('text', { x: x, y: y, 'text-anchor': anchor || 'start' });
    el.style.fill = 'var(--muted, #64748b)';
    el.style.fontSize = '11px';
    el.style.fontFamily = mono ? 'ui-monospace, SFMono-Regular, Menlo, monospace' : 'inherit';
    el.textContent = text;
    return el;
  }

  function renderSparkline(samples) {
    const host = $('llmLatencyChart');
    if (!host) return;

    let svg = host;
    if (host.namespaceURI !== SVG_NS) {
      svg = host.querySelector('svg');
      if (!svg) {
        svg = svgElement('svg', { width: '100%', height: '180' });
        host.appendChild(svg);
      }
    }
    while (svg.firstChild) svg.removeChild(svg.firstChild);

    // Measure once per render: a viewBox in real pixels avoids distorting axis
    // text, which a stretched 100%-wide viewBox would do. Hidden views report 0
    // and fall back to a usable width until the next poll lands.
    const width = Math.max(320, Math.round(host.clientWidth || 640));
    const height = 180;
    svg.setAttribute('viewBox', '0 0 ' + width + ' ' + height);

    const padL = 56;
    const padR = 16;
    const padT = 16;
    const padB = 26;
    const plotW = width - padL - padR;
    const plotH = height - padT - padB;

    const points = (Array.isArray(samples) ? samples : [])
      .map((s) => ({ at: s && s.at, ms: Number(s && s.ms), ok: !(s && s.ok === false) }))
      .filter((s) => Number.isFinite(s.ms));

    if (!points.length) {
      const empty = svgText(width / 2, height / 2, '暂无采样', 'middle');
      svg.appendChild(empty);
      return;
    }

    let max = 1;
    points.forEach((p) => { if (p.ms > max) max = p.ms; });
    const top = Math.ceil(max * 1.1);

    // Three horizontal gridlines: baseline, mid, top.
    [0, 0.5, 1].forEach((frac) => {
      const y = padT + plotH * (1 - frac);
      const line = svgElement('line', { x1: padL, y1: y, x2: width - padR, y2: y });
      line.style.stroke = 'var(--line, #e2e8f0)';
      line.setAttribute('stroke-width', '1');
      svg.appendChild(line);
      svg.appendChild(svgText(padL - 8, y + 4, Math.round(top * frac) + 'ms', 'end', true));
    });

    const xOf = (i) => (points.length === 1
      ? padL + plotW / 2
      : padL + (i / (points.length - 1)) * plotW);
    const yOf = (ms) => padT + plotH * (1 - ms / top);

    for (let i = 1; i < points.length; i += 1) {
      const seg = svgElement('line', {
        x1: xOf(i - 1), y1: yOf(points[i - 1].ms),
        x2: xOf(i), y2: yOf(points[i].ms),
      });
      seg.style.stroke = points[i].ok ? 'var(--llc-ok, #16a34a)' : 'var(--llc-bad, #dc2626)';
      seg.setAttribute('stroke-width', '2');
      seg.setAttribute('stroke-linecap', 'round');
      svg.appendChild(seg);
    }

    points.forEach((p, i) => {
      const dot = svgElement('circle', { cx: xOf(i), cy: yOf(p.ms), r: '3' });
      dot.style.fill = p.ok ? 'var(--llc-ok, #16a34a)' : 'var(--llc-bad, #dc2626)';
      svg.appendChild(dot);
    });

    // Axis endpoints only: a label per sample would collide at realistic counts.
    if (points[0].at) svg.appendChild(svgText(padL, height - 8, timeText(points[0].at), 'start'));
    if (points[points.length - 1].at) {
      svg.appendChild(svgText(width - padR, height - 8, timeText(points[points.length - 1].at), 'end'));
    }
  }

  // ── Shared field renderers ──
  // Both the instance table and the attestation tables are tbody elements per
  // the contract. Supporting a plain container keeps the renderer usable if the
  // markup ships as divs instead; the value is always set with textContent or a
  // pre-built node, never interpolated.
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
        if (opts.mono) target.classList.add('llm-mono');
      };

      if (isTable) {
        const tr = document.createElement('tr');
        const th = document.createElement('td');
        th.className = 'llm-field-label';
        th.textContent = label;
        const td = document.createElement('td');
        td.className = 'llm-field-value';
        display(td);
        tr.append(th, td);
        body.appendChild(tr);
      } else {
        const div = document.createElement('div');
        div.className = 'llm-field-row';
        const k = document.createElement('span');
        k.className = 'llm-field-label';
        k.textContent = label;
        const v = document.createElement('span');
        v.className = 'llm-field-value';
        display(v);
        div.append(k, v);
        body.appendChild(div);
      }
    });
  }

  function pillNode(ok, okText, badText) {
    const span = document.createElement('span');
    span.className = 'llm-pill ' + (ok ? 'ok' : 'bad');
    span.dataset.tone = ok ? 'ok' : 'bad';
    span.textContent = ok ? okText : badText;
    return span;
  }

  function monoWithCopy(text, label) {
    const wrap = document.createElement('span');
    wrap.className = 'llm-mono-wrap';
    const code = document.createElement('code');
    code.className = 'llm-mono';
    code.textContent = text || '—';
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'secondary btn-sm';
    btn.textContent = '复制';
    btn.addEventListener('click', () => copyText(text, label));
    wrap.append(code, btn);
    return wrap;
  }

  // The raw-report copy button sits outside #llmRawAttestation in the markup, so
  // create it once next to the <pre>. Its getter reads the live element because
  // each attestation replaces that text.
  function ensureCopyBtn(beforeEl, id, getText, label) {
    const existing = $(id);
    if (existing) return existing;
    if (!beforeEl || !beforeEl.parentElement) return null;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.id = id;
    btn.className = 'secondary btn-sm';
    btn.textContent = '复制原始证明';
    btn.addEventListener('click', () => copyText(getText(), label));
    beforeEl.parentElement.insertBefore(btn, beforeEl);
    return btn;
  }

  // ── Model catalog ──
  function ensureModelOption(model) {
    const sel = $('llmModelSelect');
    if (!sel || !model) return;
    const has = Array.from(sel.options).some((o) => o.value === model);
    if (!has) {
      const opt = document.createElement('option');
      opt.value = model;
      opt.textContent = model;
      sel.appendChild(opt);
      // Force the next full fill to rebuild in catalog order.
      sel.dataset.sig = '';
    }
    if (!sel.value) sel.value = model;
  }

  function fillModelSelect(models, active) {
    const sel = $('llmModelSelect');
    if (!sel) return;
    const previous = sel.value;
    const names = (Array.isArray(models) ? models : [])
      .map((m) => m && m.name)
      .filter(Boolean);
    if (active && names.indexOf(active) === -1) names.unshift(active);

    const sig = names.join('|');
    // Rebuilding identical options closes an open dropdown, so only touch the
    // DOM when the catalog actually changed.
    if (sel.dataset.sig !== sig) {
      sel.dataset.sig = sig;
      sel.replaceChildren();
      names.forEach((name) => {
        const opt = document.createElement('option');
        opt.value = name;
        opt.textContent = name;
        sel.appendChild(opt);
      });
    }
    const want = previous || active || names[0] || '';
    if (want) sel.value = want;
  }

  // ── Workbench ──
  function genRequestId() {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
      return 'console-' + crypto.randomUUID();
    }
    return 'console-' + Date.now() + '-' + Math.random().toString(16).slice(2, 8);
  }

  function renderChatEmpty(host) {
    const wrap = document.createElement('div');
    wrap.className = 'llm-chat-empty';

    const svg = svgElement('svg', {
      viewBox: '0 0 24 24', width: '42', height: '42',
      fill: 'none', stroke: 'currentColor', 'stroke-width': '1.5',
      'stroke-linecap': 'round', 'stroke-linejoin': 'round',
    });
    svg.style.color = 'var(--muted, #64748b)';
    svg.appendChild(svgElement('path', { d: 'M12 3l7 3v5c0 4.4-3 8.2-7 10-4-1.8-7-5.6-7-10V6l7-3z' }));
    svg.appendChild(svgElement('path', { d: 'M9.5 12l1.8 1.8L15 10' }));

    const title = document.createElement('div');
    title.className = 'llm-chat-empty-title';
    title.textContent = '在工作台发起一次机密推理';
    const desc = document.createElement('div');
    desc.className = 'llm-chat-empty-desc';
    desc.textContent = '在左侧选择模型与采样参数，输入提示词后按 Ctrl+Enter（或 Cmd+Enter）发送。'
      + '回复由 TEE-LLM 网关在机密环境中生成，平台只转发与展示，不校验其内容。';

    wrap.append(svg, title, desc);
    host.appendChild(wrap);
  }

  function metaLine(msg) {
    const meta = msg.meta || {};
    if (msg.role === 'error') {
      return [meta.requestId ? 'requestId ' + meta.requestId : '', meta.at ? timeText(meta.at) : '']
        .filter(Boolean).join(' · ');
    }
    return [
      meta.model || '—',
      meta.elapsedMs != null ? meta.elapsedMs + ' ms' : '',
      meta.status || '',
      meta.requestId ? 'requestId ' + meta.requestId : '',
    ].filter(Boolean).join(' · ');
  }

  function buildChatMessage(msg) {
    const wrap = document.createElement('div');
    wrap.className = 'llm-msg llm-msg-' + msg.role;

    const bubble = document.createElement('div');
    bubble.className = 'llm-bubble llm-bubble-' + msg.role;

    let text = msg.text == null ? '' : String(msg.text);
    if (msg.role === 'error' && msg.meta && msg.meta.httpStatus != null) {
      text += '（HTTP ' + msg.meta.httpStatus + '）';
    }

    if (msg.role === 'assistant') {
      // <pre> preserves the model's whitespace; textContent keeps it escaped.
      const pre = document.createElement('pre');
      pre.className = 'llm-reply';
      pre.textContent = text;
      bubble.appendChild(pre);
    } else {
      bubble.textContent = text;
    }
    wrap.appendChild(bubble);

    if (msg.role === 'assistant' || msg.role === 'error') {
      const meta = document.createElement('div');
      meta.className = 'llm-meta';
      meta.appendChild(document.createTextNode(metaLine(msg)));
      if (msg.role === 'assistant') {
        const copy = document.createElement('button');
        copy.type = 'button';
        copy.className = 'llm-copy-btn';
        copy.textContent = '复制';
        copy.addEventListener('click', () => copyText(text, '助手回复'));
        meta.appendChild(document.createTextNode(' '));
        meta.appendChild(copy);
      }
      wrap.appendChild(meta);
    }
    return wrap;
  }

  function renderChat() {
    const host = $('llmConversation');
    if (!host) return;
    host.replaceChildren();
    if (!state.chat.length) {
      renderChatEmpty(host);
      return;
    }
    state.chat.forEach((msg) => host.appendChild(buildChatMessage(msg)));
  }

  function startReplyHint() {
    const hint = $('llmReplyHint');
    if (!hint) return;
    hint.replaceChildren();
    const spinner = document.createElement('span');
    spinner.className = 'llm-spinner';
    spinner.setAttribute('aria-hidden', 'true');
    const label = document.createElement('span');
    hint.append(spinner, label);
    hint.style.display = '';

    const started = Date.now();
    const paint = () => {
      label.textContent = ' 推理中… ' + Math.floor((Date.now() - started) / 1000) + 's';
    };
    paint();
    if (state.elapsedTimer) clearInterval(state.elapsedTimer);
    state.elapsedTimer = setInterval(paint, 1000);
  }

  function stopReplyHint() {
    if (state.elapsedTimer) {
      clearInterval(state.elapsedTimer);
      state.elapsedTimer = null;
    }
    setText('llmReplyHint', '');
  }

  function updateCharCount() {
    const input = $('llmPromptInput');
    const out = $('llmCharCount');
    const n = input ? input.value.length : 0;
    if (!out) return;
    out.textContent = n + ' / ' + CHAR_WARN;
    out.classList.toggle('over', n > CHAR_WARN);
    out.dataset.tone = n > CHAR_WARN ? 'warn' : '';
  }

  async function llmConsoleSend() {
    if (!state.user || state.inFlight) return;

    const promptEl = $('llmPromptInput');
    const prompt = promptEl ? promptEl.value : '';
    if (!prompt.trim()) {
      toast({ type: 'warning', title: '提示词为空', message: '请输入要发送的内容' });
      if (promptEl) promptEl.focus();
      return;
    }

    const modelEl = $('llmModelSelect');
    const systemEl = $('llmSystemPrompt');
    const requestId = genRequestId();

    const body = { prompt: prompt, requestId: requestId };
    if (modelEl && modelEl.value) body.model = modelEl.value;
    if (systemEl && systemEl.value.trim()) body.system = systemEl.value;

    // Only send options the operator actually set: the server applies its own
    // reproducible default (temperature 0) when the object is absent.
    const options = {};
    const tempEl = $('llmTemperature');
    if (tempEl && tempEl.value !== '') {
      const temp = Number(tempEl.value);
      if (Number.isFinite(temp)) options.temperature = temp;
    }
    const predictEl = $('llmNumPredict');
    if (predictEl && predictEl.value !== '') {
      const num = parseInt(predictEl.value, 10);
      if (Number.isFinite(num) && num > 0) options.num_predict = num;
    }
    if (Object.keys(options).length) body.options = options;

    state.chat.push({ role: 'user', text: prompt, meta: { at: new Date().toISOString() } });
    if (promptEl) promptEl.value = '';
    updateCharCount();
    renderChat();

    state.inFlight = true;
    const sendBtn = $('llmSendBtn');
    if (sendBtn) {
      sendBtn.disabled = true;
      sendBtn.setAttribute('aria-busy', 'true');
    }
    setText('llmRequestMeta', '请求 ' + requestId + ' 进行中…');
    startReplyHint();

    try {
      const res = await llmApi('/api/llm/console/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        timeoutMs: GENERATE_TIMEOUT_MS,
      });
      const data = unwrap(res.data) || {};

      if (res.ok && data.text != null) {
        state.chat.push({
          role: 'assistant',
          text: data.text,
          meta: {
            model: data.model || body.model || '',
            elapsedMs: data.elapsedMs,
            status: data.status || 'ok',
            requestId: data.requestId || requestId,
            at: new Date().toISOString(),
          },
        });
        setText('llmRequestMeta', (data.requestId || requestId) + ' · ' + (data.status || 'ok'));
      } else {
        const httpStatus = data.httpStatus != null ? data.httpStatus : res.status;
        state.chat.push({
          role: 'error',
          text: data.error || data.errorMessage || (res.ok ? '实例未返回文本' : '推理失败'),
          meta: {
            httpStatus: httpStatus,
            requestId: data.requestId || requestId,
            at: new Date().toISOString(),
          },
        });
        setText('llmRequestMeta', (data.requestId || requestId) + ' · 失败');
      }
    } catch (err) {
      if (!err.unauthorized) {
        state.chat.push({
          role: 'error',
          text: err.timeout ? '推理请求超时（130s）' : err.message,
          meta: { httpStatus: 0, requestId: requestId, at: new Date().toISOString() },
        });
        setText('llmRequestMeta', requestId + ' · 失败');
      }
    } finally {
      state.inFlight = false;
      if (sendBtn) {
        sendBtn.disabled = false;
        sendBtn.removeAttribute('aria-busy');
      }
      stopReplyHint();
      renderChat();
    }
  }

  // ── Inline two-step confirmation ──
  // window.confirm is blocked in some embedded viewers, so destructive buttons
  // arm themselves for three seconds instead of opening a dialog.
  function bindTwoStep(btn, confirmLabel, action) {
    if (!btn || btn.getAttribute('onclick')) return;
    btn.addEventListener('click', () => {
      if (btn.dataset.armed === '1') {
        if (btn.dataset.armTimer) clearTimeout(Number(btn.dataset.armTimer));
        btn.dataset.armed = '';
        btn.dataset.armTimer = '';
        btn.textContent = btn.dataset.originalText || btn.textContent;
        action();
        return;
      }
      btn.dataset.armed = '1';
      btn.dataset.originalText = btn.dataset.originalText || btn.textContent;
      btn.textContent = confirmLabel;
      btn.dataset.armTimer = String(setTimeout(() => {
        btn.dataset.armed = '';
        btn.dataset.armTimer = '';
        btn.textContent = btn.dataset.originalText || '';
      }, TWO_STEP_MS));
    });
  }

  function clearChat() {
    state.chat = [];
    renderChat();
    toast({ type: 'success', title: '会话已清空', message: '仅清除本页内容，不影响服务端历史' });
  }

  function exportChat() {
    if (!state.chat.length) {
      toast({ type: 'info', title: '暂无可导出内容', message: '先发送一次推理' });
      return;
    }
    const payload = {
      exportedAt: new Date().toISOString(),
      user: state.user ? state.user.name : '',
      note: '平台仅展示推理结果，不校验证明内容。',
      messages: state.chat.map((m) => ({
        role: m.role,
        text: m.text,
        meta: m.meta || {},
      })),
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = 'llm-chat-' + stamp + '.json';

    if (typeof downloadBlob === 'function') {
      downloadBlob(blob, filename);
      return;
    }
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function wireWorkbench() {
    bindIfNoInline('llmSendBtn', llmConsoleSend);
    const prompt = $('llmPromptInput');
    if (prompt) {
      prompt.addEventListener('input', updateCharCount);
      prompt.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
          e.preventDefault();
          llmConsoleSend();
        }
      });
    }
    updateCharCount();
    renderChat();
    bindTwoStep($('llmClearChatBtn'), '确认清空？', clearChat);
    bindIfNoInline('llmExportChatBtn', exportChat);
  }

  // ── Attestation ──
  // The platform pulls evidence and shows it. It does not check a quote, a
  // measurement policy or a certificate chain against a trust anchor, so the
  // wording below never claims "verified" for the overall report — only that the
  // instance's own self-check passed.
  function renderAttestation(data) {
    const att = data || {};

    setText('llmAttestFetchedAt', att.fetchedAt ? timeText(att.fetchedAt) : '—');

    fillFieldList($('llmAttestFields'), [
      ['requestId', att.requestId || '—', { mono: true }],
      ['实例自检', pillNode(!!att.verifiedPass, '通过', '失败')],
      ['报告大小', att.attestationSize != null ? att.attestationSize + ' B' : '—'],
      ['获取时间', att.fetchedAt
        ? timeText(att.fetchedAt) + '（' + relativeText(att.fetchedAt) + '）'
        : '—'],
      ['错误', att.error || data.error || '—'],
      ['平台行为', '仅展示证据，不做强制校验'],
    ]);

    // /overview nests the handshake under teeTLS.lastHandshake; the attestation
    // endpoint returns the handshake itself as teeTLS. Accept both.
    const tls = att.teeTLS || {};
    const hs = tls.lastHandshake || tls;
    const hasHandshake = !!(tls.endpoint || hs.at || hs.measurementHex || hs.ok);
    if (!hasHandshake) {
      fillFieldList($('llmHandshakeFields'), [
        ['握手记录', '暂无。拉取证明或发起一次推理后会记录最近一次握手。'],
      ]);
    } else {
      // The attestation payload carries the bare handshake, so endpoint/mode
      // rows only exist when they came from the overview shape.
      const rows = [];
      if (tls.endpoint) rows.push(['endpoint', tls.endpoint, { mono: true }]);
      if (tls.mode) rows.push(['模式', tls.mode]);
      if (tls.skipChainVerify != null) rows.push(['跳过链校验', tls.skipChainVerify ? '是' : '否']);
      fillFieldList($('llmHandshakeFields'), rows.concat([
        ['握手', pillNode(!!hs.ok,
          hs.elapsedMs != null ? '成功 · ' + hs.elapsedMs + 'ms' : '成功',
          hs.error ? '失败 · ' + hs.error : '失败')],
        ['测量值', monoWithCopy(hs.measurementHex || '', '测量值')],
        ['公钥绑定', hs.publicKeyBound ? '已绑定' : '未绑定'],
        ['证书主体', hs.certSubject || '—'],
        ['握手时间', hs.at ? timeText(hs.at) + '（' + relativeText(hs.at) + '）' : '—'],
        ['错误', hs.error || tls.error || '—'],
      ]));
    }

    const raw = $('llmRawAttestation');
    const rawText = att.attestationBase64 || att.attestationValues || '';
    if (raw) raw.textContent = rawText || '—';
    ensureCopyBtn(raw, 'llmRawCopyBtn',
      () => (raw ? raw.textContent : ''), '原始证明');
  }

  async function fetchAttestation() {
    if (!state.user) return;
    const btn = $('llmFetchAttestBtn');
    if (btn) btn.disabled = true;
    try {
      const res = await llmApi('/api/llm/console/attestation', { method: 'POST' });
      const payload = res.data || {};
      const data = unwrap(payload) || {};
      // The console endpoint may return either a bare object or the {msg,result}
      // envelope of the older handler; teeTLS can sit at either level.
      if (payload && payload.teeTLS && !data.teeTLS) data.teeTLS = payload.teeTLS;
      renderAttestation(data);
      if (res.ok) {
        toast({ type: 'success', title: '已获取证明', message: '平台只展示证据，不强制校验' });
      } else {
        toast({
          type: 'warning',
          title: '获取证明失败',
          message: data.error || data.msg || 'HTTP ' + res.status,
        });
      }
    } catch (err) {
      if (!err.unauthorized) {
        toast({ type: 'warning', title: '获取证明失败', message: err.message });
      }
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function verifyTLS() {
    const pill = $('llmAttestVerifyPill');
    if (pill) {
      pill.textContent = '检测中…';
      pill.dataset.tone = '';
    }
    try {
      // A real handshake, not /health: the health probe runs an inference and
      // returns nothing about the TLS session. The attestation call dials
      // TEE-TLS and reports the evidence (measurement, binding, chain).
      const res = await llmApi('/api/llm/console/attestation', { method: 'POST' });
      const payload = res.data || {};
      const data = unwrap(payload) || {};
      if (payload && payload.teeTLS && !data.teeTLS) data.teeTLS = payload.teeTLS;
      const tls = data.teeTLS || {};
      const hs = tls.lastHandshake || tls;
      const ok = !!hs.ok;
      if (pill) {
        pill.textContent = ok
          ? 'TLS 可达 · ' + (hs.elapsedMs != null ? hs.elapsedMs + 'ms' : '—')
          : 'TLS 不可达' + (hs.error ? ' · ' + hs.error : '');
        pill.dataset.tone = ok ? 'ok' : 'bad';
        // The pill is the most likely place an operator reads as a verdict, so
        // it carries the honesty caveat too.
        pill.title = '只表示本次连接与握手成功，不表示平台校验并接受了证明';
      }
      renderAttestation(data);
      toast({
        type: ok ? 'success' : 'warning',
        title: ok ? 'TLS 可达' : 'TLS 不可达',
        message: ok
          ? '仅表示连接与握手成功，不代表证明已被校验'
          : (hs.error || 'HTTP ' + res.status),
      });
    } catch (err) {
      if (err.unauthorized) return;
      if (pill) {
        pill.textContent = 'TLS 不可达';
        pill.dataset.tone = 'bad';
      }
      toast({ type: 'warning', title: '检测失败', message: err.message });
    }
  }

  function wireAttest() {
    bindIfNoInline('llmFetchAttestBtn', fetchAttestation);
    bindIfNoInline('llmVerifyTLSBtn', verifyTLS);
    const pill = $('llmAttestVerifyPill');
    if (pill) {
      // Visible text stays short; the caveat rides on hover so the UI never
      // reads as a platform-enforced verification.
      pill.title = '平台只展示证据、不强制校验；此处仅表示最近一次 TLS 连通性检测结果';
    }
  }

  // ── Logs ──
  // /api/llm/status is the existing public snapshot endpoint; the console only
  // renders it. Entries carry {seq, message} and the level lives inside the text,
  // so detection has to read the line itself.
  function buildLogRow(entry) {
    const message = entry && entry.message != null ? String(entry.message) : '';
    const level = levelOf(message);

    const row = document.createElement('div');
    row.className = 'log-row';
    row.dataset.seq = entry && entry.seq != null ? String(entry.seq) : '';
    row.dataset.level = level;
    row.dataset.rawText = message;

    const seq = document.createElement('span');
    seq.className = 'log-seq';
    seq.textContent = '[seq=' + (entry && entry.seq != null ? entry.seq : '') + ']';

    const lvl = document.createElement('span');
    lvl.className = 'log-lvl ' + level.toLowerCase();
    lvl.textContent = level;

    const msg = document.createElement('span');
    msg.className = 'log-msg';
    msg.textContent = message;

    row.append(seq, lvl, msg);
    return row;
  }

  function applyLogFilter() {
    const out = $('llmConsoleLogOutput');
    if (!out) return;
    const keyword = state.logKeyword;
    const levels = state.logLevels;

    out.querySelectorAll('.log-row').forEach((row) => {
      const level = row.dataset.level || 'INFO';
      const raw = row.dataset.rawText || '';
      const levelMatch = levels.size === 0 || levels.has(level);
      const keywordMatch = !keyword || raw.toLowerCase().indexOf(keyword.toLowerCase()) !== -1;
      const show = levelMatch && keywordMatch;
      row.style.display = show ? '' : 'none';

      const msg = row.querySelector('.log-msg');
      if (!msg) return;
      // Highlight the escaped text, never the raw one: the raw message is
      // attacker-controlled and goes through innerHTML here.
      if (show && keyword) msg.innerHTML = highlight(esc(raw), keyword);
      else msg.textContent = raw;
    });

    updateJumpBtn();
  }

  function renderLogs(logs) {
    const out = $('llmConsoleLogOutput');
    if (!out) return;

    const entries = logs && Array.isArray(logs.entries) ? logs.entries : [];
    const total = logs && logs.totalCount != null ? logs.totalCount : entries.length;
    setText('llmConsoleLogCount', total + ' 条日志');

    if (state.logPaused) return;

    out.replaceChildren();
    if (!entries.length) {
      const empty = document.createElement('div');
      empty.className = 'llm-log-empty';
      empty.textContent = '暂无日志。mock 尚未从实例拉到 /v1/llm/log 的内容。';
      out.appendChild(empty);
      updateJumpBtn();
      return;
    }

    const fragment = document.createDocumentFragment();
    entries.forEach((entry) => fragment.appendChild(buildLogRow(entry)));
    out.appendChild(fragment);

    applyLogFilter();
    if (state.logAutoScroll) out.scrollTop = out.scrollHeight;
    updateJumpBtn();
  }

  async function refreshLogs(force) {
    if (!state.user) return;
    if (state.logPaused && !force) return;
    try {
      const res = await llmApi('/api/llm/status');
      if (!res.ok) return;
      // The status payload nests the log pull under `logs`; the rest of it
      // (last heartbeat, address) drives the platform tab, not this view.
      renderLogs((res.data && res.data.logs) || {});
    } catch (err) {
      // Background poll: keep the last render; the topbar refresh reports errors.
      if (err.unauthorized) return;
    }
  }

  function ensureJumpBtn() {
    const out = $('llmConsoleLogOutput');
    if (!out) return null;

    let btn = document.getElementById('llmJumpBottomBtn');
    if (btn) return btn;

    btn = document.createElement('button');
    btn.type = 'button';
    btn.id = 'llmJumpBottomBtn';
    btn.className = 'llm-jump-bottom';
    btn.textContent = '回到底部';
    btn.style.display = 'none';
    // Self-sufficient placement: the view container is the nearest common
    // ancestor, and inline positioning keeps the affordance usable even before
    // the stylesheet ships a rule for it.
    btn.style.position = 'absolute';
    btn.style.right = '18px';
    btn.style.bottom = '18px';
    btn.style.zIndex = '5';

    btn.addEventListener('click', () => {
      state.logAutoScroll = true;
      out.scrollTop = out.scrollHeight;
      btn.style.display = 'none';
    });

    const host = $('llmViewLogs') || out.parentElement;
    if (host) {
      try {
        if (getComputedStyle(host).position === 'static') host.style.position = 'relative';
      } catch (_) {}
      host.appendChild(btn);
    } else {
      return null;
    }
    return btn;
  }

  function updateJumpBtn() {
    const btn = document.getElementById('llmJumpBottomBtn');
    const out = $('llmConsoleLogOutput');
    if (!btn || !out) return;
    const overflow = out.scrollHeight - out.scrollTop - out.clientHeight > 48;
    btn.style.display = overflow ? '' : 'none';
  }

  function toggleLogPause() {
    state.logPaused = !state.logPaused;
    const btn = $('llmConsoleLogPauseBtn');
    if (btn) {
      btn.textContent = state.logPaused ? '继续' : '暂停';
      btn.classList.toggle('active', state.logPaused);
    }
    // Resuming must not leave a stale panel on screen: fetch at once instead of
    // waiting for the next tick.
    if (!state.logPaused) refreshLogs();
  }

  function toggleLogLevel(level) {
    if (!level) return;
    if (level === 'ALL') {
      state.logLevels.clear();
    } else if (state.logLevels.has(level)) {
      state.logLevels.delete(level);
    } else {
      state.logLevels.add(level);
    }
    syncLevelButtons();
    applyLogFilter();
  }

  function syncLevelButtons() {
    const wrap = $('llmConsoleLogLevels');
    if (!wrap) return;
    const all = state.logLevels.size === 0;
    wrap.querySelectorAll('.llm-log-level').forEach((btn) => {
      const level = btn.dataset.level;
      const active = level === 'ALL' ? all : state.logLevels.has(level);
      btn.classList.toggle('active', active);
    });
  }

  // Seed from the markup so an HTML-side default (e.g. INFO pre-selected) is
  // respected instead of silently overridden on load.
  function seedLogLevels() {
    const wrap = $('llmConsoleLogLevels');
    if (!wrap) return;
    const active = Array.from(wrap.querySelectorAll('.llm-log-level.active'))
      .map((btn) => btn.dataset.level)
      .filter((level) => level && level !== 'ALL');
    if (active.length) state.logLevels = new Set(active);
    syncLevelButtons();
  }

  async function clearLogs() {
    try {
      const res = await llmApi('/api/llm/logs/clear', { method: 'POST' });
      if (!res.ok) {
        toast({ type: 'warning', title: '清空失败', message: 'HTTP ' + res.status });
        return;
      }
      const data = unwrap(res.data) || {};
      const cleared = data.cleared != null ? data.cleared : 0;
      const out = $('llmConsoleLogOutput');
      if (out) out.replaceChildren();
      setText('llmConsoleLogCount', '0 条日志');
      toast({ type: 'success', title: '已清空', message: '已清空 ' + cleared + ' 条日志' });
    } catch (err) {
      if (!err.unauthorized) {
        toast({ type: 'warning', title: '清空失败', message: err.message });
      }
    }
  }

  async function pollNow() {
    try {
      await llmApi('/api/llm/poll', { method: 'POST' });
    } catch (_) {
      // The refresh below renders whatever the poll managed to record.
    }
    await refreshLogs(true);
  }

  function wireLogs() {
    const out = $('llmConsoleLogOutput');
    ensureJumpBtn();
    if (out) {
      out.addEventListener('scroll', () => {
        state.logAutoScroll = out.scrollHeight - out.scrollTop - out.clientHeight <= 40;
        updateJumpBtn();
      });
    }

    const search = $('llmConsoleLogSearch');
    if (search) {
      search.addEventListener('input', () => {
        state.logKeyword = search.value.trim();
        applyLogFilter();
      });
    }

    const levels = $('llmConsoleLogLevels');
    if (levels) {
      levels.querySelectorAll('.llm-log-level').forEach((btn) => {
        if (btn.getAttribute('onclick')) return;
        btn.addEventListener('click', () => toggleLogLevel(btn.dataset.level));
      });
    }
    seedLogLevels();

    bindIfNoInline('llmConsoleLogPauseBtn', toggleLogPause);
    bindIfNoInline('llmConsoleLogClearBtn', clearLogs);
    bindIfNoInline('llmConsolePollNowBtn', pollNow);
  }

  // ── Settings ──
  const SETTINGS_HINT = 'permissive 只记录证据、不因证明校验失败中断请求；'
    + 'strict 需要本机配置 HRK/HSK 信任锚，没有锚时握手会失败；'
    + 'insecure 跳过证明校验，仅供本机联调。跳过证书链校验只验证对端证明、不做 CA 链校验。'
    + '平台对证据只展示、不强制校验；设置保存后只影响后续请求。';

  function ensureOptions(select, values) {
    const have = Array.from(select.options).map((o) => o.value);
    values.forEach((value) => {
      if (have.indexOf(value) !== -1) return;
      const opt = document.createElement('option');
      opt.value = value;
      opt.textContent = value;
      select.appendChild(opt);
    });
  }

  function renderModels(models) {
    const host = $('llmModelsList');
    if (!host) return;
    const list = Array.isArray(models) ? models : [];

    if (host.tagName === 'TBODY' || host.tagName === 'TABLE') {
      const body = host.tagName === 'TABLE' ? (host.tBodies[0] || host) : host;
      body.replaceChildren();
      list.forEach((model) => {
        const tr = document.createElement('tr');
        [model.name, model.parameterSize || '—',
          model.timeoutSeconds != null ? model.timeoutSeconds + 's' : '—'].forEach((value) => {
          const td = document.createElement('td');
          td.textContent = value == null || value === '' ? '—' : String(value);
          tr.appendChild(td);
        });
        body.appendChild(tr);
      });
      return;
    }

    host.replaceChildren();
    list.forEach((model) => {
      const row = document.createElement('div');
      row.className = 'llm-model-row';
      const name = document.createElement('span');
      name.className = 'llm-model-name';
      name.textContent = model.name || '';
      const meta = document.createElement('span');
      meta.className = 'llm-model-meta';
      meta.textContent = [model.parameterSize,
        model.timeoutSeconds != null ? model.timeoutSeconds + 's' : '']
        .filter(Boolean).join(' · ');
      row.append(name, meta);
      host.appendChild(row);
    });
  }

  function renderSettings(settings) {
    const data = settings || {};
    const tls = data.teeTLS || {};
    const session = data.session || {};

    setText('llmEndpointValue', data.endpoint || '—');
    setText('llmPlaintextEndpointValue', data.plaintextEndpoint || '—');

    const mode = $('llmTLSModeSelect');
    if (mode) {
      if (mode.tagName === 'SELECT') {
        ensureOptions(mode, ['permissive', 'strict', 'insecure']);
        if (tls.mode) mode.value = tls.mode;
      } else if (tls.mode) {
        mode.textContent = tls.mode;
      }
    }

    const skip = $('llmTLSSkipChain');
    if (skip) {
      if (skip.type === 'checkbox') skip.checked = !!tls.skipChainVerify;
      else skip.textContent = tls.skipChainVerify ? '是' : '否';
    }

    const timeout = $('llmTLSTimeout');
    if (timeout) {
      if (timeout.tagName === 'INPUT') {
        timeout.value = tls.timeoutSeconds != null ? String(tls.timeoutSeconds) : '';
      } else {
        timeout.textContent = tls.timeoutSeconds != null ? tls.timeoutSeconds + 's' : '—';
      }
    }

    renderModels(data.models || []);
    setText('llmSessionTTL', session.ttlSeconds != null
      ? '会话 ' + durationText(session.ttlSeconds) + ' · 用户 ' + (session.user || '—')
      : (session.user ? '用户 ' + session.user : '—'));
    setText('llmSettingsHint', SETTINGS_HINT);
    fillModelSelect(data.models || [], data.activeModel);
  }

  async function refreshSettings(silent) {
    if (!state.user) return;
    try {
      const res = await llmApi('/api/llm/console/settings');
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

  async function saveSettings() {
    if (!state.user) return;
    const modeEl = $('llmTLSModeSelect');
    const skipEl = $('llmTLSSkipChain');
    const btn = $('llmSaveSettingsBtn');
    const mode = modeEl ? modeEl.value : 'permissive';
    const skip = skipEl ? !!skipEl.checked : true;

    if (btn) btn.disabled = true;
    try {
      const res = await llmApi('/api/llm/console/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ teeTLS: { mode: mode, skipChainVerify: skip } }),
      });
      const data = unwrap(res.data) || {};
      if (res.ok) {
        renderSettings(data);
        toast({ type: 'success', title: '设置已保存', message: '新的 TLS 参数从下一次请求生效' });
      } else {
        toast({
          type: 'warning',
          title: '保存失败',
          message: data.error || data.msg || 'HTTP ' + res.status,
        });
      }
    } catch (err) {
      if (!err.unauthorized) {
        toast({ type: 'warning', title: '保存失败', message: err.message });
      }
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  // Reset clears only this console's local state: the prompt log and remembered
  // preferences. Server-side settings and history are deliberately untouched.
  function resetConsolePrefs() {
    state.chat = [];
    state.logKeyword = '';
    state.logLevels = new Set();
    state.logPaused = false;

    const prompt = $('llmPromptInput');
    if (prompt) prompt.value = '';
    const search = $('llmConsoleLogSearch');
    if (search) search.value = '';
    const remember = $('llmLoginRemember');
    if (remember) remember.checked = false;

    ['pm.llm.tab', 'pm.llm.session', 'pm.llm.user'].forEach((key) => {
      storeRemove(localStorage, key);
      storeRemove(sessionStorage, key);
    });

    updateCharCount();
    renderChat();
    syncLevelButtons();
    applyLogFilter();
    toast({ type: 'success', title: '本地状态已重置', message: '会话内容与本地偏好已清除，服务端未改动' });
  }

  // Per-switch explanations sit next to the control that carries the risk. The
  // summary in #llmSettingsHint repeats them because that element is guaranteed
  // by the contract while these are created here.
  function ensureFieldHint(afterEl, id, text) {
    if (!afterEl || !afterEl.parentElement) return;
    let hint = $(id);
    if (!hint) {
      hint = document.createElement('div');
      hint.id = id;
      hint.className = 'llm-field-hint';
      afterEl.insertAdjacentElement('afterend', hint);
    }
    hint.textContent = text;
  }

  function wireSettings() {
    bindIfNoInline('llmSaveSettingsBtn', saveSettings);
    bindTwoStep($('llmResetBtn'), '确认重置？', resetConsolePrefs);
    ensureFieldHint($('llmTLSModeSelect'), 'llmTLSModeHint',
      'permissive 只记录证据、不因校验失败中断；strict 需要本机配置 HRK/HSK 信任锚，'
      + '没有锚时握手会失败；insecure 跳过证明校验，仅供本机联调。');
    ensureFieldHint($('llmTLSSkipChain'), 'llmSkipChainHint',
      '跳过证书链校验只验证对端证明、不做 CA 链校验；关闭后必须能验证到信任的证书链，'
      + '否则请求会失败。');
  }

  // ── Top bar ──
  function wireTopbar() {
    bindIfNoInline('llmLogoutBtn', llmConsoleLogout);
    bindIfNoInline('llmTopRefreshBtn', () => {
      if (!state.user) return;
      renderSessionPill();
      refreshVisibleView();
    });
  }

  // ── Boot ──
  function wireVisibility() {
    document.addEventListener('visibilitychange', syncPoller);
  }

  function init() {
    if (state.booted) return;
    state.booted = true;

    wireTabs();
    wireNav();
    wireLogin();
    wireWorkbench();
    wireAttest();
    wireLogs();
    wireSettings();
    wireTopbar();
    wireVisibility();

    // Restore the tab before the session call so a #llm deep link never flashes
    // the platform panel, and the poller starts only once authentication lands.
    llmTabSwitch(tabFromLocation());
    restoreLoginForm();
    checkSession();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // ── Exported surface ──
  // Exactly two things leave this IIFE: the LLMConsole namespace and the inline
  // handlers the HTML file calls by name. Everything else stays private.
  window.LLMConsole = {
    init: init,
    showTab: llmTabSwitch,
    switchView: llmConsoleSwitchView,
    isAuthenticated: () => !!state.user,
  };
  window.llmTabSwitch = llmTabSwitch;
  window.llmConsoleLogin = llmConsoleLogin;
  window.llmConsoleLogout = llmConsoleLogout;
  window.llmConsoleTogglePwd = llmConsoleTogglePwd;
  window.llmConsoleSwitchView = llmConsoleSwitchView;
  window.llmConsoleSend = llmConsoleSend;

})();
