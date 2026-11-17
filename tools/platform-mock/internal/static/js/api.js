// ── Network API Utilities & PollingManager ──

// The address console calls are sent to. It has no input: the mock detects the
// TAA target from the registration and either routes through its own reverse
// proxy (location.origin + '/taa') or calls the service directly. The address
// itself is shown on each instance row.
let taaAddrCurrent = defaultTaaAddr();

// defaultTaaAddr is the direct-TAA fallback: the host this page was opened from
// rather than a hardcoded loopback, since the console is routinely opened from
// another machine.
function defaultTaaAddr() {
  return 'http://' + (location.hostname || '127.0.0.1') + ':6001';
}

function setTaaAddr(addr) {
  taaAddrCurrent = addr || '';
  // The target resolves asynchronously after the first status poll. The API
  // tester follows this value until the operator types an address of their own,
  // so it has to learn about the change rather than keep its startup fallback.
  window.dispatchEvent(new CustomEvent('taa-addr-change', { detail: { addr: taaAddrCurrent } }));
}

function getTaaAddr() {
  return (taaAddrCurrent || '').replace(/\/+$/, '');
}

// ── Instance selection ──
//
// Every instance-scoped /api/* call carries ?dockerId=. The selection is held
// in one module-level variable so polling functions keep their existing shape.
let currentInstanceDockerId = '';

function currentDockerId() {
  return currentInstanceDockerId;
}

function withDockerId(url) {
  const id = currentDockerId();
  if (!id) return url;
  const sep = url.indexOf('?') === -1 ? '?' : '&';
  return url + sep + 'dockerId=' + encodeURIComponent(id);
}

function mockFetch(url, opts) {
  return fetch(withDockerId(url), opts);
}

let instanceListSignature = null;
// instanceCache is the last /api/instances payload. renderInstanceList() reads
// it, so a selection change repaints the list without another request.
let instanceCache = [];
let instanceRenderedSelection = '';
// instanceKinds maps dockerId to the kind the mock derived from that instance's
// registration. It is refreshed with the list; the console mode reads it on
// selection so the panels follow the instance without another request.
let instanceKinds = {};
// instanceTargets maps dockerId to the direct TAA address that instance
// reported. The API tester needs it because a sealed envelope must go straight
// to TAA; through the mock's /taa proxy it would be sealed a second time.
let instanceTargets = {};

// instanceHealthState is the last health check each row produced. Health is an
// action, not a polled fact, so it is not part of /api/instances: the row shows
// what its own 检查连通性 learned, and 查看结果 exists only where that result is
// still the one `lastHealthData` holds.
const instanceHealthState = {};
let lastHealthOwner = '';

function recordInstanceHealth(id, tone, label, title) {
  if (!id) return;
  instanceHealthState[id] = {
    tone: tone === 'ok' || tone === 'bad' || tone === 'running' ? tone : 'pending',
    label: label || '未检查',
    title: title || '',
  };
  if (tone === 'ok' || tone === 'bad') lastHealthOwner = id;
  renderInstanceList();
}

function instanceHealthFor(id) {
  return instanceHealthState[id] || {
    tone: 'pending',
    label: '未检查',
    title: '尚未对该实例执行连通性检查',
  };
}

// INSTANCE_GROUPS is the fixed display order of the list. A kind the mock does
// not infer (a record that never registered) still gets a section rather than
// disappearing from the management view.
const INSTANCE_GROUPS = [
  { kind: 'tee', label: 'TEE 实例 · CSV 机密 VM' },
  { kind: 'fhe', label: 'FHE 实例 · GPU 宿主机' },
  { kind: '', label: '未识别类型' },
];

function instanceKindLabel(kind) {
  if (kind === 'tee') return 'TEE';
  if (kind === 'fhe') return 'FHE';
  return '';
}

// instanceConnectionState is the per-row connection badge. The mock does not
// probe instances, so the honest signal is what the platform itself knows: an
// accepted registration means the instance is connected, a report that the
// platform rejected is a failed registration, and silence is "never registered".
function instanceConnectionState(item) {
  if (item.accepted) return { label: '已连接', tone: 'ok', hint: '平台已接受该实例的注册' };
  if (item.received) return { label: '注册失败', tone: 'bad', hint: '实例已上报，但平台未接受' };
  return { label: '未注册', tone: 'pending', hint: '尚未收到该实例的注册请求' };
}

function instanceClock(at) {
  if (!at) return '';
  const d = new Date(at);
  if (isNaN(d.getTime())) return at;
  const pad = (n) => String(n).padStart(2, '0');
  return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
}

function setInstanceSelectorVisibility(show) {
  const list = document.getElementById('instanceList');
  if (list) list.style.display = show ? '' : 'none';
}

function notifyInstanceChange(id) {
  window.dispatchEvent(new CustomEvent('pm-instance-change', { detail: { dockerId: id } }));
}

function instanceWarning(message) {
  if (typeof showToast === 'function') {
    showToast({ type: 'warning', title: '提示', message: message });
    return;
  }
  alert(message);
}

function applyInstanceList(list, defaultId) {
  const container = document.getElementById('instanceList');
  if (!container) return;
  instanceCache = list;
  // The signature covers everything a row renders, so the poll only repaints
  // when the payload actually changed (and never mid-click otherwise).
  const signature = list.map((item) => [
    item.dockerId || '',
    item.accepted ? '1' : '0',
    item.received ? '1' : '0',
    item.kind || '',
    item.taaTarget || '',
    item.lastReportAt || '',
    item.default ? '1' : '0',
  ].join('|')).join(',') + '#' + (defaultId || '');
  const previous = currentInstanceDockerId;
  let next = previous;
  if (!list.some((item) => (item.dockerId || '') === next)) {
    next = defaultId || (list[0] && list[0].dockerId) || '';
  }
  currentInstanceDockerId = next;
  instanceKinds = {};
  instanceTargets = {};
  list.forEach((item) => {
    if (!item.dockerId) return;
    instanceKinds[item.dockerId] = item.kind || '';
    instanceTargets[item.dockerId] = item.taaTarget || '';
  });
  updateInstanceSummary(list);
  if (signature !== instanceListSignature || next !== instanceRenderedSelection) {
    instanceListSignature = signature;
    renderInstanceList();
  }
  applySelectedInstanceKind();
  if (previous !== next) notifyInstanceChange(next);
  setInstanceSelectorVisibility(list.length > 0);
}

function updateInstanceSummary(list) {
  const el = document.getElementById('instanceSummary');
  if (!el) return;
  if (!list.length) {
    el.textContent = '暂无已注册实例';
    return;
  }
  const connected = list.filter((item) => item.accepted).length;
  el.textContent = '共 ' + list.length + ' 个实例，' + connected + ' 个已连接';
}

// renderInstanceList paints one section per kind from instanceCache. Rows are
// built with DOM calls rather than innerHTML because a dockerId is host input:
// a registration can carry any string, and it must stay text.
function renderInstanceList() {
  const container = document.getElementById('instanceList');
  if (!container) return;
  container.textContent = '';
  if (!instanceCache.length) {
    const empty = document.createElement('div');
    empty.className = 'instance-empty';
    empty.textContent = '暂无已注册实例。TAA 启动后会向平台注册，列表每 5 秒刷新一次。';
    container.appendChild(empty);
    instanceRenderedSelection = '';
    return;
  }
  INSTANCE_GROUPS.forEach((group) => {
    const items = instanceCache.filter((item) => (item.kind || '') === group.kind);
    if (!items.length) return;
    const section = document.createElement('div');
    section.className = 'instance-group';
    const head = document.createElement('div');
    head.className = 'instance-group-head';
    const label = document.createElement('span');
    label.textContent = group.label;
    const count = document.createElement('span');
    count.className = 'instance-group-count';
    count.textContent = items.length + ' 个';
    head.appendChild(label);
    head.appendChild(count);
    section.appendChild(head);
    items.forEach((item) => section.appendChild(buildInstanceRow(item)));
    container.appendChild(section);
  });
  instanceRenderedSelection = currentInstanceDockerId;
}

// buildInstanceRow is one instance: a select button carrying its identity and
// connection state, plus actions bound to this dockerId only. The actions do
// not read the selection, so a click can never be sent to a neighbouring row.
function buildInstanceRow(item) {
  const id = item.dockerId || '';
  const selected = id === currentInstanceDockerId;
  const state = instanceConnectionState(item);
  const row = document.createElement('div');
  row.className = 'instance-row' + (selected ? ' selected' : '');
  row.dataset.dockerId = id;

  const main = document.createElement('button');
  main.type = 'button';
  main.className = 'instance-row-main';
  main.setAttribute('aria-pressed', selected ? 'true' : 'false');
  main.title = state.hint + (item.taaTarget ? '\nTAA 地址 ' + item.taaTarget : '');
  main.addEventListener('click', () => selectInstance(id));

  const dot = document.createElement('span');
  dot.className = 'instance-state-dot ' + state.tone;
  const name = document.createElement('span');
  name.className = 'instance-name';
  name.textContent = id || '(legacy)';
  main.appendChild(dot);
  main.appendChild(name);
  const kind = instanceKindLabel(item.kind);
  if (kind) {
    const tag = document.createElement('span');
    tag.className = 'instance-kind-tag';
    tag.textContent = kind;
    main.appendChild(tag);
  }
  if (item.default) {
    const tag = document.createElement('span');
    tag.className = 'instance-default-tag';
    tag.textContent = '默认';
    main.appendChild(tag);
  }
  // The two facts that used to sit in a detail row under the list: the address
  // the console posts to, and the outcome of the last health check.
  const target = document.createElement('span');
  target.className = 'instance-target';
  target.textContent = item.taaTarget ? 'TAA ' + item.taaTarget : 'TAA 地址未上报';
  if (item.taaTarget) target.title = 'TAA 服务地址 ' + item.taaTarget;
  main.appendChild(target);

  const health = instanceHealthFor(id);
  const healthChip = document.createElement('span');
  healthChip.className = 'instance-health status-pill ' + health.tone;
  const healthDot = document.createElement('span');
  healthDot.className = 'pill-dot';
  const healthText = document.createElement('span');
  healthText.textContent = '环境 ' + health.label;
  healthChip.appendChild(healthDot);
  healthChip.appendChild(healthText);
  if (health.title) healthChip.title = health.title;
  main.appendChild(healthChip);

  const stateText = document.createElement('span');
  stateText.className = 'instance-state-text ' + state.tone;
  stateText.textContent = state.label;
  main.appendChild(stateText);
  const meta = document.createElement('span');
  meta.className = 'instance-meta';
  const at = instanceClock(item.lastReportAt);
  meta.textContent = at ? '最近上报 ' + at : '无上报记录';
  if (item.taaTarget) meta.title = item.taaTarget;
  main.appendChild(meta);

  const actions = document.createElement('div');
  actions.className = 'instance-row-actions';
  actions.appendChild(instanceActionButton('公钥', () => openInstancePublicKey(id), !item.accepted, '查看该实例上报的 TAA 注册公钥'));
  actions.appendChild(instanceActionButton('注册返回', () => openInstanceRegisterBody(id), !item.received, '查看该实例的注册请求与平台返回'));
  actions.appendChild(instanceActionButton('检查连通性', () => runInstanceHealth(id), false, 'GET /v1/taa/health，结果写回该行的环境状态'));
  if (lastHealthOwner === id && typeof lastHealthData !== 'undefined' && lastHealthData) {
    actions.appendChild(instanceActionButton('查看结果', () => { selectInstance(id); openHealthResultModal(); }, false, '查看该实例最近一次连通性检查的返回'));
  }
  if (item.kind === 'tee') {
    actions.appendChild(instanceActionButton('获取证明报告', () => runInstanceAttestation(id), false, '获取该实例的 CSV 远程证明报告'));
    // The report blob is one value in the page, so these two only exist on the
    // row that produced it.
    if (typeof _lastAttestationOwner !== 'undefined' && _lastAttestationOwner === id) {
      actions.appendChild(instanceActionButton('保存报告', () => saveAttestationReport(), false, '保存刚获取的证明报告'));
      actions.appendChild(instanceActionButton('查看返回', () => openInteractionModal('attestation', 'primary'), false, '查看证明接口的请求与返回'));
    }
  }
  const del = instanceActionButton('删除', () => deleteInstance(id), false, '删除该实例的本地记录（Pod 已删除后清理）');
  del.classList.add('danger');
  actions.appendChild(del);

  row.appendChild(main);
  row.appendChild(actions);
  return row;
}

function instanceActionButton(label, handler, disabled, title) {
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'secondary btn-sm';
  btn.textContent = label;
  btn.disabled = !!disabled;
  if (title) btn.title = title;
  btn.addEventListener('click', handler);
  return btn;
}

// selectInstance moves the detail view (address, registration pill, health and
// the flow panels) to one instance. A row action selects first so the request
// it sends is addressed to the row the operator clicked.
function selectInstance(id) {
  if (!id) return;
  if (id === currentInstanceDockerId) {
    renderInstanceList();
    return;
  }
  currentInstanceDockerId = id;
  applySelectedInstanceKind();
  renderInstanceList();
  notifyInstanceChange(id);
  refreshInstancePanels();
}

// fetchInstanceRegister reads one instance's registration without moving the
// selection: the list buttons act on their own row.
async function fetchInstanceRegister(id) {
  const res = await fetch('/api/dashboard/status?dockerId=' + encodeURIComponent(id), { cache: 'no-store' });
  const data = await res.json().catch(() => ({}));
  const payload = (data && data.result) || {};
  return payload.register || {};
}

async function openInstancePublicKey(id) {
  let reg = null;
  try {
    reg = await fetchInstanceRegister(id);
  } catch (_) {
    instanceWarning('读取实例 ' + id + ' 的注册信息失败');
    return;
  }
  const key = String((reg && reg.taaPublicKey) || '').trim();
  if (!key) {
    instanceWarning('实例 ' + id + ' 尚未上报 TAA 注册公钥');
    return;
  }
  openTaaPublicKeyModal(key, id);
}

async function openInstanceRegisterBody(id) {
  let reg = null;
  try {
    reg = await fetchInstanceRegister(id);
  } catch (_) {
    instanceWarning('读取实例 ' + id + ' 的注册信息失败');
    return;
  }
  if (!reg || !reg.received) {
    instanceWarning('实例 ' + id + ' 尚未上报注册请求');
    return;
  }
  openRegisterBodyModal(reg, id);
}

// runInstanceAttestation switches the target to the clicked row before the
// request, because taaFetch reads the selected instance's address.
async function runInstanceAttestation(id) {
  selectInstance(id);
  try {
    if (typeof detectTAAProxy === 'function') await detectTAAProxy();
    await testGetAttestation();
  } finally {
    renderInstanceList();
  }
}

// runInstanceHealth does the same for the health check: the result is written
// into that row's 环境状态 chip, where the row's own 查看结果 then reads it.
async function runInstanceHealth(id) {
  selectInstance(id);
  try {
    if (typeof detectTAAProxy === 'function') await detectTAAProxy();
    await testHealth();
  } finally {
    renderInstanceList();
  }
}


// applySelectedInstanceKind drives the panel set from the selected instance.
function applySelectedInstanceKind() {
  if (typeof applyConsoleKind === 'function') {
    applyConsoleKind(instanceKinds[currentInstanceDockerId]);
  }
}

let instancesInFlight = false;

async function loadInstances() {
  if (instancesInFlight || document.hidden) return;
  instancesInFlight = true;
  try {
    const res = await fetch('/api/instances', { cache: 'no-store' });
    const payload = await res.json();
    const result = (payload && payload.result) || {};
    applyInstanceList(result.instances || [], result.defaultDockerId || '');
    maybeAutoDetectTAAAddr(result);
  } catch (_) {
    // Ignore transient errors; the next poll retries.
  } finally {
    instancesInFlight = false;
  }
}

// maybeAutoDetectTAAAddr re-detects the target as soon as the selected instance
// reports one. The instance list is polled, so a registration that lands while
// the page is open is picked up without a reload; without this the address kept
// the fallback host:6001 page load produced and every call failed until the
// operator reloaded the console.
function maybeAutoDetectTAAAddr(result) {
  if (typeof detectTAAProxy !== 'function') return;
  // Already proxied: detection would only repeat what is in force.
  if (getTaaAddr() === location.origin + '/taa') return;
  const list = (result && result.instances) || [];
  const id = currentDockerId() || (result && result.defaultDockerId) || '';
  const current = list.find((item) => item.dockerId === id)
    || list.find((item) => item.default)
    || null;
  if (!current || !current.taaTarget) return;
  detectTAAProxy();
}

function initInstanceSelector() {
  loadInstances();
  setInterval(loadInstances, 5000);
}

// refreshInstancePanels re-reads every instance-scoped panel. It is shared by
// the selector's change handler and by deletion, where the selection moves to
// the new default without a change event.
function refreshInstancePanels() {
  // A paused panel skips its fetch, so clear the flags before refreshing.
  if (typeof resetLogPauseForInstanceChange === 'function') resetLogPauseForInstanceChange();
  if (typeof refreshStatus === 'function') refreshStatus();
  if (typeof refreshReportResStatus === 'function') refreshReportResStatus();
  if (typeof refreshReportModelImportStatus === 'function') refreshReportModelImportStatus();
  if (typeof refreshReportAuditStatus === 'function') refreshReportAuditStatus();
  if (typeof refreshReportProgress === 'function') refreshReportProgress();
  if (typeof refreshDashboardStatus === 'function') refreshDashboardStatus();
  if (typeof fetchModelLogs === 'function') fetchModelLogs();
  if (typeof fetchTaaLogs === 'function') fetchTaaLogs();
  // The selected instance decides the target, so the pill follows it.
  if (typeof detectTAAProxy === 'function') {
    detectTAAProxy();
  }
}

// deleteInstance removes one instance's local records after its Pod is gone. A
// deleted Pod sends nothing, so without this the list would keep offering an
// instance that can never answer again.
async function deleteInstance(id) {
  if (!id) return;
  if (!confirm('删除实例 ' + id + ' 的本地记录？\n这不会影响 Pod，只清理平台模拟器保存的注册与上报数据。')) {
    return;
  }
  try {
    const res = await fetch('/api/instances/delete?dockerId=' + encodeURIComponent(id), { method: 'POST' });
    const data = await res.json().catch(() => ({}));
    if (res.status !== 200 || data.error !== 0) {
      alert('删除失败: ' + (data.msg || 'HTTP ' + res.status));
      return;
    }
    // The selection itself must move to whatever remains before the refreshes
    // run, and the list signature is reset so the rows are rebuilt even if
    // another poll is already in flight.
    if (id === currentInstanceDockerId) currentInstanceDockerId = '';
    instanceListSignature = null;
    await loadInstances();
    refreshInstancePanels();
  } catch (err) {
    alert('删除失败: ' + err.message);
  }
}

// deleteSelectedInstance survives as the console's instance-agnostic entry
// point; the row buttons call deleteInstance(id) directly.
function deleteSelectedInstance() {
  return deleteInstance(currentDockerId());
}

function formatResp(r) {
  return JSON.stringify(r, null, 2);
}

function responseResult(data) {
  return data && data.result !== undefined ? data.result : data;
}

function formatJSONText(raw) {
  if (raw == null) return '';
  if (typeof raw === 'object') return JSON.stringify(raw, null, 2);
  try {
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch (_) {
    return String(raw);
  }
}

function parseJSONMaybe(raw) {
  if (typeof raw !== 'string') return raw;
  const trimmed = raw.trim();
  if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
    try {
      return JSON.parse(trimmed);
    } catch (_) {
      return raw;
    }
  }
  return raw;
}

function isAbortLikeError(err) {
  if (!err) return false;
  if (err.name === 'AbortError') return true;
  const msg = String(err.message || err).toLowerCase();
  return msg.includes('aborted') || msg.includes('abort') || msg.includes('timeout');
}

function downloadBlob(blob, filename, revokeDelayMs = 1000) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), revokeDelayMs);
}

function taaFetch(endpoint, body, timeoutMs = 10000) {
  const target = getTaaAddr();
  if (!target) {
    return Promise.reject(new Error('TAA 服务地址未配置'));
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let url = target + endpoint;
  if (target.endsWith('/taa')) {
    url = withDockerId(url);
  }
  return fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: typeof body === 'string' ? body : JSON.stringify(body),
    signal: controller.signal,
  }).finally(() => clearTimeout(timer));
}

async function postToTAA(endpoint, body, timeoutMs = 10000) {
  const resp = await taaFetch(endpoint, body, timeoutMs);
  const text = await resp.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch (_) {
    data = text;
  }
  return { ok: resp.ok, status: resp.status, data };
}

// decodeHeaderFilename re-interprets a response header value as UTF-8. Header
// values are decoded as latin1 by fetch, so a non-ASCII filename written by the
// server arrives as one char per raw byte. Strings that already carry real
// Unicode code points are returned untouched.
function decodeHeaderFilename(raw) {
  if (!raw) return '';
  for (let i = 0; i < raw.length; i++) {
    if (raw.charCodeAt(i) > 0xff) return raw;
  }
  try {
    const bytes = Uint8Array.from(raw, ch => ch.charCodeAt(0));
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (_) {
    return raw;
  }
}

// parseContentDispositionFilename extracts the filename from a
// Content-Disposition header, preferring the RFC 5987 filename* form.
function parseContentDispositionFilename(header) {
  if (!header) return '';

  const star = /filename\*\s*=\s*([^;]+)/i.exec(header);
  if (star) {
    const value = star[1].trim().replace(/^["']|["']$/g, '');
    const encoded = value.includes("''") ? value.slice(value.indexOf("''") + 2) : value;
    try {
      return decodeURIComponent(encoded);
    } catch (_) {
      return encoded;
    }
  }

  const plain = /filename\s*=\s*(?:"([^"]*)"|([^;]*))/i.exec(header);
  if (!plain) return '';
  return decodeHeaderFilename((plain[1] !== undefined ? plain[1] : plain[2] || '').trim());
}

async function postToTAAFile(endpoint, body, timeoutMs = 120000) {
  const resp = await taaFetch(endpoint, body, timeoutMs);
  if (!resp.ok) {
    const text = await resp.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch (_) {
      data = text;
    }
    return { ok: false, status: resp.status, data, blob: null, filename: '', encrypted: false };
  }
  const blob = await resp.blob();
  return {
    ok: true,
    status: resp.status,
    data: null,
    blob,
    filename: parseContentDispositionFilename(resp.headers.get('Content-Disposition')),
    encrypted: (resp.headers.get('X-TAA-Encrypted') || '').trim().toLowerCase() === 'true',
  };
}

// ── PollingManager with Page Visibility API ──

const PollingManager = {
  fastTimer: null,
  mediumTimer: null,
  fastIntervalMs: 1500,
  mediumIntervalMs: 2000,
  isPaused: false,

  start() {
    this.resume();
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        this.pause();
      } else {
        this.resumeAndSync();
      }
    });
  },

  pause() {
    this.isPaused = true;
    if (this.fastTimer) {
      clearInterval(this.fastTimer);
      this.fastTimer = null;
    }
    if (this.mediumTimer) {
      clearInterval(this.mediumTimer);
      this.mediumTimer = null;
    }
  },

  resume() {
    if (this.fastTimer || this.mediumTimer) return;
    this.isPaused = false;
    this.fastTimer = setInterval(() => this.pollFastTier(), this.fastIntervalMs);
    this.mediumTimer = setInterval(() => this.pollMediumTier(), this.mediumIntervalMs);
  },

  async resumeAndSync() {
    this.resume();
    // Immediate sync on returning to tab
    await Promise.allSettled([
      this.pollFastTier(),
      this.pollMediumTier(),
    ]);
  },

  async pollFastTier() {
    if (this.isPaused) return;
    try {
      const resp = await mockFetch('/api/dashboard/status');
      if (!resp.ok) return;
      const data = await resp.json();
      if (data && data.error === 0 && data.result) {
        const res = data.result;
        if (typeof syncStepperState === 'function') {
          syncStepperState(res);
        }
        if (res.register && typeof renderRegister === 'function') {
          renderRegister(res.register);
        }
        if (res.modelImport && typeof renderReportModelImport === 'function') {
          renderReportModelImport(res.modelImport);
        }
        if (res.audit && typeof renderReportAudit === 'function') {
          renderReportAudit(res.audit);
        }
        if (res.progress && typeof renderReportProgress === 'function') {
          renderReportProgress(res.progress);
        }
      }
    } catch (_) {
      // Ignore background network polling errors
    }
  },

  async pollMediumTier() {
    if (this.isPaused) return;
    try {
      if (typeof refreshReportResStatus === 'function') {
        refreshReportResStatus();
      }
      if (typeof fetchModelLogs === 'function') {
        fetchModelLogs();
      }
      if (typeof fetchTaaLogs === 'function') {
        fetchTaaLogs();
      }
      if (typeof refreshLLMStatus === 'function') {
        refreshLLMStatus();
      }
    } catch (_) {}
  }
};
