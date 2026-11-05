// ── Network API Utilities & PollingManager ──

// The address console calls are sent to. It has no input: the mock detects the
// TAA target from the registration and either routes through its own reverse
// proxy (location.origin + '/taa') or calls the service directly. The pill in
// the platform-registration card shows which one is in force.
let taaAddrCurrent = defaultTaaAddr();

// defaultTaaAddr is the direct-TAA fallback: the host this page was opened from
// rather than a hardcoded loopback, since the console is routinely opened from
// another machine.
function defaultTaaAddr() {
  return 'http://' + (location.hostname || '127.0.0.1') + ':6001';
}

function setTaaAddr(addr) {
  taaAddrCurrent = addr || '';
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
// instanceKinds maps dockerId to the kind the mock derived from that instance's
// registration. It is refreshed with the list; the console mode reads it on
// selection so the panels follow the instance without another request.
let instanceKinds = {};

function instanceKindLabel(kind) {
  if (kind === 'tee') return 'TEE';
  if (kind === 'fhe') return 'FHE';
  return '';
}

function setInstanceSelectorVisibility(show) {
  document.getElementById('instanceSelect').style.display = show ? '' : 'none';
  const label = document.getElementById('instanceSelectLabel');
  if (label) label.style.display = show ? '' : 'none';
  const del = document.getElementById('instanceDeleteBtn');
  if (del) del.style.display = show ? '' : 'none';
}

function applyInstanceList(list, defaultId) {
  const sel = document.getElementById('instanceSelect');
  if (!sel) return;
  // Rebuilding identical options closes an open dropdown, so only touch the DOM
  // when the instance set, a kind or the default actually changed. The kind is
  // part of the signature because a re-registration can change it while the
  // dockerId stays the same.
  const signature = list.map((item) => (item.dockerId || '') + '|' + (item.accepted ? '1' : '0') + '|' + (item.kind || '')).join(',') + '#' + (defaultId || '');
  if (signature !== instanceListSignature) {
    instanceListSignature = signature;
    instanceKinds = {};
    const previous = sel.value || currentInstanceDockerId;
    sel.innerHTML = '';
    list.forEach((item) => {
      const opt = document.createElement('option');
      opt.value = item.dockerId || '';
      const name = item.dockerId || '(legacy)';
      const kind = instanceKindLabel(item.kind);
      opt.textContent = (item.accepted ? name : name + ' (未注册)') + (kind ? ' · ' + kind : '');
      sel.appendChild(opt);
      if (item.dockerId) instanceKinds[item.dockerId] = item.kind || '';
    });
    if (previous && list.some((item) => (item.dockerId || '') === previous)) {
      sel.value = previous;
    } else {
      sel.value = defaultId || '';
    }
  } else if (!sel.value) {
    sel.value = defaultId || '';
  }
  currentInstanceDockerId = sel.value;
  applySelectedInstanceKind();
  setInstanceSelectorVisibility(list.length > 0);
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
  const sel = document.getElementById('instanceSelect');
  if (sel) {
    sel.addEventListener('change', () => {
      currentInstanceDockerId = sel.value;
      // The selected instance's kind decides which panels apply, before the
      // refreshes below run.
      applySelectedInstanceKind();
      refreshInstancePanels();
    });
  }
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

// deleteSelectedInstance removes the selected instance's local records after
// its Pod is gone. A deleted Pod sends nothing, so without this the selector
// would keep offering an instance that can never answer again.
async function deleteSelectedInstance() {
  const id = currentDockerId();
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
    // run, and the list signature is reset so the options are rebuilt even if
    // another poll is already in flight.
    currentInstanceDockerId = '';
    instanceListSignature = null;
    await loadInstances();
    refreshInstancePanels();
  } catch (err) {
    alert('删除失败: ' + err.message);
  }
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
