// ── Network API Utilities & PollingManager ──

function getTaaAddr() {
  const el = document.getElementById('taaAddr');
  return el ? el.value.replace(/\/+$/, '') : '';
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
  return fetch(target + endpoint, {
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
    return { ok: false, status: resp.status, data, blob: null };
  }
  const blob = await resp.blob();
  return { ok: true, status: resp.status, data: null, blob };
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
      const resp = await fetch('/api/dashboard/status');
      if (!resp.ok) return;
      const data = await resp.json();
      if (data && data.error === 0 && data.result) {
        const res = data.result;
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
    } catch (_) {}
  }
};
