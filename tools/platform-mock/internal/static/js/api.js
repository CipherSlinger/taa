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
      const resp = await fetch('/api/dashboard/status');
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
    } catch (_) {}
  }
};
