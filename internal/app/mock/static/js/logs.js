// ── Log Streaming Components (Model Log & TAA Log) ──

let modelLogPaused = false;
let taaLogPaused = false;

// ── Model Terminal Log ──
async function fetchModelLogs() {
  if (modelLogPaused) return;
  try {
    const res = await fetch('/api/modelLog/status', { cache: 'no-store' });
    const data = await res.json();
    const result = responseResult(data);
    if (!result) return;
    const entries = Array.isArray(result.entries) ? result.entries : [];
    const count = result.totalCount != null ? result.totalCount : entries.length;
    const lastSeq = result.lastSeq != null ? result.lastSeq : (entries.length ? entries[entries.length - 1].seq : 0);

    const countEl = document.getElementById('modelLogCount');
    if (countEl) countEl.textContent = `${count} 条日志`;
    const seqEl = document.getElementById('modelLogLastSeq');
    if (seqEl) seqEl.textContent = `最新 seq: ${lastSeq}`;

    const dot = document.getElementById('modelLogStatusDot');
    const statusText = document.getElementById('modelLogStatusText');
    if (entries.length > 0) {
      if (dot) dot.className = 'dot ok status-pill ok';
      if (statusText) statusText.textContent = '日志接收中';
    } else {
      if (dot) dot.className = 'dot status-pill pending';
      if (statusText) statusText.textContent = '等待日志上报...';
    }

    const output = document.getElementById('modelLogOutput');
    if (!output) return;

    if (entries.length === 0) {
      output.innerHTML = '<div style="color:#6b7280; text-align:center; padding:40px 0;">暂无模型终端日志上报。(/v1/taa/modelLog)</div>';
      return;
    }

    output.innerHTML = entries.map(e => {
      const seqStr = `<span style="color:#60a5fa; font-weight:600;">[seq=${e.seq}]</span>`;
      return `${seqStr} ${escapeHtml(e.message)}`;
    }).join('\n');

    if (!modelLogPaused) {
      output.scrollTop = output.scrollHeight;
    }
  } catch (e) {
    // Silently ignore fetch errors on poll
  }
}

function toggleModelLogPause() {
  modelLogPaused = !modelLogPaused;
  const btn = document.getElementById('modelLogPauseBtn');
  if (btn) {
    btn.textContent = modelLogPaused ? '继续' : '暂停';
    btn.className = modelLogPaused ? 'success' : 'secondary';
  }
}

async function clearModelLogs() {
  try {
    await fetch('/api/modelLog/reset', { method: 'POST' });
  } catch {}
  const output = document.getElementById('modelLogOutput');
  if (output) output.innerHTML = '';
  const countEl = document.getElementById('modelLogCount');
  if (countEl) countEl.textContent = '0 条日志';
  const seqEl = document.getElementById('modelLogLastSeq');
  if (seqEl) seqEl.textContent = '最新 seq: 0';
  const dot = document.getElementById('modelLogStatusDot');
  if (dot) dot.className = 'dot status-pill pending';
  const statusText = document.getElementById('modelLogStatusText');
  if (statusText) statusText.textContent = '等待日志上报...';
}

// ── TAA Runtime Log ──
async function fetchTaaLogs() {
  if (taaLogPaused) return;
  try {
    const res = await fetch('/api/taaLog/status', { cache: 'no-store' });
    const data = await res.json();
    const result = responseResult(data);
    if (!result) return;
    const entries = Array.isArray(result.entries) ? result.entries : [];
    const count = result.totalCount != null ? result.totalCount : entries.length;
    const lastSeq = result.lastSeq != null ? result.lastSeq : (entries.length ? entries[entries.length - 1].seq : 0);

    const countEl = document.getElementById('taaLogCount');
    if (countEl) countEl.textContent = `${count} 条日志`;
    const seqEl = document.getElementById('taaLogLastSeq');
    if (seqEl) seqEl.textContent = `最新 seq: ${lastSeq}`;

    const dot = document.getElementById('taaLogStatusDot');
    const statusText = document.getElementById('taaLogStatusText');
    if (entries.length > 0) {
      if (dot) dot.className = 'dot ok status-pill ok';
      if (statusText) statusText.textContent = '日志接收中';
    } else {
      if (dot) dot.className = 'dot status-pill pending';
      if (statusText) statusText.textContent = '等待日志上报...';
    }

    const output = document.getElementById('taaLogOutput');
    if (!output) return;

    if (entries.length === 0) {
      output.innerHTML = '<div style="color:#6b7280; text-align:center; padding:40px 0;">暂无 TAA 运行日志上报。(/v1/taa/taaLog)</div>';
      return;
    }

    output.innerHTML = entries.map(e => {
      const seqStr = `<span style="color:#60a5fa; font-weight:600;">[seq=${e.seq}]</span>`;
      return `${seqStr} ${escapeHtml(e.message)}`;
    }).join('\n');

    if (!taaLogPaused) {
      output.scrollTop = output.scrollHeight;
    }
  } catch (e) {
    // Silently ignore fetch errors on poll
  }
}

function toggleTaaLogPause() {
  taaLogPaused = !taaLogPaused;
  const btn = document.getElementById('taaLogPauseBtn');
  if (btn) {
    btn.textContent = taaLogPaused ? '继续' : '暂停';
    btn.className = taaLogPaused ? 'success' : 'secondary';
  }
}

async function clearTaaLogs() {
  try {
    await fetch('/api/taaLog/reset', { method: 'POST' });
  } catch {}
  const output = document.getElementById('taaLogOutput');
  if (output) output.innerHTML = '';
  const countEl = document.getElementById('taaLogCount');
  if (countEl) countEl.textContent = '0 条日志';
  const seqEl = document.getElementById('taaLogLastSeq');
  if (seqEl) seqEl.textContent = '最新 seq: 0';
  const dot = document.getElementById('taaLogStatusDot');
  if (dot) dot.className = 'dot status-pill pending';
  const statusText = document.getElementById('taaLogStatusText');
  if (statusText) statusText.textContent = '等待日志上报...';
}
