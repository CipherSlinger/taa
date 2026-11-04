// ── TEE-LLM instance panel ──
//
// The LLM never reports out: the mock polls it on the plaintext platform port
// and this panel renders what the poller learned. Everything below therefore
// describes a platform observation (and when it was taken), never a self-report.

// How many poll intervals without a successful heartbeat before the panel calls
// the instance offline. The interval itself comes from the status response, so
// a deployment that changed LLM_POLL_SECONDS does not silently change the rule.
const LLM_OFFLINE_AFTER_POLLS = 3;

let llmLogPaused = false;
let llmLogAutoScroll = true;

function llmRelativeTime(iso) {
  if (!iso) return '';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '';
  const diff = Date.now() - t;
  if (diff < 1000) return '刚刚';
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s 前`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m 前`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h 前`;
  return `${Math.floor(h / 24)}d 前`;
}

function llmTimeOfDay(iso) {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '—';
  return new Date(t).toLocaleTimeString('zh-CN', { hour12: false });
}

function llmDuration(seconds) {
  const s = Number(seconds) || 0;
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

function renderLLMStatus(payload) {
  const state = (payload && payload.state) || {};
  const pollSeconds = Number(payload && payload.pollSeconds) || 10;
  const offlineAfterMs = pollSeconds * 1000 * LLM_OFFLINE_AFTER_POLLS;

  let cls = 'pending';
  let label = '未发现 TEE-LLM';
  if (state.address) {
    const lastHeartbeat = state.lastHeartbeatAt ? Date.parse(state.lastHeartbeatAt) : NaN;
    if (state.reachable && !Number.isNaN(lastHeartbeat) && Date.now() - lastHeartbeat <= offlineAfterMs) {
      cls = 'ok';
      label = '在线';
    } else {
      cls = 'bad';
      label = '离线';
    }
  }

  const dot = document.getElementById('llmStatusDot');
  if (dot) dot.className = `dot pill-dot ${cls}`;
  const pill = document.getElementById('llmStatusPill');
  if (pill) pill.className = `status-pill ${cls}`;
  const statusText = document.getElementById('llmStatusText');
  if (statusText) statusText.textContent = label;

  const hbText = document.getElementById('llmHeartbeatText');
  if (hbText) {
    hbText.textContent = state.lastHeartbeatAt
      ? `心跳 ${state.heartbeats || 0} 次 · ${llmRelativeTime(state.lastHeartbeatAt)}（每 ${pollSeconds}s 轮询）`
      : `每 ${pollSeconds}s 轮询`;
  }

  const setText = (id, value) => {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  };
  setText('llmAddress', state.address || '—');
  // The instance id changes exactly when the instance's process starts, so the
  // panel shows it as reported rather than inferring a run from uptime.
  setText('llmDockerId', state.dockerId || '—');
  setText('llmModel', state.model || '—');
  setText('llmUptime', state.address && state.reachable ? llmDuration(state.uptimeSeconds) : '—');
  setText('llmLastPoll', state.lastPollAt ? llmTimeOfDay(state.lastPollAt) : '—');
  setText('llmLogCursor', `${state.logCursor || 0}${state.logDropped ? '（有丢弃）' : ''}`);

  const errEl = document.getElementById('llmLastError');
  if (errEl) {
    errEl.textContent = state.lastError || '';
    errEl.style.display = state.lastError ? '' : 'none';
  }

  renderLLMAttestation(state.attestation);
  renderLLMLogs(payload && payload.logs);
}

function renderLLMAttestation(att) {
  const box = document.getElementById('llmAttestationBox');
  if (!box) return;
  if (!att || !att.fetchedAt) {
    box.innerHTML = '<span class="muted" style="font-size:12.5px;">尚未拉取。点击「获取证明报告」向实例发起一次调用。</span>';
    return;
  }
  const verified = att.verifiedPass ? '✓ 自检通过' : '✗ 自检失败';
  const err = att.error ? `<div style="color:#dc2626; margin-top:6px;">${escapeHtml(att.error)}</div>` : '';
  box.innerHTML = `
    <div style="display:flex; gap:18px; flex-wrap:wrap; font-size:13px;">
      <span>requestId: <code>${escapeHtml(att.requestId || '—')}</code></span>
      <span>${verified}</span>
      <span>报告: ${att.attestationSize || 0} B</span>
      <span>拉取于: ${llmTimeOfDay(att.fetchedAt)}</span>
    </div>
    <pre style="margin:8px 0 0; max-height:140px; overflow:auto; background:var(--panel-sub); border:1px solid var(--line); border-radius:8px; padding:8px; font-size:12px;">${escapeHtml(att.attestationValues || '—')}</pre>
    ${err}`;
}

function renderLLMLogEntry(entry) {
  const msg = escapeHtml(entry.message || '');
  return `<div class="log-row" data-seq="${entry.seq}"><span class="log-seq" style="color:#60a5fa; font-weight:600; margin-right:6px;">[seq=${entry.seq}]</span><span class="log-msg">${msg}</span></div>`;
}

function renderLLMLogs(logs) {
  const out = document.getElementById('llmLogOutput');
  const countEl = document.getElementById('llmLogCount');
  if (!out) return;

  const entries = logs && Array.isArray(logs.entries) ? logs.entries : [];
  const total = logs && logs.totalCount != null ? logs.totalCount : entries.length;
  if (countEl) countEl.textContent = `${total} 条日志`;

  if (llmLogPaused) return;

  out.innerHTML = entries.length
    ? entries.map(renderLLMLogEntry).join('')
    : '<div style="color:#6b7280; text-align:center; padding:16px 0;">暂无日志。mock 尚未拉到 /v1/llm/log 的内容。</div>';

  if (llmLogAutoScroll) out.scrollTop = out.scrollHeight;
}

function toggleLLMLogPause() {
  llmLogPaused = !llmLogPaused;
  const btn = document.getElementById('llmLogPauseBtn');
  if (btn) {
    btn.textContent = llmLogPaused ? '继续' : '暂停';
    btn.className = llmLogPaused ? 'success' : 'secondary';
  }
}

function initLLMPanel() {
  const out = document.getElementById('llmLogOutput');
  if (!out) return;
  out.addEventListener('scroll', () => {
    llmLogAutoScroll = out.scrollHeight - out.scrollTop - out.clientHeight <= 40;
  });
}

async function refreshLLMStatus() {
  try {
    const res = await fetch('/api/llm/status', { cache: 'no-store' });
    const data = await res.json();
    renderLLMStatus(responseResult(data));
  } catch (_) {
    // Background poll: a transient failure leaves the last render in place.
  }
}

async function pollLLMNow() {
  try {
    await fetch('/api/llm/poll', { method: 'POST' });
  } catch (_) {
    // refresh below renders whatever the poll managed to record
  }
  refreshLLMStatus();
}

async function fetchLLMAttestation() {
  try {
    const res = await fetch('/api/llm/attestation', { method: 'POST' });
    const data = await res.json();
    if (data && data.error) {
      if (typeof showToast === 'function') {
        showToast({ type: 'warning', title: '获取失败', message: data.msg || '实例未应答' });
      }
    } else if (typeof showToast === 'function') {
      showToast({ type: 'success', title: '已拉取', message: '远程证明报告来自实例，未做校验' });
    }
  } catch (_) {
    if (typeof showToast === 'function') {
      showToast({ type: 'warning', title: '获取失败', message: '请求未完成' });
    }
  }
  refreshLLMStatus();
}

async function clearLLMLogs() {
  try {
    const res = await fetch('/api/llm/logs/clear', { method: 'POST' });
    const data = await res.json();
    const cleared = data && data.result ? data.result.cleared : 0;
    if (typeof showToast === 'function') {
      showToast({ type: 'success', title: '已清空', message: `已清空 ${cleared} 条日志` });
    }
  } catch (_) {
    if (typeof showToast === 'function') {
      showToast({ type: 'warning', title: '清空失败', message: '请求未完成' });
    }
  }
  refreshLLMStatus();
}

async function resetLLMStatus() {
  try {
    await fetch('/api/llm/reset', { method: 'POST' });
  } catch (_) {}
  if (typeof showToast === 'function') {
    showToast({ type: 'success', title: '已重置', message: 'TEE-LLM 轮询状态与日志已清空' });
  }
  refreshLLMStatus();
}
