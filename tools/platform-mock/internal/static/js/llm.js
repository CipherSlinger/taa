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
// llmLastAddress is the instance address the last status render saw. The
// attestation drawer uses it to name the endpoint it came from.
let llmLastAddress = '';

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
  llmLastAddress = state.address || '';
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

  renderLLMLogs(payload && payload.logs);
}

// openLLMAttestation shows one fetched report in the shared drawer. The report
// is a snapshot the poller took when the operator asked, not panel state: it
// only changes when the instance restarts, so it is displayed in full and then
// left alone. attestationValues is a JSON string in the envelope; it is parsed
// before display so the drawer can nest it instead of escaping the whole blob.
function openLLMAttestation(att) {
  const values = (typeof parseJSONRecursively === 'function')
    ? parseJSONRecursively(att.attestationValues)
    : att.attestationValues;
  const requestID = att.requestId || '';
  const report = {
    requestId: requestID,
    verifiedPass: !!att.verifiedPass,
    attestationSize: att.attestationSize || 0,
    fetchedAt: att.fetchedAt || '',
    attestationValues: values || '',
    attestationBase64: att.attestationBase64 || '',
  };
  if (att.error) report.error = att.error;
  const endpoint = '/v1/llm/getAttestation';
  // The drawer's cURL preview resolves the address from the selected TAA
  // instance, which is the wrong endpoint here. Naming the polled LLM address
  // directly keeps the preview honest; without one the button stays hidden
  // rather than pointing a curl at a TAA instance.
  const interaction = {
    title: 'TEE-LLM 远程证明报告（来自实例，未校验）' + ' (' + endpoint + ')',
    primaryLabel: '证明报告',
    secondaryLabel: '请求体',
    primaryContent: report,
    secondaryContent: { requestId: requestID },
    reqBody: { requestId: requestID },
    respBody: report,
    statusCode: 200,
  };
  if (llmLastAddress) interaction.url = llmLastAddress.replace(/\/+$/, '') + endpoint;
  recordInteraction('llmAttestation', interaction);
  openInteractionDrawer('llmAttestation', 'primary');
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
    btn.className = llmLogPaused ? 'success btn-sm' : 'secondary btn-sm';
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
  // A filled field sends that sinceSeq verbatim, which is how the log interface is
  // exercised at an arbitrary position; empty means the stored read position.
  const seqInput = document.getElementById('llmSinceSeq');
  const raw = seqInput ? seqInput.value.trim() : '';
  const opts = { method: 'POST' };
  if (raw !== '') {
    if (!/^\d+$/.test(raw)) {
      if (typeof showToast === 'function') {
        showToast({ type: 'warning', title: 'sinceSeq 无效', message: '请填写非负整数，或留空自动拉取' });
      }
      return;
    }
    opts.headers = { 'Content-Type': 'application/json' };
    opts.body = JSON.stringify({ sinceSeq: Number(raw) });
  }
  try {
    await fetch('/api/llm/poll', opts);
  } catch (_) {
    // refresh below renders whatever the poll managed to record
  }
  refreshLLMStatus();
}

async function fetchLLMAttestation() {
  let report = null;
  try {
    const res = await fetch('/api/llm/attestation', { method: 'POST' });
    const data = await res.json();
    if (data && data.error) {
      if (typeof showToast === 'function') {
        showToast({ type: 'warning', title: '获取失败', message: data.msg || '实例未应答' });
      }
    } else {
      report = responseResult(data);
    }
  } catch (_) {
    if (typeof showToast === 'function') {
      showToast({ type: 'warning', title: '获取失败', message: '请求未完成' });
    }
  }
  // The panel keeps no copy of the report: the drawer is where it is read, and
  // the poller's snapshot only matters for the next 获取证明报告 click. The
  // refresh is awaited so the drawer is titled with the address this fetch used.
  await refreshLLMStatus();
  if (report && report.fetchedAt) openLLMAttestation(report);
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
