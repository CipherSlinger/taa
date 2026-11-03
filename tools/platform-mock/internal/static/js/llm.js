// ── TEE-LLM instance panel ──
//
// The LLM is a separate instance kind: it reports in plaintext on /v1/llm/* and
// keeps its own state, so nothing here uses the ?dockerId= selection.

// Three missed heartbeats (30s each) mark the instance offline, matching the
// platform-side rule the LLM spec documents.
const LLM_OFFLINE_AFTER_MS = 90 * 1000;

let llmLogPaused = false;
let llmLogAutoScroll = true;
let lastLLMState = null;

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

function renderLLMStatus(payload) {
  lastLLMState = payload || null;
  const reg = (payload && payload.register) || {};
  const hb = (payload && payload.heartbeat) || {};

  let cls = 'pending';
  let label = '等待 TEE-LLM 注册';
  if (reg.received) {
    const lastHeartbeat = hb.receivedAt ? Date.parse(hb.receivedAt) : NaN;
    if (Number.isNaN(lastHeartbeat)) {
      label = '已注册，等待心跳';
    } else if (Date.now() - lastHeartbeat <= LLM_OFFLINE_AFTER_MS) {
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
    hbText.textContent = hb.receivedAt
      ? `心跳 ${hb.count || 0} 次 · ${llmRelativeTime(hb.receivedAt)}`
      : '';
  }

  const setText = (id, value) => {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  };
  setText('llmDockerId', reg.dockerId || '—');
  setText('llmVerified', reg.received ? (reg.verifiedPass ? '✓' : '✗') : '—');
  setText('llmAttestationSize', reg.received ? `${reg.attestationSize || 0} B` : '—');
  setText('llmRegisteredAt', reg.received ? llmTimeOfDay(reg.receivedAt) : '—');

  const pubKeyBtn = document.getElementById('llmPublicKeyBtn');
  if (pubKeyBtn) pubKeyBtn.disabled = !(reg.received && reg.taaPublicKey);
  const bodyBtn = document.getElementById('llmRegisterBodyBtn');
  if (bodyBtn) bodyBtn.disabled = !reg.received;

  renderLLMSources(payload && payload.sources, reg);
  renderLLMLogs(payload && payload.logs);
}

function renderLLMSources(sources, reg) {
  const box = document.getElementById('llmSourcesBox');
  const list = document.getElementById('llmSourcesList');
  const count = document.getElementById('llmSourcesCount');
  const items = Array.isArray(sources) ? sources : [];
  if (box) box.style.display = items.length ? '' : 'none';
  if (count) count.textContent = String(items.length);
  if (!list) return;

  const eventLabels = { register: '注册', heartbeat: '心跳', log: '日志' };
  const currentId = reg && reg.received ? reg.dockerId : '';
  list.innerHTML = items.map((src) => {
    const isCurrent = src.dockerId && src.dockerId === currentId;
    const tag = isCurrent
      ? '<span class="status-pill ok" style="font-size:11px; padding:1px 6px;">当前</span>'
      : '';
    const event = eventLabels[src.lastEvent] || src.lastEvent || '—';
    return `<div style="display:flex; align-items:center; gap:10px; padding:4px 8px; background:var(--panel-sub); border-radius:6px; flex-wrap:wrap;">
      <code style="min-width:160px;">${escapeHtml(src.dockerId || '')}</code>
      ${tag}
      <span class="muted">${escapeHtml(event)} · ${escapeHtml(llmRelativeTime(src.lastSeen))}</span>
    </div>`;
  }).join('');
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
    : '<div style="color:#6b7280; text-align:center; padding:16px 0;">暂无日志。(/v1/llm/log)</div>';

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

async function resetLLMStatus() {
  try {
    await fetch('/api/llm/reset', { method: 'POST' });
  } catch (_) {}
  if (typeof showToast === 'function') {
    showToast({ type: 'success', title: '已重置', message: 'TEE-LLM 注册、心跳、来源与日志已清空' });
  }
  refreshLLMStatus();
}

function openLLMRegisterBody() {
  if (!lastLLMState || !lastLLMState.register || !lastLLMState.register.received) {
    if (typeof showToast === 'function') {
      showToast({ type: 'warning', title: '提示', message: '暂无 TEE-LLM 注册报文' });
    }
    return;
  }
  recordInteraction('llmRegister', {
    title: 'TEE-LLM 平台注册详情',
    primaryLabel: '上报内容 (TEE-LLM 请求体)',
    secondaryLabel: '平台应答',
    primaryContent: lastLLMState.register,
    secondaryContent: { code: 0, msg: 'ok', result: { received: true } },
    endpoint: '/v1/llm/register',
  });
  openInteractionDrawer('llmRegister', 'primary');
}

function openLLMPublicKeyModal() {
  const modal = document.getElementById('llmPublicKeyModal');
  const field = document.getElementById('llmPublicKeyText');
  const key = lastLLMState && lastLLMState.register ? lastLLMState.register.taaPublicKey : '';
  if (!modal || !field || !key) {
    if (typeof showToast === 'function') {
      showToast({ type: 'warning', title: '提示', message: '暂无 TEE-LLM 注册公钥' });
    }
    return;
  }
  field.value = key;
  modal.classList.add('open');
  modal.setAttribute('aria-hidden', 'false');
}

function closeLLMPublicKeyModal() {
  const modal = document.getElementById('llmPublicKeyModal');
  if (!modal) return;
  modal.classList.remove('open');
  modal.setAttribute('aria-hidden', 'true');
}
