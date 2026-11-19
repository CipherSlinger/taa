// ── Host bar ──
//
// The machine the panel describes. Everything shown here comes from
// GET /api/host/status. Where that number was read is the mock's choice at
// startup: on this machine by default, or on the host named by -host-ssh, where
// the same /proc/meminfo and the same kubectl run over SSH. The server's
// `target` field says which, and the label beside the title shows it — a panel
// whose numbers came from somewhere other than its label is exactly the
// confusion that field prevents.
//
// The address field is the one value an operator can edit. It is detected once
// and then remembered per browser, because the detected address of a machine
// with several interfaces is often not the one the operator uses. Editing it
// only changes what is displayed and what the copy actions hand out: the mock
// addresses TAA from each instance's registration, never from this field.

const HOST_IP_STORAGE_KEY = 'pm.host.ip';
const HOST_NS_STORAGE_KEY = 'pm.host.namespace';
const HOST_POLL_MS = 5000;

let hostStatusLast = null;
let hostPodTableCollapsed = false;
let hostPollTimer = null;
// hostNamespace is the namespace the Pod table is filtered to. The table opens
// on `default`, because that is where the TAA and DCU test Pods live and the
// cluster-wide list is 27 rows of system Pods; an empty value means all, and the
// choice is remembered per browser so a reload reopens the same view.
const HOST_NS_DEFAULT = 'default';
let hostNamespace = HOST_NS_DEFAULT;

function hostStoreGet(key) {
  try {
    return localStorage.getItem(key);
  } catch (_) {
    return null;
  }
}

function hostStoreSet(key, value) {
  try {
    localStorage.setItem(key, value);
  } catch (_) {
    // A browser that refuses storage still gets the live values this session.
  }
}

// hostDisplayedIP is the address the bar shows: the operator's saved choice
// when there is one, otherwise the detected address.
function hostDisplayedIP() {
  const saved = (hostStoreGet(HOST_IP_STORAGE_KEY) || '').trim();
  if (saved) return saved;
  return (hostStatusLast && hostStatusLast.hostIp) || '';
}

function fmtBytes(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n) || n <= 0) return '—';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let value = n;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const digits = value >= 100 ? 0 : 1;
  return value.toFixed(digits) + ' ' + units[unit];
}

// fmtPodAge renders a Pod's age the way kubectl does: the largest unit that
// still reads as one number.
function fmtPodAge(seconds) {
  const s = Number(seconds);
  if (!Number.isFinite(s) || s <= 0) return '—';
  if (s < 60) return Math.floor(s) + 's';
  if (s < 3600) return Math.floor(s / 60) + 'm';
  if (s < 86400) return Math.floor(s / 3600) + 'h';
  return Math.floor(s / 86400) + 'd';
}

function renderHostStatus(status) {
  if (!status) return;
  const target = status.target || {};
  const targetLabel = document.getElementById('hostTargetLabel');
  if (targetLabel) {
    targetLabel.textContent = target.label || '';
    targetLabel.title = target.mode === 'ssh'
      ? '内存与 Pod 列表经 SSH 从 ' + (target.host || '') + ' 采集'
      : '内存与 Pod 列表在本机采集';
  }
  const ipInput = document.getElementById('hostIpInput');
  if (ipInput && document.activeElement !== ipInput) {
    const shown = hostDisplayedIP();
    if (shown) ipInput.value = shown;
  }
  const hint = document.getElementById('hostDetectedHint');
  if (hint) {
    const detected = status.hostIp || '';
    const others = (status.hostIps || []).filter((ip) => ip !== detected);
    const parts = [];
    if (detected) parts.push('检测到 ' + detected);
    if (others.length) parts.push('其它 ' + others.join(' / '));
    if (status.hostname) parts.push(status.hostname);
    hint.textContent = parts.join(' · ');
  }

  const memText = document.getElementById('hostMemoryText');
  const memPill = document.getElementById('hostMemoryPill');
  const memLabel = document.getElementById('hostMemoryLabel');
  const memBar = document.getElementById('hostMemoryBar');
  if (status.memoryError) {
    if (memText) memText.textContent = '读取失败';
    if (memPill) memPill.className = 'status-pill bad';
    if (memLabel) memLabel.textContent = '不可读';
    if (memBar) memBar.style.width = '0%';
    if (memText) memText.title = status.memoryError;
  } else if (status.memory && status.memory.totalBytes > 0) {
    const usedPercent = Math.max(0, Math.min(100, Number(status.memory.usedPercent) || 0));
    if (memText) {
      memText.textContent =
        fmtBytes(status.memory.availableBytes) + ' 可用 / 共 ' + fmtBytes(status.memory.totalBytes);
      memText.title = '已用 ' + usedPercent.toFixed(1) + '%：' + fmtBytes(status.memory.usedBytes);
    }
    if (memPill) {
      const level = usedPercent >= 90 ? 'bad' : usedPercent >= 75 ? 'pending' : 'ok';
      memPill.className = 'status-pill ' + level;
    }
    if (memLabel) memLabel.textContent = '已用 ' + usedPercent.toFixed(1) + '%';
    if (memBar) {
      memBar.style.width = usedPercent.toFixed(1) + '%';
      memBar.classList.toggle('complete', usedPercent >= 90);
    }
  }

  renderHostPods(status);
}

// renderHostNamespaces fills the filter from the cluster-wide counts. The
// selection is restored from the server's answer rather than from the local
// value, because the server resolves an unknown namespace back to "all".
function renderHostNamespaces(status) {
  const select = document.getElementById('hostPodNamespace');
  if (!select) return;
  const namespaces = Array.isArray(status.namespaces) ? status.namespaces : [];
  const current = status.namespace || '';

  const wanted = namespaces.map((ns) => ns.name).join('\n') + '\u0000' + current;
  if (select.dataset.signature !== wanted) {
    select.dataset.signature = wanted;
    while (select.options.length > 1) select.remove(1);
    namespaces.forEach((ns) => {
      const option = document.createElement('option');
      option.value = ns.name;
      option.textContent = ns.name + ' (' + ns.count + ')';
      select.appendChild(option);
    });
  }
  select.value = current;
  hostNamespace = current;
}

function renderHostPods(status) {
  const rows = document.getElementById('hostPodRows');
  const count = document.getElementById('hostPodCount');
  const errBox = document.getElementById('hostPodError');
  if (!rows) return;

  if (errBox) {
    if (status.podsError) {
      errBox.textContent = status.podsError;
      errBox.style.display = '';
    } else {
      errBox.style.display = 'none';
    }
  }

  renderHostNamespaces(status);

  const pods = Array.isArray(status.pods) ? status.pods : [];
  if (count) {
    const total = Number(status.podCount) || 0;
    if (status.podsError) {
      count.textContent = '不可用';
    } else if (status.namespace) {
      count.textContent = pods.length + ' / 全部 ' + total + ' 个';
    } else {
      count.textContent = total + ' 个';
    }
  }
  if (pods.length === 0) {
    rows.innerHTML = '';
    const tr = document.createElement('tr');
    tr.className = 'host-pod-empty';
    const td = document.createElement('td');
    td.colSpan = 7;
    td.textContent = status.podsError
      ? '无法读取 Pod 列表'
      : status.namespace
        ? '命名空间 ' + status.namespace + ' 中没有 Pod'
        : '宿主机上没有运行中的 Pod';
    tr.appendChild(td);
    rows.appendChild(tr);
    return;
  }

  const frag = document.createDocumentFragment();
  pods.forEach((pod) => {
    const tr = document.createElement('tr');

    const nameTd = document.createElement('td');
    const nameSpan = document.createElement('span');
    nameSpan.className = 'host-pod-name';
    nameSpan.textContent = pod.name || '';
    nameTd.appendChild(nameSpan);
    tr.appendChild(nameTd);

    const cells = [pod.namespace || '-', pod.phase || '-', pod.ready || '-', pod.podIp || '-'];
    cells.forEach((value) => {
      const td = document.createElement('td');
      td.textContent = value;
      tr.appendChild(td);
    });

    const restartTd = document.createElement('td');
    restartTd.textContent = String(pod.restarts || 0);
    if (Number(pod.restarts) > 0) restartTd.className = 'host-pod-restarts is-warn';
    tr.appendChild(restartTd);

    const ageTd = document.createElement('td');
    ageTd.textContent = fmtPodAge(pod.ageSeconds);
    tr.appendChild(ageTd);

    frag.appendChild(tr);
  });
  rows.innerHTML = '';
  rows.appendChild(frag);
}

function toggleHostPodTable() {
  hostPodTableCollapsed = !hostPodTableCollapsed;
  const wrap = document.getElementById('hostPodWrap');
  const btn = document.getElementById('hostPodToggleBtn');
  if (wrap) wrap.style.display = hostPodTableCollapsed ? 'none' : '';
  if (btn) btn.textContent = hostPodTableCollapsed ? '展开' : '收起';
}

// onHostIpEdit records the operator's address. An empty value clears the memory
// rather than saving "", so the field can go back to the detected address.
function onHostIpEdit(value) {
  const trimmed = String(value || '').trim();
  if (trimmed) hostStoreSet(HOST_IP_STORAGE_KEY, trimmed);
  else hostStoreSet(HOST_IP_STORAGE_KEY, '');
  if (!trimmed) {
    const detected = hostStatusLast && hostStatusLast.hostIp ? hostStatusLast.hostIp : '';
    const input = document.getElementById('hostIpInput');
    if (input && detected) input.value = detected;
  }
}

// onHostPodNamespaceChange records the operator's filter and repaints at once:
// the server filters, so the table cannot be updated from what is already on the
// page.
function onHostPodNamespaceChange(value) {
  hostNamespace = String(value || '').trim();
  hostStoreSet(HOST_NS_STORAGE_KEY, hostNamespace);
  refreshHostStatus();
}

async function refreshHostStatus() {
  try {
    const query = hostNamespace ? '?namespace=' + encodeURIComponent(hostNamespace) : '';
    const res = await fetch('/api/host/status' + query, { cache: 'no-store' });
    const payload = await res.json();
    if (!payload || payload.error !== 0) return;
    hostStatusLast = payload.result || {};
    renderHostStatus(hostStatusLast);
  } catch (_) {
    // A transient failure leaves the last render in place; the next poll
    // replaces it. The error row is only for what the mock itself reports.
  }
}

function initHostBar() {
  if (!document.getElementById('card-host')) return;
  const saved = (hostStoreGet(HOST_IP_STORAGE_KEY) || '').trim();
  const input = document.getElementById('hostIpInput');
  if (input && saved) input.value = saved;
  // A saved empty string is a real choice (全部命名空间); only the absence of a
  // saved value falls back to the default namespace.
  const savedNS = hostStoreGet(HOST_NS_STORAGE_KEY);
  hostNamespace = savedNS === null ? HOST_NS_DEFAULT : savedNS.trim();
  refreshHostStatus();
  if (hostPollTimer) clearInterval(hostPollTimer);
  hostPollTimer = setInterval(() => {
    if (!document.hidden) refreshHostStatus();
  }, HOST_POLL_MS);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initHostBar);
} else {
  initHostBar();
}