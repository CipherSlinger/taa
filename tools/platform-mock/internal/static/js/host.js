// ── Host bar ──
//
// The machine the panel describes. Everything shown here comes from
// GET /api/host/status. Which machine that is can be changed from this bar:
// filling in IP / 用户 / 密码 and pressing 连接 posts them to
// /api/host/target, and the mock then reads /proc/meminfo and runs kubectl on
// that host over SSH. 本机 switches back. The server's `target` field says
// which machine answered, and the label beside the title shows it — a panel
// whose numbers came from somewhere other than its label is exactly the
// confusion that field prevents.
//
// The IP and user fields are remembered per browser; the password is not
// stored anywhere on this side, and the mock keeps it only in memory for as
// long as that connection is the active one.
//
// Editing the address no longer changes anything displayed by itself: it is the
// destination the 连接 button dials. How the mock addresses TAA is unrelated —
// that stays derived from each instance's registration.

const HOST_IP_STORAGE_KEY = 'pm.host.ip';
const HOST_USER_STORAGE_KEY = 'pm.host.user';
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

// hostTargetParts splits a target's "user@host" into the two fields.
function hostTargetParts(target) {
  const raw = String((target && target.host) || '');
  const at = raw.lastIndexOf('@');
  if (at < 0) return { user: '', host: raw };
  return { user: raw.slice(0, at), host: raw.slice(at + 1) };
}

// hostDestinationShown is the address the field shows: the machine the server
// is actually reading when that is a remote one, otherwise the operator's saved
// destination, otherwise the detected local address.
function hostDestinationShown() {
  const target = (hostStatusLast && hostStatusLast.target) || {};
  if (target.mode === 'ssh') {
    const parts = hostTargetParts(target);
    if (parts.host) return parts.host;
  }
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
    ipInput.value = hostDestinationShown();
  }
  // The user field follows the machine actually in use. It is filled from the
  // target rather than from the entry box so a page reload still shows who the
  // server is connected as, and switching back to 本机 clears it.
  const userInput = document.getElementById('hostUserInput');
  if (userInput && document.activeElement !== userInput) {
    const parts = hostTargetParts(target);
    userInput.value = target.mode === 'ssh'
      ? parts.user
      : (hostStoreGet(HOST_USER_STORAGE_KEY) || '').trim();
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

// onHostIpEdit and onHostUserEdit remember what this browser last typed. They
// change nothing until 连接 is pressed: a typed address is a destination, not a
// statement about what the panel is currently showing.
function onHostIpEdit(value) {
  hostStoreSet(HOST_IP_STORAGE_KEY, String(value || '').trim());
}

function onHostUserEdit(value) {
  hostStoreSet(HOST_USER_STORAGE_KEY, String(value || '').trim());
}

// onHostConnect asks the mock to read the named host with these credentials.
// The password is sent once to this server and never persisted.
async function onHostConnect() {
  const hostEl = document.getElementById('hostIpInput');
  const userEl = document.getElementById('hostUserInput');
  const passEl = document.getElementById('hostPasswordInput');
  const host = (hostEl ? hostEl.value : '').trim();
  if (!host) {
    showToast({ type: 'warning', title: '未填写主机', message: '请填写远程主机的 IP 或主机名' });
    return;
  }
  const user = (userEl ? userEl.value : '').trim();
  hostStoreSet(HOST_IP_STORAGE_KEY, host);
  hostStoreSet(HOST_USER_STORAGE_KEY, user);
  await submitHostTarget({ host, user, password: passEl ? passEl.value : '' });
}

// onHostUseLocal points the panel back at the machine the mock runs on. The
// saved destination is cleared too, so the field shows the detected address
// instead of a host that is no longer in use.
function onHostUseLocal() {
  hostStoreSet(HOST_IP_STORAGE_KEY, '');
  hostStoreSet(HOST_USER_STORAGE_KEY, '');
  submitHostTarget({ host: '' });
}

// submitHostTarget posts a source change and renders the answer. The server
// reads the new source before responding, so this one call says whether the
// SSH login worked and what the host reported.
async function submitHostTarget(body) {
  const btn = document.getElementById('hostConnectBtn');
  const original = btn ? btn.textContent : '';
  if (btn) {
    btn.disabled = true;
    btn.textContent = '连接中…';
  }
  try {
    const res = await fetch('/api/host/target', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const payload = await res.json().catch(() => null);
    if (!payload || payload.error !== 0) {
      showToast({ type: 'error', title: '切换主机失败', message: (payload && payload.msg) || '请求未完成' });
      return;
    }
    hostStatusLast = payload.result || {};
    renderHostStatus(hostStatusLast);
    const failure = hostStatusLast.memoryError || hostStatusLast.podsError;
    if (failure) {
      showToast({ type: 'error', title: 'SSH 采集失败', message: failure });
    } else {
      const label = (hostStatusLast.target || {}).label || '';
      showToast({ type: 'success', title: '已连接', message: label + ' 的内存与 Pod 列表已读取' });
    }
  } catch (_) {
    showToast({ type: 'error', title: '切换主机失败', message: '请求未完成' });
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = original || '连接';
    }
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
  const savedUser = (hostStoreGet(HOST_USER_STORAGE_KEY) || '').trim();
  const userInput = document.getElementById('hostUserInput');
  if (userInput && savedUser) userInput.value = savedUser;
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