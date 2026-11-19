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

// instanceHealthState is what the 环境 chip shows for each row: the outcome of
// the last connectivity check the console ran. The reply itself is kept only
// long enough to describe that outcome; nothing in the row reopens it.
const instanceHealthState = {};
// healthStampRendered is the timestamp signature the list currently displays.
// tickInstanceHealthExpiry compares against it to repaint only when a check has
// aged out of the green badge.
let healthStampRendered = '';

// instanceLinks is the console's link state for each registered instance.
//
// A registration is not a connection: it says the instance reported once, not
// that anything is answering now. So the console checks every registered
// instance itself, on a timer, and the row says what that check last saw.
//
//	检查中 → 连通正常, or
//	检查中 → 重连中 → (five minutes without a reply) → 断开连接
//
// 断开连接 stops the checks; only a new registration starts them again. The
// timer is what makes the row truthful without an operator pressing anything.
//
// Each check is addressed with ?dockerId= through the mock's /taa proxy. The
// direct address in getTaaAddr() belongs to the *selected* row, so using it for
// another row would report one instance's answer under another instance's name.
const instanceLinks = {};
const INSTANCE_HEALTH_INTERVAL_MS = 30 * 1000;
const INSTANCE_DISCONNECT_AFTER_MS = 5 * 60 * 1000;

function recordInstanceHealth(id, tone, label, title) {
  if (!id) return;
  instanceHealthState[id] = {
    tone: tone === 'ok' || tone === 'bad' || tone === 'running' ? tone : 'pending',
    label: label || '未检查',
    title: title || '',
    checkedAt: (tone === 'ok' || tone === 'bad') ? Date.now() : 0,
  };
  renderInstanceList();
}

// instanceHealthFor is the health chip's accessor: the last check's outcome, or
// the "not checked yet" placeholder that the chip renders for a fresh row.
//
// A passing check expires here as well as in instanceConnectionState: the chip
// is what the row shows under 环境, and a green 连通正常 from ten minutes ago
// would vouch for a link nobody has re-verified. A failed check is kept,
// because "this identity did not answer when last tried" stays useful until
// the next automatic check replaces it.
function instanceHealthFor(id) {
  const slot = healthSlotFor(id);
  if (!slot) {
    return {
      tone: 'pending',
      label: '未检查',
      title: '尚未对该实例执行连通性检查',
    };
  }
  if (slot.tone === 'ok') {
    const age = Date.now() - (slot.checkedAt || 0);
    if (age > instanceHealthStaleMs) {
      return {
        tone: 'pending',
        label: '已过期',
        title: '上次连通性检查已超过 ' + Math.round(instanceHealthStaleMs / 1000) + ' 秒，结论不再显示',
      };
    }
  }
  return slot;
}

// healthSlotFor is the same lookup without the placeholder, for callers that
// must tell "no check has run" apart from "the check said pending".
function healthSlotFor(id) {
  return instanceHealthState[id] || null;
}

// healthStampKey is the signature of what the list would draw for every row:
// the check's tone plus whether it is still fresh. Including freshness is what
// makes the expiry repaint work — a key built from checkedAt alone never
// changes as time passes, so a green badge could outlive its check until some
// unrelated request repainted the row.
function healthStampKey() {
  return Object.keys(instanceHealthState)
    .sort()
    .map((id) => {
      const h = instanceHealthState[id];
      const fresh = h.checkedAt > 0 && Date.now() - h.checkedAt <= instanceHealthStaleMs;
      return id + ':' + h.tone + ':' + (fresh ? 'fresh' : 'stale');
    })
    .join(',');
}

function tickInstanceHealthExpiry() {
  if (!instanceCache.length) return;
  if (healthStampKey() === healthStampRendered) return;
  healthStampRendered = healthStampKey();
  renderInstanceList();
}

// instanceConnectionState combines the link state with the registration fact.
// The link state wins: it is what the console last observed, and an accepted
// registration must not hide a link the checks just proved is not there.
//
// 已连接 is not a label this function produces. 连通正常 is earned by a recent
// passing check; an accepted registration whose first check has not finished
// yet reads 已注册. A failing check reads 重连中 while the console keeps
// retrying, and 断开连接 once five minutes have passed without an answer, at
// which point the console stops checking until the instance registers again.
// 未注册 and 注册失败 are kept for rows with no accepted registration, which
// only happens for a configured inventory entry or a rejected registration.
const instanceHealthStaleMs = 90 * 1000;

function instanceConnectionState(item) {
  if (!item) return { label: '未连接', tone: 'pending', hint: '' };
  const link = instanceLinks[item.dockerId];
  if (link) {
    if (link.state === 'disconnected') {
      return {
        label: '断开连接',
        tone: 'bad',
        hint: '连通性检查连续失败超过 ' + Math.round(INSTANCE_DISCONNECT_AFTER_MS / 60000) +
          ' 分钟，已停止检查；实例再次注册后会自动恢复定时检查',
      };
    }
    if (link.state === 'reconnecting') {
      const downFor = Math.max(0, Date.now() - (link.firstFailureAt || Date.now()));
      const left = Math.max(0, INSTANCE_DISCONNECT_AFTER_MS - downFor);
      return {
        label: '重连中',
        tone: 'pending',
        hint: '最近一次连通性检查失败，正在重试；实例可能已被删除或尚未就绪。已持续 ' + Math.round(downFor / 1000) +
          ' 秒，' + Math.round(left / 60000 * 10) / 10 + ' 分钟后仍不可达将标记为断开连接',
      };
    }
    if (link.state === 'probing') {
      return { label: '检查中', tone: 'pending', hint: '正在检查该实例是否可达' };
    }
    if (link.state === 'ok') {
      const age = Date.now() - (link.okAt || 0);
      if (age <= instanceHealthStaleMs) {
        return { label: '连通正常', tone: 'ok', hint: '最近一次连通性检查通过' };
      }
      return {
        label: '已注册',
        tone: 'pending',
        hint: '平台已接受该实例的注册；最近一次连通性检查已超过 ' +
          Math.round(instanceHealthStaleMs / 1000) + ' 秒，正在等下一次检查',
      };
    }
  }
  if (item.accepted) {
    return { label: '已注册', tone: 'pending', hint: '平台已接受该实例的注册，正在等待首次连通性检查' };
  }
  if (item.received) return { label: '注册失败', tone: 'bad', hint: '实例已上报，但平台未接受' };
  if (item.expected) return { label: '未连接', tone: 'pending', hint: '清单中配置的实例，平台尚未收到它的注册请求' };
  return { label: '未注册', tone: 'pending', hint: '尚未收到该实例的注册请求' };
}

// INSTANCE_GROUPS is the fixed display order of the list. The rows come from
// the configured inventory merged with what registered, so a type with nothing
// configured and nothing registered draws no section; a configured instance
// whose Pod has not come up still draws its row, as 未连接.
const INSTANCE_GROUPS = [
  { kind: 'tee', label: 'TEE 实例 · CSV 机密 VM' },
  { kind: 'fhe', label: 'FHE 实例 · GPU 宿主机' },
  { kind: 'data-anaylsis', label: '数据分析实例 · CSV 机密 VM' },
  { kind: '', label: '未识别类型' },
];

function instanceKindLabel(kind) {
  if (kind === 'tee') return 'TEE';
  if (kind === 'fhe') return 'FHE';
  if (kind === 'data-anaylsis') return '数据分析';
  return '';
}


// instanceNameHint explains where the row's name comes from. The name is the
// dockerId the instance was configured with — TAA sends it in the registration
// body — so it is an identity string, not a Pod name. Comparing the two is a
// normal way to get confused, so the hint names the source and, when the
// platform knows it, the address the registration actually came from.
function instanceNameHint(item) {
  const parts = ['名称来自实例注册时上报的 dockerId（DOCKER_ID 配置），不是 Pod 名称'];
  if (item.sourceAddr) parts.push('本次注册来源地址 ' + item.sourceAddr);
  if (item.taaTarget) parts.push('TAA 服务地址 ' + item.taaTarget);
  return parts.join('\n');
}

function instanceRowTitle(item, state) {
  const lines = [state.hint];
  if (item.taaTarget) lines.push('TAA 地址 ' + item.taaTarget);
  lines.push('实例名（dockerId）：' + (item.dockerId || '(legacy)'));
  if (item.sourceAddr) lines.push('注册来源：' + item.sourceAddr);
  if (item.userAgent) lines.push('User-Agent：' + item.userAgent);
  return lines.join('\n');
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
    item.expected ? '1' : '0',
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
  if (signature !== instanceListSignature || next !== instanceRenderedSelection) {
    instanceListSignature = signature;
    renderInstanceList();
  }
  // Counts live outside the repaint signature: patching them in place keeps a
  // single new log line from rebuilding the list under the operator's cursor.
  if (typeof refreshInstanceLogBadges === 'function') refreshInstanceLogBadges();
  applySelectedInstanceKind();
  if (previous !== next) notifyInstanceChange(next);
  setInstanceSelectorVisibility(list.length > 0);
  // Last, because a row that just registered is checked now and its 检查中
  // state repaints the list: the selection and per-kind maps must already
  // describe this poll, not the one before it.
  syncInstanceConnectivity(list);
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
    healthStampRendered = '';
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
  healthStampRendered = healthStampKey();
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
  main.title = instanceRowTitle(item, state);
  main.addEventListener('click', () => selectInstance(id));

  const dot = document.createElement('span');
  dot.className = 'instance-state-dot ' + state.tone;
  const name = document.createElement('span');
  name.className = 'instance-name';
  name.textContent = id || '(legacy)';
  name.title = instanceNameHint(item);
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
    // "默认" answers a console question, not an instance question: it is the
    // row the console addresses when no row is selected — the first accepted
    // registration. It says nothing about the instance being the only, the
    // newest, or the preferred one.
    tag.title = '默认实例：控制台在未选中任何行时，把控制台自身的请求发往这一行';
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
  // The TAA log is per instance: this toggle opens a terminal inside this row.
  // It deliberately does not select the row — two instances are compared side
  // by side, so opening one terminal must not move the rest of the console.
  const logButton = instanceActionButton(
    typeof taaLogBadgeText === 'function'
      ? taaLogBadgeText(id, item)
      : '日志 (' + (item.taaLogCount || 0) + ') ▾',
    () => {
      if (typeof taaTerminalState !== 'function' || typeof setTaaTerminalExpanded !== 'function') return;
      setTaaTerminalExpanded(id, !taaTerminalState(id).expanded);
    },
    false,
    '展开/收起该实例的 TAA 运行日志；各实例的终端互相独立',
  );
  logButton.classList.add('instance-log-toggle');
  actions.appendChild(logButton);
  actions.appendChild(instanceActionButton('公钥', () => openInstancePublicKey(id), !item.accepted, '查看该实例上报的 TAA 注册公钥'));
  actions.appendChild(instanceActionButton('注册返回', () => openInstanceRegisterBody(id), !item.received, '查看该实例的注册请求与平台返回'));
  if (item.kind === 'tee') {
    actions.appendChild(instanceActionButton('获取证明报告', () => runInstanceAttestation(id), false, '获取该实例的 CSV 远程证明报告'));
    // The report blob is one value in the page, so these two only exist on the
    // row that produced it.
    if (typeof _lastAttestationOwner !== 'undefined' && _lastAttestationOwner === id) {
      actions.appendChild(instanceActionButton('保存报告', () => saveAttestationReport(), false, '保存刚获取的证明报告'));
      actions.appendChild(instanceActionButton('查看返回', () => openInteractionModal('attestation', 'primary'), false, '查看证明接口的请求与返回'));
    }
  }
  // No delete action: the list is the inventory of what this platform is
  // configured to receive, so a row is not the operator's to remove here — an
  // instance whose Pod is gone keeps its registration row until the automatic
  // checks mark it 重连中 and then 断开连接, and comes back on its own if a Pod
  // registers under the same dockerId again.

  row.appendChild(main);
  row.appendChild(actions);
  // A repaint (selection change or inventory change) rebuilds the row; the
  // terminal comes back from the state map with its filter, keyword, pause and
  // cached lines intact.
  if (typeof buildTaaTerminal === 'function' && typeof taaTerminalState === 'function' && taaTerminalState(id).expanded) {
    row.appendChild(buildTaaTerminal(item));
  }
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

// ── Automatic connectivity checks ──
//
// The console is the only party that decides what a row says, so it is also
// the party that observes the link. A registration starts a per-instance timer;
// each tick asks that instance's /v1/taa/health through the mock's proxy and
// records what came back. Nothing here moves the selection: the check is
// addressed with the row's own dockerId.

// syncInstanceConnectivity starts, resumes and stops the timers. The instance
// list is polled every five seconds, which is where a registration is observed:
// the platform rewrites the registration record's receivedAt on every POST, and
// a value this page has not seen for that row is either the first registration
// or a new one. Both restart the checks — that is the only way out of 断开连接.
//
// Date.now-free comparison is deliberate: receivedAt has one-second resolution,
// so two registrations inside the same second are indistinguishable here. TAA
// registers once at boot, and the worse outcome is a check that keeps running,
// not a stopped one.
function syncInstanceConnectivity(list) {
  const registered = {};
  list.forEach((item) => {
    const id = item.dockerId || '';
    // Only an accepted registration starts checks. A rejected one stays 注册失败:
    // its link is not what the platform needs to know about it, and a passing
    // health check must not paint over the rejection.
    if (!id || !item.accepted) return;
    registered[id] = true;
    let link = instanceLinks[id];
    if (!link) {
      link = instanceLinks[id] = {
        state: 'idle',
        registrationAt: null,
        firstFailureAt: 0,
        okAt: 0,
        timer: null,
        inFlight: false,
        generation: 0,
      };
    }
    const at = item.receivedAt || '';
    if (link.registrationAt !== at) {
      link.registrationAt = at;
      startInstanceConnectivity(id);
    }
  });
  Object.keys(instanceLinks).forEach((id) => {
    if (registered[id]) return;
    stopInstanceConnectivity(id);
    delete instanceLinks[id];
  });
}

// startInstanceConnectivity (re)starts the loop for one instance. Any failure
// timer from the previous registration is dropped: a registration that lands
// while the row is 断开连接 is new evidence that the instance is alive.
function startInstanceConnectivity(id) {
  const link = instanceLinks[id];
  if (!link) return;
  clearInstanceConnectivityTimer(link);
  link.generation += 1;
  // The reply still in flight belongs to the previous generation; dropping the
  // flag is what lets the new check run instead of bouncing off it.
  link.inFlight = false;
  link.state = 'probing';
  link.firstFailureAt = 0;
  link.okAt = 0;
  recordInstanceHealth(id, 'running', '检查中', '连通性检查进行中');
  runInstanceConnectivityCheck(id);
}

// stopInstanceConnectivity forgets an instance that left the list. The
// generation bump makes any reply still in flight land nowhere.
function stopInstanceConnectivity(id) {
  const link = instanceLinks[id];
  if (!link) return;
  clearInstanceConnectivityTimer(link);
  link.generation += 1;
  link.inFlight = false;
}

function clearInstanceConnectivityTimer(link) {
  if (link.timer) {
    clearTimeout(link.timer);
    link.timer = null;
  }
}

// runInstanceConnectivityCheck is one probe. The generation is captured before
// the request: a reply from an earlier registration must not overwrite the
// state of a newer one, which is the same stale-reply rule the manual check
// needed when two clicks overlapped.
async function runInstanceConnectivityCheck(id) {
  const link = instanceLinks[id];
  if (!link || link.inFlight) return;
  const generation = link.generation;
  link.inFlight = true;
  let result;
  try {
    result = await probeInstanceHealth(id);
  } finally {
    const current = instanceLinks[id];
    if (current && current.generation === generation) current.inFlight = false;
  }
  const current = instanceLinks[id];
  if (!current || current.generation !== generation) return;
  if (result.ok) {
    current.state = 'ok';
    current.okAt = Date.now();
    current.firstFailureAt = 0;
    recordInstanceHealth(id, 'ok', '连通正常', '连通性检查通过');
  } else {
    recordInstanceConnectivityFailure(id, result);
  }
  scheduleInstanceConnectivity(id);
}

// recordInstanceConnectivityFailure moves the row to 重连中, or to 断开连接
// once the link has been down for the whole five-minute window. The transition
// is measured from the first failure, not from the last: periodic failures do
// not extend the deadline, so an instance that never comes back is marked
// 断开连接 exactly five minutes after it was lost.
function recordInstanceConnectivityFailure(id, result) {
  const link = instanceLinks[id];
  if (!link) return;
  const now = Date.now();
  if (!link.firstFailureAt) link.firstFailureAt = now;
  const downFor = now - link.firstFailureAt;
  if (downFor >= INSTANCE_DISCONNECT_AFTER_MS) {
    link.state = 'disconnected';
    clearInstanceConnectivityTimer(link);
    recordInstanceHealth(id, 'bad', '连接断开', result.title + '：' + result.error +
      '；已持续 ' + Math.round(downFor / 60000) + ' 分钟，停止检查');
    return;
  }
  link.state = 'reconnecting';
  recordInstanceHealth(id, 'bad', '连通异常', result.title + '：' + result.error +
    '；自 ' + instanceClock(new Date(link.firstFailureAt).toISOString()) + ' 起持续失败，仍在重试');
}

function scheduleInstanceConnectivity(id) {
  const link = instanceLinks[id];
  if (!link || link.state === 'disconnected') return;
  clearInstanceConnectivityTimer(link);
  link.timer = setTimeout(() => {
    link.timer = null;
    // A hidden tab shows nothing, so it does no probing either; the next
    // visible tick picks the schedule back up.
    if (document.hidden) {
      scheduleInstanceConnectivity(id);
      return;
    }
    runInstanceConnectivityCheck(id);
  }, INSTANCE_HEALTH_INTERVAL_MS);
}

// probeInstanceHealth asks one instance whether it answers. It goes through the
// mock's /taa proxy with the row's own dockerId rather than getTaaAddr(): the
// latter is the selected row's address, and a background check of another row
// through it would report the selected instance's answer under this row's name.
async function probeInstanceHealth(id) {
  const url = location.origin + '/taa/v1/taa/health?dockerId=' + encodeURIComponent(id);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  try {
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
      signal: controller.signal,
    });
    const text = await resp.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch (_) {
      data = text;
    }
    const ok = resp.status === 200 && data && data.error === 0;
    return {
      ok: ok,
      status: resp.status,
      data: data,
      title: ok ? '连通性检查通过' : 'HTTP ' + resp.status,
      error: ok ? '' : String((data && data.msg) || ('HTTP ' + resp.status)),
    };
  } catch (e) {
    const timeout = e && e.name === 'AbortError';
    return {
      ok: false,
      status: 0,
      data: { error: -1, msg: timeout ? '请求超时（10s）' : ((e && e.message) || '网络请求异常') },
      title: timeout ? '请求超时' : '请求失败',
      error: timeout ? '10 秒内未响应' : ((e && e.message) || '网络请求异常'),
    };
  } finally {
    clearTimeout(timer);
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
  // A health result has no server-side counterpart to refresh it, so the badge
  // is repainted here once its green expires; otherwise the row would keep
  // showing 连通正常 until some unrelated event happened to redraw it.
  setInterval(tickInstanceHealthExpiry, 5000);
}

// refreshInstancePanels re-reads every instance-scoped panel that follows the
// selection. TAA log terminals are not in that set: each one belongs to its own
// instance and keeps polling regardless of what is selected.
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
  // The selected instance decides the target, so the pill follows it.
  if (typeof detectTAAProxy === 'function') {
    detectTAAProxy();
  }
}

// There is no deleteInstance / deleteSelectedInstance pair any more. The list
// is the inventory the platform is configured to receive, so removing a row
// would only make an instance the operator still runs disappear from the one
// place that shows its state; an instance whose Pod is gone keeps its 已注册
// row until a check marks it 未连接, and recovers by itself when a Pod registers
// under that dockerId again.
// Clearing one instance's *records* is still possible: the register/report
// reset endpoints are per-instance.

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
      if (typeof pollTaaTerminals === 'function') pollTaaTerminals();
      if (typeof refreshLLMStatus === 'function') {
        refreshLLMStatus();
      }
    } catch (_) {}
  }
};
