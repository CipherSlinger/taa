// ── Log Streaming Components (Model Log & TAA Log) ──

let modelLogPaused = false;
let taaLogPaused = false;
let currentLogFilter = 'ALL';
let currentSearchKeyword = '';
let autoScrollLocked = true;

// Unpause both panels after an instance switch: a paused fetch returns early,
// which would leave the previous instance's log lines on screen.
function resetLogPauseForInstanceChange() {
  modelLogPaused = false;
  taaLogPaused = false;
  const modelBtn = document.getElementById('modelLogPauseBtn');
  if (modelBtn) {
    modelBtn.textContent = '暂停';
    modelBtn.className = 'secondary';
  }
  const taaBtn = document.getElementById('taaLogPauseBtn');
  if (taaBtn) {
    taaBtn.textContent = '暂停';
    taaBtn.className = 'secondary';
  }
}

// TAA log lines arrive pre-formatted by the daemon: the level lives inside the
// text as "[YYYY-MM-DD HH:MM:SS] [LEVEL] [component] message", and /v1/taa/taaLog
// carries no separate level field. This pattern recovers that token.
const TAA_LOG_PREFIX = /^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]\s*\[(DEBUG|INFO|WARN|ERROR)\]/;

// parseStructuredLevel returns the level the daemon stamped into the line, or
// null when the line carries no such prefix.
function parseStructuredLevel(msg) {
  const m = TAA_LOG_PREFIX.exec(String(msg || ''));
  return m ? m[1] : null;
}

// detectLogLevel resolves the severity of a log line.
//
// The daemon's own token is authoritative and is always preferred. Scanning the
// text for keywords is only a fallback for lines that carry no token: it reads
// the message body, not the level, so it reports the audit-start line
// ("failClosed=true" contains "FAIL") as an error and the export line
// ("warnings=" contains "WARN") as a warning.
function detectLogLevel(msg) {
  const structured = parseStructuredLevel(msg);
  if (structured) return structured;
  if (!msg) return 'INFO';
  const upper = String(msg).toUpperCase();
  if (upper.includes('ERROR') || upper.includes('FATAL') || upper.includes('PANIC') || upper.includes('FAIL')) {
    return 'ERROR';
  }
  if (upper.includes('WARN')) {
    return 'WARN';
  }
  return 'INFO';
}

function highlightSearchMatches(safeHtml, keyword) {
  if (!keyword) return safeHtml;
  const escaped = keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const reg = new RegExp(`(${escaped})`, 'gi');
  return safeHtml.replace(reg, '<mark class="hl-match">$1</mark>');
}

function renderTaaLogEntry(e, st) {
  const view = st || { level: 'ALL', keyword: '' };
  const lvl = detectLogLevel(e.message);
  const safeMsg = escapeHtml(e.message);
  const highlightedMsg = view.keyword ? highlightSearchMatches(safeMsg, view.keyword) : safeMsg;
  const isMatch = !view.keyword || e.message.toLowerCase().includes(view.keyword.toLowerCase());
  const isLvlMatch = (view.level === 'ALL' || lvl === view.level);
  const displayStyle = (isMatch && isLvlMatch) ? '' : 'display:none;';

  return `<div class="log-row" data-seq="${e.seq}" data-level="${lvl}" data-raw-text="${safeMsg}" style="${displayStyle}"><span class="log-seq" style="color:#60a5fa; font-weight:600; margin-right:6px;">[seq=${e.seq}]</span><span class="log-lvl ${lvl.toLowerCase()}">${lvl}</span><span class="log-msg">${highlightedMsg}</span></div>`;
}

function setLogFilter(level) {
  currentLogFilter = level || 'ALL';
  document.querySelectorAll('.log-filter-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.level === currentLogFilter);
  });
  applyLogFilteringAndHighlight();
}
window.setLogFilter = setLogFilter;

function handleLogSearch(val) {
  currentSearchKeyword = (val || '').trim();
  applyLogFilteringAndHighlight();
}
window.handleLogSearch = handleLogSearch;

function applyLogFilteringAndHighlight() {
  const container = document.getElementById('taaLogOutput');
  if (!container) return;
  const rows = container.querySelectorAll('.log-row');
  let matchCount = 0;

  rows.forEach(row => {
    const rawText = row.dataset.rawText || '';
    const level = row.dataset.level || 'INFO';

    const levelMatch = (currentLogFilter === 'ALL' || level === currentLogFilter);
    let keywordMatch = true;

    if (currentSearchKeyword) {
      keywordMatch = rawText.toLowerCase().includes(currentSearchKeyword.toLowerCase());
    }

    if (levelMatch && keywordMatch) {
      row.style.display = '';
      if (currentSearchKeyword) {
        matchCount++;
        const msgSpan = row.querySelector('.log-msg');
        if (msgSpan) {
          msgSpan.innerHTML = highlightSearchMatches(rawText, currentSearchKeyword);
        }
      } else {
        const msgSpan = row.querySelector('.log-msg');
        if (msgSpan) {
          msgSpan.innerHTML = rawText;
        }
      }
    } else {
      row.style.display = 'none';
    }
  });

  const countBadge = document.getElementById('searchMatchCount');
  if (countBadge) {
    countBadge.textContent = currentSearchKeyword ? `${matchCount} 条` : '';
  }
}
window.applyLogFilteringAndHighlight = applyLogFilteringAndHighlight;

// ── Model Terminal Log ──
async function fetchModelLogs() {
  if (modelLogPaused) return;
  try {
    const res = await mockFetch('/api/modelLog/status', { cache: 'no-store' });
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
    await mockFetch('/api/modelLog/reset', { method: 'POST' });
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
    const res = await mockFetch('/api/taaLog/status', { cache: 'no-store' });
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

    output.innerHTML = entries.map((e) => renderTaaLogEntry(e, { level: currentLogFilter, keyword: currentSearchKeyword })).join('');

    if (currentSearchKeyword) {
      applyLogFilteringAndHighlight();
    }

    if (!taaLogPaused && autoScrollLocked) {
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
    await mockFetch('/api/taaLog/reset', { method: 'POST' });
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
  const countBadge = document.getElementById('searchMatchCount');
  if (countBadge) countBadge.textContent = '';
}

document.addEventListener('DOMContentLoaded', () => {
  const output = document.getElementById('taaLogOutput');
  if (output) {
    output.addEventListener('scroll', () => {
      const atBottom = output.scrollHeight - output.scrollTop - output.clientHeight <= 40;
      autoScrollLocked = atBottom;
    });
  }
  document.addEventListener('keydown', (e) => {
    if (e.key === '/' && document.activeElement && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {
      const searchInput = document.getElementById('terminalSearchInput');
      if (searchInput) {
        e.preventDefault();
        searchInput.focus();
        searchInput.select();
      }
    }
  });
});

// ── Per-instance TAA terminals ──
//
// A terminal belongs to one dockerId, not to the page's selection: two
// instances can be watched side by side, each with its own pause, level
// filter, search keyword and scroll lock. Nothing below reads the page's
// selected instance — a terminal only ever addresses the id it was built for.
const taaTerminals = new Map();

function taaTerminalState(id) {
  let st = taaTerminals.get(id);
  if (!st) {
    st = {
      expanded: false,
      paused: false,
      level: 'ALL',
      keyword: '',
      autoScroll: true,
      scrollTop: 0,
      entries: [],
      total: 0,
      lastSeq: 0,
      error: '',
      loading: false,
      fetchedAt: 0,
      generation: 0,
    };
    taaTerminals.set(id, st);
  }
  return st;
}

// findTaaTerminal / findInstanceRow scan instead of using a selector with the
// dockerId interpolated: a registration can carry any string, and quotes or
// brackets in it must not be able to change which node is found.
function findTaaTerminal(id) {
  const nodes = document.querySelectorAll('.instance-terminal');
  for (const node of nodes) {
    if (node.dataset.terminalFor === id) return node;
  }
  return null;
}

function findInstanceRow(id) {
  const rows = document.querySelectorAll('.instance-row');
  for (const row of rows) {
    if (row.dataset.dockerId === id) return row;
  }
  return null;
}

function taaTerminalButton(label, kind, handler, title) {
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = kind + ' btn-sm';
  btn.textContent = label;
  if (title) btn.title = title;
  btn.addEventListener('click', handler);
  return btn;
}

function fetchTaaLogsFor(id, force) {
  const st = taaTerminalState(id);
  if (!st.expanded || (!force && st.paused) || st.loading) return Promise.resolve();
  st.loading = true;
  const gen = st.generation;
  const done = () => {
    st.loading = false;
    const root = findTaaTerminal(id);
    if (root) paintTaaTerminal(root, id);
    refreshInstanceLogBadges();
  };
  return fetch('/api/taaLog/status?dockerId=' + encodeURIComponent(id), { cache: 'no-store' })
    .then((res) => {
      // An unknown dockerId is an empty terminal, not a failure.
      if (res.status === 404) return { entries: [], totalCount: 0, lastSeq: 0 };
      if (!res.ok) throw new Error('status ' + res.status);
      return res.json();
    })
    .then((data) => {
      if (gen !== st.generation) return;
      const result = responseResult(data);
      if (!result || !Array.isArray(result.entries)) throw new Error('unexpected payload');
      st.entries = result.entries;
      st.total = result.totalCount != null ? result.totalCount : st.entries.length;
      st.lastSeq = result.lastSeq != null
        ? result.lastSeq
        : (st.entries.length ? st.entries[st.entries.length - 1].seq : 0);
      st.error = '';
      st.fetchedAt = Date.now();
    })
    .catch(() => {
      // Keep the lines already on screen: a failed poll is not a reason to
      // blank a terminal the operator is reading. A reply from before a clear
      // is stale and must not paint an error over the fresh, empty terminal.
      if (gen === st.generation) st.error = '日志拉取失败';
    })
    .then(done);
}

// pollTaaTerminals is called by the medium polling tier. Collapsed and paused
// terminals produce no request at all, so an idle page sends nothing.
function pollTaaTerminals() {
  taaTerminals.forEach((st, id) => {
    if (st.expanded && !st.paused) fetchTaaLogsFor(id);
  });
}

function setTaaTerminalExpanded(id, expanded) {
  const st = taaTerminalState(id);
  st.expanded = !!expanded;
  const row = findInstanceRow(id);
  if (row) {
    const existing = row.querySelector('.instance-terminal');
    if (existing) existing.remove();
    if (st.expanded) {
      const item = instanceCache.find((it) => (it.dockerId || '') === id) || { dockerId: id };
      row.appendChild(buildTaaTerminal(item));
      fetchTaaLogsFor(id);
    }
  }
  refreshInstanceLogBadges();
}

function toggleTaaTerminalPause(id) {
  const st = taaTerminalState(id);
  st.paused = !st.paused;
  const root = findTaaTerminal(id);
  if (root) paintTaaTerminal(root, id);
  if (!st.paused) fetchTaaLogsFor(id);
}

function setTaaTerminalFilter(id, level) {
  const st = taaTerminalState(id);
  st.level = level || 'ALL';
  const root = findTaaTerminal(id);
  if (!root) return;
  root.querySelectorAll('.log-filter-btn').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.level === st.level);
  });
  applyTaaTerminalView(root, st);
}

function onTaaTerminalSearch(id, value) {
  const st = taaTerminalState(id);
  st.keyword = (value || '').trim();
  const root = findTaaTerminal(id);
  if (root) applyTaaTerminalView(root, st);
}

function clearTaaTerminal(id) {
  const st = taaTerminalState(id);
  st.generation += 1;
  return fetch('/api/taaLog/reset?dockerId=' + encodeURIComponent(id), { method: 'POST' })
    .then((res) => {
      if (!res.ok) throw new Error('reset ' + res.status);
      return res.json();
    })
    .then((data) => {
      if (!data || data.error !== 0) throw new Error('reset rejected');
      st.generation += 1;
      st.entries = [];
      st.total = 0;
      st.lastSeq = 0;
      st.error = '';
      st.fetchedAt = Date.now();
    })
    .catch(() => {
      st.error = '清空失败';
    })
    .then(() => {
      const root = findTaaTerminal(id);
      if (root) paintTaaTerminal(root, id);
      refreshInstanceLogBadges();
    });
}

// applyTaaTerminalView re-applies one terminal's filter and keyword to the rows
// already in its window. It takes the terminal root so the same call serves
// every open terminal without a shared "current" state.
function applyTaaTerminalView(root, st) {
  const out = root.querySelector('.taa-terminal-output');
  if (!out) return;
  let matchCount = 0;
  out.querySelectorAll('.log-row').forEach((row) => {
    const raw = row.dataset.rawText || '';
    const level = row.dataset.level || 'INFO';
    const levelMatch = st.level === 'ALL' || level === st.level;
    const keywordMatch = !st.keyword || raw.toLowerCase().includes(st.keyword.toLowerCase());
    const msg = row.querySelector('.log-msg');
    if (levelMatch && keywordMatch) {
      row.style.display = '';
      if (st.keyword) matchCount++;
      // dataset.rawText is HTML-entity-decoded by the parser, so the text must
      // be re-escaped before it goes back through innerHTML.
      const next = st.keyword ? highlightSearchMatches(escapeHtml(raw), st.keyword) : escapeHtml(raw);
      if (msg && msg.innerHTML !== next) msg.innerHTML = next;
    } else {
      row.style.display = 'none';
    }
  });
  const badge = root.querySelector('.taa-terminal-match-count');
  if (badge) badge.textContent = st.keyword ? matchCount + ' 条' : '';
}

// buildTaaTerminal mounts one instance's terminal. Every control closes over
// `id`, so no action can be sent to a neighbouring row.
function buildTaaTerminal(item) {
  const id = item.dockerId || '';
  const st = taaTerminalState(id);
  const wrap = document.createElement('div');
  wrap.className = 'instance-terminal';
  wrap.dataset.terminalFor = id;

  const shell = document.createElement('div');
  shell.className = 'terminal-shell';

  const bar = document.createElement('div');
  bar.className = 'terminal-bar';
  const left = document.createElement('div');
  left.className = 'terminal-bar-left';
  const dots = document.createElement('div');
  dots.className = 'terminal-dots';
  ['red', 'yellow', 'green'].forEach((color) => {
    const dot = document.createElement('span');
    dot.className = 't-dot ' + color;
    dots.appendChild(dot);
  });
  left.appendChild(dots);
  const title = document.createElement('span');
  title.className = 'terminal-title';
  title.textContent = 'taa-syslog · ' + (id || '(legacy)');
  left.appendChild(title);
  const stream = document.createElement('span');
  stream.className = 'muted';
  stream.style.fontSize = '11px';
  stream.textContent = 'stdout / stderr';
  left.appendChild(stream);
  bar.appendChild(left);

  const actions = document.createElement('div');
  actions.className = 'terminal-bar-actions';
  const status = document.createElement('span');
  status.className = 'status taa-terminal-status';
  const statusDot = document.createElement('span');
  statusDot.className = 'dot status-pill pending taa-terminal-status-dot';
  const statusText = document.createElement('span');
  statusText.className = 'taa-terminal-status-text';
  statusText.textContent = '等待日志上报...';
  status.appendChild(statusDot);
  status.appendChild(statusText);
  actions.appendChild(status);
  const countEl = document.createElement('span');
  countEl.className = 'muted taa-terminal-count';
  countEl.style.fontSize = '12px';
  actions.appendChild(countEl);
  const seqEl = document.createElement('span');
  seqEl.className = 'muted taa-terminal-seq';
  seqEl.style.fontSize = '12px';
  actions.appendChild(seqEl);
  actions.appendChild(taaTerminalButton('刷新', 'secondary', () => fetchTaaLogsFor(id, true), '立即重新拉取该实例的 TAA 日志'));
  const pauseBtn = taaTerminalButton('暂停', 'secondary', () => toggleTaaTerminalPause(id), '暂停后该终端停止轮询，不影响其他实例');
  pauseBtn.classList.add('taa-terminal-pause');
  actions.appendChild(pauseBtn);
  actions.appendChild(taaTerminalButton('清空', 'danger', () => clearTaaTerminal(id), '只清空该实例的 TAA 日志'));
  bar.appendChild(actions);
  shell.appendChild(bar);

  const toolbar = document.createElement('div');
  toolbar.className = 'terminal-toolbar';
  const filterGroup = document.createElement('div');
  filterGroup.className = 'log-filter-group';
  filterGroup.setAttribute('role', 'group');
  filterGroup.setAttribute('aria-label', '日志等级过滤');
  [['ALL', '全部'], ['INFO', 'INFO'], ['WARN', 'WARN'], ['ERROR', 'ERROR']].forEach(([level, label]) => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'log-filter-btn' + (st.level === level ? ' active' : '');
    btn.dataset.level = level;
    btn.textContent = label;
    btn.addEventListener('click', () => setTaaTerminalFilter(id, level));
    filterGroup.appendChild(btn);
  });
  toolbar.appendChild(filterGroup);
  const searchBox = document.createElement('div');
  searchBox.className = 'terminal-search-box';
  const search = document.createElement('input');
  search.type = 'text';
  search.className = 'taa-terminal-search';
  search.placeholder = '搜索日志... (/)';
  search.value = st.keyword;
  search.addEventListener('input', () => onTaaTerminalSearch(id, search.value));
  searchBox.appendChild(search);
  const matchCount = document.createElement('span');
  matchCount.className = 'taa-terminal-match-count';
  searchBox.appendChild(matchCount);
  toolbar.appendChild(searchBox);
  shell.appendChild(toolbar);

  const out = document.createElement('div');
  out.className = 'log-window taa-terminal-output';
  out.addEventListener('scroll', () => {
    st.autoScroll = out.scrollHeight - out.scrollTop - out.clientHeight <= 40;
    st.scrollTop = out.scrollTop;
  });
  shell.appendChild(out);

  wrap.appendChild(shell);
  paintTaaTerminal(wrap, id);
  // A detached node has no layout box, so scrollTop read/writes above are
  // inert. Restore the remembered position after the caller has mounted it.
  requestAnimationFrame(() => {
    if (!wrap.isConnected) return;
    const mounted = wrap.querySelector('.taa-terminal-output');
    if (mounted) mounted.scrollTop = st.autoScroll ? mounted.scrollHeight : (st.scrollTop || 0);
  });
  return wrap;
}

// paintTaaTerminal redraws one terminal from its state. It is safe to call on
// a detached node (buildTaaTerminal does), so it never looks the terminal up by
// id itself.
function paintTaaTerminal(root, id) {
  const st = taaTerminalState(id);
  const countEl = root.querySelector('.taa-terminal-count');
  if (countEl) countEl.textContent = st.total + ' 条日志';
  const seqEl = root.querySelector('.taa-terminal-seq');
  if (seqEl) seqEl.textContent = '最新 seq: ' + st.lastSeq;

  const dot = root.querySelector('.taa-terminal-status-dot');
  const statusText = root.querySelector('.taa-terminal-status-text');
  if (dot && statusText) {
    if (st.error) {
      dot.className = 'dot status-pill bad taa-terminal-status-dot';
      statusText.textContent = st.error;
    } else if (st.entries.length > 0) {
      dot.className = 'dot ok status-pill ok taa-terminal-status-dot';
      statusText.textContent = '日志接收中';
    } else {
      dot.className = 'dot status-pill pending taa-terminal-status-dot';
      statusText.textContent = '等待日志上报...';
    }
  }

  const pauseBtn = root.querySelector('.taa-terminal-pause');
  if (pauseBtn) {
    pauseBtn.textContent = st.paused ? '继续' : '暂停';
    pauseBtn.className = (st.paused ? 'success' : 'secondary') + ' btn-sm taa-terminal-pause';
  }
  root.querySelectorAll('.log-filter-btn').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.level === st.level);
  });
  const search = root.querySelector('.taa-terminal-search');
  if (search && search.value !== st.keyword) search.value = st.keyword;

  const out = root.querySelector('.taa-terminal-output');
  if (!out) return;
  const nextSeq = String(st.lastSeq);
  const nextCount = String(st.entries.length);
  if (out.dataset.renderedSeq !== nextSeq || out.dataset.renderedCount !== nextCount) {
    if (st.entries.length === 0) {
      out.innerHTML = '<div class="taa-terminal-empty" style="color:#6b7280; text-align:center; padding:40px 0;">该实例暂无 TAA 日志。(/v1/taa/taaLog)</div>';
    } else {
      out.innerHTML = st.entries.map((e) => renderTaaLogEntry(e, st)).join('');
    }
    out.dataset.renderedSeq = nextSeq;
    out.dataset.renderedCount = nextCount;
  }
  applyTaaTerminalView(root, st);
  if (st.autoScroll) out.scrollTop = out.scrollHeight;
  else out.scrollTop = st.scrollTop || 0;
}

// taaLogBadgeText is shared by the row builder and the in-place badge refresh.
// An open terminal shows its own live total (its polling is fresher than the
// list payload); a collapsed row shows the server-reported count from the last
// /api/instances reply.
function taaLogBadgeText(id, item) {
  const st = taaTerminals.get(id);
  const live = st && st.expanded && st.fetchedAt;
  const count = live ? st.total : ((item && item.taaLogCount) || 0);
  return '日志 (' + count + ') ' + (st && st.expanded ? '▴' : '▾');
}

// refreshInstanceLogBadges keeps the collapsed row's count current without
// touching the list signature: a new log line must not repaint every row (that
// would drop focus from a search box in an open terminal).
function refreshInstanceLogBadges() {
  document.querySelectorAll('.instance-row').forEach((row) => {
    const id = row.dataset.dockerId || '';
    const btn = row.querySelector('.instance-log-toggle');
    if (!btn) return;
    const item = (typeof instanceCache !== 'undefined' ? instanceCache : [])
      .find((it) => (it.dockerId || '') === id);
    btn.textContent = taaLogBadgeText(id, item);
  });
}
