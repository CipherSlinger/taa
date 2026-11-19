# Per-Instance TAA Log Terminals — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the TAA runtime log from one page-wide card into each instance row, so every instance has its own inline terminal with independent pause, level filter, search, clear and scroll state.

**Architecture:** All per-terminal state lives in a `Map` keyed by `dockerId` in `logs.js`; requests always name their instance explicitly (`?dockerId=...`) instead of following the page selection. Instance rows are built with DOM calls in `api.js`, so the terminal is appended to the row it belongs to and its buttons close over that row's id. The bottom `.log-panels-grid` is removed and the 模型终端日志 card remains, full width, still following the selected instance.

**Tech Stack:** Plain browser JS (no framework, no build step), `go:embed` served assets, Go source-level frontend tests (`internal/frontend_*_test.go`).

**Spec:** `.claude/specs/2026-11-19-per-instance-taa-log-terminal-design.md`

---

## File Structure

| File | Responsibility after this change |
|---|---|
| `tools/platform-mock/internal/static/js/logs.js` | Model log (unchanged) + the whole per-instance TAA terminal module: state map, fetch/poll, DOM builder, paint/filter/search/pause/clear. |
| `tools/platform-mock/internal/static/js/api.js` | Instance rows: `日志 (N)` toggle, terminal mount, badge refresh, `refreshInstancePanels`/`pollMediumTier` wiring. |
| `tools/platform-mock/internal/static/js/app.js` | Startup: no page-wide TAA log fetch. |
| `tools/platform-mock/internal/static/index.html` | Bottom grid and TAA card deleted; model log card stands alone. |
| `tools/platform-mock/internal/static/css/layout.css` | `.log-panels-*` rules deleted. |
| `tools/platform-mock/internal/static/css/components.css` | `.instance-terminal` styles added. |
| `tools/platform-mock/internal/frontend_taa_terminal_test.go` | New: source-level assertions for the per-instance terminal. |
| `tools/platform-mock/internal/server_test.go` | `TestTaaLogConsoleRendering` rewritten; import-card boundary marker changed. |
| `tools/platform-mock/README.md`, `CHANGELOG.md` | Docs. |

All `go test` commands run from the repo root `/home/hjy/taa` (or from `tools/platform-mock`, both work for the package path below). Never use `./...`.

---

### Task 1: Per-instance terminal module in `logs.js`

**Files:**
- Modify: `tools/platform-mock/internal/static/js/logs.js`
- Create: `tools/platform-mock/internal/frontend_taa_terminal_test.go`

- [ ] **Step 1: Write the failing tests**

Create `tools/platform-mock/internal/frontend_taa_terminal_test.go`:

```go
package mock

import (
	"strings"
	"testing"
)

// TestFrontendTaaTerminalIsPerInstance pins the core of the change: a terminal
// belongs to a dockerId, and every request it makes names that id explicitly.
// Following the page selection (mockFetch + withDockerId) is exactly the
// coupling that made the old bottom card swap its contents when the operator
// clicked a different row.
func TestFrontendTaaTerminalIsPerInstance(t *testing.T) {
	for _, want := range []string{
		"const taaTerminals = new Map();",
		"function taaTerminalState(id)",
		"taaTerminals.set(id, st);",
		"function fetchTaaLogsFor(id)",
		"'/api/taaLog/status?dockerId=' + encodeURIComponent(id)",
		"'/api/taaLog/reset?dockerId=' + encodeURIComponent(id)",
		"function pollTaaTerminals()",
		"if (st.expanded && !st.paused) fetchTaaLogsFor(id);",
	} {
		if !strings.Contains(frontendBundle, want) {
			t.Fatalf("frontendBundle missing %q", want)
		}
	}
}

// TestFrontendTaaTerminalStateIsPerTerminal pins that pause, level and search
// keyword are written to the terminal's own state object rather than to page
// globals, so pausing instance A cannot freeze instance B.
func TestFrontendTaaTerminalStateIsPerTerminal(t *testing.T) {
	cases := map[string]string{
		"setTaaTerminalFilter":   "st.level =",
		"onTaaTerminalSearch":    "st.keyword =",
		"toggleTaaTerminalPause": "st.paused =",
		"setTaaTerminalExpanded": "st.expanded =",
	}
	for fnName, want := range cases {
		fn := frontendFunction(t, fnName)
		if !strings.Contains(fn, want) {
			t.Fatalf("%s does not write %q", fnName, want)
		}
	}
}

// TestFrontendTaaTerminalScrollIsPerTerminal pins that the scroll lock is read
// from and written to the terminal's state, not a shared variable: scrolling up
// in one terminal must not stop the other from following its tail.
func TestFrontendTaaTerminalScrollIsPerTerminal(t *testing.T) {
	fn := frontendFunction(t, "buildTaaTerminal")
	if !strings.Contains(fn, "st.autoScroll =") {
		t.Fatal("buildTaaTerminal does not record this terminal's scroll lock")
	}
	if !strings.Contains(frontendFunction(t, "paintTaaTerminal"), "st.autoScroll") {
		t.Fatal("paintTaaTerminal does not honour this terminal's scroll lock")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/hjy/taa/tools/platform-mock && go test ./internal/ -run 'TestFrontendTaaTerminal' -count=1`

Expected: FAIL — `frontendBundle missing "const taaTerminals = new Map();"`.

- [ ] **Step 3: Add the per-instance terminal module to `logs.js`**

Append the following block at the **end** of `tools/platform-mock/internal/static/js/logs.js` (after the existing `DOMContentLoaded` listener). Also make the two small edits called out after the block.

```js
// ── Per-instance TAA terminals ──
//
// A terminal belongs to one dockerId, not to the page's selection: two
// instances can be watched side by side, each with its own pause, level
// filter, search keyword and scroll lock. Nothing below reads
// currentInstanceDockerId — a terminal only ever addresses the id it was built
// for.
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
      entries: [],
      total: 0,
      lastSeq: 0,
      error: '',
      loading: false,
      fetchedAt: 0,
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

function fetchTaaLogsFor(id) {
  const st = taaTerminalState(id);
  if (!st.expanded || st.paused || st.loading) return Promise.resolve();
  st.loading = true;
  const done = () => {
    st.loading = false;
    const root = findTaaTerminal(id);
    if (root) paintTaaTerminal(root, id);
    refreshInstanceLogBadges();
  };
  return fetch('/api/taaLog/status?dockerId=' + encodeURIComponent(id), { cache: 'no-store' })
    .then((res) => {
      if (!res.ok) throw new Error('status ' + res.status);
      return res.json();
    })
    .then((data) => {
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
      // blank a terminal the operator is reading.
      st.error = '日志拉取失败';
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
  return fetch('/api/taaLog/reset?dockerId=' + encodeURIComponent(id), { method: 'POST' })
    .then((res) => {
      if (!res.ok) throw new Error('reset ' + res.status);
      return res.json();
    })
    .then((data) => {
      if (!data || data.error !== 0) throw new Error('reset rejected');
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
      if (msg) msg.innerHTML = st.keyword ? highlightSearchMatches(raw, st.keyword) : raw;
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
  actions.appendChild(taaTerminalButton('刷新', 'secondary', () => fetchTaaLogsFor(id), '立即重新拉取该实例的 TAA 日志'));
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
  });
  shell.appendChild(out);

  wrap.appendChild(shell);
  paintTaaTerminal(wrap, id);
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
  if (st.entries.length === 0) {
    out.innerHTML = '<div class="taa-terminal-empty" style="color:#6b7280; text-align:center; padding:40px 0;">该实例暂无 TAA 日志。(/v1/taa/taaLog)</div>';
  } else {
    out.innerHTML = st.entries.map((e) => renderTaaLogEntry(e, st)).join('');
  }
  applyTaaTerminalView(root, st);
  if (st.autoScroll) out.scrollTop = out.scrollHeight;
}

// refreshInstanceLogBadges keeps the collapsed row's count current without
// touching the list signature: a new log line must not repaint every row (that
// would drop focus from a search box in an open terminal).
function refreshInstanceLogBadges() {
  document.querySelectorAll('.instance-row').forEach((row) => {
    const id = row.dataset.dockerId || '';
    const btn = row.querySelector('.instance-log-toggle');
    if (!btn) return;
    const st = taaTerminals.get(id);
    const item = (typeof instanceCache !== 'undefined' ? instanceCache : [])
      .find((it) => (it.dockerId || '') === id);
    const count = st && st.fetchedAt ? st.total : ((item && item.taaLogCount) || 0);
    btn.textContent = '日志 (' + count + ') ' + (st && st.expanded ? '▴' : '▾');
  });
}
```

Two edits inside the existing code, in the same file:

1. Change `renderTaaLogEntry` to take the terminal state (the old page-wide card keeps working by passing its globals until Task 3 deletes it):

```js
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
```

2. Update the old caller so it passes its globals as the view (only until Task 3 removes it):

```js
    output.innerHTML = entries.map((e) => renderTaaLogEntry(e, { level: currentLogFilter, keyword: currentSearchKeyword })).join('');
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/hjy/taa/tools/platform-mock && go test ./internal/ -run 'TestFrontendTaaTerminal' -count=1`

Expected: PASS (all three).

- [ ] **Step 5: Run the whole package test suite**

Run: `cd /home/hjy/taa/tools/platform-mock && go test ./internal/ -count=1`

Expected: PASS. The page-wide card still exists and still works at this commit.

- [ ] **Step 6: Commit**

```bash
cd /home/hjy/taa
git add tools/platform-mock/internal/static/js/logs.js tools/platform-mock/internal/frontend_taa_terminal_test.go
git commit -m "feat(platform-mock): add per-instance TAA log terminal state and rendering"
```

---

### Task 2: Wire terminals into instance rows and polling

**Files:**
- Modify: `tools/platform-mock/internal/static/js/api.js`
- Modify: `tools/platform-mock/internal/static/js/app.js`
- Modify: `tools/platform-mock/internal/frontend_taa_terminal_test.go`

- [ ] **Step 1: Write the failing test**

Append to `tools/platform-mock/internal/frontend_taa_terminal_test.go`:

```go
// TestFrontendTaaTerminalRowsAreWired pins that the terminal is mounted by the
// row it belongs to, that its toggle does not select that row, and that the
// page-wide fetch no longer runs on selection changes or on the medium poll
// tier.
func TestFrontendTaaTerminalRowsAreWired(t *testing.T) {
	for _, want := range []string{
		"function buildTaaTerminal(item)",
		"instance-log-toggle",
		"setTaaTerminalExpanded(id, !taaTerminalState(id).expanded)",
		"if (typeof refreshInstanceLogBadges === 'function') refreshInstanceLogBadges();",
		"if (typeof pollTaaTerminals === 'function') pollTaaTerminals();",
	} {
		if !strings.Contains(frontendBundle, want) {
			t.Fatalf("frontendBundle missing %q", want)
		}
	}
	if strings.Contains(frontendBundle, "if (typeof fetchTaaLogs === 'function') fetchTaaLogs();") {
		t.Fatal("selection changes and the medium poll tier still fetch one page-wide TAA log")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd /home/hjy/taa/tools/platform-mock && go test ./internal/ -run 'TestFrontendTaaTerminalRowsAreWired' -count=1`

Expected: FAIL — `frontendBundle missing "instance-log-toggle"`.

- [ ] **Step 3: Add the row toggle, the mount, and the badge refresh in `api.js`**

In `buildInstanceRow`, insert this block immediately before the existing `actions.appendChild(instanceActionButton('公钥', ...` line:

```js
  // The TAA log is per instance: this toggle opens a terminal inside this row.
  // It deliberately does not select the row — two instances are compared side
  // by side, so opening one terminal must not move the rest of the console.
  const logButton = instanceActionButton(
    '日志 (' + (item.taaLogCount || 0) + ') ▾',
    () => setTaaTerminalExpanded(id, !taaTerminalState(id).expanded),
    false,
    '展开/收起该实例的 TAA 运行日志；各实例的终端互相独立',
  );
  logButton.classList.add('instance-log-toggle');
  actions.appendChild(logButton);
```

At the end of `buildInstanceRow`, replace:

```js
  row.appendChild(main);
  row.appendChild(actions);
  return row;
```

with:

```js
  row.appendChild(main);
  row.appendChild(actions);
  // A repaint (selection change or inventory change) rebuilds the row; the
  // terminal comes back from the state map with its filter, keyword, pause and
  // cached lines intact.
  if (taaTerminalState(id).expanded) {
    row.appendChild(buildTaaTerminal(item));
  }
  return row;
```

In `applyInstanceList`, immediately after the `if (signature !== instanceListSignature || next !== instanceRenderedSelection) { ... }` block, add:

```js
  // Counts live outside the repaint signature: patching them in place keeps a
  // single new log line from rebuilding the list under the operator's cursor.
  if (typeof refreshInstanceLogBadges === 'function') refreshInstanceLogBadges();
```

In `refreshInstancePanels`, delete this line:

```js
  if (typeof fetchTaaLogs === 'function') fetchTaaLogs();
```

and update the function comment so it no longer implies logs follow the selection:

```js
// refreshInstancePanels re-reads every instance-scoped panel that follows the
// selection. TAA log terminals are not in that set: each one belongs to its own
// instance and keeps polling regardless of what is selected.
```

In `PollingManager.pollMediumTier`, replace:

```js
      if (typeof fetchTaaLogs === 'function') {
        fetchTaaLogs();
      }
```

with:

```js
      if (typeof pollTaaTerminals === 'function') {
        pollTaaTerminals();
      }
```

In `tools/platform-mock/internal/static/js/app.js`, delete the `fetchTaaLogs();` line in the `DOMContentLoaded` init block (it sits between `fetchModelLogs();` and `initLLMPanel();`). Adjust nothing else.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/hjy/taa/tools/platform-mock && go test ./internal/ -run 'TestFrontendTaaTerminal' -count=1`

Expected: PASS.

- [ ] **Step 5: Run the whole package test suite**

Run: `cd /home/hjy/taa/tools/platform-mock && go test ./internal/ -count=1`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd /home/hjy/taa
git add tools/platform-mock/internal/static/js/api.js tools/platform-mock/internal/static/js/app.js tools/platform-mock/internal/frontend_taa_terminal_test.go
git commit -m "feat(platform-mock): mount TAA log terminals in instance rows"
```

---

### Task 3: Remove the page-wide TAA card and its global state

**Files:**
- Modify: `tools/platform-mock/internal/static/index.html`
- Modify: `tools/platform-mock/internal/static/css/layout.css`
- Modify: `tools/platform-mock/internal/static/css/components.css`
- Modify: `tools/platform-mock/internal/static/js/logs.js`
- Modify: `tools/platform-mock/internal/server_test.go`
- Modify: `tools/platform-mock/internal/frontend_taa_terminal_test.go`

- [ ] **Step 1: Rewrite the failing test**

In `tools/platform-mock/internal/server_test.go`, replace the whole `TestTaaLogConsoleRendering` function with:

```go
func TestTaaLogConsoleRendering(t *testing.T) {
	html := frontendBundle
	// The TAA log is a per-instance terminal inside the instance list now; the
	// page-wide card and every element id it carried are gone.
	for _, gone := range []string{
		`id="card-taaLog"`,
		`id="taaLogOutput"`,
		`id="terminalSearchInput"`,
		`class="log-panels-grid"`,
	} {
		if strings.Contains(html, gone) {
			t.Errorf("frontendBundle still contains %q", gone)
		}
	}
	for _, want := range []string{
		"function buildTaaTerminal(item)",
		"instance-log-toggle",
		"taa-terminal-output",
		"taa-terminal-search",
		`/api/taaLog/status`,
		`/api/taaLog/reset`,
		`(/v1/taa/taaLog)`,
		`id="card-modelLog"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("frontendBundle missing %q", want)
		}
	}

	// The card titles live inside their cards, so neither label is emitted as a
	// standalone heading above the section anymore.
	if strings.Contains(html, `<h2>模型终端日志</h2>`) || strings.Contains(html, `<h2>TAA 运行日志</h2>`) {
		t.Error("log card titles should be rendered inside the card header, not above the section")
	}

	layoutBytes, err := staticFS.ReadFile("static/css/layout.css")
	if err != nil {
		t.Fatalf("failed to read static/css/layout.css: %v", err)
	}
	if strings.Contains(string(layoutBytes), ".log-panels-grid") {
		t.Error("layout.css still defines the removed two-column log grid")
	}

	componentBytes, err := staticFS.ReadFile("static/css/components.css")
	if err != nil {
		t.Fatalf("failed to read static/css/components.css: %v", err)
	}
	if !strings.Contains(string(componentBytes), ".instance-terminal") {
		t.Error("components.css does not style the inline instance terminal")
	}
}
```

Append to `tools/platform-mock/internal/frontend_taa_terminal_test.go`:

```go
// TestFrontendPageWideTaaLogIsGone pins the cleanup: the old card's functions,
// its page-wide flags and its element ids must not survive anywhere, or two
// implementations of the TAA log would drift apart.
func TestFrontendPageWideTaaLogIsGone(t *testing.T) {
	for _, gone := range []string{
		"taaLogPaused",
		"currentLogFilter",
		"currentSearchKeyword",
		"autoScrollLocked",
		"function fetchTaaLogs(",
		"function setLogFilter(",
		"function handleLogSearch(",
		"function applyLogFilteringAndHighlight(",
		"function toggleTaaLogPause(",
		"function clearTaaLogs(",
	} {
		if strings.Contains(frontendBundle, gone) {
			t.Fatalf("frontendBundle still contains %q", gone)
		}
	}
}
```

In `tools/platform-mock/internal/server_test.go`, in the import-card section, change the section boundary from the removed card to the model log card:

```go
	cardLogIdx := strings.Index(importSection, `id="card-modelLog"`)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/hjy/taa/tools/platform-mock && go test ./internal/ -run 'TestTaaLogConsoleRendering|TestFrontendPageWideTaaLogIsGone' -count=1`

Expected: FAIL — `frontendBundle still contains "id=\"card-taaLog\""` and the missing `.instance-terminal` style.

- [ ] **Step 3: Delete the card and the grid from `index.html`**

In `tools/platform-mock/internal/static/index.html`, delete lines **509–559** of the current file (line numbers at the time of writing; verify by content):

- line 509: `  <!-- The two log streams are read together: the model writes them, TAA relays them. -->`
- line 510: `  <div class="log-panels-grid">`
- line 511: `    <div class="log-panels-col">`
- line 512: `      <!-- TAA 运行日志 -->`
- line 513: `      <section class="card" id="card-taaLog">`
- … through the TAA card's closing `</section>` (line 557) and its column's `</div>` (line 558)
- line 559: `    <div class="log-panels-col">` (the second column's opening tag)

Keep line 560 (`      <!-- 模型终端日志 -->`) — it becomes the first line of the surviving block. Then delete the two lines **after** the model card's `</section>` (currently line 591): the column's `</div>` (592) and the grid's `</div>` (593).

The resulting block, from the kept comment to the workspace close, must read exactly:

```html
      <!-- 模型终端日志 -->
      <section class="card" id="card-modelLog">
        ... unchanged card content ...
      </section>

  </div><!-- /#workspaceFlow -->
```

The model card is now a direct child of `#workspaceFlow` and spans the full row; no wrapper element or extra CSS is needed for that.

- [ ] **Step 4: Delete the grid CSS from `layout.css` and add the terminal CSS to `components.css`**

In `tools/platform-mock/internal/static/css/layout.css`, delete the whole block starting at the comment

```css
/* The two log streams are read against each other: the model writes them and
   TAA relays them, so a wide screen puts them side by side. They stack once a
   half column would squeeze the terminal toolbar onto too many rows. */
```

through the media query:

```css
@media (max-width: 1100px) {
  .log-panels-grid {
    grid-template-columns: minmax(0, 1fr);
  }
}
```

Nothing replaces it: the model card is a normal full-width card.

In `tools/platform-mock/internal/static/css/components.css`, append after the `.instance-row-actions` rules:

```css
/* The inline TAA terminal spans the row that owns it. The row is a wrapping
   flex box, so a 100% basis puts the terminal on its own line under the
   instance it belongs to, with no extra wrapper element. */
.instance-terminal {
  flex: 1 0 100%;
  min-width: 0;
}

.instance-terminal .terminal-shell {
  margin-top: 6px;
}

.instance-terminal .terminal-bar {
  gap: 8px;
  flex-wrap: wrap;
}

.terminal-bar-left,
.terminal-bar-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.instance-terminal .terminal-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  flex-wrap: wrap;
  padding: 6px 14px;
  background: #0b1220;
  border-bottom: 1px solid #1e293b;
}

.terminal-search-box {
  position: relative;
  display: inline-flex;
  align-items: center;
}

.terminal-search-box input {
  padding: 3px 44px 3px 8px;
  font-size: 12px;
  height: 24px;
  border-radius: 4px;
  border: 1px solid #1e293b;
  background: #090d16;
  color: #e2e8f0;
}

.taa-terminal-match-count {
  position: absolute;
  right: 8px;
  font-size: 10.5px;
  color: #94a3b8;
  pointer-events: none;
}

.instance-terminal .log-window {
  min-height: 180px;
  max-height: 260px;
  overflow-y: auto;
  font-size: 13px;
  line-height: 1.6;
  padding: 12px 14px;
  margin: 0;
  white-space: pre-wrap;
}
```

- [ ] **Step 5: Delete the old TAA code from `logs.js`**

In `tools/platform-mock/internal/static/js/logs.js`:

1. Delete the globals `taaLogPaused`, `currentLogFilter`, `currentSearchKeyword`, `autoScrollLocked` (keep `modelLogPaused`).
2. Replace `resetLogPauseForInstanceChange` with the model-only version:

```js
// Unpause the model panel after an instance switch: a paused fetch returns
// early, which would leave the previous instance's log lines on screen. TAA
// terminals are not reset here — each is addressed by dockerId and belongs to
// its instance, not to the selection.
function resetLogPauseForInstanceChange() {
  modelLogPaused = false;
  const modelBtn = document.getElementById('modelLogPauseBtn');
  if (modelBtn) {
    modelBtn.textContent = '暂停';
    modelBtn.className = 'secondary';
  }
}
```

3. Delete the whole `// ── TAA Runtime Log ──` section: `fetchTaaLogs`, `toggleTaaLogPause`, `clearTaaLogs`.
4. Delete `setLogFilter`, `handleLogSearch` and `applyLogFilteringAndHighlight` together with their `window.*` exports (the per-terminal `setTaaTerminalFilter` / `onTaaTerminalSearch` / `applyTaaTerminalView` replace them).
5. Replace the `DOMContentLoaded` listener with:

```js
document.addEventListener('DOMContentLoaded', () => {
  document.addEventListener('keydown', (e) => {
    if (e.key !== '/' || !document.activeElement) return;
    const tag = document.activeElement.tagName;
    if (tag === 'INPUT' || tag === 'TEXTAREA') return;
    // There is no single page-wide search box any more: "/" jumps into the
    // selected instance's terminal, and only when that terminal is open.
    const selected = typeof currentInstanceDockerId === 'string' ? currentInstanceDockerId : '';
    const st = taaTerminals.get(selected);
    if (!st || !st.expanded) return;
    const root = findTaaTerminal(selected);
    const input = root && root.querySelector('.taa-terminal-search');
    if (!input) return;
    e.preventDefault();
    input.focus();
    input.select();
  });
});
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd /home/hjy/taa/tools/platform-mock && go test ./internal/ -run 'TestTaaLogConsoleRendering|TestFrontendPageWideTaaLogIsGone|TestFrontendTaaTerminal' -count=1`

Expected: PASS.

- [ ] **Step 7: Run the whole package test suite**

Run: `cd /home/hjy/taa/tools/platform-mock && go test ./internal/ -count=1`

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
cd /home/hjy/taa
git add tools/platform-mock/internal/static/index.html tools/platform-mock/internal/static/css/layout.css tools/platform-mock/internal/static/css/components.css tools/platform-mock/internal/static/js/logs.js tools/platform-mock/internal/server_test.go tools/platform-mock/internal/frontend_taa_terminal_test.go
git commit -m "refactor(platform-mock): remove the page-wide TAA log card"
```

---

### Task 4: Docs, full verification, deploy to 116

**Files:**
- Modify: `tools/platform-mock/README.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Update the README**

In `tools/platform-mock/README.md`, replace the bullet

```markdown
- **Real-Time Progress & Logs**: Displays real-time progress bars, streamed terminal logs (`modelLog`), and TAA daemon operational logs (`taaLog`).
```

with:

```markdown
- **Real-Time Progress & Logs**: Displays real-time progress bars, streamed terminal logs (`modelLog`), and one inline TAA log terminal per instance (`taaLog`). Each terminal is addressed by its own `dockerId`, so two instances can be watched side by side with independent pause, level filter, search and scroll; a collapsed or paused terminal sends no requests. The `日志 (N)` row button shows the instance's retained line count.
```

In the **Instance list** bullet, replace these two lines:

```markdown
  own actions (公钥, 注册返回, 检查连通性, 查看结果 for the row whose check produced the held
  result, 获取证明报告 for TEE).
```

with:

```markdown
  own actions (日志, 公钥, 注册返回, 检查连通性, 查看结果 for the row whose check produced the held
  result, 获取证明报告 for TEE). 日志 toggles an inline terminal under that row; it belongs to the
  row's `dockerId`, not to the selection, and carries its own pause, filter, search and scroll.
```

- [ ] **Step 2: Add the CHANGELOG entry**

Insert a new entry at the top of the appropriate section in `CHANGELOG.md` (follow the file's existing heading style and date `2026-11-19`):

```markdown
- **platform-mock：TAA 日志改为每实例独立终端。** 底部「TAA 运行日志」卡片只跟随选中实例，
  切换行会把操作者正在看的日志整个换掉，且暂停/级别过滤/搜索/滚动锁都是页面级变量，无法同时
  对照两个实例。现在每个实例行带 `日志 (N)` 按钮，在该行下方展开独立终端；状态按 dockerId 保存，
  日志请求始终显式带 `?dockerId=`，收起或暂停的终端不再轮询。底部只保留「模型终端日志」并改为整行
  全宽。
```

- [ ] **Step 3: Verify everything**

Run:

```bash
cd /home/hjy/taa/tools/platform-mock && go test ./internal/ -count=1
cd /home/hjy/taa && gofmt -l tools/platform-mock/internal && go vet ./tools/platform-mock/internal/
```

Expected: tests PASS; `gofmt -l` prints nothing; `go vet` prints nothing.

- [ ] **Step 4: Commit**

```bash
cd /home/hjy/taa
git add tools/platform-mock/README.md CHANGELOG.md
git commit -m "docs(platform-mock): describe per-instance TAA log terminals"
```

- [ ] **Step 5: Deploy to 116 and smoke-check**

```bash
cd /home/hjy/taa
./deploy-platform-mock.sh restart --local \
  --state-dir /home/hjy/.local/share/platform-mock \
  --llm-target http://172.16.10.178:16001 \
  --audit-engine semgrep \
  --semgrep-rules /home/hjy/taa/models/audit/semgrep/rules \
  --instances tee:kata-csv2-taa-test-0001,fhe:fhe-alpha,data-anaylsis:data-beta
curl -s http://127.0.0.1:18081/static/js/logs.js | grep -c 'function buildTaaTerminal'
curl -s http://127.0.0.1:18081/ | grep -c 'card-taaLog'
curl -s http://127.0.0.1:18081/api/instances | head -c 400
```

Expected: deploy reports the mock restarted; the first `grep -c` prints `1`; the second prints `0`; `/api/instances` still lists `kata-csv2-taa-test-0001`.

Manual check in the browser at `http://172.16.10.116:18081/`:
1. Expand `日志` on two rows, set different level filters and keywords, pause one — the other keeps updating.
2. Collapse one terminal, switch the selected instance — both terminals keep their contents and settings.
3. Clear one instance's log — the other terminal is untouched; the cleared row's badge drops to 0.
4. Confirm the bottom area shows only 模型终端日志, full width, still following the selected instance.

---

## Self-Review Notes

- Spec coverage: row toggle and inline terminal (Task 2/3), per-terminal state and explicit `dockerId` requests (Task 1), polling only expanded terminals (Tasks 1/2), card/grid removal (Task 3), error handling and empty state (Task 1 `fetchTaaLogsFor` / `paintTaaTerminal`), tests and docs (Tasks 1/2/3/4), deploy check (Task 4).
- Deliberate non-goals from the spec (no backend changes, no global aggregate view, no export, model log unchanged) are untouched by every task.
- The old card stays functional through Tasks 1–2 so each commit leaves a working console; Task 3 removes it in one commit with its tests.
