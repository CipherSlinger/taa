package mock

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// terminalShortcutCounters records the side effects one "/" keydown produced:
// how often the handler called preventDefault, focused the search box and
// selected its contents.
type terminalShortcutCounters struct {
	Prevented int `json:"prevented"`
	Focused   int `json:"focused"`
	Selected  int `json:"selected"`
}

type terminalShortcutResult struct {
	Collapsed terminalShortcutCounters `json:"collapsed"`
	Expanded  terminalShortcutCounters `json:"expanded"`
	Absent    terminalShortcutCounters `json:"absent"`
}

// renderCacheResult reports how many times the render cache wrote a row, and
// the last HTML it wrote.
type renderCacheResult struct {
	Same         int    `json:"same"`
	AfterKeyword int    `json:"afterKeyword"`
	HTML         string `json:"html"`
}

// TestFrontendTerminalShortcutKey drives the production logs.js keydown handler.
// "/" must jump into the selected instance's terminal only while that terminal is
// open: a collapsed terminal has no search box on screen to focus, and an
// instance without state has nothing to address at all.
func TestFrontendTerminalShortcutKey(t *testing.T) {
	body := `listeners.DOMContentLoaded.forEach((fn) => fn());
// drawer.js registers its own keydown listener at load time; logs.js installs
// its handler during DOMContentLoaded, so it is the last one.
const keydown = listeners.keydown[listeners.keydown.length - 1];
if (!keydown) throw new Error('logs.js did not register a keydown handler');

let focused = 0, selectedCalls = 0, prevented = 0;
const input = { focus() { focused++; }, select() { selectedCalls++; } };
const terminal = {
  dataset: { terminalFor: 'a' },
  querySelector(sel) { return sel === '.taa-terminal-search' ? input : null; },
};
terminals.push(terminal);

taaTerminals.set('a', { expanded: false });
keydown({ key: '/', preventDefault() { prevented++; } });
const collapsed = { prevented, focused, selected: selectedCalls };

taaTerminals.set('a', { expanded: true });
keydown({ key: '/', preventDefault() { prevented++; } });
const expanded = { prevented, focused, selected: selectedCalls };

// The selected instance has no terminal state at all.
globalThis.currentInstanceDockerId = 'missing';
keydown({ key: '/', preventDefault() { prevented++; } });
const absent = { prevented, focused, selected: selectedCalls };

process.stdout.write(JSON.stringify({ collapsed, expanded, absent }));`

	var got terminalShortcutResult
	decodeLogsHarness(t, body, &got)

	if got.Collapsed != (terminalShortcutCounters{}) {
		t.Errorf("collapsed terminal: got %+v, want no preventDefault and no focus", got.Collapsed)
	}
	wantExpanded := terminalShortcutCounters{Prevented: 1, Focused: 1, Selected: 1}
	if got.Expanded != wantExpanded {
		t.Errorf("expanded terminal: got %+v, want %+v", got.Expanded, wantExpanded)
	}
	if got.Absent != wantExpanded {
		t.Errorf("instance without state: got %+v, want the shortcut to stay inert (%+v)", got.Absent, wantExpanded)
	}
}

// TestFrontendTerminalRenderCache pins that applyTaaTerminalView rewrites a row
// only when the rendered view changes. The row's text is constant for the life
// of the node, so the keyword alone identifies what is on screen; keying on the
// raw text would keep a second copy of every line in the DOM for nothing.
func TestFrontendTerminalRenderCache(t *testing.T) {
	body := `let writes = 0;
let lastHtml = '';
const msg = {
  dataset: {},
  set innerHTML(v) { writes++; lastHtml = v; },
};
const row = {
  style: {},
  dataset: { rawText: 'say "hi" <b>', level: 'INFO' },
  querySelector(sel) { return sel === '.log-msg' ? msg : null; },
};
const badge = { textContent: '' };
const out = {
  querySelectorAll(sel) { return sel === '.log-row' ? [row] : []; },
};
const root = {
  querySelector(sel) {
    if (sel === '.taa-terminal-output') return out;
    if (sel === '.taa-terminal-match-count') return badge;
    return null;
  },
};
const st = { level: 'ALL', keyword: '' };
applyTaaTerminalView(root, st);
applyTaaTerminalView(root, st);
const same = writes;

st.keyword = 'hi';
applyTaaTerminalView(root, st);

process.stdout.write(JSON.stringify({ same, afterKeyword: writes, html: lastHtml }));`

	var got renderCacheResult
	decodeLogsHarness(t, body, &got)

	if got.Same != 1 {
		t.Errorf("two identical paints wrote the row %d times, want 1", got.Same)
	}
	if got.AfterKeyword != 2 {
		t.Errorf("changing the keyword left write count at %d, want 2", got.AfterKeyword)
	}
	for _, want := range []string{"&quot;", "&lt;", `<mark class="hl-match">hi</mark>`} {
		if !strings.Contains(got.HTML, want) {
			t.Errorf("rendered row %q is missing escaped/highlighted fragment %q", got.HTML, want)
		}
	}
	if strings.Contains(got.HTML, "<b>") {
		t.Errorf("rendered row %q passed raw markup through innerHTML", got.HTML)
	}
}

// decodeLogsHarness runs body against the real static/js/logs.js and decodes its
// JSON reply into out.
func decodeLogsHarness(t *testing.T, body string, out any) {
	t.Helper()

	nodePath, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not found in PATH; skipping browser-side terminal behavior test")
	}
	jsSource, err := staticFS.ReadFile("static/js/logs.js")
	if err != nil {
		t.Fatalf("read static/js/logs.js: %v", err)
	}
	escapeSource, err := staticFS.ReadFile("static/js/drawer.js")
	if err != nil {
		t.Fatalf("read static/js/drawer.js: %v", err)
	}

	// The stubs cover everything the production files touch at load time;
	// globals the appended body needs (listeners, terminals) stay visible because
	// a node script shares one top-level scope.
	prelude := `// Generated by frontend_terminal_behavior_test.go: run the production
// logs.js in node behind minimal DOM stubs.
globalThis.window = globalThis;
const listeners = {};
let terminals = [];
globalThis.document = {
  addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
  querySelectorAll(sel) { return sel === '.instance-terminal' ? terminals : []; },
  getElementById() { return null; },
  activeElement: { tagName: 'BODY' },
};
globalThis.currentInstanceDockerId = 'a';
globalThis.fetch = () => Promise.reject(new Error('network disabled in test'));
`

	harness := prelude + "\n" + string(escapeSource) + "\n" + string(jsSource) + "\n" + body + "\n"

	harnessPath := filepath.Join(t.TempDir(), "terminal_harness.js")
	if err := os.WriteFile(harnessPath, []byte(harness), 0o600); err != nil {
		t.Fatalf("write node harness: %v", err)
	}
	raw, err := exec.Command(nodePath, harnessPath).CombinedOutput()
	if err != nil {
		t.Fatalf("node harness failed: %v\noutput: %s", err, raw)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("decode harness output %q: %v", raw, err)
	}
}
