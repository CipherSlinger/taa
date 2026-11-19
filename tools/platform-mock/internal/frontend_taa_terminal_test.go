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
		"function fetchTaaLogsFor(id, force)",
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

// TestFrontendTaaTerminalModuleDoesNotFollowTheSelection pins the hard rule
// from the spec: the terminal module must not go through the selected-instance
// helpers or any page-wide TAA log state. Only the new module block is checked,
// so the old card (removed in a later task) does not mask a regression here.
func TestFrontendTaaTerminalModuleDoesNotFollowTheSelection(t *testing.T) {
	src, err := staticFS.ReadFile("static/js/logs.js")
	if err != nil {
		t.Fatalf("failed to read static/js/logs.js: %v", err)
	}
	logs := string(src)
	start := strings.Index(logs, "// ── Per-instance TAA terminals ──")
	if start == -1 {
		t.Fatal("logs.js has no per-instance terminal module")
	}
	module := logs[start:]
	for _, gone := range []string{
		"mockFetch",
		"withDockerId",
		"currentInstanceDockerId",
		"taaLogPaused",
		"currentSearchKeyword",
		"currentLogFilter",
		"autoScrollLocked",
	} {
		if strings.Contains(module, gone) {
			t.Fatalf("the terminal module still references %q", gone)
		}
	}
	if !strings.Contains(module, "fetchTaaLogsFor(id, true)") {
		t.Fatal("the refresh button does not force a fetch while paused")
	}
}

// TestFrontendTaaLogFetchKeepsLinesOnFailure pins that a failed poll leaves the
// cached lines alone: blanking the window on a transient error would look like
// the instance had no logs.
func TestFrontendTaaLogFetchKeepsLinesOnFailure(t *testing.T) {
	fn := frontendFunction(t, "fetchTaaLogsFor")
	if strings.Contains(fn, "st.entries = []") {
		t.Fatal("a failed fetch clears the cached lines")
	}
}

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
