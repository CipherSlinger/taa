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
	if !strings.Contains(fn, "st.scrollTop =") {
		t.Fatal("buildTaaTerminal does not remember this terminal's scroll position")
	}
	if !strings.Contains(fn, "requestAnimationFrame") {
		t.Fatal("buildTaaTerminal does not restore the scroll position once mounted")
	}
	paint := frontendFunction(t, "paintTaaTerminal")
	if !strings.Contains(paint, "st.autoScroll") {
		t.Fatal("paintTaaTerminal does not honour this terminal's scroll lock")
	}
	if !strings.Contains(paint, "st.scrollTop") {
		t.Fatal("paintTaaTerminal does not restore the remembered scroll position")
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
	if strings.Contains(frontendBundle, "fetchTaaLogs();") {
		t.Fatal("a page-wide TAA log fetch is still wired to selection changes or polling")
	}
	rowBuilder := frontendFunction(t, "buildInstanceRow")
	// "toggle does not select": look only at the log toggle itself, since the
	// row's identity button legitimately selects.
	toggleStart := strings.Index(rowBuilder, "const logButton")
	toggleEnd := strings.Index(rowBuilder, "actions.appendChild(logButton)")
	if toggleStart == -1 || toggleEnd == -1 || toggleEnd < toggleStart {
		t.Fatal("cannot delimit the log toggle in buildInstanceRow")
	}
	if strings.Contains(rowBuilder[toggleStart:toggleEnd], "selectInstance") {
		t.Fatal("the log toggle's row builder selects the instance it opens")
	}
	for _, want := range []string{"taaLogBadgeText(id, item)"} {
		if !strings.Contains(rowBuilder, want) {
			t.Fatalf("buildInstanceRow does not use %q", want)
		}
	}
	badgeFn := frontendFunction(t, "taaLogBadgeText")
	if !strings.Contains(badgeFn, "st.expanded && st.fetchedAt") {
		t.Fatal("the row badge does not fall back to the server count once collapsed")
	}
	if !strings.Contains(frontendFunction(t, "refreshInstanceLogBadges"), "taaLogBadgeText(id, item)") {
		t.Fatal("in-place badge refresh does not share the row builder's badge text")
	}
	if strings.Count(frontendFunction(t, "pollTaaTerminals"), "fetchTaaLogsFor(id") != 1 {
		t.Fatal("pollTaaTerminals must reach fetchTaaLogsFor only through the expanded/paused guard")
	}
}
