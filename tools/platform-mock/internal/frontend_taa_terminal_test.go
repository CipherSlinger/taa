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
