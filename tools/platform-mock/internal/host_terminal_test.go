package mock

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestOriginMatchesHost(t *testing.T) {
	cases := []struct {
		name   string
		origin string
		host   string
		want   bool
	}{
		{"same host and port", "http://172.16.10.178:18081", "172.16.10.178:18081", true},
		{"case-insensitive host", "http://Example.LOCAL:8080", "example.local:8080", true},
		{"other host", "http://evil.example:18081", "172.16.10.178:18081", false},
		{"other port", "http://172.16.10.178:9999", "172.16.10.178:18081", false},
		{"not a url", "::::", "172.16.10.178:18081", false},
		{"empty origin", "", "172.16.10.178:18081", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := originMatchesHost(tc.origin, tc.host); got != tc.want {
				t.Fatalf("originMatchesHost(%q, %q) = %v, want %v", tc.origin, tc.host, got, tc.want)
			}
		})
	}
}

func TestTerminalSessionsCap(t *testing.T) {
	sessions := newTerminalSessions()
	for i := 0; i < terminalMaxSessions; i++ {
		if !sessions.acquire() {
			t.Fatalf("acquire #%d refused below the cap", i+1)
		}
	}
	if sessions.acquire() {
		t.Fatal("acquire should refuse at the cap")
	}
	sessions.release()
	if !sessions.acquire() {
		t.Fatal("acquire should succeed after a release")
	}
}

// TestHostTerminalNeedsNoConsoleSession pins the removal of the login gate: the
// panel is part of the console page, so the socket must not answer 401 when no
// session cookie is present.
func TestHostTerminalNeedsNoConsoleSession(t *testing.T) {
	handler := hostTerminalHandler(newTerminalSessions(), "")
	req := httptest.NewRequest(http.MethodGet, "/api/host/terminal", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code == http.StatusUnauthorized {
		t.Fatal("the terminal still requires a console session")
	}
}

// TestHostTerminalRefusesAForeignOrigin proves the origin check runs before a
// shell is started: a page on another origin holding the cookie cannot open one.
func TestHostTerminalRefusesAForeignOrigin(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the terminal needs a Linux PTY")
	}
	server := httptest.NewServer(hostTerminalHandler(newTerminalSessions(), "/bin/sh"))

	header := http.Header{}
	header.Set("Origin", "http://evil.example")
	_, resp, err := websocket.DefaultDialer.Dial(wsURL(server.URL), header)
	if err == nil {
		t.Fatal("dial succeeded from a foreign origin")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("handshake status = %d, want 403", status)
	}
}

// TestHostTerminalRunsAShellOnThisHost is the end-to-end check: a socket with
// no cookie at all sends a command and receives its output, which is what the
// panel does.
func TestHostTerminalRunsAShellOnThisHost(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the terminal needs a Linux PTY")
	}
	server := httptest.NewServer(hostTerminalHandler(newTerminalSessions(), "/bin/sh"))
	defer server.Close()

	conn, _, err := websocket.DefaultDialer.Dial(wsURL(server.URL), http.Header{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := conn.WriteJSON(terminalMessage{Type: "resize", Cols: 100, Rows: 30}); err != nil {
		t.Fatalf("resize: %v", err)
	}
	if err := conn.WriteJSON(terminalMessage{Type: "input", Data: "echo terminal-ok\n"}); err != nil {
		t.Fatalf("input: %v", err)
	}

	output := collectTerminalOutput(t, conn, 5*time.Second, "terminal-ok")
	if !strings.Contains(output, "terminal-ok") {
		t.Fatalf("output = %q, want it to contain terminal-ok", output)
	}

	// The window size must reach the shell, or a full-screen program would draw
	// for the wrong geometry. `stty size` reports what the kernel applied.
	if err := conn.WriteJSON(terminalMessage{Type: "input", Data: "stty size\n"}); err != nil {
		t.Fatalf("input: %v", err)
	}
	output = collectTerminalOutput(t, conn, 5*time.Second, "30 100")
	if !strings.Contains(output, "30 100") {
		t.Fatalf("output = %q, want it to report the applied window size 30 100", output)
	}

	// The shell exiting must produce an exit frame rather than a silent close.
	if err := conn.WriteJSON(terminalMessage{Type: "input", Data: "exit\n"}); err != nil {
		t.Fatalf("input: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		var msg terminalMessage
		if err := conn.ReadJSON(&msg); err != nil {
			t.Fatalf("waiting for the exit frame: %v", err)
		}
		if msg.Type == "exit" {
			return
		}
	}
}

func wsURL(serverURL string) string {
	return "ws" + strings.TrimPrefix(serverURL, "http") + "/api/host/terminal"
}

// collectTerminalOutput reads frames until want appears or the deadline passes.
func collectTerminalOutput(t *testing.T, conn *websocket.Conn, timeout time.Duration, want string) string {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	var sb strings.Builder
	for {
		var msg terminalMessage
		if err := conn.ReadJSON(&msg); err != nil {
			return sb.String()
		}
		if msg.Type == "output" {
			sb.WriteString(msg.Data)
			if strings.Contains(sb.String(), want) {
				return sb.String()
			}
		}
	}
}

func TestTerminalShellArgs(t *testing.T) {
	cases := []struct {
		shell    string
		wantPath string
		wantArgs []string
	}{
		{"", "/bin/bash", []string{"--login"}},
		{"/bin/bash", "/bin/bash", []string{"--login"}},
		{"/usr/bin/zsh", "/usr/bin/zsh", []string{"--login"}},
		{"/bin/sh", "/bin/sh", nil},
		{"/bin/dash", "/bin/dash", nil},
	}
	for _, tc := range cases {
		path, args := terminalShellArgs(tc.shell)
		if path != tc.wantPath {
			t.Errorf("terminalShellArgs(%q) path = %q, want %q", tc.shell, path, tc.wantPath)
		}
		if len(args) != len(tc.wantArgs) {
			t.Errorf("terminalShellArgs(%q) args = %v, want %v", tc.shell, args, tc.wantArgs)
			continue
		}
		for i := range args {
			if args[i] != tc.wantArgs[i] {
				t.Errorf("terminalShellArgs(%q) args = %v, want %v", tc.shell, args, tc.wantArgs)
				break
			}
		}
	}
}

// TestHostTerminalIsMountedInTheAPITester ties the panel to where the user asked
// for it: below the generated curl command, inside the API-test tab.
func TestHostTerminalIsMountedInTheAPITester(t *testing.T) {
	curlAt := strings.Index(indexHTML, `id="apiTesterCurl"`)
	panelAt := strings.Index(indexHTML, `id="hostTerminalPanel"`)
	if curlAt < 0 || panelAt < 0 {
		t.Fatalf("index.html missing the curl block (%d) or the terminal panel (%d)", curlAt, panelAt)
	}
	if panelAt < curlAt {
		t.Fatal("the terminal panel must follow the curl command, not precede it")
	}
	apiTabAt := strings.Index(indexHTML, `id="workspaceApi"`)
	workspaceEnd := strings.Index(indexHTML, `/#workspaceApi`)
	if apiTabAt < 0 || workspaceEnd < 0 || panelAt > workspaceEnd {
		t.Fatal("the terminal panel must live inside the API-test tab")
	}
	for _, want := range []string{
		`/static/vendor/xterm/xterm.min.js`,
		`/static/vendor/xterm/addon-fit.min.js`,
		`/static/js/host-terminal.js`,
		`onclick="hostTerminalConnect()"`,
	} {
		if !strings.Contains(indexHTML, want) {
			t.Errorf("index.html missing %q", want)
		}
	}
	// The client must speak the same frame types the server switches on.
	for _, frame := range []string{`type: 'input'`, `type: 'resize'`, `'output'`, `'exit'`} {
		if !strings.Contains(frontendBundle, frame) {
			t.Errorf("host-terminal.js missing the %q frame handling", frame)
		}
	}
	// No console login: the panel is a block of the page, not a second sign-in.
	for _, gone := range []string{
		`id="hostTerminalLoginForm"`,
		`id="hostTerminalPassword"`,
		`hostTerminalLogin(`,
		`sessionIsLive(`,
	} {
		if strings.Contains(indexHTML, gone) || strings.Contains(frontendBundle, gone) {
			t.Errorf("the terminal still carries the console login: %q", gone)
		}
	}
}

func TestHostTerminalRejectsMalformedFrames(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the terminal needs a Linux PTY")
	}
	server := httptest.NewServer(hostTerminalHandler(newTerminalSessions(), "/bin/sh"))
	defer server.Close()

	conn, _, err := websocket.DefaultDialer.Dial(wsURL(server.URL), http.Header{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// An unknown frame type is ignored rather than treated as input: a client
	// bug must not end up typed into the shell.
	if err := conn.WriteJSON(map[string]any{"type": "who-knows", "data": "echo nope\n"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := conn.WriteJSON(terminalMessage{Type: "input", Data: "echo after-unknown\n"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	output := collectTerminalOutput(t, conn, 5*time.Second, "after-unknown")
	if strings.Contains(output, "nope") {
		t.Fatalf("an unknown frame was executed: %q", output)
	}
}

func TestTerminalMessageJSONShape(t *testing.T) {
	raw, err := json.Marshal(terminalMessage{Type: "resize", Cols: 120, Rows: 40})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(raw) != `{"type":"resize","cols":120,"rows":40}` {
		t.Fatalf("frame = %s", raw)
	}
}

// TestHostTerminalStopsBackgroundJobsOnClose pins the leak that a process-group
// kill leaves behind: an interactive shell puts every `cmd &` in its own process
// group (that is what job control is), so only session-wide cleanup reaches it.
// Verified against the bug: with a group kill the job survives.
func TestHostTerminalStopsBackgroundJobsOnClose(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the terminal needs a Linux PTY")
	}
	server := httptest.NewServer(hostTerminalHandler(newTerminalSessions(), "/bin/bash"))
	defer server.Close()

	conn, _, err := websocket.DefaultDialer.Dial(wsURL(server.URL), http.Header{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// A fractional duration no other process would use, so the check cannot
	// match a bystander sleep. `&` is the point: it is what moves the job into
	// its own process group.
	marker := "sleep 247." + strconv.Itoa(1000+os.Getpid()%1000)
	if err := conn.WriteJSON(terminalMessage{Type: "input", Data: marker + " &\n"}); err != nil {
		t.Fatalf("input: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !processWithArg(marker) {
		if time.Now().After(deadline) {
			t.Fatalf("the background job %q never started", marker)
		}
		time.Sleep(50 * time.Millisecond)
	}

	conn.Close()
	deadline = time.Now().Add(5 * time.Second)
	for processWithArg(marker) {
		if time.Now().After(deadline) {
			t.Fatalf("the background job %q outlived the closed terminal", marker)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// processWithArg reports whether any /proc entry's command line contains want.
func processWithArg(want string) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		cmdline, err := os.ReadFile("/proc/" + entry.Name() + "/cmdline")
		if err != nil {
			continue
		}
		if strings.Contains(strings.ReplaceAll(string(cmdline), "\x00", " "), want) {
			return true
		}
	}
	return false
}
