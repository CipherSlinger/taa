package mock

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

// The host terminal is a shell on the machine the mock runs on, streamed into
// the API-tester tab so an operator can run the generated curl command where it
// belongs — on the host that can reach the Pod — instead of copying it to
// another window.
//
// The mock already runs on that host, so the shell does not cross SSH: it is a
// child of this process, attached to a real PTY so interactive programs (an
// editor, `top`, a pager) behave. The panel has no console login of its own —
// it is a block of the console page, and connecting is one click.
//
// The origin check below is the remaining gate: it stops a page on another
// origin from opening a socket in the operator's browser. It does not stop a
// non-browser client that can reach this port, and the shell runs as whatever
// user started the mock (root on the deployed host), so the mock is meant for a
// trusted network.
const (
	terminalMaxSessions = 4
	// terminalDrainGrace is how long the session waits after the shell exits for
	// the last bytes to come through the PTY. Without it the final line of a
	// command that exits immediately ("echo x; exit") is often lost.
	terminalDrainGrace = 300 * time.Millisecond
)

// terminalPingInterval keeps an idle tab connected: the browser answers a
// protocol ping with a pong automatically, so a session with no typing stays up
// while the tab exists instead of dying on an idle timer.
var terminalPingInterval = 60 * time.Second

// terminalIdleTimeout is how long the server waits for any frame — a keystroke,
// a resize or a pong — before it treats the socket as dead and kills the shell.
// Pings land well inside it, so a live tab is never closed; a tab closed without
// a close frame, or a network that silently dropped, is reaped after this.
var terminalIdleTimeout = 5 * time.Minute

// terminalMessage is one frame in either direction.
//
//	{type:"input", data:"ls\r"}      keystrokes from the browser
//	{type:"resize", cols:120, rows:30}
//	{type:"output", data:"..."}      terminal output, server to browser
//	{type:"exit", code:0, message:""}
type terminalMessage struct {
	Type    string `json:"type"`
	Data    string `json:"data,omitempty"`
	Cols    uint   `json:"cols,omitempty"`
	Rows    uint   `json:"rows,omitempty"`
	Code    int    `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

var terminalUpgrader = websocket.Upgrader{
	// Same-origin only. The console is served from this process, and a shell is
	// not something to hand to a page on another origin even with a cookie.
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			// A non-browser client (a script reusing the cookie) sends no Origin.
			return true
		}
		return originMatchesHost(origin, r.Host)
	},
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
}

// originMatchesHost compares an Origin header's host:port with the request's
// Host. A mismatch means the page asking belongs to a different origin.
func originMatchesHost(origin, host string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, host)
}

// terminalSessions bounds concurrent shells. Each one is a process tree on the
// host; an unbounded count turns stuck browser tabs into a fork bomb.
type terminalSessions struct {
	mu   sync.Mutex
	live int
}

func newTerminalSessions() *terminalSessions { return &terminalSessions{} }

func (t *terminalSessions) acquire() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.live >= terminalMaxSessions {
		return false
	}
	t.live++
	return true
}

func (t *terminalSessions) release() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.live > 0 {
		t.live--
	}
}

// hostTerminalHandler upgrades to a WebSocket and runs a shell on this host.
func hostTerminalHandler(sessions *terminalSessions, shell string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !sessions.acquire() {
			writeEnvelope(w, http.StatusTooManyRequests,
				"宿主机终端数量已达上限（"+strconv.Itoa(terminalMaxSessions)+" 个），请先关闭其它终端",
				nil, http.StatusTooManyRequests)
			return
		}
		conn, err := terminalUpgrader.Upgrade(w, r, nil)
		if err != nil {
			// Upgrade already wrote its own error response.
			sessions.release()
			return
		}
		defer sessions.release()
		runHostTerminal(conn, shell)
	}
}

// runHostTerminal owns one shell for the lifetime of conn.
func runHostTerminal(conn *websocket.Conn, shell string) {
	defer conn.Close()
	shell, shellArgs := terminalShellArgs(shell)

	master, slavePath, err := openPTY()
	if err != nil {
		log.Printf("host terminal: %v", err)
		sendTerminalExit(conn, 1, err.Error())
		return
	}
	defer master.Close()

	slave, err := openPTYSlave(slavePath)
	if err != nil {
		sendTerminalExit(conn, 1, "打开 PTY 从设备失败: "+err.Error())
		return
	}
	cmd := exec.Command(shell, shellArgs...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.Env = terminalEnv()
	cmd.SysProcAttr = newTerminalSysProcAttr()
	startErr := cmd.Start()
	// The child holds its own copy of the slave. Closing ours is what lets the
	// master read see EIO once the shell and everything it started are gone.
	_ = slave.Close()
	if startErr != nil {
		sendTerminalExit(conn, 1, "启动宿主机 shell 失败: "+startErr.Error())
		return
	}
	pid := cmd.Process.Pid
	log.Printf("host terminal opened: shell=%s pid=%d", shell, pid)

	var writeMu sync.Mutex
	write := func(msg terminalMessage) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return conn.WriteJSON(msg)
	}

	outputDone := make(chan struct{})
	go func() {
		defer close(outputDone)
		// A small buffer keeps a keystroke's echo immediate: a larger one waits for
		// more data before delivering what it already holds.
		buf := make([]byte, 8192)
		for {
			n, readErr := master.Read(buf)
			if n > 0 {
				if err := write(terminalMessage{Type: "output", Data: string(buf[:n])}); err != nil {
					return
				}
			}
			if readErr != nil {
				if !isPTYClosed(readErr) {
					log.Printf("host terminal read: %v", readErr)
				}
				return
			}
		}
	}()

	// inputDone fires when the browser stops sending: a closed tab, a dead
	// network, or the idle deadline. The deadline is reset by a pong as well as
	// by input, which is what lets an idle tab stay open indefinitely.
	inputDone := make(chan struct{})
	pingDone := make(chan struct{})
	_ = conn.SetReadDeadline(time.Now().Add(terminalIdleTimeout))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(terminalIdleTimeout))
	})
	go func() {
		ticker := time.NewTicker(terminalPingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)); err != nil {
					return
				}
			case <-pingDone:
				return
			}
		}
	}()
	go func() {
		defer close(inputDone)
		for {
			var msg terminalMessage
			if err := conn.ReadJSON(&msg); err != nil {
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(terminalIdleTimeout))
			switch msg.Type {
			case "input":
				if _, err := master.WriteString(msg.Data); err != nil {
					return
				}
			case "resize":
				if err := resizePTY(master, msg.Cols, msg.Rows); err != nil {
					// Not fatal: the shell keeps working at its default size.
					log.Printf("host terminal resize: %v", err)
				}
			}
		}
	}()

	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()

	// The session ends when either side does. If the browser left first the
	// shell's tree is killed, because nothing will ever read its output again.
	select {
	case <-inputDone:
		killSession(pid)
		<-waitDone
	case waitErr := <-waitDone:
		code := 0
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			code = exitErr.ExitCode()
		}
		// Let the output loop deliver what the PTY still holds, then report.
		select {
		case <-outputDone:
		case <-time.After(terminalDrainGrace):
		}
		_ = write(terminalMessage{Type: "exit", Code: code})
	}
	close(pingDone)
	_ = conn.Close()
	log.Printf("host terminal closed: pid=%d", pid)
}

// terminalShellArgs picks the shell and its arguments. A login shell is used so
// the operator gets the host's own PATH, aliases and prompt rather than the
// daemon's environment; a bare sh has no --login and no history.
func terminalShellArgs(shell string) (string, []string) {
	if strings.TrimSpace(shell) == "" {
		shell = "/bin/bash"
	}
	switch shellBaseName(shell) {
	case "bash", "zsh", "ksh":
		return shell, []string{"--login"}
	case "sh", "ash", "dash":
		return shell, nil
	default:
		return shell, nil
	}
}

func shellBaseName(path string) string {
	if idx := strings.LastIndexByte(path, '/'); idx >= 0 {
		return path[idx+1:]
	}
	return path
}

// terminalEnv is the environment the shell starts with. TERM is set because a
// process without it makes full-screen programs fail; the rest is inherited so
// the operator gets the host's own PATH and kubeconfig.
func terminalEnv() []string {
	env := os.Environ()
	out := make([]string, 0, len(env)+1)
	hasTerm := false
	for _, kv := range env {
		if strings.HasPrefix(kv, "TERM=") {
			hasTerm = true
		}
		out = append(out, kv)
	}
	if !hasTerm {
		out = append(out, "TERM=xterm-256color")
	}
	return out
}

// isPTYClosed reports whether a read error is the normal end of a PTY: Linux
// returns EIO, not io.EOF, once every slave descriptor is closed.
func isPTYClosed(err error) bool {
	return errors.Is(err, syscall.EIO) || errors.Is(err, os.ErrClosed)
}

func sendTerminalExit(conn *websocket.Conn, code int, message string) {
	_ = conn.WriteJSON(terminalMessage{Type: "exit", Code: code, Message: message})
}
