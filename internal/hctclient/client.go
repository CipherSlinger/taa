// Package hctclient starts and talks to the taa-hct-helper process. TAA keeps
// its pure-Go, statically linked build contract; libhct is only ever loaded by
// the helper.
package hctclient

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"taa/internal/hctproto"
)

// ErrUnavailable reports that the helper is not usable (failed to start, died,
// or timed out). The caller must fail closed; there is no fallback.
var ErrUnavailable = errors.New("hctclient: HCT helper unavailable")

// DefaultRequestTimeout bounds a single request when the caller's context has
// no deadline.
const DefaultRequestTimeout = 30 * time.Second

// Config describes how to launch the helper.
type Config struct {
	HelperPath     string
	LoaderPath     string
	LibDir         string
	Accel          string
	RequireVersion string
	RequestTimeout time.Duration
	// ExtraArgs is appended to the helper command line. Tests use it to run
	// the test binary as a fake helper; production never sets it.
	ExtraArgs []string
}

// Hello is the helper identity returned by the handshake.
type Hello struct {
	Version string
	Accel   string
	BuildID string
}

// StatusError is a failed response carrying a protocol status. Stream and
// signature failures keep their own status values so callers can distinguish
// an authentication failure from an internal error.
type StatusError struct {
	Status  uint16
	Message string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("hctclient: helper status %d: %s", e.Status, e.Message)
}

type callResult struct {
	status  uint16
	payload []byte
	err     error
}

// Client is a started helper process. It is safe for concurrent use.
type Client struct {
	cfg    Config
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	lifeFD *os.File // write end of the parent-death pipe

	writeMu   sync.Mutex
	pendingMu sync.Mutex
	pending   map[uint64]chan callResult
	nextID    atomic.Uint64

	done      chan struct{}
	exited    chan struct{}
	closeOnce sync.Once
	doneOnce  sync.Once

	errMu sync.Mutex
	err   error

	stderr *boundedBuffer
	hello  Hello
}

// Start launches the helper, performs the HELLO handshake and verifies the
// libhct version prefix. Any failure kills the process and returns an error.
func Start(cfg Config) (*Client, error) {
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = DefaultRequestTimeout
	}
	if cfg.Accel == "" {
		cfg.Accel = "sw"
	}
	if err := validatePaths(&cfg); err != nil {
		return nil, err
	}

	args := buildArgs(cfg)
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = []string{
		"PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
		"TZ=UTC",
		"LANG=C",
		"LC_ALL=C",
		"HCT_LOG_LEVEL=error",
	}
	configureProcAttr(cmd)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("hctclient: stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("hctclient: stdout pipe: %w", err)
	}

	// Parent-death pipe: the helper watches fd 3 and exits when TAA closes it
	// (including when TAA is killed). Pdeathsig is deliberately not used: Go
	// delivers it when the creating OS thread exits, which the runtime may do
	// for unrelated reasons, killing a healthy helper.
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("hctclient: death pipe: %w", err)
	}
	cmd.ExtraFiles = []*os.File{pr}
	stderr := newBoundedBuffer(8 << 10)
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return nil, fmt.Errorf("hctclient: start helper: %w", err)
	}
	_ = pr.Close()

	c := &Client{
		cfg:     cfg,
		cmd:     cmd,
		stdin:   stdin,
		stdout:  stdout,
		lifeFD:  pw,
		pending: make(map[uint64]chan callResult),
		done:    make(chan struct{}),
		exited:  make(chan struct{}),
		stderr:  stderr,
	}
	go c.readLoop()
	go c.waitLoop()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.RequestTimeout)
	defer cancel()
	resp, err := c.Call(ctx, hctproto.OpHello, nil)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("hctclient: handshake: %w%s", err, c.stderrSuffix())
	}
	hello, err := parseHello(resp)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("hctclient: handshake: %w", err)
	}
	if cfg.RequireVersion != "" && !versionSatisfies(hello.Version, cfg.RequireVersion) {
		_ = c.Close()
		return nil, fmt.Errorf("hctclient: libhct version %q does not match required %q",
			hello.Version, cfg.RequireVersion)
	}
	c.hello = hello
	return c, nil
}

func validatePaths(cfg *Config) error {
	if cfg.HelperPath == "" || !filepath.IsAbs(cfg.HelperPath) {
		return fmt.Errorf("hctclient: helper path must be absolute: %q", cfg.HelperPath)
	}
	info, err := os.Stat(cfg.HelperPath)
	if err != nil {
		return fmt.Errorf("hctclient: stat helper: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("hctclient: helper is not an executable file: %s", cfg.HelperPath)
	}
	if cfg.LoaderPath != "" {
		if !filepath.IsAbs(cfg.LoaderPath) {
			return fmt.Errorf("hctclient: loader path must be absolute: %q", cfg.LoaderPath)
		}
		if _, err := os.Stat(cfg.LoaderPath); err != nil {
			return fmt.Errorf("hctclient: stat loader: %w", err)
		}
		if cfg.LibDir == "" || !filepath.IsAbs(cfg.LibDir) {
			return fmt.Errorf("hctclient: lib dir must be absolute when a loader is used: %q", cfg.LibDir)
		}
	}
	return nil
}

func buildArgs(cfg Config) []string {
	var args []string
	if cfg.LoaderPath != "" {
		args = append(args, cfg.LoaderPath, "--library-path", cfg.LibDir)
	}
	args = append(args, cfg.HelperPath, "--serve", "--accel", cfg.Accel)
	args = append(args, cfg.ExtraArgs...)
	return args
}

// Hello returns the handshake identity.
func (c *Client) Hello() Hello { return c.hello }

// Err reports why the helper became unavailable, if it did.
func (c *Client) Err() error {
	c.errMu.Lock()
	defer c.errMu.Unlock()
	return c.err
}

func (c *Client) dead() error {
	select {
	case <-c.done:
		return ErrUnavailable
	default:
		return nil
	}
}

// Call sends one request and waits for its response.
func (c *Client) Call(ctx context.Context, op uint16, payload []byte) ([]byte, error) {
	if err := c.dead(); err != nil {
		return nil, err
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.cfg.RequestTimeout)
		defer cancel()
	}

	id := c.nextID.Add(1)
	ch := make(chan callResult, 1)
	c.pendingMu.Lock()
	c.pending[id] = ch
	c.pendingMu.Unlock()

	frame, err := hctproto.Encode(hctproto.Header{
		Version: hctproto.Version,
		Op:      op,
		ReqID:   id,
	}, payload)
	if err != nil {
		c.removePending(id)
		return nil, fmt.Errorf("hctclient: encode request: %w", err)
	}
	c.writeMu.Lock()
	_, werr := c.stdin.Write(frame)
	c.writeMu.Unlock()
	if werr != nil {
		c.removePending(id)
		c.shutdown(fmt.Errorf("write to helper: %w", werr))
		return nil, ErrUnavailable
	}

	select {
	case res := <-ch:
		if res.err != nil {
			return nil, res.err
		}
		if res.status != hctproto.StatusOK {
			return nil, &StatusError{Status: res.status, Message: string(res.payload)}
		}
		return res.payload, nil
	case <-ctx.Done():
		c.removePending(id)
		c.shutdown(fmt.Errorf("request timed out: %w", ctx.Err()))
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, ctx.Err())
	case <-c.done:
		c.removePending(id)
		return nil, ErrUnavailable
	}
}

// Ping checks that the helper still answers.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.Call(ctx, hctproto.OpPing, nil)
	return err
}

func (c *Client) removePending(id uint64) {
	c.pendingMu.Lock()
	delete(c.pending, id)
	c.pendingMu.Unlock()
}

func (c *Client) readLoop() {
	r := bufio.NewReaderSize(c.stdout, 64<<10)
	for {
		h, payload, err := hctproto.ReadFrame(r)
		if err != nil {
			c.shutdown(fmt.Errorf("read from helper: %w", err))
			return
		}
		c.pendingMu.Lock()
		ch, ok := c.pending[h.ReqID]
		if ok {
			delete(c.pending, h.ReqID)
		}
		c.pendingMu.Unlock()
		if !ok {
			// Every request is registered before its frame is written, so an
			// unknown request ID means the peer is out of sync.
			c.shutdown(fmt.Errorf("response for unknown request %d", h.ReqID))
			return
		}
		ch <- callResult{status: h.Status, payload: payload}
	}
}

func (c *Client) waitLoop() {
	err := c.cmd.Wait()
	close(c.exited)
	if err != nil {
		c.shutdown(fmt.Errorf("helper exited: %w", err))
	} else {
		c.shutdown(errors.New("helper exited"))
	}
}

// shutdown marks the client dead exactly once, kills the process and fails
// every pending call. It is safe to call from any goroutine.
func (c *Client) shutdown(reason error) {
	c.doneOnce.Do(func() {
		c.errMu.Lock()
		c.err = reason
		c.errMu.Unlock()
		close(c.done)

		if c.cmd.Process != nil {
			_ = c.cmd.Process.Kill()
		}
		if c.lifeFD != nil {
			_ = c.lifeFD.Close()
		}

		c.pendingMu.Lock()
		pending := c.pending
		c.pending = make(map[uint64]chan callResult)
		c.pendingMu.Unlock()
		for _, ch := range pending {
			select {
			case ch <- callResult{err: ErrUnavailable}:
			default:
			}
		}
	})
}

// Close shuts the helper down. It is idempotent.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, _ = c.Call(ctx, hctproto.OpClose, nil)
		cancel()

		_ = c.stdin.Close()
		select {
		case <-c.exited:
		case <-time.After(2 * time.Second):
			c.shutdown(errors.New("helper did not exit"))
		}
		c.shutdown(errors.New("client closed"))
		if c.lifeFD != nil {
			_ = c.lifeFD.Close()
		}
		_ = c.stdout.Close()
	})
	return nil
}

func (c *Client) stderrSuffix() string {
	out := strings.TrimSpace(c.stderr.String())
	if out == "" {
		return ""
	}
	return ": helper stderr: " + out
}

// versionSatisfies reports whether version contains required as a whole
// dotted component sequence. libhct reports strings like
// "hct-3.0.10-2601d03-", so a plain prefix check would reject a correct
// library. Component equality still rejects "13.0.10" or "3.0.100".
func versionSatisfies(version, required string) bool {
	if required == "" {
		return true
	}
	isSep := func(r rune) bool { return r == '-' || r == '.' || r == '_' || r == '+' || r == ' ' }
	fields := strings.FieldsFunc(version, isSep)
	want := strings.FieldsFunc(required, isSep)
	if len(want) == 0 {
		return false
	}
	for i := 0; i+len(want) <= len(fields); i++ {
		match := true
		for j := range want {
			if fields[i+j] != want[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func parseHello(payload []byte) (Hello, error) {
	r := hctproto.NewReader(payload)
	verLen := int(r.U8())
	version := string(r.Bytes(verLen))
	accLen := int(r.U8())
	accel := string(r.Bytes(accLen))
	buildLen := int(r.U8())
	build := string(r.Bytes(buildLen))
	if err := r.Err(); err != nil {
		return Hello{}, fmt.Errorf("malformed hello: %w", err)
	}
	if version == "" {
		return Hello{}, errors.New("empty libhct version")
	}
	return Hello{Version: version, Accel: accel, BuildID: build}, nil
}

// boundedBuffer keeps the last max bytes written to it.
type boundedBuffer struct {
	mu  sync.Mutex
	max int
	buf []byte
}

func newBoundedBuffer(max int) *boundedBuffer { return &boundedBuffer{max: max} }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if len(b.buf) > b.max {
		b.buf = b.buf[len(b.buf)-b.max:]
	}
	return len(p), nil
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]byte, len(b.buf))
	copy(out, b.buf)
	return string(out)
}
