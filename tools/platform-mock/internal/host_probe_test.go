package mock

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ── host probe ──────────────────────────────────────────────────────────

// The SSH probe must put the destination, the port and the far-side script in
// the shape ssh expects, and must never put the password in argv.
func TestSSHProbeBuildsTheCommandWithoutThePasswordInArgv(t *testing.T) {
	probe := &sshHostProbe{
		user:     "root",
		host:     "172.16.10.178",
		port:     "2222",
		password: "s3cret",
		extra:    []string{"-i", "/root/.ssh/id_ed25519"},
	}
	name, args, env := probe.command("kubectl get pods -o json -A")
	if name != "sshpass" {
		t.Fatalf("a password must go through sshpass, got %q", name)
	}
	if args[0] != "-e" || args[1] != "ssh" {
		t.Fatalf("sshpass must read SSHPASS from the environment: %v", args)
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "s3cret") {
		t.Fatalf("the password leaked into argv: %v", args)
	}
	for _, want := range []string{
		"ConnectTimeout=", "StrictHostKeyChecking=accept-new", "-p 2222",
		"-i /root/.ssh/id_ed25519", "root@172.16.10.178", "sh -lc",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("argv is missing %q: %v", want, args)
		}
	}
	if len(env) != 1 || env[0] != "SSHPASS=s3cret" {
		t.Fatalf("env = %v", env)
	}
}

// Without a password ssh must not be able to prompt: BatchMode makes a missing
// key fail now instead of hanging on a tty the daemon does not have.
func TestSSHProbeUsesBatchModeWithoutAPassword(t *testing.T) {
	probe := &sshHostProbe{host: "10.0.0.5"}
	name, args, env := probe.command("cat /proc/meminfo")
	if name != "ssh" {
		t.Fatalf("name = %q", name)
	}
	if !strings.Contains(strings.Join(args, " "), "BatchMode=yes") {
		t.Fatalf("argv is missing BatchMode: %v", args)
	}
	if len(env) != 0 {
		t.Fatalf("no password means no SSHPASS, got %v", env)
	}
	if args[len(args)-1] != "sh -lc 'cat /proc/meminfo'" {
		t.Fatalf("far-side script = %q", args[len(args)-1])
	}
}

// The whole point of the seam: a remote read must parse exactly what the local
// read parses. The fixtures are a real /proc/meminfo shape and a real kubectl
// list shape, so a probe that silently returned empty values would fail here.
func TestSSHProbeReadsMemoryAndPodsThroughOneExec(t *testing.T) {
	var scripts []string
	probe := &sshHostProbe{
		user: "root",
		host: "172.16.10.178",
		exec: func(_ context.Context, name string, args []string, _ []string) ([]byte, error) {
			script := args[len(args)-1]
			scripts = append(scripts, script)
			switch {
			case strings.Contains(script, "/proc/meminfo"):
				return []byte("MemTotal:       65853056 kB\nMemAvailable:   50603008 kB\n"), nil
			case strings.Contains(script, "kubectl get pods"):
				return []byte(`{"items":[{"metadata":{"name":"taa-deploy","namespace":"osr",
				  "creationTimestamp":"2026-11-16T09:00:00Z"},
				  "spec":{"nodeName":"hygon-master","containers":[{"name":"taa"}]},
				  "status":{"phase":"Running","podIP":"10.244.0.135",
				  "containerStatuses":[{"ready":true,"restartCount":1}]}}]}`), nil
			}
			return nil, errors.New("unexpected script: " + script)
		},
	}

	mem, err := probe.Memory(context.Background())
	if err != nil {
		t.Fatalf("memory: %v", err)
	}
	if mem.TotalBytes != 65853056*1024 || mem.AvailableBytes != 50603008*1024 {
		t.Fatalf("memory = %+v", mem)
	}
	if mem.UsedPercent <= 0 || mem.UsedPercent >= 100 {
		t.Fatalf("used percent = %v", mem.UsedPercent)
	}

	pods, err := probe.Pods(context.Background(), "")
	if err != nil {
		t.Fatalf("pods: %v", err)
	}
	if len(pods) != 1 || pods[0].Name != "taa-deploy" || pods[0].Ready != "1/1" || pods[0].Restarts != 1 {
		t.Fatalf("pods = %+v", pods)
	}
	// No namespace means every namespace, as on the local path.
	if !strings.Contains(scripts[len(scripts)-1], "-A") {
		t.Fatalf("an unfiltered read must pass -A: %q", scripts[len(scripts)-1])
	}
	// A named namespace must be quoted, so a typo cannot become a second command.
	scoped := &sshHostProbe{host: "h", exec: func(_ context.Context, _ string, args []string, _ []string) ([]byte, error) {
		if !strings.Contains(args[len(args)-1], "-n") || !strings.Contains(args[len(args)-1], "osr") {
			t.Fatalf("namespace did not reach the far-side script: %q", args[len(args)-1])
		}
		return []byte(`{"items":[]}`), nil
	}}
	if _, err := scoped.Pods(context.Background(), "osr"); err != nil {
		t.Fatalf("scoped pods: %v", err)
	}
}

// A namespace comes from the page's query string, so it must not be able to
// introduce a second command on the far side.
func TestShQuoteNeutralizesShellMetacharacters(t *testing.T) {
	quoted := shQuote("a; rm -rf / #")
	if quoted != `'a; rm -rf / #'` {
		t.Fatalf("quoted = %q", quoted)
	}
	if got := shQuote("it's"); got != `'it'\''s'` {
		t.Fatalf("quoted = %q", got)
	}
}

// ssh's own failures (exit 255) must not be reported as if kubectl had said
// them: the operator's next action is different.
func TestSSHProbeNamesTheSideThatFailed(t *testing.T) {
	probe := &sshHostProbe{host: "172.16.10.178", exec: func(context.Context, string, []string, []string) ([]byte, error) {
		return nil, execExitErrorWithCode(t, 255, "ssh: connect to host 172.16.10.178 port 22: No route to host")
	}}
	_, err := probe.Pods(context.Background(), "")
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "SSH 连接") || !strings.Contains(err.Error(), "No route to host") {
		t.Fatalf("message = %q", err.Error())
	}

	far := &sshHostProbe{host: "172.16.10.178", exec: func(context.Context, string, []string, []string) ([]byte, error) {
		return nil, execExitErrorWithCode(t, 1, "error: the server doesn't have a resource type \"pods\"")
	}}
	_, err = far.Pods(context.Background(), "")
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "172.16.10.178") || !strings.Contains(err.Error(), "resource type") {
		t.Fatalf("message = %q", err.Error())
	}
	if strings.Contains(err.Error(), "SSH 连接") {
		t.Fatalf("a far-side failure must not read as a connection failure: %q", err.Error())
	}
}

// A probe that outlives its budget is reported as a timeout, not as the killed
// process's "signal: killed".
func TestSSHProbeReportsItsOwnTimeout(t *testing.T) {
	probe := &sshHostProbe{host: "172.16.10.178", exec: func(ctx context.Context, _ string, _ []string, _ []string) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	restore := shortenProbeTimeout(t, 50*time.Millisecond)
	defer restore()
	_, err := probe.Memory(context.Background())
	if err == nil || !strings.Contains(err.Error(), "超时") {
		t.Fatalf("error = %v", err)
	}
}

// A missing sshpass must name the missing tool: the operator installed a
// password and the fix is a package, not a key.
func TestSSHProbeNamesAMissingSSHClient(t *testing.T) {
	probe := &sshHostProbe{host: "h", password: "x", exec: func(context.Context, string, []string, []string) ([]byte, error) {
		return nil, fmt.Errorf("exec: \"sshpass\": %w", exec.ErrNotFound)
	}}
	if _, err := probe.Pods(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "sshpass") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseSSHTargetAcceptsWhatAnOperatorTypes(t *testing.T) {
	cases := []struct {
		spec       string
		user, host string
		port       string
	}{
		{"172.16.10.178", "", "172.16.10.178", ""},
		{"root@172.16.10.178", "root", "172.16.10.178", ""},
		{"root@172.16.10.178:2222", "root", "172.16.10.178", "2222"},
		{"172.16.10.178:2222", "", "172.16.10.178", "2222"},
		{"root@[fe80::1]:22", "root", "fe80::1", "22"},
	}
	for _, c := range cases {
		user, host, port, err := parseSSHTarget(c.spec)
		if err != nil {
			t.Fatalf("%q: %v", c.spec, err)
		}
		if user != c.user || host != c.host || port != c.port {
			t.Fatalf("%q = %q/%q/%q", c.spec, user, host, port)
		}
	}
	for _, bad := range []string{"", " ", "root@", "host:notaport"} {
		if _, _, _, err := parseSSHTarget(bad); err == nil {
			t.Fatalf("%q should be rejected", bad)
		}
	}
}

// The console feeds the destination from a form now, so an entry that ssh would
// read as an option — or that would split into more arguments — is refused
// before it can become anything but a destination.
func TestParseSSHTargetRejectsOptionInjection(t *testing.T) {
	for _, bad := range []string{
		"-oProxyCommand=touch /tmp/pwned",
		"root@-oProxyCommand=touch",
		"172.16.10.178 extra",
		"root name@172.16.10.178",
		"--help",
	} {
		if _, _, _, err := parseSSHTarget(bad); err == nil {
			t.Fatalf("%q should be rejected", bad)
		}
	}
}

// A malformed target must fail loudly on the panel instead of quietly reading
// the local machine under a "remote" label.
func TestBrokenTargetDoesNotFallBackToTheLocalMachine(t *testing.T) {
	probe := newHostProbe(Config{HostSSH: "root@"})
	if _, ok := probe.(brokenHostProbe); !ok {
		t.Fatalf("probe = %T, want brokenHostProbe", probe)
	}
	if _, err := probe.Memory(context.Background()); err == nil {
		t.Fatal("a broken target must report its reason")
	}
	// An empty target is still the local machine: that is the default path.
	if _, ok := newHostProbe(Config{}).(localHostProbe); !ok {
		t.Fatal("empty -host-ssh must stay local")
	}
}

// A remote snapshot names the remote address in the panel's address field: the
// field is what the operator copies into PLATFORM_IP, and this process's own
// address is not it.
func TestSnapshotShowsTheRemoteAddressNotTheLocalOne(t *testing.T) {
	snapshot := collectHostSnapshot(&sshHostProbe{user: "root", host: "172.16.10.178", exec: func(context.Context, string, []string, []string) ([]byte, error) {
		return []byte("MemTotal: 1000 kB\nMemAvailable: 500 kB\n"), nil
	}})
	if snapshot.Target.Mode != "ssh" {
		t.Fatalf("target = %+v", snapshot.Target)
	}
	if snapshot.HostIP != "172.16.10.178" {
		t.Fatalf("hostIp = %q, want the remote address", snapshot.HostIP)
	}
	// The name must be the remote one too: this process's hostname beside a
	// remote address is the mislabel the probe exists to end.
	if snapshot.Hostname != "172.16.10.178" {
		t.Fatalf("hostname = %q, want the remote host", snapshot.Hostname)
	}
	if snapshot.Memory.TotalBytes != 1000*1024 {
		t.Fatalf("memory = %+v", snapshot.Memory)
	}
}

// ── console-driven target ───────────────────────────────────────────────

// Pointing the panel at another machine must switch what it serves at once, and
// going back to 本机 must drop the remote snapshot the same way.
func TestSetProbeSwitchesTheSourceImmediately(t *testing.T) {
	remote := &sshHostProbe{user: "root", host: "172.16.10.178",
		exec: func(_ context.Context, _ string, args []string, _ []string) ([]byte, error) {
			if strings.Contains(args[len(args)-1], "/proc/meminfo") {
				return []byte("MemTotal: 2000 kB\nMemAvailable: 1000 kB\n"), nil
			}
			return []byte(`{"items":[]}`), nil
		}}
	cache := newHostStatusCache(localHostProbe{}, hostStatusTTL)
	cache.now = func() time.Time { return timeFixed }

	status := cache.setProbe(remote)
	if status.Target.Mode != "ssh" || status.Target.Host != "root@172.16.10.178" {
		t.Fatalf("target = %+v", status.Target)
	}
	if status.Memory.TotalBytes != 2000*1024 || status.HostIP != "172.16.10.178" {
		t.Fatalf("status = %+v", status)
	}
	// The next poll serves this snapshot: it falls back to neither the local
	// probe nor the one before it.
	if got := cache.get(); got.Target.Mode != "ssh" || got.Memory.TotalBytes != 2000*1024 {
		t.Fatalf("get() = %+v", got)
	}

	back := cache.setProbe(localHostProbe{})
	if back.Target.Mode != "local" {
		t.Fatalf("local target = %+v", back.Target)
	}
	if got := cache.get(); got.Target.Mode != "local" {
		t.Fatalf("get() after 本机 = %+v", got.Target)
	}
}

// The endpoint takes the console's credentials, refuses a request from another
// origin, rejects a destination that would read as an ssh option, and treats an
// empty host as 本机.
func TestHostTargetHandlerRoutesTheConsoleForm(t *testing.T) {
	cache := newHostStatusCache(localHostProbe{}, hostStatusTTL)
	cache.now = func() time.Time { return timeFixed }
	handler := hostTargetHandler(cache, "")

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/host/target", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler(w, req)
		return w
	}

	if w := post(`{"host":"-oProxyCommand=touch /tmp/x","user":"root"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("option injection: status = %d, body = %s", w.Code, w.Body.String())
	}

	foreign := httptest.NewRequest(http.MethodPost, "/api/host/target", strings.NewReader(`{"host":"10.0.0.5"}`))
	foreign.Host = "mock.local:8080"
	foreign.Header.Set("Origin", "http://evil.example")
	w := httptest.NewRecorder()
	handler(w, foreign)
	if w.Code != http.StatusForbidden {
		t.Fatalf("foreign origin: status = %d, body = %s", w.Code, w.Body.String())
	}

	// An empty host is the 本机 button.
	if w := post(`{"host":""}`); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"mode":"local"`) {
		t.Fatalf("本机: %d %s", w.Code, w.Body.String())
	}
}

// ── cache ───────────────────────────────────────────────────────────────

// A snapshot inside its TTL is served without touching the probe, and a poll
// that finds it stale answers from what it has while a refresh runs behind it.
func TestHostStatusCacheServesStaleWhileRefreshing(t *testing.T) {
	now := timeFixed
	cache := newHostStatusCache(localHostProbe{}, time.Second)
	cache.now = func() time.Time { return now }
	calls := 0
	done := make(chan struct{}, 4)
	cache.refresh = func() {
		calls++
		cache.mu.Lock()
		cache.last = hostSnapshot{HostIP: "10.0.0." + string(rune('0'+calls))}
		cache.at = now
		cache.inFlight = false
		cache.mu.Unlock()
		done <- struct{}{}
	}

	first := cache.get()
	if calls != 1 {
		t.Fatalf("the first poll must collect, calls = %d", calls)
	}
	<-done // the cold start collects synchronously; drain its event
	second := cache.get()
	if calls != 1 || second.HostIP != first.HostIP {
		t.Fatalf("a fresh snapshot must not re-probe: calls=%d %q", calls, second.HostIP)
	}

	// Two seconds later the snapshot is stale. The poll must answer immediately
	// (the probe has not run synchronously) and leave a refresh behind.
	now = now.Add(2 * time.Second)
	stale := cache.get()
	if stale.HostIP != first.HostIP {
		t.Fatalf("a stale poll must return the last snapshot, got %q", stale.HostIP)
	}
	<-done // the background refresh this poll started
	// The refreshed value is visible on the next poll, without another collect.
	next := cache.get()
	if next.HostIP != "10.0.0.2" {
		t.Fatalf("next poll = %q, want the refreshed value", next.HostIP)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
}

// Past the grace window the answer is too old to pass off as current, so the
// poll waits for a fresh one instead of showing a number that may be hours old.
func TestHostStatusCacheCollectsSynchronouslyOnceStarved(t *testing.T) {
	now := timeFixed
	cache := newHostStatusCache(localHostProbe{}, time.Second)
	cache.now = func() time.Time { return now }
	cache.last = hostSnapshot{HostIP: "10.0.0.1"}
	cache.at = now
	collected := false
	cache.refresh = func() {
		collected = true
		cache.mu.Lock()
		cache.last = hostSnapshot{HostIP: "10.0.0.2"}
		cache.at = now
		cache.inFlight = false
		cache.mu.Unlock()
	}

	now = now.Add(hostStatusGrace + 2*time.Second)
	got := cache.get()
	if !collected {
		t.Fatal("a starved cache must collect before answering")
	}
	if got.HostIP != "10.0.0.2" {
		t.Fatalf("got %q, want the fresh value", got.HostIP)
	}
}

// ── test plumbing ───────────────────────────────────────────────────────

// execExitErrorWithCode builds a real *exec.ExitError with a chosen exit code
// and stderr, the shape describeError has to interpret. Exit code 255 is what
// ssh uses for its own failures; any other code came from the far-side command.
func execExitErrorWithCode(t *testing.T, code int, stderr string) error {
	t.Helper()
	cmd := exec.Command("sh", "-c", "printf %s "+shellSingleQuote(stderr)+" >&2; exit "+strconv.Itoa(code))
	_, err := cmd.Output()
	if err == nil {
		t.Fatal("the helper command should have failed")
	}
	return err
}

// shortenProbeTimeout keeps the timeout test fast: the production budget is 15s
// and waiting it out would make the suite unusable.
func shortenProbeTimeout(t *testing.T, d time.Duration) func() {
	t.Helper()
	previous := hostProbeTimeout
	hostProbeTimeout = d
	return func() { hostProbeTimeout = previous }
}
