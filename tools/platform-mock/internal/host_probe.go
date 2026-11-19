package mock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// hostProbe is where the host panel's facts come from, and exactly one is active
// per process. The panel describes one machine — its memory and the Pods running
// on it — so both halves of a snapshot must come from the same source. Mixing
// them (local /proc/meminfo next to a remote kubectl) would put one host's memory
// figure under another host's Pod list, which is worse than showing nothing.
type hostProbe interface {
	// Describe names the machine this probe reads, for the panel's label.
	Describe() hostTarget
	// Memory returns the machine's physical-memory accounting.
	Memory(ctx context.Context) (hostMemory, error)
	// Pods returns the Pods that machine's cluster reports, every namespace when
	// namespace is empty.
	Pods(ctx context.Context, namespace string) ([]hostPod, error)
}

// hostTarget is how the panel says which machine it describes. The console used
// to be able to run only beside the Pods, and its address field was pure display;
// now that the mock can live elsewhere, a panel labelled with one host while
// reading another is exactly the confusion this field rules out.
type hostTarget struct {
	// Mode is "local", "ssh", or "broken" when the SSH target could not be built.
	Mode string `json:"mode"`
	// Host is the SSH destination ("[user@]host[:port]"), empty locally.
	Host string `json:"host,omitempty"`
	// Label is the one line the panel shows beside the address field.
	Label string `json:"label"`
}

const (
	// hostSSHConnectTimeout bounds the TCP+auth handshake. Without it a wrong
	// address costs the whole probe budget on every poll.
	hostSSHConnectTimeout = 5 * time.Second
)

// hostProbeTimeout bounds one complete read, handshake included. A remote
// kubectl on a busy cluster is slower than a local one, and this read runs off
// the request path behind the snapshot cache. It is a variable so a test can
// shorten it instead of waiting out the production budget.
var hostProbeTimeout = 15 * time.Second

// localHostProbe reads this machine: /proc/meminfo and the local kubectl.
type localHostProbe struct{}

func (localHostProbe) Describe() hostTarget {
	return hostTarget{Mode: "local", Label: "本机"}
}

func (localHostProbe) Memory(_ context.Context) (hostMemory, error) {
	return readHostMemory()
}

func (localHostProbe) Pods(ctx context.Context, namespace string) ([]hostPod, error) {
	return listHostPods(ctx, namespace)
}

// probeExec runs one command and returns its stdout. It is a field on the SSH
// probe so the command that would be built can be asserted without a live sshd,
// and so an *exec.ExitError keeps the stderr-carrying shape the error reader
// expects.
type probeExec func(ctx context.Context, name string, args []string, env []string) ([]byte, error)

// sshHostProbe reads the same two facts on a different machine: the operator runs
// the mock where it is convenient and drives a Hygon host that is not on that
// machine's filesystem.
//
// Each read is one `ssh … sh -lc '<script>'`. The login shell is deliberate —
// kubectl is commonly installed outside the non-interactive PATH, and the panel
// must match what the operator's own `kubectl get pods` shows. The cost is a
// handshake per read; with key auth that is milliseconds, and the snapshot cache
// already caps the poll rate.
type sshHostProbe struct {
	user     string
	host     string
	port     string
	password string
	extra    []string
	exec     probeExec
}

func (p *sshHostProbe) Describe() hostTarget {
	return hostTarget{Mode: "ssh", Host: p.target(), Label: p.target() + "（SSH 远程）"}
}

// target is the destination as ssh spells it.
func (p *sshHostProbe) target() string {
	if p.user == "" {
		return p.host
	}
	return p.user + "@" + p.host
}

func (p *sshHostProbe) Memory(ctx context.Context) (hostMemory, error) {
	out, err := p.run(ctx, "cat /proc/meminfo")
	if err != nil {
		return hostMemory{}, p.describeError(err)
	}
	return parseHostMemory(string(out))
}

func (p *sshHostProbe) Pods(ctx context.Context, namespace string) ([]hostPod, error) {
	script := "kubectl get pods -o json"
	if strings.TrimSpace(namespace) != "" {
		script += " -n " + shQuote(strings.TrimSpace(namespace))
	} else {
		script += " -A"
	}
	out, err := p.run(ctx, script)
	if err != nil {
		return nil, p.describeError(err)
	}
	return parseKubePods(out)
}

// errProbeTimeout marks a read that ran out of its budget, so the caller can
// name the timeout rather than echo "signal: killed" from the killed process.
var errProbeTimeout = errors.New("probe timeout")

func (p *sshHostProbe) run(ctx context.Context, script string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, hostProbeTimeout)
	defer cancel()
	name, args, env := p.command(script)
	out, err := p.exec(ctx, name, args, env)
	if err != nil && ctx.Err() == context.DeadlineExceeded {
		return nil, errProbeTimeout
	}
	return out, err
}

// command builds the ssh invocation. The script goes to a login shell on the far
// side; shQuote keeps it intact through ssh's own argument joining.
//
// The password never reaches argv: sshpass reads SSHPASS from the environment, so
// it is not visible in the mock's process listing either.
func (p *sshHostProbe) command(script string) (string, []string, []string) {
	name := "ssh"
	var args []string
	var env []string
	if p.password != "" {
		name = "sshpass"
		args = append(args, "-e", "ssh")
		env = append(env, "SSHPASS="+p.password)
	} else {
		// Nothing can answer a prompt, so refuse to ask: a missing key must fail
		// within the connect timeout instead of waiting on a tty that is absent.
		args = append(args, "-o", "BatchMode=yes")
	}
	args = append(args,
		"-o", "ConnectTimeout="+strconv.Itoa(int(hostSSHConnectTimeout.Seconds())),
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "LogLevel=ERROR",
	)
	if p.port != "" {
		args = append(args, "-p", p.port)
	}
	args = append(args, p.extra...)
	args = append(args, p.target(), "sh -lc "+shQuote(script))
	return name, args, env
}

// describeError reports which side of the connection failed. ssh's own failure
// arrives with exit code 255; every other code came from a command that ran on
// the far side and whose stderr is the useful half.
func (p *sshHostProbe) describeError(err error) error {
	if errors.Is(err, errProbeTimeout) {
		return &hostStatusError{msg: "探测 " + p.target() + " 超时（" + hostProbeTimeout.String() + "），检查网络或 ssh 密钥/密码"}
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		msg := strings.TrimSpace(string(exitErr.Stderr))
		if msg == "" {
			msg = exitErr.Error()
		}
		if exitErr.ExitCode() == 255 {
			return &hostStatusError{msg: "SSH 连接 " + p.target() + " 失败: " + firstLine(msg)}
		}
		return &hostStatusError{msg: "在 " + p.target() + " 上执行失败: " + firstLine(msg)}
	}
	if errors.Is(err, exec.ErrNotFound) {
		msg := firstLine(err.Error())
		if strings.Contains(msg, "sshpass") {
			return &hostStatusError{msg: "已配置 SSH 密码，但未安装 sshpass（" + p.target() + "）；安装 sshpass 或改用密钥认证"}
		}
		return &hostStatusError{msg: "未找到 SSH 客户端，无法探测 " + p.target() + ": " + msg}
	}
	return &hostStatusError{msg: "执行 SSH 客户端失败: " + firstLine(err.Error())}
}

// brokenHostProbe stands in when an SSH target was configured but cannot be
// used. It reports the reason on every read instead of falling back to the local
// machine: a label saying "remote" over local numbers is the failure the seam
// exists to prevent.
type brokenHostProbe struct{ reason string }

func (p brokenHostProbe) Describe() hostTarget {
	return hostTarget{Mode: "broken", Label: "主机探测配置有误"}
}

func (p brokenHostProbe) Memory(context.Context) (hostMemory, error) {
	return hostMemory{}, &hostStatusError{msg: p.reason}
}

func (p brokenHostProbe) Pods(context.Context, string) ([]hostPod, error) {
	return nil, &hostStatusError{msg: p.reason}
}

// newHostProbe picks the starting source from the config. An empty HostSSH
// keeps the original behaviour: the panel describes the machine the mock runs
// on. The console can point the panel elsewhere at runtime; see setProbe.
func newHostProbe(cfg Config) hostProbe {
	spec := strings.TrimSpace(cfg.HostSSH)
	if spec == "" {
		return localHostProbe{}
	}
	probe, err := newSSHHostProbe(spec, cfg.HostSSHPassword, cfg.HostSSHOptions)
	if err != nil {
		return brokenHostProbe{reason: "-host-ssh 配置无效: " + err.Error()}
	}
	return probe
}

// newSSHHostProbe builds a probe for one destination. The extra options come
// from the deployment — they name the key or the jump host that someone typing
// a password into the console cannot know — and are applied to every target,
// configured or entered, so both paths reach the host the same way.
func newSSHHostProbe(spec, password, options string) (hostProbe, error) {
	user, host, port, err := parseSSHTarget(spec)
	if err != nil {
		return nil, err
	}
	return &sshHostProbe{
		user:     user,
		host:     host,
		port:     port,
		password: password,
		extra:    strings.Fields(options),
		exec: func(ctx context.Context, name string, args []string, env []string) ([]byte, error) {
			cmd := exec.CommandContext(ctx, name, args...)
			if len(env) > 0 {
				cmd.Env = append(os.Environ(), env...)
			}
			return cmd.Output()
		},
	}, nil
}

// parseSSHTarget accepts the forms an operator actually types: "host",
// "user@host", "host:port", "user@host:port", and bracketed IPv6 destinations.
//
// It also refuses the two shapes that would turn the destination into something
// other than a destination. The console now feeds this from a form, and ssh has
// no reliable end-of-options marker: a host starting with "-" would be read as
// an ssh option, and whitespace would split into more arguments.
func parseSSHTarget(spec string) (user, host, port string, err error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", "", "", fmt.Errorf("destination 为空")
	}
	at := strings.LastIndex(spec, "@")
	if at >= 0 {
		user = spec[:at]
		spec = spec[at+1:]
	}
	if strings.HasPrefix(user, "-") || strings.ContainsAny(user, " \t\r\n") {
		return "", "", "", fmt.Errorf("用户名 %q 无效", user)
	}
	if spec == "" {
		return "", "", "", fmt.Errorf("destination %q 没有主机名", spec)
	}
	// SplitHostPort only succeeds when a port is present; a bare host is the
	// common case and must not read as an error.
	if h, p, splitErr := net.SplitHostPort(spec); splitErr == nil {
		host, port = h, p
	} else {
		host = spec
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return "", "", "", fmt.Errorf("destination %q 没有主机名", spec)
	}
	if strings.HasPrefix(host, "-") || strings.ContainsAny(host, " \t\r\n") {
		return "", "", "", fmt.Errorf("主机名 %q 无效", host)
	}
	if port != "" {
		if _, convErr := strconv.Atoi(port); convErr != nil {
			return "", "", "", fmt.Errorf("destination 端口 %q 不是数字", port)
		}
	}
	return user, host, port, nil
}

// shQuote single-quotes a string for a POSIX shell.
func shQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}
