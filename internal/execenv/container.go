package execenv

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// nsenterPath is called by absolute path: TAA's PATH is set up for its own
// tools, and a model's runtimeConfig must not be able to influence which
// nsenter gets executed by shadowing it on PATH.
const nsenterPath = "/usr/bin/nsenter"

// containerEnv is the fallback environment a container-executed model starts
// from when the container's own runtime configuration cannot be read. It is
// deliberately minimal: TAA's own environment carries key material
// (PLATFORM_PUBLIC_KEY, TAASECRETKEY), and the model is exactly the code whose
// behaviour the platform is watching, so it must not receive what TAA holds.
//
// When the OCI configuration is readable, its process.env is used instead: it
// is the environment the image's own entrypoint would run with, which is what
// the model was written against. It carries no TAA variables either.
var containerEnv = []string{
	"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	"HOME=/root",
}

// ociSpec is the subset of the container's OCI runtime configuration that TAA
// applies to the model process.
type ociSpec struct {
	Hostname string `json:"hostname"`
	Process  struct {
		Env  []string `json:"env"`
		Cwd  string   `json:"cwd"`
		User struct {
			UID uint32 `json:"uid"`
			GID uint32 `json:"gid"`
		} `json:"user"`
	} `json:"process"`
	Linux struct {
		Namespaces []struct {
			Type string `json:"type"`
		} `json:"namespaces"`
	} `json:"linux"`
}

// loadOCISpec reads the runtime configuration Kata keeps beside the container
// root (/run/kata-containers/<id>/config.json next to rootfs/). It is the only
// authoritative statement of the environment and user the image expects.
func loadOCISpec(rootFS string) (*ociSpec, error) {
	path := filepath.Join(filepath.Dir(rootFS), "config.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var spec ociSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &spec, nil
}

// Paths is the container-side contract: where the model finds its code, its
// dataset, and where it writes results, logs and progress. The model's
// runtimeConfig is resolved against these paths, so they are part of the
// product contract, not free configuration.
type Paths struct {
	ModelDir     string
	InputDir     string
	OutputDir    string
	LogDir       string
	ProgressPath string
}

// DefaultContainerPaths returns the contract every packaged image follows.
func DefaultContainerPaths() Paths {
	return Paths{
		ModelDir:     "/opt/taa/model",
		InputDir:     "/opt/taa/input",
		OutputDir:    "/opt/taa/output/result",
		LogDir:       "/opt/taa/output/log",
		ProgressPath: "/opt/taa/output/progress/progress.json",
	}
}

// dirs returns every directory Prepare owns, without duplicates.
func (p Paths) dirs() []string {
	all := []string{p.ModelDir, p.InputDir, p.OutputDir, p.LogDir, filepath.Dir(p.ProgressPath)}
	seen := map[string]bool{}
	out := all[:0]
	for _, d := range all {
		if seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

// validate refuses paths that Prepare must never clear. Prepare deletes the
// contents of everything it owns, so a path of "/" or an ancestor of the
// image's payload would delete the image itself.
func (p Paths) validate() error {
	all := append(p.dirs(), p.ProgressPath)
	for _, target := range all {
		clean := filepath.Clean(target)
		if !filepath.IsAbs(clean) {
			return fmt.Errorf("container path %q is not absolute", target)
		}
		if clean != target {
			return fmt.Errorf("container path %q is not clean (%q)", target, clean)
		}
		if clean == "/" || len(components(clean)) < 3 {
			return fmt.Errorf("container path %q is too shallow to clear safely", target)
		}
	}
	dirs := p.dirs()
	for i := range dirs {
		for j := i + 1; j < len(dirs); j++ {
			if isWithin(dirs[i], dirs[j]) || isWithin(dirs[j], dirs[i]) {
				return fmt.Errorf("container paths %q and %q overlap", dirs[i], dirs[j])
			}
		}
	}
	// The progress file lives inside its own directory by construction; any other
	// directory containing it would clear the file it is supposed to hold.
	for _, dir := range dirs {
		if dir == filepath.Dir(p.ProgressPath) {
			continue
		}
		if isWithin(dir, p.ProgressPath) {
			return fmt.Errorf("container paths %q and %q overlap", dir, p.ProgressPath)
		}
	}
	return nil
}

func components(path string) []string {
	return strings.Split(strings.Trim(path, "/"), "/")
}

// isWithin reports whether child is inside parent.
func isWithin(parent, child string) bool {
	if parent == child {
		return true
	}
	return strings.HasPrefix(child, strings.TrimSuffix(parent, "/")+"/")
}

// ContainerTarget executes a model inside a container's namespaces while TAA
// keeps running in its own.
type ContainerTarget struct {
	procRoot string
	pid      int
	rootFS   string
	paths    Paths

	// Runtime identity taken from the container's OCI configuration. The model
	// runs as the user the image declares, with the environment the image
	// declares; configErr records why that could not be read, so the fallback
	// is visible in the task log instead of silently narrowing the environment.
	env       []string
	uid       int
	gid       int
	hostname  string
	ociCwd    string
	ociNS     []string
	configErr error

	mu   sync.Mutex
	spec Spec
}

func newContainerTarget(procRoot string, pid int, rootFS string, paths Paths) *ContainerTarget {
	t := &ContainerTarget{procRoot: procRoot, pid: pid, rootFS: rootFS, paths: paths}
	t.loadRuntimeConfig()
	return t
}

// loadRuntimeConfig applies the container's OCI configuration. Only the
// environment and the user are applied to the model process; the working
// directory stays the model directory because the contract defines where the
// model finds its code, and the image's own cwd (/ or the entrypoint's) would
// not contain it.
func (t *ContainerTarget) loadRuntimeConfig() {
	spec, err := loadOCISpec(t.rootFS)
	if err != nil {
		t.configErr = err
		t.env = readProcessEnv(t.procRoot, t.pid)
		if len(t.env) == 0 {
			t.env = append([]string(nil), containerEnv...)
		}
		return
	}
	t.hostname = spec.Hostname
	t.ociCwd = spec.Process.Cwd
	t.uid = int(spec.Process.User.UID)
	t.gid = int(spec.Process.User.GID)
	for _, ns := range spec.Linux.Namespaces {
		t.ociNS = append(t.ociNS, ns.Type)
	}
	switch {
	case len(spec.Process.Env) > 0:
		t.env = append([]string(nil), spec.Process.Env...)
	default:
		t.env = readProcessEnv(t.procRoot, t.pid)
		if len(t.env) == 0 {
			t.env = append([]string(nil), containerEnv...)
		}
	}
}

// readProcessEnv reads the container process's environment as a second-best
// source when its OCI configuration is unavailable.
func readProcessEnv(procRoot string, pid int) []string {
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "environ"))
	if err != nil {
		return nil
	}
	var env []string
	for _, kv := range strings.Split(string(data), "\x00") {
		if kv != "" {
			env = append(env, kv)
		}
	}
	return env
}

// containerInvocation is the identity nsenter applies before the shell starts.
type containerInvocation struct {
	pid int
	uid int
	gid int
	env []string
}

var _ Target = (*ContainerTarget)(nil)

// PID returns the container process used as the namespace anchor.
func (t *ContainerTarget) PID() int { return t.pid }

// RootFS returns where TAA's namespace sees the container root.
func (t *ContainerTarget) RootFS() string { return t.rootFS }

// Paths returns the container-side contract.
func (t *ContainerTarget) Paths() Paths { return t.paths }

// Name implements Target.
func (t *ContainerTarget) Name() string { return "container" }

// Resolve implements Target. Only the five contract paths are translated, by
// exact match; nothing else is rewritten, so model content cannot steer the
// mapping. Call it after Prepare, which records the execution's Spec.
func (t *ContainerTarget) Resolve(initPath string) string {
	t.mu.Lock()
	spec := t.spec
	t.mu.Unlock()

	switch {
	case spec.ModelDir != "" && initPath == spec.ModelDir:
		return t.paths.ModelDir
	case spec.DataDir != "" && initPath == spec.DataDir:
		return t.paths.InputDir
	case spec.OutputDir != "" && initPath == spec.OutputDir:
		return t.paths.OutputDir
	case spec.LogDir != "" && initPath == spec.LogDir:
		return t.paths.LogDir
	case spec.ProgressPath != "" && initPath == spec.ProgressPath:
		return t.paths.ProgressPath
	}
	return initPath
}

// Visible implements Target. It maps a container path back to the path TAA can
// read and write, refusing any component that is a symbolic link: the overlay
// is writable through this path, and a symlink in the image could otherwise
// redirect TAA's staging or copy-back outside it.
func (t *ContainerTarget) Visible(targetPath string) (string, error) {
	return visiblePath(t.rootFS, targetPath)
}

// BaseEnv implements Target. A container-executed model gets the container's
// own environment, never TAA's.
func (t *ContainerTarget) BaseEnv() []string { return append([]string(nil), t.env...) }

// ConfigError reports why the container's OCI configuration could not be read,
// or nil when it was applied.
func (t *ContainerTarget) ConfigError() error { return t.configErr }

// StagesDataset implements Target: Prepare copies the dataset into the
// container root, reading it from the source directory in TAA's view.
func (t *ContainerTarget) StagesDataset() bool { return true }

// Prepare implements Target: it checks that the contract paths are not
// container mounts, verifies the copy fits in the container's writable layer,
// clears what a previous run left behind, and stages the model and dataset.
//
// Clearing before copying is also what makes the copy safe: every directory the
// copy creates afterwards is known not to have existed a moment earlier, so no
// pre-existing symlink can redirect a write.
func (t *ContainerTarget) Prepare(ctx context.Context, spec Spec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := t.paths.validate(); err != nil {
		return err
	}
	if err := t.refuseContainerMounts(); err != nil {
		return err
	}
	if spec.ModelDir == "" {
		return fmt.Errorf("container execution needs a model directory")
	}

	size, err := treeSize(spec.ModelDir)
	if err != nil {
		return fmt.Errorf("size the model directory: %w", err)
	}
	if spec.DataDir != "" {
		dataSize, err := treeSize(spec.DataDir)
		if err != nil {
			return fmt.Errorf("size the data directory: %w", err)
		}
		size += dataSize
	}
	avail, err := availableBytes(t.rootFS)
	if err != nil {
		return fmt.Errorf("read free space on the container root: %w", err)
	}
	if avail < uint64(size) {
		return fmt.Errorf("container root has %d bytes free but the model and data need %d", avail, size)
	}

	t.mu.Lock()
	t.spec = spec
	t.mu.Unlock()

	for _, dir := range t.paths.dirs() {
		vis, err := t.Visible(dir)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(vis, 0o755); err != nil {
			return fmt.Errorf("create container directory %s: %w", dir, err)
		}
	}
	for _, dir := range []string{t.paths.ModelDir, t.paths.InputDir, t.paths.OutputDir, t.paths.LogDir} {
		vis, err := t.Visible(dir)
		if err != nil {
			return err
		}
		if err := clearDirContents(vis); err != nil {
			return fmt.Errorf("clear container directory %s: %w", dir, err)
		}
	}
	progressVis, err := t.Visible(t.paths.ProgressPath)
	if err != nil {
		return err
	}
	if err := os.Remove(progressVis); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale progress file %s: %w", t.paths.ProgressPath, err)
	}

	modelVis, err := t.Visible(t.paths.ModelDir)
	if err != nil {
		return err
	}
	if err := copyTree(ctx, spec.ModelDir, modelVis); err != nil {
		return fmt.Errorf("stage the model into the container: %w", err)
	}
	if spec.DataDir != "" {
		inputVis, err := t.Visible(t.paths.InputDir)
		if err != nil {
			return err
		}
		if err := copyTree(ctx, spec.DataDir, inputVis); err != nil {
			return fmt.Errorf("stage the dataset into the container: %w", err)
		}
	}
	// The model runs as the user the image declares (nsenter -S/-G), so the
	// staged trees have to belong to that user; otherwise it cannot read its own
	// code or write results, and the failure looks like a broken model.
	if t.uid != 0 || t.gid != 0 {
		for _, dir := range t.paths.dirs() {
			vis, err := t.Visible(dir)
			if err != nil {
				return err
			}
			if err := chownTree(vis, t.uid, t.gid); err != nil {
				return fmt.Errorf("hand container path %s to uid %d: %w", dir, t.uid, err)
			}
		}
	}
	return nil
}

// chownTree hands a staged tree to the user the container's image declares.
func chownTree(root string, uid, gid int) error {
	return filepath.WalkDir(root, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := os.Lchown(path, uid, gid); err != nil {
			return fmt.Errorf("chown %s: %w", path, err)
		}
		return nil
	})
}

// Cleanup implements Target. It removes what Prepare staged and nothing else:
// the contract directories keep existing, but their contents are owned by one
// execution. Errors are ignored on purpose - a failed cleanup must not turn a
// finished task into a failure, and the next Prepare clears the same paths.
func (t *ContainerTarget) Cleanup(_ context.Context, _ Spec) {
	for _, dir := range []string{t.paths.ModelDir, t.paths.InputDir, t.paths.OutputDir, t.paths.LogDir} {
		if vis, err := t.Visible(dir); err == nil {
			_ = clearDirContents(vis)
		}
	}
	if vis, err := t.Visible(t.paths.ProgressPath); err == nil {
		_ = os.Remove(vis)
	}
}

// Command implements Target. nsenter changes the mount and PID namespaces and
// drops to the user the image declares; the process group is set here so a stop
// still SIGKILLs the whole tree, including the shell nsenter forks inside the
// container.
func (t *ContainerTarget) Command(ctx context.Context, commandLine, workDir string) *exec.Cmd {
	shell := "cd " + shellQuote(workDir) + " && " + commandLine
	return nsenterShell(ctx, containerInvocation{pid: t.pid, uid: t.uid, gid: t.gid, env: t.env}, shell)
}

// Describe summarises the container configuration the model process was given,
// for the task log. Environment values are never included - an image may carry
// credentials there - only the key names.
func (t *ContainerTarget) Describe() string {
	return fmt.Sprintf("hostname=%q uid=%d gid=%d env=[%s] image_cwd=%q namespaces(configured)=[%s] namespaces(entered)=[mnt,pid] shm=%s net=[%s]",
		t.hostname, t.uid, t.gid, strings.Join(envKeys(t.env), ","), t.ociCwd,
		strings.Join(t.ociNS, ","), t.shmSize(), t.networkInterfaces())
}

// envKeys returns the variable names of an environment, in order.
func envKeys(env []string) []string {
	keys := make([]string, 0, len(env))
	for _, kv := range env {
		key, _, _ := strings.Cut(kv, "=")
		keys = append(keys, key)
	}
	return keys
}

// shmSize reports /dev/shm inside the container. torch's DataLoader and any
// multiprocessing user allocate shared memory there, and the default 64MiB
// fails far from the actual cause.
func (t *ContainerTarget) shmSize() string {
	var st syscall.Statfs_t
	if err := syscall.Statfs(filepath.Join(t.rootFS, "dev", "shm"), &st); err != nil {
		return "unknown"
	}
	return humanBytes(st.Blocks * uint64(st.Bsize))
}

func humanBytes(n uint64) string {
	const (
		mib = 1024 * 1024
		gib = 1024 * mib
	)
	switch {
	case n >= gib:
		return fmt.Sprintf("%.1fGiB", float64(n)/float64(gib))
	case n >= mib:
		return fmt.Sprintf("%.0fMiB", float64(n)/float64(mib))
	default:
		return fmt.Sprintf("%dKiB", n/1024)
	}
}

// networkInterfaces lists the interfaces of the container's network namespace.
func (t *ContainerTarget) networkInterfaces() string {
	data, err := os.ReadFile(filepath.Join(t.procRoot, strconv.Itoa(t.pid), "net", "dev"))
	if err != nil {
		return "unknown"
	}
	var names []string
	for _, line := range strings.Split(string(data), "\n") {
		name, _, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" || strings.Contains(name, "|") {
			continue
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return "unknown"
	}
	return strings.Join(names, ",")
}

// refuseContainerMounts rejects a contract path that the container mounts
// separately. Staging through TAA's view would then write into the overlay
// while the model reads an empty volume, which looks like a missing dataset
// rather than the deployment mistake it is.
func (t *ContainerTarget) refuseContainerMounts() error {
	data, err := os.ReadFile(filepath.Join(t.procRoot, strconv.Itoa(t.pid), "mountinfo"))
	if err != nil {
		return fmt.Errorf("read the container mount table: %w", err)
	}
	mounted := map[string]bool{}
	for _, m := range parseMountInfo(string(data)) {
		mounted[m.MountPoint] = true
	}
	for _, dir := range t.paths.dirs() {
		if mounted[dir] {
			return fmt.Errorf("container path %s is a mount point inside the container; refusing to stage through the overlay", dir)
		}
	}
	return nil
}

// nsenterShell builds a shell invocation inside the container's mount and PID
// namespaces, as the user the image declares.
//
// The PID namespace is not optional. The container's /proc is a procfs mounted
// in that namespace, so a process from the guest's namespace sees no /proc/self
// in it at all: measured in a live guest, `nsenter -m -r -- cat
// /proc/self/statm` fails with ENOENT, and CatBoost aborts a training run on
// exactly that file. Entering the PID namespace makes /proc mean what the
// container's processes expect.
func nsenterShell(ctx context.Context, inv containerInvocation, shellCommand string) *exec.Cmd {
	args := []string{"-t", strconv.Itoa(inv.pid), "-m", "-p", "-r"}
	if inv.uid != 0 || inv.gid != 0 {
		args = append(args, "-S", strconv.Itoa(inv.uid), "-G", strconv.Itoa(inv.gid))
	}
	args = append(args, "--", "/bin/sh", "-c", shellCommand)

	cmd := exec.CommandContext(ctx, nsenterPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Env = append([]string(nil), inv.env...)
	return cmd
}

// shellQuote wraps a value in single quotes for /bin/sh.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// visiblePath joins the container root with an absolute container path,
// refusing ".", "..", and any component that is a symbolic link.
func visiblePath(root, targetPath string) (string, error) {
	clean := filepath.Clean(targetPath)
	if !filepath.IsAbs(clean) {
		return "", fmt.Errorf("container path %q is not absolute", targetPath)
	}
	cur := root
	for _, part := range components(clean) {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			return "", fmt.Errorf("container path %q escapes the container root", targetPath)
		}
		cur = filepath.Join(cur, part)
		info, err := os.Lstat(cur)
		if err != nil {
			if os.IsNotExist(err) {
				// Nothing below a missing component can exist either.
				continue
			}
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("container path %q passes through symlink %s", targetPath, cur)
		}
	}
	return filepath.Join(root, clean), nil
}

// availableBytes reports the space available to an unprivileged writer.
func availableBytes(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil
}
