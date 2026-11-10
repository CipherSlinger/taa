package execenv

import (
	"context"
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

// containerEnv is the environment a container-executed model starts from.
// It is deliberately minimal: TAA's own environment carries key material
// (PLATFORM_PUBLIC_KEY, TAASECRETKEY), and the model is exactly the code whose
// behaviour the platform is watching, so it must not receive what TAA holds.
var containerEnv = []string{
	"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	"HOME=/root",
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

	mu   sync.Mutex
	spec Spec
}

func newContainerTarget(procRoot string, pid int, rootFS string, paths Paths) *ContainerTarget {
	return &ContainerTarget{procRoot: procRoot, pid: pid, rootFS: rootFS, paths: paths}
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
// minimal environment, never TAA's.
func (t *ContainerTarget) BaseEnv() []string { return append([]string(nil), containerEnv...) }

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
	return nil
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

// Command implements Target. nsenter only changes the mount (and user)
// namespace; the process group is set here so a stop still SIGKILLs the whole
// tree, including the shell nsenter forks inside the container.
func (t *ContainerTarget) Command(ctx context.Context, commandLine, workDir string) *exec.Cmd {
	shell := "cd " + shellQuote(workDir) + " && " + commandLine
	return nsenterShell(ctx, t.pid, shell)
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

// nsenterShell builds a shell invocation inside the container's mount
// namespace. -m is the mount namespace and -r enters it as root; the pid
// namespace is deliberately not changed, because that would only affect
// processes nsenter forks and the model does not need a private PID view.
func nsenterShell(ctx context.Context, pid int, shellCommand string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, nsenterPath,
		"-t", strconv.Itoa(pid), "-m", "-r", "--", "/bin/sh", "-c", shellCommand)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Env = append([]string(nil), containerEnv...)
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
