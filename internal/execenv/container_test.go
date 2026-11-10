package execenv

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const containerRootLine = "1 63 0:29 / / rw - overlay overlay rw,upperdir=/run/kata-containers/abc/rootfs\n"

// newStagedTarget builds a container target over a temporary container root and
// a proc fixture whose pid has no separately mounted paths.
func newStagedTarget(t *testing.T) (*ContainerTarget, string) {
	t.Helper()
	proc := t.TempDir()
	if err := os.MkdirAll(filepath.Join(proc, "208"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "208", "mountinfo"), []byte(containerRootLine), 0o644); err != nil {
		t.Fatal(err)
	}
	return newContainerTarget(proc, 208, t.TempDir(), DefaultContainerPaths()), proc
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestContainerPathsValidation(t *testing.T) {
	if err := DefaultContainerPaths().validate(); err != nil {
		t.Fatalf("the default contract must be valid: %v", err)
	}

	cases := map[string]Paths{
		"root": {ModelDir: "/", InputDir: "/a/b", OutputDir: "/a/c", LogDir: "/a/d", ProgressPath: "/a/e/p.json"},
		"too shallow": {ModelDir: "/opt/taa", InputDir: "/opt/b", OutputDir: "/opt/c",
			LogDir: "/opt/d", ProgressPath: "/opt/e/p.json"},
		"relative": {ModelDir: "opt/taa/model", InputDir: "/opt/taa/input", OutputDir: "/opt/taa/output/result",
			LogDir: "/opt/taa/output/log", ProgressPath: "/opt/taa/output/progress/progress.json"},
		"overlapping dirs": {ModelDir: "/opt/taa/model", InputDir: "/opt/taa/model/sub",
			OutputDir: "/opt/taa/output/result", LogDir: "/opt/taa/output/log",
			ProgressPath: "/opt/taa/output/progress/progress.json"},
		"output contains progress": {ModelDir: "/opt/taa/model", InputDir: "/opt/taa/input",
			OutputDir: "/opt/taa/output", LogDir: "/opt/taa/log",
			ProgressPath: "/opt/taa/output/progress/progress.json"},
	}
	for name, paths := range cases {
		if err := paths.validate(); err == nil {
			t.Fatalf("%s: expected a validation error", name)
		}
	}
}

func TestContainerVisibleRejectsSymlinkComponents(t *testing.T) {
	target, _ := newStagedTarget(t)
	outside := t.TempDir()
	if err := os.MkdirAll(target.rootFS, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(target.rootFS, "opt")); err != nil {
		t.Fatal(err)
	}
	if _, err := target.Visible("/opt/taa/model"); err == nil {
		t.Fatal("a path through a symlink must be refused")
	}
}

func TestContainerVisibleAllowsMissingComponents(t *testing.T) {
	target, _ := newStagedTarget(t)
	got, err := target.Visible("/opt/taa/model")
	if err != nil {
		t.Fatalf("Visible: %v", err)
	}
	if want := filepath.Join(target.rootFS, "opt/taa/model"); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestContainerPrepareStagesAndClears(t *testing.T) {
	target, _ := newStagedTarget(t)
	modelDir := t.TempDir()
	writeFile(t, filepath.Join(modelDir, "train.py"), "print('hi')\n")
	writeFile(t, filepath.Join(modelDir, "lib", "util.py"), "X = 1\n")
	dataDir := t.TempDir()
	writeFile(t, filepath.Join(dataDir, "data.csv"), "a,b\n1,2\n")

	spec := Spec{
		ModelDir:     modelDir,
		DataDir:      dataDir,
		OutputDir:    "/taa-side/output",
		LogDir:       "/taa-side/log",
		ProgressPath: "/taa-side/progress/progress.json",
	}

	// A stale result and progress file from a previous run must not survive.
	writeFile(t, filepath.Join(target.rootFS, "opt/taa/output/result/stale.json"), "{}")
	writeFile(t, filepath.Join(target.rootFS, "opt/taa/output/progress/progress.json"), "{}")

	if err := target.Prepare(context.Background(), spec); err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	for _, rel := range []string{"opt/taa/model/train.py", "opt/taa/model/lib/util.py", "opt/taa/input/data.csv"} {
		if _, err := os.Stat(filepath.Join(target.rootFS, rel)); err != nil {
			t.Fatalf("%s was not staged: %v", rel, err)
		}
	}
	content, err := os.ReadFile(filepath.Join(target.rootFS, "opt/taa/input/data.csv"))
	if err != nil || string(content) != "a,b\n1,2\n" {
		t.Fatalf("dataset content=%q err=%v", content, err)
	}
	if _, err := os.Stat(filepath.Join(target.rootFS, "opt/taa/output/result/stale.json")); !os.IsNotExist(err) {
		t.Fatal("a stale result file survived Prepare")
	}
	if _, err := os.Stat(filepath.Join(target.rootFS, "opt/taa/output/progress/progress.json")); !os.IsNotExist(err) {
		t.Fatal("a stale progress file survived Prepare")
	}
	for _, dir := range []string{"opt/taa/output/result", "opt/taa/output/log", "opt/taa/output/progress"} {
		info, err := os.Stat(filepath.Join(target.rootFS, dir))
		if err != nil || !info.IsDir() {
			t.Fatalf("%s must exist as a directory: %v", dir, err)
		}
	}

	// The mapping is a whitelist: the contract paths translate, nothing else.
	if got := target.Resolve(modelDir); got != "/opt/taa/model" {
		t.Fatalf("Resolve(model)=%q", got)
	}
	if got := target.Resolve(dataDir); got != "/opt/taa/input" {
		t.Fatalf("Resolve(data)=%q", got)
	}
	if got := target.Resolve("/somewhere/else"); got != "/somewhere/else" {
		t.Fatalf("Resolve(unknown)=%q, want it untouched", got)
	}
}

func TestContainerPrepareRefusesMountedContractPath(t *testing.T) {
	target, proc := newStagedTarget(t)
	mounted := containerRootLine + "40 63 0:31 / /opt/taa/input rw - tmpfs tmpfs rw\n"
	if err := os.WriteFile(filepath.Join(proc, "208", "mountinfo"), []byte(mounted), 0o644); err != nil {
		t.Fatal(err)
	}
	modelDir := t.TempDir()
	writeFile(t, filepath.Join(modelDir, "train.py"), "x\n")

	err := target.Prepare(context.Background(), Spec{ModelDir: modelDir, DataDir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "mount point") {
		t.Fatalf("got %v, want a refusal naming the mount point", err)
	}
}

func TestContainerCleanupRemovesStaging(t *testing.T) {
	target, _ := newStagedTarget(t)
	modelDir := t.TempDir()
	writeFile(t, filepath.Join(modelDir, "train.py"), "x\n")
	if err := target.Prepare(context.Background(), Spec{ModelDir: modelDir, DataDir: t.TempDir()}); err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	target.Cleanup(context.Background(), Spec{})

	// The contract directories stay; only their contents belong to one run.
	for _, dir := range []string{"opt/taa/model", "opt/taa/input"} {
		full := filepath.Join(target.rootFS, dir)
		if info, err := os.Stat(full); err != nil || !info.IsDir() {
			t.Fatalf("%s must still exist after Cleanup: %v", dir, err)
		}
		entries, err := os.ReadDir(full)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("%s still holds %d entries after Cleanup", dir, len(entries))
		}
	}
}

func TestContainerBaseEnvKeepsTAAEnvironmentOut(t *testing.T) {
	t.Setenv("TAASECRETKEY", "secret")
	t.Setenv("PLATFORM_PUBLIC_KEY", "04ab")
	target, _ := newStagedTarget(t)
	for _, kv := range target.BaseEnv() {
		if strings.HasPrefix(kv, "TAASECRETKEY=") || strings.HasPrefix(kv, "PLATFORM_PUBLIC_KEY=") {
			t.Fatalf("the container environment carries TAA key material: %s", kv)
		}
	}
	if len(target.BaseEnv()) == 0 {
		t.Fatal("the container environment must at least provide PATH")
	}
}

func TestContainerCommandWrapsInNSEnter(t *testing.T) {
	target, _ := newStagedTarget(t)
	cmd := target.Command(context.Background(), "python3 train.py", "/opt/taa/model")

	want := []string{"/usr/bin/nsenter", "-t", "208", "-m", "-r", "--", "/bin/sh", "-c",
		"cd '/opt/taa/model' && python3 train.py"}
	if strings.Join(cmd.Args, "|") != strings.Join(want, "|") {
		t.Fatalf("argv=%q, want %q", cmd.Args, want)
	}
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid {
		t.Fatal("the command needs its own process group so a stop kills the container-side tree")
	}
	if cmd.Dir != "" {
		t.Fatalf("Dir=%q: the path is TAA's, not the container's; nsenter changes directory itself", cmd.Dir)
	}
}

func TestCopyTreeRefusesSymlinksAndSpecialFiles(t *testing.T) {
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "ok.txt"), "ok")
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}
	if err := copyTree(context.Background(), src, t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "symlink") {
		t.Fatalf("got %v, want a symlink refusal", err)
	}

	fifoDir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(fifoDir, "pipe"), 0o644); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	if err := copyTree(context.Background(), fifoDir, t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "unsupported file type") {
		t.Fatalf("got %v, want a special-file refusal", err)
	}
}

func TestTreeSizeCountsRegularFilesOnly(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a"), "12345")
	writeFile(t, filepath.Join(root, "sub", "b"), "123")
	writeFile(t, filepath.Join(root, "sub", "c"), "")

	got, err := treeSize(root)
	if err != nil {
		t.Fatalf("treeSize: %v", err)
	}
	if got != 8 {
		t.Fatalf("treeSize=%d, want 8", got)
	}
}
