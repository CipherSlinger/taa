package fhe

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	testHashA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testHashB = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
)

func TestValidHashRejectsUnsafeIdentifiers(t *testing.T) {
	bad := []string{
		"",
		"../../etc",
		"..",
		".",
		"/etc/passwd",
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",   // 63
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0", // 65
		"0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",  // uppercase
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg",  // non-hex
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde/",
		"0123456789abcdef 123456789abcdef0123456789abcdef0123456789abcdef",
	}
	for _, s := range bad {
		if ValidHash(s) {
			t.Errorf("ValidHash(%q) = true, want false", s)
		}
	}
	if !ValidHash(testHashA) {
		t.Errorf("ValidHash(%q) = false, want true", testHashA)
	}
}

func TestValidTaskID(t *testing.T) {
	good := []string{"task-1", "task_1", "task.1", "T1", "a"}
	for _, s := range good {
		if err := ValidTaskID(s); err != nil {
			t.Errorf("ValidTaskID(%q) = %v, want nil", s, err)
		}
	}
	bad := []string{"", "..", ".", "../x", "a/b", "a\\b", "a b", "a\x00b", string(make([]byte, 200))}
	for _, s := range bad {
		if err := ValidTaskID(s); err == nil {
			t.Errorf("ValidTaskID(%q) = nil, want error", s)
		}
	}
}

func TestLayoutPaths(t *testing.T) {
	l := NewLayout("/data")

	cases := []struct {
		name string
		got  string
		err  error
		want string
	}{
		{"ModelDir", "", nil, "/data/models/" + testHashA},
		{"KeyDir", "", nil, "/data/keys/" + testHashA},
		{"KeyPath", "", nil, "/data/keys/" + testHashA + "/eval_context.bin"},
		{"TaskDir", "", nil, "/data/tasks/task-1"},
		{"TaskInputPath", "", nil, "/data/tasks/task-1/input.zip"},
		{"ResultPath", "", nil, "/data/results/task-1/output.zip"},
	}
	var err error
	cases[0].got, cases[0].err = l.ModelDir(testHashA)
	cases[1].got, cases[1].err = l.KeyDir(testHashA)
	cases[2].got, cases[2].err = l.KeyPath(testHashA)
	cases[3].got, cases[3].err = l.TaskDir("task-1")
	cases[4].got, cases[4].err = l.TaskInputPath("task-1")
	cases[5].got, cases[5].err = l.ResultPath("task-1")

	for _, c := range cases {
		if c.err != nil {
			t.Fatalf("%s: unexpected error: %v", c.name, c.err)
		}
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}

	if _, err = l.KeyPath("../escape"); err == nil {
		t.Error("KeyPath accepted a traversal hash, want error")
	}
	if _, err = l.ModelDir(testHashB); err != nil {
		t.Errorf("ModelDir(%q) = %v, want nil", testHashB, err)
	}
	if _, err = l.TaskInputPath("../escape"); err == nil {
		t.Error("TaskInputPath accepted a traversal task id, want error")
	}
}

func TestLayoutRejectsEmptyRoot(t *testing.T) {
	if _, err := NewLayout("").KeyPath(testHashA); err == nil {
		t.Error("empty data dir accepted, want error")
	}
}

// TestMkdirSharedRelaxesAnAlreadyExistingDirectory pins the half of the shared
// directory fix that os.MkdirAll alone cannot cover.
//
// MkdirAll leaves the mode of a directory that already exists alone, so a
// <data>/keys/<userID> an earlier run created under a restrictive umask stays
// 0700 for good unless the call that finds it there relaxes it too - and the
// whole point of relaxing it is that the service traverses these directories as
// another user.
func TestMkdirSharedRelaxesAnAlreadyExistingDirectory(t *testing.T) {
	root := t.TempDir()
	l := NewLayout(root)
	keyDir, err := l.KeyDir(testHashA)
	if err != nil {
		t.Fatalf("KeyDir: %v", err)
	}
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatalf("pre-create the key dir: %v", err)
	}

	if err := l.MkdirShared(keyDir); err != nil {
		t.Fatalf("MkdirShared: %v", err)
	}
	for _, p := range []string{filepath.Join(root, "keys"), keyDir} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if got := st.Mode().Perm(); got != sharedDirMode {
			t.Errorf("%s is %v after MkdirShared, want %v: MkdirAll changed nothing on a directory that already existed, so relaxing a mode cannot be left to the create", p, got, sharedDirMode)
		}
	}
}

// TestMkdirSharedStaysInsideTheDataDir bounds the blast radius of the directory
// fix: since it chmods the ancestors of what it creates, it must not walk out of
// the shared data directory - neither upward past the root, whose mode belongs to
// the bind mount and to deploy-fhe.sh, nor into a path outside it at all.
func TestMkdirSharedStaysInsideTheDataDir(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "data")
	outside := filepath.Join(base, "private")
	// 0700 throughout, set rather than inherited - t.TempDir's own mode follows the
	// umask - so that any relaxation by the calls below is visible.
	for _, p := range []string{base, root, outside} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatalf("create %s: %v", p, err)
		}
		if err := os.Chmod(p, 0o700); err != nil {
			t.Fatalf("chmod %s: %v", p, err)
		}
	}
	l := NewLayout(root)

	// A published directory is a legitimate call, and the walk up from it has to
	// stop at the root.
	keyDir, err := l.KeyDir(testHashA)
	if err != nil {
		t.Fatalf("KeyDir: %v", err)
	}
	if err := l.MkdirShared(keyDir); err != nil {
		t.Fatalf("MkdirShared: %v", err)
	}
	if err := l.MkdirShared(outside); err == nil {
		t.Error("MkdirShared outside the data dir = nil, want error")
	}
	if err := l.MkdirShared(base); err == nil {
		t.Error("MkdirShared on the data dir's parent = nil, want error")
	}

	for _, p := range []string{base, root, outside} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if got := st.Mode().Perm(); got != 0o700 {
			t.Errorf("%s is %v, want 0700 unchanged: MkdirShared relaxed a directory it was not asked to create", p, got)
		}
	}
}

// TestMakeTreeSharedRelaxesAnExtractedPackage covers the tree MakeTreeShared
// exists for: one an extraction left behind, whose modes were decided by
// os.MkdirTemp (0700, whatever the umask is) and by the archive members (masked
// by the umask).
//
// It is a unit test rather than only an end-to-end one because the execute bits
// are the part that is easy to get wrong: assigning sharedFileMode outright is
// the obvious implementation and it is wrong, since ExtractArchiveToDir has
// already run ChmodScripts over the tree and a member that arrived executable has
// to stay executable.
func TestMakeTreeSharedRelaxesAnExtractedPackage(t *testing.T) {
	root := t.TempDir()
	l := NewLayout(root)
	modelDir, err := l.ModelDir(testHashA)
	if err != nil {
		t.Fatalf("ModelDir: %v", err)
	}
	serverDir := filepath.Join(modelDir, "server")
	// 0700 throughout, set rather than inherited - t.TempDir returns a directory
	// created 0777 &^ umask, so its own mode is not the one to assert against - so
	// that any relaxation by the calls below is visible.
	for _, dir := range []string{root, filepath.Join(root, "models"), modelDir, serverDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("create %s: %v", dir, err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatalf("chmod %s: %v", dir, err)
		}
	}
	plain := filepath.Join(serverDir, "model.bin")
	script := filepath.Join(serverDir, "run.sh")
	for path, mode := range map[string]os.FileMode{plain: 0o600, script: 0o755} {
		if err := os.WriteFile(path, []byte("x"), mode); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatalf("chmod %s: %v", path, err)
		}
	}

	// The two calls the import path makes, in the order it makes them: MkdirShared
	// puts <data>/models and the model directory itself in place before the
	// extraction replaces the latter, and MakeTreeShared then covers everything the
	// extraction left behind. MakeTreeShared walks down from its argument only, so
	// the parent is exactly the half MkdirShared is here for.
	if err := l.MkdirShared(modelDir); err != nil {
		t.Fatalf("MkdirShared: %v", err)
	}
	if err := l.MakeTreeShared(modelDir); err != nil {
		t.Fatalf("MakeTreeShared: %v", err)
	}

	for _, dir := range []string{filepath.Join(root, "models"), modelDir, serverDir} {
		st, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("stat %s: %v", dir, err)
		}
		if got := st.Mode().Perm(); got != sharedDirMode {
			t.Errorf("%s is %v after the import path's two calls, want %v: the service enters it as another user", dir, got, sharedDirMode)
		}
	}
	st, err := os.Stat(plain)
	if err != nil {
		t.Fatalf("stat %s: %v", plain, err)
	}
	if got := st.Mode().Perm(); got != sharedFileMode {
		t.Errorf("%s is %v after MakeTreeShared, want %v: the service reads it as another user", plain, got, sharedFileMode)
	}
	// The execute bits survive: the helper adds permissions, it does not set them.
	st, err = os.Stat(script)
	if err != nil {
		t.Fatalf("stat %s: %v", script, err)
	}
	if got := st.Mode().Perm(); got != 0o755 {
		t.Errorf("%s is %v after MakeTreeShared, want 0755: the extraction had already made it executable", script, got)
	}

	// The shared root is not the helper's to relax, and neither is anything outside
	// it: its mode belongs to the bind mount and to deploy-fhe.sh.
	if err := l.MakeTreeShared(filepath.Dir(root)); err == nil {
		t.Error("MakeTreeShared outside the data dir = nil, want error")
	}
	if err := l.MakeTreeShared(root); err != nil {
		t.Fatalf("MakeTreeShared on the shared root: %v", err)
	}
	st, err = os.Stat(root)
	if err != nil {
		t.Fatalf("stat %s: %v", root, err)
	}
	if got := st.Mode().Perm(); got != 0o700 {
		t.Errorf("the shared root is %v, want its own mode untouched", got)
	}
}
