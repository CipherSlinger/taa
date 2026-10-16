package fhe

import "testing"

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
