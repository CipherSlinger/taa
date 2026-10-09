package codeaudit

import (
	"path/filepath"
	"testing"
)

// TestScanRootsRootOf pins the classification a merged report's per-root
// breakdown is built from. Every rule below is a way to get the attribution
// wrong, and a wrong attribution is worse than no attribution: it names a root
// that the finding did not come from, which is exactly the inference a merged
// report exists to remove.
func TestScanRootsRootOf(t *testing.T) {
	base := t.TempDir()
	a := filepath.Join(base, "a")
	sibling := filepath.Join(base, "abc") // shares the byte prefix with a but not a separator

	cases := []struct {
		name string
		dirs []string
		path string
		want string
		ok   bool
	}{
		{
			name: "path equal to a root belongs to that root",
			dirs: []string{a},
			path: a,
			want: a, ok: true,
		},
		{
			name: "path under a root belongs to it",
			dirs: []string{a},
			path: filepath.Join(a, "pkg", "util.py"),
			want: a, ok: true,
		},
		{
			name: "the longest matching root wins when one root is a prefix of another",
			dirs: []string{a, filepath.Join(a, "pkg")},
			path: filepath.Join(a, "pkg", "util.py"),
			want: filepath.Join(a, "pkg"), ok: true,
		},
		{
			// The longest-match rule must not collapse a nested root's own files
			// onto the outer root either.
			name: "a file outside the nested root still belongs to the outer root",
			dirs: []string{a, filepath.Join(a, "pkg")},
			path: filepath.Join(a, "train.py"),
			want: a, ok: true,
		},
		{
			// This is the trap strings.HasPrefix walks into: the byte prefix
			// matches but the separator does not.
			name: "the prefix test includes the separator",
			dirs: []string{filepath.Join(base, "a", "b")},
			path: filepath.Join(base, "a", "bc", "x.py"),
			want: "", ok: false,
		},
		{
			name: "a sibling whose name extends a root's name is not under it",
			dirs: []string{a},
			path: filepath.Join(sibling, "x.py"),
			want: "", ok: false,
		},
		{
			name: "a path under no root answers false rather than guessing the nearest one",
			dirs: []string{a},
			path: filepath.Join(base, "elsewhere", "x.py"),
			want: "", ok: false,
		},
		{
			name: "spelling differences are normalized before comparing",
			dirs: []string{a + string(filepath.Separator) + "."},
			path: filepath.Join(a, "x.py"),
			want: a, ok: true,
		},
		{
			name: "empty entries are dropped rather than matching everything",
			dirs: []string{"", a},
			path: filepath.Join(a, "x.py"),
			want: a, ok: true,
		},
		{
			name: "an empty path is under no root",
			dirs: []string{a},
			path: "",
			want: "", ok: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewScanRoots(tc.dirs)
			got, ok := r.RootOf(tc.path)
			if ok != tc.ok {
				t.Fatalf("RootOf(%q) ok = %v, want %v", tc.path, ok, tc.ok)
			}
			if ok && cleanAbs(got) != cleanAbs(tc.want) {
				t.Errorf("RootOf(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

// TestScanRootsRootsReturnsACopy pins that a caller cannot mutate the classifier
// through the slice it was handed.
func TestScanRootsRootsReturnsACopy(t *testing.T) {
	r := NewScanRoots([]string{"/a", "/b"})
	roots := r.Roots()
	if len(roots) != 2 {
		t.Fatalf("Roots() = %v, want 2 entries", roots)
	}
	roots[0] = "/mutated"
	if again := r.Roots(); again[0] == "/mutated" {
		t.Error("Roots() handed out its backing slice; a caller can corrupt the classifier")
	}
}

// TestReportHasFindingsUnder pins that attribution reads FilePath, not File.
//
// File is a basename (audit.go's BuildFileReport sets it from filepath.Base), and
// a merged scan of two roots almost certainly contains two files with the same
// basename — an __init__.py in each tree. A check keyed on the basename would
// report a finding in one root for a file that lives in the other, which is the
// misattribution that chooses the wrong root to roll back.
func TestReportHasFindingsUnder(t *testing.T) {
	rootA := filepath.Join(t.TempDir(), "model")
	rootB := filepath.Join(t.TempDir(), "deps")

	report := &AuditReport{
		FileReports: []FileReport{
			{File: "__init__.py", FilePath: filepath.Join(rootA, "__init__.py"), FindingsCount: 0},
			{File: "train.py", FilePath: filepath.Join(rootA, "train.py"), FindingsCount: 2},
			{File: "__init__.py", FilePath: filepath.Join(rootB, "__init__.py"), FindingsCount: 0},
		},
	}

	if !ReportHasFindingsUnder(report, rootA) {
		t.Error("ReportHasFindingsUnder = false for a root with a finding under it")
	}
	if ReportHasFindingsUnder(report, rootB) {
		t.Error("ReportHasFindingsUnder = true for a root whose only file has no findings")
	}
	if ReportHasFindingsUnder(report, filepath.Join(t.TempDir(), "other")) {
		t.Error("ReportHasFindingsUnder = true for a root the report never touched")
	}
}
