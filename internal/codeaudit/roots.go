package codeaudit

import (
	"path/filepath"
	"strings"
)

// ScanRoots classifies a file path by which of a scan's roots contains it. A
// merged scan covers more than one tree and a finding carries only the path it
// was found in, so "which root is this" has to be recovered from the path. The
// classification reads no state, starts no process, and is total: a path under
// no root answers false rather than guessing the nearest one.
//
// The roots are kept in their normalized form because both sides of the
// comparison have to be spelled the same way. The walk hands back whatever
// spelling its root had, and a root can be reached through more than one
// spelling ("./a", "a" and "a/." are one directory); normalizing both sides is
// what keeps a file from being attributed to no root because its prefix did not
// match byte for byte.
type ScanRoots struct {
	roots []string
}

// NewScanRoots builds a classifier over dirs, in the order given. Empty entries
// are dropped rather than kept: an empty root has no separator to require, so it
// would match every path and make the classifier's answer useless.
func NewScanRoots(dirs []string) *ScanRoots {
	r := &ScanRoots{}
	for _, d := range dirs {
		if d == "" {
			continue
		}
		r.roots = append(r.roots, cleanAbs(d))
	}
	return r
}

// Roots returns the normalized roots, in the order given. The slice is a copy,
// so a caller cannot change what RootOf answers by editing it.
func (r *ScanRoots) Roots() []string {
	out := make([]string, len(r.roots))
	copy(out, r.roots)
	return out
}

// RootOf returns the root that contains path, and whether one does.
//
// When one root is a prefix of another the longest match wins, so a file in the
// nested tree is attributed to the nested root rather than to the tree that
// contains it. The prefix test requires a separator after the root, so /a/bc is
// not treated as living under /a/b; a bare strings.HasPrefix would say it is.
//
// A path under no root returns ("", false). It is deliberately not attributed to
// the first or nearest root: a path that belongs to neither tree can only come
// from a bug, and inventing an owner for it would put a finding under a root it
// did not come from — the misattribution this type exists to prevent.
func (r *ScanRoots) RootOf(path string) (string, bool) {
	if path == "" {
		return "", false
	}
	p := cleanAbs(path)

	best := ""
	found := false
	for _, root := range r.roots {
		if p != root && !strings.HasPrefix(p, root+string(filepath.Separator)) {
			continue
		}
		if !found || len(root) > len(best) {
			best = root
			found = true
		}
	}
	return best, found
}

// ReportHasFindingsUnder reports whether any file report whose path is under root
// carries at least one finding.
//
// Attribution uses FilePath, never File: File is a basename, and basenames
// collide across roots — a merged scan of a model tree and a dependency tree
// almost certainly holds two __init__.py files, and a check keyed on the
// basename would attribute one tree's finding to the other. The same applies to
// Finding.File, which for both engines is the path the walk produced.
func ReportHasFindingsUnder(report *AuditReport, root string) bool {
	if report == nil || root == "" {
		return false
	}
	roots := NewScanRoots([]string{root})
	for _, fr := range report.FileReports {
		if fr.FindingsCount == 0 {
			continue
		}
		if _, ok := roots.RootOf(fr.FilePath); ok {
			return true
		}
	}
	return false
}
