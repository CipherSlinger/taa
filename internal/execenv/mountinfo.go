package execenv

import (
	"strconv"
	"strings"
)

// mountEntry is one parsed /proc/<pid>/mountinfo line. The two halves of the
// line - everything before " - " and everything after it - describe the mount
// as the kernel sees it and the filesystem behind it.
type mountEntry struct {
	ID           int
	Parent       int
	MajorMinor   string
	Root         string
	MountPoint   string
	FSType       string
	SuperOptions string
}

// parseMountInfo parses a mountinfo file. A malformed line is skipped rather
// than failing the whole file: a scan that runs while processes come and go
// must not be defeated by one entry it cannot read.
func parseMountInfo(data string) []mountEntry {
	var entries []mountEntry
	for _, line := range strings.Split(data, "\n") {
		sep := strings.Index(line, " - ")
		if sep < 0 {
			continue
		}
		pre := strings.Fields(line[:sep])
		post := strings.Fields(line[sep+len(" - "):])
		if len(pre) < 5 || len(post) < 3 {
			continue
		}
		id, err := strconv.Atoi(pre[0])
		if err != nil {
			continue
		}
		parent, err := strconv.Atoi(pre[1])
		if err != nil {
			continue
		}
		entries = append(entries, mountEntry{
			ID:           id,
			Parent:       parent,
			MajorMinor:   pre[2],
			Root:         unescapeMountInfo(pre[3]),
			MountPoint:   unescapeMountInfo(pre[4]),
			FSType:       post[0],
			SuperOptions: post[2],
		})
	}
	return entries
}

// unescapeMountInfo undoes the octal escaping mountinfo applies to spaces,
// tabs, newlines and backslashes in path fields.
func unescapeMountInfo(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && isOctal(s[i+1]) && isOctal(s[i+2]) && isOctal(s[i+3]) {
			v := (s[i+1]-'0')<<6 | (s[i+2]-'0')<<3 | (s[i+3] - '0')
			b.WriteByte(v)
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isOctal(c byte) bool { return c >= '0' && c <= '7' }

// rootMount returns the entry describing the mount at "/" with root "/",
// which is the shape every container's own root has. The boolean is false when
// no such entry exists.
func rootMount(entries []mountEntry) (mountEntry, bool) {
	for _, e := range entries {
		if e.MountPoint == "/" && e.Root == "/" {
			return e, true
		}
	}
	return mountEntry{}, false
}
