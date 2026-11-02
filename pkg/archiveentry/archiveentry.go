// Package archiveentry identifies archive entries that are packaging metadata
// rather than package content.
package archiveentry

import (
	"path"
	"strings"
)

// IsMetadataPath reports whether an archive entry name is platform packaging
// metadata rather than a file the package ships.
//
// The decision is made from the name alone, and deliberately not from the tool
// or platform that produced the archive: a ZIP built by Finder, ditto or
// Info-ZIP on macOS sequesters AppleDouble files under __MACOSX, a tree copied
// from macOS to another platform can carry ._* files beside the real ones at any
// depth, and .DS_Store is the Finder's directory index. A package can therefore
// mix metadata left by several platforms, so the rule has to recognise each
// shape wherever it appears.
//
// name is an archive entry name (slash-separated) or a filesystem path. A
// backslash is normalised first, which covers the spelling a Windows packer may
// write. Any __MACOSX component disqualifies the whole entry, so content cannot
// be smuggled inside that directory.
func IsMetadataPath(name string) bool {
	normalized := strings.ReplaceAll(name, "\\", "/")
	for _, seg := range strings.Split(normalized, "/") {
		if strings.EqualFold(seg, "__MACOSX") {
			return true
		}
	}
	base := path.Base(normalized)
	return strings.HasPrefix(base, "._") || base == ".DS_Store"
}
