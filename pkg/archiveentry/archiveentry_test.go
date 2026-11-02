package archiveentry

import "testing"

func TestIsMetadataPath(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		// AppleDouble sequestered by a macOS zip.
		{"__MACOSX/._train.py", true},
		{"__MACOSX/sub/._train.py", true},
		{"./__MACOSX/._train.py", true},
		// AppleDouble left beside the real file at any depth, or after a
		// Windows packer's separator.
		{"._train.py", true},
		{"pkg/models/._weights.py", true},
		{"pkg\\models\\._weights.py", true},
		// Finder directory index.
		{".DS_Store", true},
		{"pkg/.DS_Store", true},
		// Case is not a property of the convention.
		{"__macosx/._train.py", true},
		// Real content, including names that merely look similar.
		{"train.py", false},
		{"pkg/models/weights.py", false},
		{"__MACOSX_notes.py", false},
		{"pkg/__MACOSX_notes.py", false},
		{"notes/._train.py.bak", true}, // still an AppleDouble sidecar name
		{"a/._dir/train.py", false},    // ._ as a directory is not a sidecar
		{"", false},
	}
	for _, tt := range tests {
		if got := IsMetadataPath(tt.name); got != tt.want {
			t.Errorf("IsMetadataPath(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}
