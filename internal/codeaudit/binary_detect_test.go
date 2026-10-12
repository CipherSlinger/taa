package codeaudit

import (
	"strings"
	"testing"
)

// TestClassifyBinary pins the content-first routing the binary channel is built
// on. Every case here is a byte prefix, not a file name, because the whole point
// of sniffing is that a package can be renamed freely and the bytes cannot.
func TestClassifyBinary(t *testing.T) {
	cases := []struct {
		name string
		head []byte
		path string
		want BinaryKind
	}{
		{"elf magic", []byte("\x7fELF\x02\x01\x01\x00"), "libfoo.so", KindELF},
		{"elf magic beats a source extension", []byte("\x7fELF\x02\x01\x01\x00"), "train.py", KindELF},
		{"zip magic", []byte("PK\x03\x04\x14\x00"), "model.pt", KindArchive},
		{"empty zip magic", []byte("PK\x05\x06\x00\x00"), "empty.whl", KindArchive},
		{"gzip magic", []byte{0x1f, 0x8b, 0x08, 0x00}, "weights.gz", KindCompressed},
		{"numpy magic", []byte("\x93NUMPY\x01\x00"), "tensor.npy", KindNumpy},
		{"pickle protocol 4 magic", []byte{0x80, 0x04, 0x95, 0x00}, "blob.bin", KindPickle},
		{"pickle protocol 0 by extension", []byte("(lp0\nS'x'\np1\n"), "evil.pkl", KindPickle},
		{"nul byte means binary", []byte("text\x00more text"), "weights.bin", KindRaw},
		{"nul byte under a text extension", []byte("text\x00more text"), "notes.txt", KindRaw},
		{"nul in the first byte under a text extension", []byte("\x00plain ascii after a nul"), "notes.txt", KindRaw},
		{"pickle protocol 1 is below the magic range", []byte{0x80, 0x01, 0x00, 0x00}, "blob.dat", KindRaw},
		{"pickle protocol 6 is above the magic range", []byte{0x80, 0x06, 0x00, 0x00}, "blob.dat", KindRaw},
		{"binary extension claims an all-text file", []byte("#!/bin/sh\necho hi\n"), "libevil.so", KindRaw},
		{"python source stays text", []byte("import os\nos.system('x')\n"), "train.py", KindText},
		{"utf8 text without nul stays text", []byte("héllo wörld\n"), "notes.txt", KindText},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyBinary(tc.head, tc.path); got != tc.want {
				t.Errorf("ClassifyBinary(%q, %q) = %q, want %q", tc.head, tc.path, got, tc.want)
			}
		})
	}
}

// TestClassifyBinaryEmptyFile pins the degenerate input: a zero-byte file has no
// magic and no NUL, so it is text, and the source channel's own behaviour for it
// is unchanged by this feature.
func TestClassifyBinaryEmptyFile(t *testing.T) {
	if got := ClassifyBinary(nil, "empty.py"); got != KindText {
		t.Errorf("ClassifyBinary(nil, empty.py) = %q, want %q", got, KindText)
	}
}

// TestClassifyBinaryClaimsAProtocol01PickleByItsContent pins the claim rule for
// the one pickle shape that has no magic. A protocol 0/1 stream is ASCII, so
// neither the magic test nor looksBinary sees it, and the extension was the only
// signal left - which made a rename the whole evasion.
func TestClassifyBinaryClaimsAProtocol01PickleByItsContent(t *testing.T) {
	// The classic protocol 0 payload: GLOBAL posix.system, then REDUCE over a
	// one-element tuple. The interpreter resolves the GLOBAL to a SourcePickle
	// line, and that line is what the claim rests on.
	payload := []byte("cposix\nsystem\n(Vid\ntR.")
	// A real protocol 0 pickle of a two-element list. It is a pickle, and it
	// carries no module.attribute target, so there is no PKL_001 evidence to
	// find in it.
	noTarget := []byte("(lp0\nI1\naI2\na.")

	cases := []struct {
		name string
		head []byte
		path string
		want BinaryKind
	}{
		{"a payload named .bin is claimed", payload, "model.bin", KindPickle},
		{"a payload named .pt is claimed", payload, "model.pt", KindPickle},
		{"a payload named .pth is claimed", payload, "payload.pth", KindPickle},
		{"a payload named .json is claimed", payload, "model.json", KindPickle},
		{"a payload with no extension is claimed", payload, "payload", KindPickle},
		{"the extension's case does not decide it", payload, "MODEL.PT", KindPickle},

		{"a target-less pickle named .bin stays raw", noTarget, "model.bin", KindRaw},
		{"a target-less pickle named .json stays text", noTarget, "model.json", KindText},
		{"a target-less pickle named .pkl is still claimed by extension", noTarget, "model.pkl", KindPickle},

		// A realistic source file: "#" is not an opcode, so the walk stops at
		// byte 0 and the file stays with the channel that reads Python.
		{"python source is not taken from the source channel",
			[]byte("# -*- coding: utf-8 -*-\nimport os\nos.system('id')\n"), "train.py", KindText},
		// The 3.10 .pyc magic begins 0x6f, which is the OBJ opcode: the walk takes
		// "\r\r" as a module name and then runs out of head mid-operand, so no
		// target is resolved. The coincidence is why the case is pinned.
		{"a 3.10 pyc head is not claimed",
			[]byte{0x6f, 0x0d, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00}, "m.cpython-310.pyc", KindRaw},
		{"a 3.12 pyc head is not claimed",
			[]byte{0xcb, 0x0d, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00}, "m.cpython-312.pyc", KindRaw},
		{"a binary blob is not claimed",
			[]byte{0x00, 0x01, 0x02, 0x63, 0x70, 0x6f, 0x73, 0x69, 0x78, 0x0a}, "weights.bin", KindRaw},

		// An import line is operand-shaped: "i" is INST and takes the next two
		// lines as its module and name, so this head walks and resolves a target.
		// It is still a source file, and the sniff must not take it.
		{"an import-led source head stays text",
			[]byte("import os\nos.system('x')\n"), "train.py", KindText},
		// The same head under a name the source arm does not read is not claimed
		// either: the "target" it resolves is a line of text read as an operand,
		// not a module.attribute pair.
		{"an import-led head named .bin is not claimed",
			[]byte("import os\nos.system('x')\n"), "model.bin", KindRaw},
		// A real target is a dotted identifier, and the shape test must not
		// overreach: this is the two-line protocol 0 pickle of an OrderedDict.
		{"a dotted-identifier target is claimed",
			[]byte("ccollections\nOrderedDict\np0\n."), "model.bin", KindPickle},
		// The sniff refuses a source name; the extension set still claims one.
		{"a source-named file with a pickle name is still claimed",
			payload, "model.pkl", KindPickle},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyBinary(tc.head, tc.path); got != tc.want {
				t.Errorf("ClassifyBinary(%q, %q) = %q, want %q", tc.head, tc.path, got, tc.want)
			}
		})
	}
}

// TestSourceExtensionsCoverTheSourceArmsDefaults pins the one coupling the claim
// rule rests on: every extension the source arm reads has to be one the sniff
// refuses. The rule is not "these are source files", it is "another channel has
// rules for this file, so this one does not take it" - and a language added to
// the source arm without being added here would silently reopen the hole the
// guard closes, because MergeBinaryFindings drops the text findings of every
// claimed file.
func TestSourceExtensionsCoverTheSourceArmsDefaults(t *testing.T) {
	exts := DefaultConfig().Extensions
	if len(exts) == 0 {
		t.Fatal("the source arm's default extension list is empty, so this test asserts nothing")
	}
	for _, ext := range exts {
		if !sourceExtensions[strings.ToLower(ext)] {
			t.Errorf("the source arm reads %s and the pickle sniff would claim it: add it to sourceExtensions", ext)
		}
	}
}
