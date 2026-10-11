package codeaudit

import (
	"bytes"
	"path/filepath"
	"strings"
)

// BinaryKind is the reading the binary channel applies to a file. It is decided
// from the file's own leading bytes and only then, as a fallback, from its
// extension — never from the extension alone, because a package that can be
// renamed is a package whose extension carries no evidence.
type BinaryKind string

// The values ClassifyBinary returns. The order carries no meaning: the function
// decides by content test, not by walking this list.
const (
	KindELF        BinaryKind = "elf"
	KindArchive    BinaryKind = "archive"
	KindCompressed BinaryKind = "compressed"
	KindPickle     BinaryKind = "pickle"
	KindNumpy      BinaryKind = "numpy"
	KindRaw        BinaryKind = "raw"
	// KindText is the answer that means "not this channel's business": the file
	// is text, so whichever engine the deployment selected owns it. It is a
	// distinct value rather than an empty string so that a caller cannot confuse
	// "we looked and it is text" with "we never looked".
	KindText BinaryKind = "text"
)

// sniffBytes is how much of the head is read to classify a file. It is larger
// than every magic below and large enough for the NUL heuristic to see a real
// binary header, which is what the size is for: a NUL in the first few hundred
// bytes is the signal, and the rest is slack for a texterous header.
const sniffBytes = 4096

var (
	magicELF        = []byte{0x7f, 'E', 'L', 'F'}
	magicZip        = []byte{'P', 'K', 0x03, 0x04}
	magicZipEmpty   = []byte{'P', 'K', 0x05, 0x06}
	magicZipSpanned = []byte{'P', 'K', 0x07, 0x08}
	magicGzip       = []byte{0x1f, 0x8b}
	magicNumpy      = []byte{0x93, 'N', 'U', 'M', 'P', 'Y'}
)

// binaryExtensions are the extensions that claim a file for this channel even
// when its bytes look like text.
//
// It exists for the one shape content sniffing cannot see: a file whose content
// is text but whose name says it will be loaded as a library or a serialised
// object. Nothing else in the pipeline reads such a file — the source arms
// filter by extension and this channel filters by content — so without the list
// it would be examined by nobody, and "examined by nobody" is exactly the state
// this feature exists to end.
//
// The list adds to the content verdict; it never replaces it. A file with ELF
// magic named README.md is still an ELF.
var binaryExtensions = map[string]bool{
	".so": true, ".o": true, ".a": true, ".dylib": true, ".dll": true, ".exe": true,
	".bin": true, ".pt": true, ".pth": true, ".pkl": true, ".pickle": true,
	".joblib": true, ".safetensors": true, ".onnx": true, ".whl": true,
	".h5": true, ".pb": true, ".tflite": true, ".npy": true, ".npz": true,
	// Compiled Python. It is listed even though the content heuristic already
	// catches it - a real .pyc measured 229 to 2264 NUL bytes in its first 4 KiB
	// - because a model package carries more .pyc than .py (110 against 60 in
	// the example corpus) and the most on-point format in this channel should
	// not depend on a heuristic holding. The interpreter loads these directly.
	".pyc": true, ".pyo": true,
}

// ClassifyBinary decides how a file should be read. head is the file's first
// sniffBytes (fewer at end of file); path is consulted only by the pickle branch
// and the binary-extension fallback.
func ClassifyBinary(head []byte, path string) BinaryKind {
	switch {
	case bytes.HasPrefix(head, magicELF):
		return KindELF
	case bytes.HasPrefix(head, magicZip),
		bytes.HasPrefix(head, magicZipEmpty),
		bytes.HasPrefix(head, magicZipSpanned):
		// PyTorch .pt, .whl, .npz and .jar are all zips. The format is one
		// reading because the evasion is the same in each: a member that is a
		// pickle or an ELF.
		return KindArchive
	case bytes.HasPrefix(head, magicGzip):
		return KindCompressed
	case bytes.HasPrefix(head, magicNumpy):
		return KindNumpy
	case isPickleStream(head, path):
		return KindPickle
	}
	if looksBinary(head) {
		return KindRaw
	}
	if binaryExtensions[strings.ToLower(filepath.Ext(path))] {
		return KindRaw
	}
	return KindText
}

// isPickleStream reports whether head begins a pickle stream.
//
// Pickle protocols 2 and up begin with PROTO (0x80) followed by the protocol
// number, which is a magic. Protocols 0 and 1 have no magic at all: a protocol 0
// pickle of a tuple is the single byte "(". For those the extension is the only
// signal available, and taking it is cheap — being wrong costs one strings pass
// over a file nothing else would have read.
func isPickleStream(head []byte, path string) bool {
	if len(head) >= 2 && head[0] == 0x80 && head[1] >= 0x02 && head[1] <= 0x05 {
		return true
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".pkl", ".pickle", ".joblib":
		return true
	}
	return false
}

// looksBinary applies the heuristic git and grep do: a NUL byte in the head
// means the file is not text.
//
// It is a heuristic and its blind spot is worth stating: UTF-16 text carries NUL
// bytes and is therefore read here as a raw binary. The cost of that mistake is
// a strings-and-entropy pass over a text file, which reports nothing; the cost
// of the opposite mistake is a binary read as text, which is the hole this
// feature exists to close. The asymmetry is why the cheaper error is the one
// taken.
func looksBinary(head []byte) bool {
	return bytes.IndexByte(head, 0x00) >= 0
}
