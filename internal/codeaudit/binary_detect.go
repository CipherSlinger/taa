package codeaudit

import (
	"bytes"
	"path/filepath"
	"regexp"
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

// sourceExtensions are the extensions the source arm reads, and the pickle sniff
// never claims one of them.
//
// It is not a second opinion about what source is. What makes a file a source
// file here is that another channel has rules for it: a claimed file is one the
// merge step drops from that channel's reading, keeping no text finding for a
// path in Claimed. (MergeBinaryFindings lands in the next task; this guard is
// written against that contract rather than an existing call.) Claiming a source
// file would leave it read by neither - this channel would discard its text
// findings and the source arm would not be believed about it. An import line is
// exactly the shape of a protocol 0 target - "i" is INST, which consumes the next
// two lines as its module and name, so "import os\nos.system('x')\n" walks
// cleanly and resolves one - which is why the extension, and not the walk, is
// what separates the two readings.
//
// TestSourceExtensionsCoverTheSourceArmsDefaults pins the correspondence, so a
// language added to the source arm has to be added here in the same change.
var sourceExtensions = map[string]bool{
	".py": true,
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
// pickle of a tuple is the single byte "(", and a payload is ASCII to the last
// byte. For those the extension used to be the only signal, and that left a
// rename as the whole evasion - "cposix\nsystem\n(Vid\ntR." named model.bin,
// model.pt or payload.pth was classified raw, and named model.json it was
// classified text, and either way the interpreter never ran and PKL_001 could
// not fire.
//
// So a protocol 0/1 stream is claimed by its content: one veto and two signals,
// each closing a hole the others leave open:
//
//   - The extension is not one the source arm reads. See sourceExtensions: the
//     merge step drops a claimed file from the source arm's reading, so a crafted
//     source file shaped like a pickle could hide a source finding.
//   - The head walks to a target with no structural mark on the way.
//   - The target is shaped like one. See sniffProtocol01Pickle: without this, an
//     import line resolves "mport os.os.system('x')", which is a line of text
//     read as an operand rather than a target.
//
// The extension set is the second test, ahead of both the source veto and the
// sniff, so a .pkl, .pickle or .joblib is claimed by its name whatever its bytes
// look like - which covers a protocol 0/1 stream whose target lies past the head,
// and a file that does not walk at all. It cannot cover a source-named file: .py
// is not in the extension set, and the veto for it runs after this test.
func isPickleStream(head []byte, path string) bool {
	if len(head) >= 2 && head[0] == 0x80 && head[1] >= 0x02 && head[1] <= 0x05 {
		return true
	}
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".pkl", ".pickle", ".joblib":
		return true
	}
	if sourceExtensions[ext] {
		return false
	}
	return sniffProtocol01Pickle(head)
}

// sniffProtocol01Pickle reports whether head begins a pickle stream that the
// unpickler would resolve a module.attribute target in.
//
// It asks the interpreter rather than a second opcode table. The claim has to
// agree with the parse that follows it, and a hand-written validator would be a
// second copy of operandOf, drifting the first time an opcode is added - and a
// claim that then fails to parse is not a wasted pass, it is a file counted
// BoundedExecutable.
//
// The probe runs with the normalized default config, deliberately: ClassifyBinary
// takes no config parameter, and the only field this path reads is
// MaxEvidenceLines. A scan whose own cap was lower would reach its listing bound
// on the real parse instead, and for a KindPickle that sets Bound.Listing, which
// the scanner counts BoundedExecutable - the pass is withheld rather than the
// claim silently trusted.
//
// Three conditions, all required:
//
//   - No structural mark. A mark means the walk desynchronised - an unknown
//     opcode, an operand past pickleMaxOperandBytes, an overrun stack or memo -
//     and a stream that cannot survive its own head is not one to claim.
//   - At least one SourcePickle line, because a stream with no module.attribute
//     target carries no PKL_001 evidence and the claim is not free: a claimed
//     file is read by the pickle interpreter instead of the string scanner.
//   - That line is shaped like a target. GLOBAL and INST take their operands as
//     two newline-terminated lines, so any two lines of text read as one - "import
//     os" resolves "mport os.os.system('x')". The gate is a dotted identifier:
//     identifier characters only, at least one dot, no leading digit. A space or a
//     bracket disqualifies a line because it is not an identifier character, which
//     is a consequence of the charset rather than the rule.
//
// Flush is deliberately not called. A head is a prefix, so "no STOP yet" is the
// expected state at this offset, and Flush reads exactly that as a stream that
// ended without STOP.
//
// The claim is made about a prefix. A file that walks cleanly to the end of the
// head and desynchronises past it is still claimed, and the scanner then counts
// it BoundedExecutable and withholds the pass - the fail-closed direction, with
// the bound visible in the report rather than silent.
func sniffProtocol01Pickle(head []byte) bool {
	if len(head) == 0 {
		return false
	}
	probe := newEvidenceSet("", KindPickle, BinaryConfig{})
	p := newPickleScanner(probe)
	// pickleScanner.Write always returns (len(chunk), nil), so the discarded pair
	// is deliberate rather than an oversight.
	_, _ = p.Write(head)
	if probe.Bound.Structural {
		return false
	}
	for _, line := range probe.Lines {
		if line.Source == SourcePickle && pickleTargetRe.MatchString(line.Text) {
			return true
		}
	}
	return false
}

// pickleTargetRe is the shape of a resolved module.attribute target: a dotted
// identifier, at least one dot, because recordTarget writes "module.name". A line
// that is not this shape came from a walk that consumed text as an operand.
var pickleTargetRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$`)

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
