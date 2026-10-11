package codeaudit

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestEvidence builds an empty set for the extractor tests to fill.
func newTestEvidence(path string, kind BinaryKind) *EvidenceSet {
	return &EvidenceSet{File: path, Kind: kind, seen: map[string]bool{}}
}

func TestStringScannerKeepsRunsAtOrAboveTheMinimum(t *testing.T) {
	data := []byte("ab\x00abcd\x00abcde\x00")
	ev := newTestEvidence("x.bin", KindRaw)

	s := newStringScanner(ev, DefaultBinaryConfig())
	if _, err := s.Write(data); err != nil {
		t.Fatalf("write: %v", err)
	}
	s.Flush()

	var got []string
	for _, l := range ev.Lines {
		if l.Source == SourceStrings {
			got = append(got, l.Text)
		}
	}
	want := []string{"abcd", "abcde"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("strings = %v, want %v (a 2-byte run is below the 4-byte minimum)", got, want)
	}
}

// TestStringScannerCarriesRunsAcrossChunks pins the boundary behaviour: the
// stream is read in chunks, and a run split by the chunk edge is one string, not
// two. Without the carry the extractor would miss every literal that happens to
// straddle a 64 KiB read, which is a silent and input-dependent loss.
func TestStringScannerCarriesRunsAcrossChunks(t *testing.T) {
	ev := newTestEvidence("x.bin", KindRaw)
	s := newStringScanner(ev, DefaultBinaryConfig())

	if _, err := s.Write([]byte("hello/world")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write([]byte("tail")); err != nil {
		t.Fatal(err)
	}
	s.Flush()

	if len(ev.Lines) != 1 || ev.Lines[0].Text != "hello/worldtail" {
		t.Fatalf("lines = %+v, want one line \"hello/worldtail\"", ev.Lines)
	}
}

// TestStringScannerRecordsTheOffsetOfTheFirstOccurrence pins both the offset
// semantics and the deduplication: a literal repeated a thousand times is one
// evidence line, tagged with where it first appeared.
func TestStringScannerRecordsTheOffsetOfTheFirstOccurrence(t *testing.T) {
	ev := newTestEvidence("x.bin", KindRaw)
	s := newStringScanner(ev, DefaultBinaryConfig())

	if _, err := s.Write([]byte("\x00\x00\x00abcdef")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write([]byte("\x00abcdef\x00")); err != nil {
		t.Fatal(err)
	}
	s.Flush()

	if len(ev.Lines) != 1 {
		t.Fatalf("lines = %+v, want the duplicate dropped", ev.Lines)
	}
	if ev.Lines[0].Offset != 3 {
		t.Errorf("offset = %d, want 3 (the first occurrence)", ev.Lines[0].Offset)
	}
}

func TestStringScannerCapsDistinctLinesAndRecordsIt(t *testing.T) {
	cfg := DefaultBinaryConfig()
	cfg.MaxEvidenceLines = 2
	ev := newTestEvidence("x.bin", KindRaw)
	s := newStringScanner(ev, cfg)

	if _, err := s.Write([]byte("aaaa\x00bbbb\x00cccc\x00")); err != nil {
		t.Fatal(err)
	}
	s.Flush()

	if len(ev.Lines) != 2 {
		t.Fatalf("lines = %d, want the cap of 2", len(ev.Lines))
	}
	if !ev.Bound.Listing {
		t.Error("Bound.Listing = false after the line cap fired; the loss is invisible")
	}
}

// TestEvidenceSourcesDoNotShareADedupKey pins the property the per-source key
// exists for: the same text arriving from two different sources must produce two
// lines, not one. Every writer shares one dedup map, so a key that is the bare
// text lets one source silence another. The concrete evasion is a model package
// whose string table carries the printable literal "pickle:os.system": under a
// bare-text key it occupies the key the pickle pass needs for a genuine GLOBAL
// os.system target, and the rule that exists to catch "this file unpickles a
// call to os.system" would never see it. An attacker who controls the package
// can plant that literal on purpose, which is why the key is string(src) + "\x00"
// + text: no two sources can ever build the same key.
func TestEvidenceSourcesDoNotShareADedupKey(t *testing.T) {
	ev := newTestEvidence("x.bin", KindPickle)
	// The identical text from two different sources. Under the namespaced key
	// these are two entries; if add ever lost its source prefix they would
	// collapse to one and this assertion must fail.
	ev.add(SourceStrings, 0, "os.system")
	ev.add(SourcePickle, 0, "os.system")

	// add appends in call order - Finalize is what sorts, and it is not called
	// here - so the order is total and stated: the string line first, then the
	// pickle line.
	if len(ev.Lines) != 2 {
		t.Fatalf("lines = %+v, want 2: identical text from two sources collapsed onto one key", ev.Lines)
	}
	if ev.Lines[0].Source != SourceStrings || ev.Lines[1].Source != SourcePickle {
		t.Fatalf("sources = [%s, %s], want [%s, %s]", ev.Lines[0].Source, ev.Lines[1].Source, SourceStrings, SourcePickle)
	}
}

// TestStringScannerNormalizesAZeroConfig pins that the config is normalized
// where it is consumed. A zero BinaryConfig gives MaxStringLen == 0, which the
// scanner would read as "no byte may enter a run" while MinStringLen == 0 still
// let flush emit a phantom empty line - every real string lost, and a listing
// bound recorded instead of a structural one, which is a silent failure of
// exactly the kind this completeness scheme exists to prevent.
func TestStringScannerNormalizesAZeroConfig(t *testing.T) {
	ev := newTestEvidence("x.bin", KindRaw)
	s := newStringScanner(ev, BinaryConfig{})
	if _, err := s.Write([]byte("hello world")); err != nil {
		t.Fatal(err)
	}
	s.Flush()

	if len(ev.Lines) != 1 || ev.Lines[0].Text != "hello world" {
		t.Fatalf("lines = %+v, want one line \"hello world\"", ev.Lines)
	}
	if ev.Bound.Listing {
		t.Error("Bound.Listing = true: a zero config was recorded as a listing bound instead of being normalized")
	}
}

// TestStreamEvidenceReadsTheWholeFile pins that the pass is not silently
// bounded: a literal past the first read chunk is found, and an unbounded pass
// reports no bound at all.
func TestStreamEvidenceReadsTheWholeFile(t *testing.T) {
	dir := t.TempDir()
	// 200 KiB of filler, then the literal: comfortably past the 64 KiB read
	// chunk, so a pass that stopped early would miss it.
	filler := make([]byte, 200*1024)
	for i := range filler {
		filler[i] = byte(i*7 + 1) // never 0x00, so the run would swallow the literal
	}
	content := append(append([]byte{}, filler...), []byte("\x00CURLY_MARKER\x00")...)
	path := writeTestBytes(t, dir, "blob.bin", content)

	ev := newTestEvidence(path, KindRaw)
	if err := streamEvidence(path, ev, DefaultBinaryConfig(), DefaultBinaryConfig().MaxStreamBytes); err != nil {
		t.Fatalf("streamEvidence: %v", err)
	}
	if ev.Bound.Structural {
		t.Fatalf("Bound.Structural = true on a file inside every limit: %+v", ev.Bound)
	}

	found := false
	for _, l := range ev.Lines {
		if l.Text == "CURLY_MARKER" {
			found = true
		}
	}
	if !found {
		t.Error("the literal past the first read chunk is missing from the evidence")
	}
}

// TestStreamEvidenceStopsAtTheStreamBudget pins the budget path. A file over the
// configured ceiling is read up to the ceiling and the shortfall is recorded —
// not silently ignored, which is the failure mode the whole completeness scheme
// in this package exists to prevent.
func TestStreamEvidenceStopsAtTheStreamBudget(t *testing.T) {
	dir := t.TempDir()
	content := append(make([]byte, 128), []byte("\x00BEYOND_THE_BUDGET\x00")...)
	content[0] = 'A' // keep it readable so the run below is not the literal itself
	path := writeTestBytes(t, dir, "big.bin", content)

	ev := newTestEvidence(path, KindRaw)
	if err := streamEvidence(path, ev, DefaultBinaryConfig(), 32); err != nil {
		t.Fatalf("streamEvidence: %v", err)
	}
	if !ev.Bound.Structural {
		t.Error("Bound.Structural = false after the stream budget cut the read")
	}
	for _, l := range ev.Lines {
		if l.Text == "BEYOND_THE_BUDGET" {
			t.Error("evidence beyond the stream budget was read anyway; the budget is not a budget")
		}
	}
}

// writeTestBytes writes raw bytes; writeTestFile takes a string and cannot carry
// a NUL.
func writeTestBytes(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestShannonEntropy(t *testing.T) {
	t.Run("uniform over all 256 byte values is 8 bits", func(t *testing.T) {
		var counts [256]int64
		for i := range counts {
			counts[i] = 1
		}
		if got := shannonEntropy(counts, 256); math.Abs(got-8.0) > 1e-9 {
			t.Errorf("entropy = %v, want 8", got)
		}
	})

	t.Run("one repeated byte is zero bits", func(t *testing.T) {
		var counts [256]int64
		counts[0x41] = 4096
		if got := shannonEntropy(counts, 4096); got != 0 {
			t.Errorf("entropy = %v, want 0", got)
		}
	})

	t.Run("a fair coin is one bit", func(t *testing.T) {
		var counts [256]int64
		counts[0] = 500
		counts[1] = 500
		if got := shannonEntropy(counts, 1000); math.Abs(got-1.0) > 1e-9 {
			t.Errorf("entropy = %v, want 1", got)
		}
	})

	t.Run("empty input is zero rather than a division by zero", func(t *testing.T) {
		var counts [256]int64
		if got := shannonEntropy(counts, 0); got != 0 {
			t.Errorf("entropy = %v, want 0", got)
		}
	})

	t.Run("a total of zero returns zero rather than an infinity", func(t *testing.T) {
		// The histogram and the total are a pair the caller owns, and this
		// function exists in counts form precisely so a stream can be counted as
		// it is read - a caller can therefore hold a nonzero histogram and a zero
		// total. Without the guard the division yields an infinity that compares
		// false against every threshold, so a section would be reported as
		// unremarkable by accident. Note this is not the same as an all-zero
		// histogram, where the loop skips every byte and never divides.
		var counts [256]int64
		counts[0x41] = 5
		if got := shannonEntropy(counts, 0); got != 0 {
			t.Errorf("entropy = %v, want 0", got)
		}
	})
}

// TestEntropyVerdictIsMeasuredNotAssumed pins the line the extractor emits and
// the threshold that gates it. The measurement is exact by construction:
// byte(i*7) cycles through every value of a byte before repeating, so a 512-byte
// buffer has a perfectly uniform histogram and its entropy is exactly 8.
func TestEntropyVerdictIsMeasuredNotAssumed(t *testing.T) {
	cfg := DefaultBinaryConfig()

	uniform := make([]byte, 512)
	for i := range uniform {
		uniform[i] = byte(i * 7)
	}
	if got := measureEntropy(uniform); math.Abs(got-8.0) > 1e-9 {
		t.Fatalf("fixture entropy = %v, want exactly 8; the fixture, not the code, is wrong", got)
	}

	if line, ok := entropyVerdict(".text", uniform, cfg); !ok || line != "high-entropy-executable-section .text 8.00" {
		t.Errorf("verdict = %q (emitted=%v), want high-entropy-executable-section .text 8.00", line, ok)
	}

	flat := bytes.Repeat([]byte{0x41}, 512)
	if line, ok := entropyVerdict(".text", flat, cfg); ok {
		t.Errorf("verdict = %q for a constant buffer, want no line", line)
	}

	// The comparison is inclusive: a section measuring exactly the threshold has
	// not exceeded it. The uniform buffer's entropy is exactly 8 by construction,
	// so setting the threshold to 8 pins the boundary exactly - under a strict <
	// this case would emit a line and fail.
	atThreshold := cfg
	atThreshold.HighEntropyThreshold = 8.0
	if line, ok := entropyVerdict(".text", uniform, atThreshold); ok {
		t.Errorf("verdict = %q at exactly the threshold, want no line", line)
	}
}

// runPickleStream feeds data to a scanner in fixed-size chunks, which is the
// only way a boundary bug shows up: at 64 KiB every fixture here fits in a
// single chunk, and a scanner that mishandled a split operand would look
// perfect.
func runPickleStream(t *testing.T, data []byte, chunk int) *EvidenceSet {
	t.Helper()
	if chunk < 1 {
		chunk = 1
	}
	set := newTestEvidence("x.pkl", KindPickle)
	p := newPickleScanner(set)
	for i := 0; i < len(data); i += chunk {
		j := i + chunk
		if j > len(data) {
			j = len(data)
		}
		if _, err := p.Write(data[i:j]); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	p.Flush()
	return set
}

func pickleTargetsOf(set *EvidenceSet) []string {
	var out []string
	for _, l := range set.Lines {
		if l.Source == SourcePickle {
			out = append(out, l.Text)
		}
	}
	return out
}

// pickleBinUnicode encodes a protocol-2 BINUNICODE operand: the opcode, a 4-byte
// little-endian length, then the bytes. The length prefix is the whole difference
// between a scanner that reads this operand and one that reads into it.
func pickleBinUnicode(s string) []byte {
	b := []byte{0x58, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(b[1:], uint32(len(s)))
	return append(b, s...)
}

// pickleGlobal encodes "c module\nname\n".
func pickleGlobal(mod, name string) []byte {
	return []byte("c" + mod + "\n" + name + "\n")
}

// TestPickleInterpreterFindsTargetsInItsTwoEncodings pins both spellings of
// "resolve this attribute" and the offset rule: an evidence offset is the
// opcode's own offset, so it points at the 'c' of GLOBAL and the 0x93 of
// STACK_GLOBAL, never at a string operand.
func TestPickleInterpreterFindsTargetsInItsTwoEncodings(t *testing.T) {
	data := []byte{0x80, 0x04}
	data = append(data, pickleGlobal("posix", "system")...)
	data = append(data, 0x8c, 0x02)
	data = append(data, "os"...)
	data = append(data, 0x8c, 0x06)
	data = append(data, "system"...)
	data = append(data, 0x93, 0x2e) // STACK_GLOBAL, STOP

	set := runPickleStream(t, data, 64*1024)
	got := pickleTargetsOf(set)
	want := []string{"posix.system", "os.system"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("targets = %v, want %v", got, want)
	}
	if set.Lines[0].Offset != 2 {
		t.Errorf("offset = %d, want 2 (the GLOBAL opcode)", set.Lines[0].Offset)
	}
	if set.Bound.Structural {
		t.Errorf("structural bound on a well-formed stream: %s", set.Bound.Reason)
	}
}

// TestPickleInterpreterFindsTheTargetAfterBinaryData is the test the old design
// would have failed, and it is why this task exists. The string operand's payload
// ends with an unterminated run after a stray 0x63, so a byte scan reads a
// spurious GLOBAL whose operands run across the string boundary and swallow the
// genuine GLOBAL that follows - exactly how net_001.pth's torch.LongStorage was
// being lost. The interpreter must find both targets and must not read a byte
// inside the payload as an opcode.
func TestPickleInterpreterFindsTheTargetAfterBinaryData(t *testing.T) {
	stray := "c" + "junk\n" + "c" + strings.Repeat("Z", 300)
	data := []byte{0x80, 0x02}
	data = append(data, pickleBinUnicode(stray)...)
	data = append(data, pickleGlobal("posix", "system")...)
	data = append(data, pickleGlobal("torch._utils", "_rebuild_tensor_v2")...)
	data = append(data, 0x2e)

	set := runPickleStream(t, data, 64*1024)
	got := pickleTargetsOf(set)
	want := []string{"posix.system", "torch._utils._rebuild_tensor_v2"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("targets = %v, want %v", got, want)
	}
	if set.Bound.Structural {
		t.Errorf("structural bound on a well-formed stream: %s", set.Bound.Reason)
	}
}

// TestPickleInterpreterResolvesStackGlobalThroughTheMemo pins the evasion the
// memo table exists to close: the module and name are MEMOIZEd, fetched back with
// BINGET, and only then fed to STACK_GLOBAL. Neither string is adjacent to the
// opcode, so an adjacency scan sees nothing.
func TestPickleInterpreterResolvesStackGlobalThroughTheMemo(t *testing.T) {
	data := []byte{0x80, 0x04, 0x8c, 0x05}
	data = append(data, "posix"...)
	data = append(data, 0x94) // MEMOIZE -> memo[0]
	data = append(data, 0x8c, 0x06)
	data = append(data, "system"...)
	data = append(data, 0x94)       // MEMOIZE -> memo[1]
	data = append(data, 0x68, 0x00) // BINGET 0
	data = append(data, 0x68, 0x01) // BINGET 1
	data = append(data, 0x93, 0x2e) // STACK_GLOBAL, STOP

	got := pickleTargetsOf(runPickleStream(t, data, 64*1024))
	if len(got) != 1 || got[0] != "posix.system" {
		t.Fatalf("targets = %v, want [posix.system]", got)
	}
}

// TestPickleInterpreterReadsInstAsATarget pins the protocol-0/1 spelling of the
// same thing: INST carries module and name inline, like GLOBAL.
func TestPickleInterpreterReadsInstAsATarget(t *testing.T) {
	data := append([]byte{0x80, 0x04}, []byte("iposix\nsystem\n")...)
	data = append(data, 0x2e)
	got := pickleTargetsOf(runPickleStream(t, data, 64*1024))
	if len(got) != 1 || got[0] != "posix.system" {
		t.Fatalf("targets = %v, want [posix.system]", got)
	}
}

// TestPickleInterpreterIsChunkInvariant pins the property that makes the
// streaming contract correct: the parse carries its own state, so the listing
// cannot depend on where the reads split. The fixtures above all fit in one 64
// KiB chunk, so this test must run at several sizes; it is what would catch a
// boundary bug that the real file (one chunk) cannot.
func TestPickleInterpreterIsChunkInvariant(t *testing.T) {
	data := []byte{0x80, 0x04}
	data = append(data, pickleBinUnicode(strings.Repeat("data\x63\n", 400))...)
	data = append(data, pickleGlobal("os", "system")...)
	data = append(data, 0x8c, 0x03)
	data = append(data, "abc"...)
	data = append(data, 0x8c, 0x03)
	data = append(data, "def"...)
	data = append(data, 0x93, 0x2e)

	want := "os.system,abc.def"
	for _, size := range []int{1, 2, 3, 5, 8, 64, 1024, 64 * 1024} {
		set := runPickleStream(t, data, size)
		if got := strings.Join(pickleTargetsOf(set), ","); got != want {
			t.Fatalf("chunk=%d gave %q, want %q", size, got, want)
		}
		if set.Bound.Structural {
			t.Fatalf("chunk=%d set a structural bound: %s", size, set.Bound.Reason)
		}
	}
}

// TestPickleInterpreterBoundsAnUnknownOpcode pins the fail-closed direction for
// the one case the interpreter cannot recover from: a byte it cannot classify is
// a place it does not know the next opcode starts, and stopping without a bound
// would let a later opcode hide.
func TestPickleInterpreterBoundsAnUnknownOpcode(t *testing.T) {
	data := []byte{0x80, 0x02}
	data = append(data, pickleGlobal("posix", "system")...)
	data = append(data, 0x99, 0x2e) // 0x99 is not a pickle opcode

	set := runPickleStream(t, data, 64*1024)
	if !set.Bound.Structural {
		t.Fatal("unknown opcode did not set Bound.Structural")
	}
	if got := pickleTargetsOf(set); len(got) != 1 || got[0] != "posix.system" {
		t.Errorf("targets before the unknown opcode were lost: %v", got)
	}
}

// TestPickleInterpreterBoundsATruncatedOperand pins that an operand the stream
// claimed and did not deliver is a structural gap, not a clean end.
func TestPickleInterpreterBoundsATruncatedOperand(t *testing.T) {
	// SHORT_BINUNICODE declares 5 bytes and delivers 3.
	mid := []byte{0x80, 0x02, 0x8c, 0x05, 'p', 'o', 's'}
	if set := runPickleStream(t, mid, 64*1024); !set.Bound.Structural {
		t.Error("a stream ending mid-opcode did not set Bound.Structural")
	}
	// A declared length past EOF is the same event.
	past := append([]byte{0x80, 0x02}, 0x58, 0xff, 0xff, 0x00, 0x00)
	if set := runPickleStream(t, past, 64*1024); !set.Bound.Structural {
		t.Error("a length past EOF did not set Bound.Structural")
	}
}

// TestPickleInterpreterBoundsAStreamThatNeverStops pins that a stream which never
// reaches STOP is structurally incomplete - and that an empty stream is not, for
// the same reason a bound that cost nothing is not a bound.
func TestPickleInterpreterBoundsAStreamThatNeverStops(t *testing.T) {
	for _, data := range [][]byte{{0x80, 0x02}, {0x80, 0x02, 0x4e}} {
		if set := runPickleStream(t, data, 64*1024); !set.Bound.Structural {
			t.Errorf("%x: a stream without STOP did not set Bound.Structural", data)
		}
	}
	if set := runPickleStream(t, nil, 64*1024); set.Bound.Structural {
		t.Error("an empty stream set Bound.Structural")
	}
}

// TestPickleInterpreterToleratesBytesAfterStop pins the one place trailing data
// is not a bound: the unpickler stops at STOP too, so the bytes after it are
// outside the structure that can execute. They stay visible as a notice, so the
// loss is not silent.
func TestPickleInterpreterToleratesBytesAfterStop(t *testing.T) {
	data := []byte{0x80, 0x02}
	data = append(data, pickleGlobal("posix", "system")...)
	data = append(data, 0x2e)
	data = append(data, []byte("this padding is not part of the pickle")...)

	set := runPickleStream(t, data, 64*1024)
	if set.Bound.Structural {
		t.Fatalf("bytes after STOP set Bound.Structural: %s", set.Bound.Reason)
	}
	var notice bool
	for _, l := range set.Lines {
		if l.Source == SourceNotice {
			notice = true
		}
	}
	if !notice {
		t.Error("bytes after STOP produced no notice; the loss is invisible")
	}
}

// TestPickleInterpreterBoundsAnUnresolvedStackGlobalOperand pins the bound to the
// only condition that hides a target - an unresolvable value actually used as a
// module or name - and pins the other half too: a dangling reference that is
// never so used is tolerated, because being strict there would put a bound on
// benign streams.
func TestPickleInterpreterBoundsAnUnresolvedStackGlobalOperand(t *testing.T) {
	used := []byte{0x80, 0x04, 0x68, 0x00, 0x8c, 0x06}
	used = append(used, "system"...)
	used = append(used, 0x93, 0x2e) // BINGET 0 (never written), STACK_GLOBAL
	if set := runPickleStream(t, used, 64*1024); !set.Bound.Structural {
		t.Error("an unresolved STACK_GLOBAL operand did not set Bound.Structural")
	}
	unused := []byte{0x80, 0x04, 0x68, 0x00, 0x2e} // BINGET 0, never used
	if set := runPickleStream(t, unused, 64*1024); set.Bound.Structural {
		t.Errorf("an unused dangling reference set Bound.Structural: %s", set.Bound.Reason)
	}
}

// TestPickleInterpreterNamesNothingInProse pins that the parser is a parser: the
// words appear, but not in opcode shape, so no target is reported. (In production
// the interpreter is gated to streams claimed as pickles, so prose never reaches
// it; this asserts the parser's own silence.)
func TestPickleInterpreterNamesNothingInProse(t *testing.T) {
	data := []byte("the posix system call interface is described here")
	if got := pickleTargetsOf(runPickleStream(t, data, 64*1024)); len(got) != 0 {
		t.Errorf("targets = %v, want none from prose", got)
	}
}

// TestPickleInterpreterSurvivesAdversarialBytes pins that the parser is total:
// every input either parses or records why it could not, and none of them makes
// it panic. It is fed attacker-controlled bytes by definition. The bytes are
// enumerated rather than random so the test is deterministic.
func TestPickleInterpreterSurvivesAdversarialBytes(t *testing.T) {
	for b := 0; b < 256; b++ {
		runPickleStream(t, []byte{0x80, 0x04, byte(b), byte(b), byte(b), 0x2e}, 3)
	}
	full := append([]byte{0x80, 0x04}, pickleGlobal("os", "system")...)
	full = append(full, 0x2e)
	for n := 0; n <= len(full); n++ { // every truncation of a valid stream
		runPickleStream(t, full[:n], 1)
	}
}

// TestPickleInterpreterReadsTheRealCheckpoint runs the interpreter over the one
// real checkpoint in this repository that exercises the defect: a protocol-2
// torch stream whose four GLOBAL targets sit around large binary operands, the
// last of them at an offset a byte scan was swallowing. It skips when the file is
// absent, because the corpus is not carried in every checkout.
func TestPickleInterpreterReadsTheRealCheckpoint(t *testing.T) {
	const ckpt = "../../models/examples/Retina-DKD/Retina-DKD/model/" +
		"fusion_TransMUF_dkd_win_num3_lr1_ep5bc_4lnum_1_Nopretrain_DKD/net_001.pth"
	if _, err := os.Stat(ckpt); err != nil {
		t.Skipf("corpus checkpoint not present: %v", err)
	}
	zr, err := zip.OpenReader(ckpt)
	if err != nil {
		t.Fatalf("open %s: %v", ckpt, err)
	}
	defer zr.Close()

	var pkl []byte
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "/data.pkl") {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			pkl, err = io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if pkl == nil {
		t.Fatal("no data.pkl member in the checkpoint")
	}

	set := runPickleStream(t, pkl, 64*1024)
	got := pickleTargetsOf(set)
	want := []string{
		"collections.OrderedDict",
		"torch._utils._rebuild_tensor_v2",
		"torch.FloatStorage",
		"torch.LongStorage", // the target the byte scan missed
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("targets = %v, want %v", got, want)
	}
	if set.Bound.Structural {
		t.Errorf("the real checkpoint set Bound.Structural: %s", set.Bound.Reason)
	}
}
