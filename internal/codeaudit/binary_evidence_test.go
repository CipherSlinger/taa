package codeaudit

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"debug/elf"
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

	// The streaming path and the in-memory path must agree, because an ELF
	// section is measured one way and a container member the other. Both are
	// driven from the same bytes here, and the assertion is equality of the
	// rendered line rather than of the number: the line is what reaches the
	// evidence set, so a divergence that only shows up in the formatting would
	// otherwise go unnoticed.
	var counts [256]int64
	for _, b := range uniform {
		counts[b]++
	}
	streamed, streamedOK := entropyVerdictFromCounts(".text", counts, int64(len(uniform)), cfg)
	inMemory, inMemoryOK := entropyVerdict(".text", uniform, cfg)
	if streamed != inMemory || streamedOK != inMemoryOK {
		t.Errorf("streamed = (%q, %v), in-memory = (%q, %v); the two paths must agree",
			streamed, streamedOK, inMemory, inMemoryOK)
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
// cannot depend on where the reads split. The sizes below include 1 and the whole
// stream in a single Write, because those are the two extremes a one-chunk fixture
// would never exercise, and splitAfterLength, which puts a chunk boundary in the
// one place the parser is weakest - right after the length prefix of a zero-length
// counted operand, so that operand's completion is the first thing the next call
// sees.
func TestPickleInterpreterIsChunkInvariant(t *testing.T) {
	data := []byte{0x80, 0x04}
	data = append(data, pickleBinUnicode(strings.Repeat("data\x63\n", 400))...)
	data = append(data, pickleGlobal("os", "system")...)
	// A zero-length counted operand. pickle.dumps emits these, and the length
	// prefix is BINUNICODE's opcode plus four length bytes.
	zeroLenAt := len(data)
	data = append(data, pickleBinUnicode("")...)
	splitAfterLength := zeroLenAt + 5
	data = append(data, 0x8c, 0x03)
	data = append(data, "abc"...)
	data = append(data, 0x8c, 0x03)
	data = append(data, "def"...)
	data = append(data, 0x93, 0x2e)

	want := "os.system,abc.def"
	for _, size := range []int{1, 2, 3, 5, 8, 64, 1024, 64 * 1024, splitAfterLength, len(data)} {
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

// TestPickleInterpreterParsesCPythonsZeroLengthOperands pins the interpreter
// against the two byte strings CPython itself produces for a zero-length operand,
// because the defect they exercise was in the interpreter, not in a hand-built
// fixture. Each is fed both in one 64 KiB chunk and in a single Write, since the
// streaming reader reads a file that fits one chunk in a single call. The assertion
// is on the extracted targets as well as the bound: the BINUNICODE case used to
// both set a structural bound and lose the target that followed it, so a test that
// checked only the bound would see half the defect.
func TestPickleInterpreterParsesCPythonsZeroLengthOperands(t *testing.T) {
	cases := []struct {
		name    string
		data    []byte
		targets []string
	}{
		{
			name: "pickle.dumps(b'', protocol=4): SHORT_BINBYTES of length 0",
			data: []byte{0x80, 0x04, 0x95, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43, 0x00, 0x94, 0x2e},
		},
		{
			name:    "pickle.dumps({'': b''}, protocol=2): BINUNICODE of length 0 before a GLOBAL",
			data:    []byte{0x80, 0x02, 0x7d, 0x71, 0x00, 0x58, 0x00, 0x00, 0x00, 0x00, 0x71, 0x01, 0x63, 0x5f, 0x5f, 0x62, 0x75, 0x69, 0x6c, 0x74, 0x69, 0x6e, 0x5f, 0x5f, 0x0a, 0x62, 0x79, 0x74, 0x65, 0x73, 0x0a, 0x71, 0x02, 0x29, 0x52, 0x71, 0x03, 0x73, 0x2e},
			targets: []string{"__builtin__.bytes"},
		},
	}
	for _, tc := range cases {
		for _, chunk := range []int{64 * 1024, len(tc.data)} {
			set := runPickleStream(t, tc.data, chunk)
			if set.Bound.Structural {
				t.Errorf("%s (chunk=%d): structural bound: %s", tc.name, chunk, set.Bound.Reason)
			}
			got := pickleTargetsOf(set)
			if strings.Join(got, ",") != strings.Join(tc.targets, ",") {
				t.Errorf("%s (chunk=%d): targets = %v, want %v", tc.name, chunk, got, tc.targets)
			}
		}
	}
}

// TestPickleInterpreterReadsTheQuickMnistCheckpointInOneWrite is the load-bearing
// regression test for the zero-length operand, and it uses a real file rather than
// a fixture. Its data.pkl is 1548 bytes and holds a zero-length BINUNICODE at
// offset 1315; at evidenceReadChunk (64 KiB) the whole stream arrives in one Write,
// which is exactly the case the defect mis-handled - the bytes after the operand
// were left in the buffer and Flush reported a complete pickle as structural.
// Before the fix this test fails; the same checkpoint read in chunks that split
// after the operand passes even while broken, which is why a fixture that fits one
// chunk is the one to use.
func TestPickleInterpreterReadsTheQuickMnistCheckpointInOneWrite(t *testing.T) {
	const ckpt = "../../models/examples/TEE-test/TEE-test/output/quick_mnist/train_baseline.pth"
	if _, err := os.Stat(ckpt); err != nil {
		t.Skipf("corpus checkpoint not present: %v", err)
	}
	pkl := readZipMember(t, ckpt, "/data.pkl")
	if pkl == nil {
		t.Fatal("no data.pkl member in the checkpoint")
	}
	// One Write, then Flush: the whole file in a single chunk, as the streaming
	// reader does for a file this size.
	set := runPickleStream(t, pkl, len(pkl))
	if set.Bound.Structural {
		t.Fatalf("the checkpoint was marked structural read whole: %s", set.Bound.Reason)
	}
	got := pickleTargetsOf(set)
	want := []string{
		"collections.OrderedDict",
		"torch._utils._rebuild_tensor_v2",
		"torch.FloatStorage",
		"torch.LongStorage",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("targets = %v, want %v", got, want)
	}
}

// readZipMember returns the bytes of the last zip member whose name has the given
// suffix, or nil when there is none.
func readZipMember(t *testing.T, path, suffix string) []byte {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer zr.Close()
	var out []byte
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, suffix) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		out, err = io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// TestPickleInterpreterKeepsOperandsUpToTheCapAndDropsPastIt pins the
// pickleMaxOperandBytes boundary in both directions. At the cap the operand is
// kept, so a target formed from it resolves; one byte past it the bytes are still
// consumed - the parse stays in step - but the value is unresolved, so using it as
// a STACK_GLOBAL operand is a structural bound rather than a silent wrong answer.
func TestPickleInterpreterKeepsOperandsUpToTheCapAndDropsPastIt(t *testing.T) {
	atCap := strings.Repeat("m", pickleMaxOperandBytes)
	kept := []byte{0x80, 0x04}
	kept = append(kept, pickleBinUnicode(atCap)...)
	kept = append(kept, 0x8c, 0x01, 'x')
	kept = append(kept, 0x93, 0x2e)
	set := runPickleStream(t, kept, 64*1024)
	if set.Bound.Structural {
		t.Fatalf("an operand exactly at the cap set a structural bound: %s", set.Bound.Reason)
	}
	if got := pickleTargetsOf(set); len(got) != 1 || got[0] != atCap+".x" {
		t.Fatalf("targets = %d entries, want one of the cap-length module; the operand at the cap was dropped", len(got))
	}

	past := []byte{0x80, 0x04}
	past = append(past, pickleBinUnicode(strings.Repeat("m", pickleMaxOperandBytes+1))...)
	past = append(past, 0x8c, 0x01, 'x')
	past = append(past, 0x93, 0x2e)
	if set := runPickleStream(t, past, 64*1024); !set.Bound.Structural {
		t.Error("an operand past the cap, used as a STACK_GLOBAL operand, did not set Bound.Structural")
	}
}

// TestPickleInterpreterReadsTwoByteOperands pins the 2-byte operand width, which
// only BININT2 and EXT2 use. Reading one byte of it - or three - desynchronises the
// parse at that opcode and is invisible unless the stream continues past it, so the
// fixture puts a GLOBAL after the operand and asserts it is still found.
func TestPickleInterpreterReadsTwoByteOperands(t *testing.T) {
	for _, op := range []byte{0x4d, 0x83} { // BININT2, EXT2
		data := []byte{0x80, 0x04, op, 0x01, 0x02}
		data = append(data, pickleGlobal("os", "system")...)
		data = append(data, 0x2e)
		set := runPickleStream(t, data, 64*1024)
		if set.Bound.Structural {
			t.Errorf("opcode 0x%02x: structural bound: %s", op, set.Bound.Reason)
		}
		if got := pickleTargetsOf(set); len(got) != 1 || got[0] != "os.system" {
			t.Errorf("opcode 0x%02x: targets = %v, want [os.system]: the 2-byte operand desynchronised the parse", op, got)
		}
	}
}

// TestPickleInterpreterBoundsARunawayStack pins that the value-stack cap is
// enforced and reported. A flood of operand-free opcodes is the cheapest way to
// grow the stack - each NONE is one byte and one slot - so it is what an attacker
// would send, and a cap that stopped the parse without recording a bound would
// miss every target after the cap while looking like a complete scan.
func TestPickleInterpreterBoundsARunawayStack(t *testing.T) {
	data := bytes.Repeat([]byte{0x4e}, pickleMaxStackSlots*2) // NONE
	set := runPickleStream(t, data, 64*1024)
	if !set.Bound.Structural {
		t.Fatal("a runaway value stack did not set Bound.Structural; the cap is silent")
	}
	if !strings.Contains(set.Bound.Reason, "value stack") {
		t.Errorf("reason = %q, want it to name the value stack", set.Bound.Reason)
	}
}

// TestPickleInterpreterBoundsARunawayMemo pins the memo cap the same way. MEMOIZE
// is one byte and adds one entry, so it is the memo-side analogue of the NONE
// flood.
func TestPickleInterpreterBoundsARunawayMemo(t *testing.T) {
	data := bytes.Repeat([]byte{0x94}, pickleMaxMemoSlots*2) // MEMOIZE
	set := runPickleStream(t, data, 64*1024)
	if !set.Bound.Structural {
		t.Fatal("a runaway memo did not set Bound.Structural; the cap is silent")
	}
	if !strings.Contains(set.Bound.Reason, "memo") {
		t.Errorf("reason = %q, want it to name the memo", set.Bound.Reason)
	}
}

// TestELFFixtureIsReadByTheStandardLibrary guards the fixture itself. If this
// fails, the bytes are wrong and every assertion built on them is meaningless -
// so it is checked before anything the extractor claims.
func TestELFFixtureIsReadByTheStandardLibrary(t *testing.T) {
	dir := t.TempDir()
	raw := elfFixtureBytes(t, elfSpec{
		imports:  []string{"connect", "socket"},
		needed:   []string{"libcurl.so.4"},
		text:     []byte("hello"),
		textExec: true,
	})
	path := writeTestBytes(t, dir, "libevil.so", raw)

	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("elf.Open on the fixture: %v", err)
	}
	defer f.Close()

	libs, err := f.ImportedLibraries()
	if err != nil {
		t.Fatalf("ImportedLibraries: %v", err)
	}
	if len(libs) != 1 || libs[0] != "libcurl.so.4" {
		t.Errorf("DT_NEEDED = %v, want [libcurl.so.4]", libs)
	}

	syms, err := f.ImportedSymbols()
	if err != nil {
		t.Fatalf("ImportedSymbols: %v", err)
	}
	names := map[string]bool{}
	for _, s := range syms {
		names[s.Name] = true
	}
	for _, want := range []string{"connect", "socket"} {
		if !names[want] {
			t.Errorf("imported symbol %q missing from the fixture; got %v", want, names)
		}
	}
}

func TestCollectELFEvidence(t *testing.T) {
	dir := t.TempDir()
	raw := elfFixtureBytes(t, elfSpec{
		imports:  []string{"connect", "system", "dlopen"},
		needed:   []string{"libcurl.so.4", "libc.so.6"},
		text:     uniformBytes(512),
		textExec: true,
		soname:   "libevil.so.1",
		interp:   "/lib64/ld-linux-x86-64.so.2",
	})
	path := writeTestBytes(t, dir, "libevil.so", raw)

	set := newTestEvidence(path, KindELF)
	if err := collectELF(path, set, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectELF: %v", err)
	}

	bySource := map[EvidenceSource][]string{}
	for _, l := range set.Lines {
		bySource[l.Source] = append(bySource[l.Source], l.Text)
	}

	for _, want := range []string{"connect", "system", "dlopen"} {
		if !containsString(bySource[SourceDynsym], want) {
			t.Errorf("dynsym evidence missing %q; got %v", want, bySource[SourceDynsym])
		}
	}
	for _, want := range []string{"libcurl.so.4", "libc.so.6"} {
		if !containsString(bySource[SourceNeeded], want) {
			t.Errorf("needed evidence missing %q; got %v", want, bySource[SourceNeeded])
		}
	}
	// The soname and the interpreter are the two facts this parse reads from
	// structure rather than from symbols: collectELF writes the soname as a
	// section line and the interpreter as a notice. Both are asserted in the
	// exact shape it writes, so a format change breaks this test rather than
	// silently passing an assertion written against the old shape.
	if !containsString(bySource[SourceSection], "soname libevil.so.1") {
		t.Errorf("soname section line missing; got %v", bySource[SourceSection])
	}
	if !containsString(bySource[SourceNotice], "interpreter /lib64/ld-linux-x86-64.so.2") {
		t.Errorf("interpreter notice missing; got %v", bySource[SourceNotice])
	}
	var sawExecutableSection, sawHighEntropySection bool
	for _, text := range bySource[SourceSection] {
		if strings.Contains(text, ".text") && strings.Contains(text, "executable=true") {
			sawExecutableSection = true
		}
	}
	for _, text := range bySource[SourceEntropy] {
		if strings.HasPrefix(text, "high-entropy-executable-section .text") {
			sawHighEntropySection = true
		}
	}
	if !sawExecutableSection {
		t.Errorf("no executable .text section line; got %v", bySource[SourceSection])
	}
	if !sawHighEntropySection {
		t.Errorf("a uniform .text produced no entropy verdict; got %v", bySource[SourceEntropy])
	}
}

// TestCollectELFEvidenceSkipsEntropyForDataSections pins the narrower half of the
// same rule: a non-executable section that happens to be near-random says
// nothing, because data is allowed to be random and code is not.
func TestCollectELFEvidenceSkipsEntropyForDataSections(t *testing.T) {
	dir := t.TempDir()
	raw := elfFixtureBytes(t, elfSpec{text: uniformBytes(512), textExec: false})
	path := writeTestBytes(t, dir, "libdata.so", raw)

	set := newTestEvidence(path, KindELF)
	if err := collectELF(path, set, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectELF: %v", err)
	}
	for _, l := range set.Lines {
		if l.Source == SourceEntropy {
			t.Errorf("entropy evidence %q for a non-executable section", l.Text)
		}
	}
}

// TestCollectELFEvidenceOnAStrippedFile pins that a file with no dynamic symbol
// table at all is a completed look, not a failure, and that the look says so.
// The fixture omits the SHT_DYNSYM section entirely, which is what makes
// debug/elf return elf.ErrNoSymbols: treating that as an error would make every
// Go binary build in a model package an incomplete scan. The notice it produces
// is what tells a reader the symbol list is empty because there is no table.
//
// The notice names the section type that is absent rather than calling the file
// "stripped or static". A static binary has no .dynsym but does carry .symtab,
// so the old wording was false for it, and a file with no section header table
// at all is not "stripped" either - it is a different condition with its own
// structural bound. A notice is a statement about the bytes, so it says which
// table was looked for and not found.
func TestCollectELFEvidenceOnAStrippedFile(t *testing.T) {
	dir := t.TempDir()
	raw := elfFixtureBytes(t, elfSpec{text: []byte("no symbols here"), stripped: true})
	path := writeTestBytes(t, dir, "stripped", raw)

	set := newTestEvidence(path, KindELF)
	if err := collectELF(path, set, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectELF on a file with no .dynsym: %v", err)
	}
	if set.Err != nil {
		t.Errorf("Err = %v, want nil", set.Err)
	}
	if set.Bound.Structural {
		t.Errorf("a stripped file was marked structural (%q); stripping is ordinary and must not withhold a pass", set.Bound.Reason)
	}

	var notices []string
	for _, l := range set.Lines {
		if l.Source == SourceNotice {
			notices = append(notices, l.Text)
		}
	}
	if !containsString(notices, "no dynamic symbol table (SHT_DYNSYM absent)") {
		t.Errorf("no absent-.dynsym notice; got notices %v", notices)
	}
	for _, n := range notices {
		if strings.Contains(n, "stripped or static") {
			t.Errorf("the notice still claims the file is stripped or static: %q", n)
		}
	}
}

// TestCollectELFEvidenceOnAFileWithNoSectionHeaders pins the removal of a
// fail-open. The entropy pass walks the executable sections, so a file with no
// section header table used to walk nothing, emit no line and no bound, and pass
// as clean - a pass that claimed to have looked for packing in a file it never
// examined. The fixture writes e_shoff, e_shnum and e_shstrndx as zero, which is
// the shape of a file whose section table was removed, and that must come back
// as a structural gap that names the section header table rather than as a clean
// pass.
func TestCollectELFEvidenceOnAFileWithNoSectionHeaders(t *testing.T) {
	dir := t.TempDir()
	raw := elfFixtureBytes(t, elfSpec{text: uniformBytes(512), textExec: true, noSections: true})
	path := writeTestBytes(t, dir, "packed", raw)

	// The fixture itself must survive the standard library before the extractor
	// is asked about it: a file debug/elf refuses is a different case from one
	// it reads and finds no sections in.
	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("elf.Open on the sectionless fixture: %v", err)
	}
	if got := len(f.Sections); got != 0 {
		t.Fatalf("fixture sections = %d, want 0", got)
	}
	f.Close()

	set := newTestEvidence(path, KindELF)
	if err := collectELF(path, set, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectELF: %v", err)
	}
	if !set.Bound.Structural {
		t.Fatalf("a file with no section header table produced no structural bound; bound = %+v", set.Bound)
	}
	// The reason must name the real condition. It is not a missing symbol table:
	// a stripped file has no .dynsym either and is not bounded, and this file's
	// own case is the absent section header table.
	if !strings.Contains(set.Bound.Reason, "section header table") {
		t.Errorf("bound reason = %q, want it to name the section header table", set.Bound.Reason)
	}
	if strings.Contains(set.Bound.Reason, "symbol") {
		t.Errorf("bound reason = %q, want it not to claim a symbol table is the problem", set.Bound.Reason)
	}
}

// TestCollectELFEvidenceReportsASectionThatOverrunsTheFile pins that a section
// header is not taken at its word. The fixture adds bytes to .text's declared
// sh_size that were never written, so the read stops at end of file and returns
// fewer bytes than the header claims. An extractor that trusted the header and
// measured whatever it got would score a prefix and call it the section; an
// extractor that noticed but said nothing would leave the reader unable to tell
// a short section from a short read. So the shortfall is structural and the
// declared size is still reported as what the header said.
func TestCollectELFEvidenceReportsASectionThatOverrunsTheFile(t *testing.T) {
	dir := t.TempDir()
	const textLen, overrun = 512, 1 << 20
	raw := elfFixtureBytes(t, elfSpec{text: uniformBytes(textLen), textExec: true, overrun: overrun})
	path := writeTestBytes(t, dir, "truncated.so", raw)

	set := newTestEvidence(path, KindELF)
	if err := collectELF(path, set, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectELF: %v", err)
	}
	if !set.Bound.Structural {
		t.Fatalf("a section declaring more than the file holds produced no structural bound; bound = %+v", set.Bound)
	}
	if !strings.Contains(set.Bound.Reason, "declares") || !strings.Contains(set.Bound.Reason, "readable") {
		t.Errorf("bound reason = %q, want it to state declared and readable byte counts", set.Bound.Reason)
	}

	// size= must still be the declared size, so a reader can pair the section
	// line with the shortfall instead of seeing a number that silently matched
	// the read. The section line carries its executability flag after size=, so
	// the declared size is asserted as the line's prefix and not as the whole
	// line.
	wantDeclared := fmt.Sprintf(".text size=%d", textLen+overrun)
	var sawDeclared bool
	for _, l := range set.Lines {
		if l.Source == SourceSection && strings.HasPrefix(l.Text, ".text size=") {
			sawDeclared = strings.HasPrefix(l.Text, wantDeclared+" ")
		}
	}
	if !sawDeclared {
		t.Errorf("no section line %q; lines = %v", wantDeclared, set.Lines)
	}

	// The short read must not have been scored: an entropy line would be a number
	// over a prefix, presented with the same authority as one over a whole section.
	for _, l := range set.Lines {
		if l.Source == SourceEntropy {
			t.Errorf("a section that overran the file still produced entropy evidence %q", l.Text)
		}
	}
}

// TestCollectELFEvidenceMeasuresEveryExecutableSection pins that the entropy
// pass is per section rather than per file. The fixture carries two executable
// sections, a packed .text and a flat .init, and the file-level boolean a
// one-section fixture cannot distinguish from a loop would report either both or
// neither. Exactly one line may appear, and it must name .text.
func TestCollectELFEvidenceMeasuresEveryExecutableSection(t *testing.T) {
	dir := t.TempDir()
	raw := elfFixtureBytes(t, elfSpec{
		text:      uniformBytes(512),
		textExec:  true,
		text2:     bytes.Repeat([]byte{0x90}, 512), // NOP sled: executable and not random
		text2Exec: true,
	})
	path := writeTestBytes(t, dir, "twoexec.so", raw)

	set := newTestEvidence(path, KindELF)
	if err := collectELF(path, set, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectELF: %v", err)
	}
	if set.Bound.Structural {
		t.Fatalf("a well-formed two-section file was marked structural: %q", set.Bound.Reason)
	}

	var entropyLines []string
	for _, l := range set.Lines {
		if l.Source == SourceEntropy {
			entropyLines = append(entropyLines, l.Text)
		}
	}
	if len(entropyLines) != 1 || !strings.HasPrefix(entropyLines[0], "high-entropy-executable-section .text ") {
		t.Errorf("entropy lines = %v, want exactly one for .text", entropyLines)
	}
}

// TestCollectELFEmptyDynsymIsNotAStrippedFile pins the distinction the stripped
// test cannot see: a .dynsym that exists but holds only the reserved null entry
// yields an empty symbol list and a nil error, not ErrNoSymbols. "This binary
// imports nothing" and "this file has no symbol table" are different facts, and
// reporting the second when the first is true would be a false statement in the
// report - so no notice may appear here.
func TestCollectELFEmptyDynsymIsNotAStrippedFile(t *testing.T) {
	dir := t.TempDir()
	raw := elfFixtureBytes(t, elfSpec{text: []byte("a library with no imports")})
	path := writeTestBytes(t, dir, "libempty.so", raw)

	set := newTestEvidence(path, KindELF)
	if err := collectELF(path, set, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectELF: %v", err)
	}
	for _, l := range set.Lines {
		if l.Source == SourceNotice && strings.Contains(l.Text, "no dynamic symbol table") {
			t.Errorf("a present but empty .dynsym produced the stripped/static notice: %q", l.Text)
		}
	}
}

// TestCollectELFEvidenceOnAZeroSizeDynsym pins the crash guard. A SHT_DYNSYM that
// is present but declares sh_size == 0 makes debug/elf's 64-bit symbol reader
// slice an empty buffer at byte 24 and panic ("slice bounds out of range
// [24:0]") instead of returning an error: its only length check, len(data)%24,
// accepts a zero length. ClassifyBinary returns KindELF on the four magic bytes
// alone, so the shape is reachable from an untrusted file, and a panic aborts the
// whole scan rather than marking the one file incomplete. collectELF has to hold
// the table back - it holds no symbols, so nothing is lost - and must not claim
// the table is absent, which would be a false statement about the file.
func TestCollectELFEvidenceOnAZeroSizeDynsym(t *testing.T) {
	dir := t.TempDir()
	raw := elfFixtureBytes(t, elfSpec{
		imports:    []string{"dlopen"},
		zeroDynsym: true,
		text:       []byte("a symbol table present but empty"),
	})
	path := writeTestBytes(t, dir, "zero-dynsym.so", raw)

	// Prove the fixture really carries the crash shape, or the test would pass on
	// a file that cannot panic.
	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("elf.Open on the fixture: %v", err)
	}
	ds := f.SectionByType(elf.SHT_DYNSYM)
	if ds == nil {
		f.Close()
		t.Fatal("fixture has no SHT_DYNSYM section")
	}
	size := ds.Size
	f.Close()
	if size != 0 {
		t.Fatalf("fixture .dynsym size = %d, want 0", size)
	}

	// collectELF must return, not panic, and must neither invent a symbol from the
	// unread table nor describe the present table as absent.
	set := newTestEvidence(path, KindELF)
	if err := collectELF(path, set, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectELF on a zero-size .dynsym: %v", err)
	}
	for _, l := range set.Lines {
		if l.Source == SourceDynsym {
			t.Errorf("a zero-size .dynsym produced symbol evidence %q", l.Text)
		}
		if l.Source == SourceNotice && strings.Contains(l.Text, "no dynamic symbol table") {
			t.Errorf("a present but zero-size .dynsym was reported as an absent table: %q", l.Text)
		}
	}
}

// TestCollectELFEvidenceOnAZdebugNamedDynsym pins the second route to the same
// crash. A section named ".zdebug..." of type SHT_DYNSYM whose body begins with
// "ZLIB" has Section.Size rewritten from eight bytes the file chooses when the
// section is opened - not when the file is parsed - so an on-disk sh_size that
// looks perfectly ordinary (48 here) still yields an empty buffer, which the
// symbol reader slices at entry 24 and panics on. Only reading the section the
// way the reader does sees through it; a guard written against the header size
// would wave this file through.
func TestCollectELFEvidenceOnAZdebugNamedDynsym(t *testing.T) {
	dir := t.TempDir()
	raw := elfFixtureBytes(t, elfSpec{
		zdebugDynsym: true,
		text:         []byte("a disguised symbol table"),
	})
	path := writeTestBytes(t, dir, "zdebug-dynsym.so", raw)

	// Check the shape the file presents before anything opens the section, since
	// opening it is what rewrites the size - then confirm the empty buffer.
	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("elf.Open on the fixture: %v", err)
	}
	ds := f.SectionByType(elf.SHT_DYNSYM)
	if ds == nil {
		f.Close()
		t.Fatal("fixture has no SHT_DYNSYM section")
	}
	name, onDisk := ds.Name, ds.Size
	data, dataErr := ds.Data()
	f.Close()
	if !strings.HasPrefix(name, ".zdebug") {
		t.Fatalf("fixture .dynsym name = %q, want a \".zdebug\" prefix", name)
	}
	if onDisk == 0 {
		t.Fatalf("fixture .dynsym on-disk size = 0; the point is that it looks ordinary")
	}
	if dataErr != nil {
		t.Fatalf("reading the fixture's section: %v", dataErr)
	}
	if len(data) != 0 {
		t.Fatalf("fixture section yielded %d bytes, want 0 - the ZLIB header must declare an empty table", len(data))
	}

	// collectELF must return, not panic, and must neither invent a symbol from the
	// unread table nor describe the present table as absent.
	set := newTestEvidence(path, KindELF)
	if err := collectELF(path, set, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectELF on a .zdebug-named .dynsym: %v", err)
	}
	for _, l := range set.Lines {
		if l.Source == SourceDynsym {
			t.Errorf("a .zdebug-named .dynsym produced symbol evidence %q", l.Text)
		}
		if l.Source == SourceNotice && strings.Contains(l.Text, "no dynamic symbol table") {
			t.Errorf("a present .zdebug-named .dynsym was reported as an absent table: %q", l.Text)
		}
	}
}

// TestCollectELFEvidenceFailsClosedOnATruncatedDynsym pins the boundary the
// other two fixtures do not reach. A SHT_DYNSYM whose body is shorter than one
// 24-byte entry (8 bytes here) is malformed, not empty: getSymbols64 rejects a
// length that is not a multiple of the entry size and returns a format error, so
// collectELF must fail the scan closed and say the table could not be read.
// Skipping it as empty - which is what a length-range guard (len(data) < 24)
// would do - is a fail-open, and it is the specific regression the wrong guard
// shape would have introduced: the two panic fixtures both have a genuinely
// empty buffer, so both pass under either guard, while only this one tells them
// apart.
func TestCollectELFEvidenceFailsClosedOnATruncatedDynsym(t *testing.T) {
	dir := t.TempDir()
	raw := elfFixtureBytes(t, elfSpec{
		shortDynsym: true,
		text:        []byte("a symbol table too short to hold a symbol"),
	})
	path := writeTestBytes(t, dir, "truncated-dynsym.so", raw)

	// Prove the fixture carries the shape: a non-empty body that is not a whole
	// number of entries, under an ordinary name and an ordinary declared size.
	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("elf.Open on the fixture: %v", err)
	}
	ds := f.SectionByType(elf.SHT_DYNSYM)
	if ds == nil {
		f.Close()
		t.Fatal("fixture has no SHT_DYNSYM section")
	}
	name, size := ds.Name, ds.Size
	data, dataErr := ds.Data()
	f.Close()
	if name != ".dynsym" {
		t.Fatalf("fixture .dynsym name = %q, want %q", name, ".dynsym")
	}
	if dataErr != nil {
		t.Fatalf("reading the fixture's section: %v", dataErr)
	}
	if len(data) == 0 {
		t.Fatal("fixture section yielded 0 bytes; this test is about a non-empty, malformed table")
	}
	if uint64(len(data)) != size {
		t.Fatalf("fixture section yielded %d bytes under a declared size of %d; the malformation must be the length, not a short read", len(data), size)
	}
	if len(data)%24 == 0 {
		t.Fatalf("fixture body is %d bytes, a whole number of 24-byte entries; the reader would accept it", len(data))
	}

	// collectELF must fail closed rather than skip the table as empty.
	set := newTestEvidence(path, KindELF)
	err = collectELF(path, set, DefaultBinaryConfig())
	if err == nil {
		t.Fatal("collectELF accepted a truncated .dynsym; a malformed table must fail the scan rather than be skipped as empty")
	}
	if !strings.Contains(err.Error(), "dynamic symbols") {
		t.Errorf("error = %v, want it to name the dynamic symbol read", err)
	}
}

// TestCollectELFEvidenceReportsACompressedSectionWithAnOutOfRangeSize pins the
// unsigned size comparison. For a SHF_COMPRESSED section debug/elf takes
// Section.Size from the compression header's ch_size without the int64 range
// check it applies to sh_size, so a crafted ch_size with the top bit set makes
// int64(Section.Size) negative: a signed "read < int64(sec.Size)" is false for
// every non-negative read, the section scores as read in full, and - because
// executable code is not random - its entropy is reported as clean. The fixture's
// section decompresses to far fewer bytes than it declares, which is exactly the
// short-read the check exists to catch, so the size must be compared in its own
// unsigned domain.
func TestCollectELFEvidenceReportsACompressedSectionWithAnOutOfRangeSize(t *testing.T) {
	// 2^63, one past the largest int64: int64(ch_size) is negative.
	const declared = uint64(1) << 63
	payload := bytes.Repeat([]byte{0x90}, 4096) // low entropy: no verdict either way

	dir := t.TempDir()
	path := writeTestBytes(t, dir, "packed.so", elfCompressedFixture(t, declared, payload))

	// The fixture must be the shape the check is for: a compressed executable
	// section whose reported size is the declared one.
	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("elf.Open on the fixture: %v", err)
	}
	var sec *elf.Section
	for _, s := range f.Sections {
		if s.Flags&elf.SHF_EXECINSTR != 0 {
			sec = s
		}
	}
	if sec == nil {
		f.Close()
		t.Fatal("fixture has no executable section")
	}
	size := sec.Size
	f.Close()
	if size != declared {
		t.Fatalf("fixture section size = %d, want %d (debug/elf must take it from ch_size)", size, declared)
	}

	set := newTestEvidence(path, KindELF)
	if err := collectELF(path, set, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectELF on a compressed section: %v", err)
	}
	if !set.Bound.Structural {
		t.Fatalf("a compressed executable section declaring %d bytes recorded no structural bound; bound = %+v", declared, set.Bound)
	}
	if !strings.Contains(set.Bound.Reason, "readable") {
		t.Errorf("bound reason = %q, want the short-read reason", set.Bound.Reason)
	}
	for _, l := range set.Lines {
		if l.Source == SourceEntropy {
			t.Errorf("an under-read executable section produced entropy evidence %q", l.Text)
		}
	}
}

// TestCollectELFEvidenceNormalizesAZeroConfig pins that collectELF resolves a
// zero BinaryConfig to the defaults, as its peers do. Without that,
// MaxStreamBytes of 0 spends the per-file budget before the first section, so
// every executable section records a "0-byte per-file budget was spent"
// structural bound and the import is refused - a false block produced by a
// caller that knows about only one field. The same file under the default config
// is clean, so the two must agree.
func TestCollectELFEvidenceNormalizesAZeroConfig(t *testing.T) {
	dir := t.TempDir()
	raw := elfFixtureBytes(t, elfSpec{
		imports:  []string{"dlopen"},
		text:     []byte("an ordinary executable section of perfectly normal code"),
		textExec: true,
	})
	path := writeTestBytes(t, dir, "normal.so", raw)

	zero := newTestEvidence(path, KindELF)
	if err := collectELF(path, zero, BinaryConfig{}); err != nil {
		t.Fatalf("collectELF with a zero config: %v", err)
	}
	def := newTestEvidence(path, KindELF)
	if err := collectELF(path, def, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectELF with the default config: %v", err)
	}

	if zero.Bound.Structural {
		t.Errorf("a zero config produced a structural bound %+v; the zero value must mean the defaults", zero.Bound)
	}
	if zero.Bound != def.Bound {
		t.Errorf("zero config bound = %+v, default config bound = %+v; they must agree", zero.Bound, def.Bound)
	}
	if len(zero.Lines) != len(def.Lines) {
		t.Fatalf("zero config produced %d evidence lines, default config produced %d", len(zero.Lines), len(def.Lines))
	}
	for i := range zero.Lines {
		z, d := zero.Lines[i], def.Lines[i]
		if z.Source != d.Source || z.Offset != d.Offset || z.Text != d.Text {
			t.Errorf("line %d differs: zero config (%s %d %q), default config (%s %d %q)",
				i, z.Source, z.Offset, z.Text, d.Source, d.Offset, d.Text)
		}
	}
}

// TestCountSectionStreamsTheSameHistogramAsABufferRead pins that chunking the
// section read does not change the number it produces. The fixture is larger
// than one chunk so the loop body runs more than once: an implementation that
// reset its counters per chunk, or dropped the final short chunk, would still
// pass a single-chunk test and would make an ELF section's entropy depend on its
// size rather than on its bytes.
func TestCountSectionStreamsTheSameHistogramAsABufferRead(t *testing.T) {
	data := make([]byte, entropyChunkBytes+1234)
	for i := range data {
		data[i] = byte((i * 31) % 251)
	}

	counts, n, err := countSection(bytes.NewReader(data), 0)
	if err != nil {
		t.Fatalf("countSection: %v", err)
	}
	if n != int64(len(data)) {
		t.Fatalf("countSection read %d bytes, want %d", n, len(data))
	}
	if got, want := shannonEntropy(counts, n), measureEntropy(data); math.Abs(got-want) > 1e-12 {
		t.Errorf("streamed entropy = %v, buffered = %v; the two must agree", got, want)
	}

	// A budget smaller than the section stops the read and reports how far it
	// got, which is the number the caller compares against the declared size.
	const budget = int64(4096)
	if _, n, err := countSection(bytes.NewReader(data), budget); err != nil || n != budget {
		t.Errorf("countSection with a %d-byte budget read %d bytes (err=%v), want exactly %d", budget, n, err, budget)
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// TestStreamWithSizeSwitchWindowsAFileAboveTheFullScanBudget pins the switch in
// both directions. At or below the budget the whole file is read, so a literal
// that exists only in the middle is found and no bound is recorded; above it the
// two windows are read, so the head literal is found, the middle one is not, and
// the skip is a structural bound naming the threshold and the window size.
//
// The threshold is read from cfg rather than a constant, so a small config drives
// the same branch a 64 MiB fixture would and the test does not have to build that
// fixture. Do not "fix" this by building a real oversized file.
//
// What a structural bound costs a package is not decided here. Task 9's scanner
// folds it through isExecutableKind: a windowed pickle or ELF is withheld, a
// windowed raw blob is only recorded. This test asserts the record, not the
// block, and must not be read as the place that decides whether to block or withhold.
func TestStreamWithSizeSwitchWindowsAFileAboveTheFullScanBudget(t *testing.T) {
	dir := t.TempDir()
	const fullScan, window = 4096, 64
	cfg := DefaultBinaryConfig()
	cfg.MaxFullScanBytes = fullScan
	cfg.HeadTailBytes = window

	small := make([]byte, fullScan)
	copy(small, "\x00SMALL_HEAD\x00")
	copy(small[fullScan/2:], "\x00SMALL_MIDDLE\x00")

	large := make([]byte, fullScan*2)
	copy(large, "\x00LARGE_HEAD\x00")
	copy(large[fullScan:], "\x00LARGE_MIDDLE\x00")
	copy(large[len(large)-13:], "\x00LARGE_TAIL\x00")

	for _, tc := range []struct {
		file       string
		content    []byte
		wantFound  []string
		wantAbsent []string
		wantBound  bool
	}{
		{"at_budget.bin", small, []string{"SMALL_HEAD", "SMALL_MIDDLE"}, nil, false},
		{"above_budget.bin", large, []string{"LARGE_HEAD", "LARGE_TAIL"}, []string{"LARGE_MIDDLE"}, true},
	} {
		t.Run(tc.file, func(t *testing.T) {
			path := writeTestBytes(t, dir, tc.file, tc.content)
			set := newTestEvidence(path, KindRaw)
			// CollectEvidence sets Size from the file itself, and the switch decides
			// the branch from it. A zero Size would take the whole-file branch for
			// every file and the test would pass without ever exercising the window.
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			set.Size = info.Size()

			if err := streamWithSizeSwitch(path, set, cfg); err != nil {
				t.Fatalf("streamWithSizeSwitch: %v", err)
			}

			texts := map[string]bool{}
			for _, l := range set.Lines {
				texts[l.Text] = true
			}
			for _, want := range tc.wantFound {
				if !texts[want] {
					t.Errorf("%q missing from the evidence", want)
				}
			}
			for _, absent := range tc.wantAbsent {
				if texts[absent] {
					t.Errorf("%q was read; the middle of an oversized file must be skipped", absent)
				}
			}
			if set.Bound.Structural != tc.wantBound {
				t.Fatalf("Bound.Structural = %t, want %t (reason %q)", set.Bound.Structural, tc.wantBound, set.Bound.Reason)
			}
			if !tc.wantBound {
				return
			}
			if !strings.Contains(set.Bound.Reason, "MaxFullScanBytes") {
				t.Errorf("bound reason = %q, want it to name MaxFullScanBytes", set.Bound.Reason)
			}
			if !strings.Contains(set.Bound.Reason, fmt.Sprintf("head and tail %d", window)) {
				t.Errorf("bound reason = %q, want it to name the %d-byte head/tail window", set.Bound.Reason, window)
			}
		})
	}
}

// TestStreamWithSizeSwitchRecordsNoBoundWhenTheWindowsCoverTheFile pins the
// other half of the switch: the two windows are taken for any file above
// MaxFullScanBytes, but they only leave a middle unread when the file is longer
// than both of them together.
//
// The default configuration cannot express the difference - 64 MiB is thirty-two
// times the 1 MiB window, so every file that takes the branch also has a middle -
// which is why the threshold and the window are driven from a config here. The
// reachable case is a deployment that lowers MaxFullScanBytes below twice
// HeadTailBytes: the file then fits inside the windows, is read in full, and must
// not be recorded as bounded. Recording it would be worse than a wrong number in
// a report - a structural bound on an executable kind withholds the pass, so the
// import would be refused over a file nothing was missed in, with a reason string
// claiming a middle was skipped.
func TestStreamWithSizeSwitchRecordsNoBoundWhenTheWindowsCoverTheFile(t *testing.T) {
	dir := t.TempDir()
	const fullScan, window = 64, 4096
	cfg := DefaultBinaryConfig()
	cfg.MaxFullScanBytes = fullScan
	cfg.HeadTailBytes = window

	// Above the threshold - so the windows are what read it - and no longer than
	// the two windows together, so between them they cover every byte.
	content := make([]byte, 2*window)
	copy(content, "\x00COVERED_HEAD\x00")
	copy(content[len(content)-15:], "\x00COVERED_TAIL\x00")

	path := writeTestBytes(t, dir, "covered.bin", content)
	set := newTestEvidence(path, KindELF)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	set.Size = info.Size()
	if set.Size <= int64(fullScan) || set.Size > 2*int64(window) {
		t.Fatalf("fixture is %d bytes, which does not sit in (%d, %d]; the test would not reach the branch it names",
			set.Size, fullScan, 2*window)
	}

	if err := streamWithSizeSwitch(path, set, cfg); err != nil {
		t.Fatalf("streamWithSizeSwitch: %v", err)
	}

	if set.Bound.Structural {
		t.Errorf("Bound.Structural = true with reason %q for a file the two windows cover end to end", set.Bound.Reason)
	}
	texts := map[string]bool{}
	for _, l := range set.Lines {
		texts[l.Text] = true
	}
	for _, want := range []string{"COVERED_HEAD", "COVERED_TAIL"} {
		if !texts[want] {
			t.Errorf("%q missing from the evidence", want)
		}
	}
}

// zipFixture builds a zip in memory, so the container tests state their members
// rather than depending on a committed archive.
func zipFixture(t *testing.T, members map[string][]byte, order []string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, name := range order {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(members[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestCollectArchiveEvidenceListsMembersAndRecurses(t *testing.T) {
	dir := t.TempDir()
	pickle := []byte("\x80\x04cposix\nsystem\n.")
	elfMember := elfFixtureBytes(t, elfSpec{imports: []string{"connect"}, needed: []string{"libcurl.so.4"}})
	raw := zipFixture(t, map[string][]byte{
		"archive/data.pkl": pickle,
		"archive/lib.so":   elfMember,
		"archive/version":  []byte("3"),
	}, []string{"archive/version", "archive/data.pkl", "archive/lib.so"})
	path := writeTestBytes(t, dir, "model.pt", raw)

	set := newTestEvidence(path, KindArchive)
	if err := collectArchive(path, set, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectArchive: %v", err)
	}

	var members, pickles, dynsyms, needed []string
	for _, l := range set.Lines {
		switch l.Source {
		case SourceMember:
			members = append(members, l.Text)
		case SourcePickle:
			pickles = append(pickles, l.Text)
		case SourceDynsym:
			dynsyms = append(dynsyms, l.Text)
		case SourceNeeded:
			needed = append(needed, l.Text)
		}
	}

	for _, want := range []string{"archive/version", "archive/data.pkl", "archive/lib.so"} {
		found := false
		for _, m := range members {
			if strings.HasPrefix(m, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("member %q missing; got %v", want, members)
		}
	}
	if !containsString(pickles, "posix.system") {
		t.Errorf("a pickle member produced no target evidence; got %v", pickles)
	}
	if !containsString(dynsyms, "connect") {
		t.Errorf("an ELF member's imports were not read; got %v", dynsyms)
	}
	if !containsString(needed, "libcurl.so.4") {
		t.Errorf("an ELF member's DT_NEEDED was not read; got %v", needed)
	}
}

// TestCollectArchiveEvidenceClaimsAProtocol01MemberByNameAlone pins the second
// call site of the claim rule. collectArchive classifies every zip member with
// ClassifyBinary(head, member.Name), so a member that is a protocol 0/1 pickle
// under a data name - data.bin, which the extension set reads as a raw blob - has
// to reach collectPickleMember on its content alone. Without the content claim
// the member is skipped, the container yields no pickle target, and PKL_001
// cannot fire on a checkpoint whose payload was moved inside a .pt.
func TestCollectArchiveEvidenceClaimsAProtocol01MemberByNameAlone(t *testing.T) {
	dir := t.TempDir()
	raw := zipFixture(t, map[string][]byte{
		"data.bin": []byte("cposix\nsystem\n(Vid\ntR."),
	}, []string{"data.bin"})
	path := writeTestBytes(t, dir, "model.pt", raw)

	set := newTestEvidence(path, KindArchive)
	if err := collectArchive(path, set, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectArchive: %v", err)
	}

	var pickles []string
	for _, l := range set.Lines {
		if l.Source == SourcePickle {
			pickles = append(pickles, l.Text)
		}
	}
	if !containsString(pickles, "posix.system") {
		t.Errorf("a protocol 0/1 member named data.bin produced no target evidence; got %v", pickles)
	}
}

// TestCollectArchiveEvidenceBoundsMemberCount pins the member ceiling as a
// structural bound. Members past the ceiling are never opened, and for a
// container that can hold a pickle that is a look that did not happen - so it
// withholds a clean verdict rather than being reported as a big archive.
func TestCollectArchiveEvidenceBoundsMemberCount(t *testing.T) {
	dir := t.TempDir()
	members := map[string][]byte{}
	var order []string
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("m%d", i)
		members[name] = []byte("x")
		order = append(order, name)
	}
	path := writeTestBytes(t, dir, "many.whl", zipFixture(t, members, order))

	cfg := DefaultBinaryConfig()
	cfg.MaxArchiveMembers = 2
	set := newTestEvidence(path, KindArchive)
	if err := collectArchive(path, set, cfg); err != nil {
		t.Fatalf("collectArchive: %v", err)
	}
	if !set.Bound.Structural {
		t.Error("Bound.Structural = false after the member ceiling was reached")
	}
}

// TestCollectArchiveEvidenceBoundsAMemberAtTheByteBudget pins the per-member
// structural bound, which is the one a container's import is actually withheld
// on: isExecutableKind(KindArchive) is true, so a structural bound here stops the
// scan passing, and the bound is recorded because a member's tail was never
// looked at. Without this test the guard is unpinned - removing it leaves the
// whole suite green, which is the shape a guard silently drops into.
//
// A small budget drives the same branch as a member above the default 256 MiB:
// the guard reads cfg.MaxArchiveMemberBytes, so a tiny config reaches it without
// a quarter-gigabyte fixture. The budget is the member's own length because that
// is the only value that reaches this guard rather than the dispatcher's earlier
// declared-size check: a smaller budget makes collectArchive mark the member from
// its declared UncompressedSize64 and break before the member is opened, which is
// a different guard. The comparison is >= rather than >, so a member exactly at
// the budget is bounded as well - the read was capped, and whether the member
// continued past the cap cannot be told without a further probe.
//
// The reason is asserted, not only the flag, because it is the line an operator
// reads when an import is held back: a bare Bound.Structural would not say which
// member hit which limit.
func TestCollectArchiveEvidenceBoundsAMemberAtTheByteBudget(t *testing.T) {
	dir := t.TempDir()
	elfMember := elfFixtureBytes(t, elfSpec{imports: []string{"connect"}, needed: []string{"libc.so.6"}})
	path := writeTestBytes(t, dir, "model.pt", zipFixture(t, map[string][]byte{"lib.so": elfMember}, []string{"lib.so"}))

	cfg := DefaultBinaryConfig()
	cfg.MaxArchiveMemberBytes = int64(len(elfMember))
	set := newTestEvidence(path, KindArchive)
	if err := collectArchive(path, set, cfg); err != nil {
		t.Fatalf("collectArchive: %v", err)
	}
	if !set.Bound.Structural {
		t.Fatalf("Bound.Structural = false for a member at the byte budget; its tail was never read")
	}
	if !strings.Contains(set.Bound.Reason, "lib.so") {
		t.Errorf("bound reason = %q, want it to name the member lib.so", set.Bound.Reason)
	}
	if !strings.Contains(set.Bound.Reason, "byte budget") {
		t.Errorf("bound reason = %q, want it to name the byte budget", set.Bound.Reason)
	}
}

// TestCollectArchiveEvidenceReturnsAnErrorForAnUnopenableContainer pins the other
// half of the fail-closed split, and the reason it is not folded into the
// member-ceiling test is that the two look identical if a guard is written the
// easy way. A container that will not open is a file the scan never looked at, so
// collectArchive returns an error; only a container it opened and did not finish
// gets Bound.Structural. Swallowing the open error into markStructural would make
// an unreadable file indistinguishable from a read one - the scanner counts set.Err
// as Incomplete and withholds the pass, and a bound alone does not carry that.
func TestCollectArchiveEvidenceReturnsAnErrorForAnUnopenableContainer(t *testing.T) {
	dir := t.TempDir()
	// Zip magic, then bytes with no central directory behind them, so the magic
	// classifies it as a container and zip.NewReader refuses it.
	raw := append([]byte("PK\x03\x04"), bytes.Repeat([]byte{0xff}, 64)...)
	path := writeTestBytes(t, dir, "broken.pt", raw)

	set := newTestEvidence(path, KindArchive)
	err := collectArchive(path, set, DefaultBinaryConfig())
	if err == nil {
		t.Fatal("collectArchive accepted a file with zip magic that will not open; a failed look must not be reported as a bounded one")
	}
	if set.Bound.Structural {
		t.Errorf("an unopenable container set Bound.Structural (%q); the failure must be an error, not a bound", set.Bound.Reason)
	}
}

// TestCollectCompressedEvidence pins both directions of the gzip gate. The
// decompressed bytes are a file of their own, so the pickle interpreter runs on
// them only if they sniff as a pickle: a pickle hidden in a .gz is read as one,
// and a gzip that is not a pickle gets the strings pass alone rather than a
// structural bound on KindCompressed - which is executable, so a bound there
// would block every .gz in every package.
func TestCollectCompressedEvidence(t *testing.T) {
	dir := t.TempDir()
	gz := func(name, content string) string {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		return writeTestBytes(t, dir, name, buf.Bytes())
	}

	picklePath := gz("payload.gz", "\x80\x04cposix\nsystem\n.PADDING_PADDING")
	set := newTestEvidence(picklePath, KindCompressed)
	if err := collectCompressed(picklePath, set, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectCompressed: %v", err)
	}
	var pickles []string
	for _, l := range set.Lines {
		if l.Source == SourcePickle {
			pickles = append(pickles, l.Text)
		}
	}
	if !containsString(pickles, "posix.system") {
		t.Errorf("pickle evidence = %v, want [posix.system]", pickles)
	}

	// A gzip of bytes that are not a pickle must not produce pickle evidence and
	// must not be bounded: the interpreter never ran.
	textPath := gz("notes.gz", "the posix system call interface is described here")
	set = newTestEvidence(textPath, KindCompressed)
	if err := collectCompressed(textPath, set, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectCompressed: %v", err)
	}
	for _, l := range set.Lines {
		if l.Source == SourcePickle {
			t.Errorf("pickle evidence %q from a gzip that is not a pickle", l.Text)
		}
	}
	if set.Bound.Structural {
		t.Errorf("a gzip that is not a pickle set Bound.Structural: %s", set.Bound.Reason)
	}
}

// lyingMember builds a one-member zip whose header declares a size that does not
// match the bytes it stores. zip.Writer.Create writes the true sizes, so a fixture
// that has to lie needs CreateRaw and the header fields set by hand.
//
// It exists because a member whose declared size exceeds a budget is caught by
// collectArchive's declared-size check before it is ever opened, so the inner
// per-member budgets are reachable only by a member that lies - and the reader
// bounds what it hands out: checksumReader returns ErrFormat the moment it reads
// past the declared UncompressedSize64, so a member can never deliver more than
// its declared size. The only lie that both bypasses the declared-size check and
// delivers bytes is the high bit set, which makes int64(UncompressedSize64)
// negative and the "> budget" comparison false.
func lyingMember(t *testing.T, name string, body []byte, method uint16, declared uint64) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	fh := &zip.FileHeader{Name: name, Method: method}
	fh.UncompressedSize64 = declared
	fh.CompressedSize64 = uint64(len(body))
	fh.CRC32 = crc32.ChecksumIEEE(body)
	w, err := zw.CreateRaw(fh)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestCollectCompressedEvidenceBoundsTheDecompressedBudget pins the budget on the
// decompressed bytes of a gzip. It is the most serious of the container budgets:
// it is the only thing between a small .gz and an unbounded decompression scan,
// and reaching it needs no crafted input, only ordinary compressible data.
//
// A small cfg reaches the same branch as a stream above the default 256 MiB - the
// guard reads cfg.MaxArchiveMemberBytes - so the fixture is 512 bytes, not a
// quarter of a gigabyte. The bytes are not a pickle, so the interpreter does not
// run and the bound asserted is the budget's rather than the interpreter's.
func TestCollectCompressedEvidenceBoundsTheDecompressedBudget(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(bytes.Repeat([]byte("A"), 512)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	path := writeTestBytes(t, dir, "big.gz", buf.Bytes())

	cfg := DefaultBinaryConfig()
	cfg.MaxArchiveMemberBytes = 64
	set := newTestEvidence(path, KindCompressed)
	if err := collectCompressed(path, set, cfg); err != nil {
		t.Fatalf("collectCompressed: %v", err)
	}
	if !set.Bound.Structural {
		t.Fatalf("Bound.Structural = false for a .gz past the decompressed budget; the scan was not bounded")
	}
	if want := "decompressed stream exceeds 64 bytes"; !strings.Contains(set.Bound.Reason, want) {
		t.Errorf("bound reason = %q, want it to name %q", set.Bound.Reason, want)
	}
}

// TestCollectArchiveEvidenceBoundsAPickleMemberAtTheByteBudget pins the pass-through
// from collectPickleMember to streamReaderEvidence. The bound it can set - "member
// %s exceeds the byte budget" - is unreachable for an honest member: the declared
// size that would exceed the budget is caught first by collectArchive's
// declared-size check, so the member is never opened, and an honest member never
// delivers more than its declared size. Reaching this budget is therefore only
// possible through lyingMember's high-bit lie, which is why the fixture lies.
//
// A small cfg reaches the same branch as a member above the default budget, and
// the pickle body stops at STOP well inside the budget, so the interpreter records
// only a trailing-bytes notice and the budget is the first structural reason.
func TestCollectArchiveEvidenceBoundsAPickleMemberAtTheByteBudget(t *testing.T) {
	dir := t.TempDir()
	// PROTO, GLOBAL(posix.system), STOP, then padding after STOP that the
	// interpreter counts but does not parse.
	body := append([]byte("\x80\x04cposix\nsystem\n."), bytes.Repeat([]byte(" "), 400)...)
	path := writeTestBytes(t, dir, "model.pt", lyingMember(t, "payload.pkl", body, zip.Store, 1<<63))

	cfg := DefaultBinaryConfig()
	cfg.MaxArchiveMemberBytes = 64
	set := newTestEvidence(path, KindArchive)
	if err := collectArchive(path, set, cfg); err != nil {
		t.Fatalf("collectArchive: %v", err)
	}
	if !set.Bound.Structural {
		t.Fatalf("Bound.Structural = false for a pickle member past the byte budget")
	}
	if !strings.Contains(set.Bound.Reason, "payload.pkl") {
		t.Errorf("bound reason = %q, want it to name the member", set.Bound.Reason)
	}
	if !strings.Contains(set.Bound.Reason, "exceeds the byte budget") {
		t.Errorf("bound reason = %q, want the pickle member byte-budget wording", set.Bound.Reason)
	}
}

// TestCollectArchiveEvidenceBoundsAMemberByItsDeclaredSize pins the declared-size
// check, the one that fires before a member is opened and is therefore the real
// zip-bomb guard: a small archive can declare a member far larger than the whole
// archive, and trusting the declaration is what the check refuses to do.
//
// Two cases. Declared comfortably above the budget is caught by the check itself.
// Declared with the high bit set makes int64(UncompressedSize64) negative, so the
// "> budget" comparison is false and the check is bypassed - and then it is the
// inner per-member budget, not this one, that bounds the member. That second case
// is what makes the inner budgets load-bearing rather than redundant, so it is
// pinned here over an ELF member (the pickle-side inner budget is pinned by
// TestCollectArchiveEvidenceBoundsAPickleMemberAtTheByteBudget).
func TestCollectArchiveEvidenceBoundsAMemberByItsDeclaredSize(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultBinaryConfig()
	cfg.MaxArchiveMemberBytes = 64

	t.Run("above the budget", func(t *testing.T) {
		body := append([]byte("\x80\x04cposix\nsystem\n."), bytes.Repeat([]byte(" "), 400)...)
		path := writeTestBytes(t, dir, "bomb.pt", lyingMember(t, "big.pkl", body, zip.Store, 1<<20))

		set := newTestEvidence(path, KindArchive)
		if err := collectArchive(path, set, cfg); err != nil {
			t.Fatalf("collectArchive: %v", err)
		}
		if !set.Bound.Structural {
			t.Fatalf("Bound.Structural = false for a member declaring a size above the budget")
		}
		if want := "member byte budget 64 reached at big.pkl"; !strings.Contains(set.Bound.Reason, want) {
			t.Errorf("bound reason = %q, want it to name %q", set.Bound.Reason, want)
		}
	})

	t.Run("high bit set", func(t *testing.T) {
		body := elfFixtureBytes(t, elfSpec{imports: []string{"connect"}})
		path := writeTestBytes(t, dir, "bomb2.pt", lyingMember(t, "lib.so", body, zip.Store, 1<<63))

		set := newTestEvidence(path, KindArchive)
		if err := collectArchive(path, set, cfg); err != nil {
			t.Fatalf("collectArchive: %v", err)
		}
		if !set.Bound.Structural {
			t.Fatalf("Bound.Structural = false for a high-bit declared member; the inner budget did not bound it")
		}
		if !strings.Contains(set.Bound.Reason, "lib.so") {
			t.Errorf("bound reason = %q, want it to name the member", set.Bound.Reason)
		}
		if !strings.Contains(set.Bound.Reason, "truncated at the byte budget") {
			t.Errorf("bound reason = %q, want the ELF member byte-budget wording", set.Bound.Reason)
		}
	})
}

// gzipOfZeros writes a gzip stream whose decompressed content is n zero bytes,
// streaming the input so the fixture stays small even when n is hundreds of
// megabytes. Zero bytes are used because they are neither a pickle nor a string,
// so the only bound a scan of them can record is the byte budget's.
func gzipOfZeros(t *testing.T, dir, name string, n int) string {
	t.Helper()
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	block := make([]byte, 1<<20)
	for written := 0; written < n; {
		chunk := len(block)
		if remaining := n - written; remaining < chunk {
			chunk = remaining
		}
		if _, err := zw.Write(block[:chunk]); err != nil {
			t.Fatal(err)
		}
		written += chunk
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return writeTestBytes(t, dir, name, buf.Bytes())
}

// TestCollectCompressedEvidenceNormalizesAZeroConfig pins that collectCompressed
// resolves a zero BinaryConfig to the defaults, as collectELF does. It is the
// collector where the asymmetry is a defect and not just a wart: streamReaderEvidence
// reads a budget of zero as "unlimited", so an unresolved zero disables the
// decompression bound entirely - fail-open in the one direction this design
// refuses, in contrast to the fail-closed-but-wrong a zero produces elsewhere.
//
// The mirror is Task 5's TestCollectELFEvidenceNormalizesAZeroConfig. Its shape is
// forced by the asymmetry itself: the two configs differ only on a stream past the
// DEFAULT budget, so the fixture inflates to DefaultBinaryConfig().MaxArchiveMemberBytes+1
// zero bytes and the zero config must bound it exactly as the default does.
func TestCollectCompressedEvidenceNormalizesAZeroConfig(t *testing.T) {
	dir := t.TempDir()
	budget := DefaultBinaryConfig().MaxArchiveMemberBytes
	path := gzipOfZeros(t, dir, "huge.gz", int(budget)+1)

	zero := newTestEvidence(path, KindCompressed)
	if err := collectCompressed(path, zero, BinaryConfig{}); err != nil {
		t.Fatalf("collectCompressed with a zero config: %v", err)
	}
	if !zero.Bound.Structural {
		t.Fatalf("a zero config left a %d-byte decompressed stream unbounded; the zero value must mean the default budget, not no budget", budget+1)
	}
	if want := fmt.Sprintf("decompressed stream exceeds %d bytes", budget); !strings.Contains(zero.Bound.Reason, want) {
		t.Errorf("bound reason = %q, want it to name the default budget %d", zero.Bound.Reason, budget)
	}

	def := newTestEvidence(path, KindCompressed)
	if err := collectCompressed(path, def, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectCompressed with the default config: %v", err)
	}
	if zero.Bound != def.Bound {
		t.Errorf("zero config bound = %+v, default config bound = %+v; they must agree", zero.Bound, def.Bound)
	}
}

// TestCollectArchiveEvidenceNormalizesAZeroConfig pins that collectArchive resolves
// a zero BinaryConfig to the defaults. It is not the fail-open case - a zero
// MaxArchiveMembers reads as "no member allowed" and bounds the first member, which
// is fail-closed - but it is the same asymmetry, and without it a caller that set
// one field would silently bound every archive.
func TestCollectArchiveEvidenceNormalizesAZeroConfig(t *testing.T) {
	dir := t.TempDir()
	raw := zipFixture(t, map[string][]byte{"data.pkl": []byte("\x80\x04cposix\nsystem\n.")}, []string{"data.pkl"})
	path := writeTestBytes(t, dir, "model.pt", raw)

	zero := newTestEvidence(path, KindArchive)
	if err := collectArchive(path, zero, BinaryConfig{}); err != nil {
		t.Fatalf("collectArchive with a zero config: %v", err)
	}
	def := newTestEvidence(path, KindArchive)
	if err := collectArchive(path, def, DefaultBinaryConfig()); err != nil {
		t.Fatalf("collectArchive with the default config: %v", err)
	}
	if zero.Bound.Structural {
		t.Errorf("a zero config produced a structural bound %+v; the zero value must mean the defaults", zero.Bound)
	}
	if zero.Bound != def.Bound {
		t.Errorf("zero config bound = %+v, default config bound = %+v; they must agree", zero.Bound, def.Bound)
	}
	if len(zero.Lines) != len(def.Lines) {
		t.Errorf("zero config produced %d evidence lines, default config produced %d", len(zero.Lines), len(def.Lines))
	}
}

func TestCollectEvidenceRoutesByKind(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		file string
		raw  []byte
		want BinaryKind
		// wantSource is the evidence source only the dedicated collector for
		// this kind produces. It is asserted rather than implied by a non-empty
		// listing because the shared strings pass emits "connect" from an ELF
		// and "system" from a pickle just as readily as the collectors do, so
		// presence alone stays green when a kind is misrouted into that pass -
		// which is the loss this channel exists to prevent.
		wantSource EvidenceSource
	}{
		{"elf", "lib.so", elfFixtureBytes(t, elfSpec{imports: []string{"connect"}}), KindELF, SourceDynsym},
		{"archive", "m.pt", zipFixture(t, map[string][]byte{"a": []byte("x")}, []string{"a"}), KindArchive, SourceMember},
		{"pickle", "m.pkl", []byte("\x80\x04cposix\nsystem\n."), KindPickle, SourcePickle},
		{"raw", "w.bin", []byte("data\x00literal_here"), KindRaw, SourceStrings},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTestBytes(t, dir, tc.file, tc.raw)
			set := CollectEvidence(path, tc.want, DefaultBinaryConfig())
			if set.Err != nil {
				t.Fatalf("CollectEvidence: %v", set.Err)
			}
			if len(set.Lines) == 0 {
				t.Error("no evidence at all from a file that has some")
			}
			// The source is what pins the dispatch: SourceDynsym comes only
			// from the ELF parse, SourceMember only from the zip walk and
			// SourcePickle only from the interpreter, so a kind that never
			// reached its collector cannot produce its line. KindRaw is the one
			// case where the shared strings pass is the collector, so its
			// expectation is SourceStrings and there is nothing stronger to
			// assert.
			found := false
			for _, l := range set.Lines {
				if l.Source == tc.wantSource {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("no %s evidence: the file never reached its %s collector", tc.wantSource, tc.want)
			}
			// Finalize assigns Index; nothing may read the listing before it.
			for i, l := range set.Lines {
				if l.Index != i+1 {
					t.Fatalf("line %d has Index %d; Finalize did not run or did not sort", i, l.Index)
				}
			}
			for i := 1; i < len(set.Lines); i++ {
				a, b := set.Lines[i-1], set.Lines[i]
				if a.Offset > b.Offset {
					t.Fatalf("listing is not in offset order at %d: %d then %d", i, a.Offset, b.Offset)
				}
			}
		})
	}
}

// TestCollectEvidenceDoesNotInterpretNonPicklesAsPickles pins the reversal of
// what this test used to assert. The plan previously ran the pickle scan on every
// stream unconditionally, which was harmless only because that scan was a
// byte-pattern match that never committed to a parse. The interpreter commits: it
// either reads the bytes as opcodes or records that it could not, and an ELF's
// first byte (\x7f) is not an opcode - so running it over a shared object would set
// Bound.Structural, and because KindELF is an executable kind that bound withholds
// a clean verdict and blocks the import. Every .so in every model package would be
// blocked. The interpreter therefore runs only on a stream that is claimed to be a
// pickle (Task 4's gate rule), and a non-pickle gets the strings pass alone.
func TestCollectEvidenceDoesNotInterpretNonPicklesAsPickles(t *testing.T) {
	dir := t.TempDir()
	path := writeTestBytes(t, dir, "libkernel.so",
		elfFixtureBytes(t, elfSpec{imports: []string{"connect"}}))

	set := CollectEvidence(path, KindELF, DefaultBinaryConfig())
	if set.Err != nil {
		t.Fatalf("CollectEvidence: %v", set.Err)
	}
	if set.Bound.Structural {
		t.Fatalf("an ELF tripped a structural bound (%s); the interpreter ran on a non-pickle", set.Bound.Reason)
	}
	for _, l := range set.Lines {
		if l.Source == SourcePickle {
			t.Errorf("pickle evidence %q produced from an ELF", l.Text)
		}
	}
}

// TestCollectEvidenceRecordsAnUnreadableFile pins the failure direction. A file
// that cannot be examined is an error on the set, not an empty listing: an empty
// listing reads as "clean" to everything downstream, which is the one thing an
// incomplete look must never say.
func TestCollectEvidenceRecordsAnUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	path := writeTestBytes(t, dir, "broken.so", []byte("\x7fELF\x02\x01\x01\x00not an elf at all"))

	set := CollectEvidence(path, KindELF, DefaultBinaryConfig())
	if set.Err == nil {
		t.Error("Err = nil for a file with ELF magic that does not parse; the scan would report it clean")
	}
}

// TestCollectEvidenceWindowsAFileAboveTheSizeThreshold pins the size switch and,
// more importantly, that it leaves a trace.
//
// The threshold cannot be tested by making a 64 MiB file, so the config is
// lowered and the file kept small. Both directions are asserted for the reason
// the switch exists: a windowed data file is visible but harmless, and a windowed
// pickle - a format that executes - has to record a structural bound, or padding
// a pickle past the threshold would hide a mid-stream GLOBAL and still pass.
func TestCollectEvidenceWindowsAFileAboveTheSizeThreshold(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultBinaryConfig()
	cfg.MaxFullScanBytes = 16
	cfg.HeadTailBytes = 4

	// The marker sits in the middle, past the first window and before the last.
	content := []byte("HEAD\x00")
	content = append(content, bytes.Repeat([]byte{'x'}, 64)...)
	content = append(content, []byte("\x00MIDDLE_MARKER\x00TAIL")...)

	cases := []struct {
		name        string
		file        string
		kind        BinaryKind
		wantBlocked bool // isExecutableKind: a structural bound on this kind withholds a clean verdict
	}{
		{"a windowed data file is recorded but harmless", "w.bin", KindRaw, false},
		{"a windowed pickle withholds", "m.pkl", KindPickle, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTestBytes(t, dir, tc.file, content)
			set := CollectEvidence(path, tc.kind, cfg)
			if set.Err != nil {
				t.Fatalf("CollectEvidence: %v", set.Err)
			}
			if !set.Bound.Structural {
				t.Error("Bound.Structural = false: the middle of an oversized file was skipped without a trace")
			}
			if !strings.Contains(set.Bound.Reason, "MaxFullScanBytes") {
				t.Errorf("Bound.Reason = %q, want it to name the threshold", set.Bound.Reason)
			}
			for _, l := range set.Lines {
				if l.Text == "MIDDLE_MARKER" {
					t.Error("the middle was read anyway; the threshold is not a threshold")
				}
			}
			// This last check is on the predicate itself, not on CollectEvidence:
			// CollectEvidence never consults isExecutableKind, so this only
			// keeps wantBlocked above honest against the table. What folds the
			// predicate into a withheld verdict is the scanner's, and that
			// arrives in Task 9.
			if got := isExecutableKind(tc.kind); got != tc.wantBlocked {
				t.Errorf("isExecutableKind(%s) = %t, want %t", tc.kind, got, tc.wantBlocked)
			}
		})
	}
}
