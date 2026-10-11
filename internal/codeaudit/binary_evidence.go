package codeaudit

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// EvidenceSource names where one evidence line came from.
//
// It is carried on the line so that a rule can restrict itself to the sources
// it is meaningful for, and so that the limitation is expressed once, in the
// rule table, rather than re-derived at every comparison. The distinction is
// load-bearing: "connect" as a dynamic import is a call the binary can make,
// and the same bytes in a string table are a message it can print. Only the
// first is evidence of network capability.
type EvidenceSource string

const (
	// SourceStrings is a printable byte run extracted from the file.
	SourceStrings EvidenceSource = "strings"
	// SourceDynsym is a name in the dynamic symbol table — a symbol the binary
	// imports from a library. It is the only evidence a stripped binary retains.
	SourceDynsym EvidenceSource = "dynsym"
	// SourceNeeded is a DT_NEEDED entry: a library the loader will bring in.
	SourceNeeded EvidenceSource = "needed"
	// SourceSection is a section's name, size and executability.
	SourceSection EvidenceSource = "section"
	// SourceEntropy is an entropy verdict, already computed from measurements.
	SourceEntropy EvidenceSource = "entropy"
	// SourceMember is a container member's name and size.
	SourceMember EvidenceSource = "member"
	// SourcePickle is a module.attribute pair a pickle stream asks the unpickler
	// to resolve.
	SourcePickle EvidenceSource = "pickle"
	// SourceNotice is a property of the file itself that is neither a match nor
	// a measurement: the interpreter it names, the format that was recognised
	// but not structurally parsed.
	SourceNotice EvidenceSource = "notice"
)

// EvidenceLine is one line of the evidence listing a file yields. It is the
// single representation every extractor produces and every rule matches
// against, which is what lets the rule table be written once for ELF symbols,
// file literals and container members alike.
type EvidenceLine struct {
	// Index is the line's 1-based position in the finished listing. It is what
	// Finding.Line carries for a binary finding, so it is assigned once, after
	// the listing is sorted, and never moves.
	Index int
	// Source is where the text came from.
	Source EvidenceSource
	// Offset is the byte offset in File the evidence was read at. Structured
	// evidence that names a property of the file rather than a byte range - a
	// container member, a section summary, an entropy verdict - carries zero.
	Offset int64
	// Text is what a rule matches against. It is deliberately the bare value and
	// not a pre-formatted line: a rule that had to parse its own rendering would
	// couple every pattern to the rendering.
	Text string
}

// Bounding records which limits an extraction hit, split by what the limit
// cost. The split is the difference between a report that says "we read
// everything and found this" and one that says "we read part of it".
type Bounding struct {
	// Structural is set when extraction of the file's structure was cut short:
	// an ELF section not read, a container member never opened, a stream that
	// ended at the byte budget. For a format that can execute, this withholds a
	// clean-scan verdict, because the unread part is exactly where a payload
	// would live.
	Structural bool
	// Listing is set when the evidence listing hit its line cap. The file was
	// read; not every distinct string in it is in the report. This is recorded
	// because a reader should be able to see it, and it does not withhold a
	// verdict on its own: a binary with sixty thousand distinct strings is a
	// large binary, not an unexamined one.
	Listing bool
	// Reason names the limit that fired, for the report. It is a string rather
	// than an enum so that adding a limit does not change a wire type.
	Reason string
}

// EvidenceSet is the whole evidence listing for one file, plus what is known
// about how completely it was gathered.
type EvidenceSet struct {
	File string
	Kind BinaryKind
	Size int64
	// Lines is the finished listing, sorted and indexed. Extractors append
	// unordered; Finalize assigns Index.
	Lines []EvidenceLine
	// Bound records the limits that fired during extraction.
	Bound Bounding
	// Err is set when the file could not be examined at all. A file with an
	// error is one the scan did not look at, which is a different claim from a
	// file it looked at and found nothing in.
	Err error

	// seen is the deduplication set. It is unexported because it is an
	// implementation detail of the extractors, not part of what a reader gets.
	seen map[string]bool
	// maxLines is the evidence line cap, copied here from the config by
	// newStringScanner so that add - which every extractor calls - can enforce it
	// without every caller carrying the config. Zero means unlimited.
	maxLines int
}

// markStructural records that the extraction of the file's structure was cut
// short. The first reason wins, so the report names the limit that was reached
// first rather than the last one a loop happened to notice.
//
// It lives here rather than with the extractors that call it most, because the
// stream budget in streamEvidence is the first caller: this task's own tests
// assert on the flag it sets.
func (s *EvidenceSet) markStructural(reason string) {
	if s.Bound.Structural {
		return
	}
	s.Bound.Structural = true
	s.Bound.Reason = reason
}

// markListing records that evidence lines were dropped by the listing cap, or
// that one line was cut short at MaxStringLen. Like markStructural the first
// reason wins: a structural limit is what withholds a clean verdict, and a
// listing note that only affects what is displayed must not relabel it.
func (s *EvidenceSet) markListing(reason string) {
	s.Bound.Listing = true
	if s.Bound.Reason == "" {
		s.Bound.Reason = reason
	}
}

// add records one evidence line, deduplicating on the pair (source, text).
//
// Every writer shares this map, so the key is namespaced by source. An
// unnamespaced key lets one source silence another: a file containing the
// printable literal "pickle:os.system" would otherwise occupy the key the
// pickle pass uses for a genuine GLOBAL target, and the rule that exists to
// catch "this file unpickles a call to os.system" would never see it. The NUL
// separator cannot occur in string evidence, because isPrintableByte rejects
// it, so two sources cannot build the same key.
//
// A line dropped by the cap is deliberately not recorded in the map: the map's
// length is the live line count the cap is measured against, so recording it
// would grow the structure without bound and defeat the ceiling the cap exists
// for.
func (s *EvidenceSet) add(src EvidenceSource, off int64, text string) {
	if s.seen == nil {
		s.seen = map[string]bool{}
	}
	key := string(src) + "\x00" + text
	if s.seen[key] {
		return
	}
	if s.maxLines > 0 && len(s.seen) >= s.maxLines {
		s.markListing("evidence line cap reached")
		return
	}
	s.seen[key] = true
	s.Lines = append(s.Lines, EvidenceLine{Source: src, Offset: off, Text: text})
}

// DefaultBinaryMinStringLen is the shortest printable run kept as evidence. It
// matches the default of strings(1): shorter runs are dominated by machine code
// and byte noise, and the short names that matter - socket, connect, execve -
// are at or above it.
const DefaultBinaryMinStringLen = 4

// DefaultBinaryMaxStringLen is how much of one printable run is kept. A long
// blob is truncated rather than split, so one blob is one line; the truncation
// is recorded as a listing bound.
const DefaultBinaryMaxStringLen = 1024

// evidenceReadChunk is the read size for the streaming passes. It is the unit
// the string carry works across, so it is a constant rather than a tunable.
const evidenceReadChunk = 64 * 1024

// stringScanner turns a byte stream into evidence lines: one per run of
// printable bytes at least MinStringLen long, deduplicated, each tagged with the
// offset of its first occurrence.
type stringScanner struct {
	cfg   BinaryConfig
	set   *EvidenceSet
	at    int64
	run   []byte
	runAt int64
	// truncated marks that a run hit MaxStringLen, which is a listing bound: the
	// tail of that run is not in the listing.
	truncated bool
}

func newStringScanner(set *EvidenceSet, cfg BinaryConfig) *stringScanner {
	// The config is normalized here rather than trusted from the caller: this is
	// the function that consumes it, and a zero value would be read as "no byte
	// may enter a run" while still emitting a line, so a mis-set config would
	// silently lose every string and record a listing bound instead of failing
	// loudly.
	cfg = normalizeBinaryConfig(cfg)
	set.maxLines = cfg.MaxEvidenceLines
	return &stringScanner{set: set, cfg: cfg}
}

// Write implements io.Writer. The run is carried across calls, so a literal
// split by a chunk boundary is still one string.
func (s *stringScanner) Write(p []byte) (int, error) {
	for _, b := range p {
		if isPrintableByte(b) {
			if len(s.run) == 0 {
				s.runAt = s.at
			}
			if len(s.run) < s.cfg.MaxStringLen {
				s.run = append(s.run, b)
			} else {
				s.truncated = true
			}
		} else {
			s.flush()
		}
		s.at++
	}
	return len(p), nil
}

// Flush emits the run in progress. It must be called once at end of stream; a
// trailing run is otherwise dropped, which is the kind of loss that only shows
// up on files ending in a literal.
func (s *stringScanner) Flush() {
	s.flush()
	if s.truncated {
		s.set.markListing("string truncated at MaxStringLen")
	}
}

func (s *stringScanner) flush() {
	if len(s.run) >= s.cfg.MinStringLen {
		s.emit(string(s.run), s.runAt)
	}
	s.run = s.run[:0]
}

// emit records one distinct string. The first occurrence wins, so a literal
// repeated through a file is one line tagged with where it starts.
func (s *stringScanner) emit(text string, at int64) {
	s.set.add(SourceStrings, at, text)
}

// isPrintableByte is the printable-ASCII predicate strings(1) uses, plus tab.
// Bytes above 0x7e are excluded rather than decoded: a UTF-8 literal split
// across a chunk boundary would otherwise be emitted half-formed, and the
// ASCII subset is where the paths, URLs and symbol names are.
func isPrintableByte(b byte) bool {
	return b >= 0x20 && b <= 0x7e || b == '\t'
}

// streamEvidence runs the byte-oriented extractors over one file.
//
// budget is the maximum number of bytes the pass may read, and it is enforced
// inside the read rather than between reads: checking it only at the top of the
// loop lets a single 64 KiB read walk straight past a 32-byte budget, which
// makes the budget a decoration. Whether the file was too large is decided up
// front from its size, so that a file that ends exactly at the budget is not
// reported as bounded - a bound that did not cost anything is not a bound.
//
// This pass extracts strings only. The pickle target pass is a second scanner
// over the same reads and is wired in by Task 4, once pickleTargets exists; the
// shape of that patch is written out there.
func streamEvidence(path string, set *EvidenceSet, cfg BinaryConfig, budget int64) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	if info, statErr := f.Stat(); statErr == nil && budget > 0 && info.Size() > budget {
		set.markStructural(fmt.Sprintf("stream budget %d bytes reached (file is %d)", budget, info.Size()))
	}

	scanner := newStringScanner(set, cfg)

	var read int64
	buf := make([]byte, evidenceReadChunk)
	for {
		limit := len(buf)
		if budget > 0 && int64(limit) > budget-read {
			limit = int(budget - read)
		}
		if limit <= 0 {
			break // the budget is spent; the bound was recorded above
		}
		n, readErr := f.Read(buf[:limit])
		if n > 0 {
			chunk := buf[:n]
			if _, wErr := scanner.Write(chunk); wErr != nil {
				return fmt.Errorf("scan %s: %w", path, wErr)
			}
			read += int64(n)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("read %s: %w", path, readErr)
		}
	}
	scanner.Flush()
	return nil
}

// Finalize sorts and indexes a finished listing.
//
// The order has to be independent of how the evidence was gathered, because
// Finding.Line is an index into this list: an order that varied between runs
// would make the same finding report a different line each time, and two
// reports of the same file would stop being diffable. The sort key is
// (Offset, Source, Text) - byte order first, so the listing reads front to back.
// Structural evidence leads because it carries offset 0 while real evidence
// usually carries a positive offset, which puts "what the file is" before "what
// it says"; a string that genuinely starts at offset 0 interleaves with it, and
// that is fine. The comparator does not special-case the source, so exact
// (Offset, Source, Text) ties are broken by SliceStable's insertion order - the
// key is not total, but tied lines are byte-identical and interchangeable, so
// which one lands first cannot change a finding.
func (s *EvidenceSet) Finalize() {
	for i := range s.Lines {
		s.Lines[i].Index = 0
	}
	sort.SliceStable(s.Lines, func(i, j int) bool {
		if s.Lines[i].Offset != s.Lines[j].Offset {
			return s.Lines[i].Offset < s.Lines[j].Offset
		}
		if s.Lines[i].Source != s.Lines[j].Source {
			return s.Lines[i].Source < s.Lines[j].Source
		}
		return s.Lines[i].Text < s.Lines[j].Text
	})
	for i := range s.Lines {
		s.Lines[i].Index = i + 1
	}
}

// Render draws the listing as the numbered lines the Tier 2 prompt shows. The
// index it prints is EvidenceLine.Index, so a line the model names is a line the
// report can be searched for. It expects a set that has been through Finalize:
// Index is zero until then, so calling it earlier prints 0 for every line and
// disables the maxLines cutoff.
func (s *EvidenceSet) Render(maxLines int) string {
	var b strings.Builder
	for _, l := range s.Lines {
		if maxLines > 0 && l.Index > maxLines {
			fmt.Fprintf(&b, "... (%d more evidence line(s) not shown)\n", len(s.Lines)-maxLines)
			break
		}
		fmt.Fprintf(&b, "%d\t[%s] %s\n", l.Index, l.Source, l.Text)
	}
	return strings.TrimRight(b.String(), "\n")
}

// BinaryConfig bounds one binary scan. The zero value is not usable: a config
// with no limits would read a terabyte and hold every distinct string in it in
// memory, so callers go through DefaultBinaryConfig and the collector resolves
// any zero field back to the default rather than treating zero as "unlimited".
type BinaryConfig struct {
	// Enabled turns the binary channel on for an audit run. Off means the report
	// is byte-identical to the one produced before this channel existed, which
	// is what makes turning it off a rollback.
	Enabled bool
	// MinStringLen is the shortest printable run kept as evidence.
	MinStringLen int
	// MaxStringLen is how much of one run is kept before it is truncated.
	MaxStringLen int
	// MaxEvidenceLines caps distinct evidence lines per file.
	MaxEvidenceLines int
	// MaxStreamBytes bounds how much of one file the streaming pass reads.
	MaxStreamBytes int64
	// MaxFullScanBytes is the size above which a file is no longer streamed end to
	// end, and only its head and tail are read. The number is set from the corpus
	// this platform actually audits rather than from a guess: the largest file in
	// the example package that reaches a full pass is a 10.8 MiB protocol-2 pickle,
	// with .pyc files at 45-58 KiB and the MNIST blobs at ~10 MiB behind it. 64 MiB
	// leaves six times the headroom over the largest of them, so no file in that
	// corpus changes behaviour, and at the measured 338 MB/s it caps the work one
	// file can cost at about 190 ms.
	MaxFullScanBytes int64
	// HeadTailBytes is the window read from each end of a file above
	// MaxFullScanBytes. One mebibyte is what makes an appended payload visible: a
	// zip's directory and the pickle stapled after the last member are both within
	// it of one end or the other.
	HeadTailBytes int64
	// MaxSectionBytes bounds one ELF section read.
	MaxSectionBytes int64
	// MaxArchiveMembers bounds how many container members are examined.
	MaxArchiveMembers int
	// MaxArchiveMemberBytes bounds the bytes of the ELF/pickle members read whole
	// across one container: the container's own total decompressed size is not
	// bounded, because a member that is neither an ELF nor a pickle is classified
	// and skipped without being read into memory.
	MaxArchiveMemberBytes int64
	// MaxFindings caps findings across the whole binary pass.
	//
	// It is deliberately not the source scanner's cap. The two channels are capped
	// separately and the merge re-truncates neither, because a shared ceiling
	// couples them in the one direction that costs a model package: reaching a cap
	// sets Truncated, Truncated fails ProvesCleanScan, and a failed scan has the
	// package deleted. A shared 200 would let a source arm carrying 190 findings
	// and a binary arm carrying 20 push a package that used to import into that
	// state, and would choose which findings to drop by path order rather than by
	// importance. Nothing recorded comes near either cap - the highest finding
	// count in any stored report in this repository is 7 for one sample and 80 for
	// a whole 100-sample corpus - so the ceiling that protects the model is the
	// blocking, not the cap.
	//
	// 50 rather than 200 because the evidence families number ten
	// (NET_002/CMD_001/DYN_001/BIN_001/BIN_002/PKL_001/FIL_001/PER_001/ENV_001/
	// OBF_001): fifty findings is five instances of every family, far past the
	// point where another instance changes the verdict. Worst case LLM calls go
	// from 200 to 250, and only when both arms saturate - a state that already
	// blocks and deletes regardless of how many calls it costs.
	MaxFindings int
	// HighEntropyThreshold is the bits-per-byte above which a section or file is
	// called near-random. Compiled code sits near 6.0-6.5; 7.5 is far enough
	// above that a normal binary does not reach it and far enough below 8.0 that
	// a compressed or encrypted payload does.
	HighEntropyThreshold float64
	// SkipDirs is the directory-name skip set, shared in spirit with the source
	// scanner's. It is a field rather than a shared global so that a test can
	// state its own.
	SkipDirs map[string]bool
}

// DefaultBinaryConfig returns the configuration a deployment gets when it says
// nothing.
func DefaultBinaryConfig() BinaryConfig {
	return BinaryConfig{
		Enabled:               true,
		MinStringLen:          DefaultBinaryMinStringLen,
		MaxStringLen:          DefaultBinaryMaxStringLen,
		MaxEvidenceLines:      50000,
		MaxStreamBytes:        3 * 1024 * 1024 * 1024,
		MaxFullScanBytes:      64 * 1024 * 1024,
		HeadTailBytes:         1 << 20,
		MaxSectionBytes:       16 * 1024 * 1024,
		MaxArchiveMembers:     4096,
		MaxArchiveMemberBytes: 256 * 1024 * 1024,
		// Not DefaultConfig().MaxFindings: the two channels are capped
		// independently and the merge re-truncates neither. See the field comment.
		MaxFindings:          50,
		HighEntropyThreshold: 7.5,
		SkipDirs:             DefaultConfig().SkipDirs,
	}
}

// normalizeBinaryConfig resolves every zero field back to its default. It is
// what lets the collector treat a zero as "unset" instead of "unlimited", which
// for a memory bound is the difference between a limit and no limit at all.
func normalizeBinaryConfig(cfg BinaryConfig) BinaryConfig {
	def := DefaultBinaryConfig()
	if cfg.MinStringLen <= 0 {
		cfg.MinStringLen = def.MinStringLen
	}
	if cfg.MaxStringLen <= 0 {
		cfg.MaxStringLen = def.MaxStringLen
	}
	if cfg.MaxEvidenceLines <= 0 {
		cfg.MaxEvidenceLines = def.MaxEvidenceLines
	}
	if cfg.MaxStreamBytes <= 0 {
		cfg.MaxStreamBytes = def.MaxStreamBytes
	}
	if cfg.MaxFullScanBytes <= 0 {
		cfg.MaxFullScanBytes = def.MaxFullScanBytes
	}
	if cfg.HeadTailBytes <= 0 {
		cfg.HeadTailBytes = def.HeadTailBytes
	}
	if cfg.MaxSectionBytes <= 0 {
		cfg.MaxSectionBytes = def.MaxSectionBytes
	}
	if cfg.MaxArchiveMembers <= 0 {
		cfg.MaxArchiveMembers = def.MaxArchiveMembers
	}
	if cfg.MaxArchiveMemberBytes <= 0 {
		cfg.MaxArchiveMemberBytes = def.MaxArchiveMemberBytes
	}
	if cfg.MaxFindings <= 0 {
		cfg.MaxFindings = def.MaxFindings
	}
	if cfg.HighEntropyThreshold <= 0 {
		cfg.HighEntropyThreshold = def.HighEntropyThreshold
	}
	if cfg.SkipDirs == nil {
		cfg.SkipDirs = def.SkipDirs
	}
	return cfg
}

// isExecutableKind reports whether evidence from this kind can hide an executed
// payload when it is cut short.
//
// This is the whole of the asymmetry between the two bounding classes. An ELF, a
// pickle stream, a container that may hold either, and a compressed stream that
// may decompress to either, can all end in something that runs; a raw blob and a
// tensor archive cannot, on this platform, run at all. A bounded read of the
// first group is a scan that did not look; a bounded read of the second is a scan
// that looked at as much data as there was reason to.
func isExecutableKind(k BinaryKind) bool {
	switch k {
	case KindELF, KindPickle, KindArchive, KindCompressed:
		return true
	}
	return false
}

// evidenceError builds the set a failed extraction returns, so that the scanner
// has one shape to handle rather than two.
//
// Bound is left zeroed, which is only the right default if consumers consult Err
// before Bound: Structural is false here, so a reader that checked Bound first
// would see a failed extraction as a clean scan. Callers must treat Err as the
// first thing they look at.
func evidenceError(path string, kind BinaryKind, err error) *EvidenceSet {
	return &EvidenceSet{File: path, Kind: kind, seen: map[string]bool{}, Err: err}
}
