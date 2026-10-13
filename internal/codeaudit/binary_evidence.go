package codeaudit

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strings"

	"debug/elf"
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
	// Listing is set when the evidence listing hit its line cap, so distinct
	// lines were dropped rather than displayed. It does not withhold a verdict on
	// its own, but it is not display-only either: the dropped lines are matcher
	// input that no rule was shown, so the consumer decides by kind - the scanner
	// counts a capped listing on an executable format as a bounded executable
	// read, because there the dropped lines can be blocking evidence.
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
	// maxLines is the evidence line cap, resolved from the config by
	// newEvidenceSet so that add - which every extractor calls - can enforce it
	// without every caller carrying the config. newStringScanner sets it too,
	// which is idempotent and keeps the cap on a set built by hand for the string
	// path. Zero means unlimited, so a set built literally and handed to neither
	// is uncapped: evidenceError is the only such set on a real path, and it is
	// safe because a failed extraction has nothing appended to it. The test helper
	// newTestEvidence builds one as well and relies on the trivial volume.
	maxLines int
}

// newEvidenceSet builds the set for one file and resolves the config's line cap
// here, once. Every extraction path must come through this rather than filling
// the struct literally: a set built by hand leaves maxLines at zero, and add
// reads zero as "unlimited", so the one path that forgot would silently lose the
// per-file memory ceiling - which is exactly what the structured extractors,
// none of which touch the string scanner, would otherwise all do.
func newEvidenceSet(file string, kind BinaryKind, cfg BinaryConfig) *EvidenceSet {
	cfg = normalizeBinaryConfig(cfg)
	return &EvidenceSet{
		File:     file,
		Kind:     kind,
		seen:     map[string]bool{},
		maxLines: cfg.MaxEvidenceLines,
	}
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
// that one line was cut short at MaxStringLen. A listing never relabels a reason
// already recorded - it writes only when Reason is empty - while a structural
// reason does override one, because markStructural guards on Structural rather
// than on Reason. Among reasons of the same class the first wins.
//
// That precedence is not a claim that a listing bound is harmless. A dropped line
// is a line the matcher was never shown: add returns before appending it, so the
// listing is the matcher's input rather than a view of it. Whether this bound
// withholds a clean verdict is therefore a decision for the consumer, which knows
// the file's kind - the scanner counts it BoundedExecutable for a format that
// executes, where the dropped lines can be blocking evidence, and BoundedData
// otherwise.
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

// addStructured records evidence that names a property of the file rather than a
// byte range in it. Its offset is zero and stays zero: a section summary has no
// address, and inventing one would make BinaryOffset a field a reader cannot
// trust for the findings that carry it.
func (s *EvidenceSet) addStructured(src EvidenceSource, text string) {
	s.add(src, 0, text)
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
// This pass runs two scanners over the same reads: the string scanner, and the
// pickle interpreter when the file is claimed to be a pickle. The interpreter is
// gated on set.Kind because, unlike the string scanner, it commits to a parse -
// it would set a structural bound on any other format, and on an executable kind
// that bound blocks the import. A whole file is the one stream whose kind is the
// set's own, so the gate is decided here and handed over.
//
// The read loop itself is streamReaderEvidence's: this function owns the file
// handle and the size check, so the budget clamp is written once.
func streamEvidence(path string, set *EvidenceSet, cfg BinaryConfig, budget int64) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	// The cut is decided from the file's size rather than left to the probe byte
	// streamReaderEvidence uses, so that the reason can name both numbers. It is
	// recorded before the read, and markStructural keeps the first reason, so the
	// wording handed over below is only reached where the size check could not see
	// the cut at all.
	if info, statErr := f.Stat(); statErr == nil && budget > 0 && info.Size() > budget {
		set.markStructural(fmt.Sprintf("stream budget %d bytes reached (file is %d)", budget, info.Size()))
	}
	if err := streamReaderEvidence(f, set, cfg, budget,
		fmt.Sprintf("stream budget %d bytes reached", budget), set.Kind == KindPickle); err != nil {
		return fmt.Errorf("scan %s: %w", path, err)
	}
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

// reservedExcerptSources is the set of sources RenderExcerpt reserves ahead of
// the rest. Each names a property of the file's structure rather than of its
// content volume - how many sections it declares, how many libraries it names,
// how many container members it holds - so the number of reserved lines is
// bounded by the file's shape rather than by how much text it contains.
//
// The reservation takes priority, not merely a head start. When the reserved
// lines alone reach the budget the segment is structural-only and the remainder
// stays empty, so a file that declares enough structure can still crowd the
// symbols, strings and pickle targets out of the excerpt entirely.
//
// The reservation is what fixes the plain-prefix problem. Finalize
// sorts by (Offset, Source, Text) and every structured line carries offset 0, so
// within offset 0 the sort falls through to the source name and dynsym leads. A
// symbol-dense library therefore fills a short prefix with dynsym lines alone -
// a single libstdc++ has 189 undefined global dynamic symbols (SHN_UNDEF,
// STB_GLOBAL, matching how the extractor counts them), past any cap this prompt
// uses - and the model sees no section, entropy or DT_NEEDED evidence at all,
// though those are exactly what the prompt's rubric asks it to weigh.
var reservedExcerptSources = map[EvidenceSource]bool{
	SourceEntropy: true,
	SourceSection: true,
	SourceNeeded:  true,
	SourceNotice:  true,
}

// RenderExcerpt draws a bounded excerpt of the listing for the file-level binary
// prompt. It shows every reserved structural line first, then fills whatever
// budget remains with the other sources, both in the listing's index order.
//
// The excerpt is not a plain prefix: the reserved lines are emitted first and
// the remaining budget is then filled from the other sources, so the numbering
// comes out non-monotonic exactly when a shown non-reserved line sits earlier in
// the listing than a shown reserved line (when every shown reserved line already
// precedes every shown non-reserved one, both passes stay in order and the
// result is sorted). A symbol-dense file is the first shape, because its imports
// lead the listing: the fixture's 130 imports put its first reserved line at
// index 131, so the excerpt begins high and only later drops to 1, 2, 3, 4. A
// set with no reserved sources is likewise rendered in index order. The ordering
// is not an invariant and should not be "fixed" back into a prefix; what matters
// is that the index printed is EvidenceLine.Index, so a line the model names by
// number still resolves to the line the report carries. When the budget is
// smaller than the listing it appends an omission marker with the count of lines
// actually left out, so the model is told the listing is partial - which the
// prompt's rubric relies on. It
// expects a set that has been through Finalize: without it every Index is still
// zero, and the excerpt comes out well-formed but silently wrong - a bounded
// listing that numbers every line 0, indistinguishable from a correct excerpt -
// so a caller must not read it without Finalize. maxLines <= 0 means no bound.
func (s *EvidenceSet) RenderExcerpt(maxLines int) string {
	if maxLines <= 0 || maxLines > len(s.Lines) {
		maxLines = len(s.Lines)
	}
	shown := make([]EvidenceLine, 0, maxLines)
	// The structural sources come first. The cap is still honoured if the
	// reserved lines alone reach it, so the excerpt can never exceed maxLines
	// even for a file that declares more structure than the budget holds.
	for _, l := range s.Lines {
		if len(shown) >= maxLines {
			break
		}
		if reservedExcerptSources[l.Source] {
			shown = append(shown, l)
		}
	}
	// Fill the rest of the budget from the remaining sources in index order,
	// which is what gives dynsym, member, pickle and strings their share.
	for _, l := range s.Lines {
		if len(shown) >= maxLines {
			break
		}
		if reservedExcerptSources[l.Source] {
			continue
		}
		shown = append(shown, l)
	}

	var b strings.Builder
	for _, l := range shown {
		fmt.Fprintf(&b, "%d\t[%s] %s\n", l.Index, l.Source, l.Text)
	}
	if omitted := len(s.Lines) - len(shown); omitted > 0 {
		fmt.Fprintf(&b, "... (%d more evidence line(s) not shown)\n", omitted)
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
	// MaxArchiveMembers bounds how many container members are examined.
	MaxArchiveMembers int
	// MaxArchiveMemberBytes bounds the bytes of the ELF/pickle members read whole
	// across one container: the container's own total decompressed size is not
	// bounded, because a member that is neither an ELF nor a pickle is classified
	// from its head and skipped without being read whole.
	MaxArchiveMemberBytes int64
	// MaxFindings caps findings across the whole binary pass.
	//
	// It is deliberately not the source scanner's cap. The two channels are capped
	// separately and the merge re-truncates neither, because a shared ceiling
	// couples them in the one direction that costs a model package: reaching a cap
	// sets Truncated, Truncated fails ProvesCleanScan, and a failed scan refuses
	// the import. A shared 200 would let a source arm carrying 190 findings
	// and a binary arm carrying 20 push a package that used to import into that
	// state, and would choose which findings to drop by path order rather than by
	// importance. Nothing recorded comes near either cap - the highest finding
	// count in any stored report in this repository is 7 for one sample and 80 for
	// a whole 100-sample corpus - so the ceiling that protects the model is the
	// blocking, not the cap.
	//
	// 50 rather than 200 because the evidence families number ten
	// (NET_002/CMD_001/DYN_001/BIN_001/BIN_002/PKL_001/FIL_002/PER_002/ENV_002/
	// CMD_002): fifty findings is five instances of every family, far past the
	// point where another instance changes the verdict. Worst case LLM calls go
	// from 200 to 250, and only when both arms saturate - a state that already
	// blocks regardless of how many calls it costs.
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

// shannonEntropy returns the bits per byte of a byte histogram.
//
// It is computed from counts rather than from the bytes so that the same
// function serves a buffer held in memory and a stream counted as it is read.
// A total of zero returns zero: an empty section has no entropy to speak of, and
// the alternative is a NaN that would compare false against every threshold and
// be silently dropped.
func shannonEntropy(counts [256]int64, total int64) float64 {
	if total <= 0 {
		return 0
	}
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / float64(total)
		h -= p * math.Log2(p)
	}
	return h
}

// measureEntropy is shannonEntropy over a buffer in memory, for the cases where
// the bytes are already in hand - a container member is the one that matters
// here. ELF sections do not use it: they are streamed through countSection in
// fixed chunks so that a section that declares a gigabyte cannot make this pass
// hold a gigabyte (see countSection), and both paths meet again in
// entropyVerdictFromCounts.
func measureEntropy(data []byte) float64 {
	var counts [256]int64
	for _, b := range data {
		counts[b]++
	}
	return shannonEntropy(counts, int64(len(data)))
}

// entropyVerdictFromCounts renders a section's entropy as evidence, or reports
// that there is nothing to say. It is the whole of the decision, over a
// histogram rather than over bytes.
//
// It is called for executable sections only, and that restriction is the whole
// design: code is not random, so a section that holds instructions and measures
// near eight bits per byte has been compressed or encrypted and something must
// unpack it before it can run. Data is allowed to be random - a tensor blob and
// an encrypted payload look identical to this measurement - so measuring data
// would produce a finding per model file and none of them would mean anything.
//
// Only a high reading produces a line. Emitting one for every low reading would
// put a line per section per file into every prompt for no decision value, and
// the rule table matches on the "high-entropy-" prefix - so the threshold is
// applied here, where the number is, and the rule table carries only what to call
// it. That split is deliberate: severity is policy and lives in the rule table,
// the measurement is physics and lives here.
//
// Two callers reach it and they hold their bytes differently: an ELF section
// streams through countSection in fixed-size chunks and never holds the section
// at all, while a container member is already in memory. Folding both into one
// function over the histogram is what keeps them from disagreeing - if the
// threshold lived on the in-memory path as well, the two would be two
// implementations of one rule and a later edit to either would silently make an
// identical section score differently depending on which path read it.
//
// total is passed rather than summed from the counts because it is the number of
// bytes actually read, which is the byte count the entropy is normalized by, and
// because shannonEntropy already refuses a zero total (see its comment): an empty
// section returns 0, which is below every threshold, so it produces no line.
func entropyVerdictFromCounts(section string, counts [256]int64, total int64, cfg BinaryConfig) (string, bool) {
	h := shannonEntropy(counts, total)
	if h <= cfg.HighEntropyThreshold {
		return "", false
	}
	return fmt.Sprintf("high-entropy-executable-section %s %.2f", section, h), true
}

// entropyVerdict is the in-memory spelling of the same decision, for the cases
// where the bytes are already in hand (a container member). It builds the
// histogram and hands it to entropyVerdictFromCounts so that a section measured
// in memory and the same section measured by streaming cannot differ.
func entropyVerdict(section string, data []byte, cfg BinaryConfig) (string, bool) {
	var counts [256]int64
	for _, b := range data {
		counts[b]++
	}
	return entropyVerdictFromCounts(section, counts, int64(len(data)), cfg)
}

// entropyChunkBytes is the read size countSection uses. It is a constant rather
// than a configuration field because it is not a limit: memory is one buffer of
// this size no matter what it is set to, so making it tunable would offer an
// operator a knob whose only effect is cache behaviour. 64 KiB is a size the
// kernel and the read paths are already tuned for.
const entropyChunkBytes = 64 * 1024

// symbolTableIsEmpty reports whether a symbol section would hand debug/elf's
// symbol reader an empty buffer, which is the one input that reader panics on
// instead of returning an error. Its getSymbols64 rejects a length that is not a
// multiple of its entry size and then slices off the first entry unconditionally,
// and zero is a multiple of every entry size. So a length of 1..entrySize-1 is
// an error that fails the scan closed and has to be left to the reader, while an
// empty buffer has to be caught here.
//
// It reads the section through Section.Data, the call the reader itself makes,
// rather than checking a size in the header, because the header size is not the
// whole story. Section.Data opens the section first, and opening a section named
// ".zdebug..." whose body begins with "ZLIB" rewrites Section.Size from eight
// bytes the file chooses, so a section whose on-disk sh_size looks ordinary can
// still yield nothing. Reading the data is the check that covers both routes,
// and it is also the safe direction: Data returns an error where the symbol
// reader would panic.
func symbolTableIsEmpty(sec *elf.Section) (bool, error) {
	data, err := sec.Data()
	if err != nil {
		return false, err
	}
	return len(data) == 0, nil
}

// collectELF reads a file's ELF structure into evidence.
func collectELF(path string, set *EvidenceSet, cfg BinaryConfig) error {
	// Resolve a zero config before it reaches streamWithSizeSwitch: that switch
	// reads cfg.MaxFullScanBytes, and a zero there would read every non-empty file
	// as above a 0-byte budget and window it. collectELFReader normalizes for the
	// structural pass, but the stream pass runs first and is bounded from here.
	cfg = normalizeBinaryConfig(cfg)
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	// The stream pass and the structural pass are separate on purpose: the
	// stream pass reads the file front to back for literals, and the structural
	// pass seeks. Sharing one handle between them would make the structural
	// parse depend on where the stream pass happened to stop.
	//
	// Through streamWithSizeSwitch rather than streamEvidence directly, so that a
	// large shared object is windowed at its ends like any other large blob
	// instead of being streamed whole.
	if err := streamWithSizeSwitch(path, set, cfg); err != nil {
		return err
	}
	return collectELFReader(f, set, cfg, path)
}

// collectELFReader is the ELF parse itself, over any random-access reader. It is
// separate from collectELF so that a container member - which is a stream, not a
// path - is parsed by the same code rather than by a second implementation that
// would drift from this one.
//
// It carries the whole of Task 5's body: the sectionless structural bound, the
// .dynsym walk and its too-short-section guard, the per-section summary lines,
// and the streamed entropy pass through countSection and entropyVerdictFromCounts.
// All of that reads through io.ReaderAt already - debug/elf takes one, and
// elf.Section.Open returns an io.Reader - so the move changes nothing but the
// parameter that names the file in messages.
//
// Task 5's `cfg = normalizeBinaryConfig(cfg)` moves here with the body, and it
// has to stay here rather than in the wrapper: collectELFMember reaches this
// parse directly, so normalizing only on the path side would leave every
// container member parsed against a config nobody resolved.
//
// There is no size parameter: the parse bounds itself per file through
// cfg.MaxStreamBytes, applied as the budget countSection stops at, and a size
// the body never read would be a parameter that only invites the assumption that
// something is bounds-checked elsewhere.
func collectELFReader(r io.ReaderAt, set *EvidenceSet, cfg BinaryConfig, name string) error {
	// Normalize first, like every other collector. A zero-valued BinaryConfig is
	// the shape a caller that only knows about one field passes, and leaving it
	// raw is not neutral here: MaxStreamBytes of 0 makes the per-file budget spent
	// before the first section, so every executable section records a structural
	// "0-byte budget was spent" bound and the import is refused, and a
	// HighEntropyThreshold of 0 flags every non-uniform section as packed. The
	// zero value means "use the defaults", so it is resolved to them up front.
	cfg = normalizeBinaryConfig(cfg)

	ef, err := elf.NewFile(r)
	if err != nil {
		// A file with ELF magic that will not parse is a file this scan did not
		// read. Returning the error is what turns it into an incomplete scan
		// rather than a clean one.
		return fmt.Errorf("parse elf %s: %w", name, err)
	}
	defer ef.Close()

	// A file with no section header table is a structural gap, and this check is
	// the removal of a fail-open rather than a nicety. The packing detector's
	// input is the executable sections; with no section table there are none to
	// measure, so the file used to fall through the section loop, produce no
	// entropy line and no bound, and pass as clean - a pass that says "no packing
	// found" about a file that was never examined for packing. The input most
	// likely to have no section table is one whose section table was deliberately
	// removed, which is exactly the file this detector exists for.
	//
	// The reason names the real condition. It is not "no symbol table": a
	// sectionless file has no .dynsym, but so does a stripped one, and a stripped
	// binary is ordinary and must not be treated this way. What is absent is the
	// section header table, and that is what the evidence says.
	if len(ef.Sections) == 0 {
		set.markStructural("no section header table: the executable-section entropy pass had nothing to measure")
	}

	// The interpreter and the soname are notices rather than measurements: they
	// say what kind of object this is, and a reader comparing two reports uses
	// them to tell a program from a library.
	for _, p := range ef.Progs {
		if p.Type != elf.PT_INTERP {
			continue
		}
		// The interpreter is a NUL-terminated path, and PT_INTERP is tiny by
		// construction; the limit is here so that a malformed file claiming a
		// gigabyte program header cannot make this read one.
		data, readErr := io.ReadAll(io.LimitReader(p.Open(), 4096))
		if readErr != nil {
			break
		}
		set.addStructured(SourceNotice, "interpreter "+strings.TrimRight(string(data), "\x00"))
	}
	if names, err := ef.DynString(elf.DT_SONAME); err == nil {
		for _, n := range names {
			set.addStructured(SourceSection, "soname "+n)
		}
	}
	if libs, err := ef.ImportedLibraries(); err == nil {
		for _, n := range libs {
			set.addStructured(SourceNeeded, n)
		}
	}

	// DynamicSymbols rather than ImportedSymbols: the latter drops the symbol's
	// value and section, and the section is what separates an import (SHN_UNDEF)
	// from a definition. Only imports are evidence of what the binary can call.
	//
	// SHT_SYMTAB is deliberately not read as a fallback, and the notice below is
	// worded to say only what was observed rather than to guess. A static binary
	// has no .dynsym but does carry .symtab, so a "stripped or static" notice was
	// false for it; and .symtab's entries are mostly this file's own defined
	// symbols, so using it as a capability source would mean matching the
	// program's own identifiers - the same false-positive class the free-string
	// families were demoted for. Task 8's rule table is unchanged by this: no new
	// evidence source is introduced, which is the point.
	//
	// The read is guarded rather than attempted and recovered, because
	// debug/elf's symbol reader panics instead of returning an error on one
	// input, and that input is reachable from an untrusted file: ClassifyBinary
	// returns KindELF on the four magic bytes alone, so every size and name the
	// reader acts on is a field the file itself chooses. symbolTableIsEmpty
	// probes exactly that input. A table that yields no bytes holds no symbols,
	// so skipping it reads as "imports nothing" - the fact a zero-entry table
	// reports - and raises no bound, because nothing was left unexamined.
	dynsym := ef.SectionByType(elf.SHT_DYNSYM)
	switch {
	case dynsym == nil:
		set.addStructured(SourceNotice, "no dynamic symbol table (SHT_DYNSYM absent)")
	default:
		empty, derr := symbolTableIsEmpty(dynsym)
		if derr != nil {
			return fmt.Errorf("read dynamic symbols of %s: %w", name, derr)
		}
		if empty {
			// The panic shape: an empty buffer. The section is held back, which
			// reports no symbols. Calling a present table "absent" would be a
			// false statement, so no notice is added either.
			break
		}
		syms, err := ef.DynamicSymbols()
		if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
			return fmt.Errorf("read dynamic symbols of %s: %w", name, err)
		}
		if errors.Is(err, elf.ErrNoSymbols) {
			set.addStructured(SourceNotice, "no dynamic symbol table (SHT_DYNSYM absent)")
		}
		for _, s := range syms {
			if s.Section != elf.SHN_UNDEF || elf.ST_BIND(s.Info) != elf.STB_GLOBAL {
				continue
			}
			set.addStructured(SourceDynsym, s.Name)
		}
	}

	// The per-file read budget for this parse, spent across all the sections
	// rather than reset for each one. A budget per section would make the cost of
	// a file scale with how many executable sections it declares, and a file can
	// declare as many as it likes - the same unbounded-work shape the streaming
	// pass's budget exists to stop, reintroduced through the section headers.
	budget := cfg.MaxStreamBytes
	for _, sec := range ef.Sections {
		executable := sec.Flags&elf.SHF_EXECINSTR != 0
		// size= is the section header's declared size, not a count of bytes this
		// pass read. The two differ when the section claims more than the file
		// holds, and that case gets its own line below rather than being folded
		// into this one - a reader comparing size= against a shortfall they cannot
		// see would have no way to tell the claim from the read.
		set.addStructured(SourceSection, fmt.Sprintf("%s size=%d executable=%t", sec.Name, sec.Size, executable))
		if !executable || sec.Size == 0 {
			continue
		}
		if budget <= 0 {
			// Not a zero-budget read: countSection treats a non-positive budget as
			// "unlimited", which is right for a caller with no bound and wrong
			// here. The spend is what names the limit.
			set.markStructural(fmt.Sprintf("section %s not read: the %d-byte per-file budget was spent", sec.Name, cfg.MaxStreamBytes))
			continue
		}
		counts, read, readErr := countSection(sec.Open(), budget)
		budget -= read
		if readErr != nil {
			// A section that cannot be read is a gap in the evidence, not a
			// reason to abandon the file: the symbols already gathered are still
			// evidence, and the bound records the gap.
			set.markStructural(fmt.Sprintf("section %s unreadable: %v", sec.Name, readErr))
			continue
		}
		// The comparison is unsigned on purpose. sec.Size is a uint64, and for a
		// SHF_COMPRESSED section it is the compression header's ch_size, which
		// debug/elf copies into Section.Size without the int64 range check it
		// applies to sh_size. A crafted ch_size with the high bit set therefore
		// makes int64(sec.Size) negative, and a signed `read < int64(sec.Size)`
		// is false for every non-negative read - the section would score as read
		// in full and its entropy would be reported as clean. Comparing in the
		// declared type's domain keeps "declares more than was read" true for any
		// size the field can hold.
		if uint64(read) < sec.Size {
			// The section declares more bytes than were read. Two things produce
			// this and both are the same fact about the file: a sh_offset or
			// sh_size that runs past the end of it (the read stops at EOF), and a
			// per-file budget breach. Either way the entropy number would be over
			// a prefix, so it is not reported at all and the shortfall is the
			// evidence instead: a section that could not be read in full is not a
			// section that was measured, and for a format that executes,
			// "not measured" must not reach the report as "measured clean".
			set.markStructural(fmt.Sprintf("section %s declares %d bytes, %d readable", sec.Name, sec.Size, read))
			continue
		}
		if line, ok := entropyVerdictFromCounts(sec.Name, counts, read, cfg); ok {
			set.addStructured(SourceEntropy, line)
		}
	}
	return nil
}

// countSection streams one section through the entropy histogram in fixed-size
// chunks and returns the histogram, the number of bytes it read and any read
// error.
//
// It streams because a section header may declare any size and the section may
// be read whole: an earlier version read it with io.ReadAll under a per-section
// cap, and that cap fired on ordinary real libraries. Memory here is 256 counters
// and one chunk regardless of how large the section is, so the only cost that
// scales is the read itself, and the read is bounded per file by the budget the
// caller passes (MaxStreamBytes) rather than per section - a budget that only a
// file with gigabytes of executable sections can reach.
//
// It returns the count so the caller can compare it against the declared size:
// the histogram is over a prefix whenever the read stopped early, and a prefix is
// not something this function can tell the caller about on its own.
func countSection(r io.Reader, budget int64) (counts [256]int64, n int64, err error) {
	buf := make([]byte, entropyChunkBytes)
	for budget <= 0 || n < budget {
		// The read is clamped to what the budget has left, the same way
		// streamEvidence clamps its reads. Reading whole chunks and testing the
		// budget at the top of the loop lets a single chunk walk straight past a
		// budget smaller than it, which would both overshoot the byte count the
		// caller subtracts from its per-file budget and make the count depend on
		// the chunk size rather than on the budget.
		limit := len(buf)
		if budget > 0 && int64(limit) > budget-n {
			limit = int(budget - n)
		}
		read, readErr := r.Read(buf[:limit])
		for _, b := range buf[:read] {
			counts[b]++
		}
		n += int64(read)
		if readErr == io.EOF {
			return counts, n, nil
		}
		if readErr != nil {
			return counts, n, readErr
		}
	}
	return counts, n, nil
}

// The pickle interpreter walks an opcode stream as opcodes, not as bytes.
//
// A byte-pattern scanner cannot do this job. A pickle stream interleaves its
// opcodes with raw data payloads - string and byte operands hold arbitrary
// bytes, including 0x63 and newlines - so any scan that hunts for "GLOBAL
// followed by two newline-terminated runs" will eventually read a data byte as
// an opcode, desynchronise, and then either invent a target out of the data or
// skip over a real one. Measured on models/examples/Retina-DKD's net_001.pth,
// whose data.pkl is a 68362-byte protocol-2 stream with four genuine GLOBAL
// opcodes, that scanner reported 39 targets - two clean, one corrupted, and
// torch.LongStorage missing because a false-positive match at offset 150
// swallowed the 685 bytes containing it. The whole point of this channel is to
// catch "c posix\nsystem\n"; a target that lands where torch.LongStorage landed
// was being silently dropped.
//
// So the parser is an interpreter. It does not build objects and it does not
// need to: it needs to consume every opcode's operand at the right width so it
// never loses its place, and it needs to resolve two things - the two inline
// operands of GLOBAL and INST, and the top two stack items at STACK_GLOBAL. The
// memo table closes a documented evasion: a stream that MEMOIZEs a module name
// and fetches it back with BINGET has no target adjacent to STACK_GLOBAL, so no
// adjacency scan can see it, but the value is still on the stack when the opcode
// runs.

// pickOperand classifies how an opcode's operand is framed.
type pickOperand uint8

const (
	pickNone pickOperand = iota
	pickFixed1
	pickFixed2
	pickFixed4
	pickFixed8
	pickLine     // bytes through the next newline
	pickTwoLines // two of those, as GLOBAL and INST encode their operands
	pickCounted1 // 1-byte little-endian length, then that many payload bytes
	pickCounted4 // 4-byte little-endian length, then the payload
	pickCounted8 // 8-byte little-endian length, then the payload
)

// operandOf names the operand framing of one opcode, and reports whether the byte
// is an opcode at all.
//
// The table is the complete protocol 0-5 set, and completeness is load-bearing.
// Leaving an opcode out does not degrade a result - it desynchronises the parse at
// that byte and turns the rest of the stream into noise. A missed opcode is
// therefore worse than a missed target, and there is no opcode here that is safe
// to skip: the cost of each is one case, and the cost of a gap is a checkpoint
// that either loses its targets or blocks the import on a false structural bound.
func operandOf(op byte) (pickOperand, bool) {
	switch op {
	case 0x2e, 0x30, 0x31, 0x32, 0x4e, 0x51, 0x52, 0x61, 0x62,
		0x64, 0x65, 0x6c, 0x6f, 0x73, 0x74, 0x75, 0x7d, 0x5d, 0x29,
		0x81, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8f, 0x90, 0x91, 0x92,
		0x93, 0x94, 0x97, 0x98, 0x28:
		// STOP POP POP_MARK DUP NONE BINPERSID REDUCE APPEND BUILD DICT
		// APPENDS LIST OBJ SETITEM TUPLE SETITEMS EMPTY_DICT EMPTY_LIST
		// EMPTY_TUPLE MARK NEWOBJ TUPLE1..3 NEWTRUE NEWFALSE EMPTY_SET
		// ADDITEMS FROZENSET NEWOBJ_EX STACK_GLOBAL MEMOIZE NEXT_BUFFER
		// READONLY_BUFFER: no operand, so the next byte is an opcode.
		return pickNone, true
	case 0x4a, 0x6a, 0x72, 0x84:
		return pickFixed4, true // BININT LONG_BINGET LONG_BINPUT EXT4
	case 0x47, 0x95:
		// BINFLOAT, and FRAME: FRAME's 8-byte operand is a length hint for the
		// bytes that follow it, not a body FRAME consumes, so it is read and
		// discarded like any other fixed operand.
		return pickFixed8, true
	case 0x4b, 0x82, 0x71, 0x68, 0x80:
		return pickFixed1, true // BININT1 EXT1 BINPUT BINGET PROTO
	case 0x4d, 0x83:
		return pickFixed2, true // BININT2 EXT2
	case 0x46, 0x49, 0x4c, 0x50, 0x53, 0x56, 0x67, 0x70:
		return pickLine, true // FLOAT INT LONG PERSID STRING UNICODE GET PUT
	case 0x63, 0x69:
		return pickTwoLines, true // GLOBAL, INST: module \n name \n
	case 0x55, 0x43, 0x8a, 0x8c:
		return pickCounted1, true // SHORT_BINSTRING SHORT_BINBYTES LONG1 SHORT_BINUNICODE
	case 0x54, 0x58, 0x42, 0x8b:
		return pickCounted4, true // BINSTRING BINUNICODE BINBYTES LONG4
	case 0x8d, 0x8e, 0x96:
		return pickCounted8, true // BINUNICODE8 BINBYTES8 BYTEARRAY8
	}
	return pickNone, false
}

// pickPhase is the interpreter's position within the opcode in progress. It is
// state that crosses Write calls, which is what a chunk-boundary-safe parser
// needs instead of the byte window the pattern scanner carried.
type pickPhase uint8

const (
	pickPhaseOp pickPhase = iota
	pickPhaseFixed
	pickPhaseLine
	pickPhasePayload
)

// pickleMaxOperandBytes bounds one operand the interpreter will hold. A module or
// attribute name beyond this is not a name any rule or reader can act on, so the
// bytes are consumed - the parse must stay in step - but not kept. The value
// becomes unresolved, and if it is later used as a target's module or name that
// is a structural bound rather than a silence: we did not read it, so we will not
// claim to have looked.
const pickleMaxOperandBytes = 64 * 1024

// pickleMaxStackSlots bounds the value stack. A pickle legitimately holds many
// slots at once: a mapping is written as MARK, then every key and value, then a
// single SETITEMS, so a dict of n entries occupies about 2n slots before any of
// them is popped. The deepest stack reached by any checkpoint in this repository
// is 1007 slots, on a cifar-10 batch whose own array data is truncated at 11.3
// MiB; the deepest complete one, a Retina-DKD net, reaches 826, and a full
// mnist/cifar model reaches 271. 1<<20 is about a thousand times the deepest
// measured and covers a mapping of some half a million entries, far past the tens
// of thousands a real state dict holds. The bound is memory, not correctness: at
// the 24-byte size of a pickSlot, 1<<20 slots is 24 MiB, where the unbounded stack
// a flood of operand-free opcodes would otherwise reach is gigabytes (4 MiB of
// NONE alone grows it to 4.2M slots, about 100 MiB).
const pickleMaxStackSlots = 1 << 20

// pickleMaxMemoSlots bounds the memo table. Every object a stream memoizes costs
// one entry, and torch.save memoizes each tensor and its storage, so the count
// tracks the model's size: the largest measured here is 3669, on the same
// Retina-DKD net, and a small mnist model reaches 159. 1<<20 is about 280 times
// that, enough headroom for a model two orders of magnitude larger. Like the stack
// cap this is a memory bound - a stream that MEMOIZEs on every byte would
// otherwise grow the map without limit - and the map, at roughly 64 bytes an
// entry, is the larger of the two allocations.
const pickleMaxMemoSlots = 1 << 20

// pickSlot is one value-stack or memo entry.
//
// Only string-ness and the string itself are kept. The interpreter never has to
// know what an object is; it has to know whether the top two slots at
// STACK_GLOBAL are module and name strings, and which strings they are.
// unresolved marks a value whose bytes were not kept - an operand past the cap, or
// a memo index never written - so that a target formed from it is refused rather
// than guessed.
type pickSlot struct {
	mark       bool
	str        bool
	unresolved bool
	value      string
}

// pickleScanner finds the call targets in one pickle stream.
type pickleScanner struct {
	set *EvidenceSet

	// off is the absolute file offset of buf[0], so an evidence offset is the
	// opcode's offset in the file and not an offset in the current chunk.
	off int64
	// buf holds bytes received but not yet consumed. A counted operand larger
	// than pickleMaxOperandBytes is consumed without being stored, so buf stays
	// bounded by the cap plus one fixed operand.
	buf []byte

	phase     pickPhase
	op        byte
	opOff     int64
	linesLeft int
	arg       []byte
	need      int64
	sizing    bool
	keep      bool

	stack []pickSlot
	memo  map[int]pickSlot

	// stopped ends parsing; hitStop distinguishes the pickle's own STOP from an
	// abort, so the trailing-bytes notice is not emitted after an abort.
	stopped  bool
	hitStop  bool
	trailing int64
}

func newPickleScanner(set *EvidenceSet) *pickleScanner {
	return &pickleScanner{set: set, memo: map[int]pickSlot{}}
}

// Write implements io.Writer. All parse state - the phase, the operand in
// progress, the absolute offset - crosses calls, so the result does not depend on
// where the chunk boundaries fall; a boundary inside an operand and a boundary on
// an opcode are the same thing to this loop. step consumes the buffer down to an
// unfinished opcode and returns 0 only when there is nothing left to take, so no
// byte is skipped and none is consumed twice.
func (p *pickleScanner) Write(chunk []byte) (int, error) {
	if p.stopped {
		p.trailing += int64(len(chunk))
		return len(chunk), nil
	}
	p.buf = append(p.buf, chunk...)
	i := 0
	for i < len(p.buf) {
		n := p.step(p.buf[i:], p.off+int64(i))
		i += n
		if p.stopped {
			p.trailing += int64(len(p.buf) - i)
			i = len(p.buf)
			break
		}
		if n == 0 {
			break
		}
	}
	p.off += int64(i)
	p.buf = append(p.buf[:0], p.buf[i:]...)
	return len(chunk), nil
}

// Flush ends the stream. It is where the two completeness claims are made: a
// stream that did not reach STOP was not read to the end of its structure, and a
// stream that did has trailing bytes outside that structure - visible in a
// notice, but not a bound, because the unpickler stops at STOP too.
func (p *pickleScanner) Flush() {
	if !p.stopped {
		if p.off > 0 && p.phase != pickPhaseOp {
			p.set.markStructural(fmt.Sprintf("pickle stream ended mid-opcode at offset %d", p.off))
		} else if p.off > 0 {
			p.set.markStructural(fmt.Sprintf("pickle stream ended at offset %d without STOP", p.off))
		}
		return
	}
	if p.hitStop && p.trailing > 0 {
		p.set.add(SourceNotice, 0,
			fmt.Sprintf("%d byte(s) after the pickle STOP were not interpreted", p.trailing))
	}
}

// step takes as much of the opcode stream as b holds, and returns the number of
// bytes it consumed. It returns 0 only when it cannot consume anything - b is
// empty and the opcode in progress is incomplete - so the caller can tell
// "finished, keep these bytes for the next Write" from "made no progress".
//
// The loop exists for the one opcode that completes without consuming a byte: a
// counted operand whose declared length is zero is finished at the payload phase
// having read nothing, and returning 0 there would be read as "needs more input"
// even though the bytes it needs are already in b. A stream that hit that would
// have its tail stranded, and Flush would report a valid pickle as ending without
// STOP. So the zero-length completion falls through to the opcode phase with the
// same b and absOff - no byte was consumed, so both are unchanged - and the next
// opcode is taken in this same call.
//
// It reports the absolute offset of each opcode it executes because that, not the
// operand's offset, is what an evidence line carries.
func (p *pickleScanner) step(b []byte, absOff int64) int {
	for {
		switch p.phase {
		case pickPhaseOp:
			if len(b) == 0 {
				return 0
			}
			op := b[0]
			desc, ok := operandOf(op)
			if !ok {
				// We cannot know this byte's operand width, so we cannot know where
				// the next opcode begins. Guessing is what desynchronises; stopping
				// without a bound would let a later opcode hide, so the parse ends
				// here and the file is recorded as not fully read.
				p.set.markStructural(fmt.Sprintf("unknown pickle opcode 0x%02x at offset %d", op, absOff))
				p.stopped = true
				return 1
			}
			p.op = op
			p.opOff = absOff
			p.arg = p.arg[:0]
			p.keep = true
			p.sizing = false
			switch desc {
			case pickNone:
				p.exec(op)
				return 1
			case pickFixed1:
				p.phase, p.need = pickPhaseFixed, 1
			case pickFixed2:
				p.phase, p.need = pickPhaseFixed, 2
			case pickFixed4:
				p.phase, p.need = pickPhaseFixed, 4
			case pickFixed8:
				p.phase, p.need = pickPhaseFixed, 8
			case pickLine:
				p.phase, p.need, p.linesLeft = pickPhaseLine, -1, 1
			case pickTwoLines:
				p.phase, p.need, p.linesLeft = pickPhaseLine, -1, 2
			case pickCounted1:
				p.phase, p.need, p.sizing = pickPhaseFixed, 1, true
			case pickCounted4:
				p.phase, p.need, p.sizing = pickPhaseFixed, 4, true
			case pickCounted8:
				p.phase, p.need, p.sizing = pickPhaseFixed, 8, true
			}
			return 1

		case pickPhaseFixed:
			n := len(b)
			if int64(n) > p.need {
				n = int(p.need)
			}
			p.arg = append(p.arg, b[:n]...)
			p.need -= int64(n)
			if p.need > 0 {
				return n
			}
			if p.sizing {
				length := leUint(p.arg)
				p.arg = p.arg[:0]
				p.need = length
				p.phase = pickPhasePayload
				if length > pickleMaxOperandBytes {
					p.keep = false
				}
				return n
			}
			p.phase = pickPhaseOp
			p.exec(p.op)
			return n

		case pickPhaseLine:
			idx := bytes.IndexByte(b, '\n')
			if idx < 0 {
				p.appendArg(b)
				return len(b)
			}
			p.appendArg(b[:idx+1])
			p.linesLeft--
			if p.linesLeft > 0 {
				return idx + 1
			}
			p.phase = pickPhaseOp
			p.exec(p.op)
			return idx + 1

		case pickPhasePayload:
			n := len(b)
			if int64(n) > p.need {
				n = int(p.need)
			}
			if p.keep {
				p.arg = append(p.arg, b[:n]...)
			}
			p.need -= int64(n)
			if p.need > 0 {
				return n
			}
			p.phase = pickPhaseOp
			p.exec(p.op)
			if n == 0 {
				// A zero-length operand: the completion above consumed nothing, so
				// returning here would claim it needs more bytes and strand the
				// rest of b. Loop instead, with b and absOff unchanged, so the next
				// opcode is taken in this call.
				continue
			}
			return n
		}
	}
}

// appendArg keeps operand bytes up to the cap. Past the cap the value is dropped
// but the bytes are still consumed by the caller, so the parse stays in step.
func (p *pickleScanner) appendArg(b []byte) {
	if !p.keep {
		return
	}
	if len(p.arg)+len(b) > pickleMaxOperandBytes {
		p.keep = false
		p.arg = p.arg[:0]
		return
	}
	p.arg = append(p.arg, b...)
}

// leUint reads a little-endian unsigned length of len(b) bytes. The 8-byte case is
// clamped: an 8-byte length is attacker-controlled and can name a byte count past
// any real file, and an unclamped value would overflow the skip counter.
func leUint(b []byte) int64 {
	switch len(b) {
	case 1:
		return int64(b[0])
	case 2:
		return int64(binary.LittleEndian.Uint16(b))
	case 4:
		return int64(binary.LittleEndian.Uint32(b))
	case 8:
		v := binary.LittleEndian.Uint64(b)
		if v > 1<<62 {
			return 1 << 62
		}
		return int64(v)
	}
	return 0
}

func (p *pickleScanner) push(s pickSlot) {
	if len(p.stack) >= pickleMaxStackSlots {
		p.overflow(fmt.Sprintf("pickle value stack exceeded %d slots at offset %d", pickleMaxStackSlots, p.opOff))
		return
	}
	p.stack = append(p.stack, s)
}

// overflow records a bound the interpreter cannot continue past and ends the
// parse. A stream that reaches either cap is not behaving like a pickle - the real
// ones measured here stay three orders of magnitude below - so "the structure was
// not read" is the honest report, and it takes the fail-closed direction: on a
// pickle that is a structural bound, which withholds a clean-scan verdict rather
// than hiding whatever came after the point the interpreter stopped.
func (p *pickleScanner) overflow(reason string) {
	p.set.markStructural(reason)
	p.stopped = true
}

func (p *pickleScanner) pop(n int) {
	if n > len(p.stack) {
		n = len(p.stack)
	}
	p.stack = p.stack[:len(p.stack)-n]
}

// popToMark discards stack entries through the nearest mark. A missing mark is
// tolerated: it can only mis-shape the value stack, never the byte stream, and
// refusing here would block a file on a stack-model mistake - the one failure mode
// that would make the channel useless.
func (p *pickleScanner) popToMark() {
	for i := len(p.stack) - 1; i >= 0; i-- {
		if p.stack[i].mark {
			p.stack = p.stack[:i]
			return
		}
	}
	p.stack = p.stack[:0]
}

func (p *pickleScanner) top() (pickSlot, bool) {
	if len(p.stack) == 0 {
		return pickSlot{}, false
	}
	return p.stack[len(p.stack)-1], true
}

// exec applies one opcode's stack effect and resolves its target, if it names one.
func (p *pickleScanner) exec(op byte) {
	switch op {
	case 0x28: // MARK
		p.push(pickSlot{mark: true})
	case 0x30, 0x61, 0x62: // POP APPEND BUILD
		p.pop(1)
	case 0x73: // SETITEM
		p.pop(2)
	case 0x31, 0x65, 0x75, 0x90: // POP_MARK APPENDS SETITEMS ADDITEMS
		p.popToMark()
	case 0x64, 0x6c, 0x74, 0x6f, 0x91: // DICT LIST TUPLE OBJ FROZENSET
		p.popToMark()
		p.push(pickSlot{})
	case 0x69: // INST: module and name inline, then the args popped to the mark.
		// The protocol-0/1 spelling of "resolve this attribute", so it names a
		// target the same way GLOBAL does.
		p.recordTarget(p.opOff)
		p.popToMark()
		p.push(pickSlot{})
	case 0x32: // DUP
		if s, ok := p.top(); ok {
			p.push(s)
		}
	case 0x2e: // STOP
		p.stopped, p.hitStop = true, true
	case 0x80, 0x95: // PROTO, FRAME: operand read, nothing to apply
	case 0x4e, 0x88, 0x89, 0x7d, 0x5d, 0x29, 0x8f, 0x97:
		// NONE NEWTRUE NEWFALSE EMPTY_DICT EMPTY_LIST EMPTY_TUPLE EMPTY_SET
		// NEXT_BUFFER
		p.push(pickSlot{})
	case 0x98: // READONLY_BUFFER: rewrites the top, net stack effect zero
	case 0x46, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x47, 0x8a, 0x8b, 0x50:
		// FLOAT INT BININT BININT1 LONG BININT2 BINFLOAT LONG1 LONG4 PERSID
		p.push(pickSlot{})
	case 0x51: // BINPERSID: pops the persistent id the loader will resolve
		p.pop(1)
		p.push(pickSlot{})
	case 0x52, 0x81: // REDUCE, NEWOBJ
		p.pop(2)
		p.push(pickSlot{})
	case 0x92: // NEWOBJ_EX
		p.pop(3)
		p.push(pickSlot{})
	case 0x82, 0x83, 0x84: // EXT1 EXT2 EXT4
		// The callable comes from a process-global extension registry the stream
		// does not name, so there is no target to record.
		p.push(pickSlot{})
	case 0x85: // TUPLE1
		p.pop(1)
		p.push(pickSlot{})
	case 0x86: // TUPLE2
		p.pop(2)
		p.push(pickSlot{})
	case 0x87: // TUPLE3
		p.pop(3)
		p.push(pickSlot{})
	case 0x53, 0x56: // STRING, UNICODE: text operands
		p.push(pickSlot{str: p.keep, unresolved: !p.keep, value: string(bytes.TrimRight(p.arg, "\n"))})
	case 0x54, 0x55, 0x58, 0x8c, 0x8d, 0x42, 0x43, 0x8e, 0x96:
		// BINSTRING SHORT_BINSTRING BINUNICODE SHORT_BINUNICODE BINUNICODE8
		// BINBYTES SHORT_BINBYTES BINBYTES8 BYTEARRAY8. Byte operands are kept
		// string-like too: a module name spelled as bytes is not a valid
		// STACK_GLOBAL in CPython, so it cannot appear in a stream that runs, but
		// refusing to look at it would trade a false positive that cannot happen
		// for a blind spot that can.
		p.push(pickSlot{str: p.keep, unresolved: !p.keep, value: string(p.arg)})
	case 0x63: // GLOBAL: module and name inline
		if !p.keep {
			p.set.markStructural(fmt.Sprintf(
				"GLOBAL at offset %d has an operand past the %d-byte cap", p.opOff, pickleMaxOperandBytes))
		}
		p.recordTarget(p.opOff)
		p.push(pickSlot{})
	case 0x68, 0x6a, 0x67: // BINGET LONG_BINGET GET
		var idx int
		if op == 0x67 {
			idx = atoiSafe(string(bytes.TrimRight(p.arg, "\n")))
		} else {
			idx = int(leUint(p.arg))
		}
		if s, ok := p.memo[idx]; ok {
			p.push(s)
			return
		}
		// A memo index the stream never wrote cannot be resolved. Whether that
		// matters is decided where the value is used, not here: pushing unresolved
		// and bounding only if STACK_GLOBAL consumes it keeps a bound off streams
		// where the reference is harmless.
		p.push(pickSlot{unresolved: true})
	case 0x71, 0x72, 0x70, 0x94: // BINPUT LONG_BINPUT PUT MEMOIZE
		var idx int
		switch op {
		case 0x70:
			idx = atoiSafe(string(bytes.TrimRight(p.arg, "\n")))
		case 0x94:
			// MEMOIZE stores at len(memo), matching CPython's dict-length rule so
			// that a stream mixing explicit PUT with MEMOIZE indexes the same
			// slots the unpickler would.
			idx = len(p.memo)
		default:
			idx = int(leUint(p.arg))
		}
		if len(p.memo) >= pickleMaxMemoSlots {
			p.overflow(fmt.Sprintf("pickle memo exceeded %d entries at offset %d", pickleMaxMemoSlots, p.opOff))
			return
		}
		if s, ok := p.top(); ok {
			p.memo[idx] = s
		} else {
			p.memo[idx] = pickSlot{}
		}
	case 0x93: // STACK_GLOBAL: the top two strings are the module and the name
		if len(p.stack) < 2 {
			p.push(pickSlot{})
			return
		}
		name := p.stack[len(p.stack)-1]
		mod := p.stack[len(p.stack)-2]
		p.pop(2)
		if mod.unresolved || name.unresolved {
			// The stream asked to resolve a target we could not name. Silence here
			// is the one thing not allowed: it would be a target we did not read
			// while reporting the file as read.
			p.set.markStructural(fmt.Sprintf(
				"STACK_GLOBAL at offset %d reads an operand the interpreter could not resolve", p.opOff))
			p.push(pickSlot{})
			return
		}
		if mod.str && name.str {
			p.emit(mod.value, name.value, p.opOff)
		}
		p.push(pickSlot{})
	}
}

// recordTarget emits the module.name pair a GLOBAL or INST operand carries. The
// operand bytes are "module\nname\n", both segments newline-terminated, which is
// why they are read as a pair and not as two independent strings.
func (p *pickleScanner) recordTarget(off int64) {
	if !p.keep {
		return
	}
	i := bytes.IndexByte(p.arg, '\n')
	if i < 0 {
		return
	}
	rest := p.arg[i+1:]
	j := bytes.IndexByte(rest, '\n')
	if j < 0 {
		return
	}
	mod, name := string(p.arg[:i]), string(rest[:j])
	if mod == "" || name == "" {
		return
	}
	p.emit(mod, name, off)
}

// emit records one target. It goes through add so that the cap and the
// (source, text) deduplication are the set's, not this scanner's: a checkpoint
// that rebuilds ten thousand tensors names the same rebuilder ten thousand times,
// and the listing needs it once.
func (p *pickleScanner) emit(mod, name string, off int64) {
	p.set.add(SourcePickle, off, mod+"."+name)
}

// atoiSafe parses the decimal text operand GET and PUT carry. It stops at the
// first non-digit rather than failing: the operand is already the right shape (a
// line the caller could not mis-parse), and a malformed index can only address a
// memo slot that does not exist, which is the dangling-reference case handled
// above.
func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// streamWithSizeSwitch streams a file end to end when it is small enough to be
// worth it, and reads only its head and tail when it is not.
//
// The switch exists because the two costs are not comparable. A full pass costs
// about 3 microseconds per kibibyte at the measured rate, which is nothing for
// the 10.8 MiB pickle that is the largest such file in the example package and
// nine seconds for a 3 GiB shard. Above MaxFullScanBytes the pass is replaced by
// a HeadTailBytes window at each end.
//
// Skipping the middle is recorded, and how it is recorded is isExecutableKind's
// existing asymmetry rather than a new rule: a windowed pickle or ELF leaves a
// region of an executable format unread, so it is a structural bound and a clean
// verdict is withheld; a windowed tensor blob is a data bound and is only
// reported. Without the first half the threshold would be an evasion: padding a
// pickle past 64 MiB would hide a mid-stream GLOBAL and still pass.
//
// What that gives up is stated in the plan's boundary section rather than hidden
// here: for a raw blob the middle is tensor data no loader reads, so nothing
// reachable is lost. For a pickle it is a real loss - a GLOBAL emitted in the
// middle of a long data-building run would be missed - and the two windows are
// the mitigation rather than a cure, covering the load-time call at the front and
// the post-load action at the back. A deployment whose packages contain such a
// file raises maxFullScanBytes rather than being silently exempted.
func streamWithSizeSwitch(path string, set *EvidenceSet, cfg BinaryConfig) error {
	if set.Size > cfg.MaxFullScanBytes {
		// The bound is recorded only when the two windows actually leave a middle
		// unread. On size alone it would fire for a file the windows cover end to
		// end, and the reason below would say "only the head and tail were read"
		// about a file that was read whole - which the report then carries into a
		// refusal, since a structural bound on an executable kind withholds the
		// pass. Reachable as soon as a deployment lowers MaxFullScanBytes below
		// twice HeadTailBytes, and the configuration exposes that knob.
		if set.Size > 2*cfg.HeadTailBytes {
			set.markStructural(fmt.Sprintf("file is %d bytes, above MaxFullScanBytes %d: only the head and tail %d bytes were read",
				set.Size, cfg.MaxFullScanBytes, cfg.HeadTailBytes))
		}
		return streamHeadAndTail(path, set, cfg)
	}
	return streamEvidence(path, set, cfg, cfg.MaxStreamBytes)
}

// streamHeadAndTail runs the byte extractors over the first and last
// HeadTailBytes of a file.
//
// It is what makes an appended payload visible. A zip's directory lives at the
// end of the file and describes only the members before it, so a payload stapled
// after the last member is inside no member and would otherwise be read by
// nothing; the same reasoning covers a section appended past an ELF's last
// section header.
//
// The window size is a parameter rather than a constant because two callers want
// different ones: a container always reads its two ends, while a large blob reads
// its ends only because it was too large to read whole.
//
// The pickle interpreter is gated here the same way it is gated everywhere else:
// it runs only when set.Kind is KindPickle, and only over the head window. That
// gating is what keeps this path from being a bound on every archive - a zip's own
// bytes are not an opcode stream, and KindArchive is an executable kind, so an
// ungated interpreter would set Bound.Structural on every .pt and .whl. The head
// window is a valid prefix of the opcode stream and can be parsed; the tail window
// is a splice out of the middle, and feeding a spliced fragment to a stateful
// parser would make it read the splice as a continuation and invent targets out of
// data bytes, so the tail goes to the strings pass alone. Nothing is lost by that:
// this path is only reached above MaxFullScanBytes, where the file is already
// recorded as structurally bounded.
func streamHeadAndTail(path string, set *EvidenceSet, cfg BinaryConfig) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}

	headTailBytes := cfg.HeadTailBytes
	scanner := newStringScanner(set, cfg)
	var pickles *pickleScanner
	if set.Kind == KindPickle {
		pickles = newPickleScanner(set)
	}

	head := make([]byte, headTailBytes)
	n, err := f.ReadAt(head, 0)
	if err != nil && err != io.EOF {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if _, err := scanner.Write(head[:n]); err != nil {
		return err
	}
	if pickles != nil {
		if _, err := pickles.Write(head[:n]); err != nil {
			return err
		}
	}

	if info.Size() > headTailBytes {
		tail := make([]byte, headTailBytes)
		at := info.Size() - headTailBytes
		n, err := f.ReadAt(tail, at)
		if err != nil && err != io.EOF {
			return fmt.Errorf("read %s: %w", path, err)
		}
		// The offset is rebased so that a tail literal reports where it actually
		// is: an offset that silently restarted at zero would make two different
		// payloads report the same location. The interpreter is not rebased and not
		// fed the tail at all - see the note above.
		scanner.at = at
		if _, err := scanner.Write(tail[:n]); err != nil {
			return err
		}
	}
	scanner.Flush()
	if pickles != nil {
		pickles.Flush()
	}
	return nil
}

// collectArchive reads a zip-based container: PyTorch .pt, wheels, .npz, jars.
//
// Members are the subject, not the archive's own bytes, because that is where a
// container hides code: a .pt checkpoint is a zip whose data.pkl is a pickle
// stream, and a package can ship a shared object the same way. Every member is
// sniffed, and the ones that sniff as ELF or pickle are read with the same
// extractors used for a standalone file - one level deep, because a container
// inside a container is a nesting depth this version does not follow.
//
// A member that sniffs as an archive is skipped, and the skip is silent: it stays
// visible as a member line but does not set Bound. That is deliberate and its cost
// is named in the plan's boundary section (a checkpoint shipped only inside a zip
// never reaches its data.pkl), so it is not a hole to be plugged here by
// recursing, which would need its own depth and budget model.
//
// The decompressed-byte budget is shared across the archive rather than applied
// per member: a zip bomb is many small members, not one large one, so a per-member
// limit is a limit that does not bind.
func collectArchive(path string, set *EvidenceSet, cfg BinaryConfig) error {
	// Resolve a zero config to the defaults, as the other collectors do. A zero
	// MaxArchiveMembers would read as "no member is allowed" and bound every
	// archive on its first member - wrong, and fail-closed, but wrong.
	cfg = normalizeBinaryConfig(cfg)
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}

	zr, err := zip.NewReader(f, info.Size())
	if err != nil {
		// A file with zip magic that will not open is a container this scan did
		// not look inside - a failed look, not a bounded one, so the error is
		// returned rather than marked structural. That distinction is load-bearing
		// downstream: CollectEvidence records it as set.Err, and the scanner counts
		// set.Err as Incomplete rather than passing the file off as examined. A
		// markStructural here would have said "read, with a gap" about a file that
		// was never read at all.
		return fmt.Errorf("open archive %s: %w", path, err)
	}

	var decompressed int64
	for i, member := range zr.File {
		if i >= cfg.MaxArchiveMembers {
			set.markStructural(fmt.Sprintf("member ceiling %d reached (%d member(s))", cfg.MaxArchiveMembers, len(zr.File)))
			break
		}
		set.addStructured(SourceMember, fmt.Sprintf("%s size=%d", member.Name, member.UncompressedSize64))

		if member.FileInfo().IsDir() {
			continue
		}
		// The head is read for every member, including the ones that turn out to
		// be data: sniffing is what decides whether a member is worth reading in
		// full, and a member that is never sniffed is a member whose kind is
		// unknown.
		head, err := readMemberHead(member, sniffBytes)
		if err != nil {
			set.markStructural(fmt.Sprintf("member %s unreadable: %v", member.Name, err))
			continue
		}
		kind := ClassifyBinary(head, member.Name)
		if kind != KindELF && kind != KindPickle {
			continue
		}
		if decompressed+int64(member.UncompressedSize64) > cfg.MaxArchiveMemberBytes {
			set.markStructural(fmt.Sprintf("member byte budget %d reached at %s", cfg.MaxArchiveMemberBytes, member.Name))
			break
		}
		decompressed += int64(member.UncompressedSize64)

		switch kind {
		case KindELF:
			if err := collectELFMember(set, member, cfg); err != nil {
				// A member that cannot be read is a gap, recorded rather than
				// fatal: the members already read are still evidence.
				set.markStructural(fmt.Sprintf("member %s: %v", member.Name, err))
			}
		case KindPickle:
			if err := collectPickleMember(set, member, cfg); err != nil {
				set.markStructural(fmt.Sprintf("member %s: %v", member.Name, err))
			}
		}
	}
	return nil
}

// readMemberHead reads up to n bytes of a member without decompressing more than
// that. A member that declares more bytes than it delivers is fine here: sniffing
// needs the head only.
func readMemberHead(member *zip.File, n int) ([]byte, error) {
	rc, err := member.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	buf := make([]byte, n)
	read, err := io.ReadFull(rc, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	return buf[:read], nil
}

// collectELFMember runs the byte extractors and the ELF extractor over a
// container member.
//
// debug/elf needs random access and a member is a stream, so the member is
// materialised first, bounded by the archive's byte budget. That is the cost of
// reading a nested ELF at all, and it is why the budget above is checked before
// this is called rather than inside it.
func collectELFMember(set *EvidenceSet, member *zip.File, cfg BinaryConfig) error {
	rc, err := member.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	data, err := io.ReadAll(io.LimitReader(rc, cfg.MaxArchiveMemberBytes))
	if err != nil {
		return err
	}
	if int64(len(data)) >= cfg.MaxArchiveMemberBytes {
		set.markStructural(fmt.Sprintf("member %s truncated at the byte budget", member.Name))
	}

	// The strings pass runs over the member as well as the structural parse
	// below. Without this, an ELF nested in a .whl would be the one executable
	// format in the channel read without a strings pass - its sibling member
	// kinds already get one - and a nested ELF is precisely where a stapled
	// payload would be put. The bytes are already in memory, so the pass is a scan
	// over a slice rather than a second read.
	//
	// pickleScan is false, and it must stay false: this member was classified as
	// an ELF, and the interpreter commits to a parse, so running it here would set
	// Bound.Structural on an executable kind and block the import of every wheel
	// that ships a shared object.
	//
	// A zero budget means unlimited here: the read that filled data was the
	// bounded one, and bounding the scan of an already-bounded slice would only
	// lose the tail of it.
	if err := streamReaderEvidence(bytes.NewReader(data), set, cfg, 0, "", false); err != nil {
		return err
	}

	// The member is parsed out of memory, so it gets a reader rather than a
	// path. A temporary file would be the alternative, and it would put
	// attacker-controlled bytes on the filesystem of the auditing process for no
	// reason.
	return collectELFReader(bytes.NewReader(data), set, cfg, member.Name)
}

// streamReaderEvidence runs the byte extractors over a stream, stopping after
// budget bytes and recording the cut as a structural bound. A budget of zero or
// less means the stream is read to the end. The strings pass always runs; the
// pickle interpreter runs only when pickleScan is true.
//
// It is the only implementation of this loop, because the bound has to be
// enforced identically everywhere it applies: four call sites reach it - a whole
// file, a pickle member, an ELF member, and a decompressed gzip stream. The bound
// is what sets Bound.Structural, Bound.Structural is what withholds a clean
// verdict from a stream whose tail was never read, and a call site that enforced
// it slightly differently would be a hole in the fail-closed rule rather than a
// style difference.
//
// A whole file arrives through streamEvidence, which owns the handle and records
// the cut from the file's size before entering here; the probe byte below is what
// covers the sites that cannot know a size up front.
//
// pickleScan is a parameter rather than a read of set.Kind because a member's
// kind is the member's, not the set's: the set is the archive, and every member
// of an archive would otherwise be judged by the archive's kind. The caller
// already classified the member to decide to read it, so it is the caller that
// knows whether this stream is a claimed pickle. The gate exists because the
// interpreter commits to a parse: a byte it cannot classify as an opcode ends the
// parse with a structural bound, and a structural bound on an executable kind
// blocks the import - so an interpreter run over anything but a claimed pickle is
// a bound on a file that is not malformed at all.
//
// The budget is applied inside the read rather than between reads, for the same
// reason it is in streamEvidence: checking it at the top of the loop lets one 64
// KiB read walk past a much smaller budget. When the budget is spent, one probe
// byte decides whether it actually cut anything - a stream that ends exactly at
// the budget was read completely, and marking it bounded would fail a clean scan
// for no reason.
//
// bounded is the caller's wording for the cut, because the four sites name
// different budgets in their reasons.
func streamReaderEvidence(rc io.Reader, set *EvidenceSet, cfg BinaryConfig, budget int64, bounded string, pickleScan bool) error {
	scanner := newStringScanner(set, cfg)
	var pickles *pickleScanner
	if pickleScan {
		pickles = newPickleScanner(set)
	}

	var read int64
	buf := make([]byte, evidenceReadChunk)
	for {
		limit := len(buf)
		if budget > 0 && int64(limit) > budget-read {
			limit = int(budget - read)
		}
		if limit <= 0 {
			var probe [1]byte
			if n, err := rc.Read(probe[:]); n > 0 || (err != nil && err != io.EOF) {
				set.markStructural(bounded)
			}
			break
		}
		n, readErr := rc.Read(buf[:limit])
		if n > 0 {
			if _, err := scanner.Write(buf[:n]); err != nil {
				return err
			}
			if pickles != nil {
				if _, err := pickles.Write(buf[:n]); err != nil {
					return err
				}
			}
			read += int64(n)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	scanner.Flush()
	if pickles != nil {
		pickles.Flush()
	}
	return nil
}

// collectPickleMember runs the byte extractors over a pickle container member.
//
// pickleScan is true because the dispatcher classified this member as KindPickle
// before calling, and a claimed pickle is exactly the stream the interpreter is
// allowed to commit to.
func collectPickleMember(set *EvidenceSet, member *zip.File, cfg BinaryConfig) error {
	rc, err := member.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	return streamReaderEvidence(rc, set, cfg, cfg.MaxArchiveMemberBytes,
		fmt.Sprintf("member %s exceeds the byte budget", member.Name), true)
}

// collectCompressed reads a single-stream compressed file. Only the formats the
// standard library decompresses are opened; anything else is counted as a
// bounded data read by the dispatcher and named in a notice, because a
// decompressor written for this purpose would be a new parser on the import
// path with no evidence behind it.
func collectCompressed(path string, set *EvidenceSet, cfg BinaryConfig) error {
	// Resolve a zero config to the defaults, and this is the collector where it
	// matters most: streamReaderEvidence reads a budget of zero as "unlimited", so
	// an unresolved zero here would silently disable the decompression bound - the
	// one guard between a small .gz and an unbounded scan. That is fail-open in the
	// single direction this design refuses, rather than the merely-wrong fail-closed
	// a zero config produces elsewhere.
	cfg = normalizeBinaryConfig(cfg)
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	set.addStructured(SourceNotice, "gzip stream decompressed for evidence")

	zr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("open gzip %s: %w", path, err)
	}
	defer zr.Close()

	// The decompressed bytes are a second file with their own kind, and they are
	// the one place the pickle gate has to be decided by sniffing rather than by a
	// classification the caller already made. It matters that it is decided at
	// all: a gzip of a tar is the common case (models/audit/holdout-sources/sr.tgz
	// is one), its bytes are not an opcode stream, and running the interpreter over
	// them would set a structural bound on KindCompressed - which is executable -
	// and block the import of every .gz that is not itself a pickle.
	//
	// A buffered reader peeks the head and then hands the same bytes on, so the
	// sniff reads nothing twice and costs no second pass. The path argument to
	// isPickleStream is empty on purpose: the extension belongs to the compressed
	// file, not to what it expands to.
	br := bufio.NewReaderSize(zr, sniffBytes)
	head, _ := br.Peek(sniffBytes)
	pickleScan := isPickleStream(head, "")

	// The decompressed length is attacker-controlled, so the budget is what keeps
	// a small .gz from expanding into an unbounded scan - the same guard the
	// archive path uses, and enforced through the same helper so the two cannot
	// drift.
	if err := streamReaderEvidence(br, set, cfg, cfg.MaxArchiveMemberBytes,
		fmt.Sprintf("decompressed stream exceeds %d bytes", cfg.MaxArchiveMemberBytes), pickleScan); err != nil {
		return fmt.Errorf("read gzip %s: %w", path, err)
	}
	return nil
}

// CollectEvidence gathers the evidence for one file and returns it finalized.
//
// It is the only entry point: the kind is decided by the caller so that the
// classification happens once, against the same head bytes the caller already
// read to decide the file was binary at all. A second sniff here would be a
// second answer to one question.
//
// An error is recorded on the set rather than returned, because the caller's
// decision is not "abort" but "count this file as not examined" - and a file
// that was not examined has to reach the report, not stop it. Concretely: the
// scanner reads set.Err and increments BinaryScanSummary.Incomplete, which
// ProvesCleanScan refuses on. So a file whose extraction failed is counted
// Incomplete and withholds the pass; it is never silently skipped. The two must
// not be interchangeable - "skipped" means classify said the file is not binary,
// which is not a look that failed, while set.Err means the file is binary and
// this scan could not read it.
func CollectEvidence(path string, kind BinaryKind, cfg BinaryConfig) *EvidenceSet {
	cfg = normalizeBinaryConfig(cfg)
	set := newEvidenceSet(path, kind, cfg)

	if info, err := os.Stat(path); err == nil {
		set.Size = info.Size()
	}

	var err error
	switch kind {
	case KindELF:
		err = collectELF(path, set, cfg)
	case KindArchive:
		// The head and tail pass runs over the archive's own bytes as well as
		// its members. A payload appended after the last member is outside
		// everything the zip directory describes, and reading only the members
		// would leave exactly that region unexamined.
		//
		// No size switch here: this path is already the head and tail pass, and
		// the members behind it are bounded by MaxArchiveMemberBytes rather than
		// by the file's own size. A 200 MiB .zip and a 92 MiB .pth both take this
		// route today.
		err = streamHeadAndTail(path, set, cfg)
		if err == nil {
			err = collectArchive(path, set, cfg)
		}
	case KindCompressed:
		// Also no size switch: the stream was decompressed on purpose, and
		// skipping its middle would defeat the only reason to have opened it.
		// MaxArchiveMemberBytes is the bound that applies.
		err = collectCompressed(path, set, cfg)
	case KindNumpy, KindPickle, KindRaw:
		// No entropy verdict for these, deliberately. A raw blob is most of what
		// a model package is, and weights are near-random by nature: a whole-file
		// entropy rule would fire on every .safetensors ever exported and teach
		// the operator to ignore the family. It is also unnecessary here, because
		// nothing on this platform executes a raw blob - a payload that runs
		// arrives as an ELF or a pickle, and both carry precise evidence.
		err = streamWithSizeSwitch(path, set, cfg)
	default:
		return evidenceError(path, kind, fmt.Errorf("unsupported binary kind %q", kind))
	}

	if err != nil {
		set.Err = err
	}
	set.Finalize()
	return set
}
