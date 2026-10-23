package codeaudit

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// BinaryScanSummary is what one binary pass knows about its own completeness.
// Every field is a distinct way for the pass to have not looked, and the zero
// value says it looked everywhere - which is why each is incremented where the
// loss happens rather than inferred afterwards.
type BinaryScanSummary struct {
	// FilesCount is how many files the channel examined.
	FilesCount int `json:"files_count"`
	// Kinds is the per-kind file count, so a reader can see what the package was
	// made of without walking the findings.
	Kinds map[string]int `json:"kinds,omitempty"`
	// BoundedExecutable counts files whose evidence was cut short on a format that
	// can carry an executed payload: a structural extraction that stopped early, or
	// a capped listing whose dropped lines can be blocking evidence. A pass over
	// one of these is not evidence of absence, and ProvesCleanScan withholds it.
	BoundedExecutable int `json:"bounded_executable,omitempty"`
	// BoundedData counts files whose evidence was cut short on a format that is
	// data on this platform, by either bound. It is recorded because a reader
	// should see it, and it does not withhold a verdict: a bounded tensor blob
	// cannot run, and a capped listing on one can only have dropped free-string
	// lines, which no blocking family reads.
	BoundedData int `json:"bounded_data,omitempty"`
	// Incomplete counts paths the channel set out to examine and could not: a
	// file that would not open, a file whose extraction failed, and a subtree the
	// walk could not read. It is named for what the pass failed to see rather than
	// for the file count, because an unreadable directory is not a file and still
	// has to make the pass admit it looked at nothing.
	Incomplete int `json:"incomplete,omitempty"`
	// Errored records that the pass could not run at all - the walk failed before
	// it examined anything. It is a gap for the same reason Incomplete is: a pass
	// that did not happen is not evidence of absence, and the alternative (an
	// error out of the channel) would refuse the import through
	// internal/controller/import_processing.go:651-656 without the report ever
	// saying why.
	Errored bool `json:"errored,omitempty"`
	// FindingsCapped records that the finding cap dropped at least one finding.
	//
	// It is deliberately not the report's Truncated and is deliberately not folded
	// into it. Reaching the cap is a listing budget being spent, not a look that
	// did not happen, and the report's Truncated is one of the conditions
	// ProvesCleanScan refuses on - folding this into it would make the channel
	// refuse an import for having found too much. Only LOW findings are ever
	// dropped (see ScanDirectory), and LOW does not block under the gate
	// arbitration - MEDIUM does block, which is exactly why the cap keeps it -
	// so nothing the cap drops could have blocked the import.
	FindingsCapped bool `json:"findings_capped,omitempty"`
	// FindingsDropped is how many LOW findings the cap dropped, so the count
	// travels with the flag rather than being re-derived from a list that no
	// longer has them.
	FindingsDropped int `json:"findings_dropped,omitempty"`
	// MaxFindings is the listing budget this pass ran under, carried into the
	// report so that a reader who sees findings_capped can tell what it was capped
	// at without re-reading the scanner's configuration. It is provenance, not a
	// second ceiling: MergeBinaryFindings does not reapply it to the joined list.
	MaxFindings int `json:"max_findings,omitempty"`
	// PresenceDowngraded counts findings reported below the severity their rule
	// carries because their file held no independent corroboration. It is taken at
	// downgrade time rather than at keep time, so it survives the finding cap
	// spending some of them - a reader must be able to see that the channel found
	// presence evidence and chose not to call it HIGH, even when the budget later
	// dropped the individual findings.
	PresenceDowngraded int `json:"presence_downgraded,omitempty"`
}

// BinaryScanResult is everything one binary pass produces.
type BinaryScanResult struct {
	Findings []Finding
	Summary  BinaryScanSummary
	// Claimed is every path the channel classified as binary, in walk order.
	// MergeBinaryFindings uses it to decide which files the source channel must
	// not also be believed about - a file whose bytes are binary is not a file
	// whose text reading means anything.
	Claimed []string
	// Evidence holds the listing for files that produced findings, and only for
	// those. The Tier 2 file prompt needs it, and a clean package should not pay
	// for a listing no one will read - the same principle the scanner applies to
	// parsing a source file.
	Evidence map[string]*EvidenceSet
}

// BinaryScanner walks a directory and audits the binary files in it.
//
// It is deliberately not a StaticEngine. The two engines are alternatives to
// each other, and this is not an alternative to either: a deployment that chose
// semgrep for source must still get binary coverage, and one that chose the
// regex baseline must not be the only one without it.
type BinaryScanner struct {
	matcher *BinaryMatcher
	cfg     BinaryConfig
}

// NewBinaryScanner builds a scanner. A nil matcher is replaced with the default
// table rather than being an error, because the table has no failure mode a
// caller could act on.
func NewBinaryScanner(matcher *BinaryMatcher, cfg BinaryConfig) *BinaryScanner {
	if matcher == nil {
		// The discarded error would leave matcher nil and surface as a nil
		// dereference at the first MatchAll rather than as a diagnosis, so the
		// rule-table tests in binary_rules_test.go carry the weight of proving it
		// cannot happen.
		matcher, _ = NewBinaryMatcher()
	}
	return &BinaryScanner{matcher: matcher, cfg: normalizeBinaryConfig(cfg)}
}

// ScanDirectory walks dir in lexical order and audits every binary file in it.
//
// The walk covers every regular file, not a list of extensions: the
// classification is made from the head of each file, so a binary named .py is
// found and a text file named .so is found, and neither depends on a list
// somebody could rename around. Reading 4 KiB of each of a few hundred files
// costs less than one semgrep invocation.
//
// It is the context-free entry point: it delegates to ScanDirectoryContext with
// context.Background(), so a scan through it is never cancelled.
func (s *BinaryScanner) ScanDirectory(dir string) (*BinaryScanResult, error) {
	return s.ScanDirectoryContext(context.Background(), dir)
}

// ScanDirectoryContext is ScanDirectory with the audit's cancellation attached.
//
// Cancellation is observed at the entry and at the top of every walk callback,
// so a cancelled scan stops before reading the next file rather than at the end
// of the directory. On cancellation it returns the context's error - ctx.Err(),
// not a wrapped walk error - and a nil result, never a partial one: a partial
// pass would look like a package that examined only the files it reached, and
// nothing downstream could tell that apart from one that examined all of them.
func (s *BinaryScanner) ScanDirectoryContext(ctx context.Context, dir string) (*BinaryScanResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("scan directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}

	res := &BinaryScanResult{
		Summary: BinaryScanSummary{
			Kinds:       map[string]int{},
			MaxFindings: s.cfg.MaxFindings,
		},
		Evidence: map[string]*EvidenceSet{},
	}

	err = walkContext(ctx, dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// The walk could not read this path. Two shapes arrive here: an entry
			// whose lstat failed (filepath.Walk passes info as nil, because there
			// is no FileInfo to pass), and a directory whose entries would not
			// list (info is the directory itself and err is the listing error).
			// Either way there is nothing here to classify - a nil info has no
			// mode and no bytes, and a directory has no bytes of its own.
			//
			// Returning nil is deliberate - one unreadable subtree must not abort
			// the audit of the rest - but the skip must not be silent either. This
			// is the count the classify-open and extraction failures below use, and
			// it is what makes an unreadable subtree withhold the pass rather than
			// leave a scan that looks read-and-clean. At the root it is the
			// difference between a clean scan of zero files and a scan that admits
			// it looked at nothing.
			res.Summary.Incomplete++
			return nil
		}
		if info.IsDir() {
			if s.cfg.SkipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			// A symlink, fifo, device or socket is not a file this channel reads,
			// and it is deliberately not followed: filepath.Walk lstats each
			// entry, so an entry that only points at a binary is skipped rather
			// than read through. Following one would let a link out of the model
			// directory pull in a file the package does not contain.
			return nil
		}

		kind, headErr := s.classify(path)
		if headErr != nil {
			// The walk reached the file and could not open it. That is a look
			// that did not happen, so it is counted Incomplete and
			// ProvesCleanScan withholds the pass - rather than being returned
			// away as though the file were not there, which is the fail-open the
			// completeness contract exists to close: a file the channel never
			// read would otherwise be invisible to every downstream reader.
			// The error is not propagated: one unreadable file must not abort the
			// audit of the rest, so it reaches the report through the count
			// instead of through the error path. It is also not added to Claimed,
			// because Claimed means "classified as binary" and this file was
			// never classified - so the source channel's own reading of it is
			// left alone rather than suppressed on a guess.
			res.Summary.Incomplete++
			return nil
		}
		if kind == KindText {
			return nil
		}

		res.Claimed = append(res.Claimed, path)
		set := CollectEvidence(path, kind, s.cfg)
		res.Summary.FilesCount++
		res.Summary.Kinds[string(kind)]++

		if set.Err != nil {
			// Extraction failed on a file that classify had already called binary:
			// the archive would not open, the ELF would not parse, the stream would
			// not decompress. That is a look that did not happen, and it is counted
			// - never silently skipped, because a file the channel could not read
			// and a file it decided not to read must not reach the report looking
			// the same. The host has the shape to test it with: 21 truncated
			// CUDA/MLX libraries, all of them under
			// teellm/models/ollama/lib/ollama and none under
			// deploy/guest-build/semgrep-payload/rootfs, which holds 88 .so*
			// files and not one truncated one. Twenty are exactly 10485760 bytes
			// on disk and the twenty-first is 10747904, with their section
			// headers 34483600 to 751773392 bytes into the file, so elf.NewFile
			// returns EOF. Counting is what makes such a file withhold the pass
			// instead of passing as clean.
			res.Summary.Incomplete++
			return nil
		}
		if set.Bound.Structural || set.Bound.Listing {
			// A capped listing splits by kind for the same reason a bounded read
			// does, but it is not the same loss. The cap is the matcher's input:
			// ScanDirectory matches over set.Lines, and EvidenceSet.add returns
			// before appending a line the cap refuses, so a dropped line is a line
			// no rule was shown. That is why this bound cannot be treated as
			// display-only, and why the decision belongs to the consumer that knows
			// the file's kind.
			//
			// On an executable format the loss reaches the blocking evidence. Every
			// blocking family reads a structural source - dynsym, needed, entropy,
			// pickle - and only an executable format emits those lines, while the
			// free-string families are all LOW. So a capped .so or .pt can have its
			// blocking line dropped without a trace, and it is counted
			// BoundedExecutable so the Task 10 fold withholds the pass.
			//
			// On a data kind the cap can only have dropped free-string lines, and no
			// blocking family reads those, so it stays BoundedData: visible in the
			// report, not a look that did not finish.
			if isExecutableKind(kind) {
				res.Summary.BoundedExecutable++
			} else {
				res.Summary.BoundedData++
			}
		}

		matches := s.matcher.MatchAll(set.Lines)
		if len(matches) == 0 {
			return nil
		}

		// Corroboration is decided per file, over every rule that matched in it,
		// before any finding is built: a presence finding is only meaningful next to
		// what else the file contains.
		corroborated := false
		for _, m := range matches {
			if s.matcher.corroborates(m.Rule.ID) {
				corroborated = true
				break
			}
		}

		res.Evidence[path] = set
		for _, m := range matches {
			f := binaryFinding(set, m)
			// Before the sort and the cap below, never after: the cap's contract is
			// written in terms of severity - it spends only what it positively knows
			// is LOW - so a downgrade applied afterwards would leave the cap reasoning
			// about HIGH while the report carries LOW.
			if !corroborated && s.matcher.downgrades(m.Rule.ID) {
				f.Severity = SeverityLow
				f.DowngradeReason = presenceDowngradeReason
				res.Summary.PresenceDowngraded++
			}
			res.Findings = append(res.Findings, f)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Checked again after a successful walk: a cancellation that arrives as the
	// last callback returns would otherwise leave the sort and the cap to finish
	// and hand back a full result, which the contract above rules out.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}

	// Sorted before capping, for the same reason the semgrep adapter sorts before
	// its cap: the cap keeps the first N, so a varying order would make a capped
	// pass keep a different set each time.
	//
	// The cap drops LOW findings and only LOW. A finding that can block the
	// import under the gate arbitration is kept whether or not it fits the
	// budget, and the list grows past MaxFindings instead. The keep rule below
	// therefore names the one severity that cannot block and keeps everything
	// else, rather than naming the severities that can: HIGH and MEDIUM both
	// block (internal/codeaudit/audit.go:311-327), and DYN_001 - MEDIUM in the
	// shared table - refuses the import just as a HIGH does.
	// Dropping a blocking finding would turn a package that must be withheld
	// into one that passes, which is the one failure a cap must not be
	// able to cause, and an attacker aims at exactly it by padding a package with
	// cheap LOW findings until the ones that block fall off the end of the list.
	//
	// The cost is real and is accepted: a crafted package can produce an
	// unbounded number of MEDIUM findings, because none of them may be dropped.
	// A report that grows is the safe direction to fail in; a report that is
	// short by a blocking finding is not.
	//
	// Reaching the budget is recorded on the summary and nowhere else - it must
	// not reach Report.Truncated, whose readers treat it as a completeness
	// failure and refuse the import.
	sortFindings(res.Findings)
	if len(res.Findings) > s.cfg.MaxFindings {
		kept := make([]Finding, 0, len(res.Findings))
		dropped := 0
		for _, f := range res.Findings {
			// Written as "not LOW" rather than "is HIGH or MEDIUM" on purpose:
			// the set that may be dropped has to be the one that cannot block,
			// so anything the code does not positively know to be LOW is kept.
			// The rule table cannot produce the input that separates the two
			// spellings - it writes only HIGH, MEDIUM and LOW - so the property is
			// pinned by TestBinaryScannerCapKeepsAnUnknownSeverityPastTheBudget,
			// which builds a matcher carrying a severity no table produces and
			// requires it to survive the cap.
			if len(kept) < s.cfg.MaxFindings || f.Severity != SeverityLow {
				kept = append(kept, f)
				continue
			}
			dropped++
		}
		res.Findings = kept
		if dropped > 0 {
			res.Summary.FindingsCapped = true
			res.Summary.FindingsDropped = dropped
		}
	}
	return res, nil
}

// classify reads a file's head and decides how it should be read.
//
// A zero-byte file is not an error here. os.File.Read on an empty file returns
// (0, io.EOF), so treating "err != nil && n == 0" as a failure would return
// every empty regular file as an unreadable one - and ScanDirectory counts an
// unreadable file as Incomplete, which withholds the pass. An empty __init__.py
// is routine, so that would fail a legitimate package over a file with no bytes
// to read. The branch below therefore distinguishes "could not open" (a real
// error, returned) from "opened and is empty" (io.EOF with nothing read, not an
// error), and lets ClassifyBinary decide the empty head the same way it decides
// any other: an empty .py is KindText and is skipped, not counted.
func (s *BinaryScanner) classify(path string) (BinaryKind, error) {
	f, err := os.Open(path)
	if err != nil {
		return KindText, err
	}
	defer f.Close()

	head := make([]byte, sniffBytes)
	n, err := f.Read(head)
	if err != nil && err != io.EOF {
		return KindText, err
	}
	return ClassifyBinary(head[:n], path), nil
}

// presenceDowngradeReason travels with every finding the corroboration gate
// lowered, so the report says why rather than leaving a reader to infer it from a
// severity that does not match the rule table.
const presenceDowngradeReason = "本文件内未发现独立佐证（没有可执行节区的高熵测量，也没有具备进程/IO/网络能力的 pickle 解析目标）：动态符号表或依赖库中的名字只说明该文件具备调用能力，不足以判定其会调用，故按 LOW 上报，交由语义分析定夺。"

// binaryFinding turns one matched evidence line into a finding.
//
// Line is the evidence line's index, not a source line number: a binary has no
// lines, and the index is the coordinate that resolves against the listing the
// report carries. CodeSnippet and the context window are the rendered listing
// around it, built with the same geometry the source arms use - three lines each
// side - so the Tier 2 prompt has one shape whichever channel produced the
// finding.
func binaryFinding(set *EvidenceSet, m binaryMatch) Finding {
	line := set.Lines[m.Index]
	return Finding{
		File:           set.File,
		Line:           line.Index,
		RuleID:         m.Rule.ID,
		Category:       m.Rule.Category,
		Severity:       m.Rule.Severity,
		Description:    m.Rule.Description,
		CodeSnippet:    line.Text,
		ContextBefore:  renderEvidenceWindow(set.Lines, m.Index-3, m.Index),
		ContextAfter:   renderEvidenceWindow(set.Lines, m.Index+1, m.Index+4),
		Engine:         EngineNameBinary,
		BinaryKind:     string(set.Kind),
		EvidenceSource: string(line.Source),
		BinaryOffset:   line.Offset,
	}
}

// renderEvidenceWindow renders the listing lines in [start, end) the way the
// prompt shows them. The geometry and the trimming are contextWindow's, taken
// from it rather than restated: the two channels feed one prompt, and a window
// that meant something different on one side would be a difference the reader
// cannot see.
func renderEvidenceWindow(lines []EvidenceLine, start, end int) string {
	start, end = windowBounds(len(lines), start, end)
	if start >= end {
		return ""
	}
	rendered := make([]string, 0, end-start)
	for _, l := range lines[start:end] {
		rendered = append(rendered, fmt.Sprintf("[%s] %s", l.Source, l.Text))
	}
	return contextWindow(rendered, 0, len(rendered))
}
