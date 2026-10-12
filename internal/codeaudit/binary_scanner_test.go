package codeaudit

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestBinaryScanner(cfg BinaryConfig) (*BinaryScanner, error) {
	m, err := NewBinaryMatcher()
	if err != nil {
		return nil, err
	}
	return NewBinaryScanner(m, cfg), nil
}

// TestBinaryScannerClaimsOnlyBinaryFiles pins the claim set: text files are left
// to the source channel, and everything with binary content or a binary
// extension is claimed. The claim set is what MergeBinaryFindings uses to decide
// which files the source channel must not also be believed about.
//
// empty.py is the degenerate case and it is here rather than in its own test
// because it is the same question: a zero-byte file is classified KindText (see
// TestClassifyBinaryEmptyFile), so it is not claimed and not counted. What makes
// it worth pinning is that the wrong reading of os.File.Read - the one that
// treats io.EOF as a failure - turns every empty file into an unreadable one,
// which ScanDirectory counts Incomplete and which withholds the pass. An empty
// __init__.py is routine, so that mistake fails a legitimate package, and it is
// invisible in a claim set that never contains an empty file.
func TestBinaryScannerClaimsOnlyBinaryFiles(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", "import os\n")
	writeTestFile(t, dir, "notes.txt", "just prose\n")
	writeTestFile(t, dir, "empty.py", "")
	writeTestFile(t, dir, "libevil.so", "#!/bin/sh\necho hi\n")
	writeTestBytes(t, dir, "w.bin", []byte("data\x00literal"))

	s, err := newTestBinaryScanner(DefaultBinaryConfig())
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	if res.Summary.Incomplete != 0 {
		t.Errorf("Summary.Incomplete = %d, want 0: an empty file is a file that was read, not one that could not be", res.Summary.Incomplete)
	}

	want := map[string]bool{"libevil.so": true, "w.bin": true}
	got := map[string]bool{}
	for _, p := range res.Claimed {
		got[filepath.Base(p)] = true
	}
	if len(got) != len(want) {
		t.Fatalf("claimed = %v, want %v", got, want)
	}
	for name := range want {
		if !got[name] {
			t.Errorf("%s was not claimed", name)
		}
	}
}

func TestBinaryScannerFindsImportsAndPickles(t *testing.T) {
	dir := t.TempDir()
	writeTestBytes(t, dir, "libevil.so", elfFixtureBytes(t, elfSpec{
		imports: []string{"socket", "connect", "system"},
		needed:  []string{"libcurl.so.4"},
	}))
	writeTestBytes(t, dir, "model.pt", zipFixture(t, map[string][]byte{
		"archive/data.pkl": []byte("\x80\x04cposix\nsystem\n."),
	}, []string{"archive/data.pkl"}))

	s, err := newTestBinaryScanner(DefaultBinaryConfig())
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	if res.Summary.FilesCount != 2 {
		t.Errorf("FilesCount = %d, want 2", res.Summary.FilesCount)
	}

	byRule := map[string]int{}
	for _, f := range res.Findings {
		byRule[f.RuleID]++
		if f.Engine != EngineNameBinary {
			t.Errorf("%s on %s has Engine %q, want %q", f.RuleID, f.File, f.Engine, EngineNameBinary)
		}
		if f.BinaryKind == "" || f.EvidenceSource == "" {
			t.Errorf("%s on %s lacks binary provenance: kind=%q source=%q", f.RuleID, f.File, f.BinaryKind, f.EvidenceSource)
		}
	}
	for _, want := range []string{"NET_002", "CMD_001", "PKL_001"} {
		if byRule[want] == 0 {
			t.Errorf("no %s finding; got %v", want, byRule)
		}
	}
}

// TestBinaryScannerIsDeterministic pins run-to-run stability, which is a real
// property: two scans of the same package must produce the same findings in the
// same order, or two reports of the same package stop being comparable.
//
// It does not pin the sortFindings call, and the comment here should not claim it
// does. The findings arrive already in (File, Line) order: filepath.Walk is
// lexical, which fixes the file order, and MatchAll iterates a listing Finalize
// has already ordered, which fixes the line order within a file. Deleting
// sortFindings from ScanDirectory would leave this test green - the fixture is a
// fixed point of the sort. The sort itself is pinned by
// TestSortFindingsOrdersShuffledFindings below, which drives it directly with an
// order it has to repair, and the call is kept in ScanDirectory for the case this
// test cannot construct: two producers whose listings interleave.
func TestBinaryScannerIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 8; i++ {
		writeTestBytes(t, dir, string(rune('a'+i))+".so", elfFixtureBytes(t, elfSpec{
			imports: []string{"socket", "connect", "system", "popen", "dlopen"},
		}))
	}
	s, err := newTestBinaryScanner(DefaultBinaryConfig())
	if err != nil {
		t.Fatal(err)
	}

	first, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Findings) < 8 {
		t.Fatalf("len(Findings) = %d, want at least one per file", len(first.Findings))
	}
	for run := 0; run < 5; run++ {
		next, err := s.ScanDirectory(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(next.Findings) != len(first.Findings) {
			t.Fatalf("run %d produced %d findings, first run produced %d", run, len(next.Findings), len(first.Findings))
		}
		for i := range first.Findings {
			a, b := first.Findings[i], next.Findings[i]
			if a.File != b.File || a.Line != b.Line || a.RuleID != b.RuleID {
				t.Fatalf("run %d finding %d = %s:%d %s, first run = %s:%d %s",
					run, i, b.File, b.Line, b.RuleID, a.File, a.Line, a.RuleID)
			}
		}
	}
}

// TestSortFindingsOrdersShuffledFindings pins the order itself, because no
// scan-level test can. The order has to be total - file, then line, then rule -
// and independent of the run, since the cap keeps the first N: a comparison that
// stopped at the file would leave two findings in one file ordered by whatever
// order the producers happened to emit them in, and a capped scan would keep a
// different set from run to run.
//
// The input below is shuffled on both axes, so this test fails if the comparison
// is deleted, if the file key is dropped, or if the line key is dropped.
//
// It fails if the rule-id tiebreak is dropped as well, and that is the result of
// a measurement rather than of the argument this comment used to make. The two
// fixture records {a.so, 9, CMD_001} and {a.so, 9, BIN_001} tie on file and on
// line, so the tiebreak is the only key that can order them: with the RuleID
// comparison removed they keep their input order and the test reports
// "after sort, finding 1 = a.so:9 CMD_001, want a.so:9 BIN_001". An earlier
// version of this comment claimed the opposite - that this test could not see the
// tiebreak and that it was kept only for totality - and that claim was false,
// because the fixture contains exactly the tie the tiebreak exists to break.
func TestSortFindingsOrdersShuffledFindings(t *testing.T) {
	findings := []Finding{
		{File: "b.so", Line: 3, RuleID: "BIN_001"},
		{File: "a.so", Line: 9, RuleID: "CMD_001"},
		{File: "a.so", Line: 9, RuleID: "BIN_001"},
		{File: "a.so", Line: 2, RuleID: "NET_002"},
	}
	sortFindings(findings)

	want := []struct {
		file   string
		line   int
		ruleID string
	}{
		{"a.so", 2, "NET_002"},
		{"a.so", 9, "BIN_001"},
		{"a.so", 9, "CMD_001"},
		{"b.so", 3, "BIN_001"},
	}
	for i := range want {
		got := findings[i]
		if got.File != want[i].file || got.Line != want[i].line || got.RuleID != want[i].ruleID {
			t.Fatalf("after sort, finding %d = %s:%d %s, want %s:%d %s",
				i, got.File, got.Line, got.RuleID, want[i].file, want[i].line, want[i].ruleID)
		}
	}
}

// TestBinaryScannerCountsAnUnreadableSubtree pins the walk-level error path. The
// walk must not abort on one unreadable subtree, but it must not forget it
// either: an entry the walk could not read is a look that did not happen, and it
// is counted Incomplete for the same reason an unopenable file is. Without the
// count, a directory containing an unreadable subtree scans as a clean scan of
// whatever was readable - the exact "looks read-and-clean" shape Incomplete
// exists to close, and at the root it is a clean scan of nothing.
//
// It is skipped when the suite runs as root, where mode 0o000 does not deny
// access and there is no unreadable subtree to make. The skip is not the fix: the
// count is asserted wherever the platform lets the subtree be unreadable, and it
// is not conditional on this test in any other way.
func TestBinaryScannerCountsAnUnreadableSubtree(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode 0o000 does not deny access, so no unreadable subtree can be made")
	}
	dir := t.TempDir()
	writeTestBytes(t, dir, "libevil.so", elfFixtureBytes(t, elfSpec{imports: []string{"socket"}}))
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestBytes(t, locked, "inside.so", elfFixtureBytes(t, elfSpec{imports: []string{"system"}}))
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	// Registered after t.TempDir's cleanup, so it runs first and the tree can be
	// removed.
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })

	s, err := newTestBinaryScanner(DefaultBinaryConfig())
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	if res.Summary.Incomplete == 0 {
		t.Errorf("Summary.Incomplete = 0: an unreadable subtree was skipped without being counted; summary = %+v", res.Summary)
	}
}

func TestBinaryScannerCapPreservesEveryHighFinding(t *testing.T) {
	dir := t.TempDir()
	// Four presence findings (socket/connect -> NET_002, system/popen -> CMD_001)
	// and one measured BIN_001, all HIGH, on the file that sorts second; four LOW
	// path literals (FIL_002 / CMD_002) on the file that sorts first. The cap is
	// set below the total so it has to drop something, and the property under test
	// is which something: the LOW findings are the ones a cap may spend.
	//
	// The .text below is not decoration. Without it the four presence findings
	// carry no corroborator and are reported LOW, so there would be no HIGH
	// finding for this test to preserve - the fixture would still pass an
	// assertion written loosely, and the property would have quietly vanished.
	// uniformBytes measures exactly 8.00 bits per byte, so .text is reported
	// BIN_001 HIGH and the same file's presence findings stay HIGH.
	//
	// The arithmetic, re-derived against the cap as it now reads. The sort is
	// (File, Line, RuleID) and "extra.bin" sorts before "libevil.so", so the four
	// LOW findings come first and the five HIGH ones after. With the budget at 3
	// the first three lines are kept, the fourth LOW is the one dropped, and the
	// five HIGH findings are kept past the budget: 8 kept, 1 dropped.
	//
	// This test still cannot tell the present keep rule ("keep everything not
	// positively known to be LOW") from an older one that exempted HIGH alone:
	// its fixture holds no MEDIUM, so the two rules keep the same set here. The
	// sibling test below is the one that separates them; the pair is needed
	// because a change that re-broke MEDIUM would leave this test green.
	//
	// It matters because a finding that blocks under either policy may not be
	// dropped: HIGH blocks under `assist` and `gate` alike, so a cap that dropped
	// one would turn a withholding package into a passing one - and an attacker
	// could aim at exactly that by padding a package with cheap LOW findings until
	// its HIGH ones fell off the end of the list.
	writeTestBytes(t, dir, "libevil.so", elfFixtureBytes(t, elfSpec{
		imports:  []string{"socket", "connect", "system", "popen"},
		text:     uniformBytes(512),
		textExec: true,
	}))
	writeTestBytes(t, dir, "extra.bin", []byte("x\x00/etc/passwd\x00/etc/shadow\x00/etc/sudoers\x00/bin/sh\x00"))

	cfg := DefaultBinaryConfig()
	cfg.MaxFindings = 3
	s, err := newTestBinaryScanner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	highs := 0
	for _, f := range res.Findings {
		if f.Severity == SeverityHigh {
			highs++
		}
	}
	if highs != 5 {
		t.Errorf("kept %d HIGH findings, want all 5: the cap dropped a blocking finding", highs)
	}
	// The list is allowed to exceed the budget to keep them. A cap that held the
	// line at 3 by dropping a HIGH would satisfy the budget and fail the audit.
	if len(res.Findings) <= cfg.MaxFindings {
		t.Errorf("len(Findings) = %d, want more than the budget of %d - the HIGH findings were kept",
			len(res.Findings), cfg.MaxFindings)
	}
	if !res.Summary.FindingsCapped {
		t.Error("Summary.FindingsCapped = false although the cap dropped findings")
	}
	if res.Summary.FindingsDropped == 0 {
		t.Error("Summary.FindingsDropped = 0 although the cap fired; the drop is invisible")
	}
	// The counts, not just the fact of the drop: this fixture has nine findings
	// and a budget of three, so exactly one LOW is spent and exactly eight are
	// kept - the three inside the budget and the five HIGH findings past it. A cap
	// that counted a kept finding as dropped, or spent two where it spent one,
	// satisfies the assertions above and fails these.
	if res.Summary.FindingsDropped != 1 {
		t.Errorf("Summary.FindingsDropped = %d, want 1: four LOW findings met a budget of three", res.Summary.FindingsDropped)
	}
	if len(res.Findings) != 8 {
		t.Errorf("len(Findings) = %d, want 8: three budgeted LOW findings and five HIGH ones kept past the budget", len(res.Findings))
	}
	// The budget is carried into the summary so the report can say what it capped
	// at. A reader who sees findings_capped with no number has to go find the
	// configuration that produced it, and by then it may have changed.
	if res.Summary.MaxFindings != 3 {
		t.Errorf("Summary.MaxFindings = %d, want 3", res.Summary.MaxFindings)
	}
}

// TestBinaryScannerCapKeepsAMediumFindingBeyondTheBudget is the case the HIGH
// test above cannot see. MEDIUM does not block under the default `assist`
// policy, but it does under `gate`, where `passed` is `High == 0 && Medium == 0`
// (internal/codeaudit/audit.go:298-309). A cap that dropped MEDIUM would
// therefore let a crafted package pass under `gate` with its blocking findings
// sitting past the budget - the padding attack the HIGH test describes, aimed at
// the other policy. DYN_001 is the concrete family: it is MEDIUM in the shared
// table and the binary arm borrows it, so `dlopen` in a dynamic symbol table is
// an ordinary-looking way to put a MEDIUM finding in the list.
//
// The fixture drives the cap the way the HIGH test does - a LOW-padded file that
// sorts first, then the file carrying the finding under test - arranged so the
// MEDIUM lands beyond the budget. The sort is (File, Line, RuleID) and
// "extra.bin" precedes "zlib.so", so the four LOW line literals take the first
// four positions and the single MEDIUM sits at five, two past a budget of 3.
func TestBinaryScannerCapKeepsAMediumFindingBeyondTheBudget(t *testing.T) {
	dir := t.TempDir()
	// dlopen -> DYN_001, borrowed MEDIUM.
	writeTestBytes(t, dir, "zlib.so", elfFixtureBytes(t, elfSpec{imports: []string{"dlopen"}}))
	// Four LOW findings, all sorting ahead of zlib.so.
	writeTestBytes(t, dir, "extra.bin", []byte("x\x00/etc/passwd\x00/etc/shadow\x00/etc/sudoers\x00/bin/sh\x00"))

	cfg := DefaultBinaryConfig()
	cfg.MaxFindings = 3
	s, err := newTestBinaryScanner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	mediums := 0
	for _, f := range res.Findings {
		if f.RuleID == "DYN_001" {
			if f.Severity != SeverityMedium {
				t.Fatalf("DYN_001 is %s, want %s: the family's blocking power under `gate` rests on this", f.Severity, SeverityMedium)
			}
			mediums++
		}
	}
	if mediums != 1 {
		t.Errorf("kept %d DYN_001 findings, want 1: the cap dropped a finding that blocks under the gate policy", mediums)
	}
	// The LOW padding is what the budget may spend, and the budget is still
	// reported as spent even though the listing grew past it to keep the MEDIUM.
	if !res.Summary.FindingsCapped || res.Summary.FindingsDropped == 0 {
		t.Errorf("the cap did not report the LOW it spent: capped=%v dropped=%d",
			res.Summary.FindingsCapped, res.Summary.FindingsDropped)
	}
	// Exact counts again: this fixture has five findings and a budget of three, so
	// one LOW is spent and four are kept - three inside the budget and the MEDIUM
	// past it.
	if res.Summary.FindingsDropped != 1 {
		t.Errorf("Summary.FindingsDropped = %d, want 1: four LOW findings met a budget of three", res.Summary.FindingsDropped)
	}
	if len(res.Findings) != 4 {
		t.Errorf("len(Findings) = %d, want 4: three budgeted LOW findings and the MEDIUM kept past the budget", len(res.Findings))
	}
	if len(res.Findings) <= cfg.MaxFindings {
		t.Errorf("len(Findings) = %d, want more than the budget of %d - the MEDIUM finding was kept",
			len(res.Findings), cfg.MaxFindings)
	}
}

func TestBinaryScannerCapIsSilentWhenTheBudgetIsNotReached(t *testing.T) {
	dir := t.TempDir()
	writeTestBytes(t, dir, "libevil.so", elfFixtureBytes(t, elfSpec{imports: []string{"socket"}}))

	s, err := newTestBinaryScanner(DefaultBinaryConfig())
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	if res.Summary.FindingsCapped || res.Summary.FindingsDropped != 0 {
		t.Errorf("the cap reported a drop on a package well under budget: capped=%v dropped=%d",
			res.Summary.FindingsCapped, res.Summary.FindingsDropped)
	}
}

// TestBinaryScannerSplitsStructuralBoundsByKind pins the one branch in
// ScanDirectory that decides, per file, whether a bounded read was a look that
// did not finish or a look that finished on as much as there was reason to read.
// Task 10's ProvesCleanScan reads that split - BoundedExecutable withholds a
// clean verdict, BoundedData does not - and the two mistakes available here run
// in opposite directions, which is why both are named.
//
// A scanner that exchanged the arms would pass a package holding a truncated .so
// as clean: the executable kind would land in BoundedData, BoundedExecutable
// would stay zero, nothing would withhold the verdict, and a truncated ELF is
// exactly the shape whose unread part could hold the payload this channel exists
// to catch. The same exchange would withhold a legitimate package whose only
// bound was a data file, because a large .bin windowed at its ends would be
// recorded as BoundedExecutable. That is why the split is tested here rather
// than left to Task 10: every other test in this file would stay green through
// either mistake, because nothing else reads either counter.
//
// The bound is made deliberately rather than found: MaxFullScanBytes and
// HeadTailBytes are set to 64 and 16, so the head-and-tail window is taken on
// files far above that budget and streamWithSizeSwitch records the structural
// bound - the ELF fixture is 632 bytes and the raw one is 4101.
//
// Each arm asserts the whole pair rather than a single counter. A single counter
// already catches the exchange, since the expected field reads 0 where the
// swapped scanner writes 1; what only the pair catches is double counting, a
// scanner that incremented both fields for one file reading (1, 1) while either
// field taken alone would look right.
func TestBinaryScannerSplitsStructuralBoundsByKind(t *testing.T) {
	tinyWindow := func() BinaryConfig {
		cfg := DefaultBinaryConfig()
		cfg.MaxFullScanBytes = 64
		cfg.HeadTailBytes = 16
		return cfg
	}

	t.Run("an executable kind is counted BoundedExecutable", func(t *testing.T) {
		dir := t.TempDir()
		writeTestBytes(t, dir, "libevil.so", elfFixtureBytes(t, elfSpec{imports: []string{"socket"}}))

		s, err := newTestBinaryScanner(tinyWindow())
		if err != nil {
			t.Fatal(err)
		}
		res, err := s.ScanDirectory(dir)
		if err != nil {
			t.Fatalf("ScanDirectory: %v", err)
		}
		if res.Summary.Kinds[string(KindELF)] != 1 {
			t.Fatalf("Kinds[elf] = %d, want 1: the fixture is not the executable kind this arm is about",
				res.Summary.Kinds[string(KindELF)])
		}
		if res.Summary.Incomplete != 0 {
			t.Fatalf("Incomplete = %d, want 0: a structural bound is a look that stopped short, not one that failed",
				res.Summary.Incomplete)
		}
		if res.Summary.BoundedExecutable != 1 || res.Summary.BoundedData != 0 {
			t.Errorf("BoundedExecutable = %d, BoundedData = %d, want 1 and 0: a bounded ELF is the kind that can carry an executed payload",
				res.Summary.BoundedExecutable, res.Summary.BoundedData)
		}
	})

	t.Run("a data kind is counted BoundedData", func(t *testing.T) {
		dir := t.TempDir()
		writeTestBytes(t, dir, "weights.bin", append([]byte("data\x00"), make([]byte, 4096)...))

		s, err := newTestBinaryScanner(tinyWindow())
		if err != nil {
			t.Fatal(err)
		}
		res, err := s.ScanDirectory(dir)
		if err != nil {
			t.Fatalf("ScanDirectory: %v", err)
		}
		if res.Summary.Kinds[string(KindRaw)] != 1 {
			t.Fatalf("Kinds[raw] = %d, want 1: the fixture is not the data kind this arm is about",
				res.Summary.Kinds[string(KindRaw)])
		}
		if res.Summary.Incomplete != 0 {
			t.Fatalf("Incomplete = %d, want 0: a structural bound is a look that stopped short, not one that failed",
				res.Summary.Incomplete)
		}
		if res.Summary.BoundedData != 1 || res.Summary.BoundedExecutable != 0 {
			t.Errorf("BoundedData = %d, BoundedExecutable = %d, want 1 and 0: a bounded raw blob cannot run on this platform",
				res.Summary.BoundedData, res.Summary.BoundedExecutable)
		}
	})
}

// TestBinaryScannerCapKeepsLowFindingsWithinTheBudget pins the half of the cap's
// contract that protects a legitimate package: a LOW finding inside the budget is
// kept. Without it the cap tests only ever assert that the cap *did* spend
// something, so an implementation that dropped every LOW finding wherever it sat
// - keeping the HIGH and MEDIUM families intact and every other assertion in this
// file green - would pass.
//
// The budget has to be large enough to hold every LOW finding and small enough
// that the cap still runs, which is the whole difficulty of writing this case: a
// budget above the total finding count skips the cap block entirely, and a
// mutation that spends LOW findings wherever they sit is then invisible because
// nothing is ever spent. Five findings of budget against nine findings does hold
// all four LOW findings, and it still enters the cap, so the four survive five
// HIGH findings that arrive after them rather than surviving nothing at all.
//
// The second file carries a measured BIN_001 as well as the four presence
// findings, and that is load-bearing rather than scene-setting: without a
// corroborator the four presence findings are reported LOW and the file becomes
// four more spendable findings, which is a different fixture with a different
// arithmetic (nine findings, five of them LOW, budget five) and no longer the
// shape this test is about.
//
// The counts are asserted exactly rather than as lower bounds: "at least one LOW
// survived" is an assertion the broken implementation above also satisfies.
func TestBinaryScannerCapKeepsLowFindingsWithinTheBudget(t *testing.T) {
	dir := t.TempDir()
	// Four LOW findings on the file that sorts first: three FIL_002 path literals
	// and one CMD_002 shell path.
	writeTestBytes(t, dir, "extra.bin", []byte("x\x00/etc/passwd\x00/etc/shadow\x00/etc/sudoers\x00/bin/sh\x00"))
	// Five HIGH findings on the file that sorts second: socket/connect -> NET_002,
	// system/popen -> CMD_001, and the measured BIN_001 the four need to stay HIGH.
	writeTestBytes(t, dir, "zevil.so", elfFixtureBytes(t, elfSpec{
		imports:  []string{"socket", "connect", "system", "popen"},
		text:     uniformBytes(512),
		textExec: true,
	}))

	cfg := DefaultBinaryConfig()
	cfg.MaxFindings = 5
	s, err := newTestBinaryScanner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	if len(res.Findings) != 9 {
		t.Fatalf("len(Findings) = %d, want 9: the four LOW findings are inside the budget and the five HIGH ones may not be spent", len(res.Findings))
	}
	byRule := map[string]int{}
	for _, f := range res.Findings {
		byRule[f.RuleID]++
	}
	// "LOW" is the bare string the table writes: rules.go declares no SeverityLow
	// constant, so the count of LOW findings is checked by rule id.
	if byRule["FIL_002"] != 3 || byRule["CMD_002"] != 1 {
		t.Errorf("kept FIL_002 = %d and CMD_002 = %d, want 3 and 1: the LOW findings inside the budget were not all kept",
			byRule["FIL_002"], byRule["CMD_002"])
	}
	// The HIGH findings are named too, so that a fixture edit which silently
	// dropped the corroborator (turning five HIGH into five LOW) fails here
	// instead of turning the test into one about nine spendable findings.
	if byRule["NET_002"] != 2 || byRule["CMD_001"] != 2 || byRule["BIN_001"] != 1 {
		t.Errorf("kept NET_002 = %d, CMD_001 = %d and BIN_001 = %d, want 2, 2 and 1: the fixture's HIGH findings moved",
			byRule["NET_002"], byRule["CMD_001"], byRule["BIN_001"])
	}
	if res.Summary.FindingsCapped || res.Summary.FindingsDropped != 0 {
		t.Errorf("the cap reported a drop although every LOW finding fit the budget: capped=%v dropped=%d",
			res.Summary.FindingsCapped, res.Summary.FindingsDropped)
	}
}

// TestBinaryScannerCapDropsExactlyTheLowFindingsBeyondTheBudget pins the count,
// not only the fact of the drop. A cap that counted a kept finding as dropped, or
// that spent two findings where it spent one, satisfies every existing
// "FindingsDropped != 0" assertion while making the number the report carries a
// lie - and that number is the only record of what the cap took, since the
// findings themselves are gone.
//
// One file, four LOW findings, a budget of three: the three inside the budget are
// kept and the fourth is spent, and the summary says exactly that.
func TestBinaryScannerCapDropsExactlyTheLowFindingsBeyondTheBudget(t *testing.T) {
	dir := t.TempDir()
	writeTestBytes(t, dir, "extra.bin", []byte("x\x00/etc/passwd\x00/etc/shadow\x00/etc/sudoers\x00/bin/sh\x00"))

	cfg := DefaultBinaryConfig()
	cfg.MaxFindings = 3
	s, err := newTestBinaryScanner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	if len(res.Findings) != 3 {
		t.Errorf("len(Findings) = %d, want 3: the budget was spent on the findings inside it", len(res.Findings))
	}
	if !res.Summary.FindingsCapped {
		t.Error("Summary.FindingsCapped = false although the cap spent a finding")
	}
	if res.Summary.FindingsDropped != 1 {
		t.Errorf("Summary.FindingsDropped = %d, want 1: one LOW finding was beyond the budget and one was not",
			res.Summary.FindingsDropped)
	}
	if len(res.Findings)+res.Summary.FindingsDropped != 4 {
		t.Errorf("kept %d and dropped %d, want 4 accounted for: the audit of the listing does not add up",
			len(res.Findings), res.Summary.FindingsDropped)
	}
}

// TestBinaryScannerCapWithNothingDroppableIsNotCapped pins the one cell that
// separates the cap's flag from its length: a listing that grew past the budget
// while spending nothing. Five HIGH findings against a budget of three leave
// len(Findings) = 5 > MaxFindings with FindingsCapped false, because LOW is the
// only thing the cap may spend and there is none here.
//
// The corroborator below is what keeps this the shape the name promises. The four
// presence findings are HIGH only because the file also measures as packed; drop
// the .text and they become four spendable LOW findings, at which point the cap
// does spend and the test silently becomes a second copy of
// TestBinaryScannerCapDropsExactlyTheLowFindingsBeyondTheBudget.
//
// It is the shape that tells `capped := dropped > 0` from `capped :=
// len(findings) > cfg.MaxFindings`. The second reads the budget being exceeded as
// a drop and would set the flag here, and the flag then travels into the report
// as a claim that findings were lost when every finding is in the list.
func TestBinaryScannerCapWithNothingDroppableIsNotCapped(t *testing.T) {
	dir := t.TempDir()
	// socket/connect -> NET_002, system/popen -> CMD_001, and the measured
	// BIN_001 that keeps all four HIGH: five findings, none of them spendable.
	writeTestBytes(t, dir, "libevil.so", elfFixtureBytes(t, elfSpec{
		imports:  []string{"socket", "connect", "system", "popen"},
		text:     uniformBytes(512),
		textExec: true,
	}))

	cfg := DefaultBinaryConfig()
	cfg.MaxFindings = 3
	s, err := newTestBinaryScanner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	if len(res.Findings) != 5 {
		t.Fatalf("len(Findings) = %d, want 5: HIGH findings are kept past the budget", len(res.Findings))
	}
	if res.Summary.FindingsCapped {
		t.Error("Summary.FindingsCapped = true although the cap spent nothing: the listing grew, and growing is not dropping")
	}
	if res.Summary.FindingsDropped != 0 {
		t.Errorf("Summary.FindingsDropped = %d, want 0: nothing in this package was droppable", res.Summary.FindingsDropped)
	}
	// The budget is still reported as the one the pass ran under, even though the
	// listing is longer than it.
	if res.Summary.MaxFindings != 3 {
		t.Errorf("Summary.MaxFindings = %d, want 3", res.Summary.MaxFindings)
	}
}

// TestBinaryScannerCapKeepsAnUnknownSeverityPastTheBudget pins the fail-closed
// half of the keep rule: what the cap may spend is "LOW and nothing else", not
// "HIGH or MEDIUM". The distinction cannot be reached through the rule table,
// which produces only those three severities, so the matcher is built here rather
// than by NewBinaryMatcher and carries a severity no table writes.
//
// It matters because the rule table is not the only thing that produces findings
// - a severity borrowed from a shared family or introduced by a later engine
// would be silently spendable by a cap written as `f.Severity == SeverityHigh ||
// f.Severity == SeverityMedium` - and a spent finding is invisible in the report
// by construction, since the cap's whole job is to remove it.
//
// The unknown-severity finding sits past the budget so the keep rule has to
// decide it: "a.bin" sorts before "z.bin", so the LOW padding takes the single
// budgeted slot and the unknown finding is the one whose survival is under test.
func TestBinaryScannerCapKeepsAnUnknownSeverityPastTheBudget(t *testing.T) {
	matcher := &BinaryMatcher{
		order: []binaryFamily{
			{ID: "LOWPAD", Sources: []EvidenceSource{SourceStrings}, Patterns: compilePatterns(`^PADDING$`)},
			{ID: "FUTURE_001", Sources: []EvidenceSource{SourceStrings}, Patterns: compilePatterns(`^FUTURE$`)},
		},
		rules: []Rule{
			{ID: "LOWPAD", Category: "test", Severity: "LOW", Description: "a spendable finding, to take the budgeted slot"},
			{ID: "FUTURE_001", Category: "test", Severity: "UNKNOWN-SEVERITY", Description: "a severity no rule table produces"},
		},
	}
	dir := t.TempDir()
	writeTestBytes(t, dir, "a.bin", []byte("PADDING\x00"))
	writeTestBytes(t, dir, "z.bin", []byte("FUTURE\x00"))

	cfg := DefaultBinaryConfig()
	cfg.MaxFindings = 1
	res, err := NewBinaryScanner(matcher, cfg).ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	if len(res.Findings) != 2 {
		t.Fatalf("len(Findings) = %d, want 2: the cap spent a finding whose severity it does not positively know", len(res.Findings))
	}
	survived := false
	for _, f := range res.Findings {
		if f.RuleID == "FUTURE_001" {
			survived = true
			if f.Severity != "UNKNOWN-SEVERITY" {
				t.Errorf("FUTURE_001 has severity %q, want %q: the injected severity was rewritten", f.Severity, "UNKNOWN-SEVERITY")
			}
		}
	}
	if !survived {
		t.Error("FUTURE_001 was spent: the keep rule is not fail-closed on a severity outside HIGH/MEDIUM")
	}
	if res.Summary.FindingsDropped != 0 {
		t.Errorf("Summary.FindingsDropped = %d, want 0: nothing in this package was spendable", res.Summary.FindingsDropped)
	}
}

// findFinding returns the single finding with the given rule id, or fails the
// test. The corroboration tests all ask a question about one specific family
// among the several a fixture produces, and selecting it by name is what keeps
// the assertion about that family rather than about the first finding in a list
// whose order is not the point.
func findFinding(t *testing.T, findings []Finding, ruleID string) Finding {
	t.Helper()
	var found *Finding
	for i := range findings {
		if findings[i].RuleID == ruleID {
			if found != nil {
				t.Fatalf("found %d findings under %s, want exactly one to assert against", countRule(findings, ruleID), ruleID)
			}
			found = &findings[i]
		}
	}
	if found == nil {
		t.Fatalf("no %s finding; findings = %+v", ruleID, findings)
	}
	return *found
}

// countRule counts the findings under one rule id, for the failure message above.
func countRule(findings []Finding, ruleID string) int {
	n := 0
	for _, f := range findings {
		if f.RuleID == ruleID {
			n++
		}
	}
	return n
}

// TestBinaryScannerDoesNotLetTwoPresenceFamiliesCorroborateEachOther is the test
// that protects the whole change. Two families that both read the dynamic symbol
// table are the same class of evidence counted twice, and a large legitimate
// library carries both: on this host libllama-common.so imports socket/connect/
// getaddrinfo while libggml-base.so imports execlp. So an implementation that
// treats "a second blocking family is present" as corroboration would keep every
// file this rule exists to clear, and this fixture is the smallest one that
// distinguishes it: two presence families, no measurement and no pickle parse.
func TestBinaryScannerDoesNotLetTwoPresenceFamiliesCorroborateEachOther(t *testing.T) {
	dir := t.TempDir()
	writeTestBytes(t, dir, "libboth.so", elfFixtureBytes(t, elfSpec{imports: []string{"socket", "system"}}))

	res, err := NewBinaryScanner(nil, BinaryConfig{}).ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	net := findFinding(t, res.Findings, "NET_002")
	cmd := findFinding(t, res.Findings, "CMD_001")
	for _, f := range []Finding{net, cmd} {
		if f.Severity != "LOW" {
			t.Errorf("%s severity = %q, want LOW: a presence family was corroborated by another presence family", f.RuleID, f.Severity)
		}
		if f.DowngradeReason == "" {
			t.Errorf("%s carries no downgrade reason: a reader cannot tell why it is not HIGH", f.RuleID)
		}
	}
	if res.Summary.PresenceDowngraded != 2 {
		t.Errorf("PresenceDowngraded = %d, want 2", res.Summary.PresenceDowngraded)
	}
}

// TestBinaryScannerKeepsAPresenceFamilyHighWhenTheFileIsPacked is the other half:
// corroboration has to actually work, or the rule is just a suppression.
func TestBinaryScannerKeepsAPresenceFamilyHighWhenTheFileIsPacked(t *testing.T) {
	dir := t.TempDir()
	writeTestBytes(t, dir, "libpacked.so", elfFixtureBytes(t, elfSpec{
		imports:  []string{"socket"},
		text:     uniformBytes(512),
		textExec: true,
	}))

	res, err := NewBinaryScanner(nil, BinaryConfig{}).ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	if f := findFinding(t, res.Findings, "NET_002"); f.Severity != SeverityHigh {
		t.Errorf("NET_002 severity = %q, want HIGH: a measured near-random executable section corroborates it", f.Severity)
	}
	if f := findFinding(t, res.Findings, "BIN_001"); f.Severity != SeverityHigh {
		t.Errorf("BIN_001 severity = %q, want HIGH: the entropy measurement is not itself a presence claim", f.Severity)
	}
	if res.Summary.PresenceDowngraded != 0 {
		t.Errorf("PresenceDowngraded = %d, want 0", res.Summary.PresenceDowngraded)
	}
}

// TestBinaryScannerCorroboratesAcrossArchiveMembers pins the granularity. The
// corroborator does not have to be in the same member: a .pt that carries a
// socket-importing ELF member and a process-executing data.pkl is one artifact
// whose parts run together, and collectArchive routes both members through one
// EvidenceSet.
func TestBinaryScannerCorroboratesAcrossArchiveMembers(t *testing.T) {
	dir := t.TempDir()
	writeTestBytes(t, dir, "model.pt", zipFixture(t, map[string][]byte{
		"lib/x.so":         elfFixtureBytes(t, elfSpec{imports: []string{"socket"}}),
		"archive/data.pkl": []byte("cposix\nsystem\n."),
	}, []string{"archive/data.pkl", "lib/x.so"}))

	res, err := NewBinaryScanner(nil, BinaryConfig{}).ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	if f := findFinding(t, res.Findings, "NET_002"); f.Severity != SeverityHigh {
		t.Errorf("NET_002 severity = %q, want HIGH: the same file carries a committed pickle parse", f.Severity)
	}
}

// TestBinaryScannerDoesNotLetACorroboratorTravelBetweenFiles pins the per-file
// boundary the whole gate rests on. Its justification is that a name in the
// symbol table is confirmed only by evidence the same file carries, and none of
// the tests around this one can see the outward edge of that boundary: each puts
// the corroborator and the presence family in one file, so a mutant that hoists
// the corroborated flag above the walk - letting one packed file clear every
// presence finding in the package - stays green on all of them.
//
// The ordering is what makes the leak visible. "a.so" sorts first and carries the
// corroborator, a measured near-random executable section, and no presence
// evidence of its own; "b.so" sorts second, imports socket, and carries no
// measurement and no pickle. Sticky corroboration can therefore reach b.so only
// because a.so was walked first, which is why the sorted order is load-bearing:
// with the packed file second the same mutant would look correct.
func TestBinaryScannerDoesNotLetACorroboratorTravelBetweenFiles(t *testing.T) {
	dir := t.TempDir()
	// The corroborator alone on the file that sorts first: .text measures 8.00
	// bits per byte, so BIN_001 is HIGH and nothing else here matches.
	writeTestBytes(t, dir, "a.so", elfFixtureBytes(t, elfSpec{
		text:     uniformBytes(512),
		textExec: true,
	}))
	// The presence finding on the file that sorts second: socket -> NET_002,
	// with no corroborator of its own.
	writeTestBytes(t, dir, "b.so", elfFixtureBytes(t, elfSpec{imports: []string{"socket"}}))

	res, err := NewBinaryScanner(nil, BinaryConfig{}).ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	if f := findFinding(t, res.Findings, "BIN_001"); f.Severity != SeverityHigh {
		t.Errorf("BIN_001 severity = %q, want HIGH: the entropy measurement is the corroborator, not a presence claim", f.Severity)
	}
	if f := findFinding(t, res.Findings, "NET_002"); f.Severity != "LOW" {
		t.Errorf("NET_002 severity = %q, want LOW: the corroborator is in a.so and must not clear a finding in b.so", f.Severity)
	}
	if res.Summary.PresenceDowngraded != 1 {
		t.Errorf("PresenceDowngraded = %d, want 1: only b.so's presence finding is uncorroborated", res.Summary.PresenceDowngraded)
	}
}

// TestBinaryScannerDowngradeHappensBeforeTheCap is the only test that can tell
// the two orderings apart, so it is not optional. Downgrading after the cap would
// leave the cap reasoning about HIGH while the report says LOW, and it would keep
// findings the cap was supposed to be allowed to spend.
func TestBinaryScannerDowngradeHappensBeforeTheCap(t *testing.T) {
	dir := t.TempDir()
	writeTestBytes(t, dir, "libmany.so", elfFixtureBytes(t, elfSpec{
		imports: []string{"socket", "connect", "system", "popen"},
	}))

	res, err := NewBinaryScanner(nil, BinaryConfig{MaxFindings: 2}).ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	if len(res.Findings) != 2 {
		t.Errorf("len(Findings) = %d, want 2: a downgraded finding is spendable, so the cap can drop it", len(res.Findings))
	}
	if !res.Summary.FindingsCapped || res.Summary.FindingsDropped != 2 {
		t.Errorf("capped = %v, dropped = %d, want true/2", res.Summary.FindingsCapped, res.Summary.FindingsDropped)
	}
	if res.Summary.PresenceDowngraded != 4 {
		t.Errorf("PresenceDowngraded = %d, want 4: the count is taken at downgrade time, not at keep time", res.Summary.PresenceDowngraded)
	}
}

// TestBinaryScannerDowngradedEvidenceDoesNotBlockUnderEitherPolicy pins the
// severity the decision needs. It asserts both policies, because assist passes on
// a MEDIUM downgrade too - only the gate assertion distinguishes LOW from MEDIUM,
// and MEDIUM under gate refuses the import.
func TestBinaryScannerDowngradedEvidenceDoesNotBlockUnderEitherPolicy(t *testing.T) {
	dir := t.TempDir()
	writeTestBytes(t, dir, "libnet.so", elfFixtureBytes(t, elfSpec{imports: []string{"socket"}}))

	res, err := NewBinaryScanner(nil, BinaryConfig{}).ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	report := &Report{ScanComplete: true}
	MergeBinaryFindings(report, res)

	if report.HighCount != 0 {
		t.Fatalf("HighCount = %d, want 0", report.HighCount)
	}
	if report.MediumCount != 0 {
		t.Fatalf("MediumCount = %d, want 0: MEDIUM blocks under gate, so a MEDIUM downgrade is not a fix", report.MediumCount)
	}
	stats := ComputeStatistics(report.Findings)
	// ScanPassed carries the completeness precondition the production path folds
	// in (AssembleAuditReport), so a pass here is the finding decision alone.
	scanPassed := report.ProvesCleanScan()
	for _, mode := range []string{"assist", "gate"} {
		concl := ComputeConclusionContext(stats, nil, mode, ConclusionContext{ScanPassed: &scanPassed})
		if !concl.Passed {
			t.Errorf("policy %s: passed = false for a package whose only evidence is a symbol name", mode)
		}
	}
}

func TestBinaryScannerSkipDirs(t *testing.T) {
	dir := t.TempDir()
	writeTestBytes(t, filepath.Join(dir, "node_modules"), "libevil.so", elfFixtureBytes(t, elfSpec{imports: []string{"system"}}))
	writeTestBytes(t, dir, "libevil.so", elfFixtureBytes(t, elfSpec{imports: []string{"system"}}))

	s, err := newTestBinaryScanner(DefaultBinaryConfig())
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	if res.Summary.FilesCount != 1 {
		t.Errorf("FilesCount = %d, want 1: node_modules is in the default skip set", res.Summary.FilesCount)
	}
}

// TestBinaryScannerCountsAnUnreadableFileAsIncomplete pins the failure direction
// for the scanner: a claimed file that could not be examined raises Incomplete,
// which withholds a clean verdict downstream.
func TestBinaryScannerCountsAnUnreadableFileAsIncomplete(t *testing.T) {
	dir := t.TempDir()
	path := writeTestBytes(t, dir, "broken.so", []byte("\x7fELF\x02\x01\x01\x00garbage"))
	// Make it unreadable rather than merely malformed: chmod 000 is the one
	// failure the collector cannot work around.
	if err := os.Chmod(path, 0o000); err != nil {
		t.Skipf("cannot chmod in this environment: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o644) })
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod 000 is not enforced")
	}

	s, err := newTestBinaryScanner(DefaultBinaryConfig())
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	if res.Summary.Incomplete != 1 {
		t.Errorf("Incomplete = %d, want 1", res.Summary.Incomplete)
	}
}

// TestBinaryScannerCountsAFailedExtractionAsIncomplete pins the other half of
// the same contract, and it is the half the test above does not reach: chmod 000
// fails at classify, so that file never gets as far as an extractor. Here the
// file opens and classifies as an ELF, and then fails to parse - which is the
// set.Err branch, a different line of ScanDirectory with the same meaning. The
// fixture is the shape the host actually has: 21 truncated CUDA/MLX libraries,
// all of them under teellm/models/ollama/lib/ollama - none are under
// deploy/guest-build/semgrep-payload/rootfs, which holds 88 .so* files and not
// one truncated one. Twenty are exactly 10485760 bytes on disk and the
// twenty-first is 10747904, with their section header tables between 34483600
// and 751773392 bytes into the file, so elf.NewFile returns EOF. The "~116 MB"
// figure quoted here before is a single sample, cuda_v12/libcublas.so.12.8.5.5.
// A truncated file is a file that was read and could not be
// examined, never a file that was skipped, so the count must be 1 and the pass
// must be withheld.
func TestBinaryScannerCountsAFailedExtractionAsIncomplete(t *testing.T) {
	dir := t.TempDir()
	raw := elfFixtureBytes(t, elfSpec{text: []byte("truncated")})
	// Point e_shoff past the end of the file (ELF64 header offset 0x28) so the
	// section header table cannot be read and elf.NewFile fails. The magic and
	// the rest of the header stay intact, so the file still classifies as an
	// ELF and still reaches the extractor - which is the point: this is not a
	// malformed magic, it is a well-formed claim that runs off the end.
	binary.LittleEndian.PutUint64(raw[0x28:0x30], 1<<30)
	writeTestBytes(t, dir, "truncated.so", raw)

	s, err := newTestBinaryScanner(DefaultBinaryConfig())
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	if res.Summary.Incomplete != 1 {
		t.Errorf("Incomplete = %d, want 1: a file that classified as ELF and failed to parse is a failed look, not a skip", res.Summary.Incomplete)
	}
	if res.Summary.FilesCount != 1 {
		t.Errorf("FilesCount = %d, want 1", res.Summary.FilesCount)
	}
}

// TestBinaryScannerIgnoresNonRegularEntries pins what the walk does with an
// entry that is not a regular file. A symlink is neither followed nor claimed:
// the channel reads the bytes the package contains, and reading through a link
// would read a file the package does not - possibly one outside the scanned
// directory. The entry is not counted Incomplete either, because it is not a
// file this channel was ever meant to examine; the count of what it examined
// stays exact.
func TestBinaryScannerIgnoresNonRegularEntries(t *testing.T) {
	dir := t.TempDir()
	writeTestBytes(t, dir, "real.so", elfFixtureBytes(t, elfSpec{imports: []string{"system"}}))
	if err := os.Symlink(filepath.Join(dir, "real.so"), filepath.Join(dir, "link.so")); err != nil {
		t.Skipf("cannot create a symlink in this environment: %v", err)
	}

	s, err := newTestBinaryScanner(DefaultBinaryConfig())
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	if res.Summary.FilesCount != 1 {
		t.Errorf("FilesCount = %d, want 1: the symlink must not be followed", res.Summary.FilesCount)
	}
	for _, p := range res.Claimed {
		if filepath.Base(p) == "link.so" {
			t.Error("the symlink was claimed; the channel read a file the package does not contain")
		}
	}
	if res.Summary.Incomplete != 0 {
		t.Errorf("Incomplete = %d, want 0: a skipped non-regular entry is not a look that failed", res.Summary.Incomplete)
	}
}

// TestBinaryScannerCappedListingOnAnExecutableKindWithholdsThePass pins the
// fail-open a capped listing used to leave open on a format that executes.
//
// The cap is not merely a shorter display. ScanDirectory matches over set.Lines,
// and EvidenceSet.add returns before appending a line the cap refuses, so a
// capped listing is a set of evidence lines no rule is ever shown. On an ELF the
// strings pass runs first and reads .dynstr and .shstrtab, which are walls of
// literals - one line per symbol name - so it fills the cap on its own, and every
// line the structural pass then adds is dropped. That is the whole of the
// blocking evidence: all five blocking families read dynsym, needed, entropy or
// pickle, and none of them reads a free string. A shared object padded with
// distinct symbols ahead of "socket" therefore produced no NET_002 at all, and
// while Bound.Listing was counted as BoundedData the Task 10 fold did not fire on
// it: the package was released as clean with a network symbol in it that no rule
// had been shown.
//
// The first subtest is what makes that a fact rather than an assertion. The same
// fixture with the cap lifted does match NET_002, so the finding's absence under
// the cap is the cap's doing and not a fixture that never carried it.
func TestBinaryScannerCappedListingOnAnExecutableKindWithholdsThePass(t *testing.T) {
	// The padding is what puts the blocking symbol past the cap, and both numbers
	// are chosen so the test does not depend on how many lines a fixture happens
	// to produce: 80 distinct symbols against a 4-line cap leaves "socket" the
	// eighty-first distinct line, far beyond a cutting point the strings pass
	// reaches long before it.
	const (
		padSymbols    = 80
		lineCap       = 4
		paddingPrefix = "pad_symbol_"
	)

	elfWithSocketBehindPadding := func(t *testing.T) []byte {
		t.Helper()
		imports := make([]string, 0, padSymbols+1)
		for i := 0; i < padSymbols; i++ {
			imports = append(imports, fmt.Sprintf("%s%03d", paddingPrefix, i))
		}
		// socket last, so it is the line the cap has to be past for the bypass to
		// be exercised at all.
		imports = append(imports, "socket")
		return elfFixtureBytes(t, elfSpec{imports: imports})
	}

	hasNet002 := func(res *BinaryScanResult) bool {
		for _, f := range res.Findings {
			if f.RuleID == "NET_002" {
				return true
			}
		}
		return false
	}

	t.Run("uncapped, the fixture does carry the blocking finding", func(t *testing.T) {
		dir := t.TempDir()
		writeTestBytes(t, dir, "libnet.so", elfWithSocketBehindPadding(t))

		cfg := DefaultBinaryConfig()
		s, err := newTestBinaryScanner(cfg)
		if err != nil {
			t.Fatal(err)
		}
		res, err := s.ScanDirectory(dir)
		if err != nil {
			t.Fatalf("ScanDirectory: %v", err)
		}
		if !hasNet002(res) {
			t.Fatal("no NET_002 without the cap: the fixture does not carry the finding the capped arms are about")
		}
		if res.Summary.BoundedExecutable != 0 || res.Summary.BoundedData != 0 {
			t.Fatalf("bounds = (%d executable, %d data), want (0, 0): an uncapped read is not bounded",
				res.Summary.BoundedExecutable, res.Summary.BoundedData)
		}
	})

	t.Run("capped, an executable listing withholds the pass", func(t *testing.T) {
		dir := t.TempDir()
		writeTestBytes(t, dir, "libnet.so", elfWithSocketBehindPadding(t))

		cfg := DefaultBinaryConfig()
		cfg.MaxEvidenceLines = lineCap
		s, err := newTestBinaryScanner(cfg)
		if err != nil {
			t.Fatal(err)
		}
		res, err := s.ScanDirectory(dir)
		if err != nil {
			t.Fatalf("ScanDirectory: %v", err)
		}
		if res.Summary.Kinds[string(KindELF)] != 1 || res.Summary.Incomplete != 0 {
			t.Fatalf("fixture shape = %d elf / %d incomplete, want 1 elf and 0 incomplete",
				res.Summary.Kinds[string(KindELF)], res.Summary.Incomplete)
		}
		if res.Summary.BoundedExecutable != 1 || res.Summary.BoundedData != 0 {
			t.Errorf("bounds = (%d executable, %d data), want (1, 0): a capped listing on a format that executes is a look that did not finish",
				res.Summary.BoundedExecutable, res.Summary.BoundedData)
		}
		// The mechanism, pinned rather than assumed: the line socket occupies was
		// refused by the cap, so the rule that exists to catch it was never shown
		// it. If this ever starts passing, the cap stopped being a matcher input
		// and the reasoning above needs to be re-derived.
		if hasNet002(res) {
			t.Error("NET_002 matched a listing the cap cut before socket: the cap is no longer dropping matcher input")
		}
		report := &Report{ScanComplete: true, ProcessExitCode: 0, Binary: &res.Summary}
		if report.ProvesCleanScan() {
			t.Error("ProvesCleanScan = true for a capped executable listing: the package would be released as clean with a blocking-symbol line never matched")
		}
	})

	t.Run("capped, a data listing is still only reported", func(t *testing.T) {
		dir := t.TempDir()
		fill := make([]byte, 0, padSymbols*12)
		for i := 0; i < padSymbols; i++ {
			fill = append(fill, []byte(fmt.Sprintf("%s%03d\x00", paddingPrefix, i))...)
		}
		writeTestBytes(t, dir, "weights.bin", fill)

		cfg := DefaultBinaryConfig()
		cfg.MaxEvidenceLines = lineCap
		s, err := newTestBinaryScanner(cfg)
		if err != nil {
			t.Fatal(err)
		}
		res, err := s.ScanDirectory(dir)
		if err != nil {
			t.Fatalf("ScanDirectory: %v", err)
		}
		if res.Summary.Kinds[string(KindRaw)] != 1 || res.Summary.Incomplete != 0 {
			t.Fatalf("fixture shape = %d raw / %d incomplete, want 1 raw and 0 incomplete",
				res.Summary.Kinds[string(KindRaw)], res.Summary.Incomplete)
		}
		if res.Summary.BoundedData != 1 || res.Summary.BoundedExecutable != 0 {
			t.Errorf("bounds = (%d executable, %d data), want (0, 1): nothing on this platform executes a raw blob, so its capped listing is visible but is not a look that did not finish",
				res.Summary.BoundedExecutable, res.Summary.BoundedData)
		}
		report := &Report{ScanComplete: true, ProcessExitCode: 0, Binary: &res.Summary}
		if !report.ProvesCleanScan() {
			t.Error("ProvesCleanScan = false for a capped data listing: the data bound is reported, not a completeness failure")
		}
	})
}

// TestBinaryScannerClaimsAProtocol01PickleNamedAsWeights runs the claim rule
// through the channel. The file's name is the one the extension set reads as a
// raw blob, so the finding exists only if the interpreter ran.
func TestBinaryScannerClaimsAProtocol01PickleNamedAsWeights(t *testing.T) {
	dir := t.TempDir()
	writeTestBytes(t, dir, "model.bin", []byte("cposix\nsystem\n(Vid\ntR."))

	res, err := NewBinaryScanner(nil, BinaryConfig{}).ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	if res.Summary.Kinds[string(KindPickle)] != 1 {
		t.Errorf("kinds = %v, want one pickle", res.Summary.Kinds)
	}
	// The claim must not, by itself, make the pass unprovable: the stream is a
	// pickle and it parses, so nothing here is a look that did not happen.
	if res.Summary.BoundedExecutable != 0 || res.Summary.BoundedData != 0 || res.Summary.Incomplete != 0 {
		t.Errorf("summary = %+v, want no bounds on a clean parse", res.Summary)
	}
	var found bool
	for _, f := range res.Findings {
		if f.RuleID == "PKL_001" {
			found = true
			if f.Severity != SeverityHigh {
				t.Errorf("PKL_001 severity = %q, want %q", f.Severity, SeverityHigh)
			}
			if f.BinaryKind != string(KindPickle) || f.EvidenceSource != string(SourcePickle) {
				t.Errorf("finding provenance = (%q, %q), want (%q, %q)",
					f.BinaryKind, f.EvidenceSource, KindPickle, SourcePickle)
			}
		}
	}
	if !found {
		t.Errorf("no PKL_001 finding; findings = %+v", res.Findings)
	}
}

// TestBinaryScannerCountsAStreamThatDesynchronisesPastTheHead pins the accepted
// residual of claiming a protocol 0/1 stream by its head: a file that walks
// cleanly across the whole head and then hits an unknown opcode is still
// claimed, and the scanner counts it BoundedExecutable. Withholding is the
// fail-closed answer here, and the bound is in the report rather than silent.
func TestBinaryScannerCountsAStreamThatDesynchronisesPastTheHead(t *testing.T) {
	// A clean prefix: a GLOBAL target, then a MARK and thousands of pushed ints,
	// so the first 4096 bytes are all legal opcodes.
	var b strings.Builder
	b.WriteString("cposix\nsystem\n")
	b.WriteString("(")
	for b.Len() < sniffBytes {
		b.WriteString("I1\n")
	}
	b.WriteString("t")
	b.WriteString("\x00junk")
	dir := t.TempDir()
	writeTestBytes(t, dir, "model.bin", []byte(b.String()))

	res, err := NewBinaryScanner(nil, BinaryConfig{}).ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	if res.Summary.BoundedExecutable != 1 {
		t.Errorf("bounded_executable = %d, want 1: summary = %+v", res.Summary.BoundedExecutable, res.Summary)
	}
}
