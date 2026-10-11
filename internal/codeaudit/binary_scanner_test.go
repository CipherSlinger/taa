package codeaudit

import (
	"encoding/binary"
	"os"
	"path/filepath"
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
// is deleted, if the file key is dropped, or if the line key is dropped. It does
// not fail if the rule-id tiebreak is dropped, and that is stated rather than
// implied: the tiebreak only orders findings that share a file and a line, which
// in the scanner means two rules matching one evidence line, and Match returns at
// most one rule per line. The tiebreak is kept for totality, not because this
// test can see it.
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
	// Four HIGH evidence lines (socket/connect -> NET_002, system/popen ->
	// CMD_001) and four LOW ones (the path literals -> FIL_002 / CMD_002). The cap
	// is set below the total so it has to drop something, and the property under
	// test is which something: the LOW findings are the ones a cap may spend.
	//
	// The arithmetic, re-derived against the cap as it now reads. The sort is
	// (File, Line, RuleID) and "extra.bin" sorts before "libevil.so", so the four
	// LOW findings come first and the four HIGH ones after. With the budget at 3
	// the first three lines are kept, the fourth LOW is the one dropped, and the
	// four HIGH findings are kept past the budget: 7 kept, 1 dropped.
	//
	// Those counts happen to be identical to the ones an older cap produced when
	// it exempted HIGH alone, which is why this test cannot tell the two rules
	// apart - its fixture holds no MEDIUM. The sibling test below is the one that
	// does; the pair is needed because a change that re-broke MEDIUM would leave
	// this test green.
	//
	// It matters because a finding that blocks under either policy may not be
	// dropped: HIGH blocks under `assist` and `gate` alike, so a cap that dropped
	// one would turn a withholding package into a passing one - and an attacker
	// could aim at exactly that by padding a package with cheap LOW findings until
	// its HIGH ones fell off the end of the list.
	writeTestBytes(t, dir, "libevil.so", elfFixtureBytes(t, elfSpec{
		imports: []string{"socket", "connect", "system", "popen"},
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
	if highs != 4 {
		t.Errorf("kept %d HIGH findings, want all 4: the cap dropped a blocking finding", highs)
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
// fixture is the shape the host actually has: 21 truncated CUDA/MLX libraries
// under teellm/ and deploy/guest-build/semgrep-payload/rootfs are ~10 MiB on
// disk with their section header table at a ~116 MB offset, so elf.NewFile
// returns EOF. A truncated file is a file that was read and could not be
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
