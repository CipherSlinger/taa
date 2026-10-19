package codeaudit

import (
	"context"
	"sort"
	"strings"
	"testing"
)

// endToEndConfig is the audit configuration the integration tests share: Tier 1
// only, so a verdict comes from the matchers rather than from a model.
func endToEndConfig() AuditConfig {
	return AuditConfig{
		LLM:    LLMConfig{Enabled: false},
		Binary: DefaultBinaryConfig(),
	}
}

// TestEndToEndMaliciousPackageIsBlocked walks the whole pipeline on a package
// shaped like the ones this feature exists for: ordinary training code, a shared
// object that reaches out, and a checkpoint whose pickle stream executes on load.
//
// The verdict here is over-determined, and the assertions are written knowing
// that: the shared object alone carries four HIGH findings (a packed executable
// section, plus the corroborated presence families), so the pass stays withheld
// even if the checkpoint's arm went silent. What pins each arm is its per-file
// assertion, not the conclusion - drop the container recursion and PKL_001
// disappears from the checkpoint while CRITICAL survives on the strength of the
// shared object. train.py carries no assertion at all: it is here because a real
// package has source next to its binaries, and it produces no finding either way.
func TestEndToEndMaliciousPackageIsBlocked(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", "import torch\n\ndef train():\n    return 1\n")
	writeTestBytes(t, dir, "native/libevil.so", elfFixtureBytes(t, elfSpec{
		imports:  []string{"socket", "connect", "memfd_create"},
		needed:   []string{"libcurl.so.4"},
		text:     uniformBytes(512),
		textExec: true,
	}))
	writeTestBytes(t, dir, "checkpoint.pt", zipFixture(t, map[string][]byte{
		"archive/data.pkl": []byte("\x80\x04cposix\nsystem\n."),
	}, []string{"archive/data.pkl"}))

	audit, err := GenerateAuditReport(context.Background(), dir, DefaultEngine(), endToEndConfig(), nil)
	if err != nil {
		t.Fatalf("GenerateAuditReport: %v", err)
	}

	if audit.Conclusion.Passed {
		t.Fatalf("conclusion Passed = true for a package with a native exfiltration library and an executing checkpoint; summary: %s",
			audit.Conclusion.Summary)
	}
	if audit.Conclusion.RiskLevel != "CRITICAL" {
		t.Errorf("RiskLevel = %s, want CRITICAL", audit.Conclusion.RiskLevel)
	}

	byFile := rulesByFile(audit)
	assertHasRule(t, byFile, "checkpoint.pt", "PKL_001")

	// Severity, not just presence, is what pins each arm's weight. The verdict
	// alone cannot: it is over-determined, so demoting any one arm leaves it
	// CRITICAL on the strength of the others. Asserting the tier each finding
	// lands in is what makes the entropy family, the corroborated presence
	// families and the pickle target each individually load-bearing.
	//
	// The presence families are the interesting half. This file packs its own
	// executable section, which is exactly the independent corroboration the gate
	// waits for, so they must stay at their rule's HIGH. A gate that downgraded
	// everything - or one whose corroboration lookup never matched - would leave
	// the import blocked for the wrong reason and every other assertion green.
	for _, rule := range []string{"BIN_001", "NET_002", "BIN_002"} {
		f, ok := endToEndFinding(audit, "native/libevil.so", rule)
		if !ok {
			t.Fatalf("no %s finding for native/libevil.so; findings: %s", rule, dumpFindings(audit))
		}
		if f.Severity != "HIGH" {
			t.Errorf("%s severity = %s, want HIGH: native/libevil.so carries a high-entropy executable section, "+
				"which is both the packing measurement and the corroboration these families report HIGH on", rule, f.Severity)
		}
		if f.DowngradeReason != "" {
			t.Errorf("%s carries a downgrade reason (%q) in a file that corroborates it", rule, f.DowngradeReason)
		}
	}
	pkl, ok := endToEndFinding(audit, "checkpoint.pt", "PKL_001")
	if !ok {
		t.Fatalf("no PKL_001 finding for checkpoint.pt; findings: %s", dumpFindings(audit))
	}
	if pkl.Severity != "HIGH" {
		t.Errorf("PKL_001 severity = %s, want HIGH: a pickle target that resolves to posix.system is on its own "+
			"enough to refuse the import, and at any lower tier this test stops proving the container recursion reaches the verdict",
			pkl.Severity)
	}

	summary := binarySummary(t, audit)
	if got := summary.Kinds[string(KindELF)]; got != 1 {
		t.Errorf("Binary.Kinds[elf] = %d, want 1", got)
	}
	if got := summary.Kinds[string(KindArchive)]; got != 1 {
		t.Errorf("Binary.Kinds[archive] = %d, want 1", got)
	}
	if summary.FilesCount != 2 {
		t.Errorf("Binary.FilesCount = %d, want 2 (the .so and the .pt; train.py is text)", summary.FilesCount)
	}
}

// TestEndToEndCleanPackageStillPasses is the other half, and the one that decides
// whether the feature is usable. A model package is mostly weights, framework
// imports and ordinary code; if any of those produced a blocking finding the
// channel would be turned off in a week.
//
// It asserts the absence of findings that can block rather than the absence of
// findings, which is what the channel promises and all it promises: the string
// families are LOW by design and do reach the report, so a package full of
// ordinary strings is expected to carry them.
func TestEndToEndCleanPackageStillPasses(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", "import torch\n\ndef train():\n    return 1\n")
	// A shared object with the imports an accelerated kernel actually has, plus a
	// tensor blob that is near-random by nature and must not read as packed code.
	// Neither import here matches a presence pattern, so this fixture does not
	// exercise the corroboration gate - see the gate's own test below.
	writeTestBytes(t, dir, "native/libkernel.so", elfFixtureBytes(t, elfSpec{
		imports: []string{"malloc", "memcpy", "pthread_create", "cblas_sgemm"},
		needed:  []string{"libc.so.6", "libm.so.6", "libgomp.so.1"},
		text:    []byte("ordinary kernel code"),
	}))
	writeTestBytes(t, dir, "weights.safetensors", uniformBytes(4096))

	audit, err := GenerateAuditReport(context.Background(), dir, DefaultEngine(), endToEndConfig(), nil)
	if err != nil {
		t.Fatalf("GenerateAuditReport: %v", err)
	}
	if !audit.Conclusion.Passed {
		t.Fatalf("a clean package was blocked; findings: %s", dumpFindings(audit))
	}
	for _, fr := range audit.FileReports {
		for _, f := range fr.Findings {
			if f.Severity == "HIGH" || f.Severity == "MEDIUM" {
				t.Errorf("%s was reported %s by %s, which blocks under gate; "+
					"a near-random tensor blob and a kernel's ordinary imports must not reach that tier",
					f.File, f.Severity, f.RuleID)
			}
		}
	}
	if got := binarySummary(t, audit).FilesCount; got != 2 {
		t.Errorf("Binary.FilesCount = %d, want 2", got)
	}
}

// TestEndToEndUncorroboratedPresenceStillPasses pins the corroboration gate end
// to end, which is the one shape the other tests cannot reach: a shared object
// whose only evidence is a symbol name.
//
// NET_002 reads .dynsym, and a linker writes every symbol the object might
// reference into it, so the name says the file is able to call socket - not that
// it does. The gate therefore reports it at LOW unless the same file carries
// independent corroboration (a packed executable section, or a pickle target).
// This fixture has neither, so the finding must come out LOW with a reason
// attached, the count must be recorded, and the import must be allowed through.
//
// Arbitration is always gate, so the downgrade has to reach LOW: gate passes on
// High == 0 && Medium == 0, and a MEDIUM downgrade would still refuse the import.
func TestEndToEndUncorroboratedPresenceStillPasses(t *testing.T) {
	dir := t.TempDir()
	writeTestBytes(t, dir, "native/libnet.so", elfFixtureBytes(t, elfSpec{
		imports: []string{"socket"},
		needed:  []string{"libc.so.6"},
		text:    []byte("ordinary code, no packed section"),
	}))

	audit, err := GenerateAuditReport(context.Background(), dir, DefaultEngine(), endToEndConfig(), nil)
	if err != nil {
		t.Fatalf("GenerateAuditReport: %v", err)
	}
	if !audit.Conclusion.Passed {
		t.Fatalf("a shared object whose only evidence is an uncorroborated symbol name was blocked; findings: %s",
			dumpFindings(audit))
	}

	f, ok := endToEndFinding(audit, "native/libnet.so", "NET_002")
	if !ok {
		t.Fatalf("no NET_002 finding for native/libnet.so; the dynsym import did not reach the report at all. findings: %s",
			dumpFindings(audit))
	}
	if f.Severity != "LOW" {
		t.Errorf("NET_002 severity = %s, want LOW: this file carries no corroboration, and %s blocks the import",
			f.Severity, f.Severity)
	}
	if f.DowngradeReason == "" {
		t.Error("NET_002 was reported below its rule's severity with no downgrade reason attached; " +
			"a reader cannot tell 'the rule says LOW' from 'the rule says HIGH and this file did not earn it'")
	}
	if got := binarySummary(t, audit).PresenceDowngraded; got != 1 {
		t.Errorf("Binary.PresenceDowngraded = %d, want 1", got)
	}
}

// TestEndToEndBoundedExecutableBlocks pins the fail-closed direction that is
// easiest to get wrong: a shared object the scan could not finish reading must
// block, because a verdict reached without reading it is not a verdict.
//
// The limit the fixture reaches is MaxStreamBytes, the per-file read budget,
// rather than a per-section cap - there is no per-section cap any more (see
// BinaryConfig), and a section that declares more than the file holds is caught
// by the read-versus-declared comparison instead.
//
// The absence assertion is what makes this test about the budget rather than
// about the file being large: .text here is high-entropy and executable, so if
// the section reader ignored the budget and read the section anyway, BIN_001
// would fire and the file would be refused for being packed instead. Both
// outcomes withhold the pass, so only the absence of the entropy verdict
// distinguishes a scan that stopped short from one that measured everything.
func TestEndToEndBoundedExecutableBlocks(t *testing.T) {
	dir := t.TempDir()
	writeTestBytes(t, dir, "native/libbig.so", elfFixtureBytes(t, elfSpec{
		imports:  []string{"malloc"},
		text:     uniformBytes(4096),
		textExec: true,
	}))

	cfg := endToEndConfig()
	// Only MaxStreamBytes is set: normalizeBinaryConfig resolves every other zero
	// to its default, and Enabled is the one field it cannot touch, so it is
	// spelled out. A zero-valued BinaryConfig would run the channel disabled and
	// this test would then assert a bound nothing produced.
	cfg.Binary = BinaryConfig{
		Enabled:        true,
		MaxStreamBytes: 16, // smaller than the file, so neither pass can finish reading it
	}

	audit, err := GenerateAuditReport(context.Background(), dir, DefaultEngine(), cfg, nil)
	if err != nil {
		t.Fatalf("GenerateAuditReport: %v", err)
	}
	if got := binarySummary(t, audit).BoundedExecutable; got != 1 {
		t.Errorf("BoundedExecutable = %d, want 1", got)
	}
	if audit.Conclusion.Passed {
		t.Error("Passed = true after an executable file could not be read in full; the gap did not reach the verdict")
	}
	if _, ok := endToEndFinding(audit, "native/libbig.so", "BIN_001"); ok {
		t.Error("BIN_001 fired on a file the budget was supposed to stop the section reader from measuring; " +
			"the bound is recorded but the read it bounds did not happen")
	}
}

// rulesByFile indexes the report's rule ids by file, for assertHasRule.
func rulesByFile(audit *AuditReport) map[string][]string {
	byFile := map[string][]string{}
	for _, fr := range audit.FileReports {
		for _, f := range fr.Findings {
			byFile[f.File] = append(byFile[f.File], f.RuleID)
		}
	}
	return byFile
}

// binarySummary returns the binary scan summary, failing the test rather than
// panicking when the channel did not run - a nil deref in three places would
// report the symptom as a crash instead of as the missing pass it is.
func binarySummary(t *testing.T, audit *AuditReport) *BinaryScanSummary {
	t.Helper()
	if audit.ScanMetadata.Binary == nil {
		t.Fatal("ScanMetadata.Binary is nil; the binary channel did not run")
	}
	return audit.ScanMetadata.Binary
}

// findFinding returns the first finding the report carries for the file whose
// path ends in suffix under the given rule.
func endToEndFinding(audit *AuditReport, suffix, rule string) (Finding, bool) {
	for _, fr := range audit.FileReports {
		for _, f := range fr.Findings {
			if strings.HasSuffix(f.File, suffix) && f.RuleID == rule {
				return f, true
			}
		}
	}
	return Finding{}, false
}

func assertHasRule(t *testing.T, byFile map[string][]string, file, rule string) {
	t.Helper()
	var matched []string
	for f := range byFile {
		if strings.HasSuffix(f, file) {
			matched = append(matched, f)
		}
	}
	// Sorted so that a fixture with two files sharing a suffix names the same one
	// on every run; ranging the map directly would make the message - and which
	// file is checked first - depend on map order.
	sort.Strings(matched)
	if len(matched) == 0 {
		t.Errorf("no file report for %s; findings were %v", file, byFile)
		return
	}
	for _, f := range matched {
		for _, r := range byFile[f] {
			if r == rule {
				return
			}
		}
	}
	t.Errorf("no file matching %s carries %s; findings were %v", file, rule, byFile)
}

func dumpFindings(audit *AuditReport) string {
	var b strings.Builder
	for _, fr := range audit.FileReports {
		for _, f := range fr.Findings {
			b.WriteString(f.File + ":" + f.RuleID + ":" + f.Severity + " ")
		}
	}
	return b.String()
}
