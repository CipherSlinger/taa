package codeaudit

import (
	"context"
	"strings"
	"testing"
)

// TestEndToEndMaliciousPackageIsBlocked walks the whole pipeline on a package
// shaped like the ones this feature exists for: ordinary training code, a shared
// object that reaches out, and a checkpoint whose pickle stream executes on load.
//
// Every one of the three parts is load-bearing. The source file proves the
// channel did not replace the source engines; the shared object proves the
// dynamic symbol evidence reaches the verdict; the checkpoint proves the
// container recursion does. A pass that got the verdict right by another route
// would still fail this test on the per-file assertions.
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

	cfg := AuditConfig{
		LLM:    LLMConfig{Enabled: false, Policy: "assist"},
		Binary: DefaultBinaryConfig(),
	}
	audit, err := GenerateAuditReport(context.Background(), dir, DefaultEngine(), cfg, nil)
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

	byFile := map[string][]string{}
	for _, fr := range audit.FileReports {
		for _, f := range fr.Findings {
			byFile[f.File] = append(byFile[f.File], f.RuleID)
		}
	}
	assertHasRule(t, byFile, "native/libevil.so", "NET_002")
	assertHasRule(t, byFile, "native/libevil.so", "BIN_002")
	assertHasRule(t, byFile, "checkpoint.pt", "PKL_001")

	if audit.ScanMetadata.Binary == nil {
		t.Fatal("ScanMetadata.Binary is nil")
	}
	if got := audit.ScanMetadata.Binary.Kinds[string(KindELF)]; got != 1 {
		t.Errorf("Binary.Kinds[elf] = %d, want 1", got)
	}
	if got := audit.ScanMetadata.Binary.Kinds[string(KindArchive)]; got != 1 {
		t.Errorf("Binary.Kinds[archive] = %d, want 1", got)
	}
	if audit.ScanMetadata.Binary.FilesCount != 2 {
		t.Errorf("Binary.FilesCount = %d, want 2 (the .so and the .pt; train.py is text)", audit.ScanMetadata.Binary.FilesCount)
	}
}

// TestEndToEndCleanPackageStillPasses is the other half, and the one that decides
// whether the feature is usable. A model package is mostly weights, framework
// imports and ordinary code; if any of those produced a blocking finding the
// channel would be turned off in a week.
func TestEndToEndCleanPackageStillPasses(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", "import torch\n\ndef train():\n    return 1\n")
	// A shared object with the imports an accelerated kernel actually has, plus a
	// tensor blob that is near-random by nature and must not read as packed code.
	writeTestBytes(t, dir, "native/libkernel.so", elfFixtureBytes(t, elfSpec{
		imports: []string{"malloc", "memcpy", "pthread_create", "cblas_sgemm"},
		needed:  []string{"libc.so.6", "libm.so.6", "libgomp.so.1"},
		text:    []byte("ordinary kernel code"),
	}))
	writeTestBytes(t, dir, "weights.safetensors", uniformBytes(4096))

	cfg := AuditConfig{
		LLM:    LLMConfig{Enabled: false, Policy: "assist"},
		Binary: DefaultBinaryConfig(),
	}
	audit, err := GenerateAuditReport(context.Background(), dir, DefaultEngine(), cfg, nil)
	if err != nil {
		t.Fatalf("GenerateAuditReport: %v", err)
	}
	if !audit.Conclusion.Passed {
		t.Fatalf("a clean package was blocked; findings: %s", dumpFindings(audit))
	}
	if audit.ScanMetadata.Binary.FilesCount != 2 {
		t.Errorf("Binary.FilesCount = %d, want 2", audit.ScanMetadata.Binary.FilesCount)
	}
}

// TestEndToEndBoundedExecutableBlocks pins the fail-closed direction that is
// easiest to get wrong: a shared object the scan could not finish reading must
// block, because a verdict reached without reading it is not a verdict.
//
// The limit the fixture reaches is MaxStreamBytes, the per-file read budget,
// rather than a per-section cap - there is no per-section cap any more (see
// BinaryConfig), and a section that declares more than the file holds is caught
// by the read-versus-declared comparison instead. Setting the budget below the
// file size is what makes both readers stop early: the strings pass records the
// budget bound, and the section read comes up short of .text's declared size and
// records the same fact from the other side. Either way the file is a bounded
// executable, and a bounded executable withholds the pass.
func TestEndToEndBoundedExecutableBlocks(t *testing.T) {
	dir := t.TempDir()
	writeTestBytes(t, dir, "native/libbig.so", elfFixtureBytes(t, elfSpec{
		imports:  []string{"malloc"},
		text:     uniformBytes(4096),
		textExec: true,
	}))

	cfg := AuditConfig{
		LLM: LLMConfig{Enabled: false, Policy: "assist"},
		Binary: BinaryConfig{
			Enabled:        true,
			MaxStreamBytes: 16, // smaller than the file, so neither pass can finish reading it
		},
	}
	audit, err := GenerateAuditReport(context.Background(), dir, DefaultEngine(), cfg, nil)
	if err != nil {
		t.Fatalf("GenerateAuditReport: %v", err)
	}
	if audit.ScanMetadata.Binary.BoundedExecutable != 1 {
		t.Errorf("BoundedExecutable = %d, want 1", audit.ScanMetadata.Binary.BoundedExecutable)
	}
	if audit.Conclusion.Passed {
		t.Error("Passed = true after an executable file could not be read in full; the gap did not reach the verdict")
	}
}

func assertHasRule(t *testing.T, byFile map[string][]string, file, rule string) {
	t.Helper()
	for f, rules := range byFile {
		if !strings.HasSuffix(f, file) {
			continue
		}
		for _, r := range rules {
			if r == rule {
				return
			}
		}
		t.Errorf("%s has rules %v, want %s among them", f, rules, rule)
		return
	}
	t.Errorf("no file report for %s; findings were %v", file, byFile)
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
