package mock

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"taa/internal/codeaudit"
	"taa/internal/resource"
)

// sampleRuleIDs runs the full audit over one sample's extracted tree and returns
// the rule ids that fired.
func sampleRuleIDs(t *testing.T, sample auditSample) []string {
	t.Helper()
	archive, err := buildSampleArchive(sample)
	if err != nil {
		t.Fatalf("%s: build archive: %v", sample.RuleID, err)
	}
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "sample.zip")
	if err := os.WriteFile(archivePath, archive, 0o600); err != nil {
		t.Fatalf("%s: write archive: %v", sample.RuleID, err)
	}
	src := filepath.Join(dir, "src")
	if err := resource.ExtractArchiveToDir(src, archivePath); err != nil {
		t.Fatalf("%s: extract: %v", sample.RuleID, err)
	}
	report, err := codeaudit.GenerateAuditReport(context.Background(), src,
		codeaudit.DefaultEngine(),
		codeaudit.AuditConfig{Binary: codeaudit.DefaultBinaryConfig()},
		nil)
	if err != nil {
		t.Fatalf("%s: audit: %v", sample.RuleID, err)
	}
	seen := map[string]bool{}
	for _, file := range report.FileReports {
		for _, finding := range file.Findings {
			seen[finding.RuleID] = true
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// TestAuditSamplesFireTheirRule is the corpus's own contract: a sample exists to
// demonstrate one rule, so an audit of it must report that rule and no other.
// The second half matters as much as the first — a sample that fires an earlier
// rule would leave the rule it names never exercised, which is exactly the
// failure the corpus is meant to rule out.
func TestAuditSamplesFireTheirRule(t *testing.T) {
	for _, sample := range auditSamples() {
		sample := sample
		t.Run(sample.RuleID, func(t *testing.T) {
			ids := sampleRuleIDs(t, sample)
			if sample.RuleID == "clean" {
				if len(ids) != 0 {
					t.Fatalf("control sample fired %v, want nothing", ids)
				}
				return
			}
			if len(ids) != 1 || ids[0] != sample.RuleID {
				t.Fatalf("fired %v, want exactly [%s]", ids, sample.RuleID)
			}
		})
	}
}

// samplesWithoutArchive are the rules the corpus cannot demonstrate, and the
// reason is structural rather than a gap to close later: both are read from a
// real ELF. BIN_001 measures the entropy of an executable section, so a sample
// would have to ship a genuinely packed binary; BIN_002 needs a dynamic symbol
// table naming memfd_create or fexecve. Neither can be written as source text,
// and a hand-built ELF would test the sample builder rather than the rule.
var samplesWithoutArchive = map[string]bool{"BIN_001": true, "BIN_002": true}

// TestAuditSamplesCoverEveryRule ties the corpus to the rule tables: a rule with
// no sample is a rule an operator cannot try from the console, and the two sets
// drifting apart is silent otherwise.
func TestAuditSamplesCoverEveryRule(t *testing.T) {
	covered := map[string]bool{}
	for _, sample := range auditSamples() {
		covered[sample.RuleID] = true
	}
	var missing []string
	for _, rule := range codeaudit.DefaultRules() {
		if !covered[rule.ID] {
			missing = append(missing, rule.ID)
		}
	}
	for _, id := range codeaudit.BinaryRuleIDs() {
		if samplesWithoutArchive[id] {
			continue
		}
		if !covered[id] {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("rules with no sample: %v", missing)
	}
}

// TestSeedAuditSamplesIsIdempotent pins the seeding rule: a restart adds no
// duplicate entry, and every seeded entry is sealed.
func TestSeedAuditSamplesIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	store := newAuditFileStore(dir)
	keys := newWorkbenchKeys(dir)
	if !keys.ready() {
		t.Fatal("workbench keys unavailable")
	}

	seedAuditSamples(store, keys)
	first := store.list()
	if len(first) != len(auditSamples()) {
		t.Fatalf("seeded %d entries, want %d", len(first), len(auditSamples()))
	}
	for _, entry := range first {
		if !entry.Encrypted || entry.DataKeyCipher == "" {
			t.Fatalf("sample %s stored unsealed", entry.Sample)
		}
		if entry.SampleTitle == "" || entry.SampleNote == "" {
			t.Fatalf("sample %s has no title/note", entry.Sample)
		}
	}

	seedAuditSamples(store, keys)
	if second := store.list(); len(second) != len(first) {
		t.Fatalf("second seed grew the file area to %d, want %d", len(second), len(first))
	}
}

// TestSeededSampleOpensThroughTheStore decrypts a seeded entry the way a
// submission does — store, envelope, extraction, audit — so a sealed sample
// proves the whole path and not merely that bytes were written.
func TestSeededSampleOpensThroughTheStore(t *testing.T) {
	dir := t.TempDir()
	store := newAuditFileStore(dir)
	keys := newWorkbenchKeys(dir)
	seedAuditSamples(store, keys)

	entry, srcPath, ok := findSeededSample(store, "NET_001")
	if !ok {
		t.Fatal("NET_001 sample not seeded")
	}
	plainPath := filepath.Join(t.TempDir(), "plain.zip")
	if _, err := keys.openFile(srcPath, plainPath, entry.DataKeyCipher); err != nil {
		t.Fatalf("open seeded sample: %v", err)
	}
	src := filepath.Join(t.TempDir(), "src")
	if err := resource.ExtractArchiveToDir(src, plainPath); err != nil {
		t.Fatalf("extract opened sample: %v", err)
	}
	report, err := codeaudit.GenerateAuditReport(context.Background(), src,
		codeaudit.DefaultEngine(), codeaudit.AuditConfig{}, nil)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	for _, file := range report.FileReports {
		for _, finding := range file.Findings {
			if finding.RuleID == "NET_001" {
				return
			}
		}
	}
	t.Fatalf("opened sample produced no NET_001 finding")
}

func findSeededSample(store *auditFileStore, ruleID string) (auditFileEntry, string, bool) {
	for _, entry := range store.list() {
		if entry.Sample != ruleID {
			continue
		}
		stored, path, ok := store.path(entry.ID)
		if ok {
			return stored, path, true
		}
	}
	return auditFileEntry{}, "", false
}
