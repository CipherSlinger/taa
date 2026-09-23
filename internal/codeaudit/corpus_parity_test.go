package codeaudit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The two inputs the comparison is keyed on, overridable from the environment.
//
// They are parameterized because the proof has to be run more than once. The
// evidence was gathered on the synthetic benchmark, which is the fitting set,
// and a held-out corpus is being built separately: it lives at another root and
// may be laid out at another depth. Baking either one in would make the proof
// unrunnable on the corpus that decides whether the engine may be swapped.
const (
	parityCorpusRootEnv = "TAA_PARITY_CORPUS_ROOT"
	parityResultsDirEnv = "TAA_PARITY_RESULTS_DIR"

	// Defaults keep the test on the corpus and the artifacts the existing
	// evidence came from when the variables are unset.
	defaultParityCorpusRoot = "../../models/audit/benchmarks/audit-100"
	defaultParityResultsDir = "../../models/audit/audit-results/engine-compare/regex-run1"
)

// paritySkipDirs is the set of directory names the corpus walk never treats as a
// sample or descends through: the scanner's own skip set, which already covers
// .git and __pycache__, plus any dot-directory. Sharing the scanner's set means a
// directory the engine refuses to read cannot be mistaken here for a sample.
var paritySkipDirs = DefaultConfig().SkipDirs

// paritySkipDir reports whether name is a directory the corpus walk ignores.
func paritySkipDir(name string) bool {
	return strings.HasPrefix(name, ".") || paritySkipDirs[name]
}

// envOrDefault returns the environment value for key, or fallback when unset.
func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// findSampleDirs returns the sample directories under root.
//
// Two layouts are supported because two corpora are: the synthetic benchmark
// nests samples as <root>/<project>/<sample_id>/, while a corpus whose samples
// are not grouped into projects places them directly as <root>/<sample_id>/.
//
// Which one a directory is has to be inferred from its shape, since the corpus
// itself says nothing. A directory that holds a file the scanner would read is a
// sample whatever else it holds: samples in the synthetic benchmark carry a
// data/ subdirectory, and reading those as containers would compare a corpus
// against nothing. A directory holding no source file and no subdirectory is a
// sample too, rather than being dropped for looking empty: a skipped sample is a
// sample the zero-divergence claim does not cover, and an empty one is still
// comparable, since both sides report zero findings for it.
//
// A missing root is not an error. It yields no samples, which the caller reports
// as an empty corpus exactly as it did before.
func findSampleDirs(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var samples []string
	for _, entry := range entries {
		if !entry.IsDir() || paritySkipDir(entry.Name()) {
			continue
		}
		top := filepath.Join(root, entry.Name())
		container, err := isSampleContainer(top)
		if err != nil {
			return nil, err
		}
		if !container {
			samples = append(samples, top)
			continue
		}
		children, err := os.ReadDir(top)
		if err != nil {
			return nil, err
		}
		for _, child := range children {
			if !child.IsDir() || paritySkipDir(child.Name()) {
				continue
			}
			samples = append(samples, filepath.Join(top, child.Name()))
		}
	}
	sort.Strings(samples)
	return samples, nil
}

// isSampleContainer reports whether dir holds samples rather than being one.
func isSampleContainer(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	scanner := DefaultScanner()
	hasSubdir := false
	for _, entry := range entries {
		if !entry.IsDir() {
			// The extension test is the scanner's own, so what counts as a
			// sample here cannot drift from what the engine scans.
			if scanner.hasMatchingExtension(entry.Name()) {
				return false, nil
			}
			continue
		}
		if !paritySkipDir(entry.Name()) {
			hasSubdir = true
		}
	}
	return hasSubdir, nil
}

// The engine-comparison evidence was gathered with the Python scanner
// (models/examples/code_security_analyzer.py). Production Tier 1 is this
// package. Non-inferiority only transfers between them if they are the same
// scanner, and that is an execution question rather than a reading question:
// the two rule tables are maintained separately and can drift.
//
// This test answers it by running the production engine over the same corpus
// the evidence used and comparing finding multisets per sample against the
// regex arm's own artifacts. It is the check that the measured baseline is the
// baseline production actually runs.
//
// TAA_PARITY_CORPUS_ROOT and TAA_PARITY_RESULTS_DIR point the comparison at
// another corpus and the artifacts a run over it produced, which is how the same
// proof is repeated on the held-out corpus. Unset, both stay on audit-100 and
// the regex arm's run 1.
//
// Gated behind TAA_CORPUS_PARITY=1 because it reads benchmark artifacts.
func TestGoEngineMatchesBenchmarkRegexArm(t *testing.T) {
	if os.Getenv("TAA_CORPUS_PARITY") != "1" {
		t.Skip("set TAA_CORPUS_PARITY=1 to compare the production engine against the benchmark's regex arm")
	}

	corpusRoot := envOrDefault(parityCorpusRootEnv, defaultParityCorpusRoot)
	artifacts := envOrDefault(parityResultsDirEnv, defaultParityResultsDir)

	sampleDirs, err := findSampleDirs(corpusRoot)
	if err != nil {
		t.Fatalf("list corpus %s: %v", corpusRoot, err)
	}
	if len(sampleDirs) == 0 {
		t.Fatalf("no samples under %s", corpusRoot)
	}

	type sampleDiff struct {
		Sample       string   `json:"sample"`
		GoFindings   int      `json:"go_findings"`
		PyFindings   int      `json:"python_findings"`
		OnlyGo       []string `json:"only_in_go"`
		OnlyPython   []string `json:"only_in_python"`
		LineMismatch []string `json:"line_mismatches,omitempty"`
	}

	var (
		matched    int
		diffs      []sampleDiff
		ruleTally  = map[string]map[string]int{} // rule id -> direction -> count
		filesDiff  []string
		lineOnlyOn int
	)
	noteRule := func(rule, direction string) {
		if ruleTally[rule] == nil {
			ruleTally[rule] = map[string]int{}
		}
		ruleTally[rule][direction]++
	}

	for _, sampleDir := range sampleDirs {
		sampleID := filepath.Base(sampleDir)

		goReport, err := DefaultEngine().ScanDirectory(sampleDir)
		if err != nil {
			t.Fatalf("go scan %s: %v", sampleID, err)
		}

		raw, err := os.ReadFile(filepath.Join(artifacts, sampleID, "audit_report.json"))
		if err != nil {
			t.Fatalf("read artifact for %s: %v", sampleID, err)
		}
		var doc struct {
			FileReports []struct {
				Findings []Finding `json:"findings"`
			} `json:"file_reports"`
			Target struct {
				FilesScanned int `json:"files_scanned"`
			} `json:"target"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("parse artifact for %s: %v", sampleID, err)
		}

		goFindings := goReport.Findings
		var pyFindings []Finding
		for _, fr := range doc.FileReports {
			pyFindings = append(pyFindings, fr.Findings...)
		}

		// A finding's identity here is the rule that fired and the severity it
		// fired at: those are what both gates are keyed on. Lines are compared
		// separately so that a line-number convention difference cannot
		// masquerade as a rule difference.
		goCounts := multiset(goFindings)
		pyCounts := multiset(pyFindings)

		var onlyGo, onlyPy, lineMismatch []string
		for k, n := range goCounts {
			if d := n - pyCounts[k]; d > 0 {
				onlyGo = append(onlyGo, fmt.Sprintf("%s/%s x%d", k.RuleID, k.Severity, d))
				noteRule(k.RuleID, "only_in_go")
			}
		}
		for k, n := range pyCounts {
			if d := n - goCounts[k]; d > 0 {
				onlyPy = append(onlyPy, fmt.Sprintf("%s/%s x%d", k.RuleID, k.Severity, d))
				noteRule(k.RuleID, "only_in_python")
			}
		}
		goLines, pyLines := linesByKey(goFindings), linesByKey(pyFindings)
		for k, gl := range goLines {
			if pl, ok := pyLines[k]; !ok || fmt.Sprint(gl) != fmt.Sprint(pl) {
				lineMismatch = append(lineMismatch, fmt.Sprintf("%s/%s go=%v py=%v", k.RuleID, k.Severity, gl, pl))
			}
		}
		sort.Strings(onlyGo)
		sort.Strings(onlyPy)
		sort.Strings(lineMismatch)

		if goReport.FilesCount != doc.Target.FilesScanned {
			filesDiff = append(filesDiff, fmt.Sprintf("%s go=%d py=%d", sampleID, goReport.FilesCount, doc.Target.FilesScanned))
		}

		if len(onlyGo) == 0 && len(onlyPy) == 0 {
			matched++
			if len(lineMismatch) > 0 {
				lineOnlyOn++
			}
			continue
		}
		diffs = append(diffs, sampleDiff{
			Sample: sampleID, GoFindings: len(goFindings), PyFindings: len(pyFindings),
			OnlyGo: onlyGo, OnlyPython: onlyPy, LineMismatch: lineMismatch,
		})
	}

	t.Logf("samples=%d  identical rule/severity multiset=%d  divergent=%d  (of the identical, %d differ on line numbers only)",
		len(sampleDirs), matched, len(diffs), lineOnlyOn)
	if len(filesDiff) > 0 {
		t.Logf("files_scanned differs on %d samples: %v", len(filesDiff), filesDiff)
	}
	for _, d := range diffs {
		t.Logf("  %s: go=%d py=%d  only-go=%v only-py=%v", d.Sample, d.GoFindings, d.PyFindings, d.OnlyGo, d.OnlyPython)
	}
	for _, rule := range sortedKeys(ruleTally) {
		t.Logf("  rule %s: %v", rule, ruleTally[rule])
	}

	// Assert rather than only report: the first run of this test found eight
	// divergent samples and passed anyway, which is how a real recall hole
	// (ENV_001 missing upper-case names) stayed invisible. A divergence here
	// means the evidence describes an engine other than the one production
	// runs, so it must fail loudly.
	if len(diffs) > 0 {
		t.Errorf("production engine diverges from the benchmark's regex arm on %d/%d samples across %d rules; "+
			"the non-inferiority evidence would not describe the engine production runs",
			len(diffs), len(sampleDirs), len(ruleTally))
	}
	if lineOnlyOn > 0 {
		t.Errorf("%d samples agree on rules but differ on line numbers, which the LLM context window is built from", lineOnlyOn)
	}
	if len(filesDiff) > 0 {
		t.Errorf("files_scanned differs on %d samples: %v", len(filesDiff), filesDiff)
	}

	blob, err := json.MarshalIndent(map[string]any{
		"source": "internal/codeaudit.TestGoEngineMatchesBenchmarkRegexArm",
		"note": "Compares the production Go engine (internal/codeaudit) against the regex arm's own " +
			"artifacts, which the Python scanner (models/examples/code_security_analyzer.py) produced. " +
			"Equal multisets mean the measured baseline is the baseline production runs.",
		"samples":                  len(sampleDirs),
		"identical":                matched,
		"divergent":                len(diffs),
		"line_number_only_diffs":   lineOnlyOn,
		"rule_directions":          ruleTally,
		"files_scanned_mismatches": filesDiff,
		"details":                  diffs,
	}, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Written beside the results directory it was computed from rather than at a
	// fixed path: a run against another corpus now produces its own report
	// instead of overwriting this corpus's evidence. The default resolves to the
	// same file it always did.
	dest := filepath.Join(filepath.Dir(artifacts), "corpus-parity-go-vs-python-regex.json")
	if err := os.WriteFile(dest, blob, 0o644); err != nil {
		t.Fatalf("write %s: %v", dest, err)
	}
	fmt.Printf("wrote %s\n", dest)
}

// findingKey is the identity used for the multiset comparison: the rule that
// fired and the severity it fired at, which is what the gates are keyed on.
type findingKey struct {
	RuleID   string
	Severity string
}

func multiset(fs []Finding) map[findingKey]int {
	m := map[findingKey]int{}
	for _, f := range fs {
		m[findingKey{f.RuleID, f.Severity}]++
	}
	return m
}

func linesByKey(fs []Finding) map[findingKey][]int {
	m := map[findingKey][]int{}
	for _, f := range fs {
		k := findingKey{f.RuleID, f.Severity}
		m[k] = append(m[k], f.Line)
	}
	for _, v := range m {
		sort.Ints(v)
	}
	return m
}

func sortedKeys(m map[string]map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
