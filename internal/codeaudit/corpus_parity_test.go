package codeaudit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

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
// Gated behind TAA_CORPUS_PARITY=1 because it reads benchmark artifacts.
func TestGoEngineMatchesBenchmarkRegexArm(t *testing.T) {
	if os.Getenv("TAA_CORPUS_PARITY") != "1" {
		t.Skip("set TAA_CORPUS_PARITY=1 to compare the production engine against the benchmark's regex arm")
	}

	corpusRoot := filepath.Join("..", "..", "models", "audit", "benchmarks", "audit-100")
	artifacts := filepath.Join("..", "..", "models", "audit", "audit-results", "engine-compare", "regex-run1")

	sampleDirs, err := filepath.Glob(filepath.Join(corpusRoot, "*", "*"))
	if err != nil {
		t.Fatalf("glob corpus: %v", err)
	}
	if len(sampleDirs) == 0 {
		t.Fatalf("no samples under %s", corpusRoot)
	}
	sort.Strings(sampleDirs)

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
	dest := filepath.Join("..", "..", "models", "audit", "audit-results", "engine-compare", "corpus-parity-go-vs-python-regex.json")
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
