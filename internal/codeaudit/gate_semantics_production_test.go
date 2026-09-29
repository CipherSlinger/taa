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

// TestProductionGateSemantics derives the production gate outcome for every
// sample of the six engine-comparison runs, using the real aggregation and
// policy functions rather than a re-implementation.
//
// This exists because the production severity path differs from a static
// reading of the rule table, and reading the rule table got it wrong three
// times. ComputeStatistics does not consume Finding.Severity directly: it
// calls ClassifyFindingRisk, which lets an LLM verdict override the static
// severity (MALICIOUS -> HIGH, SUSPICIOUS -> MEDIUM, BENIGN -> LOW) and only
// falls back to the static severity when no verdict is present. A MEDIUM rule
// hit that the LLM calls MALICIOUS therefore blocks under assist, which blocks
// on HIGH alone.
//
// It is gated behind TAA_PRODUCTION_GATE=1 because it reads benchmark
// artifacts rather than exercising the package, and it writes its result next
// to them so the numbers in the report can be re-derived instead of cited.
func TestProductionGateSemantics(t *testing.T) {
	if os.Getenv("TAA_PRODUCTION_GATE") != "1" {
		t.Skip("set TAA_PRODUCTION_GATE=1 to derive production gate semantics from the run artifacts")
	}

	// The run trees default to the fitting-set results, which is where this test
	// has always read them. The holdout matrix is written inside the benchmark
	// container and has no host path, so the input has to be overridable to
	// derive a holdout reading at all.
	//
	// Re-pointing the input REQUIRES an explicit output. The test writes its
	// result into the tree it derives from, so an input override alone would
	// drop production-gate-semantics.json into a measured matrix and add a file
	// to the artifacts a report cites. That is the same hazard gate_rescore.py
	// guards with a mandatory --out, and it is refused here rather than
	// documented, because the failure is silent and the tree is expensive to
	// rebuild.
	runsRoot := filepath.Join("..", "..", "models", "audit", "audit-results", "engine-compare")
	if v := os.Getenv("TAA_PRODUCTION_GATE_RUNS"); v != "" {
		runsRoot = v
	}
	outPath := filepath.Join(runsRoot, "production-gate-semantics.json")
	if v := os.Getenv("TAA_PRODUCTION_GATE_OUT"); v != "" {
		outPath = v
	} else if os.Getenv("TAA_PRODUCTION_GATE_RUNS") != "" {
		t.Fatalf("TAA_PRODUCTION_GATE_RUNS is set but TAA_PRODUCTION_GATE_OUT is not: "+
			"the result would be written into the tree under measurement (%s); "+
			"point TAA_PRODUCTION_GATE_OUT outside it", runsRoot)
	}
	// Ground-truth labels come from a corpus list when one is supplied. The
	// fitting set marks a benign sample by a B-prefixed directory name, and the
	// holdout uses cq-/dd-/pypi-/sr- identifiers that never match that test, so
	// re-pointing the runs alone labels every holdout sample malicious. The
	// benign denominator then collapses to zero, ratio() returns its zero guard,
	// and the FPR reads 0.0000 out of 0/0 instead of out of a measurement -- a
	// silent failure that presents as a pass. The labels are therefore required
	// as soon as the runs are overridden.
	labels := map[string]string{}
	if v := os.Getenv("TAA_PRODUCTION_GATE_LABELS"); v != "" {
		raw, err := os.ReadFile(v)
		if err != nil {
			t.Fatalf("read labels %s: %v", v, err)
		}
		var doc struct {
			Samples []struct {
				SampleID string `json:"sample_id"`
				Label    string `json:"label"`
			} `json:"samples"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("parse labels %s: %v", v, err)
		}
		for _, s := range doc.Samples {
			labels[s.SampleID] = s.Label
		}
	} else if os.Getenv("TAA_PRODUCTION_GATE_RUNS") != "" {
		t.Fatalf("TAA_PRODUCTION_GATE_RUNS is set but TAA_PRODUCTION_GATE_LABELS is not: " +
			"the fitting-set B-prefix convention does not describe another corpus, " +
			"so every sample would be labelled malicious and FPR would be 0/0")
	}

	// The pattern also matches the manifests and the logs written beside the run
	// directories, so its matches are narrowed to directories. A file match is a
	// zero-sample run, which the zero-denominator guard below rejects.
	matched, err := filepath.Glob(filepath.Join(runsRoot, "*-run*"))
	if err != nil {
		t.Fatalf("glob runs: %v", err)
	}
	var runDirs []string
	for _, m := range matched {
		if fi, err := os.Stat(m); err == nil && fi.IsDir() {
			runDirs = append(runDirs, m)
		}
	}
	if len(runDirs) == 0 {
		t.Fatalf("no run directories under %s", runsRoot)
	}
	sort.Strings(runDirs)

	type sampleOutcome struct {
		SampleID string `json:"sample_id"`
		Label    string `json:"label"`
		Findings int    `json:"findings"`
		High     int    `json:"classified_high"`
		Medium   int    `json:"classified_medium"`
		Low      int    `json:"classified_low"`
		// ConclusionGate/Assist are AuditReport.Conclusion.Passed, which is the
		// value production consumes (controller/import_processing.go:645).
		ConclusionGate   bool `json:"conclusion_passed_gate"`
		ConclusionAssist bool `json:"conclusion_passed_assist"`
		// ReportGate/Assist are Report.Passed as the verifier's recalculators
		// leave it. It can only force the conclusion to false, never true.
		ReportGate   bool `json:"report_passed_gate"`
		ReportAssist bool `json:"report_passed_assist"`
	}
	type runSummary struct {
		Run           string          `json:"run"`
		Samples       int             `json:"samples"`
		GateFPR       float64         `json:"gate_fpr"`
		GateRecall    float64         `json:"gate_recall"`
		AssistFPR     float64         `json:"assist_fpr"`
		AssistRecall  float64         `json:"assist_recall"`
		FinalGateFPR  float64         `json:"final_gate_fpr"`
		FinalGateRec  float64         `json:"final_gate_recall"`
		FinalAssistFP float64         `json:"final_assist_fpr"`
		FinalAssistRe float64         `json:"final_assist_recall"`
		SamplesDetail []sampleOutcome `json:"samples_detail"`
		MissedAssist  []string        `json:"missed_malicious_under_assist"`
		FalseAssist   []string        `json:"blocked_benign_under_assist"`
		// RescuedAssist lists malicious samples whose conclusion under assist
		// would have let them through but whose Report.Passed is false, so the
		// second gate blocks them. They are the reason the conclusion alone
		// scores 0.94-0.98 recall while the final value scores 1.0000, and they
		// are always samples where the LLM downgraded a static HIGH.
		RescuedAssist []string                  `json:"rescued_by_report_gate_under_assist"`
		Stats         map[string]map[string]int `json:"verdict_severity_crosstab"`
	}

	var out []runSummary
	for _, runDir := range runDirs {
		reports, err := filepath.Glob(filepath.Join(runDir, "*", "audit_report.json"))
		if err != nil {
			t.Fatalf("glob reports in %s: %v", runDir, err)
		}
		sort.Strings(reports)

		rs := runSummary{Run: filepath.Base(runDir), Stats: map[string]map[string]int{}}
		var bTotal, mTotal, bBlockGate, mBlockGate, bBlockAssist, mBlockAssist int
		var bFinalGate, mFinalGate, bFinalAssist, mFinalAssist int

		for _, rp := range reports {
			raw, err := os.ReadFile(rp)
			if err != nil {
				t.Fatalf("read %s: %v", rp, err)
			}
			// The report carries the fields the aggregators consume; only
			// file_reports[].findings[] is needed here.
			var doc struct {
				FileReports []struct {
					File     string    `json:"file"`
					Findings []Finding `json:"findings"`
				} `json:"file_reports"`
			}
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatalf("parse %s: %v", rp, err)
			}

			var all []Finding
			var fileReports []FileReport
			for _, fr := range doc.FileReports {
				all = append(all, fr.Findings...)
				fileReports = append(fileReports, BuildFileReport(fr.File, fr.Findings))
			}

			stats := ComputeStatistics(all)

			// Reproduce Report.Passed exactly as the verifier leaves it, for the
			// scan these runs actually were: one that completed and dropped
			// nothing. The fail-closed branches can only set it to false, so
			// these two are the most permissive values for each policy.
			//
			// The completeness fields are set explicitly rather than left at
			// their zero values, and that is load-bearing rather than tidiness.
			// The zero value of ScanComplete means "did not complete", and the
			// pass decision withholds a pass on exactly that, so a report literal
			// that leaves the field unset is the least permissive value, not the
			// most: it blocks every sample and would misreport the production
			// decision as a total denial of service.
			reportGate := &Report{Findings: all, ScanComplete: true}
			recalculateGatePassed(reportGate)
			reportAssist := &Report{Findings: all, ScanComplete: true}
			recalculateStaticPassed(reportAssist)

			ctx := ConclusionContext{HasLLMBenign: true}
			conclGate := ComputeConclusionContext(stats, fileReports, "gate", ctx)
			conclAssist := ComputeConclusionContext(stats, fileReports, "assist", ctx)

			sampleID := filepath.Base(filepath.Dir(rp))
			label, labelled := labels[sampleID]
			if !labelled {
				if len(labels) > 0 {
					t.Fatalf("%s: sample %s is absent from the supplied corpus list; "+
						"falling back to the name convention here would mix two label sources",
						filepath.Base(runDir), sampleID)
				}
				// No corpus list, so fall back to the fitting-set convention: a
				// B-prefixed directory names a benign sample.
				label = "malicious"
				if strings.HasPrefix(sampleID, "B") {
					label = "benign"
				}
			}

			// Final production verdict: the conclusion, forced false by the
			// report value when the verifier's recalculation disagrees.
			finalGate := conclGate.Passed && reportGate.Passed
			finalAssist := conclAssist.Passed && reportAssist.Passed

			so := sampleOutcome{
				SampleID: sampleID, Label: label, Findings: len(all),
				High: stats.High, Medium: stats.Medium, Low: stats.Low,
				ConclusionGate: conclGate.Passed, ConclusionAssist: conclAssist.Passed,
				ReportGate: reportGate.Passed, ReportAssist: reportAssist.Passed,
			}
			rs.SamplesDetail = append(rs.SamplesDetail, so)
			rs.Samples++

			for _, f := range all {
				if rs.Stats[f.Severity] == nil {
					rs.Stats[f.Severity] = map[string]int{}
				}
				v := f.LLMVerdict
				if v == "" {
					v = "<none>"
				}
				rs.Stats[f.Severity][v]++
			}

			if label == "benign" {
				bTotal++
				if !conclGate.Passed {
					bBlockGate++
				}
				if !conclAssist.Passed {
					bBlockAssist++
				}
				if !finalGate {
					bFinalGate++
				}
				if !finalAssist {
					bFinalAssist++
				}
				if !finalAssist {
					rs.FalseAssist = append(rs.FalseAssist, sampleID)
				}
			} else {
				mTotal++
				if !conclGate.Passed {
					mBlockGate++
				}
				if !conclAssist.Passed {
					mBlockAssist++
				}
				if !finalGate {
					mFinalGate++
				}
				if !finalAssist {
					mFinalAssist++
				}
				if finalAssist {
					rs.MissedAssist = append(rs.MissedAssist, sampleID)
				}
				// The conclusion alone would pass this malicious sample; the
				// report gate is what blocks it. This is the second gate doing
				// real work, not a vestigial field.
				if conclAssist.Passed && !reportAssist.Passed {
					rs.RescuedAssist = append(rs.RescuedAssist, sampleID)
				}
			}
		}

		// A run with an empty benign or malicious set cannot produce a rate:
		// ratio() returns its zero guard, and the summary would report 0.0000 for
		// a quantity that was never measured. Refuse to emit that.
		if bTotal == 0 || mTotal == 0 {
			t.Fatalf("%s: %d benign and %d malicious labelled samples; an empty set "+
				"makes FPR or recall a 0/0 zero-guard rather than a measurement",
				rs.Run, bTotal, mTotal)
		}

		ratio := func(num, den int) float64 {
			if den == 0 {
				return 0
			}
			return float64(num) / float64(den)
		}
		rs.GateFPR = ratio(bBlockGate, bTotal)
		rs.GateRecall = ratio(mBlockGate, mTotal)
		rs.AssistFPR = ratio(bBlockAssist, bTotal)
		rs.AssistRecall = ratio(mBlockAssist, mTotal)
		rs.FinalGateFPR = ratio(bFinalGate, bTotal)
		rs.FinalGateRec = ratio(mFinalGate, mTotal)
		rs.FinalAssistFP = ratio(bFinalAssist, bTotal)
		rs.FinalAssistRe = ratio(mFinalAssist, mTotal)
		sort.Strings(rs.MissedAssist)
		sort.Strings(rs.FalseAssist)
		sort.Strings(rs.RescuedAssist)
		out = append(out, rs)

		t.Logf("%s n=%d  conclusion: gate FPR=%.4f recall=%.4f | assist FPR=%.4f recall=%.4f"+
			"  ||  final: gate FPR=%.4f recall=%.4f | assist FPR=%.4f recall=%.4f",
			rs.Run, rs.Samples,
			rs.GateFPR, rs.GateRecall, rs.AssistFPR, rs.AssistRecall,
			rs.FinalGateFPR, rs.FinalGateRec, rs.FinalAssistFP, rs.FinalAssistRe)
		if len(rs.MissedAssist) > 0 {
			t.Logf("  missed under assist: %v", rs.MissedAssist)
		}
		if len(rs.RescuedAssist) > 0 {
			t.Logf("  conclusion would pass, report gate blocks: %v", rs.RescuedAssist)
		}
	}

	blob, err := json.MarshalIndent(map[string]any{
		"source": "internal/codeaudit.TestProductionGateSemantics",
		"note": "ComputeStatistics/ComputeConclusionContext/recalculate* are the real " +
			"production functions. conclusion_passed_* is AuditReport.Conclusion.Passed, " +
			"the value production consumes. report_passed_* is Report.Passed; it can only " +
			"force the conclusion to false, never true, so final <= conclusion.",
		"runs": out,
	}, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	dest := outPath
	if err := os.WriteFile(dest, blob, 0o644); err != nil {
		t.Fatalf("write %s: %v", dest, err)
	}
	fmt.Printf("wrote %s\n", dest)
}
