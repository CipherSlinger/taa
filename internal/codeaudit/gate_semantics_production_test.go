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

	runsRoot := filepath.Join("..", "..", "models", "audit", "audit-results", "engine-compare")
	runDirs, err := filepath.Glob(filepath.Join(runsRoot, "*-run*"))
	if err != nil {
		t.Fatalf("glob runs: %v", err)
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
		Run           string                    `json:"run"`
		Samples       int                       `json:"samples"`
		GateFPR       float64                   `json:"gate_fpr"`
		GateRecall    float64                   `json:"gate_recall"`
		AssistFPR     float64                   `json:"assist_fpr"`
		AssistRecall  float64                   `json:"assist_recall"`
		FinalGateFPR  float64                   `json:"final_gate_fpr"`
		FinalGateRec  float64                   `json:"final_gate_recall"`
		FinalAssistFP float64                   `json:"final_assist_fpr"`
		FinalAssistRe float64                   `json:"final_assist_recall"`
		SamplesDetail []sampleOutcome           `json:"samples_detail"`
		MissedAssist  []string                  `json:"missed_malicious_under_assist"`
		FalseAssist   []string                  `json:"blocked_benign_under_assist"`
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

			// Reproduce Report.Passed exactly as the verifier leaves it. The
			// fail-closed branches can only set it to false, so these two are
			// the most permissive values for each policy.
			reportGate := &Report{Findings: all}
			recalculatePassed(reportGate)
			reportAssist := &Report{Findings: all}
			recalculateStaticPassed(reportAssist)

			ctx := ConclusionContext{HasLLMBenign: true}
			conclGate := ComputeConclusionContext(stats, fileReports, "gate", ctx)
			conclAssist := ComputeConclusionContext(stats, fileReports, "assist", ctx)

			sampleID := filepath.Base(filepath.Dir(rp))
			label := "malicious"
			if strings.HasPrefix(sampleID, "B") {
				label = "benign"
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
	dest := filepath.Join(runsRoot, "production-gate-semantics.json")
	if err := os.WriteFile(dest, blob, 0o644); err != nil {
		t.Fatalf("write %s: %v", dest, err)
	}
	fmt.Printf("wrote %s\n", dest)
}
