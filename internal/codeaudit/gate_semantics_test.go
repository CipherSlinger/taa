package codeaudit

import (
	"testing"

	"github.com/CipherSlinger/teellm"
)

// The production decision is the classified check over the statistics, where
// ClassifyFindingRisk lets an LLM verdict override the static severity
// (MALICIOUS -> HIGH, SUSPICIOUS -> MEDIUM, BENIGN -> LOW). A SUSPICIOUS
// verdict on a presence-only rule (CMD_001 / DYN_001) with no corroborating
// evidence is the one exception: it is demoted to LOW.
//
//	final = gateCheck(classified)
//
// Report.Passed still exists and still folds in the completeness precondition,
// but the audit conclusion no longer ANDs it: scan gaps are advisory follow-up
// items (see buildScanGapNote), not a verdict. The report half is kept in this
// helper so the tests below can still pin the static-severity arbitration that
// drives it, and to show that it does not change the final result.
//
// The classified half is the only thing that blocks a static MEDIUM the LLM
// escalated; the report half lets an LLM BENIGN verdict clear a static HIGH.
// These tests pin the composition, not either function in isolation.

// productionDecision mirrors the production path for one scanned sample.
// conclusionOnly is what the gate check alone decides; final is what production
// actually consumes (import_processing.go takes Conclusion.Passed).
func productionDecision(findings []Finding) (conclusionOnly, reportPassed, final bool) {
	// ScanComplete models the engine having stamped a completed scan. It is not
	// optional detail: the pass decision withholds a pass from a report that
	// cannot prove it looked, and the field's zero value means "did not
	// complete", so a bare literal would decide every sample as blocked.
	report := &Report{Findings: findings, ScanComplete: true}
	recalculateGatePassed(report)

	stats := ComputeStatistics(findings)
	fileReports := []FileReport{BuildFileReport("sample.py", findings)}

	conclusionOnly = ComputeConclusionContext(stats, fileReports, ConclusionContext{
		HasLLMBenign: true,
	}).Passed

	// The conclusion is taken from the classified findings alone.
	final = conclusionOnly

	return conclusionOnly, report.Passed, final
}

func finding(ruleID, severity, verdict string) Finding {
	return Finding{
		File:       "sample.py",
		Line:       7,
		RuleID:     ruleID,
		Severity:   severity,
		LLMVerdict: verdict,
	}
}

// TestGateLLMBenignClearsStaticHigh pins the arbitration the deployment relies
// on: a static HIGH no longer blocks by itself. The LLM's BENIGN verdict decides
// it, and both halves of the decision must agree.
func TestGateLLMBenignClearsStaticHigh(t *testing.T) {
	findings := []Finding{finding("CMD_001", SeverityHigh, teellm.VerdictBenign)}

	conclusionOnly, reportPassed, final := productionDecision(findings)

	if !conclusionOnly {
		t.Error("classified check blocked a static HIGH the LLM called BENIGN")
	}
	if !reportPassed {
		t.Error("Report.Passed = false for a static HIGH the LLM called BENIGN; the verdict must decide it")
	}
	if !final {
		t.Error("final = false for a static HIGH the LLM called BENIGN; the LLM verdict must decide the outcome")
	}
}

// TestGateStaticHighNonBenignBlocks is the other half: every verdict other than
// BENIGN leaves a static HIGH blocking, including UNCERTAIN and no verdict at
// all (the LLM was not consulted). NET_001 is the carrier here rather than
// CMD_001 because a SUSPICIOUS verdict on the presence-only families is
// demoted to LOW; TestPresenceOnlySuspiciousDemotesToLow pins that exception.
func TestGateStaticHighNonBenignBlocks(t *testing.T) {
	for _, verdict := range []string{
		teellm.VerdictMalicious,
		teellm.VerdictSuspicious,
		teellm.VerdictUncertain,
		"",
	} {
		t.Run(verdict, func(t *testing.T) {
			findings := []Finding{finding("NET_001", SeverityHigh, verdict)}

			_, _, final := productionDecision(findings)

			if final {
				t.Errorf("final = true for a static HIGH with verdict %q; only BENIGN may clear it", verdict)
			}
		})
	}
}

// TestStaticSeverityFollowsVerdict pins both directions of the arbitration for
// the static severities that do not block on their own. BENIGN lowers either to
// LOW and passes, while every other verdict replaces the static severity, so a
// static LOW the LLM calls MALICIOUS blocks and a static MEDIUM only clears on
// BENIGN. The empty verdict is the static fallback.
func TestStaticSeverityFollowsVerdict(t *testing.T) {
	cases := []struct {
		name     string
		ruleID   string
		severity string
		want     map[string]bool
	}{
		{"medium", "ENV_001", SeverityMedium, map[string]bool{
			teellm.VerdictMalicious:  false, // classified HIGH
			teellm.VerdictSuspicious: false, // classified MEDIUM
			teellm.VerdictBenign:     true,  // classified LOW
			teellm.VerdictUncertain:  false, // classified MEDIUM
			"":                       false, // static fallback: MEDIUM
		}},
		{"low", "CMD_002", SeverityLow, map[string]bool{
			teellm.VerdictMalicious:  false, // classified HIGH
			teellm.VerdictSuspicious: false, // classified MEDIUM
			teellm.VerdictBenign:     true,  // classified LOW
			teellm.VerdictUncertain:  false, // classified MEDIUM
			"":                       true,  // static fallback: LOW
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for verdict, want := range tc.want {
				t.Run(verdict, func(t *testing.T) {
					findings := []Finding{finding(tc.ruleID, tc.severity, verdict)}

					conclusionOnly, reportPassed, final := productionDecision(findings)

					if !reportPassed {
						t.Fatalf("Report.Passed = false for a %s finding with verdict %q; "+
							"the report gate has no reason to withhold here", tc.severity, verdict)
					}
					if conclusionOnly != want {
						t.Errorf("conclusion only = %v, want %v", conclusionOnly, want)
					}
					if final != want {
						t.Errorf("final = %v, want %v", final, want)
					}
				})
			}
		})
	}
}
