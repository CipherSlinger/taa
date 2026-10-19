package codeaudit

import (
	"testing"

	"github.com/CipherSlinger/teellm"
)

// The production decision is the AND of two checks that are keyed on different
// severities:
//
//  1. the check over the *classified* statistics, where ClassifyFindingRisk lets
//     an LLM verdict override the static severity (MALICIOUS -> HIGH,
//     SUSPICIOUS -> MEDIUM, BENIGN -> LOW);
//  2. Report.Passed, which the verifier leaves keyed on the *static* severity,
//     and which AssembleAuditReport copies into ConclusionContext.ScanPassed.
//
//	final = gateCheck(classified) && reportPassed(static)
//
// The classified half is the only thing that blocks a static MEDIUM the LLM
// escalated; the report half lets an LLM BENIGN verdict clear a static HIGH.
// These tests pin the composition, not either function in isolation.

// productionDecision mirrors the production path for one scanned sample.
// conclusionOnly is what the gate check alone decides; final is what production
// actually consumes (import_processing.go takes Conclusion.Passed), which also
// ANDs in Report.Passed via ScanPassed.
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

	sp := report.Passed
	final = ComputeConclusionContext(stats, fileReports, ConclusionContext{
		HasLLMBenign: true,
		ScanPassed:   &sp,
	}).Passed

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
// all (the LLM was not consulted).
func TestGateStaticHighNonBenignBlocks(t *testing.T) {
	for _, verdict := range []string{
		teellm.VerdictMalicious,
		teellm.VerdictSuspicious,
		teellm.VerdictUncertain,
		"",
	} {
		t.Run(verdict, func(t *testing.T) {
			findings := []Finding{finding("CMD_001", SeverityHigh, verdict)}

			_, _, final := productionDecision(findings)

			if final {
				t.Errorf("final = true for a static HIGH with verdict %q; only BENIGN may clear it", verdict)
			}
		})
	}
}

// TestGateStaticMediumFollowsVerdict pins that the LLM also decides a static
// MEDIUM: BENIGN lowers it to LOW and passes, any other verdict leaves it
// classified at MEDIUM and blocks.
func TestGateStaticMediumFollowsVerdict(t *testing.T) {
	cases := []struct {
		verdict string
		want    bool
	}{
		{teellm.VerdictMalicious, false},  // classified HIGH
		{teellm.VerdictSuspicious, false}, // classified MEDIUM
		{teellm.VerdictBenign, true},      // classified LOW
		{teellm.VerdictUncertain, false},  // classified MEDIUM
		{"", false},                       // static fallback: MEDIUM
	}

	for _, tc := range cases {
		t.Run(tc.verdict, func(t *testing.T) {
			findings := []Finding{finding("ENV_001", SeverityMedium, tc.verdict)}

			conclusionOnly, _, final := productionDecision(findings)

			if conclusionOnly != tc.want {
				t.Errorf("conclusion only = %v, want %v", conclusionOnly, tc.want)
			}
			if final != tc.want {
				t.Errorf("final = %v, want %v", final, tc.want)
			}
		})
	}
}

// TestGateStaticLowFollowsVerdict pins the escalation direction: a static LOW is
// harmless unless the LLM raises it.
func TestGateStaticLowFollowsVerdict(t *testing.T) {
	cases := []struct {
		verdict string
		want    bool
	}{
		{teellm.VerdictMalicious, false},  // classified HIGH
		{teellm.VerdictSuspicious, false}, // classified MEDIUM
		{teellm.VerdictBenign, true},      // classified LOW
		{teellm.VerdictUncertain, false},  // classified MEDIUM
		{"", true},                        // static fallback: LOW
	}

	for _, tc := range cases {
		t.Run(tc.verdict, func(t *testing.T) {
			findings := []Finding{finding("CMD_002", SeverityLow, tc.verdict)}

			_, _, final := productionDecision(findings)

			if final != tc.want {
				t.Errorf("final = %v, want %v for verdict %q", final, tc.want, tc.verdict)
			}
		})
	}
}
