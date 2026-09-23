package codeaudit

import (
	"testing"

	"github.com/CipherSlinger/teellm"
)

// The production decision is the AND of two checks that are keyed on different
// severities:
//
//  1. the policy check over the *classified* statistics, where
//     ClassifyFindingRisk lets an LLM verdict override the static severity
//     (MALICIOUS -> HIGH, SUSPICIOUS -> MEDIUM, BENIGN -> LOW);
//  2. Report.Passed, which the verifier leaves keyed on the *static* severity,
//     and which AssembleAuditReport copies into ConclusionContext.ScanPassed.
//
//	final = policyCheck(classified, policy) && reportPassed(static)
//
// Neither half is meaningful alone. The classified half is the only thing that
// blocks a static MEDIUM the LLM escalated; the static half is the only thing
// that blocks a static HIGH the LLM downgraded. In the six-round benchmark the
// static half is what keeps recall at 1.0000 under the production default
// policy: without it, the fifteen samples listed in REPORT.md 7.5 whose static
// HIGH the LLM called SUSPICIOUS would be missed.
//
// These tests therefore pin the composition, not either function in isolation.

// productionDecision mirrors the production path for one scanned sample.
// conclusionOnly is what the policy check alone decides; final is what
// production actually consumes (import_processing.go:645 takes
// Conclusion.Passed), which also ANDs in Report.Passed via ScanPassed.
func productionDecision(findings []Finding, policy string) (conclusionOnly, reportPassed, final bool) {
	report := &Report{Findings: findings}
	if policy == "gate" {
		recalculateGatePassed(report)
	} else {
		recalculateStaticPassed(report)
	}

	stats := ComputeStatistics(findings)
	fileReports := []FileReport{BuildFileReport("sample.py", findings)}

	conclusionOnly = ComputeConclusionContext(stats, fileReports, policy, ConclusionContext{
		HasLLMBenign: true,
	}).Passed

	sp := report.Passed
	final = ComputeConclusionContext(stats, fileReports, policy, ConclusionContext{
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

// TestAssistStaticHighDowngradedByLLMStillBlocks pins the static fallback.
// The LLM can call a static HIGH benign or merely suspicious, and the policy
// check will pass it, but production must still block.
func TestAssistStaticHighDowngradedByLLMStillBlocks(t *testing.T) {
	cases := []struct {
		verdict            string
		wantConclusionOnly bool
	}{
		// Classified MEDIUM: assist blocks on classified HIGH only, so the
		// policy check alone passes this sample.
		{teellm.VerdictSuspicious, true},
		// Classified LOW: same, the policy check alone passes it.
		{teellm.VerdictBenign, true},
		// Classified HIGH (static HIGH survives UNCERTAIN), so here the policy
		// check happens to block on its own.
		{teellm.VerdictUncertain, false},
	}

	for _, tc := range cases {
		t.Run(tc.verdict, func(t *testing.T) {
			findings := []Finding{finding("CMD_001", SeverityHigh, tc.verdict)}

			conclusionOnly, reportPassed, final := productionDecision(findings, "assist")

			if conclusionOnly != tc.wantConclusionOnly {
				t.Errorf("conclusion only = %v, want %v", conclusionOnly, tc.wantConclusionOnly)
			}
			if reportPassed {
				t.Errorf("Report.Passed = true for a static HIGH; the static fallback must not consult verdicts")
			}
			if final {
				t.Errorf("final = true for a static HIGH with verdict %s; production must block", tc.verdict)
			}
		})
	}
}

// TestAssistStaticMediumIsVerdictSensitive is the mirror image, and the reason
// the benchmark's two arms disagree under the production default policy. For a
// static MEDIUM the policy check alone decides, so the same finding set is
// blocked when the LLM escalates and passed when it does not.
func TestAssistStaticMediumIsVerdictSensitive(t *testing.T) {
	cases := []struct {
		verdict string
		want    bool
	}{
		{teellm.VerdictMalicious, false}, // classified HIGH, blocks
		{teellm.VerdictSuspicious, true}, // classified MEDIUM, passes
		{teellm.VerdictBenign, true},     // classified LOW, passes
		{teellm.VerdictUncertain, true},  // classified MEDIUM, passes
	}

	for _, tc := range cases {
		t.Run(tc.verdict, func(t *testing.T) {
			findings := []Finding{finding("ENV_001", SeverityMedium, tc.verdict)}

			conclusionOnly, reportPassed, final := productionDecision(findings, "assist")

			if conclusionOnly != tc.want {
				t.Errorf("conclusion only = %v, want %v", conclusionOnly, tc.want)
			}
			if !reportPassed {
				t.Errorf("Report.Passed = false for a MEDIUM-only finding; the static fallback blocks HIGH only")
			}
			if final != tc.want {
				t.Errorf("final = %v, want %v", final, tc.want)
			}
		})
	}
}

// TestGateIsVerdictBlind documents why the six-round benchmark could not see the
// difference between the two engines: gate blocks on any verdict that is not
// BENIGN, so a verdict-level difference between the arms cannot change its
// outcome. Every finding in the benchmark corpus was non-BENIGN, which is why
// the measured delta was exactly zero.
func TestGateIsVerdictBlind(t *testing.T) {
	for _, sev := range []string{SeverityHigh, SeverityMedium} {
		for _, verdict := range []string{teellm.VerdictMalicious, teellm.VerdictSuspicious, teellm.VerdictUncertain} {
			t.Run(sev+"/"+verdict, func(t *testing.T) {
				findings := []Finding{finding("ENV_001", sev, verdict)}
				if _, _, final := productionDecision(findings, "gate"); final {
					t.Errorf("gate passed a %s finding with verdict %s; gate must block every non-BENIGN verdict", sev, verdict)
				}
			})
		}
	}
}

// TestAssistIsOneDirectional states the whole assist semantics in one
// property: the LLM can add blocking but never remove it. A static HIGH blocks
// no matter what the LLM says, and a non-HIGH finding blocks only when the LLM
// calls it MALICIOUS. So under the production default policy, Tier 2
// arbitration cannot clear a static HIGH.
func TestAssistIsOneDirectional(t *testing.T) {
	verdicts := []string{
		teellm.VerdictMalicious,
		teellm.VerdictSuspicious,
		teellm.VerdictBenign,
		teellm.VerdictUncertain,
		"", // no verdict at all, i.e. the LLM was not consulted
	}

	for _, sev := range []string{SeverityHigh, SeverityMedium} {
		for _, verdict := range verdicts {
			name := sev + "/" + verdict
			t.Run(name, func(t *testing.T) {
				findings := []Finding{finding("ENV_001", sev, verdict)}

				// final is the pass decision, so a blocked sample is !final.
				wantPassed := !(sev == SeverityHigh || verdict == teellm.VerdictMalicious)
				_, _, final := productionDecision(findings, "assist")

				if final == wantPassed {
					return
				}
				if wantPassed {
					t.Errorf("assist blocked a %s finding with verdict %q; want passed", sev, verdict)
				} else {
					t.Errorf("assist passed a %s finding with verdict %q; want blocked", sev, verdict)
				}
			})
		}
	}
}
