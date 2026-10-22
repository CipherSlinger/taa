package codeaudit

import (
	"context"
	"strings"
	"testing"
)

// TestPresenceOnlySuspiciousDemotesToLow pins the presence-only demotion: a
// SUSPICIOUS verdict on CMD_001 or DYN_001, with no corroborating evidence and
// no explicit severity in the risk field, is an advisory LOW rather than a
// blocking MEDIUM. Both static severities are covered because the demotion is
// keyed on the rule family, not on the severity the rule carries.
func TestPresenceOnlySuspiciousDemotesToLow(t *testing.T) {
	for _, ruleID := range []string{"CMD_001", "DYN_001"} {
		for _, severity := range []string{SeverityHigh, SeverityMedium} {
			f := Finding{
				File:       "train_fusion.py",
				RuleID:     ruleID,
				Severity:   severity,
				LLMVerdict: "SUSPICIOUS",
				LLMRisk:    "如果命令参数不安全，可能会被恶意用户利用执行任意系统命令",
			}
			if got := ClassifyFindingRisk(f); got != "LOW" {
				t.Errorf("%s/%s SUSPICIOUS classified %s, want LOW", ruleID, severity, got)
			}
		}
	}
}

// TestPresenceOnlySuspiciousCorroboratedStaysMedium is the boundary of the
// demotion: a cross-file chain or a taint trace is evidence beyond the sink
// itself, so the suspicion keeps blocking.
func TestPresenceOnlySuspiciousCorroboratedStaysMedium(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Finding)
	}{
		{"cross-file", func(f *Finding) { f.IsCrossFile = true }},
		{"taint-trace", func(f *Finding) {
			f.TaintTrace = []TaintStep{{Step: 1, Type: "source", File: "train.py", Line: 3, Code: "read()"}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := Finding{
				File:       "train_fusion.py",
				RuleID:     "CMD_001",
				Severity:   SeverityHigh,
				LLMVerdict: "SUSPICIOUS",
				LLMRisk:    "命令参数可能来自不可信输入",
			}
			tc.mut(&f)
			if got := ClassifyFindingRisk(f); got != "MEDIUM" {
				t.Errorf("corroborated SUSPICIOUS classified %s, want MEDIUM", got)
			}
		})
	}
}

// TestPresenceOnlySuspiciousExplicitHighRiskStaysBlocking keeps the inference
// service's own severity assessment authoritative: SUSPICIOUS with an explicit
// HIGH/CRITICAL risk is not demoted.
func TestPresenceOnlySuspiciousExplicitHighRiskStaysBlocking(t *testing.T) {
	for _, risk := range []string{"HIGH", "CRITICAL", " high "} {
		f := Finding{
			File:       "train_fusion.py",
			RuleID:     "CMD_001",
			Severity:   SeverityHigh,
			LLMVerdict: "SUSPICIOUS",
			LLMRisk:    risk,
		}
		if got := ClassifyFindingRisk(f); got != "HIGH" {
			t.Errorf("risk %q classified %s, want HIGH", risk, got)
		}
	}
}

// TestPresenceOnlyMaliciousStillBlocks: the demotion is only for SUSPICIOUS.
func TestPresenceOnlyMaliciousStillBlocks(t *testing.T) {
	for _, ruleID := range []string{"CMD_001", "DYN_001"} {
		f := Finding{RuleID: ruleID, Severity: SeverityMedium, LLMVerdict: "MALICIOUS"}
		if got := ClassifyFindingRisk(f); got != "HIGH" {
			t.Errorf("%s MALICIOUS classified %s, want HIGH", ruleID, got)
		}
	}
}

// TestNonPresenceRuleSuspiciousStillMedium keeps the demotion scoped: a
// SUSPICIOUS verdict on any other family still blocks.
func TestNonPresenceRuleSuspiciousStillMedium(t *testing.T) {
	f := Finding{RuleID: "NET_001", Severity: SeverityHigh, LLMVerdict: "SUSPICIOUS"}
	if got := ClassifyFindingRisk(f); got != "MEDIUM" {
		t.Errorf("NET_001 SUSPICIOUS classified %s, want MEDIUM", got)
	}
}

// TestVerifyReportRecordsPresenceDowngrade checks that the verifier writes the
// explanatory DowngradeReason onto the finding it demoted, so the report can
// distinguish "the rule says LOW" from "the rule says HIGH but this did not
// earn it", and that the report still passes.
func TestVerifyReportRecordsPresenceDowngrade(t *testing.T) {
	report := &Report{
		ScanComplete: true,
		Findings: []Finding{{
			File:        "train_fusion.py",
			Line:        31,
			RuleID:      "CMD_001",
			Category:    "命令执行",
			Severity:    SeverityHigh,
			CodeSnippet: "os.system(order)",
		}},
	}
	client := &mockLLMClient{decisions: []LLMDecision{{
		Verdict: "SUSPICIOUS",
		Reason:  "代码通过 os.system 执行外部命令，存在命令注入的风险。",
		Risk:    "如果命令参数不安全，可能会被恶意用户利用",
	}}}

	got, err := VerifyReport(context.Background(), report, LLMConfig{Enabled: true}, client)
	if err != nil {
		t.Fatalf("VerifyReport: %v", err)
	}
	f := got.Findings[0]
	if !strings.Contains(f.DowngradeReason, "SUSPICIOUS") {
		t.Errorf("DowngradeReason = %q, want it to name the SUSPICIOUS verdict", f.DowngradeReason)
	}
	if risk := ClassifyFindingRisk(f); risk != "LOW" {
		t.Errorf("classified risk = %s, want LOW", risk)
	}
	// Report.Passed is the scan-level value and still counts the static HIGH;
	// the audit verdict is the conclusion, which must now pass.
	conclusion := ComputeConclusionContext(ComputeStatistics(got.Findings), nil, ConclusionContext{})
	if !conclusion.Passed {
		t.Errorf("conclusion passed = false (risk %s); the demoted finding must not block", conclusion.RiskLevel)
	}
}

// TestConclusionPassesWithTwoPresenceSuspicions reproduces the report that
// motivated the demotion: two SUSPICIOUS presence-only findings plus four LOW
// ones must produce a passing, LOW-risk conclusion instead of a MEDIUM refusal.
func TestConclusionPassesWithTwoPresenceSuspicions(t *testing.T) {
	findings := []Finding{
		{File: "test_run.py", RuleID: "CMD_001", Severity: SeverityHigh, LLMVerdict: "SUSPICIOUS",
			LLMRisk: "如果命令参数不安全，可能会被恶意用户利用"},
		{File: "data_pre_process/data_process.py", RuleID: "DYN_001", Severity: SeverityMedium, LLMVerdict: "SUSPICIOUS",
			LLMRisk: "恶意代码可能被执行，窃取或篡改数据"},
	}
	for _, rule := range []string{"NET_001", "FIL_001", "EMB_003", "ENV_001"} {
		findings = append(findings, Finding{File: "train_fusion.py", RuleID: rule, Severity: SeverityLow, LLMVerdict: "BENIGN"})
	}

	stats := ComputeStatistics(findings)
	conclusion := ComputeConclusionContext(stats, nil, ConclusionContext{HasLLMBenign: true})

	if stats.Total() != 6 || stats.High != 0 || stats.Medium != 0 || stats.Low != 6 {
		t.Fatalf("statistics = high:%d medium:%d low:%d, want 0/0/6", stats.High, stats.Medium, stats.Low)
	}
	if !conclusion.Passed {
		t.Errorf("passed = false, want true (risk %s, summary %q)", conclusion.RiskLevel, conclusion.Summary)
	}
	if conclusion.RiskLevel != "LOW" {
		t.Errorf("risk level = %s, want LOW", conclusion.RiskLevel)
	}
}
