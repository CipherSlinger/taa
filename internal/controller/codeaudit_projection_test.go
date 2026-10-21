package controller

import (
	"encoding/json"
	"testing"

	"taa/internal/codeaudit"
)

// The report field is the only carrier of the audit's timing to the platform:
// scan_metadata stays in-process. Losing duration_ms would silently remove the
// one place the total audit time is visible outside TAA.
func TestAuditReportJSONCarriesDuration(t *testing.T) {
	audit := &codeaudit.AuditReport{
		Conclusion: codeaudit.AuditConclusion{Passed: true, RiskLevel: "NONE"},
		ScanMetadata: codeaudit.AuditMetadata{
			ScanDurationMs: 12345,
		},
	}

	var got map[string]json.RawMessage
	if err := json.Unmarshal([]byte(auditReportJSON(audit)), &got); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}

	raw, ok := got["duration_ms"]
	if !ok {
		t.Fatalf("report has no duration_ms: %s", auditReportJSON(audit))
	}
	var duration int64
	if err := json.Unmarshal(raw, &duration); err != nil {
		t.Fatalf("duration_ms is not an integer: %s", raw)
	}
	if duration != 12345 {
		t.Fatalf("duration_ms = %d, want 12345", duration)
	}

	// scan_metadata stays in-process; only duration_ms is lifted out of it.
	if _, leaked := got["scan_metadata"]; leaked {
		t.Fatalf("report leaked scan_metadata: %s", auditReportJSON(audit))
	}
}

func TestAuditReportJSONNilAuditIsEmpty(t *testing.T) {
	if got := auditReportJSON(nil); got != "" {
		t.Fatalf("auditReportJSON(nil) = %q, want empty", got)
	}
}
