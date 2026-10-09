package codeaudit

import (
	"context"
	"strings"
	"testing"
)

// These tests cover the case the audit had no name for: the LLM was configured
// on, and no client was available to run it. GenerateAuditReport takes the client
// as an argument, so a caller can hand it nil while Config.Enabled is still true —
// the controller does exactly that when the endpoint is empty or the client
// cannot be constructed. Both LLM phases are then skipped, and before this the
// report still said LLMEnabled = true with LLMDegraded = false, which made a
// static-only verdict indistinguishable from one the LLM had adjudicated.
//
// The distinction only matters when there was something to adjudicate. With no
// findings the LLM would not have been called even if it were reachable —
// VerifyReport returns early on an empty finding list and the file-level phase
// only visits files that produced findings — so marking such a run degraded
// would be a false statement, and rejecting it would block a package the scan
// had already examined completely.

// auditFixtureWithFindings writes a file that produces exactly one finding
// (ENV_001, MEDIUM), so that the LLM had work waiting for it.
func auditFixtureWithFindings(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", "import os\nx = os.environ.get('api_key')\n")
	return dir
}

// auditFixtureWithoutFindings writes a file that produces none, so that the LLM
// had nothing to do.
func auditFixtureWithoutFindings(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "train.py", "import torch\nmodel = torch.nn.Linear(2, 2)\n")
	return dir
}

// TestAuditWithoutAClientIsRejectedUnderFailClosed pins the fail-closed hole a
// missing client used to open.
//
// Fail-closed means a finding that could not be adjudicated does not pass. A
// deployment that asked for the LLM and got no client has exactly that: findings
// the second opinion never reached. Skipping the phases and passing on the static
// severities alone is the silent allow this policy exists to prevent, so the
// audit is refused rather than quietly downgraded.
func TestAuditWithoutAClientIsRejectedUnderFailClosed(t *testing.T) {
	dir := auditFixtureWithFindings(t)

	cfg := LLMConfig{Enabled: true, Policy: "assist", FailClosed: true}
	audit, err := GenerateAuditReport(context.Background(), dir, DefaultEngine(), cfg, nil)

	if err == nil {
		t.Fatal("an audit with the LLM enabled and fail-closed returned a report although no client was " +
			"available and a finding went unadjudicated")
	}
	if !strings.Contains(err.Error(), "client") {
		t.Errorf("error does not name the missing client: %v", err)
	}
	if audit != nil {
		t.Errorf("GenerateAuditReport returned an audit alongside an error: %+v", audit)
	}
}

// TestAuditWithoutAClientIsMarkedDegraded is the other side of the same policy:
// with fail-closed off the run is allowed to proceed on static severities, and
// the report has to say that is what happened.
//
// LLMEnabled stays true, because that is the deployment's request and it remains
// the truth about the configuration; LLMDegraded is what records that the request
// was not honoured. Dropping neither field would leave the two ways of producing
// a report — one the LLM saw, one it did not — reading identically.
func TestAuditWithoutAClientIsMarkedDegraded(t *testing.T) {
	dir := auditFixtureWithFindings(t)

	cfg := LLMConfig{Enabled: true, Policy: "assist", FailClosed: false}
	audit, err := GenerateAuditReport(context.Background(), dir, DefaultEngine(), cfg, nil)
	if err != nil {
		t.Fatalf("GenerateAuditReport: %v", err)
	}

	if !audit.ScanMetadata.LLMEnabled {
		t.Error("LLMEnabled = false although the configuration asked for the LLM")
	}
	if !audit.ScanMetadata.LLMDegraded {
		t.Error("LLMDegraded = false although a finding went unadjudicated; " +
			"a static-only verdict is indistinguishable from one the LLM produced")
	}
}

// TestAuditWithNothingToAdjudicateIsNotDegraded keeps the degradation claim
// honest in the other direction.
//
// A clean package leaves the LLM nothing to do, so its absence costs nothing and
// must not be reported as a degradation — nor, under fail-closed, be treated as
// one. The fixture is asserted to have produced no findings, so the test fails
// loudly if the rule is ever widened to every run.
func TestAuditWithNothingToAdjudicateIsNotDegraded(t *testing.T) {
	dir := auditFixtureWithoutFindings(t)

	cfg := LLMConfig{Enabled: true, Policy: "assist", FailClosed: true}
	audit, err := GenerateAuditReport(context.Background(), dir, DefaultEngine(), cfg, nil)
	if err != nil {
		t.Fatalf("a clean scan was refused because the LLM was unreachable, although it had nothing to "+
			"adjudicate: %v", err)
	}

	if len(audit.FileReports) != 0 {
		t.Fatalf("fixture produced %d file report(s); the no-work path is what is under test", len(audit.FileReports))
	}
	if audit.ScanMetadata.LLMDegraded {
		t.Error("LLMDegraded = true for a scan with nothing to adjudicate; " +
			"the LLM would not have been called even if it were reachable")
	}
}
