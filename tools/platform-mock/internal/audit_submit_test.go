package mock

import (
	"strings"
	"testing"
)

// ── start / abandon / record / stages ───────────────────────────────────────

func TestAuditJobBeginIsIdempotent(t *testing.T) {
	store := newAuditJobStore()
	store.now = auditTestClock()

	store.begin("d1", "req1", "task1")
	store.begin("d1", "req1", "task1")

	jobs := store.list("d1")
	if len(jobs) != 1 {
		t.Fatalf("jobs = %d, want 1 after a repeated begin", len(jobs))
	}
	if jobs[0].Status != auditJobStatusPending {
		t.Fatalf("status = %q, want pending", jobs[0].Status)
	}
	if jobs[0].ID != "req1" || jobs[0].Code != 0 || jobs[0].Passed {
		t.Fatalf("pending row = %+v", jobs[0])
	}
	if jobs[0].High != 0 || jobs[0].Medium != 0 || jobs[0].Low != 0 {
		t.Fatalf("pending row carries severity counts: %+v", jobs[0])
	}
}

func TestAuditJobBeginStartsTheLocalFlow(t *testing.T) {
	store := newAuditJobStore()
	store.begin("d1", "req1", "task1")

	jobs := store.list("d1")
	if jobs[0].Stage != "receive" {
		t.Fatalf("stage = %q, want receive", jobs[0].Stage)
	}
	if len(jobs[0].Stages) != len(localAuditStepKeys) {
		t.Fatalf("stages = %v, want every step", jobs[0].Stages)
	}
	if jobs[0].Stages["receive"] != auditStepActive {
		t.Fatalf("receive = %q, want active", jobs[0].Stages["receive"])
	}
	for _, key := range localAuditStepKeys[1:] {
		if jobs[0].Stages[key] != auditStepPending {
			t.Fatalf("step %s = %q, want pending", key, jobs[0].Stages[key])
		}
	}
}

func TestAuditJobBeginDoesNotOverwriteDone(t *testing.T) {
	store := newAuditJobStore()
	store.now = auditTestClock()
	store.record("d1", "req1", "task1", 0, buildAuditTestReport(t, true, "HIGH", auditTestStats(1, 0, 0), 10, []int{1}))

	store.begin("d1", "req1", "task1")

	jobs := store.list("d1")
	if len(jobs) != 1 {
		t.Fatalf("jobs = %d, want 1", len(jobs))
	}
	if jobs[0].Status != auditJobStatusDone {
		t.Fatalf("status = %q, want done: a real verdict outranks a pending mark", jobs[0].Status)
	}
}

func TestAuditJobBeginIDRules(t *testing.T) {
	store := newAuditJobStore()
	store.now = auditTestClock()
	store.record("d1", "", "task1", 0, `{}`)
	store.begin("d1", "task1", "task2")

	ids := map[string]bool{}
	for _, job := range store.list("d1") {
		ids[job.ID] = true
	}
	if !ids["task1"] || !ids["task1-2"] {
		t.Fatalf("ids = %v, want task1 and task1-2", ids)
	}

	// No requestId and no taskId falls back to the clock-based name.
	store.begin("d1", "", "")
	jobs := store.list("d1")
	if !strings.HasPrefix(jobs[0].ID, "job-") {
		t.Fatalf("fallback id = %q, want a job-<nano> name", jobs[0].ID)
	}
}

func TestAuditJobRecordPromotesPendingInPlace(t *testing.T) {
	store := newAuditJobStore()
	store.now = auditTestClock()

	store.begin("d1", "req1", "task1")
	store.record("d1", "req1", "task1", 0,
		buildAuditTestReport(t, true, "MEDIUM", auditTestStats(0, 2, 0), 55, []int{2}))

	jobs := store.list("d1")
	if len(jobs) != 1 {
		t.Fatalf("jobs = %d, want 1: the verdict must replace the pending row", len(jobs))
	}
	job := jobs[0]
	if job.ID != "req1" || job.Status != auditJobStatusDone {
		t.Fatalf("row = %+v, want id req1 and status done", job)
	}
	if job.Error != "" {
		t.Fatalf("a done row carries an error: %q", job.Error)
	}
	if !job.Passed || job.Medium != 2 || job.DurationMS != 55 {
		t.Fatalf("verdict was not applied: %+v", job)
	}
}

func TestAuditJobRecordSettlesTheLocalFlow(t *testing.T) {
	store := newAuditJobStore()
	store.begin("d1", "req1", "task1")
	store.setStage("d1", "req1", "receive", auditStepDone)
	store.setStage("d1", "req1", "extract", auditStepActive)
	store.setStage("d1", "req1", "extract", auditStepDone)
	store.setStage("d1", "req1", "ai", auditStepSkipped)

	store.record("d1", "req1", "task1", 0, `{}`)

	job := store.list("d1")[0]
	if job.Stage != "done" {
		t.Fatalf("stage = %q, want done", job.Stage)
	}
	if job.Stages["conclude"] != auditStepDone || job.Stages["ai"] != auditStepSkipped {
		t.Fatalf("stages = %v, want inherited states with conclude done", job.Stages)
	}
}

func TestAuditJobRecordLeavesCallbackRowsWithoutStages(t *testing.T) {
	store := newAuditJobStore()
	store.record("d1", "req1", "task1", 0, `{}`)

	job := store.list("d1")[0]
	if job.Stage != "" || job.Stages != nil {
		t.Fatalf("callback row grew stage fields: %+v", job)
	}
}

func TestAuditJobSetStageCopiesTheRow(t *testing.T) {
	store := newAuditJobStore()
	store.begin("d1", "req1", "task1")
	before, _ := store.get("d1", "req1")

	if !store.setStage("d1", "req1", "extract", auditStepActive) {
		t.Fatal("setStage(pending row) = false, want true")
	}
	after, _ := store.get("d1", "req1")

	if before == after {
		t.Fatal("setStage mutated the published row instead of swapping it")
	}
	if before.Stages["extract"] != auditStepPending {
		t.Fatalf("the old snapshot changed: %v", before.Stages)
	}
	if after.Stages["extract"] != auditStepActive || after.Stage != "extract" {
		t.Fatalf("after = %+v", after.auditJobSummary)
	}
}

func TestAuditJobSetStageIgnoresSettledRows(t *testing.T) {
	store := newAuditJobStore()
	store.record("d1", "req1", "task1", 0, `{}`)

	if store.setStage("d1", "req1", "ai", auditStepActive) {
		t.Fatal("setStage on a done row must not match")
	}
	if store.setStage("d1", "missing", "ai", auditStepActive) {
		t.Fatal("setStage on an unknown requestId must not match")
	}
}

func TestAuditJobFailAtKeepsEarlierSteps(t *testing.T) {
	store := newAuditJobStore()
	store.begin("d1", "req1", "task1")
	store.setStage("d1", "req1", "receive", auditStepDone)
	store.setStage("d1", "req1", "extract", auditStepActive)

	if !store.failAt("d1", "req1", "extract", "解压归档失败") {
		t.Fatal("failAt(pending row) = false, want true")
	}

	job := store.list("d1")[0]
	if job.Status != auditJobStatusFailed || job.Error != "解压归档失败" {
		t.Fatalf("row = %+v", job)
	}
	if job.Stage != "extract" || job.Stages["extract"] != auditStepError {
		t.Fatalf("failing step = %q / %v", job.Stage, job.Stages)
	}
	if job.Stages["receive"] != auditStepDone {
		t.Fatalf("earlier step was lost: %v", job.Stages)
	}

	if store.failAt("d1", "req1", "extract", "again") {
		t.Fatal("failAt on a failed row must not match")
	}
}

func TestAuditJobDelete(t *testing.T) {
	store := newAuditJobStore()
	store.record("d1", "req1", "task1", 0, `{}`)
	store.record("d1", "req2", "task2", 0, `{}`)

	if !store.delete("d1", "req1") {
		t.Fatal("delete(existing) = false, want true")
	}
	jobs := store.list("d1")
	if len(jobs) != 1 || jobs[0].ID != "req2" {
		t.Fatalf("jobs = %+v, want only req2", jobs)
	}
	if store.delete("d1", "req1") {
		t.Fatal("delete(missing) = true, want false")
	}
	if store.delete("d1", "") {
		t.Fatal("delete(empty id) = true, want false")
	}
}

func TestAuditJobAbandon(t *testing.T) {
	store := newAuditJobStore()
	store.now = auditTestClock()
	store.begin("d1", "req1", "task1")

	if !store.abandon("d1", "req1", "下发失败: 连接被拒绝") {
		t.Fatal("abandon(pending row) = false, want true")
	}
	jobs := store.list("d1")
	if len(jobs) != 1 {
		t.Fatalf("jobs = %d, want the abandoned row kept", len(jobs))
	}
	if jobs[0].Status != auditJobStatusFailed || jobs[0].Error != "下发失败: 连接被拒绝" {
		t.Fatalf("abandoned row = %+v", jobs[0])
	}

	if store.abandon("d1", "req1", "again") {
		t.Fatal("abandon on an already abandoned row must not match")
	}
	if store.abandon("d1", "missing", "x") {
		t.Fatal("abandon on an unknown requestId must not match")
	}

	// A completed verdict is never rewritten by a late failure.
	store.record("d1", "req2", "task2", 0, `{}`)
	if store.abandon("d1", "req2", "late") {
		t.Fatal("abandon must not rewrite a done row")
	}
}

func TestAuditOverviewCountsOnlyDoneJobs(t *testing.T) {
	store := newAuditJobStore()
	store.now = auditTestClock()
	store.record("d1", "req-a", "", 0, buildAuditTestReport(t, true, "HIGH", auditTestStats(1, 0, 0), 100, []int{1}))
	store.record("d1", "req-b", "", 1, buildAuditTestReport(t, false, "MEDIUM", auditTestStats(0, 1, 0), 200, []int{1}))
	store.begin("d1", "req-pending", "task-3")
	store.begin("d1", "req-abandoned", "task-4")
	store.abandon("d1", "req-abandoned", "下发失败")

	summary := store.overview("d1")
	if summary.Jobs != 2 {
		t.Fatalf("jobs = %d, want 2 done jobs", summary.Jobs)
	}
	if summary.Pending != 1 {
		t.Fatalf("pending = %d, want 1", summary.Pending)
	}
	if summary.Passed != 1 || summary.Failed != 1 || summary.LLMUnavailable != 0 {
		t.Fatalf("buckets = %+v", summary)
	}
	if summary.PassRate != 0.5 {
		t.Fatalf("passRate = %v, want 0.5 (done jobs only)", summary.PassRate)
	}
	if summary.AvgDurationMs != 150 {
		t.Fatalf("avgDurationMs = %d, want 150", summary.AvgDurationMs)
	}
	if summary.LastAt != "2026-11-13T09:01:00Z" {
		t.Fatalf("lastAt = %q, want the newest done row", summary.LastAt)
	}

	// The list still shows every row, pending and abandoned included.
	if jobs := store.list("d1"); len(jobs) != 4 {
		t.Fatalf("list = %d rows, want all 4", len(jobs))
	}
}
