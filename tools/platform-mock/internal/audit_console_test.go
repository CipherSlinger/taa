package mock

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"testing"
	"time"
)

// auditTestClock returns a clock that advances one minute per call, so the
// newest-first ordering is unambiguous even within one test.
func auditTestClock() func() time.Time {
	base := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	step := 0
	return func() time.Time {
		now := base.Add(time.Duration(step) * time.Minute)
		step++
		return now
	}
}

// buildAuditTestReport marshals a report the way TAA does: one object with the
// conclusion, raw file reports and a duration.
func buildAuditTestReport(t *testing.T, passed bool, risk string, stats map[string]int, durationMS int64, fileFindings []int) string {
	t.Helper()
	files := make([]any, 0, len(fileFindings))
	for i, count := range fileFindings {
		findings := make([]any, 0, count)
		for j := 0; j < count; j++ {
			findings = append(findings, map[string]any{
				"file":     fmt.Sprintf("f%d.py", i),
				"line":     j + 1,
				"rule_id":  "NET_001",
				"severity": "HIGH",
			})
		}
		files = append(files, map[string]any{
			"file":     fmt.Sprintf("f%d.py", i),
			"findings": findings,
		})
	}
	report := map[string]any{
		"conclusion": map[string]any{
			"passed":         passed,
			"risk_level":     risk,
			"summary":        "结论摘要",
			"recommendation": "修复建议",
			"statistics":     stats,
		},
		"file_reports": files,
		"duration_ms":  durationMS,
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	return string(raw)
}

func auditTestStats(high, medium, low int) map[string]int {
	return map[string]int{"high": high, "medium": medium, "low": low, "cross_file": 0, "microservice": 0}
}

func TestAuditJobRecordParsesReport(t *testing.T) {
	store := newAuditJobStore()
	store.now = auditTestClock()
	raw := buildAuditTestReport(t, true, "HIGH", auditTestStats(1, 2, 3), 1234, []int{2, 1})

	store.record("d1", "req1", "task1", 0, raw)

	jobs := store.list("d1")
	if len(jobs) != 1 {
		t.Fatalf("jobs = %d, want 1", len(jobs))
	}
	job := jobs[0]
	if job.ID != "req1" || job.DockerID != "d1" || job.RequestID != "req1" || job.TaskID != "task1" {
		t.Fatalf("identity fields = %+v", job)
	}
	if !job.Passed || job.Code != 0 {
		t.Fatalf("passed/code = %v/%d, want true/0", job.Passed, job.Code)
	}
	if job.RiskLevel != "HIGH" {
		t.Fatalf("riskLevel = %q, want HIGH", job.RiskLevel)
	}
	if job.High != 1 || job.Medium != 2 || job.Low != 3 {
		t.Fatalf("severity = %d/%d/%d, want 1/2/3", job.High, job.Medium, job.Low)
	}
	if job.DurationMS != 1234 {
		t.Fatalf("durationMs = %d, want 1234", job.DurationMS)
	}
	if job.Files != 2 || job.Findings != 3 {
		t.Fatalf("files/findings = %d/%d, want 2/3", job.Files, job.Findings)
	}
	if job.At != "2026-11-13T09:00:00Z" {
		t.Fatalf("at = %q", job.At)
	}
	if job.PromptPreview != "" {
		t.Fatalf("promptPreview = %q, want empty", job.PromptPreview)
	}

	stored, ok := store.get("d1", "req1")
	if !ok {
		t.Fatal("get(req1) = missing")
	}
	detail := stored.detail()
	if detail.SummaryText != "结论摘要" || detail.Recommendation != "修复建议" {
		t.Fatalf("detail text = %q / %q", detail.SummaryText, detail.Recommendation)
	}
	if detail.Statistics.High != 1 || detail.Statistics.Medium != 2 || detail.Statistics.Low != 3 || detail.Statistics.Total != 6 {
		t.Fatalf("detail statistics = %+v", detail.Statistics)
	}
	if len(detail.FileReports) != 2 {
		t.Fatalf("detail fileReports = %d, want 2", len(detail.FileReports))
	}
	if detail.Raw != raw {
		t.Fatal("detail raw does not echo the report string")
	}
}

func TestAuditJobFindingsFallBackToStatistics(t *testing.T) {
	store := newAuditJobStore()
	// No findings arrays anywhere: the count must come from the statistics.
	raw := `{"conclusion":{"statistics":{"high":4,"medium":5,"low":6}},"file_reports":[{"file":"a.py"}]}`
	store.record("d1", "req1", "task1", 1, raw)

	jobs := store.list("d1")
	if len(jobs) != 1 {
		t.Fatalf("jobs = %d", len(jobs))
	}
	if jobs[0].Findings != 15 {
		t.Fatalf("findings = %d, want 15", jobs[0].Findings)
	}
	if jobs[0].Passed {
		t.Fatal("code 1 must not be marked passed")
	}
}

func TestAuditJobCode2MarksLLMUnavailable(t *testing.T) {
	store := newAuditJobStore()
	// Even a report whose conclusion says passed must be failed when code is 2.
	raw := buildAuditTestReport(t, true, "MEDIUM", auditTestStats(0, 1, 0), 10, []int{1})
	store.record("d1", "req1", "task1", 2, raw)

	jobs := store.list("d1")
	if jobs[0].Passed {
		t.Fatal("code 2 must not be marked passed")
	}
	summary := store.overview("d1")
	if summary.LLMUnavailable != 1 || summary.Failed != 0 || summary.Passed != 0 {
		t.Fatalf("overview buckets = %+v", summary)
	}
}

func TestAuditJobDedupKeepsOriginalID(t *testing.T) {
	store := newAuditJobStore()
	store.now = auditTestClock()
	first := buildAuditTestReport(t, true, "HIGH", auditTestStats(1, 0, 0), 100, []int{1})
	second := buildAuditTestReport(t, false, "LOW", auditTestStats(0, 0, 9), 200, []int{9})

	store.record("d1", "req1", "task1", 0, first)
	store.record("d1", "req1", "task1", 1, second)

	jobs := store.list("d1")
	if len(jobs) != 1 {
		t.Fatalf("jobs = %d, want 1 after dedup", len(jobs))
	}
	if jobs[0].ID != "req1" {
		t.Fatalf("id = %q, want the original req1", jobs[0].ID)
	}
	if jobs[0].Code != 1 || jobs[0].Passed || jobs[0].RiskLevel != "LOW" || jobs[0].Low != 9 {
		t.Fatalf("replacement was not applied: %+v", jobs[0])
	}
}

func TestAuditJobIDSuffixOnCollision(t *testing.T) {
	store := newAuditJobStore()
	store.record("d1", "", "task1", 0, `{}`)
	store.record("d1", "task1", "task2", 0, `{}`)

	jobs := store.list("d1")
	ids := map[string]bool{}
	for _, job := range jobs {
		ids[job.ID] = true
	}
	if !ids["task1"] || !ids["task1-2"] {
		t.Fatalf("ids = %v, want task1 and task1-2", ids)
	}
}

func TestAuditJobRingCapacity(t *testing.T) {
	store := newAuditJobStore()
	store.now = auditTestClock()
	for i := 0; i < auditJobRingCapacity+5; i++ {
		store.record("d1", fmt.Sprintf("req-%03d", i), "", 0, `{"duration_ms":1}`)
	}

	jobs := store.list("d1")
	if len(jobs) != auditJobRingCapacity {
		t.Fatalf("jobs = %d, want %d", len(jobs), auditJobRingCapacity)
	}
	if jobs[0].RequestID != "req-204" {
		t.Fatalf("newest = %q, want req-204", jobs[0].RequestID)
	}
	if jobs[len(jobs)-1].RequestID != "req-005" {
		t.Fatalf("oldest kept = %q, want req-005", jobs[len(jobs)-1].RequestID)
	}
}

func TestAuditJobOverviewAggregates(t *testing.T) {
	store := newAuditJobStore()
	store.now = auditTestClock()
	store.record("d1", "req-a", "", 0, buildAuditTestReport(t, true, "HIGH", auditTestStats(1, 2, 3), 100, []int{1}))
	store.record("d1", "req-b", "", 1, buildAuditTestReport(t, false, "MEDIUM", auditTestStats(4, 0, 0), 200, []int{1}))
	store.record("d1", "req-c", "", 2, buildAuditTestReport(t, false, "LOW", auditTestStats(0, 5, 0), 300, []int{1}))

	summary := store.overview("d1")
	if summary.Jobs != 3 || summary.Passed != 1 || summary.Failed != 1 || summary.LLMUnavailable != 1 {
		t.Fatalf("buckets = %+v", summary)
	}
	if math.Abs(summary.PassRate-1.0/3.0) > 1e-9 {
		t.Fatalf("passRate = %v", summary.PassRate)
	}
	if summary.High != 5 || summary.Medium != 7 || summary.Low != 3 {
		t.Fatalf("severity totals = %d/%d/%d", summary.High, summary.Medium, summary.Low)
	}
	if summary.AvgDurationMs != 200 {
		t.Fatalf("avgDurationMs = %d, want 200", summary.AvgDurationMs)
	}
	if summary.LastAt != "2026-11-13T09:02:00Z" {
		t.Fatalf("lastAt = %q", summary.LastAt)
	}

	recent := store.recent("d1", auditRecentLimit)
	if len(recent) != 3 || recent[0].RequestID != "req-c" || recent[2].RequestID != "req-a" {
		t.Fatalf("recent order = %+v", recent)
	}

	empty := store.overview("unknown")
	if empty.Jobs != 0 || empty.PassRate != 0 || empty.LastAt != "" {
		t.Fatalf("empty overview = %+v", empty)
	}
}

func TestAuditJobOverviewRecentLimit(t *testing.T) {
	store := newAuditJobStore()
	for i := 0; i < 12; i++ {
		store.record("d1", fmt.Sprintf("req-%02d", i), "", 0, `{}`)
	}
	recent := store.recent("d1", auditRecentLimit)
	if len(recent) != 10 {
		t.Fatalf("recent = %d, want 10", len(recent))
	}
	if recent[0].RequestID != "req-11" || recent[9].RequestID != "req-02" {
		t.Fatalf("recent order = %q .. %q", recent[0].RequestID, recent[9].RequestID)
	}
}

// auditTestHandlers wires the audit console to a private store and the shared
// console session gate, mirroring how server.go mounts the routes.
func auditTestHandlers(t *testing.T) (*consoleTestRig, *auditConsole) {
	t.Helper()
	rig := newConsoleTestRig(t, "")
	mgr := testManagerWith(t, "d1", func(b *instanceStores) {
		b.register.set(registerState{Received: true, Accepted: true, ReceivedAt: "2026-11-13T09:00:00Z", VerifiedPass: true})
		b.setTarget("http://192.0.2.9:6001")
	})
	return rig, newAuditConsole(mgr, newAuditJobStore())
}

func TestAuditConsoleRequiresSession(t *testing.T) {
	rig, audit := auditTestHandlers(t)
	cases := []struct {
		name    string
		handler http.HandlerFunc
		target  string
	}{
		{"overview", audit.handleOverview, "/api/audit/console/overview?dockerId=d1"},
		{"jobs", audit.handleJobs, "/api/audit/console/jobs?dockerId=d1"},
		{"detail", audit.handleJobDetail, "/api/audit/console/jobs/req1?dockerId=d1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := rig.call(rig.console.requireSession(tc.handler), http.MethodGet, tc.target, "", nil)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if body["error"] != "未登录或会话已过期" {
				t.Fatalf("error = %q", body["error"])
			}
		})
	}
}

func TestAuditConsoleRejectsWrongMethod(t *testing.T) {
	rig, audit := auditTestHandlers(t)
	cookie := rig.loginCookie(t)
	rec := rig.call(rig.console.requireSession(audit.handleOverview), http.MethodPost, "/api/audit/console/overview?dockerId=d1", "", cookie)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestAuditConsoleOverviewInstance(t *testing.T) {
	rig, audit := auditTestHandlers(t)
	audit.jobs.record("d1", "req1", "task1", 0, buildAuditTestReport(t, true, "HIGH", auditTestStats(1, 0, 0), 100, []int{1}))
	cookie := rig.loginCookie(t)

	rec := rig.call(rig.console.requireSession(audit.handleOverview), http.MethodGet, "/api/audit/console/overview?dockerId=d1", "", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	var resp auditOverviewResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Instance.DockerID != "d1" || resp.Instance.Kind != instanceKindTEE {
		t.Fatalf("instance = %+v", resp.Instance)
	}
	if resp.Instance.Address != "http://192.0.2.9:6001" || !resp.Instance.Online {
		t.Fatalf("instance address/online = %+v", resp.Instance)
	}
	if resp.Summary.Jobs != 1 || len(resp.Recent) != 1 {
		t.Fatalf("summary/recent = %+v / %d", resp.Summary, len(resp.Recent))
	}
}

func TestAuditConsoleJobDetailNotFound(t *testing.T) {
	rig, audit := auditTestHandlers(t)
	cookie := rig.loginCookie(t)

	rec := rig.call(rig.console.requireSession(audit.handleJobDetail), http.MethodGet, "/api/audit/console/jobs/missing?dockerId=d1", "", cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["error"] != "审计任务不存在" {
		t.Fatalf("error = %q", body["error"])
	}
}

func TestAuditConsoleJobDetailPassesRawReport(t *testing.T) {
	rig, audit := auditTestHandlers(t)
	raw := buildAuditTestReport(t, true, "MEDIUM", auditTestStats(0, 2, 0), 77, []int{2})
	audit.jobs.record("d1", "req1", "task1", 0, raw)
	cookie := rig.loginCookie(t)

	rec := rig.call(rig.console.requireSession(audit.handleJobDetail), http.MethodGet, "/api/audit/console/jobs/req1?dockerId=d1", "", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Job auditJobDetail `json:"job"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Job.ID != "req1" || resp.Job.Raw != raw || len(resp.Job.FileReports) != 1 {
		t.Fatalf("detail = %+v", resp.Job)
	}
	if resp.Job.Statistics.Total != 2 {
		t.Fatalf("statistics = %+v", resp.Job.Statistics)
	}
}

func TestAuditConsoleJobsLimit(t *testing.T) {
	rig, audit := auditTestHandlers(t)
	// More than the ring capacity, so the stored total itself is the cap.
	for i := 0; i < auditJobRingCapacity+5; i++ {
		audit.jobs.record("d1", fmt.Sprintf("req-%03d", i), "", 0, `{}`)
	}
	cookie := rig.loginCookie(t)

	cases := []struct {
		query string
		want  int
	}{
		{"", auditJobsDefaultLimit},
		{"&limit=10", 10},
		{"&limit=999", auditJobRingCapacity},
		{"&limit=abc", auditJobsDefaultLimit},
	}
	for _, tc := range cases {
		target := "/api/audit/console/jobs?dockerId=d1" + tc.query
		rec := rig.call(rig.console.requireSession(audit.handleJobs), http.MethodGet, target, "", cookie)
		if rec.Code != http.StatusOK {
			t.Fatalf("%q status = %d", tc.query, rec.Code)
		}
		var resp auditJobsResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("%q decode: %v", tc.query, err)
		}
		if len(resp.Jobs) != tc.want {
			t.Fatalf("%q jobs = %d, want %d", tc.query, len(resp.Jobs), tc.want)
		}
		if resp.Total != auditJobRingCapacity {
			t.Fatalf("%q total = %d, want %d", tc.query, resp.Total, auditJobRingCapacity)
		}
	}
}

// Guard against the handler response types drifting apart from the contract's
// JSON field names for the list row.
func TestAuditJobSummaryJSONFieldNames(t *testing.T) {
	job := auditJobSummary{ID: "i", DockerID: "d", RequestID: "r", TaskID: "t", At: "a", Code: 1,
		Passed: true, RiskLevel: "HIGH", High: 1, Medium: 2, Low: 3, DurationMS: 4, Files: 5, Findings: 6}
	raw, err := json.Marshal(job)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, name := range []string{"id", "dockerId", "requestId", "taskId", "at", "code", "passed",
		"riskLevel", "high", "medium", "low", "durationMs", "files", "findings", "promptPreview"} {
		if _, ok := fields[name]; !ok {
			t.Errorf("jobSummary JSON is missing %q: %s", name, raw)
		}
	}
}

// The detail endpoint must flatten the summary fields rather than nest them.
func TestAuditJobDetailJSONFlattensSummary(t *testing.T) {
	job := &auditJob{auditJobSummary: auditJobSummary{ID: "i"}, FileReports: nil}
	raw, err := json.Marshal(job.detail())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, name := range []string{"id", "summaryText", "recommendation", "statistics", "fileReports", "raw"} {
		if _, ok := fields[name]; !ok {
			t.Errorf("detail JSON is missing %q: %s", name, raw)
		}
	}
	if fields["fileReports"] == nil {
		t.Error("fileReports must be [] rather than null")
	}
}
