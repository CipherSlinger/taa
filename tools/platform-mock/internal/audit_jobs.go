package mock

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// auditJobRingCapacity is the per-instance ring bound. Audits are a few per
	// day, so 200 entries cover a long debugging session; overflow drops the
	// oldest job, which is the one least likely to be inspected.
	auditJobRingCapacity = 200
	// auditRecentLimit is how many jobs the overview embeds. The UI's recent
	// table has ten rows and the overview is polled, so more would be waste.
	auditRecentLimit = 10
)

// auditStatistics is the conclusion's severity breakdown as TAA reports it.
type auditStatistics struct {
	High         int `json:"high"`
	Medium       int `json:"medium"`
	Low          int `json:"low"`
	CrossFile    int `json:"cross_file"`
	Microservice int `json:"microservice"`
}

// auditConclusion is the verdict half of the report projection.
type auditConclusion struct {
	Passed         bool            `json:"passed"`
	RiskLevel      string          `json:"risk_level"`
	Summary        string          `json:"summary"`
	Recommendation string          `json:"recommendation"`
	Statistics     auditStatistics `json:"statistics"`
}

// auditReport is the projection TAA sends as the `report` string. The file
// reports stay raw: the platform only counts them for the summary and hands the
// original objects back on the detail endpoint, so a field this struct does not
// know is never lost.
type auditReport struct {
	Conclusion  auditConclusion   `json:"conclusion"`
	FileReports []json.RawMessage `json:"file_reports"`
	DurationMS  int64             `json:"duration_ms"`
}

// Audit job statuses. A row starts as pending when the platform submits it,
// becomes done once reportAudit carries the verdict, and becomes failed when a
// submission never produced one (see abandon).
const (
	auditJobStatusPending = "pending"
	auditJobStatusDone    = "done"
	auditJobStatusFailed  = "failed"
)

// Per-step states of a locally executed audit. The steps run in the order of
// localAuditStepKeys; a step that the run does not need (the AI adjudicator with
// no gateway, for instance) ends as skipped rather than done.
const (
	auditStepPending = "pending"
	auditStepActive  = "active"
	auditStepDone    = "done"
	auditStepSkipped = "skipped"
	auditStepError   = "error"
)

// localAuditStepKeys is the step order the workbench's vertical flow renders.
// receive and extract happen in the mock; the rest are reported by codeaudit
// through AuditConfig.OnStage.
var localAuditStepKeys = []string{"receive", "extract", "static", "binary", "ai", "conclude"}

func newPendingAuditStages() map[string]string {
	stages := make(map[string]string, len(localAuditStepKeys))
	for _, key := range localAuditStepKeys {
		stages[key] = auditStepPending
	}
	return stages
}

func newLocalAuditStages() map[string]string {
	stages := newPendingAuditStages()
	stages[localAuditStepKeys[0]] = auditStepActive
	return stages
}

func cloneAuditStages(stages map[string]string) map[string]string {
	if stages == nil {
		return nil
	}
	out := make(map[string]string, len(stages))
	for key, state := range stages {
		out[key] = state
	}
	return out
}

// auditJobStatusOf normalizes a stored status. Records written before the
// status field existed carry the zero value, and a zero value is a completed
// verdict: those rows only ever came from reportAudit.
func auditJobStatusOf(raw string) string {
	switch raw {
	case auditJobStatusPending, auditJobStatusDone, auditJobStatusFailed:
		return raw
	}
	return auditJobStatusDone
}

// auditJobSummary is the list row shape shared by the overview's recent list,
// the jobs endpoint and the detail header.
type auditJobSummary struct {
	ID        string `json:"id"`
	DockerID  string `json:"dockerId"`
	RequestID string `json:"requestId"`
	TaskID    string `json:"taskId"`
	At        string `json:"at"`
	// Status is pending while the verdict has not arrived, done once
	// reportAudit recorded it, and failed for a submission that never produced
	// one. An empty value is treated as done.
	Status string `json:"status"`
	// Error explains a failed row. It is omitted everywhere else so completed
	// and in-flight rows keep their previous JSON shape.
	Error         string `json:"error,omitempty"`
	Code          int    `json:"code"`
	Passed        bool   `json:"passed"`
	RiskLevel     string `json:"riskLevel"`
	High          int    `json:"high"`
	Medium        int    `json:"medium"`
	Low           int    `json:"low"`
	DurationMS    int64  `json:"durationMs"`
	Files         int    `json:"files"`
	Findings      int    `json:"findings"`
	PromptPreview string `json:"promptPreview"`
	// Stage is the step a local audit is currently on, or "done" once it
	// settled. Rows written by the reportAudit callback leave it empty.
	Stage string `json:"stage,omitempty"`
	// Stages carries the state of every step of a local audit so the console's
	// flow diagram has one authoritative answer. It is omitted for jobs that
	// came from a TAA callback.
	Stages map[string]string `json:"stages,omitempty"`
}

// auditJob keeps the parsed report fields the list does not carry. The raw
// string is retained so the detail endpoint can echo exactly what TAA sent.
type auditJob struct {
	auditJobSummary
	SummaryText    string
	Recommendation string
	Statistics     auditStatistics
	FileReports    []json.RawMessage
	Raw            string
}

// auditDetailStatistics is the detail variant: it folds the three severities
// into a total the UI can display without summing in the browser.
type auditDetailStatistics struct {
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
	Total  int `json:"total"`
}

// auditJobDetail is the detail payload. The summary is embedded so every list
// field is repeated in the detail view without a second lookup.
type auditJobDetail struct {
	auditJobSummary
	SummaryText    string                `json:"summaryText"`
	Recommendation string                `json:"recommendation"`
	Statistics     auditDetailStatistics `json:"statistics"`
	FileReports    []json.RawMessage     `json:"fileReports"`
	Raw            string                `json:"raw"`
}

// auditOverviewSummary is the aggregate the overview cards are built from.
// Every counter except Pending is computed from done jobs only: a pending
// submission has no verdict yet, so counting it would make the pass rate
// depend on how many audits happen to be in flight.
type auditOverviewSummary struct {
	Jobs           int     `json:"jobs"`
	Pending        int     `json:"pending"`
	Passed         int     `json:"passed"`
	Failed         int     `json:"failed"`
	LLMUnavailable int     `json:"llmUnavailable"`
	PassRate       float64 `json:"passRate"`
	High           int     `json:"high"`
	Medium         int     `json:"medium"`
	Low            int     `json:"low"`
	AvgDurationMs  int64   `json:"avgDurationMs"`
	LastAt         string  `json:"lastAt"`
}

// auditJobStore holds one process-local ring of jobs per dockerId. Nothing is
// persisted: losing the workbench after a restart is acceptable because TAA
// keeps reporting, while a persisted copy would need the same encryption story
// as every other state file for data the platform only mirrors.
type auditJobStore struct {
	mu sync.Mutex
	// byInstance maps a dockerId to its jobs, newest first. Prepending on every
	// insert keeps both the list endpoint and the ring trim O(1) in the common
	// case.
	byInstance map[string][]*auditJob
	// now is a seam for the tests; production leaves it at time.Now.
	now func() time.Time
}

// globalAuditJobs is the store the TAA callback writes to. reportAuditHandler
// has no store parameter, so the accepted branch and the console handlers must
// agree on this one instance.
var globalAuditJobs = newAuditJobStore()

func newAuditJobStore() *auditJobStore {
	return &auditJobStore{
		byInstance: make(map[string][]*auditJob),
		now:        time.Now,
	}
}

// parseAuditReport decodes the report string. An empty or malformed report is
// not fatal: the job is still worth showing (its code and ids are valid), so the
// record keeps it with zero-valued report fields rather than dropping the audit.
func parseAuditReport(raw string) (auditReport, error) {
	var rep auditReport
	if strings.TrimSpace(raw) == "" {
		return rep, fmt.Errorf("report 为空")
	}
	if err := json.Unmarshal([]byte(raw), &rep); err != nil {
		return rep, err
	}
	return rep, nil
}

// countFindings sums the findings across file reports. A report that carries no
// findings arrays at all falls back to the conclusion's severity counts, which
// is the only other place the total exists.
func countFindings(rep auditReport) int {
	total := 0
	present := false
	for _, raw := range rep.FileReports {
		var file struct {
			Findings []json.RawMessage `json:"findings"`
		}
		if err := json.Unmarshal(raw, &file); err != nil {
			continue
		}
		if file.Findings != nil {
			present = true
			total += len(file.Findings)
		}
	}
	if !present {
		return rep.Conclusion.Statistics.High + rep.Conclusion.Statistics.Medium + rep.Conclusion.Statistics.Low
	}
	return total
}

// record parses one accepted reportAudit callback and stores it. The id is the
// requestId when present; a requestId collision replaces the previous job while
// keeping the id it was first published under, and an id already held by a
// different requestId gets a -2, -3... suffix.
//
// A pending row written by begin carries the same requestId, so this replacement
// is also what promotes it to done: the row never flickers between two entries.
func (s *auditJobStore) record(dockerID, requestID, taskID string, code int, raw string) {
	rep, parseErr := parseAuditReport(raw)
	if parseErr != nil {
		log.Printf("audit job %s/%s: report parse failed: %v", dockerID, requestID, parseErr)
	}
	summary := auditJobSummary{
		DockerID:      dockerID,
		RequestID:     requestID,
		TaskID:        taskID,
		Status:        auditJobStatusDone,
		Code:          code,
		Passed:        code == 0,
		RiskLevel:     rep.Conclusion.RiskLevel,
		High:          rep.Conclusion.Statistics.High,
		Medium:        rep.Conclusion.Statistics.Medium,
		Low:           rep.Conclusion.Statistics.Low,
		DurationMS:    rep.DurationMS,
		Files:         len(rep.FileReports),
		Findings:      countFindings(rep),
		PromptPreview: "",
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// One timestamp per record: the clock is a test seam that advances on every
	// call, so asking twice would date a single report two steps apart from its
	// own id.
	now := s.now()
	summary.At = now.Format(time.RFC3339)
	jobs := s.byInstance[dockerID]

	// Same requestId means the same audit reported twice: replace the record in
	// place but keep the identifier the console may already be showing.
	id := ""
	var inheritedStages map[string]string
	if requestID != "" {
		for i, existing := range jobs {
			if existing.RequestID == requestID {
				id = existing.ID
				inheritedStages = existing.Stages
				jobs = append(jobs[:i], jobs[i+1:]...)
				break
			}
		}
	}

	if id == "" {
		id = nextAuditJobID(jobs, requestID, taskID, now)
	}

	job := &auditJob{
		auditJobSummary: summary,
		SummaryText:     rep.Conclusion.Summary,
		Recommendation:  rep.Conclusion.Recommendation,
		Statistics:      rep.Conclusion.Statistics,
		FileReports:     rep.FileReports,
		Raw:             raw,
	}
	job.ID = id
	// A locally executed audit began with a step map; the verdict settles it.
	// Rows that only ever existed as a reportAudit callback have no map, and
	// keeping it nil keeps their JSON shape unchanged.
	if inheritedStages != nil {
		stages := cloneAuditStages(inheritedStages)
		stages["conclude"] = auditStepDone
		job.Stages = stages
		job.Stage = "done"
	}

	jobs = append([]*auditJob{job}, jobs...)
	if len(jobs) > auditJobRingCapacity {
		jobs = jobs[:auditJobRingCapacity]
	}
	s.byInstance[dockerID] = jobs
}

func auditIDTaken(jobs []*auditJob, id string) bool {
	for _, job := range jobs {
		if job.ID == id {
			return true
		}
	}
	return false
}

// nextAuditJobID derives the id a new row is published under, using the same
// rule for begin and record: requestId first, then taskId, then a clock-based
// fallback, with -2, -3... appended when that id is already held.
func nextAuditJobID(jobs []*auditJob, requestID, taskID string, now time.Time) string {
	base := requestID
	if base == "" {
		base = taskID
	}
	if base == "" {
		base = "job-" + strconv.FormatInt(now.UnixNano(), 10)
	}
	id := base
	for suffix := 2; auditIDTaken(jobs, id); suffix++ {
		id = fmt.Sprintf("%s-%d", base, suffix)
	}
	return id
}

// begin records a submission that TAA has accepted but whose verdict has not
// arrived. It is replaced in place by record() when reportAudit names the same
// requestId, so the row never flickers between two entries.
//
// The call is idempotent: a repeated submission for a requestId that already
// has a row changes nothing. A done row wins over a new pending one, because a
// real verdict is worth more than the knowledge that a request was sent.
func (s *auditJobStore) begin(dockerID, requestID, taskID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	jobs := s.byInstance[dockerID]
	if requestID != "" {
		for _, existing := range jobs {
			if existing.RequestID == requestID {
				return
			}
		}
	}

	now := s.now()
	job := &auditJob{auditJobSummary: auditJobSummary{
		ID:        nextAuditJobID(jobs, requestID, taskID, now),
		DockerID:  dockerID,
		RequestID: requestID,
		TaskID:    taskID,
		At:        now.Format(time.RFC3339),
		Status:    auditJobStatusPending,
		Stage:     localAuditStepKeys[0],
		Stages:    newLocalAuditStages(),
	}}

	jobs = append([]*auditJob{job}, jobs...)
	if len(jobs) > auditJobRingCapacity {
		jobs = jobs[:auditJobRingCapacity]
	}
	s.byInstance[dockerID] = jobs
}

// abandon marks a pending submission that never produced a verdict. The row is
// kept (with the reason) so an operator can tell "TAA never answered" from
// "the request was never sent".
func (s *auditJobStore) abandon(dockerID, requestID, reason string) bool {
	if requestID == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	jobs := s.byInstance[dockerID]
	for i, job := range jobs {
		if job.RequestID != requestID {
			continue
		}
		// A verdict that already arrived is never rewritten by a late failure:
		// only the pending state can be abandoned.
		if auditJobStatusOf(job.Status) != auditJobStatusPending {
			return false
		}
		// Published auditJob pointers are read without the lock, so the
		// transition builds a replacement and swaps the slot instead of
		// mutating a row a reader may be holding. The position is kept: the
		// row's submission order still decides where it sits in the list.
		abandoned := *job
		abandoned.Status = auditJobStatusFailed
		abandoned.Error = reason
		jobs[i] = &abandoned
		return true
	}
	return false
}

// setStage moves one step of a pending local audit to state. Only the pending
// status is eligible: once a verdict landed or a failure was recorded, the row
// is final and a late stage transition must not rewrite it.
//
// Like abandon, it builds a replacement row and swaps the slot, because
// published *auditJob pointers are read without the lock. It deliberately does
// not touch the clock: a stage change is progress inside one submission, not a
// new submission, and the row's At must keep naming when it was received.
func (s *auditJobStore) setStage(dockerID, requestID, step, state string) bool {
	if requestID == "" || step == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	jobs := s.byInstance[dockerID]
	for i, job := range jobs {
		if job.RequestID != requestID {
			continue
		}
		if auditJobStatusOf(job.Status) != auditJobStatusPending {
			return false
		}
		updated := *job
		updated.Stages = cloneAuditStages(job.Stages)
		if updated.Stages == nil {
			updated.Stages = newPendingAuditStages()
		}
		updated.Stages[step] = state
		updated.Stage = step
		jobs[i] = &updated
		return true
	}
	return false
}

// failAt turns a pending local audit into a failed row at step. Steps that
// already completed keep their state; the failing step alone becomes error.
//
// The caller must not follow a failure with record(): that would replace the
// row with a done verdict and lose both the failing step and the reason.
func (s *auditJobStore) failAt(dockerID, requestID, step, reason string) bool {
	if requestID == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	jobs := s.byInstance[dockerID]
	for i, job := range jobs {
		if job.RequestID != requestID {
			continue
		}
		if auditJobStatusOf(job.Status) != auditJobStatusPending {
			return false
		}
		failed := *job
		failed.Status = auditJobStatusFailed
		failed.Error = reason
		failed.Stages = cloneAuditStages(job.Stages)
		if failed.Stages == nil {
			failed.Stages = newPendingAuditStages()
		}
		if step != "" {
			failed.Stages[step] = auditStepError
			failed.Stage = step
		}
		jobs[i] = &failed
		return true
	}
	return false
}

// delete removes one job from the instance's ring. Removing a row a reader is
// holding is safe: published pointers are immutable, so the reader keeps a
// consistent copy and simply stops seeing it in later lists.
func (s *auditJobStore) delete(dockerID, id string) bool {
	if id == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	jobs := s.byInstance[dockerID]
	for i, job := range jobs {
		if job.ID != id {
			continue
		}
		jobs = append(jobs[:i], jobs[i+1:]...)
		s.byInstance[dockerID] = jobs
		return true
	}
	return false
}

// list returns the instance's jobs newest first. The returned summaries are
// copies, so a caller can render them without holding the store lock.
func (s *auditJobStore) list(dockerID string) []auditJobSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	jobs := s.byInstance[dockerID]
	out := make([]auditJobSummary, 0, len(jobs))
	for _, job := range jobs {
		out = append(out, job.auditJobSummary)
	}
	return out
}

// recent narrows list to the newest limit entries.
func (s *auditJobStore) recent(dockerID string, limit int) []auditJobSummary {
	jobs := s.list(dockerID)
	if limit > 0 && len(jobs) > limit {
		jobs = jobs[:limit]
	}
	return jobs
}

// summaryForRequest returns the row published for one requestId. The submit
// endpoint uses it to report the id and timestamp the row actually has, rather
// than recomputing an id that a collision may have suffixed.
func (s *auditJobStore) summaryForRequest(dockerID, requestID string) (auditJobSummary, bool) {
	if requestID == "" {
		return auditJobSummary{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, job := range s.byInstance[dockerID] {
		if job.RequestID == requestID {
			return job.auditJobSummary, true
		}
	}
	return auditJobSummary{}, false
}

// get returns one job. Records are immutable once published (a replacement
// builds a new auditJob), so the pointer may be read after the lock is released.
func (s *auditJobStore) get(dockerID, id string) (*auditJob, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, job := range s.byInstance[dockerID] {
		if job.ID == id {
			return job, true
		}
	}
	return nil, false
}

// overview aggregates the instance's jobs. passed comes from code 0; a job that
// was not passed and was not an LLM outage is counted as failed, so the three
// buckets always add up to Jobs.
//
// Only done jobs participate. A pending submission has no verdict, and an
// abandoned one produced no TAA answer at all, so folding either into the
// buckets would report a pass rate over rows that never had a conclusion.
// Pending is reported separately; abandoned rows are visible in the list.
func (s *auditJobStore) overview(dockerID string) auditOverviewSummary {
	jobs := s.list(dockerID)
	var summary auditOverviewSummary
	var durationTotal int64
	for _, job := range jobs {
		if auditJobStatusOf(job.Status) != auditJobStatusDone {
			if auditJobStatusOf(job.Status) == auditJobStatusPending {
				summary.Pending++
			}
			continue
		}
		summary.Jobs++
		if job.Passed {
			summary.Passed++
		} else if job.Code == 2 {
			summary.LLMUnavailable++
		} else {
			summary.Failed++
		}
		summary.High += job.High
		summary.Medium += job.Medium
		summary.Low += job.Low
		durationTotal += job.DurationMS
		if summary.LastAt == "" {
			summary.LastAt = job.At
		}
	}
	if summary.Jobs > 0 {
		summary.PassRate = float64(summary.Passed) / float64(summary.Jobs)
		summary.AvgDurationMs = durationTotal / int64(summary.Jobs)
	}
	return summary
}

// detail expands one stored job for the detail endpoint. The file reports are
// handed back as the original JSON objects.
func (j *auditJob) detail() auditJobDetail {
	files := j.FileReports
	if files == nil {
		files = []json.RawMessage{}
	}
	return auditJobDetail{
		auditJobSummary: j.auditJobSummary,
		SummaryText:     j.SummaryText,
		Recommendation:  j.Recommendation,
		Statistics: auditDetailStatistics{
			High:   j.Statistics.High,
			Medium: j.Statistics.Medium,
			Low:    j.Statistics.Low,
			Total:  j.Statistics.High + j.Statistics.Medium + j.Statistics.Low,
		},
		FileReports: files,
		Raw:         j.Raw,
	}
}
