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

// auditJobSummary is the list row shape shared by the overview's recent list,
// the jobs endpoint and the detail header.
type auditJobSummary struct {
	ID            string `json:"id"`
	DockerID      string `json:"dockerId"`
	RequestID     string `json:"requestId"`
	TaskID        string `json:"taskId"`
	At            string `json:"at"`
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
type auditOverviewSummary struct {
	Jobs           int     `json:"jobs"`
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
func (s *auditJobStore) record(dockerID, requestID, taskID string, code int, raw string) {
	rep, parseErr := parseAuditReport(raw)
	if parseErr != nil {
		log.Printf("audit job %s/%s: report parse failed: %v", dockerID, requestID, parseErr)
	}
	summary := auditJobSummary{
		DockerID:      dockerID,
		RequestID:     requestID,
		TaskID:        taskID,
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

	summary.At = s.now().Format(time.RFC3339)
	jobs := s.byInstance[dockerID]

	// Same requestId means the same audit reported twice: replace the record in
	// place but keep the identifier the console may already be showing.
	id := ""
	if requestID != "" {
		for i, existing := range jobs {
			if existing.RequestID == requestID {
				id = existing.ID
				jobs = append(jobs[:i], jobs[i+1:]...)
				break
			}
		}
	}

	if id == "" {
		base := requestID
		if base == "" {
			base = taskID
		}
		if base == "" {
			base = "job-" + strconv.FormatInt(s.now().UnixNano(), 10)
		}
		id = base
		for suffix := 2; auditIDTaken(jobs, id); suffix++ {
			id = fmt.Sprintf("%s-%d", base, suffix)
		}
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
func (s *auditJobStore) overview(dockerID string) auditOverviewSummary {
	jobs := s.list(dockerID)
	var summary auditOverviewSummary
	summary.Jobs = len(jobs)
	var durationTotal int64
	for _, job := range jobs {
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
	}
	if summary.Jobs > 0 {
		summary.PassRate = float64(summary.Passed) / float64(summary.Jobs)
		summary.AvgDurationMs = durationTotal / int64(summary.Jobs)
		summary.LastAt = jobs[0].At
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
