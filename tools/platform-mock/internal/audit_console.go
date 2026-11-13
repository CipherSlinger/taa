package mock

import (
	"net/http"
	"strconv"
	"strings"
)

const (
	auditJobsDefaultLimit = 50
	auditJobsMaxLimit     = 200
)

// auditConsoleInstance is the instance block every audit endpoint echoes. It
// reuses the existing kind inference and address derivation instead of
// inventing a second view of an instance.
type auditConsoleInstance struct {
	DockerID string `json:"dockerId"`
	Kind     string `json:"kind"`
	Address  string `json:"address"`
	Online   bool   `json:"online"`
}

type auditOverviewResponse struct {
	Instance auditConsoleInstance `json:"instance"`
	Summary  auditOverviewSummary `json:"summary"`
	Recent   []auditJobSummary    `json:"recent"`
}

type auditJobsResponse struct {
	Jobs  []auditJobSummary `json:"jobs"`
	Total int               `json:"total"`
}

// auditConsole serves the read side of the audit workbench. Authentication is
// not its concern: the routes wrap each handler in the existing console's
// requireSession, so there is exactly one session store for both tabs.
type auditConsole struct {
	mgr  *instanceManager
	jobs *auditJobStore
}

func newAuditConsole(mgr *instanceManager, jobs *auditJobStore) *auditConsole {
	if jobs == nil {
		jobs = globalAuditJobs
	}
	return &auditConsole{mgr: mgr, jobs: jobs}
}

// instance resolves the requested dockerId to its instance block. An explicit
// unknown id is not an error here: the console shows an empty offline instance
// rather than failing the overview. The returned id is the key the job store
// was written under, which for the no-selection case is the default instance.
func (a *auditConsole) instance(requested string) (string, auditConsoleInstance) {
	id := strings.TrimSpace(requested)
	var b *instanceStores
	if a.mgr != nil {
		if id != "" {
			b = a.mgr.lookup(id)
		} else {
			b = a.mgr.defaultBundle()
		}
	}
	if b != nil {
		id = b.dockerID
	}
	info := auditConsoleInstance{DockerID: id}
	if b == nil {
		return id, info
	}
	reg := b.register.get()
	info.Kind = registrationKind(reg)
	info.Address = targetForDisplay(a.mgr, b.dockerID)
	info.Online = reg.Received || reg.ReceivedAt != ""
	return id, info
}

func (a *auditConsole) handleOverview(w http.ResponseWriter, r *http.Request) {
	if !consoleRequireMethod(w, r, http.MethodGet) {
		return
	}
	id, info := a.instance(requestedDockerID(r))
	writeJSON(w, http.StatusOK, auditOverviewResponse{
		Instance: info,
		Summary:  a.jobs.overview(id),
		Recent:   a.jobs.recent(id, auditRecentLimit),
	})
}

func (a *auditConsole) handleJobs(w http.ResponseWriter, r *http.Request) {
	if !consoleRequireMethod(w, r, http.MethodGet) {
		return
	}
	id, _ := a.instance(requestedDockerID(r))
	jobs := a.jobs.list(id)
	total := len(jobs)
	limit := parseAuditLimit(r.URL.Query().Get("limit"))
	if limit < total {
		jobs = jobs[:limit]
	}
	writeJSON(w, http.StatusOK, auditJobsResponse{Jobs: jobs, Total: total})
}

func (a *auditConsole) handleJobDetail(w http.ResponseWriter, r *http.Request) {
	if !consoleRequireMethod(w, r, http.MethodGet) {
		return
	}
	jobID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/audit/console/jobs/"))
	if jobID == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "审计任务不存在"})
		return
	}
	id, _ := a.instance(requestedDockerID(r))
	job, ok := a.jobs.get(id, jobID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "审计任务不存在"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"job": job.detail()})
}

// parseAuditLimit applies the default and the hard cap. A malformed or
// non-positive value is treated as "not supplied" rather than as an error, so a
// stale bookmark cannot break the list.
func parseAuditLimit(raw string) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return auditJobsDefaultLimit
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return auditJobsDefaultLimit
	}
	if n > auditJobsMaxLimit {
		return auditJobsMaxLimit
	}
	return n
}
