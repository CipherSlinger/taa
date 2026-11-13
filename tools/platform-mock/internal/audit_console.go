package mock

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

const (
	auditJobsDefaultLimit = 50
	auditJobsMaxLimit     = 200
)

// auditConsoleInstance is the instance block every audit endpoint echoes. The
// workbench runs audits inside this process, so the block names that engine
// rather than a registered TAA node.
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

// auditConsole serves the workbench's read side. Authentication is not its
// concern: the routes wrap each handler in the existing console's
// requireSession, so there is exactly one session store for both tabs.
type auditConsole struct {
	jobs  *auditJobStore
	files *auditFileStore
}

func newAuditConsole(jobs *auditJobStore, files *auditFileStore) *auditConsole {
	if jobs == nil {
		jobs = globalAuditJobs
	}
	return &auditConsole{jobs: jobs, files: files}
}

// instance always resolves to the local engine: this workbench has no target
// instance to select, and ignoring the query keeps a stale ?dockerId= harmless.
func (a *auditConsole) instance() (string, auditConsoleInstance) {
	return localAuditInstanceKey, auditConsoleInstance{
		DockerID: localAuditInstanceKey,
		Kind:     "local",
		Address:  "进程内",
		Online:   true,
	}
}

func (a *auditConsole) handleOverview(w http.ResponseWriter, r *http.Request) {
	if !consoleRequireMethod(w, r, http.MethodGet) {
		return
	}
	id, info := a.instance()
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
	id, _ := a.instance()
	jobs := a.jobs.list(id)
	total := len(jobs)
	limit := parseAuditLimit(r.URL.Query().Get("limit"))
	if limit < total {
		jobs = jobs[:limit]
	}
	writeJSON(w, http.StatusOK, auditJobsResponse{Jobs: jobs, Total: total})
}

// handleJobDetail serves one job and its deletion. Deletion exists because the
// list is a test workbench's history: an operator comparing prompt wordings
// needs to clear the runs a wording produced, and the store is in-memory only
// anyway, so refusing would only push them to restart the process.
func (a *auditConsole) handleJobDetail(w http.ResponseWriter, r *http.Request) {
	jobID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/audit/console/jobs/"))
	if jobID == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "审计任务不存在"})
		return
	}
	id, _ := a.instance()

	switch r.Method {
	case http.MethodGet:
	case http.MethodDelete:
		if !a.jobs.delete(id, jobID) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "审计任务不存在"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": jobID})
		return
	default:
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodDelete)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 GET 或 DELETE 方法"})
		return
	}

	job, ok := a.jobs.get(id, jobID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "审计任务不存在"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"job": job.detail()})
}

// auditFilesResponse is the file area: every archive the workbench has
// accepted, newest first. A submission names one of these by `fileId` to run
// again without uploading the bytes.
type auditFilesResponse struct {
	Files []auditFileEntry `json:"files"`
}

func (a *auditConsole) handleFiles(w http.ResponseWriter, r *http.Request) {
	if !consoleRequireMethod(w, r, http.MethodGet) {
		return
	}
	files := []auditFileEntry{}
	if a.files != nil {
		files = a.files.list()
	}
	writeJSON(w, http.StatusOK, auditFilesResponse{Files: files})
}

// handleFileDetail deletes one saved archive. Removing it only affects future
// submissions: a run in flight already copied the archive into its own work
// directory.
func (a *auditConsole) handleFileDetail(w http.ResponseWriter, r *http.Request) {
	fileID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/audit/console/files/"))
	if fileID == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "文件不存在"})
		return
	}
	if !consoleRequireMethod(w, r, http.MethodDelete) {
		return
	}
	if a.files == nil || !a.files.delete(fileID) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "文件不存在"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": fileID})
}

// auditPromptResponse is the editable audit prompt: the instruction text the
// workbench sends to TEE-LLM ahead of each finding's evidence. Prompt is always
// the effective text (the override, or the built-in default when unset), so the
// editor can show exactly what the next audit would send; Custom says whether
// that text is an override.
type auditPromptResponse struct {
	Prompt string `json:"prompt"`
	Custom bool   `json:"custom"`
}

func currentAuditPrompt(runner *localAuditRunner) auditPromptResponse {
	return auditPromptResponse{
		Prompt: runner.effectivePromptText(),
		Custom: runner.promptText() != "",
	}
}

// auditPromptHandler reads and writes the operator's prompt. It is not
// persisted: every other console setting behaves the same way (in-memory for
// the process lifetime), and a prompt edit is usually compared against a run
// made moments earlier.
func auditPromptHandler(runner *localAuditRunner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, currentAuditPrompt(runner))
		case http.MethodPut, http.MethodPost:
			var body auditPromptResponse
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "请求体不是合法 JSON: " + err.Error()})
				return
			}
			runner.setPrompt(body.Prompt)
			response := currentAuditPrompt(runner)
			writeJSON(w, http.StatusOK, map[string]any{
				"ok":     true,
				"prompt": response.Prompt,
				"custom": response.Custom,
			})
		default:
			w.Header().Set("Allow", http.MethodGet+", "+http.MethodPut)
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 GET 或 PUT 方法"})
		}
	}
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
