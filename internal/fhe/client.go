package fhe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// maxErrorBodyBytes bounds how much of an error response is copied into an error
// message.
const maxErrorBodyBytes = 4 << 10

// APIError is a non-2xx answer from the FHE service.
type APIError struct {
	Method     string
	Path       string
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	body := strings.TrimSpace(e.Body)
	if body == "" {
		return fmt.Sprintf("fhe %s %s: HTTP %d", e.Method, e.Path, e.StatusCode)
	}
	return fmt.Sprintf("fhe %s %s: HTTP %d: %s", e.Method, e.Path, e.StatusCode, body)
}

func asAPIError(err error, target **APIError) bool {
	return errors.As(err, target)
}

// Client talks to the FHE service's /api/v1 surface.
//
// Only the calls TAA makes are implemented. The service is unauthenticated and
// takes the tenant from the X-User-Id header, so every task-scoped call carries
// the eval key digest as that header.
type Client struct {
	baseURL string
	http    *http.Client
}

// NewClient returns a client for endpoint, which may or may not already carry
// the /api/v1 prefix.
func NewClient(endpoint string, timeout time.Duration) (*Client, error) {
	raw := strings.TrimRight(strings.TrimSpace(endpoint), "/")
	if raw == "" {
		return nil, fmt.Errorf("fhe endpoint is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse fhe endpoint %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("fhe endpoint %q must use the http or https scheme", raw)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("fhe endpoint %q has no host", raw)
	}
	base := raw
	if !strings.HasSuffix(base, "/api/v1") {
		base += "/api/v1"
	}
	return &Client{baseURL: base, http: &http.Client{Timeout: timeout}}, nil
}

func (c *Client) do(ctx context.Context, method, path, userID string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode fhe %s %s body: %w", method, path, err)
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("build fhe %s %s request: %w", method, path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if userID != "" {
		req.Header.Set("X-User-Id", userID)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("fhe %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return &APIError{Method: method, Path: path, StatusCode: resp.StatusCode, Body: string(snippet)}
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode fhe %s %s response: %w", method, path, err)
	}
	return nil
}

// Health checks that the service answers.
func (c *Client) Health(ctx context.Context) error {
	var st map[string]any
	return c.do(ctx, http.MethodGet, "/health", "", nil, &st)
}

// ActivateModel asks the service to scan and hot-load a model. The call is
// idempotent, so it may be repeated.
func (c *Client) ActivateModel(ctx context.Context, modelID string) error {
	var st map[string]any
	return c.do(ctx, http.MethodPost, "/models/activate?model_id="+url.QueryEscape(modelID), "", nil, &st)
}

// CreateTaskRequest is the body of POST /tasks.
type CreateTaskRequest struct {
	UserID             string `json:"user_id"`
	ModelID            string `json:"model_id"`
	TaskID             string `json:"task_id"`
	CallbackURL        string `json:"callback_url"`
	CancelOnDisconnect bool   `json:"cancel_on_disconnect"`
}

// CreateTask submits a task. The input package must already be on disk.
func (c *Client) CreateTask(ctx context.Context, req CreateTaskRequest) error {
	var st map[string]any
	return c.do(ctx, http.MethodPost, "/tasks", req.UserID, req, &st)
}

// CaseStatus is one entry of a task's case list.
type CaseStatus struct {
	Entry    string `json:"entry"`
	ResultID string `json:"result_id"`
	Error    string `json:"error"`
}

// TaskStatus is what the service reports for a task.
//
// Only Status is load-bearing: it is the field the service's own callback
// documents. The per-case list feeds percentage reporting alone, so an
// unrecognised shape degrades progress reporting without touching the outcome -
// a task whose status never becomes terminal still ends at TaskTimeout.
type TaskStatus struct {
	TaskID    string       `json:"task_id"`
	Status    string       `json:"status"`
	ResultZip string       `json:"result_zip"`
	Cases     []CaseStatus `json:"cases"`
	Results   []CaseStatus `json:"results"`
}

func (t TaskStatus) caseList() []CaseStatus {
	if len(t.Cases) > 0 {
		return t.Cases
	}
	return t.Results
}

// Progress returns the finished case count and the total the service reported.
// Both are zero when no case list was recognised.
func (t TaskStatus) Progress() (done, total int) {
	cases := t.caseList()
	for _, c := range cases {
		if c.ResultID != "" || c.Error != "" {
			done++
		}
	}
	return done, len(cases)
}

// Failed returns the number of cases the service reported as failed.
func (t TaskStatus) Failed() int {
	n := 0
	for _, c := range t.caseList() {
		if c.Error != "" {
			n++
		}
	}
	return n
}

// Task fetches a task's state.
func (c *Client) Task(ctx context.Context, taskID, userID string) (TaskStatus, error) {
	var st TaskStatus
	err := c.do(ctx, http.MethodGet, "/tasks/"+url.PathEscape(taskID), userID, nil, &st)
	return st, err
}

// CancelTask maps TAA's stopTraining onto the service's cancel endpoint.
func (c *Client) CancelTask(ctx context.Context, taskID, userID string) error {
	var st map[string]any
	return c.do(ctx, http.MethodPost, "/tasks/"+url.PathEscape(taskID)+"/cancel", userID, nil, &st)
}

// ContinueTask re-runs the unfinished cases of a task that already exists, which
// is how a replayed import is retried instead of creating a second task.
func (c *Client) ContinueTask(ctx context.Context, taskID, userID string) error {
	var st map[string]any
	return c.do(ctx, http.MethodPost, "/tasks/"+url.PathEscape(taskID)+"/continue", userID, nil, &st)
}

// DownloadResult fetches output.zip and writes it to dst, creating parent
// directories. It is the fallback used when the shared directory does not hold
// the result - for instance when TAA and the service are not on one host.
func (c *Client) DownloadResult(ctx context.Context, taskID, userID, dst string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/tasks/"+url.PathEscape(taskID)+"/results/download", nil)
	if err != nil {
		return fmt.Errorf("build result download request: %w", err)
	}
	if userID != "" {
		req.Header.Set("X-User-Id", userID)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("download fhe result: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return &APIError{Method: http.MethodGet, Path: "/tasks/" + taskID + "/results/download",
			StatusCode: resp.StatusCode, Body: string(snippet)}
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("create result dir: %w", err)
	}
	tmp := dst + ".partial"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("create result temp file: %w", err)
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("write result file: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close result file: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("move result into place: %w", err)
	}
	return nil
}

// IsTerminal reports whether a status means the task will not change again.
func IsTerminal(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "completed", "succeeded", "success",
		"failed", "error",
		"cancelled", "canceled",
		"timeout", "timed_out",
		"expired", "deleted":
		return true
	}
	return false
}

// IsSuccess reports whether a terminal status means the task produced results.
func IsSuccess(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "completed", "succeeded", "success":
		return true
	}
	return false
}
