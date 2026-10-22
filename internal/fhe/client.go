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

// Client talks to the FHE service's /api/v1 surface.
//
// Only the calls TAA makes are implemented. The service is unauthenticated and
// takes the tenant from the X-User-Id header, so every task-scoped call carries
// the eval key digest as that header - and refuses to send one without it,
// because the header is what the service reads the tenant from.
//
// The two HTTP clients differ in exactly one way, and it is load-bearing: the
// unary client bounds a whole call by the configured request timeout, and the
// download client must not, because http.Client.Timeout also covers reading the
// body, so a per-request timeout aborts a multi-gigabyte result mid-stream. The
// wait for a response head is bounded on both of them, so the download client is
// not the one place a wedged service can hold a call open: it takes that bound
// from the configured request timeout instead of from a whole-request deadline.
type Client struct {
	baseURL  string
	http     *http.Client
	download *http.Client
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
	// The download client is built with no whole-request deadline, so the header
	// bound it does get cannot come from the same argument. A non-positive request
	// timeout therefore falls back to the default rather than leaving the one
	// streaming client unbounded at both ends.
	headerTimeout := timeout
	if headerTimeout <= 0 {
		headerTimeout = DefaultRequestTimeout
	}
	return &Client{
		baseURL:  base,
		http:     newHTTPClient(timeout, headerTimeout),
		download: newHTTPClient(0, headerTimeout),
	}, nil
}

// newHTTPClient builds one HTTP client. A timeout of 0 means "no whole-request
// deadline", which is what the download needs; headerTimeout is separate from it
// and always positive, so a service that accepts a connection and then says
// nothing cannot hold a call open for longer than that, whether or not the body
// is allowed to stream.
//
// Neither client follows a redirect. A redirect is how a task-scoped call
// leaks its tenant: a 307 re-sends the POST to whatever host Location names, and
// a 303 turns the POST into a GET that still answers 200, so a mutating call
// reports success while doing nothing. Handing the 3xx back to the caller
// surfaces both as an APIError instead.
func newHTTPClient(timeout, headerTimeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Time to the first byte, not time to the last: headers still have to arrive
	// inside headerTimeout, which the body must not be.
	transport.ResponseHeaderTimeout = headerTimeout
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// guardTaskCall rejects a task-scoped call this package must not send.
//
// The id must be one safe path segment, because url.PathEscape is not a traversal
// defence. It does escape "/" - as %2F - but it leaves "." alone, so the id ".."
// survives escaping unchanged and lands in the URL as a parent segment; and
// escaping the slash in a longer id buys nothing, because the hierarchy is
// restored the moment the path is decoded for matching, which is what net/http
// does (URL.Path is stored decoded). The conclusion is the one that matters: the
// segment has to be checked before the request is built, and ValidTaskID is that
// check. The tenant must be present, because an empty one used to drop the
// X-User-Id header and succeed as no tenant at all.
func guardTaskCall(taskID, userID string) error {
	if err := ValidTaskID(taskID); err != nil {
		return err
	}
	if strings.TrimSpace(userID) == "" {
		return fmt.Errorf("fhe task-scoped call for task %q requires a user id", taskID)
	}
	return nil
}

// do performs one unary call.
//
// emptyOK marks the calls whose response body this package does not consume:
// the service is entitled to answer a cancel with 204 No Content, and decoding
// an empty body into a throwaway value would turn that success into an error.
// The calls whose body carries data (health, create, task) pass false, where an
// empty body is still an error - a zero value returned there would be a phantom
// success that the runner acts on.
func (c *Client) do(ctx context.Context, method, path, userID string, body, out any, emptyOK bool) error {
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
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		if emptyOK && errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("decode fhe %s %s response: %w", method, path, err)
	}
	return nil
}

// Health checks that the service answers.
func (c *Client) Health(ctx context.Context) error {
	var st map[string]any
	return c.do(ctx, http.MethodGet, "/health", "", nil, &st, false)
}

// ActivateModel asks the service to scan and hot-load a model. The call is
// idempotent, so it may be repeated.
func (c *Client) ActivateModel(ctx context.Context, modelID string) error {
	var st map[string]any
	return c.do(ctx, http.MethodPost, "/models/activate?model_id="+url.QueryEscape(modelID), "", nil, &st, true)
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
	if err := guardTaskCall(req.TaskID, req.UserID); err != nil {
		return err
	}
	return c.do(ctx, http.MethodPost, "/tasks", req.UserID, req, &st, false)
}

// CaseStatus is one entry of a task's case list.
type CaseStatus struct {
	Entry    string `json:"entry"`
	Status   string `json:"status"`
	Progress int    `json:"progress"`
	ResultID string `json:"result_id"`
	Error    string `json:"error"`
}

// TaskStatus is what the service reports for a task.
//
// Only Status is load-bearing: it is the field the service's own callback
// documents. Progress and the per-case list feed percentage reporting alone, so
// an unrecognised shape degrades progress reporting without touching the
// outcome - it keeps polling until the service reports a terminal state or the
// caller cancels.
type TaskStatus struct {
	TaskID string `json:"task_id"`
	Status string `json:"status"`
	// TaskProgress is the task-level percentage. It is a pointer because a
	// service that predates the field omits it, and 0 is a valid percentage.
	TaskProgress *int         `json:"progress"`
	ResultZip    string       `json:"result_zip"`
	Cases        []CaseStatus `json:"cases"`
	Results      []CaseStatus `json:"results"`
}

// caseList returns the case entries the service reported.
//
// "results" is a fallback spelling of "cases", not a second list to merge: the
// response shape is undocumented and only one of the two keys is ever filled in,
// so cases wins whenever it is non-empty. A service that one day sends both
// would have its "cases" list reported and its "results" list ignored.
func (t TaskStatus) caseList() []CaseStatus {
	if len(t.Cases) > 0 {
		return t.Cases
	}
	return t.Results
}

// Progress returns the finished case count and the total the service reported,
// in that order. Both are zero when no case list was recognised, so a caller
// MUST check total > 0 before computing a percentage: done*100/total divides by
// zero otherwise. A case whose Error field is set still counts as done - the
// service finished with it, so a failed case must not stall the reported
// percentage below 100.
func (t TaskStatus) Progress() (done, total int) {
	cases := t.caseList()
	for _, c := range cases {
		if c.ResultID != "" || c.Error != "" {
			done++
		}
	}
	return done, len(cases)
}

// ProgressPercent returns the task's completion in percent, and whether the
// service reported anything to base it on.
//
// v1 of the service reports task-level progress: a finished case counts 100, a
// running case contributes its own percentage, and the value stays below 100
// until the task reaches its terminal state. A service that predates the field
// omits it, so the per-case list is averaged here instead - the same scale,
// just coarser between case boundaries.
func (t TaskStatus) ProgressPercent() (float64, bool) {
	if t.TaskProgress != nil {
		return clampPercent(*t.TaskProgress, 100), true
	}
	cases := t.caseList()
	if len(cases) == 0 {
		return 0, false
	}
	sum := 0.0
	for _, c := range cases {
		if isFinishedCase(c) {
			sum += 100
			continue
		}
		sum += clampPercent(c.Progress, 99)
	}
	return sum / float64(len(cases)), true
}

// isFinishedCase reports whether the service is done with a case. A failed or
// cancelled case still counts as finished, so it must not hold the reported
// percentage below 100; the per-case progress of a case the service has not
// started is zero anyway.
func isFinishedCase(c CaseStatus) bool {
	if c.ResultID != "" || c.Error != "" {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(c.Status)) {
	case "completed", "failed", "cancelled":
		return true
	}
	return false
}

// clampPercent keeps a value the service reported within [0, maxValue]. The
// service owns these numbers; the clamp only makes a malformed one harmless,
// since the platform rejects a percentage outside 0-100 outright.
func clampPercent(value, maxValue int) float64 {
	if value < 0 {
		return 0
	}
	if value > maxValue {
		return float64(maxValue)
	}
	return float64(value)
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

// Task fetches a task's state. The body carries the status this package waits
// on, so an empty one is an error rather than a zero TaskStatus.
func (c *Client) Task(ctx context.Context, taskID, userID string) (TaskStatus, error) {
	var st TaskStatus
	if err := guardTaskCall(taskID, userID); err != nil {
		return st, err
	}
	err := c.do(ctx, http.MethodGet, "/tasks/"+url.PathEscape(taskID), userID, nil, &st, false)
	return st, err
}

// maxTaskLogBytes bounds one replay of a task's terminal log. The log is
// re-read on every poll, so the cap is what keeps a runaway progress bar from
// growing the poll response without limit.
const maxTaskLogBytes = 8 << 20

// TaskLogs fetches the task's terminal log.
//
// The request asks for follow=false. The service's default follows the live
// stream and only returns once the task ends, which would make polling a
// second, slower copy of the callback; with follow=false it replays everything
// logged so far and closes, so each poll answers with the whole log and the
// caller is the one that must not report the replayed prefix twice.
func (c *Client) TaskLogs(ctx context.Context, taskID, userID string) (string, error) {
	if err := guardTaskCall(taskID, userID); err != nil {
		return "", err
	}
	path := "/tasks/" + url.PathEscape(taskID) + "/logs?follow=false"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return "", fmt.Errorf("build fhe log request for task %s: %w", taskID, err)
	}
	req.Header.Set("X-User-Id", userID)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("fhe task log for %s: %w", taskID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return "", &APIError{Method: http.MethodGet, Path: path, StatusCode: resp.StatusCode, Body: string(snippet)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTaskLogBytes+1))
	if err != nil {
		return "", fmt.Errorf("read fhe task log for %s: %w", taskID, err)
	}
	if len(body) > maxTaskLogBytes {
		return "", fmt.Errorf("fhe task log for %s exceeds %d bytes", taskID, maxTaskLogBytes)
	}
	return string(body), nil
}

// CancelTask maps TAA's stopTraining onto the service's cancel endpoint.
func (c *Client) CancelTask(ctx context.Context, taskID, userID string) error {
	if err := guardTaskCall(taskID, userID); err != nil {
		return err
	}
	var st map[string]any
	return c.do(ctx, http.MethodPost, "/tasks/"+url.PathEscape(taskID)+"/cancel", userID, nil, &st, true)
}

// ContinueTask re-runs the unfinished cases of a task that already exists, which
// is how a replayed import is retried instead of creating a second task.
func (c *Client) ContinueTask(ctx context.Context, taskID, userID string) error {
	if err := guardTaskCall(taskID, userID); err != nil {
		return err
	}
	var st map[string]any
	return c.do(ctx, http.MethodPost, "/tasks/"+url.PathEscape(taskID)+"/continue", userID, nil, &st, true)
}

// DownloadResult fetches output.zip and writes it to dst, creating parent
// directories. It is the fallback used when the shared directory does not hold
// the result - for instance when TAA and the service are not on one host.
//
// The archive is streamed by the download client, which has no whole-request
// timeout, so the caller's context is what bounds it. There is deliberately no
// size cap here: neither result archives nor eval keys are bounded by one.
func (c *Client) DownloadResult(ctx context.Context, taskID, userID, dst string) error {
	if err := guardTaskCall(taskID, userID); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/tasks/"+url.PathEscape(taskID)+"/results/download", nil)
	if err != nil {
		return fmt.Errorf("build result download request for task %s: %w", taskID, err)
	}
	req.Header.Set("X-User-Id", userID)
	resp, err := c.download.Do(req)
	if err != nil {
		return fmt.Errorf("download result for task %s: %w", taskID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return &APIError{Method: http.MethodGet, Path: "/tasks/" + taskID + "/results/download",
			StatusCode: resp.StatusCode, Body: string(snippet)}
	}
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create result dir %s for task %s: %w", dir, taskID, err)
	}
	// The archive is staged next to dst and renamed into place, so a reader never
	// sees a partial file: after the rename, "dst exists" means "dst is complete".
	// The staging name is unique per attempt, so two concurrent downloads of one
	// task cannot truncate each other's bytes into the same temp file.
	f, err := os.CreateTemp(dir, filepath.Base(dst)+".partial.*")
	if err != nil {
		return fmt.Errorf("create result temp file in %s for task %s: %w", dir, taskID, err)
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // a no-op once the rename moved it
	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		return fmt.Errorf("set result temp file mode for task %s: %w", taskID, err)
	}
	written, err := io.Copy(f, resp.Body)
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("write result file for task %s to %s after %d bytes: %w", taskID, dst, written, err)
	}
	// Syncing before the rename is what keeps the invariant above true across a
	// crash: without it the rename can land while the bytes are still in the page
	// cache, leaving a short or empty output.zip under the final name.
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync result file for task %s to %s (%d bytes): %w", taskID, dst, written, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close result file for task %s to %s (%d bytes): %w", taskID, dst, written, err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		return fmt.Errorf("move result for task %s into place at %s (%d bytes): %w", taskID, dst, written, err)
	}
	if parent, err := os.Open(dir); err == nil {
		_ = parent.Sync()
		_ = parent.Close()
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
