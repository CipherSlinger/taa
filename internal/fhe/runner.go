package fhe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Task status values this package produces locally. The service's own status
// string is passed through as-is; these three are used when no service status is
// available.
const (
	StatusCompleted = "completed"
	StatusFailed    = "failed"
	StatusCancelled = "cancelled"
)

// Level is a log severity the runner emits.
type Level string

const (
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

// Logger receives the runner's progress messages. It is nil-safe: a nil Logger
// discards everything, which is what tests use.
type Logger func(level Level, scope, format string, args ...any)

// TaskSpec is everything needed to run one FHE task.
type TaskSpec struct {
	TaskID    string
	RequestID string
	// UserID is the eval key digest, and doubles as the FHE-side user id.
	UserID string
	// ModelID is the model package digest, and doubles as the FHE-side model id.
	ModelID     string
	EvalKeyHash string
	EvalKeyURL  string
	// InputZipPath is the local plaintext archive the caller already resolved.
	// Reusing it avoids downloading the same bytes twice and reuses the import
	// download cap the caller already enforced.
	InputZipPath string
}

// TaskOutcome is a task's terminal state.
type TaskOutcome struct {
	Status    string
	Total     int
	Failed    int
	ResultZip string
	Err       error
}

// CallbackPayload is what the FHE service POSTs when a task reaches a terminal
// state.
type CallbackPayload struct {
	TaskID    string       `json:"task_id"`
	Status    string       `json:"status"`
	ResultZip string       `json:"result_zip"`
	Cases     []CaseStatus `json:"cases"`
}

// ParseCallback decodes a callback body. Both snake_case and camelCase spellings
// are accepted: the casing is the service's to choose, and rejecting the wrong
// guess would drop a terminal state and leave the task to time out.
func ParseCallback(body []byte) (CallbackPayload, error) {
	var raw struct {
		TaskID         string       `json:"task_id"`
		TaskIDCamel    string       `json:"taskId"`
		Status         string       `json:"status"`
		ResultZip      string       `json:"result_zip"`
		ResultZipCamel string       `json:"resultZip"`
		Cases          []CaseStatus `json:"cases"`
		Results        []CaseStatus `json:"results"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return CallbackPayload{}, fmt.Errorf("decode fhe callback: %w", err)
	}
	p := CallbackPayload{
		TaskID:    firstNonEmpty(raw.TaskID, raw.TaskIDCamel),
		Status:    strings.TrimSpace(raw.Status),
		ResultZip: firstNonEmpty(raw.ResultZip, raw.ResultZipCamel),
		Cases:     raw.Cases,
	}
	if len(p.Cases) == 0 {
		p.Cases = raw.Results
	}
	if p.TaskID == "" {
		return CallbackPayload{}, fmt.Errorf("fhe callback has no task id")
	}
	if p.Status == "" {
		return CallbackPayload{}, fmt.Errorf("fhe callback for task %s has no status", p.TaskID)
	}
	return p, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// taskRun is the in-flight state of one task, shared between the polling
// goroutine and the callback handler.
type taskRun struct {
	spec    TaskSpec
	done    chan struct{}
	once    sync.Once
	outcome TaskOutcome
}

// Runner drives FHE tasks.
//
// One runner serves the whole process: it owns the key cache, the shared
// directory, and the table of in-flight tasks that lets a callback delivered on
// an unrelated HTTP request advance the task its importer is waiting on.
type Runner struct {
	cfg    Config
	layout Layout
	keys   *KeyCache
	client *Client
	logf   Logger

	mu    sync.Mutex
	tasks map[string]*taskRun
}

// New builds a runner, creating the key cache directory.
func New(cfg Config, logf Logger) (*Runner, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	client, err := NewClient(cfg.Endpoint, cfg.RequestTimeout)
	if err != nil {
		return nil, err
	}
	keys, err := NewKeyCache(cfg.KeyCacheDir, cfg.MaxEvalKeyBytes)
	if err != nil {
		return nil, err
	}
	return &Runner{
		cfg:    cfg,
		layout: NewLayout(cfg.DataDir),
		keys:   keys,
		client: client,
		logf:   logf,
		tasks:  map[string]*taskRun{},
	}, nil
}

// Config returns the runner's configuration.
func (r *Runner) Config() Config { return r.cfg }

// Layout returns the shared-directory layout.
func (r *Runner) Layout() Layout { return r.layout }

// Client returns the underlying API client.
func (r *Runner) Client() *Client { return r.client }

func (r *Runner) log(level Level, format string, args ...any) {
	if r.logf == nil {
		return
	}
	r.logf(level, "fhe", format, args...)
}

func (r *Runner) lookup(taskID string) *taskRun {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tasks[taskID]
}

// registerTestRun exposes task registration to tests without going through the
// service. Production code registers through prepare.
func (r *Runner) registerTestRun(taskID string, spec TaskSpec) *taskRun {
	run := &taskRun{spec: spec, done: make(chan struct{})}
	r.mu.Lock()
	r.tasks[taskID] = run
	r.mu.Unlock()
	return run
}

func (r *Runner) lookupForTest(taskID string) *taskRun { return r.lookup(taskID) }

func (r *Runner) forget(taskID string) {
	r.mu.Lock()
	delete(r.tasks, taskID)
	r.mu.Unlock()
}

// finish resolves a run exactly once and reports whether this call is the one
// that resolved it. Every path to a terminal state goes through here, which is
// what makes the service's 0/1/4/16s callback retries and a callback/poll race
// collapse into a single transition.
func (r *Runner) finish(run *taskRun, out TaskOutcome) (TaskOutcome, bool) {
	won := false
	run.once.Do(func() {
		run.outcome = out
		won = true
		close(run.done)
	})
	return run.outcome, won
}

// ResolveTask reports the terminal state of an in-flight task.
func (r *Runner) ResolveTask(taskID string) (TaskOutcome, bool) {
	run := r.lookup(taskID)
	if run == nil {
		return TaskOutcome{}, false
	}
	select {
	case <-run.done:
		return run.outcome, true
	default:
		return TaskOutcome{}, false
	}
}

// Deliver records a terminal callback. It returns true only for the delivery
// that actually advanced the task, so a retry or a race with the poller is a
// no-op.
func (r *Runner) Deliver(p CallbackPayload) bool {
	run := r.lookup(p.TaskID)
	if run == nil {
		r.log(LevelWarn, "收到未知任务的回调，已忽略: taskId=%s", p.TaskID)
		return false
	}
	_, won := r.finish(run, r.outcomeFromStatus(run.spec, TaskStatus{
		TaskID: p.TaskID, Status: p.Status, ResultZip: p.ResultZip, Cases: p.Cases,
	}))
	return won
}

// Cancel maps TAA's stopTraining onto the service's cancel endpoint and resolves
// the local run.
//
// A task this instance does not track is refused rather than cancelled: the
// tenant the service scopes every task call by is the eval key digest, which is
// known only for an in-flight task, and the table holding it is in memory, so it
// is empty after a restart. Sending the cancel anyway would put TAA in the worst
// possible position: the service answers a tenant-less cancel without matching
// the task, so the call returns 2xx for a cancel that did nothing and TAA
// reports that no-op to the platform as a success. Reporting the task as unknown
// is the only answer here that is true, and Cancel is TAA's stopTraining, which
// must not claim a stop that never happened.
func (r *Runner) Cancel(ctx context.Context, taskID string) error {
	run := r.lookup(taskID)
	if run == nil {
		return fmt.Errorf("fhe task %s is not in flight on this TAA instance, so it cannot be cancelled: "+
			"it either never ran here, already finished, or was started before the last restart. "+
			"The FHE service scopes task calls by tenant and the tenant is known only for an in-flight task, "+
			"so no cancel request was sent; cancel it through the FHE service directly if it is still running", taskID)
	}
	sendCtx, cancel := context.WithTimeout(ctx, r.cfg.RequestTimeout)
	defer cancel()
	if err := r.client.CancelTask(sendCtx, taskID, run.spec.UserID); err != nil {
		return err
	}
	r.finish(run, TaskOutcome{Status: StatusCancelled, Err: fmt.Errorf("fhe task %s was cancelled", taskID)})
	return nil
}

// Execute runs one task to a terminal state.
//
// It publishes the eval key and the input archive into the shared directory,
// creates the task, then waits for the callback or the poll fallback, whichever
// arrives first, bounded by TaskTimeout. onProgress, when non-nil, receives the
// finished and total case counts the service reported.
func (r *Runner) Execute(ctx context.Context, spec TaskSpec, onProgress func(done, total int)) (TaskOutcome, error) {
	run, err := r.prepare(spec)
	if err != nil {
		return TaskOutcome{Status: StatusFailed, Err: err}, err
	}
	defer r.forget(spec.TaskID)

	createCtx, cancel := context.WithTimeout(ctx, r.cfg.RequestTimeout)
	err = r.client.CreateTask(createCtx, CreateTaskRequest{
		UserID:             spec.UserID,
		ModelID:            spec.ModelID,
		TaskID:             spec.TaskID,
		CallbackURL:        r.cfg.CallbackURL(),
		CancelOnDisconnect: false,
	})
	cancel()
	if err != nil {
		// A replayed import must resume the task that already exists rather than
		// create a second one: the input package is still on disk and the service
		// keeps per-case results, so /continue reruns only what is unfinished.
		probeCtx, probeCancel := context.WithTimeout(ctx, r.cfg.RequestTimeout)
		_, probeErr := r.client.Task(probeCtx, spec.TaskID, spec.UserID)
		probeCancel()
		if probeErr != nil {
			out := TaskOutcome{Status: StatusFailed, Err: fmt.Errorf("create fhe task: %w", err)}
			r.finish(run, out)
			return out, out.Err
		}
		r.log(LevelInfo, "任务已存在，改用 continue 重跑未完成 case: taskId=%s", spec.TaskID)
		contCtx, contCancel := context.WithTimeout(ctx, r.cfg.RequestTimeout)
		contErr := r.client.ContinueTask(contCtx, spec.TaskID, spec.UserID)
		contCancel()
		if contErr != nil {
			out := TaskOutcome{Status: StatusFailed, Err: fmt.Errorf("continue existing fhe task: %w (create failed: %v)", contErr, err)}
			r.finish(run, out)
			return out, out.Err
		}
	}

	return r.wait(ctx, run, onProgress)
}

// prepare validates the spec, publishes the key and the input package, and
// registers the run. Registration happens before the task is created so a
// callback that arrives immediately still finds the run.
func (r *Runner) prepare(spec TaskSpec) (*taskRun, error) {
	if !ValidHash(spec.EvalKeyHash) {
		return nil, fmt.Errorf("invalid eval key hash %q: want 64 lowercase hex characters", spec.EvalKeyHash)
	}
	if !ValidHash(spec.ModelID) {
		return nil, fmt.Errorf("invalid model hash %q: want 64 lowercase hex characters", spec.ModelID)
	}
	if err := ValidTaskID(spec.TaskID); err != nil {
		return nil, err
	}
	if strings.TrimSpace(spec.InputZipPath) == "" {
		return nil, fmt.Errorf("input archive path is empty")
	}

	keySrc, err := r.keys.Ensure(spec.EvalKeyHash, spec.EvalKeyURL)
	if err != nil {
		return nil, err
	}
	keyDst, err := r.layout.KeyPath(spec.EvalKeyHash)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(keyDst), 0o755); err != nil {
		return nil, fmt.Errorf("create the shared key dir: %w", err)
	}
	if err := linkOrCopy(keySrc, keyDst); err != nil {
		return nil, fmt.Errorf("publish the eval key into the shared dir: %w", err)
	}

	inDst, err := r.layout.TaskInputPath(spec.TaskID)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(inDst), 0o755); err != nil {
		return nil, fmt.Errorf("create the shared task dir: %w", err)
	}
	if err := copyFileAtomic(spec.InputZipPath, inDst); err != nil {
		return nil, fmt.Errorf("publish the input archive into the shared dir: %w", err)
	}

	run := &taskRun{spec: spec, done: make(chan struct{})}
	r.mu.Lock()
	r.tasks[spec.TaskID] = run
	r.mu.Unlock()
	r.log(LevelInfo, "已下发 FHE 任务: taskId=%s, userId=%s, modelId=%s", spec.TaskID, spec.UserID, spec.ModelID)
	return run, nil
}

func (r *Runner) wait(ctx context.Context, run *taskRun, onProgress func(done, total int)) (TaskOutcome, error) {
	deadline := time.NewTimer(r.cfg.TaskTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(r.cfg.PollInterval)
	defer ticker.Stop()

	for {
		if out, ok := r.pollOnce(ctx, run, onProgress); ok {
			r.finish(run, out)
			final, _ := r.finish(run, out)
			return final, final.Err
		}
		select {
		case <-run.done:
			select {
			case <-ctx.Done():
			default:
			}
			return run.outcome, run.outcome.Err
		case <-ticker.C:
		case <-deadline.C:
			out, _ := r.finish(run, TaskOutcome{
				Status: StatusFailed,
				Err:    fmt.Errorf("fhe task %s timed out after %s", run.spec.TaskID, r.cfg.TaskTimeout),
			})
			r.log(LevelError, "FHE 任务超时: taskId=%s, timeout=%s", run.spec.TaskID, r.cfg.TaskTimeout)
			return out, out.Err
		case <-ctx.Done():
			out, _ := r.finish(run, TaskOutcome{Status: StatusFailed, Err: ctx.Err()})
			return out, out.Err
		}
	}
}

// pollOnce asks the service for the task state once. It reports ok when the task
// reached a terminal state.
func (r *Runner) pollOnce(ctx context.Context, run *taskRun, onProgress func(done, total int)) (TaskOutcome, bool) {
	pollCtx, cancel := context.WithTimeout(ctx, r.cfg.RequestTimeout)
	defer cancel()

	st, err := r.client.Task(pollCtx, run.spec.TaskID, run.spec.UserID)
	if err != nil {
		// A poll failure is never fatal: the callback is the primary channel and
		// the timeout is the backstop, so a transient error only means trying again.
		r.log(LevelWarn, "轮询 FHE 任务状态失败，将继续重试: taskId=%s, err=%v", run.spec.TaskID, err)
		return TaskOutcome{}, false
	}
	if onProgress != nil {
		if done, total := st.Progress(); total > 0 {
			onProgress(done, total)
		}
	}
	if !IsTerminal(st.Status) {
		return TaskOutcome{}, false
	}
	return r.outcomeFromStatus(run.spec, st), true
}

// outcomeFromStatus converts a terminal service status into a run outcome,
// locating the result archive.
func (r *Runner) outcomeFromStatus(spec TaskSpec, st TaskStatus) TaskOutcome {
	out := TaskOutcome{Status: strings.ToLower(strings.TrimSpace(st.Status))}
	// Progress reports (done, total). The outcome keeps the total and the number
	// of cases the service reported as failed; the finished count is reporting
	// only, and travels through onProgress instead.
	_, out.Total = st.Progress()
	out.Failed = st.Failed()
	if out.Status == "" {
		out.Status = StatusFailed
	}
	if !IsSuccess(out.Status) {
		out.Err = fmt.Errorf("fhe task %s ended with status %q (%d/%d cases failed)",
			spec.TaskID, st.Status, out.Failed, out.Total)
	}
	if p, err := r.layout.ResultPath(spec.TaskID); err == nil {
		if _, statErr := os.Stat(p); statErr == nil {
			out.ResultZip = p
		}
	}
	return out
}

// CopyResult makes the task's result archive available at dst and returns the
// path it used.
//
// The shared directory is the primary source, because TAA and the FHE service
// are on one host and reading a file beats re-downloading it. A service that did
// not write there - a split deployment, or a task whose results were cleaned up -
// is covered by the download fallback.
//
// The return value is NOT dst, in either branch, and callers must not treat it
// as the published location: on the shared-directory hit it is the source path
// inside the shared directory, and on the download fallback it is the empty
// string. dst is the only path that holds the result in both cases, so that is
// the one to hand to whatever publishes it.
func (r *Runner) CopyResult(ctx context.Context, spec TaskSpec, out TaskOutcome, dst string) (string, error) {
	if out.ResultZip != "" {
		if err := copyFileAtomic(out.ResultZip, dst); err != nil {
			return "", fmt.Errorf("copy the shared-directory result: %w", err)
		}
		return out.ResultZip, nil
	}
	// A result archive is a bulk transfer, not a request/response round trip, so
	// RequestTimeout - a per-call budget that defaults to 30s - is the wrong bound
	// for it: with it, any archive that needed longer than 30s died mid-body even
	// though the download client has no whole-request timeout of its own.
	// TaskTimeout is the budget this config already has for "as long as one task
	// may take", which is the scale a multi-gigabyte archive belongs to. It is
	// derived from the caller's ctx, so cancelling the caller still cancels the
	// transfer.
	dlCtx, cancel := context.WithTimeout(ctx, r.cfg.TaskTimeout)
	defer cancel()
	if err := r.client.DownloadResult(dlCtx, spec.TaskID, spec.UserID, dst); err != nil {
		return "", fmt.Errorf("download the task result: %w", err)
	}
	return "", nil
}

// linkOrCopy hard-links src to dst, falling back to a copy when the two are not
// on one filesystem. A hard link is what keeps publishing a 3.1 GiB eval key
// free; the copy fallback costs one extra copy, not a wrong result.
//
// The destination is left mode 0644 because the FHE service reads it from a
// container running as a different user. On a hard link this also relaxes the
// source's mode, which is fine: the cache holds public keys.
func linkOrCopy(src, dst string) error {
	if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Link(src, dst); err == nil {
		return os.Chmod(dst, 0o644)
	}
	if err := copyFileAtomic(src, dst); err != nil {
		return err
	}
	return os.Chmod(dst, 0o644)
}

// copyFileAtomic stages the copy next to its destination and renames it into
// place, so a reader never observes a half-written archive.
func copyFileAtomic(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp := dst + ".partial"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
