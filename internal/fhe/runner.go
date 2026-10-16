package fhe

import (
	"context"
	"encoding/json"
	"errors"
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

// SetLogger installs the logger after construction, for callers that only have
// a logger once the state they log into exists.
func (r *Runner) SetLogger(logf Logger) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logf = logf
}

func (r *Runner) log(level Level, format string, args ...any) {
	r.mu.Lock()
	logf := r.logf
	r.mu.Unlock()
	if logf == nil {
		return
	}
	logf(level, "fhe", format, args...)
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

// forget drops run from the in-flight table, but only if the table still holds
// that very run.
//
// Two Executes for one task id - a replayed import, or a platform retry while
// the first is still in flight - both run to completion, and the second
// prepare replaces the first's entry. Deleting by id alone therefore lets
// whichever run returns first delete the other's entry, after which that run's
// callbacks are dropped as "unknown task" and Cancel can no longer find it.
func (r *Runner) forget(run *taskRun) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur, ok := r.tasks[run.spec.TaskID]; ok && cur == run {
		delete(r.tasks, run.spec.TaskID)
	}
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
//
// The callback channel and the polling channel must agree on what ends a task:
// both decide with IsTerminal, and Deliver used not to. Without that agreement a
// callback carrying a non-terminal status - "running", which is out of contract
// but arrives over the same wire - resolved the run as failed while the service
// was still burning the GPU on it, and the poller was then shut out by the
// once-only transition.
//
// Every terminal status the service can emit is inside IsTerminal: the status
// vocabulary is queued / running / completed / failed / cancelled (tools/fake-fhe
// implements the contract), and IsTerminal also covers the plausible synonyms
// succeeded / success / error / canceled / timeout / timed_out / expired /
// deleted. A status word outside that set is treated as non-terminal here, so
// such a callback is ignored and the run is left to its poll and its TaskTimeout
// - it waits for the timeout instead of being resolved, which is the failure
// mode this predicate trades for.
func (r *Runner) Deliver(p CallbackPayload) bool {
	run := r.lookup(p.TaskID)
	if run == nil {
		r.log(LevelWarn, "收到未知任务的回调，已忽略: taskId=%s", p.TaskID)
		return false
	}
	if !IsTerminal(p.Status) {
		r.log(LevelWarn, "收到非终态回调，已忽略: taskId=%s, status=%s", p.TaskID, p.Status)
		return false
	}
	_, won := r.finish(run, r.outcomeFromStatus(run.spec, TaskStatus{
		TaskID: p.TaskID, Status: p.Status, ResultZip: p.ResultZip, Cases: p.Cases,
	}))
	return won
}

// ErrTaskAlreadyFinished reports that Cancel was called for a task this instance
// did run and that had already reached a terminal state.
//
// It is a distinct value rather than a plain message because the two refusals
// are opposite from the caller's side. A task this instance never tracked is a
// stop that cannot be performed and must be reported as such; a task that
// finished a moment ago is a stop that does not have to be performed, and the
// platform's stopTraining arriving just after a task ends is a race common
// enough that reporting it as a failed stop would be wrong. Callers tell the two
// apart with errors.Is.
var ErrTaskAlreadyFinished = errors.New("fhe task already finished")

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
//
// A run that already reached a terminal state is a third case, and it is not a
// refusal in the same sense: the run is over, so there is nothing to cancel and
// nothing to report as broken. It is reported through ErrTaskAlreadyFinished,
// without a request, so a caller does not have to treat "it just finished" as a
// failed stop.
func (r *Runner) Cancel(ctx context.Context, taskID string) error {
	run := r.lookup(taskID)
	if run == nil {
		return fmt.Errorf("fhe task %s is not in flight on this TAA instance, so it cannot be cancelled: "+
			"it either never ran here, already finished, or was started before the last restart. "+
			"The FHE service scopes task calls by tenant and the tenant is known only for an in-flight task, "+
			"so no cancel request was sent; cancel it through the FHE service directly if it is still running", taskID)
	}
	// Reading run.outcome after observing done closed is ordered by the channel
	// close, which finish performs after storing the outcome.
	select {
	case <-run.done:
		return fmt.Errorf("fhe task %s already reached the terminal state %q, so there is nothing to cancel "+
			"and no cancel request was sent: %w", taskID, run.outcome.Status, ErrTaskAlreadyFinished)
	default:
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
//
// The task's budget is derived here, at the entry, and covers staging as well as
// waiting: publishing the key is a multi-gigabyte download when the cache is
// cold, so a key server that never answers would otherwise hold the import
// goroutine open forever, and TaskTimeout's claim to bound "a whole task" would
// be false. Staging, the create/probe/continue calls and the wait all run on
// that one deadline, so the caller's cancellation stops staging too.
func (r *Runner) Execute(ctx context.Context, spec TaskSpec, onProgress func(done, total int)) (TaskOutcome, error) {
	deadline := time.Now().Add(r.cfg.TaskTimeout)
	stageCtx, cancelStage := context.WithDeadline(ctx, deadline)
	defer cancelStage()

	run, err := r.prepare(stageCtx, spec)
	if err != nil {
		return TaskOutcome{Status: StatusFailed, Err: err}, err
	}
	defer r.forget(run)

	createCtx, cancel := context.WithTimeout(stageCtx, r.cfg.RequestTimeout)
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
		//
		// The probe's answer is what decides whether that is the right move, so it
		// is kept. It used to be discarded, and a task that had already completed
		// was then handed a /continue that reset it to running and threw away the
		// result already sitting in the shared directory.
		//
		// The probe proves only that a task with this id exists for this tenant. It
		// cannot prove the task belongs to this spec, so reusing one task id for
		// two different specs is the caller's responsibility.
		probeCtx, probeCancel := context.WithTimeout(stageCtx, r.cfg.RequestTimeout)
		st, probeErr := r.client.Task(probeCtx, spec.TaskID, spec.UserID)
		probeCancel()
		if probeErr != nil {
			out := TaskOutcome{Status: StatusFailed, Err: fmt.Errorf("create fhe task: %w", err)}
			r.finish(run, out)
			return out, out.Err
		}
		// A task that already ran to a successful end is adopted as it is: it has
		// a stored result, and /continue on it would destroy that result to rerun
		// cases that are already done. A task that ended unsuccessfully is the case
		// the design's replay rule covers - rerun the unfinished cases rather than
		// report the old failure a second time - so only that one is continued.
		if IsSuccess(st.Status) {
			out, _ := r.finish(run, r.outcomeFromStatus(spec, st))
			r.log(LevelInfo, "任务已完成，直接采用服务端结果: taskId=%s, status=%s", spec.TaskID, st.Status)
			return out, out.Err
		}
		r.log(LevelInfo, "任务已存在，改用 continue 重跑未完成 case: taskId=%s, status=%s", spec.TaskID, st.Status)
		contCtx, contCancel := context.WithTimeout(stageCtx, r.cfg.RequestTimeout)
		contErr := r.client.ContinueTask(contCtx, spec.TaskID, spec.UserID)
		contCancel()
		if contErr != nil {
			out := TaskOutcome{Status: StatusFailed, Err: fmt.Errorf("continue existing fhe task: %w (create failed: %v)", contErr, err)}
			r.finish(run, out)
			return out, out.Err
		}
	}

	return r.wait(ctx, run, deadline, onProgress)
}

// prepare validates the spec, publishes the key and the input package, and
// registers the run. Registration happens before the task is created so a
// callback that arrives immediately still finds the run.
//
// ctx is the task's context, so cancelling the caller aborts a cold-cache key
// download instead of leaving it running behind a returned Execute.
func (r *Runner) prepare(ctx context.Context, spec TaskSpec) (*taskRun, error) {
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

	keySrc, err := r.keys.Ensure(ctx, spec.EvalKeyHash, spec.EvalKeyURL)
	if err != nil {
		return nil, err
	}
	keyDst, err := r.layout.KeyPath(spec.EvalKeyHash)
	if err != nil {
		return nil, err
	}
	// MkdirShared rather than MkdirAll: the service has to traverse these
	// directories as another user, and MkdirAll would leave them at the umask's
	// answer. See Layout.MkdirShared.
	if err := r.layout.MkdirShared(filepath.Dir(keyDst)); err != nil {
		return nil, fmt.Errorf("create the shared key dir: %w", err)
	}
	if err := linkOrCopy(keySrc, keyDst); err != nil {
		return nil, fmt.Errorf("publish the eval key into the shared dir: %w", err)
	}

	inDst, err := r.layout.TaskInputPath(spec.TaskID)
	if err != nil {
		return nil, err
	}
	if err := r.layout.MkdirShared(filepath.Dir(inDst)); err != nil {
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

// wait blocks until the run reaches a terminal state, through any of its four
// channels: a poll that saw one, a callback that resolved the run while this
// loop was sleeping, the task's own deadline, or the caller giving up.
//
// deadline is the one derived in Execute, not a fresh TaskTimeout: staging has
// already spent part of the budget, and giving the wait its own full timeout
// would let one task run for a multiple of what Config.TaskTimeout promises.
func (r *Runner) wait(ctx context.Context, run *taskRun, deadline time.Time, onProgress func(done, total int)) (TaskOutcome, error) {
	expired := time.NewTimer(time.Until(deadline))
	defer expired.Stop()
	// The polls are bounded by whichever runs out first: the per-call request
	// budget, or what is left of the task budget. The task deadline itself is
	// reported by the timer below rather than by ctx, so which of the two ends the
	// task does not change the error the caller sees.
	pollCtx, stopPolling := context.WithDeadline(ctx, deadline)
	defer stopPolling()
	ticker := time.NewTicker(r.cfg.PollInterval)
	defer ticker.Stop()

	for {
		if out, ok := r.pollOnce(pollCtx, run, onProgress); ok {
			final, _ := r.finish(run, out)
			return final, final.Err
		}
		select {
		case <-run.done:
			// A callback delivered while this loop was waiting: the callback
			// channel's whole purpose is to resolve a run its importer is waiting
			// on, so this is the path a healthy task normally takes.
			return run.outcome, run.outcome.Err
		case <-ticker.C:
		case <-expired.C:
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

// linkOrCopy publishes src at dst without ever destroying what is already there.
//
// A hard link is what keeps publishing a 3.1 GiB eval key free; the copy
// fallback costs one extra copy, not a wrong result.
//
// Both paths stage next to dst and rename into place. Removing dst and only then
// linking - which is what this used to do - has two failures: a link that fails
// after the remove leaves no key at all where a good one was, and in between the
// two calls a reader sees no key. A rename is atomic, so the published path only
// ever holds a complete file.
//
// The destination is left mode 0644 because the FHE service reads it from a
// container running as a different user. On a hard link this also relaxes the
// source's mode, which is fine: the cache holds public keys.
func linkOrCopy(src, dst string) error {
	dir := filepath.Dir(dst)
	// A safety net only: the shared data directory this publishes into is created
	// by Layout.MkdirShared, which is what fixes its mode for the service.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	staged, err := stagePath(dir, filepath.Base(dst))
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(staged) }() // a no-op once the rename moved it

	// Anything but a successful link - a different filesystem, the link limit,
	// permissions - falls back to the copy.
	if err := os.Link(src, staged); err != nil {
		if err := copyFileAtomic(src, staged); err != nil {
			return err
		}
	}
	// 0644 explicitly, for the reason above: the process umask must not decide
	// whether the service can read the key it is being handed.
	if err := os.Chmod(staged, 0o644); err != nil {
		return err
	}
	return os.Rename(staged, dst)
}

// stagePath reserves a unique staging path in dir for a file named base.
//
// The name must be unique per attempt, and must not be derived from the
// destination alone: copyFileAtomic is called with no lock at all on the shared
// data directory, so a fixed "<dst>.partial" name lets two publishers of one
// destination open the same staging file and truncate each other's bytes. This
// is the hazard client.DownloadResult already avoids with os.CreateTemp.
//
// The file CreateTemp made is removed so the caller gets a free name it can
// create itself, which is what os.Link needs; the window in which another
// process could take the name is the width of the random name's collision odds.
func stagePath(dir, base string) (string, error) {
	f, err := os.CreateTemp(dir, base+".partial.*")
	if err != nil {
		return "", err
	}
	name := f.Name()
	if err := f.Close(); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	if err := os.Remove(name); err != nil {
		return "", err
	}
	return name, nil
}

// fsyncFile pushes a file's bytes to stable storage, so a rename that follows
// cannot land ahead of the data it names.
func fsyncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// fsyncDir pushes a directory's entries to stable storage, which is what makes a
// rename inside it survive a crash. Callers treat a failure as best-effort, the
// way client.DownloadResult does: the file itself is already synced.
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// copyFileAtomic stages the copy next to its destination and renames it into
// place, so a reader never observes a half-written archive.
//
// The staging name is unique per attempt rather than a fixed "<dst>.partial";
// see stagePath. The file is synced before the rename, so "dst exists" keeps
// meaning "dst is complete" across a crash as well as between processes, and it
// is 0644 in spite of the umask, because the FHE service reads these archives
// from a container running as another user.
func copyFileAtomic(src, dst string) error {
	dir := filepath.Dir(dst)
	// A safety net only, and deliberately left at 0755-and-umask: dst is a shared
	// data directory (already created by Layout.MkdirShared) or a destination of
	// TAA's own that no other user reads. See Layout.MkdirShared for the modes
	// that are load-bearing.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp, err := stagePath(dir, filepath.Base(dst))
	if err != nil {
		return err
	}
	// O_EXCL because stagePath released the name: this holds it for the whole copy.
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Chmod(0o644); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Sync(); err != nil {
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
	_ = fsyncDir(dir)
	return nil
}
