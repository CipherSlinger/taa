package controller

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"taa/internal/platform"
	"taa/pkg/utils"
)

const (
	defaultReportRetryInitial = time.Second
	defaultReportRetryMax     = 60 * time.Second
	// reportSendTimeout mirrors the platform client's own limit: one send cannot
	// outlive the request it makes, so the two must not drift apart.
	reportSendTimeout = platform.DefaultTimeout
)

// clonePendingReport deep-copies the map field so the sealed state never shares
// memory with the live outbox entry.
func clonePendingReport(in PendingReportSnapshot) PendingReportSnapshot {
	out := in
	if in.Checksum != nil {
		out.Checksum = make(map[string]any, len(in.Checksum))
		for k, v := range in.Checksum {
			out.Checksum[k] = v
		}
	}
	return out
}

// clonePendingReports deep-copies a whole queue. It is used on both sides of the
// sealed state boundary, which is why it lives next to the per-entry clone.
func clonePendingReports(in []PendingReportSnapshot) []PendingReportSnapshot {
	if len(in) == 0 {
		return nil
	}
	out := make([]PendingReportSnapshot, len(in))
	for i := range in {
		out[i] = clonePendingReport(in[i])
	}
	return out
}

// retryState is one entry's backoff schedule. It is in-memory only: a restart
// retries everything immediately, which is the right response to a restart.
type retryState struct {
	wait time.Duration
	due  time.Time
}

// reportOutbox drains pendingReports in FIFO order and retries each entry with
// exponential backoff until the platform acknowledges it. It is the only writer
// of the platform terminal-report endpoints once an entry is queued.
type reportOutbox struct {
	ctx     context.Context
	cancel  context.CancelFunc
	state   *TAAState
	wake    chan struct{}
	initial time.Duration
	max     time.Duration
	wg      sync.WaitGroup
	stopped sync.Once

	// mu guards the per-entry retry schedule.
	mu    sync.Mutex
	retry map[string]retryState
}

func newReportOutbox(ctx context.Context, state *TAAState, initial, max time.Duration) *reportOutbox {
	outboxCtx, cancel := context.WithCancel(ctx)
	return &reportOutbox{
		ctx:     outboxCtx,
		cancel:  cancel,
		state:   state,
		wake:    make(chan struct{}, 1),
		initial: initial,
		max:     max,
		retry:   make(map[string]retryState),
	}
}

func (o *reportOutbox) Stop() {
	o.stopped.Do(func() {
		o.cancel()
		o.wg.Wait()
	})
}

// Wake asks the worker to look at the queue now. A wake already pending is
// enough, so the signal is dropped rather than queued twice.
func (o *reportOutbox) Wake() {
	select {
	case o.wake <- struct{}{}:
	default:
	}
}

func (o *reportOutbox) run() {
	defer o.wg.Done()
	for {
		select {
		case <-o.ctx.Done():
			return
		case <-o.wake:
		}

		if !o.drain() {
			return
		}
	}
}

// drain attempts every pending report once, oldest first, until the queue is
// empty or the context ends. Ready entries are delivered in enqueue order; an
// entry that fails does not block the ones behind it, because a report captured
// against an address that no longer answers would otherwise starve every later
// report forever.
//
// Acks are collected and applied in one batch: sealing the state file rewrites
// the whole file, so a pass that delivers N reports must not pay N fsyncs.
func (o *reportOutbox) drain() bool {
	for {
		entries := o.state.pendingReportsSnapshot()
		if len(entries) == 0 {
			return true
		}

		var acked []string
		var next time.Duration
		now := time.Now()

		for _, entry := range entries {
			o.mu.Lock()
			state, seen := o.retry[entry.ID]
			o.mu.Unlock()
			wait := o.initial
			if seen {
				wait = state.wait
				if now.Before(state.due) {
					if d := state.due.Sub(now); next == 0 || d < next {
						next = d
					}
					continue
				}
			}

			if err := o.send(entry); err != nil {
				log.Printf("report outbox: %s delivery failed, retrying in %s: %v", entry.Kind, wait, err)
				o.mu.Lock()
				o.retry[entry.ID] = retryState{wait: min(wait*2, o.max), due: time.Now().Add(wait)}
				o.mu.Unlock()
				if next == 0 || wait < next {
					next = wait
				}
				continue
			}

			o.mu.Lock()
			delete(o.retry, entry.ID)
			o.mu.Unlock()
			acked = append(acked, entry.ID)
			if o.state.Logs != nil {
				o.state.Logs.Add(LogInfo, "report", "平台上报补发成功: kind=%s, taskId=%s", entry.Kind, entry.TaskID)
			}
		}

		if len(acked) > 0 {
			o.state.ackPendingReports(acked...)
			// The queue shrank, so what was behind the acknowledged entries is due
			// now rather than when the last timer fires.
			continue
		}
		if next > 0 {
			if !o.wait(next) {
				return false
			}
			continue
		}
		return true
	}
}

// wait sleeps for d, waking early when a new report is enqueued so a freshly
// queued report is not held behind another entry's backoff timer.
func (o *reportOutbox) wait(d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-o.ctx.Done():
		return false
	case <-o.wake:
		return true
	case <-timer.C:
		return true
	}
}

func (o *reportOutbox) send(entry PendingReportSnapshot) error {
	ctx, cancel := context.WithTimeout(o.ctx, reportSendTimeout)
	defer cancel()

	switch entry.Kind {
	case ReportKindRes:
		return platform.ReportRes(ctx, entry.PlatformAddr, entry.DockerID, entry.RequestID, entry.TaskID, entry.Code, entry.Msg, entry.Report)
	case ReportKindModelImport:
		return platform.ReportModelImport(ctx, entry.PlatformAddr, entry.DockerID, entry.RequestID, entry.TaskID, entry.Code, entry.Msg, entry.Checksum)
	case ReportKindAudit:
		return platform.ReportAudit(ctx, entry.PlatformAddr, entry.DockerID, entry.RequestID, entry.TaskID, entry.Code, entry.Msg, entry.Report)
	default:
		return fmt.Errorf("unknown pending report kind %q", entry.Kind)
	}
}

// startReportOutbox starts the worker with explicit retry bounds. Tests use it
// to keep the backoff short; StartReportOutbox supplies the production values.
// Starting twice returns the worker already running.
func (s *TAAState) startReportOutbox(ctx context.Context, initial, max time.Duration) *reportOutbox {
	if max < initial {
		max = initial
	}
	s.outboxMu.Lock()
	defer s.outboxMu.Unlock()
	if s.outbox == nil {
		o := newReportOutbox(ctx, s, initial, max)
		s.outbox = o
		o.wg.Add(1)
		go o.run()
		o.Wake()
	}
	return s.outbox
}

// StartReportOutbox starts the durable platform-report retrier, or returns the
// one already running. It must be called after RestoreFromPersistentState so a
// queue left by the previous process is picked up.
func (s *TAAState) StartReportOutbox(ctx context.Context) *reportOutbox {
	return s.startReportOutbox(ctx, defaultReportRetryInitial, defaultReportRetryMax)
}

// QueueReport puts a terminal report into the sealed outbox. It is the single
// entry point for the three terminal endpoints, so call sites supply only the
// report content and cannot drift on identity capture or failure logging.
func (s *TAAState) QueueReport(kind, requestID, taskID string, code int, msg, report string, checksum map[string]any) {
	err := s.EnqueuePlatformReport(PendingReportSnapshot{
		Kind:      kind,
		RequestID: requestID,
		TaskID:    taskID,
		Code:      code,
		Msg:       msg,
		Report:    report,
		Checksum:  checksum,
	})
	if err != nil {
		log.Printf("queue %s report failed: requestId=%s taskId=%s, err=%v", kind, requestID, taskID, err)
	}
}

// ReportKindForTaskType maps a task type onto the terminal endpoint that
// carries its outcome.
func ReportKindForTaskType(taskType string) string {
	if taskType == "model_import" {
		return ReportKindModelImport
	}
	return ReportKindRes
}

// EnqueuePlatformReport writes a terminal report into the sealed outbox and
// wakes the retrier. A report the platform may never accept (missing platform
// identity, unknown kind) is refused rather than queued forever.
func (s *TAAState) EnqueuePlatformReport(entry PendingReportSnapshot) error {
	switch entry.Kind {
	case ReportKindRes, ReportKindModelImport, ReportKindAudit:
	default:
		return fmt.Errorf("platform report not queued: unknown kind %q", entry.Kind)
	}

	s.mu.RLock()
	platformAddr, dockerID := entry.PlatformAddr, entry.DockerID
	if strings.TrimSpace(platformAddr) == "" {
		platformAddr = s.PlatformIP
	}
	if strings.TrimSpace(dockerID) == "" {
		dockerID = s.DockerID
	}
	s.mu.RUnlock()

	// A missing identity is a deployment error, not a transient outage: queueing
	// it would grow the sealed state forever with something unsendable.
	addr, dID, reqID, taskID, err := platform.ValidateAndNormalizePlatformParams(
		platformAddr, dockerID, entry.RequestID, entry.TaskID)
	if err != nil {
		return fmt.Errorf("platform report not queued: %w", err)
	}
	entry.PlatformAddr, entry.DockerID = addr, dID
	entry.RequestID, entry.TaskID = reqID, taskID
	if entry.ID == "" {
		entry.ID = utils.NewUUID()
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}

	s.mu.Lock()
	s.pendingReports = append(s.pendingReports, entry)
	sealErr := s.sealStateLocked()
	s.mu.Unlock()

	s.StartReportOutbox(context.Background()).Wake()

	if sealErr != nil {
		return fmt.Errorf("seal pending platform report: %w", sealErr)
	}
	return nil
}

func (s *TAAState) hasPendingReports() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.pendingReports) > 0
}

// pendingReportsSnapshot copies the queue so the worker can attempt deliveries
// without holding the state lock across network calls. Entries are only appended
// and removed, never mutated in place, so a shallow copy is enough; the deep
// copy happens once, at the seal boundary.
func (s *TAAState) pendingReportsSnapshot() []PendingReportSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]PendingReportSnapshot(nil), s.pendingReports...)
}

// ackPendingReports removes the acknowledged entries and reseals once. Sealing
// rewrites the whole state file, so a pass that delivers several reports must
// not seal per report.
func (s *TAAState) ackPendingReports(ids ...string) {
	acked := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		acked[id] = struct{}{}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.pendingReports[:0]
	for _, entry := range s.pendingReports {
		if _, drop := acked[entry.ID]; !drop {
			kept = append(kept, entry)
		}
	}
	s.pendingReports = kept
	if err := s.sealStateLocked(); err != nil && s.Logs != nil {
		s.Logs.Add(LogError, "report", "持久化已确认的平台上报失败: %v", err)
	}
}
