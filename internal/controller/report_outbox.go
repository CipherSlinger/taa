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
	reportSendTimeout         = 10 * time.Second
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

// reportOutbox drains pendingReports in FIFO order and retries each entry with
// exponential backoff until the platform acknowledges it. It is the only writer
// of the platform terminal-report endpoints once an entry is queued.
type reportOutbox struct {
	ctx       context.Context
	cancel    context.CancelFunc
	state     *TAAState
	wake      chan struct{}
	initial   time.Duration
	max       time.Duration
	wg        sync.WaitGroup
	startOnce sync.Once
	stopOnce  sync.Once

	// mu guards the per-entry retry schedule. It is in-memory only: a restart
	// retries everything immediately, which is the right response to a restart.
	mu      sync.Mutex
	backoff map[string]time.Duration
	nextAt  map[string]time.Time
}

func newReportOutbox(ctx context.Context, state *TAAState, initial, max time.Duration) *reportOutbox {
	if ctx == nil {
		ctx = context.Background()
	}
	if initial <= 0 {
		initial = defaultReportRetryInitial
	}
	if max < initial {
		max = initial
	}
	outboxCtx, cancel := context.WithCancel(ctx)
	return &reportOutbox{
		ctx:     outboxCtx,
		cancel:  cancel,
		state:   state,
		wake:    make(chan struct{}, 1),
		initial: initial,
		max:     max,
		backoff: make(map[string]time.Duration),
		nextAt:  make(map[string]time.Time),
	}
}

func (o *reportOutbox) start() {
	o.startOnce.Do(func() {
		o.wg.Add(1)
		go o.run()
		o.Wake()
	})
}

func (o *reportOutbox) Stop() {
	o.stopOnce.Do(func() {
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
func (o *reportOutbox) drain() bool {
	for {
		entries := o.state.pendingReportsSnapshot()
		if len(entries) == 0 {
			return true
		}

		queued := make(map[string]struct{}, len(entries))
		var next time.Duration
		now := time.Now()
		delivered := false

		for _, entry := range entries {
			queued[entry.ID] = struct{}{}

			o.mu.Lock()
			wait, seen := o.backoff[entry.ID]
			nextAt := o.nextAt[entry.ID]
			o.mu.Unlock()
			if !seen {
				wait = o.initial
			}
			if !nextAt.IsZero() && now.Before(nextAt) {
				if d := nextAt.Sub(now); next == 0 || d < next {
					next = d
				}
				continue
			}

			if err := o.send(entry); err != nil {
				log.Printf("report outbox: %s delivery failed, retrying in %s: %v", entry.Kind, wait, err)
				o.mu.Lock()
				o.backoff[entry.ID] = minDuration(wait*2, o.max)
				o.nextAt[entry.ID] = time.Now().Add(wait)
				o.mu.Unlock()
				if next == 0 || wait < next {
					next = wait
				}
				continue
			}

			o.clearRetryState(entry.ID)
			o.state.ackPendingReport(entry.ID)
			delivered = true
			if o.state.Logs != nil {
				o.state.Logs.Add(LogInfo, "report", "平台上报补发成功: kind=%s, taskId=%s", entry.Kind, entry.TaskID)
			}
		}

		// Forget retry state for entries that are no longer queued, so a
		// long-lived process does not accumulate it.
		o.mu.Lock()
		for id := range o.backoff {
			if _, ok := queued[id]; !ok {
				delete(o.backoff, id)
				delete(o.nextAt, id)
			}
		}
		o.mu.Unlock()

		// A delivery shortened the queue, so look again right away: whatever was
		// behind the acknowledged entry is due now, not when the last timer fires.
		if delivered {
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

func (o *reportOutbox) clearRetryState(id string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.backoff, id)
	delete(o.nextAt, id)
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func (o *reportOutbox) wait(d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-o.ctx.Done():
		return false
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
func (s *TAAState) startReportOutbox(ctx context.Context, initial, max time.Duration) *reportOutbox {
	s.outboxMu.Lock()
	defer s.outboxMu.Unlock()
	if s.outbox == nil {
		s.outbox = newReportOutbox(ctx, s, initial, max)
		s.outbox.start()
	}
	return s.outbox
}

// StartReportOutbox starts the durable platform-report retrier, or returns the
// one already running. It must be called after RestoreFromPersistentState so a
// queue left by the previous process is picked up.
func (s *TAAState) StartReportOutbox(ctx context.Context) *reportOutbox {
	return s.startReportOutbox(ctx, defaultReportRetryInitial, defaultReportRetryMax)
}

func (s *TAAState) currentReportOutbox() *reportOutbox {
	s.outboxMu.Lock()
	defer s.outboxMu.Unlock()
	return s.outbox
}

// EnqueuePlatformReport writes a terminal report into the sealed outbox and
// wakes the retrier. A report the platform may never accept (missing platform
// identity, unknown kind) is refused rather than queued forever.
func (s *TAAState) EnqueuePlatformReport(entry PendingReportSnapshot) error {
	s.mu.RLock()
	if strings.TrimSpace(entry.PlatformAddr) == "" {
		entry.PlatformAddr = s.PlatformIP
	}
	if strings.TrimSpace(entry.DockerID) == "" {
		entry.DockerID = s.DockerID
	}
	s.mu.RUnlock()

	if strings.TrimSpace(entry.PlatformAddr) == "" || strings.TrimSpace(entry.DockerID) == "" {
		return fmt.Errorf("platform report not queued: platformAddr and dockerId are required")
	}
	if strings.TrimSpace(entry.RequestID) == "" && strings.TrimSpace(entry.TaskID) == "" {
		return fmt.Errorf("platform report not queued: requestId and taskId are both empty")
	}
	switch entry.Kind {
	case ReportKindRes, ReportKindModelImport, ReportKindAudit:
	default:
		return fmt.Errorf("platform report not queued: unknown kind %q", entry.Kind)
	}

	s.mu.Lock()
	if entry.ID == "" {
		entry.ID = utils.NewUUID()
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}
	s.pendingReports = append(s.pendingReports, entry)
	sealErr := s.sealStateLocked()
	s.mu.Unlock()

	outbox := s.currentReportOutbox()
	if outbox == nil {
		outbox = s.StartReportOutbox(context.Background())
	}
	outbox.Wake()

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
// without holding the state lock across network calls.
func (s *TAAState) pendingReportsSnapshot() []PendingReportSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.pendingReports) == 0 {
		return nil
	}
	out := make([]PendingReportSnapshot, len(s.pendingReports))
	for i := range s.pendingReports {
		out[i] = clonePendingReport(s.pendingReports[i])
	}
	return out
}

func (s *TAAState) ackPendingReport(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.pendingReports {
		if s.pendingReports[i].ID == id {
			s.pendingReports = append(s.pendingReports[:i], s.pendingReports[i+1:]...)
			break
		}
	}
	if err := s.sealStateLocked(); err != nil && s.Logs != nil {
		s.Logs.Add(LogError, "report", "持久化已确认的平台上报失败: %v", err)
	}
}
