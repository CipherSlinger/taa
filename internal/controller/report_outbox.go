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

		backoff := o.initial
		for {
			if o.ctx.Err() != nil {
				return
			}
			entry, ok := o.state.peekPendingReport()
			if !ok {
				break
			}
			if err := o.send(entry); err != nil {
				log.Printf("report outbox: %s delivery failed, retrying in %s: %v", entry.Kind, backoff, err)
				if !o.wait(backoff) {
					return
				}
				backoff *= 2
				if backoff > o.max {
					backoff = o.max
				}
				continue
			}
			o.state.ackPendingReport(entry.ID)
			if o.state.Logs != nil {
				o.state.Logs.Add(LogInfo, "report", "平台上报补发成功: kind=%s, taskId=%s", entry.Kind, entry.TaskID)
			}
			backoff = o.initial
		}
	}
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

func (s *TAAState) peekPendingReport() (PendingReportSnapshot, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.pendingReports) == 0 {
		return PendingReportSnapshot{}, false
	}
	return clonePendingReport(s.pendingReports[0]), true
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
