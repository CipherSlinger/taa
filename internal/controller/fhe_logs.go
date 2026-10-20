package controller

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"taa/internal/fhe"
)

const (
	// fheLogPollInterval is how often the service's task log is replayed. The
	// log endpoint replays and closes (follow=false), so a poll either re-reads
	// a log that has not grown or picks up what the previous poll could not see.
	fheLogPollInterval = 2 * time.Second
	// fheLogFlushTimeout bounds the final replay after the run ends. The last
	// line of the log - the "task ... end" line - is written as the task
	// finishes, so it can miss the last in-run poll and has to be collected
	// after Execute returns.
	fheLogFlushTimeout = 10 * time.Second
)

// fheLogPoller forwards the FHE service's terminal log to the platform's
// modelLog endpoint.
//
// The training path reads the model's log from ModelLogDir, but on an fhe
// instance the model runs inside the FHE service, so there is no such directory
// to tail: the service's /tasks/{id}/logs endpoint is the only source. Polling
// it with follow=false replays the whole log each time, so the poller keeps the
// byte offset it has already accounted for and only queues the suffix.
//
// Sequence numbers are assigned once, when a line is queued, and a failed
// report keeps the queue: re-sending is idempotent on the platform's side,
// while skipping would leave a hole in the seq stream the platform checks.
type fheLogPoller struct {
	state        *TAAState
	client       *fhe.Client
	platformAddr string
	dockerID     string
	requestID    string
	taskID       string
	userID       string

	consumed int    // bytes of the replayed log already accounted for
	lastText string // the last replay, to tell an append from a new log
	nextSeq  uint64 // seq of the next queued entry
	pending  []ModelLogEntry
	lastErr  string

	// created is set when Execute reports the task exists on the service. Until
	// then a 404 from the log endpoint means "not created yet", not a failure.
	created atomic.Bool
}

// startFHELogPoller starts forwarding the task's log and returns the stop
// function and the callback Execute calls once the task exists. Stopping
// cancels the loop, waits for it, and takes one final replay so the closing
// line is not lost.
//
// Without a platform address there is nowhere to report to, which is the same
// condition reportFHEProgress checks before it sends anything.
func (s *TAAState) startFHELogPoller(runner *fhe.Runner, requestID, taskID, userID string) (stop func(), onCreated func()) {
	noop := func() {}
	if runner == nil {
		return noop, noop
	}
	s.mu.RLock()
	platformAddr, dockerID := s.PlatformIP, s.DockerID
	s.mu.RUnlock()
	if strings.TrimSpace(platformAddr) == "" {
		return noop, noop
	}

	p := &fheLogPoller{
		state:        s,
		client:       runner.Client(),
		platformAddr: strings.TrimSpace(platformAddr),
		dockerID:     strings.TrimSpace(dockerID),
		requestID:    strings.TrimSpace(requestID),
		taskID:       strings.TrimSpace(taskID),
		userID:       strings.TrimSpace(userID),
		nextSeq:      1,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(fheLogPollInterval)
		defer ticker.Stop()
		// The first poll waits for the first tick: the poller starts before
		// Execute creates the task, and asking for the log of a task that does
		// not exist yet would only report a 404. The replay makes the wait
		// invisible - the first poll returns every line from the start - and
		// poll() keeps a 404 quiet until Execute says the task exists.
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				p.poll(ctx, false)
			}
		}
	}()

	return func() {
		cancel()
		<-done
		flushCtx, flushCancel := context.WithTimeout(context.Background(), fheLogFlushTimeout)
		defer flushCancel()
		p.poll(flushCtx, true)
	}, func() { p.created.Store(true) }
}

// poll replays the log once and reports what is new. A failure never ends the
// poller: the service is the primary channel for the result, and a log that
// cannot be fetched must not turn a running task into a failed one.
func (p *fheLogPoller) poll(ctx context.Context, final bool) {
	text, err := p.client.TaskLogs(ctx, p.taskID, p.userID)
	if err != nil {
		// Until Execute has created the task, the service answers 404 for the
		// log. Staging the eval key and the input can take minutes, so this is
		// the normal state for the first polls, not a reportable failure; the
		// first replay after creation carries every line from the start.
		if !p.created.Load() && isTaskNotFound(err) {
			return
		}
		p.warn(err)
		return
	}
	p.lastErr = ""
	p.absorb(text, final)
	p.flush(ctx)
}

// isTaskNotFound reports the service's 404 for a task that does not exist (yet).
func isTaskNotFound(err error) bool {
	var apiErr *fhe.APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}

// absorb queues the lines appended since the last replay.
//
// A line is only taken once it is terminated by \n or \r. The service draws
// progress bars with carriage returns and the tail of a replayed log can still
// grow between two polls, so an unterminated fragment waits for the next
// replay - except on the final one, where nothing else will come to finish it.
func (p *fheLogPoller) absorb(text string, final bool) {
	if !strings.HasPrefix(text, p.lastText) {
		// The service restarted the log for this task id, which is how a
		// continue re-run of an existing task reports. Start it over.
		p.consumed = 0
	}
	p.lastText = text
	tail := text[p.consumed:]
	if !final {
		cut := strings.LastIndexAny(tail, "\r\n")
		if cut < 0 {
			return
		}
		tail = tail[:cut+1]
	}
	p.consumed += len(tail)

	stamp := time.Now().UTC().Format(time.RFC3339)
	for _, line := range strings.FieldsFunc(tail, func(r rune) bool { return r == '\n' || r == '\r' }) {
		message := strings.TrimSpace(line)
		if message == "" {
			continue
		}
		p.pending = append(p.pending, ModelLogEntry{
			Seq:       p.nextSeq,
			Message:   message,
			Timestamp: stamp,
			Component: "fhe",
			Level:     "info",
		})
		p.nextSeq++
	}
}

// flush sends the queued entries in platform-sized batches. The queue is only
// shortened after the platform accepted a batch, so a failed report is retried
// on the next poll with the same sequence numbers.
func (p *fheLogPoller) flush(ctx context.Context) {
	for len(p.pending) > 0 {
		size := len(p.pending)
		if size > maxLogBatchSize {
			size = maxLogBatchSize
		}
		batch := append([]ModelLogEntry(nil), p.pending[:size]...)
		if err := ReportModelLog(ctx, p.platformAddr, p.dockerID, p.requestID, p.taskID, batch[0].Seq, batch); err != nil {
			p.warn(err)
			return
		}
		p.pending = p.pending[size:]
	}
}

// warn records a polling failure once per distinct message. A service that
// refuses the endpoint would otherwise add a warning every two seconds for the
// whole run.
func (p *fheLogPoller) warn(err error) {
	msg := err.Error()
	if msg == p.lastErr {
		return
	}
	p.lastErr = msg
	p.state.Logs.Add(LogWarn, "fhe", "上报 FHE 任务日志失败: %v", err)
}
