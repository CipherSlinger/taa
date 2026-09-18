package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	taaLogEndpoint = "/v1/taa/taaLog"
)

// TaaLogEntry 表示 TAA 自身运行日志上报中的单条日志。
type TaaLogEntry struct {
	Seq     uint64 `json:"seq"`
	Message string `json:"message"`
}

type taaLogRequest struct {
	DockerID  string        `json:"dockerId"`
	RequestID string        `json:"requestId"`
	TaskID    string        `json:"taskId,omitempty"`
	SeqStart  uint64        `json:"seqStart"`
	Entries   []TaaLogEntry `json:"entries"`
}

// ReportTaaLog 主动向平台上报 TAA 自身的运行日志。
// taskId 可为空；requestId 是当前任务执行的关联标识或 "system"。
func ReportTaaLog(ctx context.Context, platformAddr, dockerID, requestID, taskID string, seqStart uint64, entries []TaaLogEntry) error {
	if strings.TrimSpace(platformAddr) == "" {
		return fmt.Errorf("PLATFORM_IP is required")
	}
	if strings.TrimSpace(dockerID) == "" {
		return fmt.Errorf("DOCKER_ID is required")
	}
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		return fmt.Errorf("requestId is required")
	}
	if len(entries) == 0 {
		return fmt.Errorf("entries must not be empty")
	}
	for i, entry := range entries {
		expected := seqStart + uint64(i)
		if entry.Seq != expected {
			return fmt.Errorf("entries[%d].seq = %d, want %d", i, entry.Seq, expected)
		}
		if strings.TrimSpace(entry.Message) == "" {
			return fmt.Errorf("entries[%d].message must not be empty", i)
		}
	}

	payload, err := json.Marshal(taaLogRequest{
		DockerID:  strings.TrimSpace(dockerID),
		RequestID: requestID,
		TaskID:    strings.TrimSpace(taskID),
		SeqStart:  seqStart,
		Entries:   entries,
	})
	if err != nil {
		return fmt.Errorf("marshal taa log request: %w", err)
	}
	return sendReportingJSON(ctx, platformAddr, taaLogEndpoint, payload)
}

type taaLogWatcher struct {
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	state        *TAAState
	platformAddr string
	dockerID     string
	pendingLogs  []TaaLogEntry
	interval     time.Duration
	startOnce    sync.Once
	stopOnce     sync.Once
}

// StartTaaLogWatcher 启动 TAA 自身运行日志的后台定时批量上报协程。
func (s *TAAState) StartTaaLogWatcher(ctx context.Context) *taaLogWatcher {
	if ctx == nil {
		ctx = context.Background()
	}
	watcherCtx, cancel := context.WithCancel(ctx)
	w := &taaLogWatcher{
		ctx:          watcherCtx,
		cancel:       cancel,
		state:        s,
		platformAddr: s.PlatformIP,
		dockerID:     s.DockerID,
		interval:     defaultReportInterval,
	}
	w.start()
	return w
}

func (w *taaLogWatcher) start() {
	w.startOnce.Do(func() {
		w.wg.Add(1)
		go func() {
			defer w.wg.Done()
			ticker := time.NewTicker(w.interval)
			defer ticker.Stop()
			for {
				select {
				case <-w.ctx.Done():
					return
				case <-ticker.C:
					w.flushWithContext(w.ctx)
				}
			}
		}()
	})
}

func (w *taaLogWatcher) Stop() {
	w.stopOnce.Do(func() {
		w.cancel()
		w.wg.Wait()
		w.flushWithContext(context.Background())
	})
}

func (w *taaLogWatcher) flushWithContext(ctx context.Context) {
	if w.state == nil || w.state.Logs == nil || strings.TrimSpace(w.platformAddr) == "" {
		return
	}
	drained := w.state.Logs.Drain()
	for _, entry := range drained {
		w.pendingLogs = append(w.pendingLogs, TaaLogEntry{
			Seq:     entry.Seq,
			Message: entry.FormatMessage(),
		})
	}

	w.state.mu.RLock()
	reqID := w.state.ActiveRequestID
	taskID := w.state.ActiveTaskID
	w.state.mu.RUnlock()

	if strings.TrimSpace(reqID) == "" {
		reqID = "system"
	}

	for len(w.pendingLogs) > 0 {
		batchSize := len(w.pendingLogs)
		if batchSize > maxLogBatchSize {
			batchSize = maxLogBatchSize
		}
		batch := append([]TaaLogEntry(nil), w.pendingLogs[:batchSize]...)
		if err := ReportTaaLog(ctx, w.platformAddr, w.dockerID, reqID, taskID, batch[0].Seq, batch); err != nil {
			break
		}
		w.pendingLogs = w.pendingLogs[batchSize:]
	}
}
