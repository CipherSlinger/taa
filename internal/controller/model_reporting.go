package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"taa/internal/platform"
	"taa/internal/runtime"
)

const (
	modelLogEndpoint       = "/v1/taa/modelLog"
	reportProgressEndpoint = "/v1/taa/reportProgress"
	defaultReportInterval  = 500 * time.Millisecond
	maxLogBatchSize        = 100
)

// ModelLogEntry 表示模型日志上报中的单条日志。
type ModelLogEntry = platform.ModelLogEntry

type modelLogRequest struct {
	DockerID  string          `json:"dockerId"`
	RequestID string          `json:"requestId"`
	TaskID    string          `json:"taskId,omitempty"`
	SeqStart  uint64          `json:"seqStart"`
	Entries   []ModelLogEntry `json:"entries"`
}

type reportProgressRequest struct {
	DockerID  string  `json:"dockerId"`
	RequestID string  `json:"requestId"`
	TaskID    string  `json:"taskId,omitempty"`
	Percent   float64 `json:"percent"`
	Timestamp string  `json:"timestamp"`
}

type reportingAck struct {
	Msg    string `json:"msg"`
	Result struct {
		Received bool `json:"received"`
	} `json:"result"`
	Error int `json:"error"`
}

// ReportModelLog 主动向平台上报模型方写入的任务日志。
// taskId 可为空；requestId 是当前任务执行的关联标识。
func ReportModelLog(ctx context.Context, platformAddr, dockerID, requestID, taskID string, seqStart uint64, entries []ModelLogEntry) error {
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

	payload, err := json.Marshal(modelLogRequest{
		DockerID:  strings.TrimSpace(dockerID),
		RequestID: requestID,
		TaskID:    strings.TrimSpace(taskID),
		SeqStart:  seqStart,
		Entries:   entries,
	})
	if err != nil {
		return fmt.Errorf("marshal model log request: %w", err)
	}
	return sendReportingJSON(ctx, platformAddr, modelLogEndpoint, payload)
}

// ReportProgress 主动向平台上报任务数值进度。
func ReportProgress(ctx context.Context, platformAddr, dockerID, requestID, taskID string, percent float64, timestamp time.Time) error {
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
	if math.IsNaN(percent) || math.IsInf(percent, 0) || percent < 0 || percent > 100 {
		return fmt.Errorf("percent must be between 0 and 100")
	}
	if timestamp.IsZero() {
		return fmt.Errorf("timestamp is required")
	}

	payload, err := json.Marshal(reportProgressRequest{
		DockerID:  strings.TrimSpace(dockerID),
		RequestID: requestID,
		TaskID:    strings.TrimSpace(taskID),
		Percent:   percent,
		Timestamp: timestamp.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return fmt.Errorf("marshal progress request: %w", err)
	}
	return sendReportingJSON(ctx, platformAddr, reportProgressEndpoint, payload)
}

func sendReportingJSON(ctx context.Context, platformAddr, endpoint string, payload []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, platformURL(platformAddr, endpoint), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := platformHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("platform returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var ack reportingAck
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&ack); err != nil {
		return fmt.Errorf("decode platform acknowledgement: %w", err)
	}
	if ack.Error != 0 || !ack.Result.Received {
		return fmt.Errorf("platform rejected report: error=%d msg=%s (received=%v)", ack.Error, ack.Msg, ack.Result.Received)
	}
	return nil
}

type progressSnapshot = runtime.ProgressSnapshot
type jsonlLogReader = runtime.JSONLLogReader

func newJSONLLogReader(dir string) *jsonlLogReader {
	return runtime.NewJSONLLogReader(dir)
}

func readLatestProgress(dir string) (progressSnapshot, bool, error) {
	return runtime.ReadLatestProgress(dir)
}

type reportWatcher struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	state  *TAAState

	platformAddr    string
	dockerID        string
	requestID       string
	taskID          string
	logs            *jsonlLogReader
	pendingLogs     []ModelLogEntry
	lastProgressKey string
	interval        time.Duration

	startOnce sync.Once
	stopOnce  sync.Once
}

func newReportWatcher(ctx context.Context, state *TAAState, requestID, taskID string, interval time.Duration) *reportWatcher {
	if ctx == nil {
		ctx = context.Background()
	}
	if interval <= 0 {
		interval = defaultReportInterval
	}
	watcherCtx, cancel := context.WithCancel(ctx)
	w := &reportWatcher{
		ctx:       watcherCtx,
		cancel:    cancel,
		state:     state,
		requestID: strings.TrimSpace(requestID),
		taskID:    strings.TrimSpace(taskID),
		interval:  interval,
	}
	if state != nil {
		w.platformAddr = state.PlatformIP
		w.dockerID = state.DockerID
		w.logs = newJSONLLogReader(state.Security.GetModelLogDir())
	}
	return w
}

func (s *TAAState) startModelReportWatcher(ctx context.Context, requestID, taskID string) *reportWatcher {
	watcher := newReportWatcher(ctx, s, requestID, taskID, defaultReportInterval)
	watcher.start()
	return watcher
}

func (w *reportWatcher) start() {
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

func (w *reportWatcher) Stop() {
	w.stop(true)
}

func (w *reportWatcher) StopWithoutFlush() {
	w.stop(false)
}

func (w *reportWatcher) stop(flush bool) {
	w.stopOnce.Do(func() {
		w.cancel()
		w.wg.Wait()
		if flush {
			w.flushWithContext(context.Background())
		}
	})
}

func (w *reportWatcher) flush() {
	w.flushWithContext(context.Background())
}

func (w *reportWatcher) flushWithContext(ctx context.Context) {
	if w.logs == nil || w.state == nil {
		return
	}
	newEntries, err := w.logs.ReadNew()
	if err != nil {
		w.warn("读取模型日志失败: %v", err)
	}
	w.pendingLogs = append(w.pendingLogs, newEntries...)
	for len(w.pendingLogs) > 0 {
		batchSize := len(w.pendingLogs)
		if batchSize > maxLogBatchSize {
			batchSize = maxLogBatchSize
		}
		batch := append([]ModelLogEntry(nil), w.pendingLogs[:batchSize]...)
		if err := ReportModelLog(ctx, w.platformAddr, w.dockerID, w.requestID, w.taskID, batch[0].Seq, batch); err != nil {
			w.warn("上报模型日志失败: %v", err)
			break
		}
		w.pendingLogs = w.pendingLogs[batchSize:]
	}

	progress, ok, err := readLatestProgress(w.state.Security.GetModelProgressDir())
	if err != nil {
		w.warn("读取训练进度失败: %v", err)
		return
	}
	if !ok || progress.Key == w.lastProgressKey {
		return
	}
	if err := ReportProgress(ctx, w.platformAddr, w.dockerID, w.requestID, w.taskID, progress.Percent, progress.Timestamp); err != nil {
		w.warn("上报训练进度失败: %v", err)
		return
	}
	w.lastProgressKey = progress.Key
}

func (w *reportWatcher) warn(format string, args ...any) {
	if w.state != nil && w.state.Logs != nil {
		w.state.Logs.Add(LogWarn, "report", format, args...)
	}
}
