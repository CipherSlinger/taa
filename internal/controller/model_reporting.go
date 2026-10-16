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

// progressHoldPercent is the progress value the watcher deliberately withholds. A model
// reporting 100% has finished training, but TAA has not finished the task: the artifacts
// still have to be collected out of the model output directory and the result leakage
// check still has to run over them. Reporting 100% as soon as it is read would tell the
// platform the task is over while that work is in flight, so the snapshot is parked in
// the watcher and released by reportDeferredProgress once the pipeline is past the check.
const progressHoldPercent = 100.0

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

	// deferredProgress holds the snapshot the watcher is sitting on because it is
	// progressHoldPercent or above; see flushWithContext and reportDeferredProgress.
	deferredProgress    progressSnapshot
	hasDeferredProgress bool

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
	if progress.Percent >= progressHoldPercent {
		w.holdFullProgress(progress)
		return
	}
	if err := ReportProgress(ctx, w.platformAddr, w.dockerID, w.requestID, w.taskID, progress.Percent, progress.Timestamp); err != nil {
		w.warn("上报训练进度失败: %v", err)
		return
	}
	w.lastProgressKey = progress.Key
}

// holdFullProgress parks a 100% snapshot instead of reporting it. See
// progressHoldPercent for why it is held; reportDeferredProgress releases it.
func (w *reportWatcher) holdFullProgress(progress progressSnapshot) {
	if !w.hasDeferredProgress {
		w.info("训练已到 100%%，暂不上报，等结果检查结束后补报: taskId=%s", w.taskID)
	}
	w.deferredProgress = progress
	w.hasDeferredProgress = true
	// Claimed like any reported snapshot so the next tick does not park it again.
	w.lastProgressKey = progress.Key
}

// reportDeferredProgress reports the 100% snapshot the watcher held back. The training
// pipeline calls it once the result leakage check has reached its verdict - or, when
// that check is switched off, once the artifacts have been collected - so the platform
// only learns the task reached 100% after TAA has finished the work that follows
// training. A model that never reported 100% leaves nothing to release, and a failure or
// a stop before the release point drops the held snapshot on the floor - 100% is only
// ever reported for a run TAA carried to its end. Releasing twice reports once: the
// snapshot is claimed before it is sent.
func (w *reportWatcher) reportDeferredProgress(ctx context.Context) {
	if !w.hasDeferredProgress {
		return
	}
	progress := w.deferredProgress
	w.deferredProgress = progressSnapshot{}
	w.hasDeferredProgress = false
	w.info("结果检查结束，补报训练进度 100%%: taskId=%s", w.taskID)
	if err := ReportProgress(ctx, w.platformAddr, w.dockerID, w.requestID, w.taskID, progress.Percent, progress.Timestamp); err != nil {
		w.warn("上报训练进度失败: %v", err)
	}
}

func (w *reportWatcher) info(format string, args ...any) {
	if w.state != nil && w.state.Logs != nil {
		w.state.Logs.Add(LogInfo, "report", format, args...)
	}
}

func (w *reportWatcher) warn(format string, args ...any) {
	if w.state != nil && w.state.Logs != nil {
		w.state.Logs.Add(LogWarn, "report", format, args...)
	}
}
