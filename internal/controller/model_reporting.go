package controller

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	modelLogEndpoint       = "/v1/taa/modelLog"
	reportProgressEndpoint = "/v1/taa/reportProgress"
	defaultReportInterval  = 500 * time.Millisecond
	maxLogBatchSize        = 100
)

// ModelLogEntry 表示模型日志上报中的单条日志。
type ModelLogEntry struct {
	Seq     uint64 `json:"seq"`
	Message string `json:"message"`
}

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

type progressSnapshot struct {
	Percent   float64
	Timestamp time.Time
	Key       string
}

type logFileCursor struct {
	Offset int64
}

type jsonlLogReader struct {
	dir     string
	files   map[string]logFileCursor
	nextSeq uint64
}

func newJSONLLogReader(dir string) *jsonlLogReader {
	return &jsonlLogReader{
		dir:   dir,
		files: make(map[string]logFileCursor),
	}
}

// ReadNew 读取日志目录中已完整落盘且尚未消费的 JSONL 行。
func (r *jsonlLogReader) ReadNew() ([]ModelLogEntry, error) {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !isLogFile(entry.Name()) {
			continue
		}
		paths = append(paths, filepath.Join(r.dir, entry.Name()))
	}
	sort.Strings(paths)

	var result []ModelLogEntry
	for _, path := range paths {
		newEntries, err := r.readFile(path)
		if err != nil {
			return result, err
		}
		result = append(result, newEntries...)
	}
	return result, nil
}

func isLogFile(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".jsonl" || ext == ".log"
}

func (r *jsonlLogReader) readFile(path string) ([]ModelLogEntry, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	cursor := r.files[path]
	if info.Size() < cursor.Offset {
		cursor.Offset = 0
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if _, err := file.Seek(cursor.Offset, io.SeekStart); err != nil {
		return nil, err
	}

	reader := bufio.NewReader(file)
	var result []ModelLogEntry
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil && readErr != io.EOF {
			return result, readErr
		}
		if readErr == io.EOF {
			// 没有换行的尾部仍可能是模型正在写入的半行，留到下次读取。
			break
		}
		cursor.Offset += int64(len(line))
		line = strings.TrimSpace(strings.TrimSuffix(line, "\n"))
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		message := logMessageFromLine(line)
		if message == "" {
			continue
		}
		r.nextSeq++
		result = append(result, ModelLogEntry{Seq: r.nextSeq, Message: message})
	}
	r.files[path] = cursor
	return result, nil
}

func logMessageFromLine(line string) string {
	var raw any
	if err := json.Unmarshal([]byte(line), &raw); err == nil {
		switch value := raw.(type) {
		case string:
			return strings.TrimSpace(value)
		case map[string]any:
			if message, ok := value["message"].(string); ok {
				return strings.TrimSpace(message)
			}
		}
	}
	return strings.TrimSpace(line)
}

func readLatestProgress(dir string) (progressSnapshot, bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return progressSnapshot{}, false, nil
		}
		return progressSnapshot{}, false, err
	}

	type candidate struct {
		path string
		info os.FileInfo
	}
	candidates := make([]candidate, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || strings.ToLower(filepath.Ext(entry.Name())) != ".json" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		candidates = append(candidates, candidate{path: filepath.Join(dir, entry.Name()), info: info})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].info.ModTime().Equal(candidates[j].info.ModTime()) {
			return candidates[i].path > candidates[j].path
		}
		return candidates[i].info.ModTime().After(candidates[j].info.ModTime())
	})

	for _, item := range candidates {
		data, err := os.ReadFile(item.path)
		if err != nil {
			continue
		}
		var raw struct {
			Percent    *float64 `json:"percent"`
			Percentage *float64 `json:"percentage"`
			Timestamp  string   `json:"timestamp"`
		}
		if err := json.Unmarshal(data, &raw); err != nil {
			continue
		}
		percent := raw.Percent
		if percent == nil {
			percent = raw.Percentage
		}
		if percent == nil || math.IsNaN(*percent) || math.IsInf(*percent, 0) || *percent < 0 || *percent > 100 {
			continue
		}
		timestamp := item.info.ModTime().UTC()
		if strings.TrimSpace(raw.Timestamp) != "" {
			parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(raw.Timestamp))
			if err != nil {
				continue
			}
			timestamp = parsed.UTC()
		}
		return progressSnapshot{
			Percent:   *percent,
			Timestamp: timestamp,
			Key:       fmt.Sprintf("%.9f|%s", *percent, timestamp.Format(time.RFC3339Nano)),
		}, true, nil
	}
	return progressSnapshot{}, false, nil
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
