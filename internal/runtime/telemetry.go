package runtime

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"taa/internal/platform"
)

// LogFileCursor 跟踪单个日志文件的消费偏移量
type LogFileCursor struct {
	Offset int64
}

// JSONLLogReader 增量扫描并消费指定目录下的 .jsonl / .log 日志条目
type JSONLLogReader struct {
	dir     string
	files   map[string]LogFileCursor
	nextSeq uint64
}

// NewJSONLLogReader 创建日志读取器
func NewJSONLLogReader(dir string) *JSONLLogReader {
	return &JSONLLogReader{
		dir:   dir,
		files: make(map[string]LogFileCursor),
	}
}

// ReadNew 读取日志目录中已完整落盘且尚未消费的日志行
func (r *JSONLLogReader) ReadNew() ([]platform.ModelLogEntry, error) {
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

	var result []platform.ModelLogEntry
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

func (r *JSONLLogReader) readFile(path string) ([]platform.ModelLogEntry, error) {
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
	var result []platform.ModelLogEntry
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil && readErr != io.EOF {
			return result, readErr
		}
		if readErr == io.EOF {
			// 没有换行的尾部仍可能是模型正在写入的半行，留到下次读取
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
		result = append(result, platform.ModelLogEntry{Seq: r.nextSeq, Message: message})
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

// ProgressSnapshot 训练进度快照
type ProgressSnapshot struct {
	Percent   float64
	Timestamp time.Time
	Key       string
}

// ReadLatestProgress 扫描指定目录下的进度文件并提取最新合法进度值
func ReadLatestProgress(dir string) (ProgressSnapshot, bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return ProgressSnapshot{}, false, nil
		}
		return ProgressSnapshot{}, false, err
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
		return ProgressSnapshot{
			Percent:   *percent,
			Timestamp: timestamp,
			Key:       fmt.Sprintf("%.9f|%s", *percent, timestamp.Format(time.RFC3339Nano)),
		}, true, nil
	}
	return ProgressSnapshot{}, false, nil
}
