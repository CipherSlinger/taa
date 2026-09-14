package controller

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"taa/pkg/utils"
)

type ImportIndexRecord struct {
	RequestID string `json:"requestId"`
	TaskID    string `json:"taskId"`
	Hash      string `json:"hash"`
	DataDir   string `json:"dataDir"`
	ResultDir string `json:"resultDir"`
	Phase     int    `json:"phase"`
}

type importIndexSnapshot struct {
	Records []ImportIndexRecord `json:"records"`
	Latest  *ImportIndexRecord  `json:"latest,omitempty"`
}

type ImportIndexStore struct {
	mu             sync.RWMutex
	path           string
	records        []ImportIndexRecord
	byRequestID    map[string]ImportIndexRecord
	byTaskID       map[string]ImportIndexRecord
	pendingReqIDs  map[string]struct{}
	pendingTaskIDs map[string]struct{}
	latestRecord   *ImportIndexRecord
}

func LoadImportIndexStore(path string) (*ImportIndexStore, error) {
	store := &ImportIndexStore{
		path:           path,
		byRequestID:    map[string]ImportIndexRecord{},
		byTaskID:       map[string]ImportIndexRecord{},
		pendingReqIDs:  map[string]struct{}{},
		pendingTaskIDs: map[string]struct{}{},
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return store, nil
		}
		return nil, fmt.Errorf("read import index: %w", err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return store, nil
	}

	var snap importIndexSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		bakPath := path + ".bak"
		bakData, bakErr := os.ReadFile(bakPath)
		recovered := false
		if bakErr == nil && len(strings.TrimSpace(string(bakData))) > 0 {
			var bakSnap importIndexSnapshot
			if bErr := json.Unmarshal(bakData, &bakSnap); bErr == nil {
				snap = bakSnap
				recovered = true
				log.Printf("WARN: import index at %s is corrupted (%v), successfully recovered from backup %s", path, err, bakPath)
				_ = os.WriteFile(path, bakData, 0o644)
			}
		}

		if !recovered {
			timestamp := time.Now().Unix()
			corruptedPath := fmt.Sprintf("%s.corrupted.%d", path, timestamp)
			if renameErr := os.Rename(path, corruptedPath); renameErr != nil && !os.IsNotExist(renameErr) {
				log.Printf("ERROR: failed to rename corrupted import index %s to %s: %v", path, corruptedPath, renameErr)
			}
			log.Printf("ALERT: import index at %s is corrupted (%v), archived to %s; initializing clean store", path, err, corruptedPath)
			return store, nil
		}
	}
	for _, record := range snap.Records {
		record.RequestID = strings.TrimSpace(record.RequestID)
		record.TaskID = strings.TrimSpace(record.TaskID)
		record.Hash = strings.TrimSpace(record.Hash)
		if (record.RequestID == "" && record.TaskID == "") || record.Hash == "" {
			return nil, fmt.Errorf("invalid import index record: requestId/taskId/hash required")
		}
		if record.RequestID != "" {
			if _, ok := store.byRequestID[record.RequestID]; ok {
				return nil, fmt.Errorf("duplicate requestId in import index: %s", record.RequestID)
			}
			store.byRequestID[record.RequestID] = record
		}
		if record.TaskID != "" {
			if _, ok := store.byTaskID[record.TaskID]; ok {
				return nil, fmt.Errorf("duplicate taskId in import index: %s", record.TaskID)
			}
			store.byTaskID[record.TaskID] = record
		}
		store.records = append(store.records, record)
	}
	if snap.Latest != nil {
		rec := *snap.Latest
		store.latestRecord = &rec
	} else if len(store.records) > 0 {
		rec := store.records[len(store.records)-1]
		store.latestRecord = &rec
	}
	return store, nil
}

func (s *ImportIndexStore) Reserve(requestID, taskID string) error {
	requestID = strings.TrimSpace(requestID)
	taskID = strings.TrimSpace(taskID)
	if requestID == "" && taskID == "" {
		return fmt.Errorf("requestId 和 taskId 不能同时为空")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if requestID != "" {
		if _, ok := s.byRequestID[requestID]; ok {
			return fmt.Errorf("requestId 已存在: %s", requestID)
		}
		if _, ok := s.pendingReqIDs[requestID]; ok {
			return fmt.Errorf("requestId 正在处理中: %s", requestID)
		}
	}
	if taskID != "" {
		if _, ok := s.byTaskID[taskID]; ok {
			return fmt.Errorf("taskId 已存在: %s", taskID)
		}
		if _, ok := s.pendingTaskIDs[taskID]; ok {
			return fmt.Errorf("taskId 正在处理中: %s", taskID)
		}
	}

	if requestID != "" {
		s.pendingReqIDs[requestID] = struct{}{}
	}
	if taskID != "" {
		s.pendingTaskIDs[taskID] = struct{}{}
	}
	return nil
}

func (s *ImportIndexStore) Commit(record ImportIndexRecord) error {
	record.RequestID = strings.TrimSpace(record.RequestID)
	record.TaskID = strings.TrimSpace(record.TaskID)
	record.Hash = strings.TrimSpace(record.Hash)
	record.DataDir = strings.TrimSpace(record.DataDir)
	record.ResultDir = strings.TrimSpace(record.ResultDir)
	if (record.RequestID == "" && record.TaskID == "") || record.Hash == "" {
		return fmt.Errorf("requestId 和 taskId 不能同时为空且 hash 不能为空")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if record.RequestID != "" {
		if _, ok := s.pendingReqIDs[record.RequestID]; !ok {
			return fmt.Errorf("requestId 未预留: %s", record.RequestID)
		}
		if _, ok := s.byRequestID[record.RequestID]; ok {
			return fmt.Errorf("requestId 已存在: %s", record.RequestID)
		}
	}
	if record.TaskID != "" {
		if _, ok := s.pendingTaskIDs[record.TaskID]; !ok {
			return fmt.Errorf("taskId 未预留: %s", record.TaskID)
		}
		if _, ok := s.byTaskID[record.TaskID]; ok {
			return fmt.Errorf("taskId 已存在: %s", record.TaskID)
		}
	}

	oldRecords := append([]ImportIndexRecord(nil), s.records...)
	oldByRequest := cloneImportIndexMap(s.byRequestID)
	oldByTask := cloneImportIndexMap(s.byTaskID)
	oldPendingReq := cloneImportIndexPending(s.pendingReqIDs)
	oldPendingTask := cloneImportIndexPending(s.pendingTaskIDs)
	oldLatest := s.latestRecord

	s.records = append(s.records, record)
	recCopy := record
	s.latestRecord = &recCopy
	if record.RequestID != "" {
		s.byRequestID[record.RequestID] = record
		delete(s.pendingReqIDs, record.RequestID)
	}
	if record.TaskID != "" {
		s.byTaskID[record.TaskID] = record
		delete(s.pendingTaskIDs, record.TaskID)
	}

	if err := s.saveLocked(); err != nil {
		s.records = oldRecords
		s.byRequestID = oldByRequest
		s.byTaskID = oldByTask
		s.pendingReqIDs = oldPendingReq
		s.pendingTaskIDs = oldPendingTask
		s.latestRecord = oldLatest
		return err
	}
	return nil
}

func (s *ImportIndexStore) Rollback(requestID, taskID string) {
	requestID = strings.TrimSpace(requestID)
	taskID = strings.TrimSpace(taskID)
	if requestID == "" && taskID == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if requestID != "" {
		delete(s.pendingReqIDs, requestID)
	}
	if taskID != "" {
		delete(s.pendingTaskIDs, taskID)
	}
}

func (s *ImportIndexStore) LookupByRequestID(requestID string) (ImportIndexRecord, bool) {
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		return ImportIndexRecord{}, false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.byRequestID[requestID]
	return record, ok
}

func (s *ImportIndexStore) LookupByTaskID(taskID string) (ImportIndexRecord, bool) {
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return ImportIndexRecord{}, false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.byTaskID[taskID]
	return record, ok
}

func (s *ImportIndexStore) Lookup(requestID, taskID string) (ImportIndexRecord, error) {
	requestID = strings.TrimSpace(requestID)
	taskID = strings.TrimSpace(taskID)
	if requestID == "" && taskID == "" {
		return ImportIndexRecord{}, fmt.Errorf("requestId 和 taskId 不能同时为空")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var (
		reqRecord  ImportIndexRecord
		taskRecord ImportIndexRecord
		reqOK      bool
		taskOK     bool
	)
	if requestID != "" {
		reqRecord, reqOK = s.byRequestID[requestID]
	}
	if taskID != "" {
		taskRecord, taskOK = s.byTaskID[taskID]
	}

	switch {
	case reqOK && taskOK:
		if sameImportIndexRecord(reqRecord, taskRecord) {
			return reqRecord, nil
		}
		return ImportIndexRecord{}, fmt.Errorf("requestId 和 taskId 命中了不同记录: requestId=%s taskId=%s", requestID, taskID)
	case reqOK:
		return reqRecord, nil
	case taskOK:
		return taskRecord, nil
	default:
		return ImportIndexRecord{}, fmt.Errorf("未找到对应记录: requestId=%s taskId=%s", requestID, taskID)
	}
}

func (s *ImportIndexStore) Latest() (ImportIndexRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.latestRecord != nil {
		return *s.latestRecord, true
	}
	if len(s.records) > 0 {
		return s.records[len(s.records)-1], true
	}
	return ImportIndexRecord{}, false
}

func (s *ImportIndexStore) Purge(requestID, taskID string) error {
	requestID = strings.TrimSpace(requestID)
	taskID = strings.TrimSpace(taskID)
	if requestID == "" && taskID == "" {
		return fmt.Errorf("requestId 和 taskId 不能同时为空")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var matched []ImportIndexRecord
	newRecords := make([]ImportIndexRecord, 0, len(s.records))
	for _, rec := range s.records {
		match := false
		if requestID != "" && rec.RequestID == requestID {
			match = true
		}
		if taskID != "" && rec.TaskID == taskID {
			match = true
		}
		if match {
			matched = append(matched, rec)
		} else {
			newRecords = append(newRecords, rec)
		}
	}

	if requestID != "" {
		delete(s.pendingReqIDs, requestID)
	}
	if taskID != "" {
		delete(s.pendingTaskIDs, taskID)
	}

	if len(matched) == 0 {
		return nil
	}

	s.records = newRecords

	// 2. 从 byRequestID、byTaskID 移除
	for _, m := range matched {
		if m.RequestID != "" {
			delete(s.byRequestID, m.RequestID)
		}
		if m.TaskID != "" {
			delete(s.byTaskID, m.TaskID)
		}
	}

	// 3. 若 latestRecord 正好是该条目，则回退为列表中上一条合法记录（或 nil）
	if s.latestRecord != nil {
		latestRemoved := false
		for _, m := range matched {
			if sameImportIndexRecord(*s.latestRecord, m) {
				latestRemoved = true
				break
			}
		}
		if latestRemoved {
			if len(s.records) > 0 {
				rec := s.records[len(s.records)-1]
				s.latestRecord = &rec
			} else {
				s.latestRecord = nil
			}
		}
	}

	// 4. 若对应的 ResultDir 存在，重命名为 <ResultDir>/.failed-<taskID>-<timestamp> 归档
	for _, m := range matched {
		if m.ResultDir == "" {
			continue
		}
		tID := m.TaskID
		if tID == "" {
			tID = taskID
		}
		if tID == "" {
			tID = m.RequestID
		}
		if _, err := utils.ArchiveFailedDir(m.ResultDir, tID); err != nil {
			log.Printf("WARN: failed to archive ResultDir %s: %v", m.ResultDir, err)
		}
	}

	// 5. 执行 saveLocked 持久化
	return s.saveLocked()
}

func (s *ImportIndexStore) saveLocked() error {
	snap := importIndexSnapshot{
		Records: append([]ImportIndexRecord(nil), s.records...),
		Latest:  s.latestRecord,
	}
	sort.Slice(snap.Records, func(i, j int) bool {
		if snap.Records[i].RequestID != snap.Records[j].RequestID {
			return snap.Records[i].RequestID < snap.Records[j].RequestID
		}
		if snap.Records[i].TaskID != snap.Records[j].TaskID {
			return snap.Records[i].TaskID < snap.Records[j].TaskID
		}
		return snap.Records[i].Hash < snap.Records[j].Hash
	})

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal import index: %w", err)
	}
	data = append(data, '\n')

	if err := utils.AtomicWriteFile(s.path, data, 0o600); err != nil {
		return fmt.Errorf("replace import index file: %w", err)
	}

	// 成功后顺带刷新 .bak 文件
	s.refreshBakLocked(data)
	return nil
}

func (s *ImportIndexStore) refreshBakLocked(data []byte) {
	bakPath := s.path + ".bak"
	_ = utils.AtomicWriteFile(bakPath, data, 0o600)
}

func sameImportIndexRecord(a, b ImportIndexRecord) bool {
	return a.RequestID == b.RequestID && a.TaskID == b.TaskID && a.Hash == b.Hash && a.DataDir == b.DataDir && a.ResultDir == b.ResultDir && a.Phase == b.Phase
}

func cloneImportIndexMap(src map[string]ImportIndexRecord) map[string]ImportIndexRecord {
	out := make(map[string]ImportIndexRecord, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func cloneImportIndexPending(src map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(src))
	for k := range src {
		out[k] = struct{}{}
	}
	return out
}

// ImportIndexStore 返回导入索引存储引擎实例
func (s *TAAState) ImportIndexStore() (*ImportIndexStore, error) {
	s.importIndexOnce.Do(func() {
		path := filepath.Join(s.Security.ResultDir, "import-index.json")
		s.importIndex, s.importIndexErr = LoadImportIndexStore(path)
	})
	return s.importIndex, s.importIndexErr
}

func (s *TAAState) importIndexStore() (*ImportIndexStore, error) {
	return s.ImportIndexStore()
}
