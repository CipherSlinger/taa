package controller

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type ImportIndexRecord struct {
	RequestID string `json:"requestId"`
	TaskID    string `json:"taskId"`
	Hash      string `json:"hash"`
	DataDir   string `json:"dataDir"`
	ResultDir string `json:"resultDir"`
}

type importIndexSnapshot struct {
	Records []ImportIndexRecord `json:"records"`
}

type ImportIndexStore struct {
	mu            sync.RWMutex
	path          string
	records       []ImportIndexRecord
	byRequestID   map[string]ImportIndexRecord
	byTaskID      map[string]ImportIndexRecord
	pendingReqIDs map[string]struct{}
	pendingTaskIDs map[string]struct{}
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
		return nil, fmt.Errorf("parse import index: %w", err)
	}
	for _, record := range snap.Records {
		record.RequestID = strings.TrimSpace(record.RequestID)
		record.TaskID = strings.TrimSpace(record.TaskID)
		record.Hash = strings.TrimSpace(record.Hash)
		if record.RequestID == "" || record.TaskID == "" || record.Hash == "" {
			return nil, fmt.Errorf("invalid import index record: requestId/taskId/hash required")
		}
		if _, ok := store.byRequestID[record.RequestID]; ok {
			return nil, fmt.Errorf("duplicate requestId in import index: %s", record.RequestID)
		}
		if _, ok := store.byTaskID[record.TaskID]; ok {
			return nil, fmt.Errorf("duplicate taskId in import index: %s", record.TaskID)
		}
		store.records = append(store.records, record)
		store.byRequestID[record.RequestID] = record
		store.byTaskID[record.TaskID] = record
	}
	return store, nil
}

func (s *ImportIndexStore) Reserve(requestID, taskID string) error {
	requestID = strings.TrimSpace(requestID)
	taskID = strings.TrimSpace(taskID)
	if requestID == "" {
		return fmt.Errorf("requestId 不能为空")
	}
	if taskID == "" {
		return fmt.Errorf("taskId 不能为空")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.byRequestID[requestID]; ok {
		return fmt.Errorf("requestId 已存在: %s", requestID)
	}
	if _, ok := s.byTaskID[taskID]; ok {
		return fmt.Errorf("taskId 已存在: %s", taskID)
	}
	if _, ok := s.pendingReqIDs[requestID]; ok {
		return fmt.Errorf("requestId 正在处理中: %s", requestID)
	}
	if _, ok := s.pendingTaskIDs[taskID]; ok {
		return fmt.Errorf("taskId 正在处理中: %s", taskID)
	}

	s.pendingReqIDs[requestID] = struct{}{}
	s.pendingTaskIDs[taskID] = struct{}{}
	return nil
}

func (s *ImportIndexStore) Commit(record ImportIndexRecord) error {
	record.RequestID = strings.TrimSpace(record.RequestID)
	record.TaskID = strings.TrimSpace(record.TaskID)
	record.Hash = strings.TrimSpace(record.Hash)
	record.DataDir = strings.TrimSpace(record.DataDir)
	record.ResultDir = strings.TrimSpace(record.ResultDir)
	if record.RequestID == "" || record.TaskID == "" || record.Hash == "" {
		return fmt.Errorf("requestId/taskId/hash 不能为空")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.pendingReqIDs[record.RequestID]; !ok {
		return fmt.Errorf("requestId 未预留: %s", record.RequestID)
	}
	if _, ok := s.pendingTaskIDs[record.TaskID]; !ok {
		return fmt.Errorf("taskId 未预留: %s", record.TaskID)
	}
	if _, ok := s.byRequestID[record.RequestID]; ok {
		return fmt.Errorf("requestId 已存在: %s", record.RequestID)
	}
	if _, ok := s.byTaskID[record.TaskID]; ok {
		return fmt.Errorf("taskId 已存在: %s", record.TaskID)
	}

	oldRecords := append([]ImportIndexRecord(nil), s.records...)
	oldByRequest := cloneImportIndexMap(s.byRequestID)
	oldByTask := cloneImportIndexMap(s.byTaskID)
	oldPendingReq := cloneImportIndexPending(s.pendingReqIDs)
	oldPendingTask := cloneImportIndexPending(s.pendingTaskIDs)

	s.records = append(s.records, record)
	s.byRequestID[record.RequestID] = record
	s.byTaskID[record.TaskID] = record
	delete(s.pendingReqIDs, record.RequestID)
	delete(s.pendingTaskIDs, record.TaskID)

	if err := s.saveLocked(); err != nil {
		s.records = oldRecords
		s.byRequestID = oldByRequest
		s.byTaskID = oldByTask
		s.pendingReqIDs = oldPendingReq
		s.pendingTaskIDs = oldPendingTask
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
	delete(s.pendingReqIDs, requestID)
	delete(s.pendingTaskIDs, taskID)
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

func (s *ImportIndexStore) saveLocked() error {
	snap := importIndexSnapshot{Records: append([]ImportIndexRecord(nil), s.records...)}
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

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create import index dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(s.path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create import index temp file: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write import index temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close import index temp file: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("replace import index file: %w", err)
	}
	return nil
}

func sameImportIndexRecord(a, b ImportIndexRecord) bool {
	return a.RequestID == b.RequestID && a.TaskID == b.TaskID && a.Hash == b.Hash && a.DataDir == b.DataDir && a.ResultDir == b.ResultDir
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

func (s *TAAState) importIndexStore() (*ImportIndexStore, error) {
	s.importIndexOnce.Do(func() {
		path := filepath.Join(s.Security.ResultDir, "import-index.json")
		s.importIndex, s.importIndexErr = LoadImportIndexStore(path)
	})
	return s.importIndex, s.importIndexErr
}
