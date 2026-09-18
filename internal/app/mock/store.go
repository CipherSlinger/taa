package mock

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type registerState struct {
	Received           bool   `json:"received"`
	Accepted           bool   `json:"accepted"`
	ReceivedAt         string `json:"receivedAt"`
	DockerID           string `json:"dockerId"`
	AuthInfo           string `json:"authInfo"`
	TaaPublicKey       string `json:"taaPublicKey"`
	AttestationValues  string `json:"attestationValues"`
	Timestamp          string `json:"timestamp"`
	VerifiedPass       bool   `json:"verifiedPass"`
	AttestationName    string `json:"attestationName"`
	AttestationSize    int64  `json:"attestationSize"`
	ContentType        string `json:"contentType"`
	StatusCode         int    `json:"statusCode"`
	Message            string `json:"message"`
	AttestationBase64  string `json:"attestationBase64"`
	AttestationContent string `json:"attestationContent"`
}

type registerRequest struct {
	DockerID          string          `json:"dockerId"`
	AuthInfo          json.RawMessage `json:"authInfo"`
	TaaPublicKey      string          `json:"taaPublicKey"`
	AttestationValues string          `json:"attestationValues"`
	Timestamp         string          `json:"timestamp"`
	VerifiedPass      bool            `json:"verifiedPass"`
	Attestation       string          `json:"attestation"`
}

type registerStateStore struct {
	mu    sync.RWMutex
	path  string
	state registerState
}

func newRegisterStateStore(stateDir string) *registerStateStore {
	store := &registerStateStore{path: defaultStateFile(stateDir, "register-state.json")}
	store.load()
	return store
}

func (s *registerStateStore) load() {
	state, err := loadJSONFile[registerState](s.path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("load register state failed: %v", err)
		}
		return
	}
	s.state = state
}

func (s *registerStateStore) get() registerState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

func (s *registerStateStore) set(state registerState) {
	s.mu.Lock()
	s.state = state
	path := s.path
	s.mu.Unlock()
	if err := saveJSONFile(path, state); err != nil {
		log.Printf("save register state failed: %v", err)
	}
}

func (s *registerStateStore) reset() {
	s.mu.Lock()
	s.state = registerState{}
	path := s.path
	s.mu.Unlock()
	if err := saveJSONFile(path, registerState{}); err != nil {
		log.Printf("save register state failed: %v", err)
	}
}

type apiResponse struct {
	Msg    string `json:"msg"`
	Result any    `json:"result"`
	Error  int    `json:"error"`
}

type uploadedFileRecord struct {
	Filename     string    `json:"filename"`
	OriginalName string    `json:"originalName"`
	Size         int64     `json:"size"`
	URL          string    `json:"url"`
	UploadedAt   time.Time `json:"uploadedAt"`
	Encrypted    bool      `json:"encrypted"`
}

type reportState struct {
	Received    bool           `json:"received"`
	Accepted    bool           `json:"accepted"`
	ReceivedAt  string         `json:"receivedAt"`
	DockerID    string         `json:"dockerId"`
	RequestID   string         `json:"requestId"`
	TaskID      string         `json:"taskId"`
	Code        int            `json:"code"`
	Msg         string         `json:"msg"`
	Report      string         `json:"report"`
	Checksum    map[string]any `json:"checksum,omitempty"`
	ContentType string         `json:"contentType"`
	StatusCode  int            `json:"statusCode"`
	Message     string         `json:"message"`
	RawBody     string         `json:"rawBody"`
}

type reportStoreData struct {
	Current reportState   `json:"current"`
	History []reportState `json:"history"`
}

type reportStateStore struct {
	mu      sync.RWMutex
	path    string
	state   reportState
	history []reportState
}

func newReportStateStore(stateDir string, filename ...string) *reportStateStore {
	name := "report-state.json"
	if len(filename) > 0 {
		name = filename[0]
	}
	store := &reportStateStore{path: defaultStateFile(stateDir, name)}
	store.load()
	return store
}

func (s *reportStateStore) load() {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("load report state failed: %v", err)
		}
		return
	}
	if len(data) == 0 {
		return
	}

	var storeData reportStoreData
	if err := json.Unmarshal(data, &storeData); err == nil && (storeData.Current.Received || len(storeData.History) > 0) {
		s.state = storeData.Current
		s.history = storeData.History
		return
	}

	var legacy reportState
	if err := json.Unmarshal(data, &legacy); err == nil && legacy.Received {
		s.state = legacy
		s.history = []reportState{legacy}
		return
	}
}

func (s *reportStateStore) saveLocked() {
	if s.path == "" {
		return
	}
	history := s.history
	if history == nil {
		history = []reportState{}
	}
	data := reportStoreData{
		Current: s.state,
		History: history,
	}
	if err := saveJSONFile(s.path, data); err != nil {
		log.Printf("save report state failed: %v", err)
	}
}

func (s *reportStateStore) get() reportState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

func (s *reportStateStore) getHistory() []reportState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.history) == 0 {
		return []reportState{}
	}
	h := make([]reportState, len(s.history))
	copy(h, s.history)
	return h
}

func (s *reportStateStore) set(state reportState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = state
	s.history = append([]reportState{state}, s.history...)
	if len(s.history) > 500 {
		s.history = s.history[:500]
	}
	s.saveLocked()
}

func (s *reportStateStore) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = reportState{}
	s.history = nil
	s.saveLocked()
}

type progressState struct {
	Received   bool    `json:"received"`
	Accepted   bool    `json:"accepted"`
	ReceivedAt string  `json:"receivedAt"`
	DockerID   string  `json:"dockerId"`
	RequestID  string  `json:"requestId"`
	TaskID     string  `json:"taskId"`
	Percent    float64 `json:"percent"`
	Timestamp  string  `json:"timestamp"`
	StatusCode int     `json:"statusCode"`
	Message    string  `json:"message"`
	RawBody    string  `json:"rawBody"`
}

type reportProgressRequest struct {
	DockerID  string  `json:"dockerId"`
	RequestID string  `json:"requestId"`
	TaskID    string  `json:"taskId"`
	Percent   float64 `json:"percent"`
	Timestamp string  `json:"timestamp"`
}

type progressStateStore struct {
	mu    sync.RWMutex
	path  string
	state progressState
}

func newProgressStateStore(stateDir string) *progressStateStore {
	store := &progressStateStore{path: defaultStateFile(stateDir, "reportProgress-state.json")}
	store.load()
	return store
}

func (s *progressStateStore) load() {
	state, err := loadJSONFile[progressState](s.path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("load progress state failed: %v", err)
		}
		return
	}
	s.state = state
}

func (s *progressStateStore) get() progressState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

func (s *progressStateStore) set(state progressState) {
	s.mu.Lock()
	s.state = state
	path := s.path
	s.mu.Unlock()
	if err := saveJSONFile(path, state); err != nil {
		log.Printf("save progress state failed: %v", err)
	}
}

func (s *progressStateStore) reset() {
	s.mu.Lock()
	s.state = progressState{}
	path := s.path
	s.mu.Unlock()
	if err := saveJSONFile(path, progressState{}); err != nil {
		log.Printf("save progress state failed: %v", err)
	}
}

type modelLogEntry struct {
	Seq       uint64 `json:"seq"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp,omitempty"`
}

type modelLogState struct {
	DockerID   string          `json:"dockerId"`
	RequestID  string          `json:"requestId"`
	TaskID     string          `json:"taskId"`
	TotalCount int             `json:"totalCount"`
	LastSeq    uint64          `json:"lastSeq"`
	Entries    []modelLogEntry `json:"entries"`
}

type modelLogRequest struct {
	DockerID  string          `json:"dockerId"`
	RequestID string          `json:"requestId"`
	TaskID    string          `json:"taskId,omitempty"`
	SeqStart  uint64          `json:"seqStart"`
	Entries   []modelLogEntry `json:"entries"`
}

type modelLogStore struct {
	mu       sync.RWMutex
	path     string
	capacity int
	seen     map[string]struct{}
	state    modelLogState
	out      io.Writer
}

func newModelLogStore(stateDir string, capacity int) *modelLogStore {
	if capacity <= 0 {
		capacity = 2000
	}
	store := &modelLogStore{
		path:     defaultStateFile(stateDir, "modelLog-state.json"),
		capacity: capacity,
		seen:     make(map[string]struct{}),
		out:      os.Stdout,
	}
	store.load()
	return store
}

func (s *modelLogStore) load() {
	state, err := loadJSONFile[modelLogState](s.path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("load modelLog state failed: %v", err)
		}
		return
	}
	s.state = state
	for _, entry := range state.Entries {
		key := fmt.Sprintf("%s:%s:%d", state.DockerID, state.RequestID, entry.Seq)
		s.seen[key] = struct{}{}
	}
}

func (s *modelLogStore) get() modelLogState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cpy := s.state
	if len(s.state.Entries) > 0 {
		cpy.Entries = append([]modelLogEntry(nil), s.state.Entries...)
	} else {
		cpy.Entries = []modelLogEntry{}
	}
	return cpy
}

func (s *modelLogStore) reset() {
	s.mu.Lock()
	s.state = modelLogState{
		Entries: []modelLogEntry{},
	}
	s.seen = make(map[string]struct{})
	path := s.path
	s.mu.Unlock()
	if err := saveJSONFile(path, modelLogState{Entries: []modelLogEntry{}}); err != nil {
		log.Printf("save modelLog state failed: %v", err)
	}
}

func (s *modelLogStore) addEntries(dockerId, requestId, taskId string, entries []modelLogEntry) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	var toAdd []modelLogEntry
	for _, entry := range entries {
		key := fmt.Sprintf("%s:%s:%d", dockerId, requestId, entry.Seq)
		if _, exists := s.seen[key]; exists {
			continue
		}
		s.seen[key] = struct{}{}
		toAdd = append(toAdd, entry)
	}

	addedCount := len(toAdd)
	if addedCount == 0 {
		return 0
	}

	s.state.DockerID = dockerId
	s.state.RequestID = requestId
	if taskId != "" {
		s.state.TaskID = taskId
	}
	s.state.TotalCount += addedCount

	sort.Slice(toAdd, func(i, j int) bool {
		return toAdd[i].Seq < toAdd[j].Seq
	})
	out := s.out
	if out == nil {
		out = os.Stdout
	}
	for _, entry := range toAdd {
		fmt.Fprintln(out, entry.Message)
	}

	s.state.Entries = append(s.state.Entries, toAdd...)
	sort.Slice(s.state.Entries, func(i, j int) bool {
		return s.state.Entries[i].Seq < s.state.Entries[j].Seq
	})

	if s.capacity > 0 && len(s.state.Entries) > s.capacity {
		s.state.Entries = append([]modelLogEntry(nil), s.state.Entries[len(s.state.Entries)-s.capacity:]...)
	}

	for _, entry := range toAdd {
		if entry.Seq > s.state.LastSeq {
			s.state.LastSeq = entry.Seq
		}
	}
	if len(s.state.Entries) > 0 && s.state.Entries[len(s.state.Entries)-1].Seq > s.state.LastSeq {
		s.state.LastSeq = s.state.Entries[len(s.state.Entries)-1].Seq
	}

	stateToSave := s.state
	path := s.path
	if err := saveJSONFile(path, stateToSave); err != nil {
		log.Printf("save modelLog state failed: %v", err)
	}

	return addedCount
}

type taaLogEntry struct {
	Seq       uint64 `json:"seq"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp,omitempty"`
}

type taaLogState struct {
	DockerID   string        `json:"dockerId"`
	RequestID  string        `json:"requestId"`
	TaskID     string        `json:"taskId"`
	TotalCount int           `json:"totalCount"`
	LastSeq    uint64        `json:"lastSeq"`
	Entries    []taaLogEntry `json:"entries"`
}

type taaLogRequest struct {
	DockerID  string        `json:"dockerId"`
	RequestID string        `json:"requestId"`
	TaskID    string        `json:"taskId,omitempty"`
	SeqStart  uint64        `json:"seqStart"`
	Entries   []taaLogEntry `json:"entries"`
}

type taaLogStore struct {
	mu       sync.RWMutex
	path     string
	capacity int
	seen     map[string]struct{}
	state    taaLogState
}

func newTaaLogStore(stateDir string, capacity int) *taaLogStore {
	if capacity <= 0 {
		capacity = 2000
	}
	store := &taaLogStore{
		path:     defaultStateFile(stateDir, "taaLog-state.json"),
		capacity: capacity,
		seen:     make(map[string]struct{}),
	}
	store.load()
	return store
}

func (s *taaLogStore) load() {
	state, err := loadJSONFile[taaLogState](s.path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("load taaLog state failed: %v", err)
		}
		return
	}
	s.state = state
	for _, entry := range state.Entries {
		key := fmt.Sprintf("%s:%s:%d", state.DockerID, state.RequestID, entry.Seq)
		s.seen[key] = struct{}{}
	}
}

func (s *taaLogStore) get() taaLogState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cpy := s.state
	if len(s.state.Entries) > 0 {
		cpy.Entries = append([]taaLogEntry(nil), s.state.Entries...)
	} else {
		cpy.Entries = []taaLogEntry{}
	}
	return cpy
}

func (s *taaLogStore) reset() {
	s.mu.Lock()
	s.state = taaLogState{
		Entries: []taaLogEntry{},
	}
	s.seen = make(map[string]struct{})
	path := s.path
	s.mu.Unlock()
	if err := saveJSONFile(path, taaLogState{Entries: []taaLogEntry{}}); err != nil {
		log.Printf("save taaLog state failed: %v", err)
	}
}

func (s *taaLogStore) addEntries(dockerId, requestId, taskId string, entries []taaLogEntry) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	var toAdd []taaLogEntry
	for _, entry := range entries {
		key := fmt.Sprintf("%s:%s:%d", dockerId, requestId, entry.Seq)
		if _, exists := s.seen[key]; exists {
			continue
		}
		s.seen[key] = struct{}{}
		toAdd = append(toAdd, entry)
	}

	addedCount := len(toAdd)
	if addedCount == 0 {
		return 0
	}

	s.state.DockerID = dockerId
	s.state.RequestID = requestId
	if taskId != "" {
		s.state.TaskID = taskId
	}
	s.state.TotalCount += addedCount

	s.state.Entries = append(s.state.Entries, toAdd...)
	sort.Slice(s.state.Entries, func(i, j int) bool {
		return s.state.Entries[i].Seq < s.state.Entries[j].Seq
	})

	if s.capacity > 0 && len(s.state.Entries) > s.capacity {
		s.state.Entries = append([]taaLogEntry(nil), s.state.Entries[len(s.state.Entries)-s.capacity:]...)
	}

	for _, entry := range toAdd {
		if entry.Seq > s.state.LastSeq {
			s.state.LastSeq = entry.Seq
		}
	}
	if len(s.state.Entries) > 0 && s.state.Entries[len(s.state.Entries)-1].Seq > s.state.LastSeq {
		s.state.LastSeq = s.state.Entries[len(s.state.Entries)-1].Seq
	}

	stateToSave := s.state
	path := s.path
	if err := saveJSONFile(path, stateToSave); err != nil {
		log.Printf("save taaLog state failed: %v", err)
	}

	return addedCount
}

type requestLogEntry struct {
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
	Direction string `json:"direction,omitempty"`
	Level     string `json:"level,omitempty"`
	Component string `json:"component,omitempty"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status,omitempty"`
	Message   string `json:"message,omitempty"`
	Body      string `json:"body,omitempty"`
}

type requestLogStore struct {
	mu      sync.RWMutex
	path    string
	entries []requestLogEntry
	max     int
}

func newRequestLogStore(max int) *requestLogStore {
	if max <= 0 {
		max = 500
	}
	return &requestLogStore{max: max}
}

func (s *requestLogStore) add(entry requestLogEntry) {
	if entry.ID == "" {
		entry.ID = fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().Format(time.RFC3339Nano)
	}
	if entry.Level == "" {
		entry.Level = "info"
	}
	if entry.Direction == "" {
		entry.Direction = "out"
	}
	s.mu.Lock()
	s.entries = append(s.entries, entry)
	if len(s.entries) > s.max*2 {
		s.entries = append([]requestLogEntry(nil), s.entries[len(s.entries)-s.max:]...)
	}
	s.mu.Unlock()
}

func (s *requestLogStore) list() []requestLogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]requestLogEntry(nil), s.entries...)
}

func (s *requestLogStore) drain() []requestLogEntry {
	s.mu.Lock()
	entries := append([]requestLogEntry(nil), s.entries...)
	s.entries = nil
	s.mu.Unlock()
	return entries
}

func (s *requestLogStore) reset() {
	s.mu.Lock()
	s.entries = nil
	s.mu.Unlock()
}

func summarizeRequestBody(body []byte, limit int) string {
	text := strings.TrimSpace(string(body))
	if text == "" {
		return "{}"
	}
	if limit <= 0 || len(text) <= limit {
		return text
	}
	return text[:limit]
}

func defaultStateFile(stateDir, name string) string {
	if strings.TrimSpace(stateDir) == "" {
		stateDir = "/root/taa"
	}
	return filepath.Join(stateDir, name)
}

func loadJSONFile[T any](path string) (T, error) {
	var zero T
	data, err := os.ReadFile(path)
	if err != nil {
		return zero, err
	}
	if len(data) == 0 {
		return zero, nil
	}
	if err := json.Unmarshal(data, &zero); err != nil {
		return zero, err
	}
	return zero, nil
}

func saveJSONFile(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
