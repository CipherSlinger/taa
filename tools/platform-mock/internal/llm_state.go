package mock

import (
	"log"
	"os"
	"sync"
	"time"
)

// llmAttestationState is the last report the platform pulled from the LLM. The
// report is stored as it came; the mock verifies nothing, which matches how the
// platform treats TEE-LLM evidence (it is displayed, not enforced).
type llmAttestationState struct {
	FetchedAt         string `json:"fetchedAt"`
	RequestID         string `json:"requestId"`
	VerifiedPass      bool   `json:"verifiedPass"`
	AttestationValues string `json:"attestationValues"`
	AttestationSize   int    `json:"attestationSize"`
	AttestationBase64 string `json:"attestationBase64"`
	Error             string `json:"error,omitempty"`
}

// llmState is what the mock knows about the TEE-LLM instance, all of it learned
// by polling. Nothing here is self-reported: the address is the one the mock
// called, and every other field is an answer to a call the mock made.
type llmState struct {
	// Address is the base URL currently being polled ("" before discovery).
	Address string `json:"address"`
	// Reachable is the last poll's outcome.
	Reachable bool `json:"reachable"`
	// Model and UptimeSeconds come from the heartbeat's result.
	Model         string `json:"model"`
	UptimeSeconds int64  `json:"uptimeSeconds"`

	Heartbeats      uint64 `json:"heartbeats"`
	LastHeartbeatAt string `json:"lastHeartbeatAt"`
	LastPollAt      string `json:"lastPollAt"`
	// LastError keeps the most recent failure until a poll succeeds, so the
	// panel can show why an instance went offline instead of only that it did.
	LastError string `json:"lastError"`

	// LogCursor is the highest seq the mock has consumed. sinceSeq is inclusive,
	// so the next pull asks from LogCursor+1. LogDropped reports that the
	// instance's ring aged out records before this poll read them.
	LogCursor  uint64 `json:"logCursor"`
	LogDropped bool   `json:"logDropped"`
	LogEntries uint64 `json:"logEntries"`

	Attestation llmAttestationState `json:"attestation"`
}

type llmStateStore struct {
	mu    sync.RWMutex
	path  string
	now   func() time.Time
	state llmState
}

func newLLMStateStore(stateDir string) *llmStateStore {
	store := &llmStateStore{
		path: defaultStateFile(stateDir, "llm-state.json"),
		now:  time.Now,
	}
	store.load()
	return store
}

func (s *llmStateStore) load() {
	state, err := loadJSONFile[llmState](s.path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("load llm state failed: %v", err)
		}
		return
	}
	s.mu.Lock()
	s.state = state
	s.mu.Unlock()
}

func (s *llmStateStore) get() llmState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

// persist writes a snapshot taken under the lock. Saving outside the lock keeps
// the poller from stalling the status endpoint for a disk write.
func (s *llmStateStore) persist(snapshot llmState) {
	if err := saveJSONFile(s.path, snapshot); err != nil {
		log.Printf("save llm state failed: %v", err)
	}
}

// recordAddress notes which base URL the poller will call next.
func (s *llmStateStore) recordAddress(addr string) {
	s.mu.Lock()
	if s.state.Address == addr {
		s.mu.Unlock()
		return
	}
	s.state.Address = addr
	snapshot := s.state
	s.mu.Unlock()
	s.persist(snapshot)
}

// recordHeartbeat records one successful liveness answer.
func (s *llmStateStore) recordHeartbeat(model string, uptimeSeconds int64) {
	s.mu.Lock()
	now := s.now().Format(time.RFC3339)
	s.state.Reachable = true
	s.state.Model = model
	s.state.UptimeSeconds = uptimeSeconds
	s.state.Heartbeats++
	s.state.LastHeartbeatAt = now
	s.state.LastPollAt = now
	s.state.LastError = ""
	snapshot := s.state
	s.mu.Unlock()
	s.persist(snapshot)
}

// recordPollError records a failed poll. It leaves the last good heartbeat
// timestamp alone: that is the liveness signal the panel ages out.
func (s *llmStateStore) recordPollError(errMsg string) {
	s.mu.Lock()
	s.state.Reachable = false
	s.state.LastPollAt = s.now().Format(time.RFC3339)
	s.state.LastError = errMsg
	snapshot := s.state
	s.mu.Unlock()
	s.persist(snapshot)
}

// recordLogError records a failed log pull without touching liveness: the
// heartbeat succeeded, so the instance is up even though this call failed.
func (s *llmStateStore) recordLogError(errMsg string) {
	s.mu.Lock()
	s.state.LastError = errMsg
	snapshot := s.state
	s.mu.Unlock()
	s.persist(snapshot)
}

// recordLogPull advances the cursor and counts what was added.
func (s *llmStateStore) recordLogPull(latestSeq uint64, added int, dropped bool) {
	s.mu.Lock()
	if latestSeq > s.state.LogCursor {
		s.state.LogCursor = latestSeq
	}
	s.state.LogEntries += uint64(added)
	if dropped {
		s.state.LogDropped = true
	}
	snapshot := s.state
	s.mu.Unlock()
	s.persist(snapshot)
}

// resetLogCursor clears the read position after the instance restarted (its seq
// numbering starts over), so the new run's records are not mistaken for
// duplicates.
func (s *llmStateStore) resetLogCursor() {
	s.mu.Lock()
	s.state.LogCursor = 0
	s.state.LogDropped = false
	snapshot := s.state
	s.mu.Unlock()
	s.persist(snapshot)
}

func (s *llmStateStore) setAttestation(state llmAttestationState) {
	s.mu.Lock()
	s.state.Attestation = state
	snapshot := s.state
	s.mu.Unlock()
	s.persist(snapshot)
}

func (s *llmStateStore) reset() {
	s.mu.Lock()
	s.state = llmState{}
	snapshot := s.state
	s.mu.Unlock()
	s.persist(snapshot)
}
