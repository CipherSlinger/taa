package mock

import (
	"log"
	"os"
	"sync"
)

// llmRegisterState mirrors the plaintext registration an LLM instance sends.
// It is deliberately separate from registerState: TAA and LLM instances report
// different identities and must not overwrite each other's panel entries.
type llmRegisterState struct {
	Received          bool   `json:"received"`
	ReceivedAt        string `json:"receivedAt"`
	DockerID          string `json:"dockerId"`
	TaaPublicKey      string `json:"taaPublicKey"`
	AttestationValues string `json:"attestationValues"`
	Timestamp         string `json:"timestamp"`
	VerifiedPass      bool   `json:"verifiedPass"`
	AttestationSize   int    `json:"attestationSize"`
	AttestationBase64 string `json:"attestationBase64"`
	Certificate       string `json:"certificate"`
}

// llmHeartbeatState records the most recent liveness ping.
type llmHeartbeatState struct {
	DockerID   string `json:"dockerId"`
	Timestamp  string `json:"timestamp"`
	ReceivedAt string `json:"receivedAt"`
	Count      uint64 `json:"count"`
}

// llmState is the persisted aggregate shown by the status endpoint.
type llmState struct {
	Register  llmRegisterState  `json:"register"`
	Heartbeat llmHeartbeatState `json:"heartbeat"`
}

type llmStateStore struct {
	mu    sync.RWMutex
	path  string
	state llmState
}

func newLLMStateStore(stateDir string) *llmStateStore {
	store := &llmStateStore{path: defaultStateFile(stateDir, "llm-state.json")}
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

func (s *llmStateStore) setRegister(state llmRegisterState) {
	s.mu.Lock()
	s.state.Register = state
	snapshot := s.state
	s.mu.Unlock()
	if err := saveJSONFile(s.path, snapshot); err != nil {
		log.Printf("save llm state failed: %v", err)
	}
}

func (s *llmStateStore) recordHeartbeat(state llmHeartbeatState) {
	s.mu.Lock()
	s.state.Heartbeat = state
	snapshot := s.state
	s.mu.Unlock()
	if err := saveJSONFile(s.path, snapshot); err != nil {
		log.Printf("save llm state failed: %v", err)
	}
}

func (s *llmStateStore) reset() {
	s.mu.Lock()
	s.state = llmState{}
	path := s.path
	s.mu.Unlock()
	if err := saveJSONFile(path, llmState{}); err != nil {
		log.Printf("save llm state failed: %v", err)
	}
}
