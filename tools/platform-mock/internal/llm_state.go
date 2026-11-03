package mock

import (
	"log"
	"os"
	"sort"
	"sync"
	"time"
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
}

// llmHeartbeatState records the most recent liveness ping.
type llmHeartbeatState struct {
	DockerID   string `json:"dockerId"`
	Timestamp  string `json:"timestamp"`
	ReceivedAt string `json:"receivedAt"`
	Count      uint64 `json:"count"`
}

// maxLLMSources bounds the recent-source list. Five is enough to see which
// instances have been talking without turning the panel into an audit log.
const maxLLMSources = 5

// LastEvent values recorded in llmSource.
const (
	llmEventRegister  = "register"
	llmEventHeartbeat = "heartbeat"
	llmEventLog       = "log"
)

// llmSource records that a dockerId has reported to this mock. It exists only
// for observability: the registration state itself stays single-instance, so a
// second dockerId overwrites the panel while leaving a trace here.
type llmSource struct {
	DockerID   string `json:"dockerId"`
	FirstSeen  string `json:"firstSeen"`
	LastSeen   string `json:"lastSeen"`
	LastEvent  string `json:"lastEvent"`
	Registers  uint64 `json:"registers"`
	Heartbeats uint64 `json:"heartbeats"`
	Logs       uint64 `json:"logs"`
}

// llmState is the persisted aggregate shown by the status endpoint.
type llmState struct {
	Register  llmRegisterState  `json:"register"`
	Heartbeat llmHeartbeatState `json:"heartbeat"`
	Sources   []llmSource       `json:"sources"`
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
	cpy := s.state
	if len(s.state.Sources) > 0 {
		cpy.Sources = append([]llmSource(nil), s.state.Sources...)
	} else {
		// An empty list must marshal as [] rather than null, matching the
		// other status fields the console renders.
		cpy.Sources = []llmSource{}
	}
	return cpy
}

func (s *llmStateStore) setRegister(state llmRegisterState) {
	s.mu.Lock()
	s.state.Register = state
	s.touchSourceLocked(state.DockerID, llmEventRegister)
	snapshot := s.state
	s.mu.Unlock()
	if err := saveJSONFile(s.path, snapshot); err != nil {
		log.Printf("save llm state failed: %v", err)
	}
}

func (s *llmStateStore) recordHeartbeat(state llmHeartbeatState) {
	s.mu.Lock()
	s.state.Heartbeat = state
	s.touchSourceLocked(state.DockerID, llmEventHeartbeat)
	snapshot := s.state
	s.mu.Unlock()
	if err := saveJSONFile(s.path, snapshot); err != nil {
		log.Printf("save llm state failed: %v", err)
	}
}

// touchLog records that a log batch arrived. Logs live in their own store, so
// this only keeps the recent-source list current.
func (s *llmStateStore) touchLog(dockerID string) {
	s.mu.Lock()
	s.touchSourceLocked(dockerID, llmEventLog)
	snapshot := s.state
	s.mu.Unlock()
	if err := saveJSONFile(s.path, snapshot); err != nil {
		log.Printf("save llm state failed: %v", err)
	}
}

// touchSourceLocked upserts one dockerId and re-sorts newest-first. Empty ids
// are rejected by the handlers already, but guarding here keeps a malformed
// state file from producing a nameless row.
func (s *llmStateStore) touchSourceLocked(dockerID, event string) {
	if dockerID == "" {
		return
	}
	now := s.now().Format(time.RFC3339)
	for i := range s.state.Sources {
		src := &s.state.Sources[i]
		if src.DockerID != dockerID {
			continue
		}
		src.LastSeen = now
		src.LastEvent = event
		switch event {
		case llmEventRegister:
			src.Registers++
		case llmEventHeartbeat:
			src.Heartbeats++
		case llmEventLog:
			src.Logs++
		}
		s.sortSourcesLocked()
		return
	}
	src := llmSource{
		DockerID:  dockerID,
		FirstSeen: now,
		LastSeen:  now,
		LastEvent: event,
	}
	switch event {
	case llmEventRegister:
		src.Registers = 1
	case llmEventHeartbeat:
		src.Heartbeats = 1
	case llmEventLog:
		src.Logs = 1
	}
	s.state.Sources = append(s.state.Sources, src)
	s.sortSourcesLocked()
	if len(s.state.Sources) > maxLLMSources {
		s.state.Sources = s.state.Sources[:maxLLMSources]
	}
}

// sortSourcesLocked orders newest first. The dockerId is the tie-break so an
// equal timestamp cannot reshuffle the list between request and render.
func (s *llmStateStore) sortSourcesLocked() {
	sort.SliceStable(s.state.Sources, func(i, j int) bool {
		ti, tj := s.state.Sources[i], s.state.Sources[j]
		if ti.LastSeen != tj.LastSeen {
			return ti.LastSeen > tj.LastSeen
		}
		return ti.DockerID < tj.DockerID
	})
}

func (s *llmStateStore) reset() {
	s.mu.Lock()
	s.state = llmState{Sources: []llmSource{}}
	path := s.path
	s.mu.Unlock()
	if err := saveJSONFile(path, llmState{Sources: []llmSource{}}); err != nil {
		log.Printf("save llm state failed: %v", err)
	}
}
