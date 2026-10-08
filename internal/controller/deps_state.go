package controller

import (
	"path/filepath"
	"strings"
)

// saveDepsSuccess records a successful dependency import: sets the flag, records the
// content-address hash and checksum, and seals the state to disk.
// It takes ownership of checksum; the caller must not mutate it afterwards.
func (s *TAAState) saveDepsSuccess(hash string, checksum map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.DepsImported = true
	s.DepsHash = hash
	s.DepsChecksum = checksum
	if err := s.sealStateLocked(); err != nil {
		s.Logs.Add(LogError, "state", "failed to persist dependency import state: %v", err)
	}
}

// clearDepsState rolls the dependency state back (called on import failure or a failed audit).
func (s *TAAState) clearDepsState() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.DepsImported = false
	s.DepsHash = ""
	s.DepsChecksum = nil
	if err := s.sealStateLocked(); err != nil {
		s.Logs.Add(LogError, "state", "failed to persist dependency state rollback: %v", err)
	}
}

// getDepsChecksum returns a snapshot of the dependency checksum so callers never hold
// the internal map.
func (s *TAAState) getDepsChecksum() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.DepsChecksum == nil {
		return nil
	}
	out := make(map[string]any, len(s.DepsChecksum))
	for k, v := range s.DepsChecksum {
		out[k] = v
	}
	return out
}

// currentDepsDir returns the directory of the active dependency installation, or an
// empty string when none is imported.
//
// The empty string is the signal meaning "inject nothing into the training environment",
// so this must remain the only predicate for that decision.
func (s *TAAState) currentDepsDir() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.DepsImported || strings.TrimSpace(s.DepsHash) == "" {
		return ""
	}
	return filepath.Join(s.Security.GetDepsDir(), s.DepsHash)
}

// depsDirForHash returns the content-addressed directory for any hash, including
// historical versions that are not currently active (also used to address historical versions for rollback and cleanup).
func (s *TAAState) depsDirForHash(hash string) string {
	return filepath.Join(s.Security.GetDepsDir(), hash)
}
