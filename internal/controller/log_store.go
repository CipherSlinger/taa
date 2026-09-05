package controller

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

// LogLevel represents the severity of a log entry.
type LogLevel string

const (
	LogInfo  LogLevel = "info"
	LogWarn  LogLevel = "warn"
	LogError LogLevel = "error"
)

// LogEntry is a single structured log record.
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     LogLevel  `json:"level"`
	Component string    `json:"component"`
	Message   string    `json:"message"`
}

// LogStore is a thread-safe bounded log buffer.
type LogStore struct {
	mu      sync.Mutex
	entries []LogEntry
	maxSize int
	cursor  int // index of the next unread entry
}

// NewLogStore creates a log store with the given capacity.
func NewLogStore(maxSize int) *LogStore {
	if maxSize <= 0 {
		maxSize = 1000
	}
	return &LogStore{
		entries: make([]LogEntry, 0, maxSize),
		maxSize: maxSize,
	}
}

// Add appends a log entry. If the buffer is full, the oldest entries are discarded.
// Also writes to standard log for backward compatibility.
func (ls *LogStore) Add(level LogLevel, component, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	entry := LogEntry{
		Timestamp: time.Now().UTC(),
		Level:     level,
		Component: component,
		Message:   msg,
	}

	// Write to standard log with colors
	switch level {
	case LogError:
		log.Printf("%s%s[ERROR]%s %s[%s]%s %s", colorBold, colorRed, colorReset, colorDim, component, colorReset, msg)
	case LogWarn:
		log.Printf("%s%s[WARN] %s %s[%s]%s %s", colorBold, colorYellow, colorReset, colorDim, component, colorReset, msg)
	default:
		log.Printf("%s[INFO] %s %s[%s]%s %s", colorGreen, colorReset, colorDim, component, colorReset, msg)
	}

	ls.mu.Lock()
	defer ls.mu.Unlock()

	// If full, drop oldest half
	if len(ls.entries) >= ls.maxSize {
		drop := ls.maxSize / 2
		if drop > len(ls.entries) {
			drop = len(ls.entries)
		}
		ls.entries = ls.entries[drop:]
		if ls.cursor >= drop {
			ls.cursor -= drop
		} else {
			ls.cursor = 0
		}
	}

	ls.entries = append(ls.entries, entry)
}

// Drain returns all log entries since the last Drain call and advances the cursor.
func (ls *LogStore) Drain() []LogEntry {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	if ls.cursor >= len(ls.entries) {
		return nil
	}
	result := make([]LogEntry, len(ls.entries)-ls.cursor)
	copy(result, ls.entries[ls.cursor:])
	ls.cursor = len(ls.entries)
	return result
}

// Since returns all log entries after the given timestamp.
func (ls *LogStore) Since(t time.Time) []LogEntry {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	// Binary search for the first entry after t
	lo, hi := 0, len(ls.entries)
	for lo < hi {
		mid := (lo + hi) / 2
		if ls.entries[mid].Timestamp.Before(t) || ls.entries[mid].Timestamp.Equal(t) {
			lo = mid + 1
		} else {
			hi = mid
		}
	}

	if lo >= len(ls.entries) {
		return nil
	}
	result := make([]LogEntry, len(ls.entries)-lo)
	copy(result, ls.entries[lo:])
	return result
}

// All returns a copy of all log entries.
func (ls *LogStore) All() []LogEntry {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	result := make([]LogEntry, len(ls.entries))
	copy(result, ls.entries)
	return result
}

// Count returns the total number of log entries.
func (ls *LogStore) Count() int {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return len(ls.entries)
}

// PhaseSeparator prints a visual separator for phase transitions.
func PhaseSeparator(title string) {
	log.Printf("%s%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s", colorBold, colorCyan, colorReset)
	log.Printf("%s%s  %s  %s", colorBold, colorCyan, title, colorReset)
	log.Printf("%s%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s", colorBold, colorCyan, colorReset)
}

// StepSeparator prints a visual separator for step transitions within a phase.
func StepSeparator(title string) {
	log.Printf("%s── %s%s%s ──%s", colorDim, colorBold, title, colorReset, colorReset)
}
