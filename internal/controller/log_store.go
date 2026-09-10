package controller

import (
	"log"

	"taa/pkg/logger"
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
type LogLevel = logger.Level

const (
	LogInfo  = logger.LevelInfo
	LogWarn  = logger.LevelWarn
	LogError = logger.LevelError
)

// LogEntry is a single structured log record.
type LogEntry = logger.Entry

// LogStore is a thread-safe bounded log buffer backed by pkg/logger.Store.
type LogStore = logger.Store

// NewLogStore creates a log store with the given capacity.
func NewLogStore(maxSize int) *LogStore {
	return logger.NewStore(maxSize)
}

// PhaseSeparator prints a visual separator for phase transitions.
func PhaseSeparator(title string) {
	log.Printf("%s%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s", colorBold, colorCyan, colorReset)
	log.Printf("%s%s  %s  %s", colorBold, colorCyan, title, colorReset)
	log.Printf("%s%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s", colorBold, colorCyan, colorReset)
}

// StepSeparator prints a visual separator for step transitions within a phase.
func StepSeparator(title string) {
	log.Printf("%s%s── %s ──────────────────────────────────────────────────────────%s", colorDim, colorCyan, title, colorReset)
}
