// Package logger 提供通用的轻量级分级日志记录器与有界内存日志存储池（Ring Buffer），
// 支持终端 ANSI 彩色高亮、时间区间过滤及 JSON 序列化，完全独立于特定业务。
package logger

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// ANSI color escape codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

// Level 代表日志严重级别。
type Level string

const (
	LevelDebug Level = "debug"
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

// Entry 代表单条结构化日志记录。
type Entry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     Level     `json:"level"`
	Component string    `json:"component,omitempty"`
	Message   string    `json:"message"`
}

// Store 是一个线程安全的有界内存日志缓冲区（达到上限时自动淘汰最旧日志）。
type Store struct {
	mu      sync.RWMutex
	entries []Entry
	maxSize int
	stdout  bool
}

// StoreOption 配置 Store 行为。
type StoreOption func(*Store)

// WithStdout 设置是否在写入内存的同时同步打印到标准日志。
func WithStdout(enable bool) StoreOption {
	return func(s *Store) {
		s.stdout = enable
	}
}

// NewStore 创建一个指定最大容量的日志存储池。
func NewStore(maxSize int, opts ...StoreOption) *Store {
	if maxSize <= 0 {
		maxSize = 1000
	}
	s := &Store{
		entries: make([]Entry, 0, maxSize),
		maxSize: maxSize,
		stdout:  true,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Add 格式化并追加一条日志。
func (s *Store) Add(level Level, component, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	entry := Entry{
		Timestamp: time.Now().UTC(),
		Level:     level,
		Component: component,
		Message:   msg,
	}

	if s.stdout {
		switch level {
		case LevelError:
			log.Printf("%s%s[ERROR]%s %s[%s]%s %s", colorBold, colorRed, colorReset, colorDim, component, colorReset, msg)
		case LevelWarn:
			log.Printf("%s%s[WARN] %s %s[%s]%s %s", colorBold, colorYellow, colorReset, colorDim, component, colorReset, msg)
		case LevelDebug:
			log.Printf("%s[DEBUG]%s %s[%s]%s %s", colorCyan, colorReset, colorDim, component, colorReset, msg)
		default:
			log.Printf("%s[INFO] %s %s[%s]%s %s", colorGreen, colorReset, colorDim, component, colorReset, msg)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.entries) >= s.maxSize {
		// 丢弃最老的一条记录
		copy(s.entries, s.entries[1:])
		s.entries[len(s.entries)-1] = entry
	} else {
		s.entries = append(s.entries, entry)
	}
}

// Info 记录一条 Info 级别日志。
func (s *Store) Info(component, format string, args ...any) {
	s.Add(LevelInfo, component, format, args...)
}

// Warn 记录一条 Warn 级别日志。
func (s *Store) Warn(component, format string, args ...any) {
	s.Add(LevelWarn, component, format, args...)
}

// Error 记录一条 Error 级别日志。
func (s *Store) Error(component, format string, args ...any) {
	s.Add(LevelError, component, format, args...)
}

// Debug 记录一条 Debug 级别日志。
func (s *Store) Debug(component, format string, args ...any) {
	s.Add(LevelDebug, component, format, args...)
}

// Since 获取指定时间点之后的增量日志切片（不破坏缓冲区）。
func (s *Store) Since(t time.Time) []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]Entry, 0)
	for _, entry := range s.entries {
		if entry.Timestamp.After(t) {
			result = append(result, entry)
		}
	}
	return result
}

// All 返回当前缓冲区内的所有日志副本。
func (s *Store) All() []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]Entry, len(s.entries))
	copy(res, s.entries)
	return res
}

// Drain 清空并返回缓冲区内的所有日志记录。
func (s *Store) Drain() []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()

	res := s.entries
	s.entries = make([]Entry, 0, s.maxSize)
	return res
}

// Count 返回当前存储的日志总条数。
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// Clear 清空日志缓冲区。
func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = make([]Entry, 0, s.maxSize)
}
