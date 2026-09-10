// Package logger 提供通用的轻量级分级日志记录器与有界内存日志存储池（Ring Buffer），
// 支持终端 ANSI 彩色高亮、增量排空、二分时间过滤及 JSON 序列化，完全独立于特定业务。
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
	Component string    `json:"component"`
	Message   string    `json:"message"`
}

// Store 是一个线程安全的有界内存日志缓冲区（达到上限时自动淘汰最旧日志）。
type Store struct {
	mu      sync.Mutex
	entries []Entry
	maxSize int
	cursor  int // 下一次未读日志索引
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

	// 达到最大容量时淘汰较旧条目，并校准 cursor
	if len(s.entries) >= s.maxSize {
		drop := s.maxSize / 2
		if drop <= 0 {
			drop = 1
		}
		if drop > len(s.entries) {
			drop = len(s.entries)
		}
		s.entries = s.entries[drop:]
		if s.cursor >= drop {
			s.cursor -= drop
		} else {
			s.cursor = 0
		}
	}

	s.entries = append(s.entries, entry)
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

// Drain 返回自上一次 Drain 以来所有未读的增量日志，并推进内部已读游标。
func (s *Store) Drain() []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cursor >= len(s.entries) {
		return nil
	}
	result := make([]Entry, len(s.entries)-s.cursor)
	copy(result, s.entries[s.cursor:])
	s.cursor = len(s.entries)
	return result
}

// Since 二分查找并返回给定时间戳之后的所有日志切片副本。
func (s *Store) Since(t time.Time) []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()

	lo, hi := 0, len(s.entries)
	for lo < hi {
		mid := (lo + hi) / 2
		if s.entries[mid].Timestamp.Before(t) || s.entries[mid].Timestamp.Equal(t) {
			lo = mid + 1
		} else {
			hi = mid
		}
	}

	if lo >= len(s.entries) {
		return nil
	}
	result := make([]Entry, len(s.entries)-lo)
	copy(result, s.entries[lo:])
	return result
}

// All 返回当前缓冲区内的所有日志副本。
func (s *Store) All() []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()

	res := make([]Entry, len(s.entries))
	copy(res, s.entries)
	return res
}

// Count 返回当前存储的日志总条数。
func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// Clear 清空日志缓冲区并重置游标。
func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = make([]Entry, 0, s.maxSize)
	s.cursor = 0
}
