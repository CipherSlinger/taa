package controller

import (
	"testing"
	"time"
)

func TestLogStoreAdd(t *testing.T) {
	ls := NewLogStore(10)
	ls.Add(LogInfo, "test", "hello %s", "world")

	entries := ls.All()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Level != LogInfo {
		t.Fatalf("level = %s, want info", entries[0].Level)
	}
	if entries[0].Component != "test" {
		t.Fatalf("component = %s, want test", entries[0].Component)
	}
	if entries[0].Message != "hello world" {
		t.Fatalf("message = %q, want %q", entries[0].Message, "hello world")
	}
}

func TestLogStoreDrain(t *testing.T) {
	ls := NewLogStore(10)
	ls.Add(LogInfo, "a", "msg1")
	ls.Add(LogWarn, "b", "msg2")

	entries := ls.Drain()
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	// Second drain should return nothing
	entries = ls.Drain()
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries after drain, got %d", len(entries))
	}

	// Add more and drain again
	ls.Add(LogError, "c", "msg3")
	entries = ls.Drain()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Level != LogError {
		t.Fatalf("level = %s, want error", entries[0].Level)
	}
}

func TestLogStoreSince(t *testing.T) {
	ls := NewLogStore(10)
	ls.Add(LogInfo, "a", "msg1")
	time.Sleep(10 * time.Millisecond)
	mid := time.Now().UTC()
	time.Sleep(10 * time.Millisecond)
	ls.Add(LogWarn, "b", "msg2")
	ls.Add(LogError, "c", "msg3")

	entries := ls.Since(mid)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries after mid, got %d", len(entries))
	}
	if entries[0].Message != "msg2" {
		t.Fatalf("first entry = %q, want msg2", entries[0].Message)
	}
}

func TestLogStoreOverflow(t *testing.T) {
	ls := NewLogStore(4)
	for i := 0; i < 10; i++ {
		ls.Add(LogInfo, "test", "msg%d", i)
	}

	entries := ls.All()
	if len(entries) > 4 {
		t.Fatalf("expected at most 4 entries, got %d", len(entries))
	}
	// Should have the most recent entries
	last := entries[len(entries)-1]
	if last.Message != "msg9" {
		t.Fatalf("last entry = %q, want msg9", last.Message)
	}
}

func TestLogStoreCount(t *testing.T) {
	ls := NewLogStore(10)
	if ls.Count() != 0 {
		t.Fatalf("count = %d, want 0", ls.Count())
	}
	ls.Add(LogInfo, "a", "msg1")
	ls.Add(LogInfo, "b", "msg2")
	if ls.Count() != 2 {
		t.Fatalf("count = %d, want 2", ls.Count())
	}
}
