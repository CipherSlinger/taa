package logger

import (
	"sync"
	"testing"
	"time"
)

func TestStoreBasics(t *testing.T) {
	store := NewStore(5, WithStdout(false))

	store.Info("test", "msg 1")
	store.Warn("test", "msg 2")
	store.Error("test", "msg 3")

	if store.Count() != 3 {
		t.Fatalf("expected count 3, got %d", store.Count())
	}

	all := store.All()
	if len(all) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(all))
	}
	if all[0].Message != "msg 1" || all[0].Level != LevelInfo {
		t.Fatalf("unexpected entry: %+v", all[0])
	}
}

func TestStoreOverflow(t *testing.T) {
	store := NewStore(4, WithStdout(false))

	for i := 0; i < 10; i++ {
		store.Info("test", "msg%d", i)
	}

	entries := store.All()
	if len(entries) > 4 {
		t.Fatalf("expected at most 4 entries, got %d", len(entries))
	}
	last := entries[len(entries)-1]
	if last.Message != "msg9" {
		t.Fatalf("last entry = %q, want msg9", last.Message)
	}
}

func TestStoreSince(t *testing.T) {
	store := NewStore(10, WithStdout(false))

	store.Info("c", "old")
	time.Sleep(10 * time.Millisecond)
	mid := time.Now().UTC()
	time.Sleep(10 * time.Millisecond)
	store.Info("c", "new")

	since := store.Since(mid)
	if len(since) != 1 {
		t.Fatalf("expected 1 entry since mid, got %d", len(since))
	}
	if since[0].Message != "new" {
		t.Fatalf("expected 'new', got '%s'", since[0].Message)
	}
}

func TestStoreDrain(t *testing.T) {
	store := NewStore(10, WithStdout(false))
	store.Info("a", "msg1")
	store.Warn("b", "msg2")

	entries := store.Drain()
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	// Second drain should return nothing
	entries = store.Drain()
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries after drain, got %d", len(entries))
	}

	// Add more and drain again
	store.Error("c", "msg3")
	entries = store.Drain()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Level != LevelError {
		t.Fatalf("level = %s, want error", entries[0].Level)
	}
}

func TestStoreConcurrency(t *testing.T) {
	store := NewStore(100, WithStdout(false))
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				store.Info("worker", "worker %d iteration %d", id, j)
			}
		}(i)
	}

	wg.Wait()
	if store.Count() > 100 {
		t.Fatalf("count exceeded max size: %d", store.Count())
	}
}
