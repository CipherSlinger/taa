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
	store := NewStore(3, WithStdout(false))

	store.Info("c", "1")
	store.Info("c", "2")
	store.Info("c", "3")
	store.Info("c", "4") // should drop "1"

	if store.Count() != 3 {
		t.Fatalf("expected count 3, got %d", store.Count())
	}

	all := store.All()
	if all[0].Message != "2" || all[1].Message != "3" || all[2].Message != "4" {
		t.Fatalf("unexpected entries: %+v", all)
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
	store := NewStore(5, WithStdout(false))
	store.Info("c", "1")
	store.Info("c", "2")

	drained := store.Drain()
	if len(drained) != 2 {
		t.Fatalf("expected 2 drained entries, got %d", len(drained))
	}
	if store.Count() != 0 {
		t.Fatalf("expected 0 count after drain, got %d", store.Count())
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
