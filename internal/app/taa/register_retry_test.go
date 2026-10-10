package taa

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestRetryRegisterSucceedsAfterTransientFailures covers the guest-network case:
// the first attempts fail, a later one succeeds, and the loop stops there.
func TestRetryRegisterSucceedsAfterTransientFailures(t *testing.T) {
	attempts := 0
	err := retryRegister(context.Background(), time.Millisecond, 2*time.Millisecond, time.Second,
		func(context.Context) error {
			attempts++
			if attempts < 3 {
				return errors.New("connect: network is unreachable")
			}
			return nil
		})
	if err != nil {
		t.Fatalf("expected the loop to succeed, got %v", err)
	}
	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
}

// TestRetryRegisterStopsAtTheWindow checks that an unreachable platform cannot keep
// the loop alive forever: it must report the window as exhausted.
func TestRetryRegisterStopsAtTheWindow(t *testing.T) {
	attempts := 0
	err := retryRegister(context.Background(), time.Millisecond, 2*time.Millisecond, 20*time.Millisecond,
		func(context.Context) error {
			attempts++
			return errors.New("connection refused")
		})
	if err == nil {
		t.Fatalf("expected an error once the window is exhausted")
	}
	if attempts == 0 {
		t.Fatalf("expected at least one attempt before giving up")
	}
}

// TestRetryRegisterHonoursContextCancellation checks that shutdown does not leave a
// retry sleeping until the next delay elapses.
func TestRetryRegisterHonoursContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := retryRegister(ctx, time.Second, time.Second, time.Minute, func(context.Context) error {
		t.Fatalf("attempt must not run on a cancelled context")
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
