package inference_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"taa/internal/inference"
)

func TestCircuitBreaker_Defaults(t *testing.T) {
	cb := inference.NewCircuitBreaker(0, 0)
	if cb.State() != inference.StateClosed {
		t.Fatalf("expected default state StateClosed, got %v", cb.State())
	}
	if !cb.Allow() {
		t.Fatal("expected newly created circuit breaker to allow requests")
	}
}

func TestCircuitBreaker_StateString(t *testing.T) {
	tests := []struct {
		state    inference.State
		expected string
	}{
		{inference.StateClosed, "CLOSED"},
		{inference.StateOpen, "OPEN"},
		{inference.StateHalfOpen, "HALF-OPEN"},
		{inference.State(99), "State(99)"},
	}

	for _, tt := range tests {
		if tt.state.String() != tt.expected {
			t.Errorf("expected string representation %q, got %q", tt.expected, tt.state.String())
		}
	}
}

func TestCircuitBreaker_StateTransitions(t *testing.T) {
	cooldown := 50 * time.Millisecond
	cb := inference.NewCircuitBreaker(3, cooldown)

	// Initially CLOSED
	if cb.State() != inference.StateClosed {
		t.Fatalf("expected StateClosed, got %v", cb.State())
	}
	if !cb.Allow() {
		t.Fatal("expected circuit breaker to be CLOSED and allow requests")
	}

	// 1st failure - still closed
	cb.RecordFailure()
	if cb.State() != inference.StateClosed {
		t.Fatalf("expected StateClosed after 1 failure, got %v", cb.State())
	}
	if !cb.Allow() {
		t.Fatal("expected circuit breaker to allow requests after 1 failure")
	}

	// 2nd failure - still closed
	cb.RecordFailure()
	if cb.State() != inference.StateClosed {
		t.Fatalf("expected StateClosed after 2 failures, got %v", cb.State())
	}
	if !cb.Allow() {
		t.Fatal("expected circuit breaker to allow requests after 2 failures")
	}

	// 3rd failure - transitions to OPEN
	cb.RecordFailure()
	if cb.State() != inference.StateOpen {
		t.Fatalf("expected StateOpen after 3 failures, got %v", cb.State())
	}
	if cb.Allow() {
		t.Fatal("expected circuit breaker to be OPEN and reject requests")
	}

	// Wait for cooldown to expire
	time.Sleep(cooldown + 10*time.Millisecond)

	// State() should report StateHalfOpen after cooldown
	if cb.State() != inference.StateHalfOpen {
		t.Fatalf("expected StateHalfOpen after cooldown, got %v", cb.State())
	}

	// Allow() should return true and transition state to StateHalfOpen
	if !cb.Allow() {
		t.Fatal("expected circuit breaker to allow probe in HALF-OPEN")
	}
	if cb.State() != inference.StateHalfOpen {
		t.Fatalf("expected StateHalfOpen, got %v", cb.State())
	}

	// Probe success -> transitions back to CLOSED
	cb.RecordSuccess()
	if cb.State() != inference.StateClosed {
		t.Fatalf("expected StateClosed after RecordSuccess, got %v", cb.State())
	}
	if !cb.Allow() {
		t.Fatal("expected circuit breaker to be CLOSED and allow requests after successful probe")
	}
}

func TestCircuitBreaker_HalfOpenFailure(t *testing.T) {
	cooldown := 30 * time.Millisecond
	cb := inference.NewCircuitBreaker(3, cooldown)

	// Trip to OPEN
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordFailure()

	if cb.Allow() {
		t.Fatal("expected circuit breaker to be OPEN")
	}

	// Wait for cooldown
	time.Sleep(cooldown + 10*time.Millisecond)

	// Allow probe -> HALF-OPEN
	if !cb.Allow() {
		t.Fatal("expected circuit breaker to allow probe in HALF-OPEN")
	}
	if cb.State() != inference.StateHalfOpen {
		t.Fatalf("expected StateHalfOpen, got %v", cb.State())
	}

	// Probe fails -> must immediately transition to OPEN
	cb.RecordFailure()
	if cb.State() != inference.StateOpen {
		t.Fatalf("expected immediate transition to StateOpen upon failure in HALF-OPEN, got %v", cb.State())
	}
	if cb.Allow() {
		t.Fatal("expected circuit breaker to reject requests after failing in HALF-OPEN")
	}
}

func TestExecuteWithRetry_Success(t *testing.T) {
	attempts := 0
	op := func() error {
		attempts++
		if attempts < 2 {
			return inference.ErrRetryable
		}
		return nil
	}

	err := inference.ExecuteWithRetry(op, 2, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("expected retry to succeed, got: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("expected 2 attempts, got %d", attempts)
	}
}

func TestExecuteWithRetry_ImmediateSuccess(t *testing.T) {
	attempts := 0
	op := func() error {
		attempts++
		return nil
	}

	err := inference.ExecuteWithRetry(op, 3, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("expected immediate success, got: %v", err)
	}
	if attempts != 1 {
		t.Fatalf("expected exactly 1 attempt, got %d", attempts)
	}
}

func TestExecuteWithRetry_NonRetryable(t *testing.T) {
	attempts := 0
	fatalErr := errors.New("fatal client error")
	op := func() error {
		attempts++
		return fatalErr
	}

	err := inference.ExecuteWithRetry(op, 3, 5*time.Millisecond)
	if err == nil {
		t.Fatal("expected non-retryable error to fail immediately")
	}
	if !errors.Is(err, fatalErr) {
		t.Fatalf("expected fatal error %v, got %v", fatalErr, err)
	}
	if attempts != 1 {
		t.Fatalf("expected exactly 1 attempt for fatal error, got %d", attempts)
	}
}

func TestExecuteWithRetry_MaxRetriesExceeded(t *testing.T) {
	attempts := 0
	op := func() error {
		attempts++
		return inference.ErrRetryable
	}

	maxRetries := 3
	err := inference.ExecuteWithRetry(op, maxRetries, 5*time.Millisecond)
	if err == nil {
		t.Fatal("expected error when max retries exceeded, got nil")
	}
	if !errors.Is(err, inference.ErrRetryable) {
		t.Fatalf("expected ErrRetryable, got: %v", err)
	}
	// Initial attempt + 3 retries = 4 attempts total
	expectedAttempts := maxRetries + 1
	if attempts != expectedAttempts {
		t.Fatalf("expected %d attempts, got %d", expectedAttempts, attempts)
	}
}

func TestExecuteWithRetry_NegativeRetries(t *testing.T) {
	attempts := 0
	op := func() error {
		attempts++
		return inference.ErrRetryable
	}

	err := inference.ExecuteWithRetry(op, -1, 5*time.Millisecond)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if attempts != 1 {
		t.Fatalf("expected exactly 1 attempt when maxRetries < 0, got %d", attempts)
	}
}

func TestCircuitBreaker_Concurrency(t *testing.T) {
	cb := inference.NewCircuitBreaker(5, 50*time.Millisecond)

	var wg sync.WaitGroup
	workers := 20
	iterations := 100

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				switch (workerID + j) % 4 {
				case 0:
					_ = cb.Allow()
				case 1:
					cb.RecordFailure()
				case 2:
					cb.RecordSuccess()
				case 3:
					_ = cb.State()
				}
			}
		}(i)
	}

	wg.Wait()
}

func TestCircuitBreaker_HalfOpenSingleProbe(t *testing.T) {
	cooldown := 30 * time.Millisecond
	cb := inference.NewCircuitBreaker(1, cooldown)

	// Trip breaker to OPEN
	cb.RecordFailure()
	if cb.Allow() {
		t.Fatal("expected breaker to be OPEN")
	}

	// Wait for cooldown
	time.Sleep(cooldown + 10*time.Millisecond)

	// First call in half-open state should succeed as probe
	if !cb.Allow() {
		t.Fatal("expected first Allow() in half-open state to return true")
	}

	// Second sequential call while probe is active should be rejected
	if cb.Allow() {
		t.Fatal("expected second Allow() while probe is active to return false")
	}
}

func TestCircuitBreaker_HalfOpenConcurrentProbes(t *testing.T) {
	cooldown := 30 * time.Millisecond
	cb := inference.NewCircuitBreaker(1, cooldown)

	// Trip breaker to OPEN
	cb.RecordFailure()
	time.Sleep(cooldown + 10*time.Millisecond)

	// Concurrently invoke Allow() from multiple goroutines
	numGoroutines := 30
	var wg sync.WaitGroup
	var allowedCount atomic.Int32

	start := make(chan struct{})
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if cb.Allow() {
				allowedCount.Add(1)
			}
		}()
	}

	close(start)
	wg.Wait()

	if allowedCount.Load() != 1 {
		t.Fatalf("expected exactly 1 probe to be allowed in half-open state, got %d", allowedCount.Load())
	}
}

func TestCircuitBreaker_ProbeFailure(t *testing.T) {
	cooldown := 30 * time.Millisecond
	cb := inference.NewCircuitBreaker(1, cooldown)

	cb.RecordFailure()
	time.Sleep(cooldown + 10*time.Millisecond)

	// Allow probe
	if !cb.Allow() {
		t.Fatal("expected probe to be allowed")
	}

	// Probe fails -> StateOpen and probeActive must be cleared
	cb.RecordFailure()
	if cb.State() != inference.StateOpen {
		t.Fatalf("expected StateOpen after probe failure, got %v", cb.State())
	}
	if cb.Allow() {
		t.Fatal("expected Allow() to return false immediately after probe failure")
	}

	// Wait for cooldown again -> probe should be permitted again
	time.Sleep(cooldown + 10*time.Millisecond)
	if !cb.Allow() {
		t.Fatal("expected new probe to be allowed after second cooldown")
	}
}

func TestCircuitBreaker_ProbeSuccess(t *testing.T) {
	cooldown := 30 * time.Millisecond
	cb := inference.NewCircuitBreaker(1, cooldown)

	cb.RecordFailure()
	time.Sleep(cooldown + 10*time.Millisecond)

	if !cb.Allow() {
		t.Fatal("expected probe to be allowed")
	}
	if cb.Allow() {
		t.Fatal("expected second call while probe active to return false")
	}

	// Probe succeeds -> transitions to StateClosed, clears probeActive
	cb.RecordSuccess()
	if cb.State() != inference.StateClosed {
		t.Fatalf("expected StateClosed after probe success, got %v", cb.State())
	}

	// In StateClosed, multiple calls to Allow() must all return true
	for i := 0; i < 5; i++ {
		if !cb.Allow() {
			t.Fatalf("expected Allow() to return true in StateClosed on call %d", i+1)
		}
	}
}

func TestCircuitBreaker_RecordSuccess_ResetsFailCount(t *testing.T) {
	cb := inference.NewCircuitBreaker(3, 100*time.Millisecond)

	// 2 failures (threshold is 3, so breaker remains closed)
	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != inference.StateClosed {
		t.Fatalf("expected StateClosed after 2 failures, got %v", cb.State())
	}

	// Reset via RecordSuccess in StateClosed
	cb.RecordSuccess()
	if cb.State() != inference.StateClosed {
		t.Fatalf("expected StateClosed after RecordSuccess, got %v", cb.State())
	}

	// Another 2 failures; if failCount was reset, breaker remains closed (2 < 3)
	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != inference.StateClosed {
		t.Fatalf("expected StateClosed because failCount was reset, got %v", cb.State())
	}

	// 3rd failure trips the breaker to StateOpen
	cb.RecordFailure()
	if cb.State() != inference.StateOpen {
		t.Fatalf("expected StateOpen after 3rd failure post-reset, got %v", cb.State())
	}
}

func TestExecuteWithRetryContext_PreCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	attempts := 0
	op := func() error {
		attempts++
		return nil
	}

	err := inference.ExecuteWithRetryContext(ctx, op, 3, 10*time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if attempts != 0 {
		t.Fatalf("expected 0 attempts for pre-cancelled context, got %d", attempts)
	}
}

func TestExecuteWithRetryContext_CancelledDuringSleep(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	attempts := 0
	op := func() error {
		attempts++
		if attempts == 1 {
			// Cancel context shortly after first failure
			go func() {
				time.Sleep(10 * time.Millisecond)
				cancel()
			}()
			return inference.ErrRetryable
		}
		return nil
	}

	start := time.Now()
	// baseDelay is set high (500ms), but cancellation should interrupt sleep promptly
	err := inference.ExecuteWithRetryContext(ctx, op, 3, 500*time.Millisecond)
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if elapsed >= 300*time.Millisecond {
		t.Fatalf("expected cancellation to interrupt sleep quickly, but took %v", elapsed)
	}
	if attempts != 1 {
		t.Fatalf("expected 1 attempt before cancel, got %d", attempts)
	}
}

func TestExecuteWithRetryContext_ContextErrorFromOp(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0
	op := func() error {
		attempts++
		cancel()
		return ctx.Err()
	}

	err := inference.ExecuteWithRetryContext(ctx, op, 3, 10*time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if attempts != 1 {
		t.Fatalf("expected exactly 1 attempt when op returns ctx.Err(), got %d", attempts)
	}
}

func TestExecuteWithRetryContext_SafeDefaultBaseDelay(t *testing.T) {
	attempts := 0
	op := func() error {
		attempts++
		if attempts < 2 {
			return inference.ErrRetryable
		}
		return nil
	}

	// baseDelay <= 0 should safely default to 100ms
	start := time.Now()
	err := inference.ExecuteWithRetryContext(context.Background(), op, 2, 0)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if attempts != 2 {
		t.Fatalf("expected 2 attempts, got %d", attempts)
	}
	if elapsed < 50*time.Millisecond {
		t.Fatalf("expected non-zero sleep duration from safe default baseDelay, elapsed: %v", elapsed)
	}
}
