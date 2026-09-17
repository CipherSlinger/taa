package inference

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"
)

// ErrRetryable indicates a transient failure that can be retried.
var ErrRetryable = errors.New("transient retryable error")

// ErrCircuitOpen is returned when requests are rejected by an open circuit breaker.
var ErrCircuitOpen = errors.New("circuit breaker is OPEN: inference service is unavailable")

// State represents the circuit breaker operational state.
type State int

const (
	// StateClosed allows all requests to pass through normally.
	StateClosed State = iota
	// StateOpen rejects requests immediately without calling the backend.
	StateOpen
	// StateHalfOpen allows a limited probe request to test backend availability.
	StateHalfOpen
)

// String returns a human-readable representation of the circuit breaker state.
func (s State) String() string {
	switch s {
	case StateClosed:
		return "CLOSED"
	case StateOpen:
		return "OPEN"
	case StateHalfOpen:
		return "HALF-OPEN"
	default:
		return fmt.Sprintf("State(%d)", s)
	}
}

// CircuitBreaker guards against cascading failures when inference backends degrade.
type CircuitBreaker struct {
	mu           sync.Mutex
	state        State
	failCount    int
	threshold    int
	cooldown     time.Duration
	lastFailTime time.Time
	probeActive  bool
}

// NewCircuitBreaker constructs a CircuitBreaker instance.
// If threshold <= 0, it defaults to 3.
// If cooldown <= 0, it defaults to 30 seconds.
func NewCircuitBreaker(threshold int, cooldown time.Duration) *CircuitBreaker {
	if threshold <= 0 {
		threshold = 3
	}
	if cooldown <= 0 {
		cooldown = 30 * time.Second
	}
	return &CircuitBreaker{
		threshold: threshold,
		cooldown:  cooldown,
		state:     StateClosed,
	}
}

// Allow reports whether a new request is permitted to proceed.
// In StateClosed: returns true.
// In StateOpen: transitions to StateHalfOpen, activates probe, and returns true if cooldown elapsed; otherwise returns false.
// In StateHalfOpen: allows only one active probe request at a time, returning false if a probe is already in flight.
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()
	switch cb.state {
	case StateClosed:
		return true
	case StateOpen:
		if now.Sub(cb.lastFailTime) > cb.cooldown {
			cb.state = StateHalfOpen
			cb.probeActive = true
			return true
		}
		return false
	case StateHalfOpen:
		if !cb.probeActive {
			cb.probeActive = true
			return true
		}
		return false
	default:
		return true
	}
}

// RecordSuccess resets the failure count and transitions the circuit breaker back to StateClosed.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failCount = 0
	cb.state = StateClosed
	cb.probeActive = false
}

// RecordFailure increments failure counts and opens the circuit breaker if the threshold is reached or in StateHalfOpen.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.probeActive = false
	cb.failCount++
	cb.lastFailTime = time.Now()
	if cb.state == StateHalfOpen || cb.failCount >= cb.threshold {
		cb.state = StateOpen
	}
}

// State returns the current operational state in a thread-safe manner.
// If state is StateOpen and cooldown elapsed, it returns StateHalfOpen.
func (cb *CircuitBreaker) State() State {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == StateOpen && time.Since(cb.lastFailTime) > cb.cooldown {
		return StateHalfOpen
	}
	return cb.state
}

// ExecuteWithRetryContext executes an operation with context cancellation awareness,
// exponential backoff, and jitter for retryable errors.
func ExecuteWithRetryContext(ctx context.Context, op func() error, maxRetries int, baseDelay time.Duration) error {
	if maxRetries < 0 {
		maxRetries = 0
	}
	if baseDelay <= 0 {
		baseDelay = 100 * time.Millisecond
	}

	var err error
	delay := baseDelay
	if delay > 5*time.Second {
		delay = 5 * time.Second
	}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if ctx != nil && ctx.Err() != nil {
			return ctx.Err()
		}

		err = op()
		if err == nil {
			return nil
		}

		// Non-retryable or context error from op should abort retry loop immediately.
		if !errors.Is(err, ErrRetryable) || (ctx != nil && errors.Is(err, ctx.Err())) {
			return err
		}

		// Break when retry attempts are exhausted.
		if attempt == maxRetries {
			break
		}

		// Apply jittered exponential backoff (0.8x to 1.2x delay).
		jitter := float64(delay) * (0.8 + 0.4*rand.Float64())
		sleepDuration := time.Duration(jitter)
		if sleepDuration > 5*time.Second {
			sleepDuration = 5 * time.Second
		}

		if ctx != nil {
			timer := time.NewTimer(sleepDuration)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		} else {
			time.Sleep(sleepDuration)
		}

		delay *= 2
		if delay > 5*time.Second {
			delay = 5 * time.Second
		}
	}

	return err
}

// ExecuteWithRetry executes an operation with exponential backoff and jitter for retryable errors.
func ExecuteWithRetry(op func() error, maxRetries int, baseDelay time.Duration) error {
	return ExecuteWithRetryContext(context.Background(), op, maxRetries, baseDelay)
}
