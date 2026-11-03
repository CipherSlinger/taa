package taa

import (
	"context"
	"fmt"
	"log"
	"time"
)

// Platform registration is attempted once during startup, but in a Kata CSV2 guest
// that first attempt is always doomed: TAA is the guest's first userspace process,
// while the guest's network is configured by the host through the kata-agent, which
// taa-init only execs after TAA has reported its attestation verdict. The attempt
// therefore runs before the guest has an address and fails as a transport error.
// Retries continue until the platform answers, so a platform deployed after TAA
// still registers without a restart.
const (
	registerRetryInitialDelay = 5 * time.Second
	registerRetryMaxDelay     = 30 * time.Second
	// Zero means no window: retry until success or process shutdown. The loop is
	// unbounded on purpose so a platform that starts late is still reached, and
	// the failure log below is throttled because TAA's log lives on the guest's
	// tmpfs.
	registerRetryWindow = 0
)

// retryRegister calls attempt until it succeeds or ctx is cancelled. A positive
// window additionally gives up when the next sleep would land past that deadline.
// Delays double from initial up to max. Failures are logged at a throttled rate
// once the loop is clearly long-lived, and the last error is returned when a
// window expires.
//
// The caller rebuilds the same payload on every attempt -- including the startup
// timestamp -- so what the platform eventually stores stays consistent with the
// attestation report attached to it.
func retryRegister(ctx context.Context, initial, max, window time.Duration, attempt func(context.Context) error) error {
	var deadline time.Time
	if window > 0 {
		deadline = time.Now().Add(window)
	}
	delay := initial
	for n := 1; ; n++ {
		// Give up when the next sleep would land past the window, so the loop
		// cannot sleep past its own deadline.
		if window > 0 && time.Now().Add(delay).After(deadline) {
			return fmt.Errorf("register retry window of %s exhausted after %d attempts", window, n-1)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		if err := attempt(ctx); err == nil {
			if n > 1 {
				log.Printf("platform register succeeded on retry %d", n)
			}
			return nil
		} else if n <= 5 || n%20 == 0 {
			// Throttle a loop that may now run for days: the first few failures
			// stay visible, then one line every twenty attempts (about ten
			// minutes at the 30s ceiling) keeps the guest's tmpfs bounded.
			log.Printf("WARNING: platform register attempt %d failed: %v (retrying)", n, err)
		}
		delay *= 2
		if delay > max {
			delay = max
		}
	}
}
