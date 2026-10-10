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
// These settings retry it in the background until the sandbox network is up.
const (
	registerRetryInitialDelay = 5 * time.Second
	registerRetryMaxDelay     = 30 * time.Second
	// Bounded on purpose. TAA's log lives on the guest's tmpfs and every attempt
	// dumps the full registration payload (attestation report included), so an
	// unbounded loop would grow the guest's RAM forever if the platform is down.
	// Minutes is generous: the network is up seconds after the sandbox is created.
	registerRetryWindow = 5 * time.Minute
)

// retryRegister calls attempt until it succeeds, the window runs out, or ctx is
// cancelled. Delays double from initial up to max. Every failure is logged and the
// final one is returned, so the caller can report that the retries are over.
//
// The caller rebuilds the same payload on every attempt -- including the startup
// timestamp -- so what the platform eventually stores stays consistent with the
// attestation report attached to it.
func retryRegister(ctx context.Context, initial, max, window time.Duration, attempt func(context.Context) error) error {
	deadline := time.Now().Add(window)
	delay := initial
	for n := 1; ; n++ {
		// Give up when the next sleep would land past the window, so the loop
		// cannot sleep past its own deadline.
		if time.Now().Add(delay).After(deadline) {
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
		} else {
			log.Printf("WARNING: platform register attempt %d failed: %v", n, err)
		}
		delay *= 2
		if delay > max {
			delay = max
		}
	}
}
