package taa

import (
	"context"
	"log"
	"time"

	"taa/internal/config"
	"taa/internal/store"
)

// Startup gates for every role except fhe.
//
// Instance types 1-3 (tee training, tee inference, data analysis) run inside
// the CSV guest and must prove themselves before the platform is told about
// them. /dev/csv-guest is not part of the base image: in a Kata CSV2 Pod a
// postStart hook creates the node, which races TAA as the container's first
// process. A missing node therefore does not mean "not a CSV guest" -- it can
// mean "not yet" -- and these roles never fall back to the empty report that an
// fhe instance registers with. They wait, without a window, until the node is
// present and a report can be generated and self-verified, and register only
// then. An fhe instance (type 4) is not a TEE and keeps registering immediately.
//
// The same race decides where the state sealing key comes from, so those roles
// wait for the node before choosing that source as well (see
// awaitStateSealingKeySource). Choosing early would seal the state with the
// SM2-derived key on a boot that merely lost the race, and the next boot would
// then archive that state as drifted once csv-hw wins.
const (
	attestationWaitInitialDelay = 5 * time.Second
	attestationWaitMaxDelay     = 30 * time.Second
)

// registerInstance applies the role's registration policy. For fhe the first
// attempt runs here, on the startup path, and the background retry keeps that
// attempt's verdict. For every other role nothing is sent until
// awaitAttestation reports success, after which the first attempt and the
// retry both carry verifiedPass=true.
func registerInstance(
	ctx context.Context,
	serverType string,
	register func(ctx context.Context, verifiedPass bool) error,
	awaitAttestation func(ctx context.Context) bool,
) {
	if serverType == config.ServerTypeFHE {
		registerWithRetry(ctx, func(attemptCtx context.Context) error {
			return register(attemptCtx, false)
		})
		return
	}

	go func() {
		if !awaitAttestation(ctx) {
			return
		}
		registerWithRetry(ctx, func(attemptCtx context.Context) error {
			return register(attemptCtx, true)
		})
	}()
}

// registerWithRetry makes one attempt now and retries in the background until
// the platform answers or the process stops.
func registerWithRetry(ctx context.Context, attempt func(context.Context) error) {
	if err := attempt(ctx); err != nil {
		log.Printf("[WARN] [register] platform register failed, continuing startup: %v", err)
		go func() {
			err := retryRegister(ctx, registerRetryInitialDelay, registerRetryMaxDelay, registerRetryWindow, attempt)
			if err != nil {
				log.Printf("[WARN] [register] platform register retries gave up: %v", err)
			}
		}()
		return
	}
	log.Printf("[INFO] [register] platform register completed")
}

// waitForAttestation blocks until devicePath exists and attest reports a
// verified report, polling with the given backoff. There is no attempt limit:
// it returns false only when ctx is cancelled first. Failures are logged at a
// throttled rate because the loop may run for the lifetime of a misconfigured
// guest.
func waitForAttestation(
	ctx context.Context,
	devicePath string,
	attest func(context.Context) (bool, error),
	initialDelay, maxDelay time.Duration,
) bool {
	return pollUntil(ctx, initialDelay, maxDelay, func(attempt int) bool {
		if detectStateSealingKeySource(devicePath) == store.KeySourceCSVHW {
			verified, err := attest(ctx)
			if verified {
				log.Printf("[INFO] [attestation] %s is usable and the report self-verified; registering with the platform", devicePath)
				return true
			}
			if attempt <= 5 || attempt%20 == 0 {
				if err != nil {
					log.Printf("[WARN] [attestation] attempt %d failed: %v (retrying, no limit)", attempt, err)
				} else {
					log.Printf("[WARN] [attestation] attempt %d produced no verified report (retrying, no limit)", attempt)
				}
			}
		} else if attempt <= 5 || attempt%20 == 0 {
			log.Printf("[INFO] [attestation] %s is not available yet; not registering (attempt %d, retrying, no limit)", devicePath, attempt)
		}
		return false
	})
}

// waitForCSVDevice blocks until devicePath exists, with the same backoff and
// the same absence of an attempt limit as waitForAttestation. It is used before
// the state sealing key source is chosen.
func waitForCSVDevice(ctx context.Context, devicePath string, initialDelay, maxDelay time.Duration) bool {
	return pollUntil(ctx, initialDelay, maxDelay, func(attempt int) bool {
		if detectStateSealingKeySource(devicePath) == store.KeySourceCSVHW {
			log.Printf("[INFO] [sealing] %s is available; the state sealing key comes from the CSV hardware", devicePath)
			return true
		}
		if attempt <= 5 || attempt%20 == 0 {
			log.Printf("[INFO] [sealing] %s is not available yet; waiting before choosing the state sealing key (attempt %d, retrying, no limit)", devicePath, attempt)
		}
		return false
	})
}

// awaitStateSealingKeySource picks the state sealing key source for this
// startup. Instance types 1-3 wait for /dev/csv-guest first, without a window,
// so a boot that lost the postStart race still seals with csv-hw instead of
// briefly using the SM2-derived key and forcing a key-drift archive on the next
// boot. An fhe instance is not a CSV guest: it never waits and keeps the
// immediate detection (which yields the SM2-derived key).
func awaitStateSealingKeySource(ctx context.Context, serverType, devicePath string) (store.KeySource, error) {
	if serverType != config.ServerTypeFHE {
		if !waitForCSVDevice(ctx, devicePath, attestationWaitInitialDelay, attestationWaitMaxDelay) {
			return "", ctx.Err()
		}
	}

	source := detectStateSealingKeySource(devicePath)
	if source == store.KeySourceSM2 {
		log.Printf("CSV guest device %s not found; sealing persistent state with the SM2-derived key", devicePath)
	}
	return source, nil
}

// pollUntil calls check with exponential backoff until it reports true. There
// is no attempt limit: it returns false only when ctx is cancelled first.
func pollUntil(ctx context.Context, initialDelay, maxDelay time.Duration, check func(attempt int) bool) bool {
	delay := initialDelay
	for attempt := 1; ; attempt++ {
		if check(attempt) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(delay):
		}
		delay *= 2
		if delay > maxDelay {
			delay = maxDelay
		}
	}
}
