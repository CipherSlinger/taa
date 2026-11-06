package taa

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"taa/internal/config"
	"taa/internal/store"
)

func touchDevice(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create device node stand-in %s: %v", path, err)
	}
}

// TestWaitForAttestationReturnsOnVerifiedReport pins the gate's success path:
// a present device plus a verified report ends the wait on the first check.
func TestWaitForAttestationReturnsOnVerifiedReport(t *testing.T) {
	device := filepath.Join(t.TempDir(), "csv-guest")
	touchDevice(t, device)

	calls := 0
	ok := waitForAttestation(context.Background(), device, func(context.Context) (bool, error) {
		calls++
		return true, nil
	}, time.Millisecond, 5*time.Millisecond)

	if !ok {
		t.Fatal("waitForAttestation returned false with a present device and a verified report")
	}
	if calls != 1 {
		t.Fatalf("attestation ran %d times, want exactly 1", calls)
	}
}

// TestWaitForAttestationRetriesUntilVerified pins that a present device whose
// report does not verify keeps the instance in the wait loop.
func TestWaitForAttestationRetriesUntilVerified(t *testing.T) {
	device := filepath.Join(t.TempDir(), "csv-guest")
	touchDevice(t, device)

	calls := 0
	ok := waitForAttestation(context.Background(), device, func(context.Context) (bool, error) {
		calls++
		return calls >= 3, nil
	}, time.Millisecond, 2*time.Millisecond)

	if !ok {
		t.Fatal("waitForAttestation gave up before the report verified")
	}
	if calls != 3 {
		t.Fatalf("attestation ran %d times, want 3", calls)
	}
}

// TestWaitForAttestationWaitsForTheDevice pins the case that motivated the
// gate: the node appears after TAA started (Kata CSV2 creates it in a
// postStart hook), and the wait has to survive that race.
func TestWaitForAttestationWaitsForTheDevice(t *testing.T) {
	device := filepath.Join(t.TempDir(), "csv-guest")

	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = os.WriteFile(device, nil, 0o600)
	}()

	attested := false
	ok := waitForAttestation(context.Background(), device, func(context.Context) (bool, error) {
		attested = true
		return true, nil
	}, 2*time.Millisecond, 5*time.Millisecond)

	if !ok {
		t.Fatal("waitForAttestation did not pick up a device that appeared while waiting")
	}
	if !attested {
		t.Fatal("the report was never attempted after the device appeared")
	}
	if _, err := os.Stat(device); err != nil {
		t.Fatalf("stat device: %v", err)
	}
}

// TestWaitForAttestationStopsWhenTheProcessStops pins that the wait ends with
// the process context and never touches a missing device.
func TestWaitForAttestationStopsWhenTheProcessStops(t *testing.T) {
	device := filepath.Join(t.TempDir(), "csv-guest")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	called := false
	ok := waitForAttestation(ctx, device, func(context.Context) (bool, error) {
		called = true
		return true, nil
	}, time.Millisecond, 5*time.Millisecond)

	if ok {
		t.Fatal("waitForAttestation reported success after the context was cancelled")
	}
	if called {
		t.Fatal("waitForAttestation attempted attestation without the device")
	}
}

// TestWaitForAttestationKeepsTryingAnUnverifiedReport pins that a present but
// unusable device is retried rather than accepted.
func TestWaitForAttestationKeepsTryingAnUnverifiedReport(t *testing.T) {
	device := filepath.Join(t.TempDir(), "csv-guest")
	touchDevice(t, device)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	calls := 0
	ok := waitForAttestation(ctx, device, func(context.Context) (bool, error) {
		calls++
		return false, nil
	}, time.Millisecond, 2*time.Millisecond)

	if ok {
		t.Fatal("waitForAttestation accepted an unverified report")
	}
	if calls < 2 {
		t.Fatalf("attestation ran %d times, want at least 2", calls)
	}
}

// TestRegisterInstanceFHERegistersImmediately pins that type 4 keeps the old
// behavior: no attestation gate, and an empty report (verifiedPass=false).
func TestRegisterInstanceFHERegistersImmediately(t *testing.T) {
	var (
		registered atomic.Bool
		verified   atomic.Bool
		awaited    atomic.Bool
	)
	registerInstance(context.Background(), config.ServerTypeFHE,
		func(_ context.Context, verifiedPass bool) error {
			registered.Store(true)
			verified.Store(verifiedPass)
			return nil
		},
		func(context.Context) bool {
			awaited.Store(true)
			return true
		})

	if !registered.Load() {
		t.Fatal("an fhe instance did not register on the startup path")
	}
	if verified.Load() {
		t.Fatal("an fhe instance registered with verifiedPass=true")
	}
	if awaited.Load() {
		t.Fatal("an fhe instance went through the attestation gate")
	}
}

// TestRegisterInstanceWaitsForAttestation pins that instance types 1-3 do not
// register until the gate reports a verified report, and register as attested.
func TestRegisterInstanceWaitsForAttestation(t *testing.T) {
	for _, serverType := range []string{config.ServerTypeTEE, config.ServerTypeDataAnalysis} {
		t.Run(serverType, func(t *testing.T) {
			registered := make(chan bool, 1)
			awaited := make(chan struct{})

			registerInstance(context.Background(), serverType,
				func(_ context.Context, verifiedPass bool) error {
					registered <- verifiedPass
					return nil
				},
				func(context.Context) bool {
					close(awaited)
					return true
				})

			<-awaited
			select {
			case verifiedPass := <-registered:
				if !verifiedPass {
					t.Fatal("the instance registered with verifiedPass=false")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("the instance never registered after attestation succeeded")
			}
		})
	}
}

// TestRegisterInstanceDoesNotRegisterWithoutAttestation pins the requirement:
// with no verified report there is no registration at all, for both gated roles.
func TestRegisterInstanceDoesNotRegisterWithoutAttestation(t *testing.T) {
	for _, serverType := range []string{config.ServerTypeTEE, config.ServerTypeDataAnalysis} {
		t.Run(serverType, func(t *testing.T) {
			awaited := make(chan struct{})
			registered := make(chan struct{}, 1)

			registerInstance(context.Background(), serverType,
				func(context.Context, bool) error {
					registered <- struct{}{}
					return nil
				},
				func(context.Context) bool {
					close(awaited)
					return false
				})

			<-awaited
			select {
			case <-registered:
				t.Fatal("the instance registered without a verified attestation report")
			case <-time.After(50 * time.Millisecond):
			}
		})
	}
}

// TestWaitForCSVDevicePicksUpTheNode pins the wait that precedes the sealing
// key source decision: a node that appears after startup is still picked up,
// which is what keeps the node race from choosing the SM2-derived key.
func TestWaitForCSVDevicePicksUpTheNode(t *testing.T) {
	device := filepath.Join(t.TempDir(), "csv-guest")

	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = os.WriteFile(device, nil, 0o600)
	}()

	if !waitForCSVDevice(context.Background(), device, 2*time.Millisecond, 5*time.Millisecond) {
		t.Fatal("waitForCSVDevice did not pick up a device that appeared while waiting")
	}
}

// TestWaitForCSVDeviceStopsWhenTheProcessStops pins that the wait is unbounded
// only until the process stops, not forever against cancellation.
func TestWaitForCSVDeviceStopsWhenTheProcessStops(t *testing.T) {
	device := filepath.Join(t.TempDir(), "csv-guest")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if waitForCSVDevice(ctx, device, time.Millisecond, 5*time.Millisecond) {
		t.Fatal("waitForCSVDevice reported success after the context was cancelled")
	}
}

// TestAwaitStateSealingKeySourceUsesTheDeviceForGatedRoles pins that instance
// types 1-3 seal with the CSV hardware key once the node is there.
func TestAwaitStateSealingKeySourceUsesTheDeviceForGatedRoles(t *testing.T) {
	for _, serverType := range []string{config.ServerTypeTEE, config.ServerTypeDataAnalysis} {
		t.Run(serverType, func(t *testing.T) {
			device := filepath.Join(t.TempDir(), "csv-guest")
			touchDevice(t, device)

			source, err := awaitStateSealingKeySource(context.Background(), serverType, device)
			if err != nil {
				t.Fatalf("awaitStateSealingKeySource: %v", err)
			}
			if source != store.KeySourceCSVHW {
				t.Fatalf("source = %q, want %q", source, store.KeySourceCSVHW)
			}
		})
	}
}

// TestAwaitStateSealingKeySourceFHEReadsImmediately pins that type 4 keeps the
// old behavior: no wait, and the SM2-derived key when there is no CSV guest.
func TestAwaitStateSealingKeySourceFHEReadsImmediately(t *testing.T) {
	device := filepath.Join(t.TempDir(), "csv-guest")

	done := make(chan error, 1)
	go func() {
		source, err := awaitStateSealingKeySource(context.Background(), config.ServerTypeFHE, device)
		if err == nil && source != store.KeySourceSM2 {
			err = fmt.Errorf("source = %q, want %q", source, store.KeySourceSM2)
		}
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("an fhe instance waited for a CSV guest device")
	}
}

// TestAwaitStateSealingKeySourceStopsWithTheProcess pins that a cancelled
// process aborts the wait instead of sealing with a source it never saw.
func TestAwaitStateSealingKeySourceStopsWithTheProcess(t *testing.T) {
	device := filepath.Join(t.TempDir(), "csv-guest")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := awaitStateSealingKeySource(ctx, config.ServerTypeDataAnalysis, device); err == nil {
		t.Fatal("awaitStateSealingKeySource returned a source after the context was cancelled")
	}
}
