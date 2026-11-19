package hctclient

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"taa/internal/hctproto"
)

// The test binary doubles as a fake helper when started with --serve, which is
// how the client always launches the real one.
func TestMain(m *testing.M) {
	for _, a := range os.Args[1:] {
		if a == "--serve" {
			runFakeHelper()
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}

// Fake-helper-only ops.
const (
	opHang  uint16 = 0xF001
	opCrash uint16 = 0xF002
)

func runFakeHelper() {
	for {
		h, payload, err := hctproto.ReadFrame(os.Stdin)
		if err != nil {
			return
		}
		respond := func(status uint16, body []byte) {
			_ = hctproto.WriteFrame(os.Stdout, hctproto.Header{
				Version: hctproto.Version,
				Op:      h.Op,
				Status:  status,
				ReqID:   h.ReqID,
			}, body)
		}
		switch h.Op {
		case hctproto.OpHello:
			var b hctproto.Builder
			version := "hct-3.0.10-2601d03-"
			b.U8(uint8(len(version)))
			b.Bytes([]byte(version))
			b.U8(2)
			b.Bytes([]byte("sw"))
			b.U8(4)
			b.Bytes([]byte("test"))
			respond(hctproto.StatusOK, b.Payload())
		case hctproto.OpPing:
			respond(hctproto.StatusOK, nil)
		case hctproto.OpClose:
			respond(hctproto.StatusOK, nil)
			return
		case opHang:
			// Never answer.
		case opCrash:
			os.Exit(7)
		case hctproto.OpGCMFinal:
			respond(hctproto.StatusAuthFailed, []byte("bad tag"))
		case hctproto.OpSM2VerifyDigest:
			respond(hctproto.StatusInvalidSignature, nil)
		default:
			respond(hctproto.StatusOK, payload)
		}
	}
}

func testConfig(t *testing.T) Config {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	return Config{
		HelperPath:     exe,
		Accel:          "sw",
		RequireVersion: "3.0.10",
		RequestTimeout: 5 * time.Second,
	}
}

func startTestClient(t *testing.T) *Client {
	t.Helper()
	c, err := Start(testConfig(t))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestStartAndHello(t *testing.T) {
	c := startTestClient(t)
	h := c.Hello()
	if !strings.Contains(h.Version, "3.0.10") || h.Accel != "sw" || h.BuildID != "test" {
		t.Fatalf("hello = %+v", h)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestStartRejectsVersionMismatch(t *testing.T) {
	cfg := testConfig(t)
	cfg.RequireVersion = "3.0.11"
	c, err := Start(cfg)
	if err == nil {
		_ = c.Close()
		t.Fatal("expected version mismatch")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("err = %v", err)
	}
}

func TestStartRejectsMissingHelper(t *testing.T) {
	if _, err := Start(Config{HelperPath: "/nonexistent/taa-hct-helper"}); err == nil {
		t.Fatal("expected error for a missing helper")
	}
}

func TestStartRejectsRelativeHelper(t *testing.T) {
	if _, err := Start(Config{HelperPath: "taa-hct-helper"}); err == nil {
		t.Fatal("expected error for a relative helper path")
	}
}

func TestCallEchoAndConcurrency(t *testing.T) {
	c := startTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			want := fmt.Sprintf("payload-%d", i)
			got, err := c.Call(ctx, hctproto.OpSM3Sum, []byte(want))
			if err != nil {
				errs <- err
				return
			}
			if string(got) != want {
				errs <- fmt.Errorf("call %d: got %q want %q", i, got, want)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestCallMapsStatus(t *testing.T) {
	c := startTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := c.Call(ctx, hctproto.OpGCMFinal, nil)
	var se *StatusError
	if !errors.As(err, &se) || se.Status != hctproto.StatusAuthFailed {
		t.Fatalf("err = %v, want StatusAuthFailed", err)
	}
	_, err = c.Call(ctx, hctproto.OpSM2VerifyDigest, nil)
	if !errors.As(err, &se) || se.Status != hctproto.StatusInvalidSignature {
		t.Fatalf("err = %v, want StatusInvalidSignature", err)
	}
}

func TestCallTimeoutKillsHelper(t *testing.T) {
	c := startTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := c.Call(ctx, opHang, nil)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	if err := c.Ping(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Ping after timeout = %v, want ErrUnavailable", err)
	}
}

func TestHelperCrashIsFatal(t *testing.T) {
	c := startTestClient(t)
	_, err := c.Call(context.Background(), opCrash, nil)
	if err == nil {
		t.Fatal("expected an error when the helper dies")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if err := c.Ping(context.Background()); errors.Is(err, ErrUnavailable) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("client did not become unavailable after helper crash")
}

func TestCloseIsIdempotent(t *testing.T) {
	c, err := Start(testConfig(t))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := c.Call(context.Background(), hctproto.OpPing, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Call after Close = %v, want ErrUnavailable", err)
	}
}
