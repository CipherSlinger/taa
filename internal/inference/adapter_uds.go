package inference

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// NewUDSAdapter creates an inference adapter using Unix Domain Sockets.
func NewUDSAdapter(socketPath string, timeout time.Duration, cb *CircuitBreaker) (*HTTPAdapter, error) {
	v := NewEndpointValidator(nil, false)
	if err := v.Validate("unix://" + socketPath); err != nil {
		return nil, fmt.Errorf("uds socket path validation failed: %w", err)
	}

	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if cb == nil {
		cb = NewCircuitBreaker(3, 30*time.Second)
	}

	dialer := func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socketPath)
	}

	transport := &http.Transport{
		DialContext: dialer,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	return &HTTPAdapter{
		endpoint:       "http://unix",
		client:         client,
		circuitBreaker: cb,
		validator:      v,
	}, nil
}
