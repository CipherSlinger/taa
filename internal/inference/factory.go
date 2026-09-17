package inference

import (
	"fmt"
	"strings"
	"time"
)

// Config defines client initialization settings.
type Config struct {
	Transport               string
	Endpoint                string
	UDSPath                 string
	AuthToken               string
	Timeout                 time.Duration
	AllowedHosts            []string
	CircuitBreakerThreshold int
	CooldownSec             int
}

// NewClient initializes an InferenceClient based on the supplied configuration.
func NewClient(cfg Config) (InferenceClient, error) {
	threshold := cfg.CircuitBreakerThreshold
	if threshold <= 0 {
		threshold = 3
	}
	cooldown := time.Duration(cfg.CooldownSec) * time.Second
	if cooldown <= 0 {
		cooldown = 30 * time.Second
	}
	cb := NewCircuitBreaker(threshold, cooldown)

	endpoint := strings.TrimSpace(cfg.Endpoint)
	transport := strings.ToLower(strings.TrimSpace(cfg.Transport))
	if transport == "uds" || (transport == "" && cfg.UDSPath != "") || strings.HasPrefix(strings.ToLower(endpoint), "unix://") {
		udsPath := cfg.UDSPath
		if udsPath == "" && strings.HasPrefix(strings.ToLower(endpoint), "unix://") {
			udsPath = endpoint[len("unix://"):]
		}
		return NewUDSAdapter(udsPath, cfg.Timeout, cb)
	}

	if transport != "" && transport != "http" && transport != "https" {
		return nil, fmt.Errorf("unsupported transport protocol %q: must be http, https, or uds", cfg.Transport)
	}

	validator := NewEndpointValidator(cfg.AllowedHosts, false)
	return NewHTTPAdapter(cfg.Endpoint, cfg.AuthToken, cfg.Timeout, cb, validator)
}
