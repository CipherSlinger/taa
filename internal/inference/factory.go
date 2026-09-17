package inference

import (
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

	transport := strings.ToLower(strings.TrimSpace(cfg.Transport))
	if transport == "uds" || (transport == "" && cfg.UDSPath != "") {
		return NewUDSAdapter(cfg.UDSPath, cfg.Timeout, cb)
	}

	validator := NewEndpointValidator(cfg.AllowedHosts, false)
	return NewHTTPAdapter(cfg.Endpoint, cfg.AuthToken, cfg.Timeout, cb, validator)
}
