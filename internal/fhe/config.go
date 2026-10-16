package fhe

import (
	"crypto/subtle"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultMaxEvalKeyBytes bounds the eval key download.
	//
	// This cap must stay separate from codeAudit.resultCheck.maxFileBytes. That
	// setting is the import download cap and defaults to 3 GiB, while a measured
	// eval_context.bin is 3,329,929,205 B - 103.7 MiB over. Reusing it makes the
	// key impossible to download at all. 6 GiB leaves room for parameter growth
	// while remaining a finite bound.
	DefaultMaxEvalKeyBytes = int64(6) << 30 // 6442450944

	DefaultPollInterval   = 5 * time.Second
	DefaultRequestTimeout = 30 * time.Second
	DefaultTaskTimeout    = 30 * time.Minute
)

// Config is the runtime configuration of the FHE integration on a
// server.type=fhe instance.
type Config struct {
	// Endpoint is the FHE API base, e.g. http://127.0.0.1:58996.
	Endpoint string
	// DataDir is the shared directory: the local path of the same bind mount the
	// FHE containers see as /data.
	DataDir string
	// KeyCacheDir holds eval keys by content digest, so a repeat user never
	// re-downloads several gigabytes.
	KeyCacheDir string
	// CallbackBaseURL is how the FHE service reaches this TAA instance, e.g.
	// http://172.16.10.130:6001.
	CallbackBaseURL string
	// CallbackToken authenticates the callback endpoint. An unauthenticated
	// callback endpoint is open to every process on the host, so an empty token
	// is refused rather than defaulted.
	CallbackToken string
	// MaxEvalKeyBytes bounds the eval key download; see DefaultMaxEvalKeyBytes.
	MaxEvalKeyBytes int64
	// PollInterval is the fallback poll period while waiting for a task.
	PollInterval time.Duration
	// RequestTimeout bounds one HTTP call to the FHE service.
	RequestTimeout time.Duration
	// TaskTimeout bounds a whole task, polls and callback together.
	TaskTimeout time.Duration
	// ActivateModelOnImport calls /models/activate right after a model is staged.
	ActivateModelOnImport bool
}

// Validate rejects a configuration this package cannot safely run with. It is
// deliberately strict: a half-configured FHE instance would fail at task time,
// after the platform has already been told the import succeeded.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Endpoint) == "" {
		return fmt.Errorf("fhe.endpoint is required")
	}
	u, err := url.Parse(strings.TrimSpace(c.Endpoint))
	if err != nil {
		return fmt.Errorf("fhe.endpoint %q is not a valid URL: %w", c.Endpoint, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("fhe.endpoint %q must use the http or https scheme", c.Endpoint)
	}
	if u.Host == "" {
		return fmt.Errorf("fhe.endpoint %q has no host", c.Endpoint)
	}
	if strings.TrimSpace(c.DataDir) == "" {
		return fmt.Errorf("fhe.dataDir is required")
	}
	if strings.TrimSpace(c.KeyCacheDir) == "" {
		return fmt.Errorf("fhe.keyCacheDir is required")
	}
	if strings.TrimSpace(c.CallbackBaseURL) == "" {
		return fmt.Errorf("fhe.callbackBaseUrl is required")
	}
	if strings.TrimSpace(c.CallbackToken) == "" {
		return fmt.Errorf("fhe.callbackToken is required")
	}
	if c.MaxEvalKeyBytes <= 0 {
		return fmt.Errorf("fhe.maxEvalKeyBytes must be positive, got %d", c.MaxEvalKeyBytes)
	}
	if c.PollInterval <= 0 {
		return fmt.Errorf("fhe.pollIntervalMs must be positive, got %s", c.PollInterval)
	}
	if c.RequestTimeout <= 0 {
		return fmt.Errorf("fhe.requestTimeoutMs must be positive, got %s", c.RequestTimeout)
	}
	if c.TaskTimeout <= 0 {
		return fmt.Errorf("fhe.taskTimeoutMs must be positive, got %s", c.TaskTimeout)
	}
	return nil
}

// TokenMatches compares a presented callback token against the configured one in
// constant time, so the comparison leaks nothing about how much of a guess was
// correct. An unconfigured token never matches, not even an empty presented one.
func (c Config) TokenMatches(presented string) bool {
	if c.CallbackToken == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(c.CallbackToken)) == 1
}

// CallbackURL is the URL handed to the FHE service so it can report a terminal
// state back to this instance.
func (c Config) CallbackURL() string {
	return strings.TrimRight(strings.TrimSpace(c.CallbackBaseURL), "/") +
		"/v1/taa/fheCallback?token=" + url.QueryEscape(c.CallbackToken)
}
