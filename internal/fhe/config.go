package fhe

import (
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
	// CallbackBaseURL is how the FHE service reaches this TAA instance. It is
	// derived at startup as http://127.0.0.1:<listen port>: TAA and the FHE
	// service share the host's network namespace.
	CallbackBaseURL string
	// MaxEvalKeyBytes bounds the eval key download; see DefaultMaxEvalKeyBytes.
	MaxEvalKeyBytes int64
	// PollInterval is the fallback poll period while waiting for a task.
	PollInterval time.Duration
	// RequestTimeout bounds one HTTP call to the FHE service.
	RequestTimeout time.Duration
	// TaskTimeout bounds a whole task, polls and callback together.
	TaskTimeout time.Duration
	// ActivateModelOnImport calls /models/activate right after a model is staged.
	//
	// This field is the exception to this struct's rule that a zero value is an
	// obviously broken configuration: its zero value is a working-but-wrong one.
	// A plain bool cannot tell "the operator turned activation off" from "the
	// field was never set", so a Config built without it stages models and never
	// hot-loads them - no startup error, no log line, and every task then fails
	// at run time with a model the service never loaded. Production is safe only
	// because the JSON layer resolves a *bool that defaults to true; a second
	// caller building a Config in Go must set this field as well.
	ActivateModelOnImport bool
}

// validateBaseURL checks that raw is an absolute http or https URL with a host.
//
// Both URL-shaped fields go through here: this package appends a path to each of
// them and hands the result to the FHE service, so a value the service cannot
// POST to has to be an operator-facing startup error rather than a silent
// failure discovered at task time.
func validateBaseURL(field, raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("fhe.%s %q is not a valid URL: %w", field, raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("fhe.%s %q must use the http or https scheme", field, raw)
	}
	if u.Host == "" {
		return fmt.Errorf("fhe.%s %q has no host", field, raw)
	}
	// Host is not enough: "http://:1" has Host ":1" and no host name at all, so
	// the two would accept a URL nothing can connect to. The startup-config layer
	// reads Hostname for the same reason, and two gates that validate the same
	// property must not disagree.
	if u.Hostname() == "" {
		return fmt.Errorf("fhe.%s %q has no host name", field, raw)
	}
	return nil
}

// Validate rejects a configuration this package cannot safely run with. It is
// deliberately strict: a half-configured FHE instance would fail at task time,
// after the platform has already been told the import succeeded.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Endpoint) == "" {
		return fmt.Errorf("fhe.endpoint is required")
	}
	if err := validateBaseURL("endpoint", c.Endpoint); err != nil {
		return err
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
	if err := validateBaseURL("callbackBaseUrl", c.CallbackBaseURL); err != nil {
		return err
	}
	// CallbackURL appends "/v1/taa/fheCallback" to this value, so either
	// character would corrupt the result.
	if strings.ContainsAny(c.CallbackBaseURL, "?#") {
		return fmt.Errorf("fhe.callbackBaseUrl %q must not contain a query or a fragment", c.CallbackBaseURL)
	}
	if c.MaxEvalKeyBytes <= 0 {
		return fmt.Errorf("fhe.maxEvalKeyBytes must be positive, got %d", c.MaxEvalKeyBytes)
	}
	// The ...Ms keys are milliseconds, so the message prints milliseconds rather
	// than the raw time.Duration ("got -1ns" names a unit the operator cannot
	// find anywhere in the startup config).
	if c.PollInterval <= 0 {
		return fmt.Errorf("fhe.pollIntervalMs must be positive, got %d", int64(c.PollInterval/time.Millisecond))
	}
	if c.RequestTimeout <= 0 {
		return fmt.Errorf("fhe.requestTimeoutMs must be positive, got %d", int64(c.RequestTimeout/time.Millisecond))
	}
	if c.TaskTimeout <= 0 {
		return fmt.Errorf("fhe.taskTimeoutMs must be positive, got %d", int64(c.TaskTimeout/time.Millisecond))
	}
	return nil
}

// CallbackURL is the URL handed to the FHE service so it can report a terminal
// state back to this instance.
func (c Config) CallbackURL() string {
	return strings.TrimRight(strings.TrimSpace(c.CallbackBaseURL), "/") +
		"/v1/taa/fheCallback"
}
