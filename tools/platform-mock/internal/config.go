package mock

import (
	"os"
	"strconv"
)

const (
	defaultAddr      = ":8080"
	defaultStateDir  = "/root/taa"
	defaultUploadDir = ".local/upload"
	defaultTAAPod    = "simple-busybox"
	defaultTAAPort   = "6001"
	defaultLLMPod    = "taa-teellm"
	defaultLLMPort   = "6001"
)

// Config carries the runtime configuration for the platform mock service.
type Config struct {
	// Addr is the listen address for the mock HTTP server.
	Addr string
	// StateDir is the directory used to persist register/report state files.
	StateDir string
	// UploadDir is the directory used to store uploaded files, served at /files/.
	UploadDir string
	// TAATarget is the single-instance fixed TAA address (e.g.
	// http://10.244.0.5:6001). targetFor resolves an instance's outbound
	// address in this order: the address derived from that instance's own
	// registration, then this fixed target, then the Pod address discovered via
	// TAAPod. While only one real instance exists, this fixed target keeps
	// winning as it did before multi-instance. Empty means no fixed target.
	TAATarget string
	// TAAPod is the Kubernetes pod name used to discover a fallback TAA
	// address when neither the per-instance derived address nor TAATarget is
	// available.
	TAAPod string
	// TAANS is the Kubernetes namespace for TAAPod (empty = default namespace).
	TAANS string
	// TAAPort is the TAA service port used for auto-discovery fallback and to
	// derive each instance's target from its registration's source IP.
	TAAPort string
	// LLMPod is the Kubernetes pod name the mock polls for the TEE-LLM
	// instance. The LLM does not register, so this is how its address is
	// learned.
	LLMPod string
	// LLMNS is the Kubernetes namespace for LLMPod (empty = the kubectl
	// context's default namespace).
	LLMNS string
	// LLMPort is the TEE-LLM plaintext platform port.
	LLMPort string
	// LLMTarget is an explicit TEE-LLM base URL that skips pod discovery. It
	// exists for local testing and for deployments where the mock cannot run
	// kubectl; when set, LLMPod is not consulted.
	LLMTarget string
	// LLMPollSeconds is the heartbeat/log poll interval.
	LLMPollSeconds int
	// AllowEmptyAttestation allows registration without an attestation
	// report, for local testing without TEE hardware.
	AllowEmptyAttestation bool
	// SM2ID is the SM2 signature identity ("ID_A") both sides must agree on.
	// Empty means the protocol default ("1234567812345678"). It must match the
	// value TAA was started with (PLATFORM_SM2_ID), or its signatures will not
	// verify and its requests will not seal.
	SM2ID string
	// PlatformKeyFile overrides where the platform SM2 key pair is persisted.
	// Empty means <StateDir>/platform-key.json.
	PlatformKeyFile string
}

func (c Config) withDefaults() Config {
	if c.Addr == "" {
		c.Addr = defaultAddr
	}
	if c.StateDir == "" {
		c.StateDir = defaultStateDir
	}
	if c.UploadDir == "" {
		c.UploadDir = defaultUploadDir
	}
	if c.TAAPort == "" {
		c.TAAPort = defaultTAAPort
	}
	if c.LLMPod == "" {
		c.LLMPod = defaultLLMPod
	}
	if c.LLMPort == "" {
		c.LLMPort = defaultLLMPort
	}
	if c.LLMPollSeconds <= 0 {
		c.LLMPollSeconds = defaultLLMPollSeconds
	}
	return c
}

// envOrDefault returns the value of the environment variable key, or
// fallback if it is unset or empty.
func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// envIntOrDefault parses a positive integer override. A malformed value is
// ignored rather than fatal: a typo must not keep the mock from starting.
func envIntOrDefault(key string, fallback int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}

// DefaultConfig returns the default Config for the platform mock service,
// resolving values from environment variables where applicable (STATE_DIR,
// UPLOAD_DIR, TAA_POD, TAA_NS, TAA_PORT, LLM_POD, LLM_NS, LLM_PORT,
// LLM_TARGET, LLM_POLL_SECONDS, PLATFORM_SM2_ID, PLATFORM_KEY_FILE).
// PLATFORM_SM2_ID is deliberately the same variable TAA reads, so one exported
// value configures both ends.
func DefaultConfig() Config {
	return Config{
		StateDir:        envOrDefault("STATE_DIR", defaultStateDir),
		UploadDir:       envOrDefault("UPLOAD_DIR", defaultUploadDir),
		TAAPod:          envOrDefault("TAA_POD", defaultTAAPod),
		TAANS:           envOrDefault("TAA_NS", ""),
		TAAPort:         envOrDefault("TAA_PORT", defaultTAAPort),
		LLMPod:          envOrDefault("LLM_POD", defaultLLMPod),
		LLMNS:           envOrDefault("LLM_NS", ""),
		LLMPort:         envOrDefault("LLM_PORT", defaultLLMPort),
		LLMTarget:       envOrDefault("LLM_TARGET", ""),
		LLMPollSeconds:  envIntOrDefault("LLM_POLL_SECONDS", defaultLLMPollSeconds),
		SM2ID:           os.Getenv("PLATFORM_SM2_ID"),
		PlatformKeyFile: envOrDefault("PLATFORM_KEY_FILE", ""),
	}.withDefaults()
}
