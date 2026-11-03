package mock

import (
	"os"
)

const (
	defaultAddr      = ":8080"
	defaultStateDir  = "/root/taa"
	defaultUploadDir = ".local/upload"
	defaultTAAPod    = "simple-busybox"
	defaultTAAPort   = "6001"
)

// Config carries the runtime configuration for the platform mock service.
type Config struct {
	// Addr is the listen address for the mock HTTP server.
	Addr string
	// StateDir is the directory used to persist register/report state files.
	StateDir string
	// UploadDir is the directory used to store uploaded files, served at /files/.
	UploadDir string
	// TAATarget is the console's default TAA address (e.g.
	// http://10.244.0.5:6001). The /taa/* proxy does not use it: each request
	// selects the target of the instance it names or the default instance.
	// When empty, TAAPod is used to auto-discover a fallback address via kubectl.
	TAATarget string
	// TAAPod is the Kubernetes pod name used for auto-discovering the TAA
	// address when TAATarget is empty.
	TAAPod string
	// TAANS is the Kubernetes namespace for TAAPod (empty = default namespace).
	TAANS string
	// TAAPort is the TAA service port used for auto-discovery fallback and to
	// derive each instance's target from its registration's source IP.
	TAAPort string
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

// DefaultConfig returns the default Config for the platform mock service,
// resolving values from environment variables where applicable (STATE_DIR,
// UPLOAD_DIR, TAA_POD, TAA_NS, TAA_PORT, PLATFORM_SM2_ID,
// PLATFORM_KEY_FILE). PLATFORM_SM2_ID is deliberately the same variable TAA
// reads, so one exported value configures both ends.
func DefaultConfig() Config {
	return Config{
		StateDir:        envOrDefault("STATE_DIR", defaultStateDir),
		UploadDir:       envOrDefault("UPLOAD_DIR", defaultUploadDir),
		TAAPod:          envOrDefault("TAA_POD", defaultTAAPod),
		TAANS:           envOrDefault("TAA_NS", ""),
		TAAPort:         envOrDefault("TAA_PORT", defaultTAAPort),
		SM2ID:           os.Getenv("PLATFORM_SM2_ID"),
		PlatformKeyFile: envOrDefault("PLATFORM_KEY_FILE", ""),
	}.withDefaults()
}
