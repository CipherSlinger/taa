package mock

import (
	"os"
)

const defaultTAAPort = "6001"

// Config carries the runtime configuration for the platform mock service.
type Config struct {
	// Addr is the listen address for the mock HTTP server.
	Addr string
	// StateDir is the directory used to persist register/report state files.
	StateDir string
	// UploadDir is the directory used to store uploaded files, served at /files/.
	UploadDir string
	// TAATarget is the TAA service address used for the reverse proxy
	// (e.g. http://10.244.0.5:6001). When empty, TAAPod is used to
	// auto-discover the address via kubectl.
	TAATarget string
	// TAAPod is the Kubernetes pod name used for auto-discovering the TAA
	// address when TAATarget is empty.
	TAAPod string
	// TAANS is the Kubernetes namespace for TAAPod (empty = default namespace).
	TAANS string
	// TAAPort is the TAA service port used for auto-discovery fallback.
	TAAPort string
	// AllowEmptyAttestation allows registration without an attestation
	// report, for local testing without TEE hardware.
	AllowEmptyAttestation bool
}

func (c Config) withDefaults() Config {
	if c.Addr == "" {
		c.Addr = ":8080"
	}
	if c.StateDir == "" {
		c.StateDir = "/root/taa"
	}
	if c.UploadDir == "" {
		c.UploadDir = ".local/upload"
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
// UPLOAD_DIR, TAA_POD, TAA_NS, TAA_PORT).
func DefaultConfig() Config {
	return Config{
		Addr:      ":8080",
		StateDir:  envOrDefault("STATE_DIR", "/root/taa"),
		UploadDir: envOrDefault("UPLOAD_DIR", ".local/upload"),
		TAAPod:    envOrDefault("TAA_POD", "simple-busybox"),
		TAANS:     envOrDefault("TAA_NS", ""),
		TAAPort:   envOrDefault("TAA_PORT", defaultTAAPort),
	}
}
