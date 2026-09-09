// Command platform-mock is the thin entrypoint for the platform mock
// service. All business logic lives in internal/app/mock.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"taa/internal/app/mock"
)

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	cfg := mock.Config{}
	flag.StringVar(&cfg.Addr, "addr", ":8080", "mock platform listen address")
	flag.StringVar(&cfg.StateDir, "state-dir", envOrDefault("STATE_DIR", "/root/taa"), "directory for mock platform state files")
	flag.StringVar(&cfg.UploadDir, "upload-dir", envOrDefault("UPLOAD_DIR", "./uploads"), "directory for uploaded files served at /files/")
	flag.StringVar(&cfg.TAATarget, "taa-target", "", "TAA service address for reverse proxy (e.g. http://10.244.0.5:6001). Auto-detected via -taa-pod if empty")
	flag.StringVar(&cfg.TAAPod, "taa-pod", envOrDefault("TAA_POD", "simple-busybox"), "Kubernetes pod name for auto-discovering TAA address")
	flag.StringVar(&cfg.TAANS, "taa-ns", envOrDefault("TAA_NS", ""), "Kubernetes namespace for TAA pod (empty = default namespace)")
	flag.StringVar(&cfg.TAAPort, "taa-port", envOrDefault("TAA_PORT", "6001"), "TAA service port for auto-discovery fallback")
	flag.BoolVar(&cfg.AllowEmptyAttestation, "allow-empty-attestation", false, "allow registration without attestation report (for local testing without TEE hardware)")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := mock.Run(ctx, cfg); err != nil {
		log.Printf("[MOCK-FATAL] %v", err)
		os.Exit(1)
	}
}
