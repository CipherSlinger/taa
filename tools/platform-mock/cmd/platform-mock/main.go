package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	mock "taa/tools/platform-mock/internal"
)

func main() {
	cfg := mock.DefaultConfig()
	flag.StringVar(&cfg.Addr, "addr", cfg.Addr, "mock platform listen address")
	flag.StringVar(&cfg.StateDir, "state-dir", cfg.StateDir, "state directory")
	flag.StringVar(&cfg.UploadDir, "upload-dir", cfg.UploadDir, "upload directory")
	flag.StringVar(&cfg.TAATarget, "taa-target", cfg.TAATarget, "TAA reverse proxy target")
	flag.StringVar(&cfg.TAAPod, "taa-pod", cfg.TAAPod, "TAA pod name for discovery")
	flag.StringVar(&cfg.TAANS, "taa-ns", cfg.TAANS, "TAA pod namespace")
	flag.StringVar(&cfg.TAAPort, "taa-port", cfg.TAAPort, "TAA port for discovery")
	flag.BoolVar(&cfg.AllowEmptyAttestation, "allow-empty-attestation", false, "skip attestation check")
	flag.StringVar(&cfg.SM2ID, "sm2-id", cfg.SM2ID, "SM2 signature identity, must match TAA's PLATFORM_SM2_ID (empty = protocol default)")
	flag.StringVar(&cfg.PlatformKeyFile, "platform-key-file", cfg.PlatformKeyFile, "platform SM2 key file (default: <state-dir>/platform-key.json)")
	flag.Parse()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := mock.Run(ctx, cfg); err != nil {
		log.Printf("[MOCK-FATAL] %v", err)
		os.Exit(1)
	}
}
