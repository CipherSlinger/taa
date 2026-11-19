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
	flag.StringVar(&cfg.TAAPort, "taa-port", cfg.TAAPort, "TAA port for discovery and per-instance target derivation")
	flag.StringVar(&cfg.LLMPod, "llm-pod", cfg.LLMPod, "TEE-LLM pod name for discovery")
	flag.StringVar(&cfg.LLMNS, "llm-ns", cfg.LLMNS, "TEE-LLM pod namespace")
	flag.StringVar(&cfg.LLMPort, "llm-port", cfg.LLMPort, "TEE-LLM plaintext platform port")
	flag.StringVar(&cfg.LLMTarget, "llm-target", cfg.LLMTarget, "TEE-LLM base URL; skips pod discovery")
	flag.IntVar(&cfg.LLMPollSeconds, "llm-poll-seconds", cfg.LLMPollSeconds, "TEE-LLM heartbeat/log poll interval")
	flag.BoolVar(&cfg.AllowEmptyAttestation, "allow-empty-attestation", false, "skip attestation check")
	flag.StringVar(&cfg.SM2ID, "sm2-id", cfg.SM2ID, "SM2 signature identity, must match TAA's PLATFORM_SM2_ID (empty = protocol default)")
	flag.StringVar(&cfg.PlatformKeyFile, "platform-key-file", cfg.PlatformKeyFile, "platform SM2 key file (default: <state-dir>/platform-key.json)")
	flag.StringVar(&cfg.ConsoleUser, "console-user", cfg.ConsoleUser, "TEE-LLM console username")
	flag.StringVar(&cfg.ConsolePassword, "console-password", cfg.ConsolePassword, "TEE-LLM console password")
	flag.StringVar(&cfg.AuditEngine, "audit-engine", cfg.AuditEngine, "audit workbench static engine: semgrep or regex")
	flag.StringVar(&cfg.SemgrepRules, "semgrep-rules", cfg.SemgrepRules, "semgrep rules file or directory")
	flag.StringVar(&cfg.TerminalShell, "terminal-shell", cfg.TerminalShell, "shell the API tester's host terminal starts")
	flag.StringVar(&cfg.ExpectedInstances, "instances", cfg.ExpectedInstances, "configured instance inventory, type:dockerId[,type:dockerId...]; entries that never register are listed as 未连接")
	flag.Parse()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := mock.Run(ctx, cfg); err != nil {
		log.Printf("[MOCK-FATAL] %v", err)
		os.Exit(1)
	}
}
