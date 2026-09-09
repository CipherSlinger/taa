package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"taa/internal/app/taa"
)

func main() {
	configFile := flag.String("config", "", "Path to taa-config.json (optional)")
	addr := flag.String("addr", "", "Server listen address (optional, overrides config)")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := taa.Run(ctx, *configFile, *addr); err != nil {
		log.Printf("[TAA-FATAL] %v", err)
		os.Exit(1)
	}
}
