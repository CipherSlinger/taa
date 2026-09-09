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
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := taa.Run(ctx, *configFile); err != nil {
		log.Printf("[TAA-FATAL] %v", err)
		os.Exit(1)
	}
}
