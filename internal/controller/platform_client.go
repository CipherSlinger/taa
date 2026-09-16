package controller

import (
	"net/http"
	"time"

	"taa/internal/platform"
)

var platformHTTPClient = &http.Client{Timeout: 10 * time.Second}

func platformURL(platformAddr, endpoint string) string {
	return platform.PlatformURL(platformAddr, endpoint)
}
