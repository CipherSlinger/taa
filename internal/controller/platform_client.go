package controller

import (
	"net/http"
	"strings"
	"time"
)

var platformHTTPClient = &http.Client{Timeout: 10 * time.Second}

func platformURL(platformAddr, endpoint string) string {
	platformAddr = strings.TrimRight(strings.TrimSpace(platformAddr), "/")
	if strings.HasPrefix(platformAddr, "http://") || strings.HasPrefix(platformAddr, "https://") {
		return platformAddr + endpoint
	}
	return "http://" + platformAddr + endpoint
}
