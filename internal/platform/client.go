package platform

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	JSONContentType = "application/json"
	DefaultTimeout  = 10 * time.Second
)

var defaultHTTPClient = &http.Client{Timeout: DefaultTimeout}

// Client 封装与管控平台通信的 HTTP 客户端及默认配置
type Client struct {
	HTTPClient   *http.Client
	PlatformAddr string
	DockerID     string
}

// NewClient 构造管控平台客户端
func NewClient(platformAddr, dockerID string) *Client {
	return &Client{
		HTTPClient:   defaultHTTPClient,
		PlatformAddr: strings.TrimSpace(platformAddr),
		DockerID:     strings.TrimSpace(dockerID),
	}
}

// PlatformURL 规范化平台服务接口 URL
func PlatformURL(platformAddr, endpoint string) string {
	addr := strings.TrimRight(strings.TrimSpace(platformAddr), "/")
	if strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://") {
		return addr + endpoint
	}
	return "http://" + addr + endpoint
}

// LogRequestFailure 记录平台请求失败转储日志
func LogRequestFailure(url, contentType string, payload []byte, statusCode int, responseBody string, sendErr error) {
	if sendErr != nil {
		log.Printf("platform register request failed before response: error=%v", sendErr)
	} else {
		log.Printf("platform register request rejected: status=%d response=%s", statusCode, responseBody)
	}
	log.Printf("platform register request dump:\nPOST %s\nContent-Type: %s\nContent-Length: %d\n\n%s",
		url, contentType, len(payload), string(payload))
}

// SendPlatformJSON 发送 JSON POST 请求到管控平台
func SendPlatformJSON(ctx context.Context, client *http.Client, url string, payload []byte) error {
	if client == nil {
		client = defaultHTTPClient
	}
	if ctx == nil {
		ctx = context.Background()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create platform request: %w", err)
	}
	req.Header.Set("Content-Type", JSONContentType)

	resp, err := client.Do(req)
	if err != nil {
		LogRequestFailure(url, JSONContentType, payload, 0, "", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		respText := strings.TrimSpace(string(respBody))
		LogRequestFailure(url, JSONContentType, payload, resp.StatusCode, respText, nil)
		return fmt.Errorf("platform returned status %d: %s", resp.StatusCode, respText)
	}

	return nil
}
