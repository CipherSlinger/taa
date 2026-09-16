package platform

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"taa/internal/attestation"
)

const (
	RegisterEndpoint = "/v1/taa/register"
)

type registerRequest struct {
	DockerID          string `json:"dockerId"`
	AuthInfo          any    `json:"authInfo"`
	TaaPublicKey      string `json:"taaPublicKey"`
	AttestationValues string `json:"attestationValues"`
	Timestamp         string `json:"timestamp"`
	VerifiedPass      bool   `json:"verifiedPass"`
	Attestation       string `json:"attestation"`
}

// NoticeRegister 向管控平台注册本 TAA 实例并上报 TEE 远程证明报告与公钥
func NoticeRegister(ctx context.Context, platformAddr, dockerID, attestationFile, taaPublicKey string, timestamp int64) error {
	client := NewClient(platformAddr, dockerID)
	return client.NoticeRegister(ctx, attestationFile, taaPublicKey, timestamp)
}

// NoticeRegister 实例方法
func (c *Client) NoticeRegister(ctx context.Context, attestationFile, taaPublicKey string, timestamp int64) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if c.PlatformAddr == "" {
		return fmt.Errorf("PLATFORM_IP is required")
	}
	if c.DockerID == "" {
		return fmt.Errorf("DOCKER_ID is required")
	}
	if strings.TrimSpace(attestationFile) == "" {
		return fmt.Errorf("attestation report file is required")
	}
	if strings.TrimSpace(taaPublicKey) == "" {
		return fmt.Errorf("taaPublicKey is required")
	}
	if _, err := os.Stat(attestationFile); err != nil {
		return fmt.Errorf("attestation report file is not accessible: %w", err)
	}

	url := PlatformURL(c.PlatformAddr, RegisterEndpoint)

	reportValues, err := attestation.ExtractReportValues(attestationFile)
	verifiedPass := true
	if err != nil {
		log.Printf("notice platform register: extract report values failed, continuing with empty report: %v", err)
		reportValues = ""
		verifiedPass = false
	}

	reportData, err := os.ReadFile(attestationFile)
	if err != nil {
		return fmt.Errorf("read attestation file: %w", err)
	}
	attestationBase64 := base64.StdEncoding.EncodeToString(reportData)

	body := registerRequest{
		DockerID:          c.DockerID,
		AuthInfo:          nil,
		TaaPublicKey:      taaPublicKey,
		AttestationValues: reportValues,
		Timestamp:         fmt.Sprintf("%d", timestamp),
		VerifiedPass:      verifiedPass,
		Attestation:       attestationBase64,
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal register request: %w", err)
	}

	return SendPlatformJSON(ctx, c.HTTPClient, url, payload)
}
