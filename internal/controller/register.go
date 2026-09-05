package controller

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"taa/internal/attestation"
)

const (
	registerEndpoint = "/v1/taa/register"
	jsonContentType  = "application/json"
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

// NoticeRegister makes one best-effort attempt to POST /v1/taa/register.
// The request carries the attestation report and TAA public key.
func NoticeRegister(ctx context.Context, platformAddr, dockerID, attestationFile, taaPublicKey string, timestamp int64) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(platformAddr) == "" {
		return fmt.Errorf("PLATFORM_IP is required")
	}
	if strings.TrimSpace(dockerID) == "" {
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

	url := platformURL(platformAddr, registerEndpoint)

	// Extract report values for attestationValues field.
	// If extraction fails, continue with an empty report so registration can still proceed.
	reportValues, err := attestation.ExtractReportValues(attestationFile)
	verifiedPass := true
	if err != nil {
		log.Printf("notice platform register: extract report values failed, continuing with empty report: %v", err)
		reportValues = ""
		verifiedPass = false
	}

	if err := postRegister(ctx, platformHTTPClient, url, dockerID, attestationFile, taaPublicKey, reportValues, verifiedPass, timestamp); err != nil {
		return err
	}
	return nil
}


func logRegisterRequestFailure(url, contentType string, payload []byte, statusCode int, responseBody string, sendErr error) {
	if sendErr != nil {
		log.Printf("platform register request failed before response: error=%v", sendErr)
	} else {
		log.Printf("platform register request rejected: status=%d response=%s", statusCode, responseBody)
	}
	log.Printf("platform register request dump:\nPOST %s\nContent-Type: %s\nContent-Length: %d\n\n%s", url, contentType, len(payload), string(payload))
}

func postRegister(ctx context.Context, client *http.Client, url, dockerID, attestationFile, taaPublicKey, reportValues string, verifiedPass bool, timestamp int64) error {
	// Read and Base64 encode the attestation report
	reportData, err := os.ReadFile(attestationFile)
	if err != nil {
		return fmt.Errorf("read attestation file: %w", err)
	}
	attestationBase64 := base64.StdEncoding.EncodeToString(reportData)

	body := registerRequest{
		DockerID:          dockerID,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", jsonContentType)

	resp, err := client.Do(req)
	if err != nil {
		logRegisterRequestFailure(url, jsonContentType, payload, 0, "", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		respText := strings.TrimSpace(string(respBody))
		logRegisterRequestFailure(url, jsonContentType, payload, resp.StatusCode, respText, nil)
		return fmt.Errorf("platform returned status %d: %s", resp.StatusCode, respText)
	}

	return nil
}
