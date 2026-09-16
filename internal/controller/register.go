package controller

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"taa/internal/platform"
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
	return platform.NoticeRegister(ctx, platformAddr, dockerID, attestationFile, taaPublicKey, timestamp)
}

func logRegisterRequestFailure(url, contentType string, payload []byte, statusCode int, responseBody string, sendErr error) {
	platform.LogRequestFailure(url, contentType, payload, statusCode, responseBody, sendErr)
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
