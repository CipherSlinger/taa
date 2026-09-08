package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	reportResEndpoint         = "/v1/taa/reportRes"
	reportModelImportEndpoint = "/v1/taa/reportModelImport"
)

type reportRequest struct {
	DockerID  string  `json:"dockerId"`
	RequestID string  `json:"requestId,omitempty"`
	TaskID    string  `json:"taskId,omitempty"`
	Code      int     `json:"code"`
	Msg       *string `json:"msg"`
	Report    string  `json:"report,omitempty"`
}

// ReportRes notifies the platform of the training/test completion result.
// It follows the TAA -> platform contract defined in docs/taa接口设计文档.md §3.4.
func ReportRes(ctx context.Context, platformAddr, dockerID, requestID, taskID string, code int, msg, report string) error {
	return reportToPlatform(ctx, platformAddr, dockerID, requestID, taskID, code, msg, report, reportResEndpoint, true)
}

// ReportModelImport notifies the platform of the model import result, including the code audit report.
// It follows the TAA -> platform contract defined in docs/taa接口设计文档.md §3.5.
// The requestId is required and must match the originating importModel request.
func ReportModelImport(ctx context.Context, platformAddr, dockerID, requestID, taskID string, code int, msg, report string) error {
	return reportToPlatform(ctx, platformAddr, dockerID, requestID, taskID, code, msg, report, reportModelImportEndpoint, true)
}

// reportToPlatform is a helper that sends a report to the platform.
func reportToPlatform(ctx context.Context, platformAddr, dockerID, requestID, taskID string, code int, msg, report, endpoint string, requireRequestID bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(platformAddr) == "" {
		return fmt.Errorf("PLATFORM_IP is required")
	}
	if strings.TrimSpace(dockerID) == "" {
		return fmt.Errorf("DOCKER_ID is required")
	}
	if requireRequestID && strings.TrimSpace(requestID) == "" && strings.TrimSpace(taskID) == "" {
		return fmt.Errorf("requestId 和 taskId 不能同时为空")
	}

	var msgPtr *string
	if strings.TrimSpace(msg) != "" {
		msgValue := msg
		msgPtr = &msgValue
	}

	payload, err := json.Marshal(reportRequest{
		DockerID:  dockerID,
		RequestID: requestID,
		TaskID:    taskID,
		Code:      code,
		Msg:       msgPtr,
		Report:    report,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, platformURL(platformAddr, endpoint), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := platformHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("platform returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	return nil
}
