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
	reportAuditEndpoint       = "/v1/taa/reportAudit"
)

type reportRequest struct {
	DockerID  string         `json:"dockerId"`
	RequestID string         `json:"requestId"`
	TaskID    string         `json:"taskId"`
	Code      int            `json:"code"`
	Msg       *string        `json:"msg"`
	Report    string         `json:"report,omitempty"`
	Checksum  map[string]any `json:"checksum,omitempty"`
}

type reportResRequest struct {
	DockerID  string  `json:"dockerId"`
	RequestID string  `json:"requestId"`
	TaskID    string  `json:"taskId"`
	Code      int     `json:"code"`
	Msg       *string `json:"msg"`
	Report    string  `json:"report,omitempty"`
}

type reportModelImportRequest struct {
	DockerID  string         `json:"dockerId"`
	RequestID string         `json:"requestId"`
	TaskID    string         `json:"taskId"`
	Code      int            `json:"code"`
	Msg       *string        `json:"msg"`
	Checksum  map[string]any `json:"checksum,omitempty"`
}

type reportAuditRequest struct {
	DockerID  string  `json:"dockerId"`
	RequestID string  `json:"requestId"`
	TaskID    string  `json:"taskId"`
	Code      int     `json:"code"`
	Msg       *string `json:"msg"`
	Report    string  `json:"report"`
}

// ReportRes notifies the platform of the training/test completion result.
// It follows the TAA -> platform contract defined in docs/taa接口设计文档.md §3.4.
func ReportRes(ctx context.Context, platformAddr, dockerID, requestID, taskID string, code int, msg, report string) error {
	platformAddr, dockerID, requestID, taskID, err := validateAndNormalizePlatformParams(platformAddr, dockerID, requestID, taskID, true)
	if err != nil {
		return err
	}
	var msgPtr *string
	if strings.TrimSpace(msg) != "" {
		msgVal := msg
		msgPtr = &msgVal
	}
	payload, err := json.Marshal(reportResRequest{
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
	return sendPlatformJSON(ctx, platformAddr, reportResEndpoint, payload)
}

// ReportModelImport notifies the platform of the model import and archive checksum result.
// It follows the TAA -> platform contract defined in docs/taa接口设计文档.md §3.5.
// The requestId is required and must match the originating importModel request.
func ReportModelImport(ctx context.Context, platformAddr, dockerID, requestID, taskID string, code int, msg string, checksum ...map[string]any) error {
	var cs map[string]any
	if len(checksum) > 0 {
		cs = checksum[0]
	}
	if code == 0 && strings.TrimSpace(msg) == "" {
		msg = "模型导入成功"
	}
	platformAddr, dockerID, requestID, taskID, err := validateAndNormalizePlatformParams(platformAddr, dockerID, requestID, taskID, true)
	if err != nil {
		return err
	}
	var msgPtr *string
	if strings.TrimSpace(msg) != "" {
		msgVal := msg
		msgPtr = &msgVal
	}
	payload, err := json.Marshal(reportModelImportRequest{
		DockerID:  dockerID,
		RequestID: requestID,
		TaskID:    taskID,
		Code:      code,
		Msg:       msgPtr,
		Checksum:  cs,
	})
	if err != nil {
		return err
	}
	return sendPlatformJSON(ctx, platformAddr, reportModelImportEndpoint, payload)
}

// ReportAudit notifies the platform of the code security audit result.
// It follows the TAA -> platform contract defined in docs/taa接口设计文档.md §3.6.
// The requestId is required and must match the originating importModel request.
func ReportAudit(ctx context.Context, platformAddr, dockerID, requestID, taskID string, code int, msg, report string) error {
	platformAddr, dockerID, requestID, taskID, err := validateAndNormalizePlatformParams(platformAddr, dockerID, requestID, taskID, true)
	if err != nil {
		return err
	}
	var msgPtr *string
	if strings.TrimSpace(msg) != "" {
		msgVal := msg
		msgPtr = &msgVal
	}
	payload, err := json.Marshal(reportAuditRequest{
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
	return sendPlatformJSON(ctx, platformAddr, reportAuditEndpoint, payload)
}

// ReportTaskOutcome 根据任务类型自动分流上报至相应平台通道。
func ReportTaskOutcome(ctx context.Context, platformAddr, dockerID, requestID, taskID, taskType string, code int, msg, report string, checksum ...map[string]any) error {
	if taskType == "model_import" {
		return ReportModelImport(ctx, platformAddr, dockerID, requestID, taskID, code, msg, checksum...)
	}
	return ReportRes(ctx, platformAddr, dockerID, requestID, taskID, code, msg, report)
}

func validateAndNormalizePlatformParams(platformAddr, dockerID, requestID, taskID string, requireRequestID bool) (string, string, string, string, error) {
	if strings.TrimSpace(platformAddr) == "" {
		return "", "", "", "", fmt.Errorf("PLATFORM_IP is required")
	}
	if strings.TrimSpace(dockerID) == "" {
		return "", "", "", "", fmt.Errorf("DOCKER_ID is required")
	}
	requestID = strings.TrimSpace(requestID)
	taskID = strings.TrimSpace(taskID)
	if requireRequestID && requestID == "" && taskID == "" {
		return "", "", "", "", fmt.Errorf("requestId 和 taskId 不能同时为空")
	}

	// 真实管控平台强要求: requestId、dockerId 和 taskId 不能为空。
	// 当外部调用方缺省任一标识时，自动相互补齐兜底，确保发往平台的上报请求中两者均非空。
	if taskID == "" && requestID != "" {
		taskID = requestID
	}
	if requestID == "" && taskID != "" {
		requestID = taskID
	}

	return strings.TrimSpace(platformAddr), strings.TrimSpace(dockerID), requestID, taskID, nil
}

func sendPlatformJSON(ctx context.Context, platformAddr, endpoint string, payload []byte) error {
	if ctx == nil {
		ctx = context.Background()
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
