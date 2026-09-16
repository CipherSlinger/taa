package controller

import (
	"context"

	"taa/internal/platform"
)

const (
	reportModelImportEndpoint = platform.ReportModelImportEndpoint
	reportAuditEndpoint       = platform.ReportAuditEndpoint
	reportResEndpoint         = platform.ReportResEndpoint
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

// ReportRes notifies the platform of the training/test completion result.
func ReportRes(ctx context.Context, platformAddr, dockerID, requestID, taskID string, code int, msg, report string) error {
	return platform.ReportRes(ctx, platformAddr, dockerID, requestID, taskID, code, msg, report)
}

// ReportModelImport notifies the platform of the model import and archive checksum result.
func ReportModelImport(ctx context.Context, platformAddr, dockerID, requestID, taskID string, code int, msg string, checksum ...map[string]any) error {
	return platform.ReportModelImport(ctx, platformAddr, dockerID, requestID, taskID, code, msg, checksum...)
}

// ReportAudit notifies the platform of the code security audit result.
func ReportAudit(ctx context.Context, platformAddr, dockerID, requestID, taskID string, code int, msg, report string) error {
	return platform.ReportAudit(ctx, platformAddr, dockerID, requestID, taskID, code, msg, report)
}

// ReportTaskOutcome 根据任务类型自动分流上报至相应平台通道。
func ReportTaskOutcome(ctx context.Context, platformAddr, dockerID, requestID, taskID, taskType string, code int, msg, report string, checksum ...map[string]any) error {
	return platform.ReportTaskOutcome(ctx, platformAddr, dockerID, requestID, taskID, taskType, code, msg, report, checksum...)
}

func validateAndNormalizePlatformParams(platformAddr, dockerID, requestID, taskID string, requireRequestID bool) (string, string, string, string, error) {
	return platform.ValidateAndNormalizePlatformParams(platformAddr, dockerID, requestID, taskID)
}

func sendPlatformJSON(ctx context.Context, platformAddr, endpoint string, payload []byte) error {
	url := platform.PlatformURL(platformAddr, endpoint)
	return platform.SendPlatformJSON(ctx, platformHTTPClient, url, payload)
}
