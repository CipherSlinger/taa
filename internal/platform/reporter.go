package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	ReportModelImportEndpoint = "/v1/taa/reportModelImport"
	ReportAuditEndpoint       = "/v1/taa/reportAudit"
	ReportResEndpoint         = "/v1/taa/reportRes"
	ModelLogEndpoint          = "/v1/taa/modelLog"
	ReportProgressEndpoint    = "/v1/taa/reportProgress"
)

// ModelLogEntry 定义训练终端上报日志条目
type ModelLogEntry struct {
	Seq       uint64 `json:"seq,omitempty"`
	Timestamp string `json:"timestamp"`
	Component string `json:"component,omitempty"`
	Level     string `json:"level,omitempty"`
	Message   string `json:"message"`
}

type reportResPayload struct {
	DockerID  string  `json:"dockerId"`
	RequestID string  `json:"requestId"`
	TaskID    string  `json:"taskId"`
	Code      int     `json:"code"`
	Msg       *string `json:"msg"`
	Report    string  `json:"report"`
}

type reportModelImportPayload struct {
	DockerID  string         `json:"dockerId"`
	RequestID string         `json:"requestId"`
	TaskID    string         `json:"taskId"`
	Code      int            `json:"code"`
	Msg       *string        `json:"msg"`
	Checksum  map[string]any `json:"checksum,omitempty"`
}

type reportAuditPayload struct {
	DockerID  string  `json:"dockerId"`
	RequestID string  `json:"requestId"`
	TaskID    string  `json:"taskId"`
	Code      int     `json:"code"`
	Msg       *string `json:"msg"`
	Report    string  `json:"report,omitempty"`
}

type reportModelLogPayload struct {
	DockerID  string          `json:"dockerId"`
	RequestID string          `json:"requestId"`
	TaskID    string          `json:"taskId"`
	SeqStart  uint64          `json:"seqStart"`
	Entries   []ModelLogEntry `json:"entries"`
}

type reportProgressPayload struct {
	DockerID  string  `json:"dockerId"`
	RequestID string  `json:"requestId"`
	TaskID    string  `json:"taskId"`
	Percent   float64 `json:"percent"`
	Timestamp string  `json:"timestamp"`
}

func ValidateAndNormalizePlatformParams(platformAddr, dockerID, requestID, taskID string) (string, string, string, string, error) {
	cleanPlatformAddr := strings.TrimSpace(platformAddr)
	if cleanPlatformAddr == "" {
		return "", "", "", "", fmt.Errorf("PLATFORM_IP is required")
	}

	cleanDockerID := strings.TrimSpace(dockerID)
	if cleanDockerID == "" {
		return "", "", "", "", fmt.Errorf("DOCKER_ID is required")
	}

	cleanReqID := strings.TrimSpace(requestID)
	cleanTaskID := strings.TrimSpace(taskID)
	if cleanReqID == "" && cleanTaskID == "" {
		return "", "", "", "", fmt.Errorf("requestId 和 taskId 不能同时为空")
	}
	if cleanReqID == "" {
		cleanReqID = cleanTaskID
	}
	if cleanTaskID == "" {
		cleanTaskID = cleanReqID
	}

	return cleanPlatformAddr, cleanDockerID, cleanReqID, cleanTaskID, nil
}

// ReportRes 向上游平台发送训练完成状态上报
func ReportRes(ctx context.Context, platformAddr, dockerID, requestID, taskID string, code int, msg, report string) error {
	addr, dID, reqID, tID, err := ValidateAndNormalizePlatformParams(platformAddr, dockerID, requestID, taskID)
	if err != nil {
		return err
	}

	var msgPtr *string
	if strings.TrimSpace(msg) != "" {
		msgVal := msg
		msgPtr = &msgVal
	}

	payload := reportResPayload{
		DockerID:  dID,
		RequestID: reqID,
		TaskID:    tID,
		Code:      code,
		Msg:       msgPtr,
		Report:    report,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal reportRes payload: %w", err)
	}

	url := PlatformURL(addr, ReportResEndpoint)
	return SendPlatformJSON(ctx, defaultHTTPClient, url, data)
}

// ReportModelImport 向上游平台发送模型导入完成状态上报
func ReportModelImport(ctx context.Context, platformAddr, dockerID, requestID, taskID string, code int, msg string, checksum ...map[string]any) error {
	addr, dID, reqID, tID, err := ValidateAndNormalizePlatformParams(platformAddr, dockerID, requestID, taskID)
	if err != nil {
		return err
	}

	if code == 0 && strings.TrimSpace(msg) == "" {
		msg = "模型导入成功"
	}

	var cs map[string]any
	if len(checksum) > 0 {
		cs = checksum[0]
	}

	var msgPtr *string
	if strings.TrimSpace(msg) != "" {
		msgVal := msg
		msgPtr = &msgVal
	}

	payload := reportModelImportPayload{
		DockerID:  dID,
		RequestID: reqID,
		TaskID:    tID,
		Code:      code,
		Msg:       msgPtr,
		Checksum:  cs,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal reportModelImport payload: %w", err)
	}

	url := PlatformURL(addr, ReportModelImportEndpoint)
	return SendPlatformJSON(ctx, defaultHTTPClient, url, data)
}

// ReportAudit 向上游平台发送模型代码审计结果上报
func ReportAudit(ctx context.Context, platformAddr, dockerID, requestID, taskID string, code int, msg, report string) error {
	addr, dID, reqID, tID, err := ValidateAndNormalizePlatformParams(platformAddr, dockerID, requestID, taskID)
	if err != nil {
		return err
	}

	var msgPtr *string
	if strings.TrimSpace(msg) != "" {
		msgVal := msg
		msgPtr = &msgVal
	}

	payload := reportAuditPayload{
		DockerID:  dID,
		RequestID: reqID,
		TaskID:    tID,
		Code:      code,
		Msg:       msgPtr,
		Report:    report,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal reportAudit payload: %w", err)
	}

	url := PlatformURL(addr, ReportAuditEndpoint)
	return SendPlatformJSON(ctx, defaultHTTPClient, url, data)
}

// ReportTaskOutcome 统一任务结果上报分发器
func ReportTaskOutcome(ctx context.Context, platformAddr, dockerID, requestID, taskID, taskType string, code int, msg, report string, checksum ...map[string]any) error {
	if taskType == "model_import" {
		return ReportModelImport(ctx, platformAddr, dockerID, requestID, taskID, code, msg, checksum...)
	}
	return ReportRes(ctx, platformAddr, dockerID, requestID, taskID, code, msg, report)
}

// ReportModelLog 向上游平台推送模型训练终端分块日志
func ReportModelLog(ctx context.Context, platformAddr, dockerID, requestID, taskID string, seqStart uint64, entries []ModelLogEntry) error {
	addr, dID, reqID, tID, err := ValidateAndNormalizePlatformParams(platformAddr, dockerID, requestID, taskID)
	if err != nil {
		return err
	}
	if entries == nil {
		entries = []ModelLogEntry{}
	}

	payload := reportModelLogPayload{
		DockerID:  dID,
		RequestID: reqID,
		TaskID:    tID,
		SeqStart:  seqStart,
		Entries:   entries,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal reportModelLog payload: %w", err)
	}

	url := PlatformURL(addr, ModelLogEndpoint)
	return SendPlatformJSON(ctx, defaultHTTPClient, url, data)
}

// ReportProgress 向上游平台推送训练百分比进度
func ReportProgress(ctx context.Context, platformAddr, dockerID, requestID, taskID string, percent float64, timestamp time.Time) error {
	addr, dID, reqID, tID, err := ValidateAndNormalizePlatformParams(platformAddr, dockerID, requestID, taskID)
	if err != nil {
		return err
	}
	if percent < 0 || percent > 100 {
		return fmt.Errorf("invalid progress percent: %v (must be between 0 and 100)", percent)
	}

	ts := timestamp.UTC().Format("2006-01-02T15:04:05Z07:00")
	payload := reportProgressPayload{
		DockerID:  dID,
		RequestID: reqID,
		TaskID:    tID,
		Percent:   percent,
		Timestamp: ts,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal reportProgress payload: %w", err)
	}

	url := PlatformURL(addr, ReportProgressEndpoint)
	return SendPlatformJSON(ctx, defaultHTTPClient, url, data)
}

// Client 实例调用方法绑定
func (c *Client) ReportRes(ctx context.Context, requestID, taskID string, code int, msg, report string) error {
	return ReportRes(ctx, c.PlatformAddr, c.DockerID, requestID, taskID, code, msg, report)
}

func (c *Client) ReportModelImport(ctx context.Context, requestID, taskID string, code int, msg string, checksum ...map[string]any) error {
	return ReportModelImport(ctx, c.PlatformAddr, c.DockerID, requestID, taskID, code, msg, checksum...)
}

func (c *Client) ReportAudit(ctx context.Context, requestID, taskID string, code int, msg, report string) error {
	return ReportAudit(ctx, c.PlatformAddr, c.DockerID, requestID, taskID, code, msg, report)
}

func (c *Client) ReportTaskOutcome(ctx context.Context, requestID, taskID, taskType string, code int, msg, report string, checksum ...map[string]any) error {
	return ReportTaskOutcome(ctx, c.PlatformAddr, c.DockerID, requestID, taskID, taskType, code, msg, report, checksum...)
}

func (c *Client) ReportModelLog(ctx context.Context, requestID, taskID string, seqStart uint64, entries []ModelLogEntry) error {
	return ReportModelLog(ctx, c.PlatformAddr, c.DockerID, requestID, taskID, seqStart, entries)
}

func (c *Client) ReportProgress(ctx context.Context, requestID, taskID string, percent float64, timestamp time.Time) error {
	return ReportProgress(ctx, c.PlatformAddr, c.DockerID, requestID, taskID, percent, timestamp)
}
