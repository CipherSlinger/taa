package runtime

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// LoadTrainingResult 读取并反序列化指定路径下的 training_result.json
func LoadTrainingResult(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]any{}, nil
		}
		return nil, fmt.Errorf("read training_result.json: %w", err)
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parse training_result.json: %w", err)
	}
	if result == nil {
		result = map[string]any{}
	}
	return result, nil
}

// BuildCrashFailureReport 构造崩溃/异常自愈场景下的标准 Schema 1.0 失败报告
func BuildCrashFailureReport(taskID string, startedAt, finishedAt time.Time, failureReason string, modelChecksum, dataChecksum map[string]any) (map[string]any, error) {
	if dataChecksum == nil {
		dataChecksum = map[string]any{
			"algorithm": "sm3",
			"value":     "N/A",
		}
	}
	if strings.TrimSpace(failureReason) == "" {
		failureReason = "TAA 异常崩溃重启，执行已被安全终止 (Process Interrupted by Crash)"
	}
	return BuildTrainingReport(taskID, startedAt, finishedAt, "failed", 137, failureReason, modelChecksum, dataChecksum, nil, nil)
}

// BuildTrainingReport 聚合各维度指标构造标准 Schema 1.0 训练报告数据结构
func BuildTrainingReport(taskID string, startedAt, finishedAt time.Time, status string, exitCode int, failureReason string, modelChecksum map[string]any, dataChecksum map[string]any, trainingResult map[string]any, codeauditSection map[string]any) (map[string]any, error) {
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		taskID = "task-" + finishedAt.UTC().Format("20060102-150405")
	}
	if status == "" {
		status = "succeeded"
	}
	if status != "succeeded" && strings.TrimSpace(failureReason) == "" {
		failureReason = "训练流程失败"
	}

	trainingTaskSource := ObjectField(trainingResult, "training_task")
	trainingTask := make(map[string]any, len(trainingTaskSource)+7)
	for key, value := range trainingTaskSource {
		if value != nil {
			trainingTask[key] = value
		}
	}
	trainingTask["task_id"] = taskID
	trainingTask["started_at"] = startedAt.UTC().Format(time.RFC3339)
	trainingTask["finished_at"] = finishedAt.UTC().Format(time.RFC3339)
	trainingTask["duration_seconds"] = DurationSeconds(startedAt, finishedAt)
	trainingTask["status"] = status
	trainingTask["exit_code"] = exitCode
	trainingTask["failure_reason"] = NullableString(failureReason)

	trainingTaskMetrics := ObjectField(trainingTaskSource, "metrics")
	if len(trainingTaskMetrics) == 0 {
		trainingTaskMetrics = ObjectField(trainingResult, "metrics")
	}
	if len(trainingTaskMetrics) > 0 {
		trainingTask["metrics"] = trainingTaskMetrics
	}

	if modelChecksum != nil {
		trainingTask["model_checksum"] = modelChecksum
	}

	dataset := CleanDatasetField(ObjectField(trainingResult, "dataset"))
	if dataChecksum != nil {
		dataset["checksum"] = dataChecksum
	}

	report := map[string]any{
		"report_id":      NewTrainingReportID(finishedAt),
		"generated_at":   finishedAt.UTC().Format(time.RFC3339),
		"schema_version": "1.0",
		"training_task":  trainingTask,
		"dataset":        dataset,
	}

	if codeauditSection != nil {
		report["codeaudit"] = codeauditSection
	}

	return report, nil
}

// CleanDatasetField 清理 dataset 字段中不合规的动态结构
func CleanDatasetField(src map[string]any) map[string]any {
	if len(src) == 0 {
		return map[string]any{}
	}
	out := make(map[string]any, len(src))
	for k, v := range src {
		if k == "data_structure" {
			continue
		}
		out[k] = v
	}
	return out
}

// ObjectField 安全获取嵌套 map[string]any 对象
func ObjectField(src map[string]any, key string) map[string]any {
	if src == nil {
		return map[string]any{}
	}
	if v, ok := src[key].(map[string]any); ok {
		return v
	}
	return map[string]any{}
}

// DurationSeconds 计算时间跨度秒数
func DurationSeconds(startedAt, finishedAt time.Time) int64 {
	if startedAt.IsZero() || finishedAt.IsZero() {
		return 0
	}
	d := int64(finishedAt.Sub(startedAt).Seconds())
	if d < 0 {
		return 0
	}
	return d
}

// NewTrainingReportID 生成唯一的训练报告 ID
func NewTrainingReportID(now time.Time) string {
	stamp := now.UTC().Format("20060102-150405")
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("train-report-%s-00000000", stamp)
	}
	return fmt.Sprintf("train-report-%s-%x", stamp, b[:])
}

// NullableString 处理空字符串转 nil
func NullableString(v string) any {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return v
}
