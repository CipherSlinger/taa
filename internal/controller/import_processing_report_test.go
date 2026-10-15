package controller

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"taa/internal/codeaudit"
	"taa/internal/resource"
)

func TestBuildTrainingReportAddsModelChecksumAndKeepsTrainingMetrics(t *testing.T) {
	startedAt := mustParseReportTime(t, "2026-09-02T10:03:35Z")
	finishedAt := mustParseReportTime(t, "2026-09-02T10:03:43Z")

	trainingResult := map[string]any{
		"training_task": map[string]any{
			"task_id":          "task-20260902-001",
			"started_at":       "2026-09-02T10:03:35Z",
			"finished_at":      "2026-09-02T10:03:43Z",
			"duration_seconds": 8,
			"status":           "succeeded",
			"exit_code":        0,
			"failure_reason":   nil,
			"metrics": map[string]any{
				"final_accuracy": 0.91,
				"final_loss":     0.21,
				"epochs":         []any{map[string]any{"epoch": 1, "accuracy": 0.52, "loss": 1.23}},
			},
		},
		"dataset": map[string]any{
			"total_samples":  12500,
			"splits":         map[string]any{"train": 10000, "test": 1000},
			"data_structure": map[string]any{"features": []any{map[string]any{"name": "feature1"}, map[string]any{"name": "label"}}},
			"checksum":       map[string]any{"algorithm": "sm3", "value": "dataset-digest"},
		},
	}
	audit := &codeaudit.AuditReport{
		Conclusion: codeaudit.AuditConclusion{
			Passed:         true,
			RiskLevel:      "NONE",
			Summary:        "未发现安全问题，代码通过审计",
			Recommendation: "无需修复",
			Statistics:     codeaudit.AuditStatistics{},
		},
		FileReports: nil,
		Target: codeaudit.AuditTarget{
			Directory:    "models/examples",
			FilesScanned: 3,
		},
	}

	report, err := buildTrainingReport(
		"task-20260902-001",
		startedAt,
		finishedAt,
		"succeeded",
		0,
		"",
		map[string]any{"algorithm": "sm3", "value": "model-digest"},
		map[string]any{"algorithm": "sm3", "value": "data-archive-digest", "size": int64(934)},
		trainingResult,
		audit,
		true,
	)
	if err != nil {
		t.Fatalf("buildTrainingReport: %v", err)
	}

	if report["schema_version"] != "1.0" {
		t.Fatalf("schema_version = %v, want 1.0", report["schema_version"])
	}
	trainingTask := report["training_task"].(map[string]any)
	if trainingTask["task_id"] != "task-20260902-001" {
		t.Fatalf("task_id = %v", trainingTask["task_id"])
	}
	metrics := trainingTask["metrics"].(map[string]any)
	if metrics["final_accuracy"] != 0.91 || metrics["final_loss"] != 0.21 {
		t.Fatalf("training_task.metrics = %v", metrics)
	}
	if trainingTask["model_checksum"].(map[string]any)["value"] != "model-digest" {
		t.Fatalf("training_task.model_checksum = %v", trainingTask["model_checksum"])
	}
	dataset := report["dataset"].(map[string]any)
	datasetChecksum, ok := dataset["checksum"].(map[string]any)
	if !ok {
		t.Fatalf("dataset missing checksum: %v", dataset)
	}
	if datasetChecksum["algorithm"] != "sm3" {
		t.Fatalf("dataset checksum algorithm = %v, want sm3", datasetChecksum["algorithm"])
	}
	if datasetChecksum["value"] != "data-archive-digest" {
		t.Fatalf("dataset checksum value = %v, want data-archive-digest (TAA 注入值覆盖训练脚本值)", datasetChecksum["value"])
	}
	if datasetChecksum["size"] != int64(934) {
		t.Fatalf("dataset checksum size = %v, want 934", datasetChecksum["size"])
	}
	if _, ok := dataset["data_structure"]; ok {
		t.Fatalf("dataset should not include data_structure: %v", dataset)
	}
	if _, ok := report["data_structure"]; ok {
		t.Fatalf("report should not include data_structure: %v", report)
	}
	codeauditSection, ok := report["codeaudit"].(map[string]any)
	if !ok {
		t.Fatalf("report missing codeaudit: %v", report)
	}
	if _, ok := codeauditSection["report_id"]; ok {
		t.Fatalf("codeaudit should not include report_id: %v", codeauditSection)
	}
	if _, ok := codeauditSection["target"]; ok {
		t.Fatalf("codeaudit should not include target: %v", codeauditSection)
	}
	if _, ok := codeauditSection["statistics"]; ok {
		t.Fatalf("codeaudit should not include statistics: %v", codeauditSection)
	}
	if _, ok := codeauditSection["scan_metadata"]; ok {
		t.Fatalf("codeaudit should not include scan_metadata: %v", codeauditSection)
	}
	conclusion, ok := codeauditSection["conclusion"].(codeaudit.AuditConclusion)
	if !ok {
		t.Fatalf("codeaudit conclusion type = %T, want codeaudit.AuditConclusion", codeauditSection["conclusion"])
	}
	if conclusion.Summary != "未发现安全问题，代码通过审计" {
		t.Fatalf("codeaudit conclusion summary = %v", conclusion.Summary)
	}
	if fileReports, ok := codeauditSection["file_reports"]; ok && fileReports != nil {
		t.Fatalf("file_reports = %v, want nil", fileReports)
	}
	if _, ok := report["model"]; ok {
		t.Fatalf("report should not include model: %v", report)
	}
	if _, ok := report["metrics"]; ok {
		t.Fatalf("report should not include metrics: %v", report)
	}
	if _, ok := report["artifacts"]; ok {
		t.Fatalf("report should not include artifacts: %v", report)
	}
}

func TestBuildDirectoryChecksumSkipsSymlinkedDirectories(t *testing.T) {
	dir := t.TempDir()

	payloadDir := filepath.Join(dir, "payload")
	if err := os.Mkdir(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload: %v", err)
	}
	if err := os.WriteFile(filepath.Join(payloadDir, "model.bin"), []byte("abc"), 0o644); err != nil {
		t.Fatalf("write payload file: %v", err)
	}
	if err := os.Symlink(payloadDir, filepath.Join(dir, "data")); err != nil {
		t.Fatalf("symlink data: %v", err)
	}

	checksum, err := buildDirectoryChecksum(dir, "sm3")
	if err != nil {
		t.Fatalf("buildDirectoryChecksum: %v", err)
	}
	if got := checksum["size"].(int64); got != 3 {
		t.Fatalf("checksum size = %d, want 3", got)
	}
	if checksum["value"] == "" {
		t.Fatalf("checksum value is empty: %v", checksum)
	}
}

func mustParseReportTime(t *testing.T, value string) (result time.Time) {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse time %q: %v", value, err)
	}
	return parsed
}

func TestBuildAndSaveTrainingReportDoesNotScanDataset(t *testing.T) {
	resultDir := t.TempDir()
	modelDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(modelDir, "model.bin"), []byte("test-model"), 0o644); err != nil {
		t.Fatalf("write model file: %v", err)
	}

	state := &TAAState{
		Security: SecurityConfig{
			ModelDir: modelDir,
		},
	}

	startedAt := time.Now().Add(-10 * time.Second)
	finishedAt := time.Now()

	// buildAndSaveTrainingReport 不再包含 dataDir 和 loadResourceDataset
	data, err := state.buildAndSaveTrainingReport("task-123", startedAt, finishedAt, "succeeded", 0, "", nil, false, resultDir, nil)
	if err != nil {
		t.Fatalf("buildAndSaveTrainingReport: %v", err)
	}

	var report map[string]any
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}

	if _, ok := report["data_structure"]; ok {
		t.Fatalf("report should not contain data_structure: %v", report)
	}
	if dataset, ok := report["dataset"].(map[string]any); ok {
		if _, ok := dataset["data_structure"]; ok {
			t.Fatalf("dataset should not contain data_structure: %v", dataset)
		}
	}
}

func TestBuildAndSaveTrainingReportAddsResultFilesWithPreview(t *testing.T) {
	resultDir := t.TempDir()
	modelDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(modelDir, "model.bin"), []byte("test-model"), 0o644); err != nil {
		t.Fatalf("write model file: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(resultDir, "logs"), 0o755); err != nil {
		t.Fatalf("mkdir logs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(resultDir, "logs", "train.log"), []byte("epoch 1\n"), 0o644); err != nil {
		t.Fatalf("write train.log: %v", err)
	}
	csv := "epoch,val_accuracy\n1,0.52\n2,0.68\n"
	if err := os.WriteFile(filepath.Join(resultDir, "metrics.csv"), []byte(csv), 0o644); err != nil {
		t.Fatalf("write metrics.csv: %v", err)
	}

	state := &TAAState{
		Security: SecurityConfig{ModelDir: modelDir},
		Logs:     NewLogStore(64),
	}

	data, err := state.buildAndSaveTrainingReport("task-123", time.Now().Add(-time.Second), time.Now(), "succeeded", 0, "", nil, false, resultDir, nil)
	if err != nil {
		t.Fatalf("buildAndSaveTrainingReport: %v", err)
	}

	var report map[string]any
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	resultFiles, ok := report["result_files"].(map[string]any)
	if !ok {
		t.Fatalf("report missing result_files: %v", report)
	}
	if got := resultFiles["total_files"]; got != float64(2) {
		t.Fatalf("result_files.total_files = %v, want 2", got)
	}
	tree, ok := resultFiles["tree"].(map[string]any)
	if !ok {
		t.Fatalf("result_files.tree missing: %v", resultFiles)
	}
	if tree["name"] != filepath.Base(resultDir) {
		t.Fatalf("result_files.tree.name = %v, want %v", tree["name"], filepath.Base(resultDir))
	}

	// 样本行随报告上报给平台，与 getResourceInfo 一致；它们不会流到导出产物里，
	// 因为 training_report.json 已被排除在导出清单之外（见 flow 测试）
	csvNode := findTreeNode(t, tree, "metrics.csv")
	preview, ok := csvNode["preview"].([]any)
	if !ok {
		t.Fatalf("metrics.csv node missing preview: %v", csvNode)
	}
	if len(preview) != 2 {
		t.Fatalf("preview rows = %d, want 2: %v", len(preview), preview)
	}
	if first, _ := preview[0].([]any); len(first) != 2 || first[0] != "1" || first[1] != "0.52" {
		t.Fatalf("first preview row = %#v, want [1 0.52]", preview[0])
	}

	// 同一份内容也要落盘到训练报告文件中
	onDisk, err := os.ReadFile(filepath.Join(resultDir, trainingReportFileName))
	if err != nil {
		t.Fatalf("read training_report.json: %v", err)
	}
	if !strings.Contains(string(onDisk), `"result_files"`) {
		t.Fatalf("training_report.json missing result_files: %s", onDisk)
	}
}

// findTreeNode 在目录树里按名字深度优先找一个节点。
func findTreeNode(t *testing.T, node map[string]any, name string) map[string]any {
	t.Helper()
	if node["name"] == name {
		return node
	}
	children, _ := node["children"].([]any)
	for _, child := range children {
		childNode, ok := child.(map[string]any)
		if !ok {
			continue
		}
		if found := findTreeNode(t, childNode, name); found != nil {
			return found
		}
	}
	return nil
}

func TestBuildAndSaveTrainingReportWithholdsResultFilesOnLeak(t *testing.T) {
	newState := func(t *testing.T) (*TAAState, string) {
		t.Helper()
		resultDir := t.TempDir()
		modelDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(modelDir, "model.bin"), []byte("test-model"), 0o644); err != nil {
			t.Fatalf("write model file: %v", err)
		}
		if err := os.WriteFile(filepath.Join(resultDir, "model.pt"), []byte("weights"), 0o644); err != nil {
			t.Fatalf("write result file: %v", err)
		}
		return &TAAState{Security: SecurityConfig{ModelDir: modelDir}, Logs: NewLogStore(64)}, resultDir
	}

	build := func(t *testing.T, state *TAAState, resultDir string, verdict *resource.ResultCheckVerdict) map[string]any {
		t.Helper()
		data, err := state.buildAndSaveTrainingReport("task-cd", time.Now().Add(-time.Second), time.Now(), "succeeded", 0, "", nil, false, resultDir, verdict)
		if err != nil {
			t.Fatalf("buildAndSaveTrainingReport: %v", err)
		}
		var report map[string]any
		if err := json.Unmarshal(data, &report); err != nil {
			t.Fatalf("unmarshal report: %v", err)
		}
		return report
	}

	// 裁决指认结果目录里有原始数据：整段 result_files 都不给——树的预览就是那些数据行。
	// 落盘的 training_report.json 与上报的那份是同一个 map，一起没有。
	t.Run("leaking verdict withholds result_files", func(t *testing.T) {
		state, resultDir := newState(t)
		report := build(t, state, resultDir, &resource.ResultCheckVerdict{Passed: false, Details: []string{"[plaintext_section] leak.csv"}})
		if resultFiles, ok := report["result_files"]; ok {
			t.Fatalf("result_files should be withheld on a leaking verdict: %v", resultFiles)
		}
		onDisk, err := os.ReadFile(filepath.Join(resultDir, trainingReportFileName))
		if err != nil {
			t.Fatalf("read training_report.json: %v", err)
		}
		if strings.Contains(string(onDisk), `"result_files"`) {
			t.Fatalf("training_report.json should not carry result_files: %s", onDisk)
		}
	})

	t.Run("passing verdict keeps result_files", func(t *testing.T) {
		state, resultDir := newState(t)
		report := build(t, state, resultDir, &resource.ResultCheckVerdict{Passed: true})
		resultFiles, ok := report["result_files"].(map[string]any)
		if !ok {
			t.Fatalf("report missing result_files: %v", report)
		}
		if _, ok := resultFiles["contains_dataset"]; ok {
			t.Fatalf("contains_dataset is no longer a report field: %v", resultFiles)
		}
	})

	t.Run("no verdict keeps result_files", func(t *testing.T) {
		state, resultDir := newState(t)
		report := build(t, state, resultDir, nil)
		if _, ok := report["result_files"].(map[string]any); !ok {
			t.Fatalf("report missing result_files: %v", report)
		}
	})

	// 检查自己没跑起来只是没有证据，不是有证据说泄露：照常给树。
	t.Run("verdict that failed to run keeps result_files", func(t *testing.T) {
		state, resultDir := newState(t)
		report := build(t, state, resultDir, &resource.ResultCheckVerdict{Error: "read result dir: permission denied"})
		if _, ok := report["result_files"].(map[string]any); !ok {
			t.Fatalf("report missing result_files: %v", report)
		}
	})
}

func TestBuildAndSaveTrainingReportOmitsResultFilesWhenScanFails(t *testing.T) {
	resultDir := t.TempDir()
	modelDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(modelDir, "model.bin"), []byte("test-model"), 0o644); err != nil {
		t.Fatalf("write model file: %v", err)
	}
	// 结果目录不可读，结构树扫描必然失败
	missing := filepath.Join(resultDir, "gone")

	state := &TAAState{
		Security: SecurityConfig{ModelDir: modelDir},
		Logs:     NewLogStore(64),
	}

	data, err := state.buildAndSaveTrainingReport("task-123", time.Now().Add(-time.Second), time.Now(), "succeeded", 0, "", nil, false, missing, nil)
	if err != nil {
		t.Fatalf("buildAndSaveTrainingReport should tolerate a failed tree scan: %v", err)
	}

	var report map[string]any
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if _, ok := report["result_files"]; ok {
		t.Fatalf("result_files should be omitted when the scan fails: %v", report)
	}
}

func TestBuildCrashFailureReportCarriesResultFiles(t *testing.T) {
	resultDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(resultDir, "train.log"), []byte("epoch 1\n"), 0o644); err != nil {
		t.Fatalf("write train.log: %v", err)
	}
	if err := os.WriteFile(filepath.Join(resultDir, "metrics.csv"), []byte("epoch,val_accuracy\n1,0.52\n"), 0o644); err != nil {
		t.Fatalf("write metrics.csv: %v", err)
	}
	startedAt := time.Now().Add(-time.Minute)
	finishedAt := time.Now()

	// 崩溃自愈与异步 panic 都走这个入口；它们产出的报告必须与正常路径同构
	report, err := BuildCrashFailureReport("task-crash-1", startedAt, finishedAt, "boom", nil, nil, resultDir)
	if err != nil {
		t.Fatalf("BuildCrashFailureReport: %v", err)
	}
	resultFiles, ok := report["result_files"].(map[string]any)
	if !ok {
		t.Fatalf("crash report missing result_files: %v", report)
	}
	if got := resultFiles["total_files"]; got != 2 {
		t.Fatalf("result_files.total_files = %v, want 2", got)
	}

	// 崩溃路径的报告同样带样本行预览（与正常路径一致）
	if data, mErr := json.Marshal(report); mErr != nil {
		t.Fatalf("marshal crash report: %v", mErr)
	} else if !strings.Contains(string(data), `"preview"`) {
		t.Fatalf("crash report missing preview: %s", data)
	}

	// 没有结果目录时（例如崩溃发生在目录创建前）报告照常产出，只是不带该字段
	bare, err := BuildCrashFailureReport("task-crash-2", startedAt, finishedAt, "boom", nil, nil, "")
	if err != nil {
		t.Fatalf("BuildCrashFailureReport without resultDir: %v", err)
	}
	if _, ok := bare["result_files"]; ok {
		t.Fatalf("result_files should be omitted without a result dir: %v", bare)
	}
}

func TestBuildResourceInfoJSONIncludesPreview(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "users.csv"), []byte("user_id,name\n1,alice\n2,bob\n"), 0o644); err != nil {
		t.Fatalf("write users.csv: %v", err)
	}

	out, err := buildResourceInfoJSON(dataDir, "")
	if err != nil {
		t.Fatalf("buildResourceInfoJSON: %v", err)
	}
	if !strings.Contains(out, `"preview"`) {
		t.Fatalf("getResourceInfo output missing preview: %s", out)
	}

	var payload struct {
		Tree struct {
			Children []struct {
				Name    string                        `json:"name"`
				Fields  []struct{ Name, Type string } `json:"fields"`
				Preview [][]any                       `json:"preview"`
			} `json:"children"`
		} `json:"tree"`
	}
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("unmarshal resource info: %v", err)
	}
	if len(payload.Tree.Children) != 1 {
		t.Fatalf("tree children = %d, want 1", len(payload.Tree.Children))
	}
	csv := payload.Tree.Children[0]
	if csv.Name != "users.csv" {
		t.Fatalf("child name = %q, want %q", csv.Name, "users.csv")
	}
	if len(csv.Preview) != 2 {
		t.Fatalf("preview rows = %d, want 2", len(csv.Preview))
	}
	// 预览行按位置对齐 fields，不带列名
	if len(csv.Fields) != 2 || csv.Fields[0].Name != "user_id" || csv.Fields[1].Name != "name" {
		t.Fatalf("fields = %#v, want user_id,name", csv.Fields)
	}
	if first := csv.Preview[0]; len(first) != 2 || first[0] != "1" || first[1] != "alice" {
		t.Fatalf("first preview row = %#v, want [1 alice]", first)
	}
}
