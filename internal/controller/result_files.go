package controller

import (
	"strings"

	"taa/internal/resource"
	filetree "taa/pkg/filetree"
)

// AttachResultFiles 把结果目录结构树挂到报告的 result_files 段上。
//
// 结构树与 /v1/taa/getResourceInfo 的 tree 完全一致，但**不含预览**：这个段会写进
// training_report.json，而该文件就在结果目录里，会被 /v1/taa/export 一起打包外发，
// 带上预览等于把训练数据的样本行送进导出产物。
//
// resultCheck 非空时额外挂上 contains_dataset —— 训练结束时那次明文泄露检查的结论，
// 也就是 /v1/taa/export 用来决定放不放行的那份裁决。没有裁决（未开启检查、失败路径、
// 崩溃自愈路径，或检查自身没跑起来）时该字段整个不出现：缺字段表示"没查过"，比写成
// false（读起来像"查过且干净"）诚实。
//
// 目录为空时什么也不做；扫描失败时原样返回错误，由调用方告警——结构树是附加证据，
// 缺了不该拖垮整份报告。三条产出 training_report.json 的路径（正常完成、启动崩溃自愈、
// 异步 panic）都必须经过这里，否则平台拿到的报告结构会随死法而变。
//
// 扫描发生在 training_report.json 落盘之前，所以树里不含该文件本身。
func AttachResultFiles(report map[string]any, resultDir string, resultCheck *resource.ResultCheckVerdict) error {
	resultFiles, err := buildResultFilesTree(resultDir, resultCheck)
	if err != nil {
		return err
	}
	if resultFiles != nil {
		report["result_files"] = resultFiles
	}
	return nil
}

func buildResultFilesTree(resultDir string, resultCheck *resource.ResultCheckVerdict) (map[string]any, error) {
	if strings.TrimSpace(resultDir) == "" {
		return nil, nil
	}
	opts := filetree.DefaultOptions()
	// 这里只取 tree 与几个统计值，不序列化 checksum。默认选项既没给 Checksum 也没给
	// ArchivePath，BuildReport 会回落到整目录 SM3——那是对结果目录的又一次全量读取。
	opts.SkipChecksum = true
	rep, err := filetree.BuildReport(resultDir, opts)
	if err != nil {
		return nil, err
	}
	resultFiles := map[string]any{
		"total_files":  rep.TotalFiles,
		"total_size":   rep.TotalSize,
		"total_size_h": rep.TotalSizeH,
		"tree":         rep.Tree,
	}
	// contains_dataset 即训练结束那次 bytes.Contains 检查的结论：true 表示结果目录里
	// 出现了训练数据（或其它高危明文），与导出闸门读的是同一份裁决。
	if containsDataset, ok := verdictContainsDataset(resultCheck); ok {
		resultFiles["contains_dataset"] = containsDataset
	}
	return resultFiles, nil
}

// verdictContainsDataset 把裁决折算成报告字段：ok 为 false 表示没有可用结论。
func verdictContainsDataset(resultCheck *resource.ResultCheckVerdict) (bool, bool) {
	if resultCheck == nil || resultCheck.Error != "" {
		return false, false
	}
	return !resultCheck.Passed, true
}
