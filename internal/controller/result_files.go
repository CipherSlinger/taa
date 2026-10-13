package controller

import (
	"strings"

	filetree "taa/pkg/filetree"
)

// BuildResultFilesTree 扫描结果目录，生成训练报告的 result_files 段。
//
// 结构与 /v1/taa/getResourceInfo 的 tree 完全一致，但**不含预览**：这个段会写进
// training_report.json，而该文件就在结果目录里，会被 /v1/taa/export 一起打包外发，
// 带上预览等于把训练数据的样本行送进导出产物。
//
// 扫描发生在 training_report.json 落盘之前，所以树里不含该文件本身。
// 目录为空或不可读时返回错误，调用方应省略该字段而不是让整份报告构建失败。
func BuildResultFilesTree(resultDir string) (map[string]any, error) {
	if strings.TrimSpace(resultDir) == "" {
		return nil, nil
	}
	rep, err := filetree.BuildReport(resultDir, filetree.DefaultOptions())
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"total_files":  rep.TotalFiles,
		"total_size":   rep.TotalSize,
		"total_size_h": rep.TotalSizeH,
		"tree":         rep.Tree,
	}, nil
}
