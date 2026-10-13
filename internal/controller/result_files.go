package controller

import (
	"strings"

	filetree "taa/pkg/filetree"
)

// AttachResultFiles 把结果目录结构树挂到报告的 result_files 段上。
//
// 结构树与 /v1/taa/getResourceInfo 的 tree 完全一致，但**不含预览**：这个段会写进
// training_report.json，而该文件就在结果目录里，会被 /v1/taa/export 一起打包外发，
// 带上预览等于把训练数据的样本行送进导出产物。
//
// 目录为空时什么也不做；扫描失败时原样返回错误，由调用方告警——结构树是附加证据，
// 缺了不该拖垮整份报告。三条产出 training_report.json 的路径（正常完成、启动崩溃自愈、
// 异步 panic）都必须经过这里，否则平台拿到的报告结构会随死法而变。
//
// 扫描发生在 training_report.json 落盘之前，所以树里不含该文件本身。
func AttachResultFiles(report map[string]any, resultDir string) error {
	resultFiles, err := buildResultFilesTree(resultDir)
	if err != nil {
		return err
	}
	if resultFiles != nil {
		report["result_files"] = resultFiles
	}
	return nil
}

func buildResultFilesTree(resultDir string) (map[string]any, error) {
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
	return map[string]any{
		"total_files":  rep.TotalFiles,
		"total_size":   rep.TotalSize,
		"total_size_h": rep.TotalSizeH,
		"tree":         rep.Tree,
	}, nil
}
