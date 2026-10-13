package controller

import (
	filetree "taa/pkg/filetree"
)

func buildResourceInfoJSON(dataDir, archivePath string) (string, error) {
	opts := filetree.DefaultOptions()
	// 只有这个接口打开预览：它是对资源包的一次性应答，平台要看的就是样本数据本身。
	// 报告类产物（training_report.json）必须保持关闭——那个文件在导出目录里，
	// 会随 /v1/taa/export 一起打包外发。
	opts.IncludePreview = true
	if archivePath != "" {
		opts.ArchivePath = archivePath
	}
	data, err := filetree.MarshalReport(dataDir, opts)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
