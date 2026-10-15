package controller

import (
	"strings"

	"taa/internal/resource"
	filetree "taa/pkg/filetree"
)

// trainingReportFileName is TAA's own report, written at the root of the result
// directory by every path that ends a training run (normal completion, boot-time
// crash recovery, async panic). It is not a training artifact: it is packed out of
// the export and skipped by the leakage check - because it carries table previews,
// i.e. dataset rows, by design (see AttachResultFiles). Every write, the export
// 404 probe, the packer and the check resolve the name through this constant so
// the exclusions cannot drift away from the file actually written.
const trainingReportFileName = "training_report.json"

// reportCodeResultLeak is the /v1/taa/reportRes code TAA reports when the training-end
// leakage check found the dataset (or other high-severity plaintext) inside the result
// directory. It is deliberately distinct from 1, the code for a training run that failed
// on its own: the training succeeded, its artifacts are what got rejected. The report
// body records the same rejection (status "failed", the reason in failure_reason) and
// drops result_files entirely.
const reportCodeResultLeak = 2

// AttachResultFiles 把结果目录结构树挂到报告的 result_files 段上。
//
// 结构树与 /v1/taa/getResourceInfo 的 tree 完全一致，**含预览**：平台需要看到样本行本身，
// 和 getResourceInfo 一样。这些样本行不会流到导出产物里——training_report.json 已被排除在
// /v1/taa/export 的打包清单之外（见 trainingReportFileName），报告只经 /v1/taa/reportRes
// 上报给平台，而导出目录里那些真正会被打包外发的文件照旧受明文泄露检查约束。
//
// resultCheck 是训练结束时那次明文泄露检查的裁决，也就是 /v1/taa/export 用来决定放不放行
// 的那一份。它一旦指认结果目录里有原始数据，这里整段省略 result_files——连目录树都不扫：
// 树的预览就是那些数据行，正是要拒的东西，扫出来也只能丢掉。其余情况（没开启检查、检查
// 自己没跑起来、查过且干净）照常挂树。
//
// 目录为空时什么也不做；扫描失败时原样返回错误，由调用方告警——结构树是附加证据，
// 缺了不该拖垮整份报告。三条产出 training_report.json 的路径（正常完成、启动崩溃自愈、
// 异步 panic）都必须经过这里，否则平台拿到的报告结构会随死法而变。
//
// 扫描发生在 training_report.json 落盘之前，所以树里不含该文件本身。
func AttachResultFiles(report map[string]any, resultDir string, resultCheck *resource.ResultCheckVerdict) error {
	if resultLeakDetected(resultCheck) {
		return nil
	}
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
	// 模板类文件的样本行要随报告上报，与 getResourceInfo 一致。
	opts.IncludePreview = true
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
	return resultFiles, nil
}

// 训练结果被拒时给平台的两段文字：report 体里的 failure_reason 只交代事实，/v1/taa/reportRes
// 的 msg 再多说一句 TAA 做了什么。两者共用同一份高危明细。
const (
	resultLeakBaseReason = "结果目录包含原始训练数据"
	resultLeakBaseMsg    = "结果目录包含原始训练数据，训练结果拒绝提供目录清单与预览"
)

// resultLeakDetected 判定训练结束那次明文泄露检查是否指认结果目录里有原始数据。
// 没有裁决、或裁决记着检查自己没跑起来（Error 非空）都不算：那是没有证据，不是有证据说泄露。
func resultLeakDetected(resultCheck *resource.ResultCheckVerdict) bool {
	return resultCheck != nil && resultCheck.Error == "" && !resultCheck.Passed
}

// resultLeakText 拼出给平台看的拒绝原因，把检查记下的高危项接在后面。
func resultLeakText(base string, resultCheck *resource.ResultCheckVerdict) string {
	if resultCheck == nil || len(resultCheck.Details) == 0 {
		return base
	}
	return base + ": " + strings.Join(resultCheck.Details, "; ")
}
