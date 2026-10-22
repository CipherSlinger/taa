package controller

import (
	"fmt"
	"time"

	"taa/internal/codeaudit"
	"taa/internal/resource"
)

// runResultCheck 对训练结果目录与训练输入目录逐文件做哈希比对，并返回可持久化的裁决。
//
// It never returns an error and never panics: the caller runs under runAsyncSafe,
// where a panic would turn a successful training run into a failed one. A check
// that could not be executed yields a non-nil verdict carrying Error, so
// "checked but broken" stays distinguishable from "never checked".
func (s *TAAState) runResultCheck(resultDir, inputDir string) *resource.ResultCheckVerdict {
	verdict := &resource.ResultCheckVerdict{
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
	}

	checker := codeaudit.NewResultChecker(inputDir)
	// The report itself is skipped: it is TAA's own artifact and holds table previews
	// by design, so hashing it could flag the check's own output as leaked data.
	report, err := checker.CheckDirectory(resultDir, trainingReportFileName)
	if err != nil {
		verdict.Error = err.Error()
		return verdict
	}
	if report == nil {
		verdict.Error = "结果检查未返回报告"
		return verdict
	}

	verdict.Passed = report.Passed
	for _, item := range report.Warnings {
		if item.Severity == codeaudit.SeverityHigh {
			verdict.Details = append(verdict.Details, fmt.Sprintf("[%s] %s", item.Check, item.Detail))
		}
	}
	return verdict
}
