package controller

import (
	"fmt"
	"time"

	"taa/internal/codeaudit"
	"taa/internal/resource"
)

// runResultCheck 对训练结果目录执行一次明文泄露检查，并返回可持久化的裁决。
//
// It never returns an error and never panics: the caller runs under runAsyncSafe,
// where a panic would turn a successful training run into a failed one. A check
// that could not be executed yields a non-nil verdict carrying Error, so
// "checked but broken" stays distinguishable from "never checked".
func (s *TAAState) runResultCheck(dir string) *resource.ResultCheckVerdict {
	verdict := &resource.ResultCheckVerdict{
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
	}

	// GetMaxFileBytes feeds ResultChecker.limit(); using another value here would
	// change the oversized-file verdict.
	checker := codeaudit.NewResultChecker(s.Security.DataDir, s.Security.GetMaxFileBytes())
	report, err := checker.CheckDirectory(dir)
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
