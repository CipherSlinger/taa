# 审计中重新下发模型：中止旧审计并重建审计链 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 审计运行中收到新的模型下发时，取消旧审计、覆盖模型目录、重新发起审计，且旧审计静默中止不回调平台。

**Architecture:** 给 `codeaudit` 的扫描入口加 context 贯通（semgrep 子进程、二进进扫描、LLM 请求、健康探测），controller 用 `auditGen` 代际号隔离新旧审计的状态写入与上报；模型导入在取得任务权后立即取消旧审计，覆盖目录前有界等待旧 goroutine 退出。

**Tech Stack:** Go 1.22+、`context`、`exec.CommandContext`、标准库 `testing`/`httptest`。

**Spec:** `.claude/specs/2026-10-22-model-reimport-aborts-audit-design.md`

---

## File Structure

| 文件 | 责任 |
| --- | --- |
| `internal/codeaudit/engine.go` | `StaticEngine` 增加 context 扫描方法；regex 适配器实现 |
| `internal/codeaudit/scanner.go` | 正则扫描的 context 变体与遍历内取消检查 |
| `internal/codeaudit/semgrep_engine.go` | semgrep 扫描的 context 贯通 |
| `internal/codeaudit/binary_scanner.go` | 二进制通道的 context 变体与遍历取消 |
| `internal/codeaudit/verifier.go` | `runBinaryChannel` 传 ctx；`GenerateAuditReport` 阶段边界检查 |
| `internal/controller/route.go` | 审计代际状态、abort/finish/wait、panic 处理、`tryAcquireTask` 闸门删除 |
| `internal/controller/import_processing.go` | `launchModelAudit`、`auditAndReportModelImport`、健康探测、上报校验 |
| `internal/controller/handler_task.go` | 模型导入受理后立即中止旧审计 |
| `internal/controller/codeaudit_projection.go` | `setLastAudit` 代际校验 |
| `internal/codeaudit/cancel_test.go`（新建） | codeaudit 取消测试 |
| `internal/controller/audit_abort_test.go`（新建） | 中止/代际/静默测试与阻塞引擎夹具 |
| `internal/controller/concurrency_test.go` | 替换旧的审计拒绝测试 |
| `internal/controller/audit_model_import_test.go` | 适配新签名与健康探测 ctx |
| `docs/api-design.md` | 并发语义文档 |

---

### Task 1: 正则引擎支持 context 扫描

**Files:**
- Modify: `internal/codeaudit/engine.go:27-62`
- Modify: `internal/codeaudit/scanner.go:265-325`
- Modify: `internal/codeaudit/verifier.go:378-382`
- Create: `internal/codeaudit/cancel_test.go`
- Test: `internal/codeaudit/cancel_test.go`

- [ ] **Step 1: 写失败测试**

Create `internal/codeaudit/cancel_test.go`:

```go
package codeaudit

import (
	"context"
	"errors"
	"testing"
)

// TestScannerCancelStopsWalk pins that a cancelled context aborts the walk
// instead of scanning the directory to the end.
func TestScannerCancelStopsWalk(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "a.py", "import os\nos.system('x')\n")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := NewScanner(DefaultRules(), DefaultConfig()).ScanDirectoryWithLinesContext(ctx, dir)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

// TestScannerContextMatchesPlainScan is the regression side: a live context
// produces the same report and line counts as the context-free entry point.
func TestScannerContextMatchesPlainScan(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "a.py", "import os\nos.system('x')\n")

	plain, plainLines, err := NewScanner(DefaultRules(), DefaultConfig()).ScanDirectoryWithLines(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctxReport, ctxLines, err := NewScanner(DefaultRules(), DefaultConfig()).ScanDirectoryWithLinesContext(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}

	if plain.Passed != ctxReport.Passed || len(plain.Findings) != len(ctxReport.Findings) {
		t.Fatalf("context scan diverged: plain=%+v ctx=%+v", plain, ctxReport)
	}
	if len(plainLines) != len(ctxLines) {
		t.Fatalf("line counts diverged: plain=%d ctx=%d", len(plainLines), len(ctxLines))
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/codeaudit/ -run 'TestScannerCancelStopsWalk|TestScannerContextMatchesPlainScan' -v`
Expected: FAIL — `ScanDirectoryWithLinesContext` undefined.

- [ ] **Step 3: 实现接口与 regex 适配器**

在 `internal/codeaudit/engine.go` 的 `StaticEngine` 中、`ScanDirectoryWithLines` 之后加入：

```go
	// ScanDirectoryWithLinesContext is ScanDirectoryWithLines with cancellation.
	// A cancelled context makes the scan return ctx.Err() promptly instead of a
	// report, so a superseded audit stops reading the model directory.
	ScanDirectoryWithLinesContext(ctx context.Context, dir string) (*Report, map[string]int, error)
```

在 `engine.go` 的 import 块加入 `"context"`，并在 `regexEngine` 的 `ScanDirectoryWithLines` 后加入：

```go
// ScanDirectoryWithLinesContext delegates to the wrapped scanner with the
// caller's cancellation attached.
func (e regexEngine) ScanDirectoryWithLinesContext(ctx context.Context, dir string) (*Report, map[string]int, error) {
	report, lineCounts, err := e.scanner.ScanDirectoryWithLinesContext(ctx, dir)
	return e.stamp(report), lineCounts, err
}
```

在 `internal/codeaudit/scanner.go` 中把现有 `ScanDirectoryWithLines` 改为委托，并新增 context 版本。将 `func (s *Scanner) ScanDirectoryWithLines(dir string) ...` 的函数体整体替换为：

```go
func (s *Scanner) ScanDirectoryWithLines(dir string) (*Report, map[string]int, error) {
	return s.ScanDirectoryWithLinesContext(context.Background(), dir)
}

// ScanDirectoryWithLinesContext is ScanDirectoryWithLines that can be
// cancelled: it returns ctx.Err() rather than a partial report.
func (s *Scanner) ScanDirectoryWithLinesContext(ctx context.Context, dir string) (*Report, map[string]int, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("scan directory: %w", err)
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("%s is not a directory", dir)
	}

	var findings []Finding
	filesCount := 0
	lineCounts := make(map[string]int)
	truncated := false

	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if s.config.SkipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !s.hasMatchingExtension(path) {
			return nil
		}

		filesCount++

		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		lines := strings.Split(string(content), "\n")
		lineCounts[path] = len(lines)

		fileFindings := s.scanLines(path, string(content), lines)
		findings = append(findings, fileFindings...)

		if len(findings) >= s.config.MaxFindings {
			findings = findings[:s.config.MaxFindings]
			truncated = true
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, ctxErr
		}
		return nil, nil, fmt.Errorf("walk directory: %w", err)
	}

	return s.buildReport(dir, filesCount, findings, truncated), lineCounts, nil
}
```

在 `scanner.go` 的 import 块加入 `"context"`。

最后在 `internal/codeaudit/verifier.go` 的 `GenerateAuditReport` 中把静态扫描调用改为传 ctx：

```go
	// Phase 1: Static scan with line counts.
	scanReport, lineCounts, err := engine.ScanDirectoryWithLinesContext(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("static scan: %w", err)
	}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./internal/codeaudit/ -run 'TestScannerCancelStopsWalk|TestScannerContextMatchesPlainScan' -v`
Expected: PASS（两个测试）。

- [ ] **Step 5: 全包回归**

Run: `go test ./internal/codeaudit/`
Expected: PASS。

- [ ] **Step 6: 提交**

```bash
git add internal/codeaudit/engine.go internal/codeaudit/scanner.go internal/codeaudit/verifier.go internal/codeaudit/cancel_test.go
git commit -m "feat(codeaudit): make the static scan cancelable"
```

---

### Task 2: semgrep 扫描支持取消

**Files:**
- Modify: `internal/codeaudit/semgrep_engine.go:194-280`, `:289-316`, `:368-378`, `:401-414`
- Test: `internal/codeaudit/cancel_test.go`

- [ ] **Step 1: 写失败测试**

追加到 `internal/codeaudit/cancel_test.go`：

```go
// blockingSemgrep replaces the process boundary with one that blocks until the
// context is cancelled, so the test can prove the adapter passes cancellation
// through rather than waiting for the CLI to finish.
type blockingSemgrep struct {
	called chan struct{}
}

func (b *blockingSemgrep) exec(ctx context.Context, _ string, _ []string) ([]byte, int, error) {
	close(b.called)
	<-ctx.Done()
	return nil, -1, ctx.Err()
}

// TestSemgrepCancelStopsTheRun pins that cancelling the audit context reaches
// the process boundary and returns promptly.
func TestSemgrepCancelStopsTheRun(t *testing.T) {
	scanDir := t.TempDir()
	writeTestFile(t, scanDir, "train.py", semgrepFixtureSource())
	rulesDir := t.TempDir()
	rulesPath := writeTestFile(t, rulesDir, "rules.yaml", "rules: []\n")

	engine := NewSemgrepEngine(NewScanner(DefaultRules(), DefaultConfig()), rulesPath, SemgrepLimits{})
	stub := &blockingSemgrep{called: make(chan struct{})}
	engine.execFn = stub.exec

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, _, err := engine.ScanDirectoryWithLinesContext(ctx, scanDir)
		errCh <- err
	}()

	<-stub.called
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("semgrep scan did not stop after cancellation")
	}
}
```

在 `cancel_test.go` 的 import 中加入 `"time"`。

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/codeaudit/ -run TestSemgrepCancelStopsTheRun -v`
Expected: FAIL — `ScanDirectoryWithLinesContext` 未在 `semgrepEngine` 上定义（编译错误）。

- [ ] **Step 3: 实现 semgrep context 贯通**

在 `semgrep_engine.go` 中替换以下函数：

```go
func (e *semgrepEngine) ScanDirectoryWithLines(dir string) (*Report, map[string]int, error) {
	return e.scan(context.Background(), dir, true)
}

// ScanDirectoryWithLinesContext is ScanDirectoryWithLines with the caller's
// cancellation attached to the whole pipeline, including the CLI subprocess.
func (e *semgrepEngine) ScanDirectoryWithLinesContext(ctx context.Context, dir string) (*Report, map[string]int, error) {
	return e.scan(ctx, dir, true)
}

func (e *semgrepEngine) scan(ctx context.Context, dir string, withLineCounts bool) (*Report, map[string]int, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("scan directory: %w", err)
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("%s is not a directory", dir)
	}

	targets, err := e.walkSourceFiles(ctx, dir)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, ctxErr
		}
		return nil, nil, err
	}

	var lineCounts map[string]int
	if withLineCounts {
		lineCounts, err = e.countLines(ctx, targets)
		if err != nil {
			return nil, nil, err
		}
	}

	if len(targets) == 0 {
		return e.stamp(e.scanner.buildReport(dir, 0, nil, false)), lineCounts, nil
	}

	output, err := e.run(ctx, targets)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, ctxErr
		}
		return nil, nil, err
	}

	findings, err := e.buildFindings(output, targets)
	if err != nil {
		return nil, nil, err
	}

	// The graph build has no cancellation of its own; check at the boundary so
	// a superseded audit does not start it at all, and so its possibly slow
	// fixed-point traversal does not begin after a cancel.
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	findings = enrichFindingsWithCPG(dir, targets, findings)
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	sortFindings(findings)

	truncated := false
	if len(findings) > e.scanner.config.MaxFindings {
		findings = findings[:e.scanner.config.MaxFindings]
		truncated = true
	}

	report := e.scanner.buildReport(dir, len(targets), findings, truncated)
	report.EngineVersion = output.Version
	report.ParserErrors = len(output.Errors)
	report.ProcessExitCode = 0
	return e.stamp(report), lineCounts, nil
}
```

替换 `walkSourceFiles` 与 `walkTargets`：

```go
func (e *semgrepEngine) walkSourceFiles(ctx context.Context, dir string) ([]string, error) {
	var targets []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if e.scanner != nil && e.scanner.config.SkipDirs != nil && e.scanner.config.SkipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !e.isSourceFile(path) {
			return nil
		}
		targets = append(targets, path)
		return nil
	})
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("walk directory: %w", err)
	}
	return targets, nil
}

func (e *semgrepEngine) walkTargets(dir string) ([]string, error) {
	return e.walkSourceFiles(context.Background(), dir)
}

func (e *semgrepEngine) countLines(ctx context.Context, targets []string) (map[string]int, error) {
	counts := make(map[string]int, len(targets))
	for _, path := range targets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		counts[path] = len(strings.Split(string(content), "\n"))
	}
	return counts, nil
}
```

替换 `run` 的开头：

```go
func (e *semgrepEngine) run(ctx context.Context, targets []string) (*semgrepOutput, error) {
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	stdout, exitCode, err := e.execFn(ctx, e.bin, e.semgrepArgs(targets))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("semgrep did not run: %w", err)
	}
```

其余 `run` 函数体保持不变。

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./internal/codeaudit/ -run TestSemgrepCancelStopsTheRun -v`
Expected: PASS。

- [ ] **Step 5: 全包回归**

Run: `go test ./internal/codeaudit/`
Expected: PASS。

- [ ] **Step 6: 提交**

```bash
git add internal/codeaudit/semgrep_engine.go internal/codeaudit/cancel_test.go
git commit -m "feat(codeaudit): thread cancellation through the semgrep scan"
```

---

### Task 3: 二进制通道支持取消

**Files:**
- Modify: `internal/codeaudit/binary_scanner.go:115-136`
- Modify: `internal/codeaudit/verifier.go:379`, `:485-500`
- Test: `internal/codeaudit/cancel_test.go`

- [ ] **Step 1: 写失败测试**

追加到 `internal/codeaudit/cancel_test.go`：

```go
// TestBinaryScannerCancelStopsWalk pins that a cancelled context aborts the
// binary walk immediately.
func TestBinaryScannerCancelStopsWalk(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "blob.bin"), []byte{0x7f, 'E', 'L', 'F'}, 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := NewBinaryScanner(nil, BinaryConfig{}).ScanDirectoryContext(ctx, dir)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}
```

在 import 中加入 `"os"`、`"path/filepath"`。

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/codeaudit/ -run TestBinaryScannerCancelStopsWalk -v`
Expected: FAIL — `ScanDirectoryContext` undefined.

- [ ] **Step 3: 实现**

在 `binary_scanner.go` 中把 `ScanDirectory` 函数整体替换为：

```go
func (s *BinaryScanner) ScanDirectory(dir string) (*BinaryScanResult, error) {
	return s.ScanDirectoryContext(context.Background(), dir)
}

// ScanDirectoryContext is ScanDirectory with cancellation: the walk returns
// ctx.Err() instead of a partial result.
func (s *BinaryScanner) ScanDirectoryContext(ctx context.Context, dir string) (*BinaryScanResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("scan directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}

	res := &BinaryScanResult{
		Summary: BinaryScanSummary{
			Kinds:       map[string]int{},
			MaxFindings: s.cfg.MaxFindings,
		},
		Evidence: map[string]*EvidenceSet{},
	}

	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		// (rest of the existing callback body unchanged)
```

保留回调其余内容不动，只把 `err := filepath.Walk` 改成 `err = filepath.Walk`，并在 `if err != nil` 分支前加：

```go
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("walk directory: %w", err)
	}
```

替换 `binary_scanner.go` 的 import 块，加入 `"context"`。

在 `verifier.go` 中替换 `runBinaryChannel` 并新增 context 版本（旧签名保留为委托，现有 `runBinaryChannel` 测试不用改）：

```go
func runBinaryChannel(dir string, binCfg BinaryConfig) *BinaryScanResult {
	return runBinaryChannelContext(context.Background(), dir, binCfg)
}

func runBinaryChannelContext(ctx context.Context, dir string, binCfg BinaryConfig) *BinaryScanResult {
	if !binCfg.Enabled {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return &BinaryScanResult{Summary: BinaryScanSummary{Errored: true}}
	}
	matcher, err := NewBinaryMatcher()
	if err != nil {
		log.Printf("binary channel: matcher build failed, pass withheld: %v", err)
		return &BinaryScanResult{Summary: BinaryScanSummary{Errored: true}}
	}
	res, err := NewBinaryScanner(matcher, binCfg).ScanDirectoryContext(ctx, dir)
	if err != nil {
		log.Printf("binary channel: scan failed, pass withheld: %v", err)
		return &BinaryScanResult{Summary: BinaryScanSummary{Errored: true}}
	}
	return res
}
```

并在 `GenerateAuditReport` 中把调用改为 `binaryRes := runBinaryChannelContext(ctx, dir, cfg.Binary)`。

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./internal/codeaudit/ -run TestBinaryScannerCancelStopsWalk -v`
Expected: PASS。

- [ ] **Step 5: 全包回归**

Run: `go test ./internal/codeaudit/`
Expected: PASS。

- [ ] **Step 6: 提交**

```bash
git add internal/codeaudit/binary_scanner.go internal/codeaudit/verifier.go internal/codeaudit/cancel_test.go
git commit -m "feat(codeaudit): make the binary scan cancelable"
```

---

### Task 4: controller 审计代际、中止与有界等待

**Files:**
- Modify: `internal/controller/route.go:106-180`（结构体字段）、`:604-700`（审计状态辅助）
- Create: `internal/controller/audit_abort_test.go`
- Test: `internal/controller/audit_abort_test.go`

- [ ] **Step 1: 写失败测试**

创建 `internal/controller/audit_abort_test.go`：

```go
package controller

import (
	"context"
	"sync"
	"testing"
	"time"

	"taa/internal/codeaudit"
)

// blockingAuditEngine blocks the audit's static scan until the audit context is
// cancelled. Every call blocks, so a test that starts two audits releases the
// second one explicitly.
type blockingAuditEngine struct {
	startedOnce sync.Once
	stoppedOnce sync.Once
	started     chan struct{}
	stopped     chan struct{}
}

func newBlockingAuditEngine() *blockingAuditEngine {
	return &blockingAuditEngine{
		started: make(chan struct{}),
		stopped: make(chan struct{}),
	}
}

func (e *blockingAuditEngine) ScanDirectory(dir string) (*codeaudit.Report, error) {
	return e.ScanDirectoryWithLinesContext(context.Background(), dir)
}

func (e *blockingAuditEngine) ScanDirectoryWithLines(dir string) (*codeaudit.Report, map[string]int, error) {
	return e.ScanDirectoryWithLinesContext(context.Background(), dir)
}

func (e *blockingAuditEngine) ScanDirectoryWithLinesContext(ctx context.Context, dir string) (*codeaudit.Report, map[string]int, error) {
	e.startedOnce.Do(func() { close(e.started) })
	<-ctx.Done()
	e.stoppedOnce.Do(func() { close(e.stopped) })
	return nil, nil, ctx.Err()
}

func (e *blockingAuditEngine) Name() string { return "blocking" }

// TestAbortModelAuditStopsTheRunningAudit pins that an abort cancels the scan,
// clears the durable pending marker, and leaves the audit fields idle.
func TestAbortModelAuditStopsTheRunningAudit(t *testing.T) {
	state, _ := setupTestState(t)
	store, _ := createTestStateStore(t)
	state.SetStateStore(store)
	state.Security.ScanEnabled = true
	engine := newBlockingAuditEngine()
	state.Security.Engine = engine

	req := importRequest{RequestID: "req-old", TaskID: "task-old"}
	state.mu.Lock()
	state.markModelAuditPendingLocked(req, 1)
	state.saveModelSuccessLocked("https://example.test/old.tar.gz")
	state.mu.Unlock()
	state.launchModelAudit(req)

	select {
	case <-engine.started:
	case <-time.After(5 * time.Second):
		t.Fatal("audit did not start")
	}

	state.abortModelAudit()

	select {
	case <-engine.stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("audit did not stop after abort")
	}
	state.waitAuditStopped()

	state.mu.RLock()
	defer state.mu.RUnlock()
	if state.AuditRunning || state.CurrentAuditOp != "idle" || state.ActiveAuditTaskID != "" {
		t.Fatalf("audit state not reset: running=%v op=%s task=%s",
			state.AuditRunning, state.CurrentAuditOp, state.ActiveAuditTaskID)
	}
	if state.pendingAudit != nil {
		t.Fatalf("pending audit marker survived abort: %+v", state.pendingAudit)
	}

	sealed, err := store.UnsealState()
	if err != nil {
		t.Fatalf("unseal state: %v", err)
	}
	if sealed.AuditPending != nil {
		t.Fatalf("the abort left a durable pending marker: %+v", sealed.AuditPending)
	}
}

// TestFinishAuditStaleGenerationKeepsTheNewAudit pins that the goroutine of an
// aborted audit cannot clear the state or the marker of the audit that replaced
// it.
func TestFinishAuditStaleGenerationKeepsTheNewAudit(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.ScanEnabled = true

	state.mu.Lock()
	state.auditGen++
	oldGen := state.auditGen
	oldDone := make(chan struct{})
	state.auditDone = oldDone
	state.mu.Unlock()

	state.mu.Lock()
	state.auditGen++
	state.auditDone = make(chan struct{})
	state.markModelAuditPendingLocked(importRequest{RequestID: "req-new", TaskID: "task-new"}, 1)
	state.mu.Unlock()

	state.finishAudit(oldGen, oldDone)

	state.mu.RLock()
	defer state.mu.RUnlock()
	if state.ActiveAuditTaskID != "task-new" || !state.AuditRunning {
		t.Fatalf("stale finish cleared the new audit state: running=%v task=%s",
			state.AuditRunning, state.ActiveAuditTaskID)
	}
	if state.pendingAudit == nil || state.pendingAudit.TaskID != "task-new" {
		t.Fatalf("stale finish cleared the new pending marker: %+v", state.pendingAudit)
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/controller/ -run 'TestAbortModelAuditStopsTheRunningAudit|TestFinishAuditStaleGenerationKeepsTheNewAudit' -v`
Expected: FAIL — `state.launchModelAudit` 签名存在但内部未注册代际；`finishAudit` / `waitAuditStopped` 未定义（编译错误）。

- [ ] **Step 3: 实现状态字段与辅助方法**

在 `internal/controller/route.go` 的 `TAAState` 中、`ActiveAuditRequestID` 之后加入：

```go
	// auditGen identifies the audit that currently owns the audit fields above.
	// Every audit goroutine carries the generation it started with; writes and
	// reports are dropped once the field no longer matches, so an aborted or
	// superseded audit cannot clear or overwrite its successor's state. It is
	// in-memory only and deliberately not persisted.
	auditGen    uint64
	auditCancel context.CancelFunc
	auditDone   chan struct{}
```

在 `route.go` 中 `resetAuditStateLocked` 之后加入：

```go
// isCurrentAuditGen reports whether gen still owns the audit state.
func (s *TAAState) isCurrentAuditGen(gen uint64) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.auditGen == gen
}

// finishAudit releases one audit goroutine's registration. The busy fields and
// the pending marker are cleared only when the generation still owns them; a
// stale goroutine must not erase the state of the audit that replaced it.
func (s *TAAState) finishAudit(gen uint64, done chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.auditDone == done {
		s.auditDone = nil
		s.auditCancel = nil
	}
	if s.auditGen != gen {
		return
	}
	s.resetAuditStateLocked()
	if s.pendingAudit != nil {
		s.clearAuditPendingLocked()
		if err := s.sealStateLocked(); err != nil {
			s.Logs.Add(LogError, "state", "持久化审计结论状态失败: %v", err)
		}
	}
}

// abortModelAudit cancels the running model audit, if any. It is silent: no
// platform callback is sent. The durable marker is dropped so a restart does
// not report an audit that was deliberately abandoned.
//
// The generation is incremented before the cancel, so every later write from
// the old goroutine (state, last audit, platform report) fails its ownership
// check even if it was already past the context check.
func (s *TAAState) abortModelAudit() {
	s.mu.Lock()
	if !s.isAuditBusyLocked() {
		s.mu.Unlock()
		return
	}
	oldTask := s.ActiveAuditTaskID
	oldRequest := s.ActiveAuditRequestID
	s.auditGen++
	s.resetAuditStateLocked()
	s.clearAuditPendingLocked()
	if err := s.sealStateLocked(); err != nil {
		s.Logs.Add(LogError, "state", "持久化审计中止状态失败: %v", err)
	}
	cancel := s.auditCancel
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	s.Logs.Add(LogInfo, "audit", "模型代码审计已中止: 收到新的模型下发; 旧 taskId=%s, requestId=%s", oldTask, oldRequest)
}

// auditAbortWaitTimeout bounds how long an import waits for the aborted audit to
// leave the model directory before overwriting it.
const auditAbortWaitTimeout = 30 * time.Second

// waitAuditStopped waits for the audit goroutine to exit before ModelDir is
// replaced. A superseded audit's result is discarded either way, so a timeout
// only logs: blocking the import forever on a scan that refuses to die would
// defeat the point of aborting it.
func (s *TAAState) waitAuditStopped() {
	s.mu.RLock()
	done := s.auditDone
	s.mu.RUnlock()
	if done == nil {
		return
	}

	timer := time.NewTimer(auditAbortWaitTimeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		s.Logs.Add(LogWarn, "audit",
			"旧模型审计未在 %s 内退出，继续覆盖模型目录；其结论已被代际号作废", auditAbortWaitTimeout)
	}
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./internal/controller/ -run 'TestAbortModelAuditStopsTheRunningAudit|TestFinishAuditStaleGenerationKeepsTheNewAudit' -v`
Expected: PASS（`launchModelAudit` 已在 Task 5 改造；若此步编译失败，先完成 Task 5 的 `launchModelAudit`，再回到本步）。

> 实现顺序说明：Task 4 与 Task 5 共享 `launchModelAudit`，两个任务应连续完成后再跑本步测试。

- [ ] **Step 5: 提交**

```bash
git add internal/controller/route.go internal/controller/audit_abort_test.go
git commit -m "feat(controller): track audit generations and abort a running audit"
```

---

### Task 5: 可取消的审计流水线与代际校验上报

**Files:**
- Modify: `internal/controller/import_processing.go:659-760`, `:793-820`, `:832-880`
- Modify: `internal/controller/route.go:604-610`, `:879-914`
- Modify: `internal/controller/codeaudit_projection.go:9-13`
- Test: `internal/controller/audit_abort_test.go`, `internal/controller/audit_model_import_test.go`

- [ ] **Step 1: 写失败测试（静默中止）**

追加到 `internal/controller/audit_abort_test.go`：

```go
// TestAbortedAuditDoesNotReport pins the silent-abort decision: the old audit
// must not reach the platform, even though it was interrupted rather than
// completed.
func TestAbortedAuditDoesNotReport(t *testing.T) {
	state, _ := setupTestState(t)
	state.Security.ScanEnabled = true
	engine := newBlockingAuditEngine()
	state.Security.Engine = engine

	reports := make(chan reportRequest, 4)
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == reportAuditEndpoint {
			var rr reportRequest
			_ = json.NewDecoder(r.Body).Decode(&rr)
			reports <- rr
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer platform.Close()
	state.PlatformIP = platform.URL
	state.DockerID = "docker-test"

	req := importRequest{RequestID: "req-old", TaskID: "task-old"}
	state.launchModelAudit(req)
	select {
	case <-engine.started:
	case <-time.After(5 * time.Second):
		t.Fatal("audit did not start")
	}

	state.abortModelAudit()
	state.waitAuditStopped()

	select {
	case rr := <-reports:
		t.Fatalf("aborted audit reported to the platform: %+v", rr)
	case <-time.After(300 * time.Millisecond):
	}
}
```

在 import 中加入 `"encoding/json"`、`"net/http"`、`"net/http/httptest"`。

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/controller/ -run TestAbortedAuditDoesNotReport -v`
Expected: FAIL — 当前审计使用 `context.Background()`，取消不会生效，测试超时或收到上报。

- [ ] **Step 3: 实现代际校验写入与上报**

在 `internal/controller/codeaudit_projection.go` 中替换 `setLastAudit`：

```go
func (s *TAAState) setLastAudit(gen uint64, audit *codeaudit.AuditReport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.auditGen != gen {
		return
	}
	s.LastAudit = audit
}
```

在 `route.go` 中替换 `setCurrentAuditOp`：

```go
func (s *TAAState) setCurrentAuditOp(gen uint64, op string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.auditGen != gen {
		return
	}
	s.CurrentAuditOp = op
	s.AuditRunning = (op != "idle" && op != "")
}
```

在 `route.go` 中替换 `concludeAuditPending` 与导出的 `ConcludeAuditPending`：

```go
func (s *TAAState) concludeAuditPending(gen uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.auditGen != gen || s.pendingAudit == nil {
		return
	}
	s.clearAuditPendingLocked()
	if err := s.sealStateLocked(); err != nil {
		s.Logs.Add(LogError, "state", "持久化审计结论状态失败: %v", err)
	}
}

// ConcludeAuditPending 导出供启动期对账使用。恢复路径没有并发审计，不需要代际校验。
func (s *TAAState) ConcludeAuditPending() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pendingAudit == nil {
		return
	}
	s.clearAuditPendingLocked()
	if err := s.sealStateLocked(); err != nil {
		s.Logs.Add(LogError, "state", "持久化审计结论状态失败: %v", err)
	}
}
```

在 `route.go` 中新增 `handleAuditPanic`，并从 `handleAsyncPanic` 删除 `if name == "modelAudit" { ... }` 整段（约 `:884-914`）：

```go
// handleAuditPanic is the model audit's panic recovery. A panic in a superseded
// audit is not reported: the audit that replaced it owns the task ids now.
func (s *TAAState) handleAuditPanic(gen uint64, req importRequest, r any) {
	panicMsg := fmt.Sprintf("%v", r)
	s.Logs.Add(LogError, "panic", "modelAudit 发生异常恢复: %v", r)
	log.Printf("[PANIC RECOVERY] modelAudit recovered from panic: %v", r)

	s.mu.Lock()
	if s.auditGen != gen {
		s.mu.Unlock()
		return
	}
	taskID := s.ActiveAuditTaskID
	requestID := s.ActiveAuditRequestID
	if taskID == "" {
		taskID = req.TaskID
	}
	if requestID == "" {
		requestID = req.RequestID
	}
	platformIP := s.PlatformIP
	dockerID := s.DockerID
	s.auditGen++
	s.resetAuditStateLocked()
	s.clearAuditPendingLocked()
	if err := s.sealStateLocked(); err != nil {
		s.Logs.Add(LogError, "panic", "持久化审计中断状态失败: %v", err)
	}
	s.mu.Unlock()

	if platformIP != "" && dockerID != "" && (taskID != "" || requestID != "") {
		s.reportAuditAsync(requestID, taskID, 2, fmt.Sprintf("model audit panic: %s", panicMsg), "")
	}
}
```

- [ ] **Step 4: 改造审计启动与执行**

在 `internal/controller/import_processing.go` 中替换 `launchModelAudit`：

```go
func (s *TAAState) launchModelAudit(req importRequest) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	s.mu.Lock()
	s.auditGen++
	gen := s.auditGen
	s.auditCancel = cancel
	s.auditDone = done
	s.mu.Unlock()

	go func() {
		defer close(done)
		defer s.finishAudit(gen, done)
		defer func() {
			if r := recover(); r != nil {
				s.handleAuditPanic(gen, req, r)
			}
		}()
		if !s.auditAndReportModelImport(ctx, gen, req) {
			s.Logs.Add(LogWarn, "import", "模型代码审计未通过或已中止，结论仅作参考，不阻断导入与训练: taskId=%s", req.TaskID)
		}
	}()
}
```

替换 `auditAndReportModelImport` 签名与状态写入（其余审计逻辑不变）：

```go
func (s *TAAState) auditAndReportModelImport(ctx context.Context, gen uint64, req importRequest) bool {
	defer s.concludeAuditPending(gen)

	s.setLastAudit(gen, nil)
	if !s.Security.ScanEnabled {
		s.Logs.Add(LogInfo, "audit", "安全扫描未启用，跳过模型代码审计")
		return true
	}

	cfg := s.Security.LLM
	StepSeparator("Code Audit")
	s.setCurrentAuditOp(gen, "auditing")
	defer s.setCurrentAuditOp(gen, "idle")
	s.Logs.Add(LogInfo, "audit", "开始模型代码审计: engine=%s, dir=%s, llmEnabled=%v, failClosed=%v",
		engineName(s.Security.Engine), s.Security.ModelDir, cfg.Enabled, cfg.FailClosed)

	llmClient := newLLMClient(cfg)

	if cfg.Enabled && cfg.FailClosed && !isLLMServiceAvailable(ctx, llmClient, cfg.Endpoint, cfg.Model) {
		if ctx.Err() != nil || !s.isCurrentAuditGen(gen) {
			s.logAuditAborted(req)
			return false
		}
		s.Logs.Add(LogError, "audit", "LLM 服务不可用，按 fail-closed 策略上报失败: endpoint=%s model=%s", cfg.Endpoint, cfg.Model)
		s.Logs.Add(LogWarn, "audit", "审计未通过：仅上报结论，未删除或改动模型包与依赖库: dir=%s", s.Security.ModelDir)
		s.reportAuditIfCurrent(gen, req.RequestID, req.TaskID, 2, "LLM 服务不可用，按 fail-closed 策略上报失败", "")
		return false
	}

	audit, err := codeaudit.GenerateAuditReport(ctx, s.Security.ModelDir, s.Security.Engine,
		codeaudit.AuditConfig{LLM: cfg, Binary: s.Security.Binary}, llmClient)
	if err != nil {
		if ctx.Err() != nil || !s.isCurrentAuditGen(gen) {
			s.logAuditAborted(req)
			return false
		}
		s.Logs.Add(LogError, "audit", "模型代码审计失败: %v", err)
		s.Logs.Add(LogWarn, "audit", "审计未通过：仅上报结论，未删除或改动模型包与依赖库: dir=%s", s.Security.ModelDir)
		s.reportAuditIfCurrent(gen, req.RequestID, req.TaskID, 2, fmt.Sprintf("代码审计失败: %v", err), "")
		return false
	}
	if ctx.Err() != nil || !s.isCurrentAuditGen(gen) {
		s.logAuditAborted(req)
		return false
	}
	s.setLastAudit(gen, audit)

	code := 0
	msg := audit.Conclusion.Summary
	passed := audit.Conclusion.Passed
	if !passed {
		code = 1
		s.Logs.Add(LogWarn, "audit", "审计未通过：仅上报结论，未删除或改动模型包与依赖库: dir=%s", s.Security.ModelDir)
	}
	s.Logs.Add(LogInfo, "audit", "审计完成: passed=%v, riskLevel=%s, totalFindings=%d",
		audit.Conclusion.Passed, audit.Conclusion.RiskLevel, audit.Conclusion.Statistics.Total())
	if audit.ScanMetadata.Binary != nil {
		b := audit.ScanMetadata.Binary
		s.Logs.Add(LogInfo, "audit", "二进制审计: files=%d kinds=%v boundedExecutable=%d boundedData=%d incomplete=%d errored=%v findingsCapped=%v findingsDropped=%d",
			b.FilesCount, b.Kinds, b.BoundedExecutable, b.BoundedData, b.Incomplete, b.Errored, b.FindingsCapped, b.FindingsDropped)
	}

	s.reportAuditIfCurrent(gen, req.RequestID, req.TaskID, code, msg, auditReportJSON(audit))
	return passed
}

func (s *TAAState) logAuditAborted(req importRequest) {
	s.Logs.Add(LogInfo, "audit", "模型代码审计已中止: 收到新的模型下发或状态已被取代; taskId=%s, requestId=%s",
		req.TaskID, req.RequestID)
}
```

- [ ] **Step 5: 上报加代际校验**

在 `import_processing.go` 中替换 `reportAuditAsync` 并新增 `reportAuditIfCurrent`：

```go
// reportAuditAsync 异步将模型代码安全审计结果上报平台（无代际校验）。
func (s *TAAState) reportAuditAsync(requestID, taskID string, code int, msg, report string) {
	s.mu.RLock()
	platformIP, dockerID := s.PlatformIP, s.DockerID
	s.mu.RUnlock()

	log.Printf("reportAuditAsync: scheduling audit report upload, platformIP=%s, dockerID=%s, requestID=%s, taskID=%s, code=%d, reportLen=%d",
		platformIP, dockerID, requestID, taskID, code, len(report))
	go s.sendAuditReport(platformIP, dockerID, requestID, taskID, code, msg, report)
}

// reportAuditIfCurrent schedules the report only while gen still owns the
// audit. The check runs inside the goroutine, immediately before the request,
// so an abort that lands after the audit's last context check still drops the
// verdict.
func (s *TAAState) reportAuditIfCurrent(gen uint64, requestID, taskID string, code int, msg, report string) {
	s.mu.RLock()
	platformIP, dockerID := s.PlatformIP, s.DockerID
	s.mu.RUnlock()

	log.Printf("reportAuditIfCurrent: scheduling audit report, platformIP=%s, dockerID=%s, requestID=%s, taskID=%s, code=%d, reportLen=%d",
		platformIP, dockerID, requestID, taskID, code, len(report))
	go func() {
		s.mu.RLock()
		current := s.auditGen == gen
		s.mu.RUnlock()
		if !current {
			log.Printf("reportAuditIfCurrent: dropping stale audit report: requestID=%s taskID=%s", requestID, taskID)
			return
		}
		s.sendAuditReport(platformIP, dockerID, requestID, taskID, code, msg, report)
	}()
}

func (s *TAAState) sendAuditReport(platformIP, dockerID, requestID, taskID string, code int, msg, report string) {
	if err := ReportAudit(context.Background(), platformIP, dockerID, requestID, taskID, code, msg, report); err != nil {
		log.Printf("reportAuditAsync: report audit result failed: requestID=%s taskID=%s, err=%v", requestID, taskID, err)
		return
	}
	log.Printf("reportAuditAsync: report audit result succeeded: requestID=%s taskID=%s", requestID, taskID)
}
```

- [ ] **Step 6: 健康探测接收 ctx**

在 `import_processing.go` 中替换 `isLLMServiceAvailable` 与 `llmAvailable`：

```go
func isLLMServiceAvailable(ctx context.Context, client codeaudit.LLMClient, endpoint, model string) bool {
	if client != nil {
		probeCtx, cancel := context.WithTimeout(ctx, auditLLMHealthCheckTimeout)
		defer cancel()
		if err := client.HealthCheck(probeCtx); err != nil {
			log.Printf("isLLMServiceAvailable: health check failed: endpoint=%s model=%s timeout=%s error=%v",
				endpoint, model, auditLLMHealthCheckTimeout, err)
			return false
		}
		return true
	}
	return llmAvailable(ctx, endpoint, model)
}

func llmAvailable(ctx context.Context, endpoint, model string) bool {
	if strings.TrimSpace(endpoint) == "" {
		return false
	}
	base := endpoint
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "http://" + base
	}
	base = strings.TrimRight(base, "/")

	tagsClient := &http.Client{Timeout: 3 * time.Second}
	tagsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/tags", nil)
	if err != nil {
		return false
	}
	resp, err := tagsClient.Do(tagsReq)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	body, _ := io.ReadAll(resp.Body)
	if model != "" && !strings.Contains(string(body), model) {
		return false
	}

	if model != "" {
		probeClient := &http.Client{Timeout: auditLLMHealthCheckTimeout}
		probePayload := fmt.Sprintf(`{"model":%q,"prompt":"ping","stream":false,"options":{"num_predict":1}}`, model)
		probeReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/generate", strings.NewReader(probePayload))
		if err != nil {
			return false
		}
		probeReq.Header.Set("Content-Type", "application/json")
		genResp, err := probeClient.Do(probeReq)
		if err != nil {
			return false
		}
		defer genResp.Body.Close()
		if genResp.StatusCode != http.StatusOK {
			return false
		}
	}

	return true
}
```

- [ ] **Step 7: 更新受签名影响的测试**

`internal/controller/audit_model_import_test.go`：
- 把每处 `state.auditAndReportModelImport(importRequest{...})` 改为 `state.auditAndReportModelImport(context.Background(), 0, importRequest{...})`；
- 把 `isLLMServiceAvailable(client, ...)` 改为 `isLLMServiceAvailable(context.Background(), client, ...)`；
- 把 `llmAvailable(url, model)` 改为 `llmAvailable(context.Background(), url, model)`；
- 文件 import 加入 `"context"`（若尚无）。

`internal/controller/concurrency_test.go`：`TestConcurrency_AuditPanicKeepsModelAndTrainingTask` 设置 `state.auditGen = 7` 并调用
`state.handleAuditPanic(7, importRequest{RequestID: "req-audit-panicking", TaskID: "task-audit-panicking"}, "simulated audit failure")`
替代 `handleAsyncPanic("modelAudit", ...)`。

- [ ] **Step 8: 跑测试**

Run: `go test ./internal/controller/ -run 'TestAbortedAuditDoesNotReport|TestAbortModelAuditStopsTheRunningAudit|TestFinishAuditStaleGenerationKeepsTheNewAudit|TestFailedAuditLeavesTheImportedPackageUntouched|TestLLMAvailable|TestIsLLMServiceAvailable|TestAuditAndReportModelImport|TestAuditStartLogNamesTheEngine|TestConcurrency_AuditPanicKeepsModelAndTrainingTask' -v`
Expected: PASS。

- [ ] **Step 9: 提交**

```bash
git add internal/controller/route.go internal/controller/import_processing.go internal/controller/codeaudit_projection.go internal/controller/audit_model_import_test.go internal/controller/concurrency_test.go internal/controller/audit_abort_test.go
git commit -m "feat(controller): cancel and generation-gate the model audit"
```

---

### Task 6: 模型导入受理时中止旧审计，覆盖前等待退出

**Files:**
- Modify: `internal/controller/route.go:765-790`（删除审计闸门）
- Modify: `internal/controller/handler_task.go:466-472`
- Modify: `internal/controller/import_processing.go:88-100`
- Test: `internal/controller/concurrency_test.go`, `internal/controller/audit_abort_test.go`

- [ ] **Step 1: 写失败测试**

替换 `internal/controller/concurrency_test.go` 中的 `TestConcurrency_ModelImportRejectedWhileAuditing` 为：

```go
// TestConcurrency_ModelImportNotBlockedByAuditing pins that a running audit no
// longer refuses a model import: the new import is what cancels that audit.
func TestConcurrency_ModelImportNotBlockedByAuditing(t *testing.T) {
	state, server := setupTestServer(t)

	state.mu.Lock()
	state.AuditRunning = true
	state.CurrentAuditOp = "auditing"
	state.ActiveAuditTaskID = "contract-model-import-task-01"
	state.ActiveAuditRequestID = "contract-model-import-req-01"
	state.mu.Unlock()

	release, err := state.tryAcquireTask("task-model-02", "req-model-02", "downloading", true)
	if err != nil {
		t.Fatalf("model import was refused while an audit was running: %v", err)
	}
	release()

	resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
		"resourceUrl": "http://127.0.0.1:1/model2.tar.gz",
		"requestId":   "req-model-02b",
		"taskId":      "task-model-02b",
	})
	api := decodeResponse(t, resp)
	if resp.StatusCode == http.StatusConflict || api.Error == http.StatusConflict {
		t.Fatalf("model import returned 409 while an audit was running: %s", api.Msg)
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/controller/ -run TestConcurrency_ModelImportNotBlockedByAuditing -v`
Expected: FAIL — 仍返回 409「当前已有模型代码审计正在执行中」。

- [ ] **Step 3: 删除审计闸门并接入中止**

在 `internal/controller/route.go` 的 `tryAcquireTask` 中删除整段（含注释）：

```go
	// 2. If requesting model import, ensure no previous model code audit is actively running.
	// Data import and training are decoupled from model audit and can proceed concurrently.
	if isModel && s.isAuditBusyLocked() {
		auditTask := s.ActiveAuditTaskID
		if auditTask == "" {
			auditTask = "model_audit"
		}
		return nil, pkgerrors.New(pkgerrors.CodeConflict,
			fmt.Sprintf("当前已有模型代码审计正在执行中 (taskId: %s, op: auditing)，请等待完成后再提交", auditTask))
	}
```

并把后续注释编号从 `// 3.` 改为 `// 2.`。

在 `internal/controller/handler_task.go` 的 `tryAcquireTask` 成功之后、`s.mu.Lock()` 之前加入：

```go
	// A new model replaces the one the running audit is judging. Cancel that
	// audit before the download, so its scan releases the CPU at once; the
	// model directory itself is not touched until the async stage has waited
	// for the goroutine to exit.
	s.abortModelAudit()
```

在 `internal/controller/import_processing.go` 模型分支的 `extractArchiveToDir` 之前加入：

```go
		// The previous model's audit reads ModelDir. Let it stop before the
		// directory is removed and replaced; a scan racing this overwrite would
		// read a tree that is being deleted. Bounded, because a superseded
		// audit's verdict is discarded either way.
		s.waitAuditStopped()
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./internal/controller/ -run 'TestConcurrency_ModelImportNotBlockedByAuditing|TestConcurrency_ModelImportRejectedWhenTrainingBusy' -v`
Expected: PASS（第二个测试确认训练互斥未被误删）。

- [ ] **Step 5: 提交**

```bash
git add internal/controller/route.go internal/controller/handler_task.go internal/controller/import_processing.go internal/controller/concurrency_test.go
git commit -m "feat(controller): accept a model import that replaces an auditing model"
```

---

### Task 7: 端到端测试（中止 → 覆盖 → 重新审计）

**Files:**
- Test: `internal/controller/audit_abort_test.go`

- [ ] **Step 1: 写失败测试**

追加到 `internal/controller/audit_abort_test.go`：

```go
// TestModelImportReplacesAuditingModelAndAuditsAgain is the whole contract:
// the old audit is cancelled, the archive replaces ModelDir, and a new audit is
// launched under the new request ids, while the platform receives nothing for
// the aborted audit.
func TestModelImportReplacesAuditingModelAndAuditsAgain(t *testing.T) {
	state, server := setupTestServer(t)
	store, _ := createTestStateStore(t)
	state.SetStateStore(store)
	engine := newBlockingAuditEngine()
	state.Security.Engine = engine
	state.Security.ScanEnabled = true

	var mu sync.Mutex
	var auditReports []reportRequest
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == reportAuditEndpoint {
			var rr reportRequest
			_ = json.NewDecoder(r.Body).Decode(&rr)
			mu.Lock()
			auditReports = append(auditReports, rr)
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer platform.Close()
	state.PlatformIP = platform.URL
	state.DockerID = "docker-test"

	oldReq := importRequest{RequestID: "req-old", TaskID: "task-old"}
	state.mu.Lock()
	state.markModelAuditPendingLocked(oldReq, 1)
	state.saveModelSuccessLocked("https://example.test/old.tar.gz")
	state.mu.Unlock()
	state.launchModelAudit(oldReq)
	select {
	case <-engine.started:
	case <-time.After(5 * time.Second):
		t.Fatal("old audit did not start")
	}

	archive := buildTarGzArchive(t, map[string]archiveEntry{
		"bundle/train.py": {mode: 0o755, data: []byte("print('new model')\n")},
	})
	ciphertext, keyHex := urlKeyResource(t, &state.SM2PrivateKey.PublicKey, archive)
	fileServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(ciphertext)
	}))
	defer fileServer.Close()

	resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
		"resourceUrl":   fileServer.URL + "/model-package.tar.gz?dataKeyCipher=" + keyHex,
		"requestId":     "req-new",
		"taskId":        "task-new",
		"runtimeConfig": makeRuntimeConfigJSON(t, []string{"python3", "train.py"}, nil),
	})
	api := decodeResponse(t, resp)
	if resp.StatusCode == http.StatusConflict || api.Error == http.StatusConflict {
		t.Fatalf("model import during audit returned 409: %s", api.Msg)
	}

	select {
	case <-engine.stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("old audit was not cancelled")
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		state.mu.RLock()
		pending := state.pendingAudit
		state.mu.RUnlock()
		if pending != nil && pending.TaskID == "task-new" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the new audit was not launched for the new model")
		}
		time.Sleep(10 * time.Millisecond)
	}

	got, err := os.ReadFile(filepath.Join(state.Security.ModelDir, "bundle", "train.py"))
	if err != nil {
		t.Fatalf("read replaced model: %v", err)
	}
	if !strings.Contains(string(got), "new model") {
		t.Fatalf("model directory was not replaced: %q", got)
	}

	mu.Lock()
	for _, rr := range auditReports {
		if rr.RequestID == "req-old" || rr.TaskID == "task-old" {
			mu.Unlock()
			t.Fatalf("aborted audit was reported to the platform: %+v", rr)
		}
	}
	mu.Unlock()

	// Release the second blocking audit and wait for it, so it cannot outlive
	// the test's TempDir cleanup.
	state.abortModelAudit()
	state.waitAuditStopped()
}

// TestModelImportDownloadFailureAfterAbortRollsBack pins the failure path: the
// old audit has already been aborted when the download fails, the imported flag
// is rolled back, and no audit verdict is sent for the old model.
func TestModelImportDownloadFailureAfterAbortRollsBack(t *testing.T) {
	state, server := setupTestServer(t)
	engine := newBlockingAuditEngine()
	state.Security.Engine = engine
	state.Security.ScanEnabled = true

	var mu sync.Mutex
	var auditReports []reportRequest
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == reportAuditEndpoint {
			var rr reportRequest
			_ = json.NewDecoder(r.Body).Decode(&rr)
			mu.Lock()
			auditReports = append(auditReports, rr)
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer platform.Close()
	state.mu.Lock()
	state.PlatformIP = platform.URL
	state.DockerID = "docker-test"
	state.ModelImported = true
	state.mu.Unlock()

	oldReq := importRequest{RequestID: "req-old", TaskID: "task-old"}
	state.mu.Lock()
	state.markModelAuditPendingLocked(oldReq, 1)
	state.mu.Unlock()
	state.launchModelAudit(oldReq)
	select {
	case <-engine.started:
	case <-time.After(5 * time.Second):
		t.Fatal("old audit did not start")
	}

	fileServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer fileServer.Close()

	resp := postJSON(t, server.URL+"/v1/taa/importModel", map[string]any{
		"resourceUrl":   fileServer.URL + "/missing.tar.gz",
		"requestId":     "req-new",
		"taskId":        "task-new",
		"runtimeConfig": makeRuntimeConfigJSON(t, []string{"python3", "train.py"}, nil),
	})
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("download failure status = %d, want 500", resp.StatusCode)
	}

	select {
	case <-engine.stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("old audit was not cancelled before the failed download")
	}
	state.waitAuditStopped()

	state.mu.RLock()
	imported := state.ModelImported
	state.mu.RUnlock()
	if imported {
		t.Fatal("ModelImported stayed true after the download failed")
	}

	mu.Lock()
	for _, rr := range auditReports {
		if rr.RequestID == "req-old" || rr.TaskID == "task-old" {
			mu.Unlock()
			t.Fatalf("aborted audit was reported to the platform: %+v", rr)
		}
	}
	mu.Unlock()
}
```

在 import 中加入 `"os"`、`"path/filepath"`、`"strings"`。

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/controller/ -run 'TestModelImportReplacesAuditingModelAndAuditsAgain|TestModelImportDownloadFailureAfterAbortRollsBack' -v`
Expected: 在实现完成前失败（409 或旧审计未取消）。

- [ ] **Step 3: 若测试失败，定位并修正**

该测试依赖 Task 4–6 全部完成；失败时按断言逐项检查：`tryAcquireTask` 闸门、`abortModelAudit` 调用位置、`waitAuditStopped` 位置、`beginModelImportAndAudit` 的新标记。

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./internal/controller/ -run 'TestModelImportReplacesAuditingModelAndAuditsAgain|TestModelImportDownloadFailureAfterAbortRollsBack' -v`
Expected: PASS。

- [ ] **Step 5: 提交**

```bash
git add internal/controller/audit_abort_test.go
git commit -m "test(controller): cover replacing an auditing model end to end"
```

---

### Task 8: 文档与全量回归

**Files:**
- Modify: `docs/api-design.md:1084`
- Test: 全仓库

- [ ] **Step 1: 更新文档**

把 `docs/api-design.md:1084` 的 409 说明替换为：

```markdown
其余 409 场景：`resourceUrl` 非空时，已有其他任务在飞（`当前已有任务正在执行中`）。模型代码审计与训练并行：审计进行中**不阻止**新的模型下发——新模型会中止旧模型的审计（静默中止，不回调 `reportAudit`），下载并覆盖模型目录后，对新模型重新发起审计。训练任务进行中仍会拒绝模型下发。
```

- [ ] **Step 2: 全仓库测试**

Run: `go test ./...`
Expected: PASS。

- [ ] **Step 3: 并发与数据竞争检查**

Run: `go test -race ./internal/controller/... ./internal/codeaudit/...`
Expected: PASS，无 data race 报告。

- [ ] **Step 4: 静态构建**

Run: `CGO_ENABLED=0 GOOS=linux go build -o bin/taa ./cmd/taa`
Expected: 退出码 0。

- [ ] **Step 5: 提交**

```bash
git add docs/api-design.md
git commit -m "docs(api): document model re-import during an audit"
```

---

## Self-Review

- **Spec coverage:** 取消贯通（Task 1–3）、中止入口与代际（Task 4–5）、静默不回调（Task 5 测试）、覆盖前等待（Task 6）、重新审计与新标记（Task 7）、文档（Task 8）。
- **签名一致性:** `ScanDirectoryWithLinesContext(ctx, dir)`、`ScanDirectoryContext(ctx, dir)`、`auditAndReportModelImport(ctx, gen, req)`、`setCurrentAuditOp(gen, op)`、`setLastAudit(gen, audit)`、`concludeAuditPending(gen)`、`isLLMServiceAvailable(ctx, client, endpoint, model)` 在测试与实现中同名同参。
- **已知例外:** `reportAuditAsync` 保持无代际签名供 panic 路径使用；正常裁决走 `reportAuditIfCurrent(gen, ...)`。
- **无占位符:** 每个代码步骤均给出可直接粘贴的实现或完整替换片段。
