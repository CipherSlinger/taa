# macOS 打包元数据兼容 Implementation Plan

**Goal:** 解压时丢弃 `__MACOSX` / `._*` / `.DS_Store`，并在 regex、semgrep、二进制三个扫描 walk 中兜底，使 macOS 打包的模型包不再因元数据导致审计失败。

**Architecture:** 新增无依赖的 `pkg/archiveentry` 作为唯一判定；`internal/resource` 在 zip/tar 条目写盘前过滤；`internal/codeaudit` 在三个 walk 中跳过同名条目，并把 `__MACOSX` 加入共享 `SkipDirs`。

**Spec:** `.claude/specs/2026-11-02-macos-archive-metadata-design.md`

---

## File Structure

| 文件 | 责任 |
| --- | --- |
| `pkg/archiveentry/archiveentry.go`（新建） | `IsMetadataPath` 判定 |
| `pkg/archiveentry/archiveentry_test.go`（新建） | 判定表测试 |
| `internal/resource/archive.go` | zip/tar 条目过滤 + 跳过计数日志 |
| `internal/resource/archive_test.go` | zip/tar 元数据剥离测试 |
| `internal/codeaudit/scanner.go` | `__MACOSX` 进 SkipDirs；两个 walk 跳过元数据 |
| `internal/codeaudit/semgrep_engine.go` | `walkSourceFiles` 跳过元数据 |
| `internal/codeaudit/binary_scanner.go` | 二进制 walk 跳过元数据 |
| `internal/codeaudit/*_test.go` | 三个 walk 的扫描目标断言 |
| `CHANGELOG.md` | 记录行为变更与原因 |

## Tasks

- [x] **Task 1: 共享判定**
  - [x] 实现 `pkg/archiveentry.IsMetadataPath`（反斜杠归一化、`__MACOSX` 段、`._` 前缀、`.DS_Store`）。
  - [x] 表测试覆盖：`__MACOSX/._x.py`、`pkg/__MACOSX/x.py`、`__macosx`、任意层级 `._x.py`、`.DS_Store`、正常源码、名字近似但非元数据（`__MACOSX_notes.py`）。

- [x] **Task 2: 解压剥离**
  - [x] `ExtractZipArchive` 跳过元数据条目并计数。
  - [x] `ExtractTarStream` 同样处理；EOF 改为 `break` 后统一写日志。
  - [x] 测试：真实源码保留，元数据文件与 `__MACOSX/` 目录均不存在。

- [x] **Task 3: 扫描兜底**
  - [x] `DefaultConfig().SkipDirs` 增加 `__MACOSX`。
  - [x] regex 两个 walk、semgrep `walkSourceFiles`、二进制 walk 调用判定并 `SkipDir`。
  - [x] 测试：三个引擎在含元数据的目录上，目标集合/claim 集合干净。

- [x] **Task 4: 验证与收尾**
  - [x] `go test ./internal/resource/ ./internal/codeaudit/ ./pkg/...`
  - [x] `gofmt -w`、`go vet`
  - [x] CHANGELOG 条目；提交（Conventional Commits，英文，无 AI 署名）。
