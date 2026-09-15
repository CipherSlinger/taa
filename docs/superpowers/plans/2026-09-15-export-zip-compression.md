# TAA 结果导出 ZIP 压缩实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将 TAA 结果导出接口（`/v1/taa/export`）的底层打包压缩格式由 `tar.gz` 彻底重构为 `zip` 格式（包含明文 `.zip` 与加密 `.zip.enc`），保留软链接逃逸防御，并同步更新测试与文档。

**Architecture:** 在 `internal/controller/route.go` 中实现具备符号链接越界安全校验的 `compressDirToZip` 函数，在 `exportHandler` 中替换旧有的 `compressDirToTarGz` 打包调用；文件名及响应头从 `.tar.gz` 适配为 `.zip`；在测试套件中引入 `extractZipMap` 并调整断言，确保全流程测试覆盖。

**Tech Stack:** Go 1.22+, `archive/zip`, `crypto/subtle`, `taa/pkg/crypto`.

---

### Task 1: 实现具备软链接安全防护的 `compressDirToZip` 函数

**Files:**
- Modify: `internal/controller/security_hardening_test.go:150-165`
- Modify: `internal/controller/route.go:1390-1480`

- [ ] **Step 1: 在 `security_hardening_test.go` 中编写失败测试**

修改 `internal/controller/security_hardening_test.go` 中的 `TestSecurity_ExportSymlinkEscapeDefense`，将其调用的 `compressDirToTarGz` 改为 `compressDirToZip`：

```go
func TestSecurity_ExportSymlinkEscapeDefense(t *testing.T) {
	srcDir := t.TempDir()
	outDir := t.TempDir()

	// 构造越界软链接指向临时目录外部
	escapeTarget := filepath.Join(outDir, "secret.txt")
	if err := os.WriteFile(escapeTarget, []byte("sensitive-data"), 0600); err != nil {
		t.Fatalf("failed to write secret file: %v", err)
	}

	symlinkPath := filepath.Join(srcDir, "evil_link")
	if err := os.Symlink(escapeTarget, symlinkPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	_, err := compressDirToZip(srcDir)
	if err == nil {
		t.Fatalf("expected error on symlink escape, but compressDirToZip succeeded")
	}
	if !strings.Contains(err.Error(), "检测到非法越界软链接") {
		t.Fatalf("expected illegal symlink error, got: %v", err)
	}
}
```

- [ ] **Step 2: 运行测试以验证失败**

运行：
```bash
go test -run TestSecurity_ExportSymlinkEscapeDefense ./internal/controller
```
预期输出：编译失败，提示 `undefined: compressDirToZip`。

- [ ] **Step 3: 在 `route.go` 中实现 `compressDirToZip` 并替换 `compressDirToTarGz`**

在 `internal/controller/route.go` 中新增 `compressDirToZip` 函数：

```go
// compressDirToZip 将目录压缩为 zip 格式的字节切片。
func compressDirToZip(srcDir string) ([]byte, error) {
	log.Printf("compressDirToZip: 开始压缩目录: %s", srcDir)
	info, err := os.Stat(srcDir)
	if err != nil {
		log.Printf("compressDirToZip: 目录不存在: %v", err)
		return nil, fmt.Errorf("目录不存在: %w", err)
	}
	if !info.IsDir() {
		log.Printf("compressDirToZip: 路径不是目录: %s", srcDir)
		return nil, fmt.Errorf("路径不是目录: %s", srcDir)
	}

	evalSrcDir, err := filepath.EvalSymlinks(srcDir)
	if err != nil {
		evalSrcDir = srcDir
	}
	cleanSrcDir := filepath.Clean(evalSrcDir)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	baseDir := filepath.Dir(srcDir)
	fileCount := 0
	err = filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.Mode()&os.ModeSymlink != 0 {
			evalPath, err := filepath.EvalSymlinks(path)
			if err != nil {
				return fmt.Errorf("解析物理路径失败 %s: %w", path, err)
			}
			cleanEval := filepath.Clean(evalPath)
			if cleanEval != cleanSrcDir && !strings.HasPrefix(cleanEval, cleanSrcDir+string(filepath.Separator)) {
				return fmt.Errorf("检测到非法越界软链接: %s -> %s", path, evalPath)
			}
		}

		relPath, err := filepath.Rel(baseDir, path)
		if err != nil {
			return err
		}
		// 统一使用 / 分隔符，兼容跨平台
		relPath = filepath.ToSlash(relPath)

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}

		if info.IsDir() {
			header.Name = strings.TrimSuffix(relPath, "/") + "/"
			_, err = zw.CreateHeader(header)
			return err
		}

		header.Name = relPath
		header.Method = zip.Deflate

		w, err := zw.CreateHeader(header)
		if err != nil {
			return err
		}

		fileCount++
		log.Printf("compressDirToZip:   [文件] %s (%d bytes)", relPath, info.Size())
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(w, f)
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	if err != nil {
		log.Printf("compressDirToZip: 遍历目录失败: %v", err)
		return nil, err
	}

	log.Printf("compressDirToZip: 共压缩 %d 个文件", fileCount)

	if err := zw.Close(); err != nil {
		return nil, err
	}
	result := buf.Bytes()
	log.Printf("compressDirToZip: 压缩完成，最终大小=%d bytes", len(result))
	return result, nil
}
```

- [ ] **Step 4: 运行测试验证通过**

运行：
```bash
go test -run TestSecurity_ExportSymlinkEscapeDefense ./internal/controller
```
预期输出：PASS。

- [ ] **Step 5: 提交更改**

```bash
git add internal/controller/route.go internal/controller/security_hardening_test.go
git commit -m "feat(controller): 实现具备软链接安全防护的compressDirToZip"
```

---

### Task 2: 更新 `exportHandler` 结果导出逻辑与文件名规范

**Files:**
- Modify: `internal/controller/route.go:1358-1410`

- [ ] **Step 1: 修改 `exportHandler` 中的压缩调用和导出文件名**

将 `internal/controller/route.go` 中 `exportHandler` 的逻辑修改为：
1. 压缩调用改为 `resultData, err := compressDirToZip(record.ResultDir)`。
2. 基础文件名变更为 `filename := filepath.Base(record.ResultDir) + ".zip"`。
3. 加密文件名追加 `.enc`（即 `.zip.enc`）。
4. 清理废弃的 `compressDirToTarGz` 函数。

- [ ] **Step 2: 编译与单测初筛**

运行：
```bash
go test -run TestSecurity_ExportSymlinkEscapeDefense ./internal/controller
```
预期输出：PASS。

- [ ] **Step 3: 提交更改**

```bash
git add internal/controller/route.go
git commit -m "feat(controller): 导出接口切换为ZIP压缩与.zip文件名格式"
```

---

### Task 3: 重构测试用例适配 ZIP 导出格式

**Files:**
- Modify: `internal/controller/handler_test.go`
- Modify: `internal/controller/import_flow_new_test.go`
- Modify: `internal/controller/security_hardening_test.go`

- [ ] **Step 1: 在 `internal/controller/handler_test.go` 中添加 `extractZipMap` 辅助函数**

在 `internal/controller/handler_test.go` 中引入：
```go
// extractZipMap 将 zip 字节解压为 文件名->内容的映射（跳过目录项）。
func extractZipMap(t *testing.T, zipData []byte) map[string][]byte {
	t.Helper()
	r, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		t.Fatalf("zip.NewReader failed: %v", err)
	}

	files := make(map[string][]byte)
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("failed to open zip file entry %s: %v", f.Name, err)
		}
		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("failed to read zip file entry %s: %v", f.Name, err)
		}
		files[f.Name] = content
	}
	return files
}
```

- [ ] **Step 2: 更新 `handler_test.go` 中所有 `/v1/taa/export` 测试用例**

1. 将断言 `filepath.Base(record.ResultDir)+".tar.gz"` 改为 `filepath.Base(record.ResultDir)+".zip"`。
2. 将断言 `.tar.gz.enc` 改为 `.zip.enc`。
3. 将解压函数调用 `extractTarGzMap` 替换为 `extractZipMap`。
4. 修复对应的测试失败日志提示。

- [ ] **Step 3: 更新 `import_flow_new_test.go` 中的导出断言**

1. 将 `exportTarGz` / `extractTarGzMap` 替换为 `exportZip` / `extractZipMap`。
2. 确保端到端测试流程通过。

- [ ] **Step 4: 运行所有控制器单元测试与集成测试**

运行：
```bash
go test -v ./internal/controller/...
```
预期输出：所有测试全部 PASS。

- [ ] **Step 5: 提交更改**

```bash
git add internal/controller/handler_test.go internal/controller/import_flow_new_test.go internal/controller/security_hardening_test.go
git commit -m "test(controller): 重构导出测试用例适配ZIP压缩格式"
```

---

### Task 4: 同步更新项目设计文档与接口规格

**Files:**
- Modify: `docs/taa接口设计文档.md`
- Modify: `docs/TAA状态持久化与崩溃自愈设计文档.md`

- [ ] **Step 1: 更新 `docs/taa接口设计文档.md`**

将 `/v1/taa/export` 章节中的响应头、返回示例和文件名从 `.tar.gz` / `.tar.gz.enc` 修改为 `.zip` / `.zip.enc`。

- [ ] **Step 2: 更新 `docs/TAA状态持久化与崩溃自愈设计文档.md`**

将软链接越界防护描述中的 `compressDirToTarGz` 更新为 `compressDirToZip`。

- [ ] **Step 3: 运行 git diff 检查文档修改无误**

运行：
```bash
git diff docs/
```

- [ ] **Step 4: 提交文档更新**

```bash
git add docs/taa接口设计文档.md docs/TAA状态持久化与崩溃自愈设计文档.md
git commit -m "docs(export): 同步更新接口设计与持久化文档中的ZIP导出说明"
```

---

### Task 5: 全局集成验证

**Files:**
- All touched files

- [ ] **Step 1: 运行项目完整测试**

```bash
go test -v ./...
```
预期输出：全部 PASS，无编译告警与测试回归。

- [ ] **Step 2: 验证 git 状态干净**

```bash
git status
```
预期输出：除先前工作区未跟踪文件外，本次改动全部提交完毕。
