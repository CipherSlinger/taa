# TAA 结果导出 ZIP 压缩改造设计规格文档

- **创建日期**: 2026-09-15
- **状态**: 已确认 (Approved)
- **关联接口**: `/v1/taa/export`

---

## 1. 背景与目标

当前 TAA 结果导出接口（`/v1/taa/export`）在打包训练产物目录时，默认采用 `tar.gz` 格式（`compressDirToTarGz`）。为了提升与更广泛客户端（特别是 Windows SDK 等开箱即用场景）的兼容性与处理效率，需要将结果导出接口底层的打包压缩格式从 `tar.gz` 彻底重构为 `zip` 格式（包括明文 `.zip` 与加密 `.zip.enc`）。

### 核心目标
1. `/v1/taa/export` 打包逻辑由 `compressDirToTarGz` 替换为 `compressDirToZip`。
2. 采用 Go 标准库 `archive/zip` 并指定 `zip.Deflate` 压缩方法，确保真实压缩率。
3. 严格保留现有的 `filepath.EvalSymlinks` 软链接越界防御逻辑，防止训练脚本逃逸窃取宿主敏感文件。
4. 导出文件名与 HTTP 头部全面适配为 `.zip` / `.zip.enc`。
5. 同步重构所有涉及导出产物断言的单元测试、集成测试与设计文档。

---

## 2. 接口设计与改动

### 2.1 响应头与文件名规范
- **明文导出**（未提供 `publicKey` 或阶段不支持加密）：
  - 导出文件名: `<ResultDirBaseName>.zip`（例如 `train-001.zip`）
  - HTTP 响应头:
    - `Content-Type`: `application/octet-stream`
    - `Content-Disposition`: `attachment; filename="<ResultDirBaseName>.zip"`
    - `X-TAA-Encrypted`: `false`
- **加密导出**（提供 `publicKey` 或阶段 3 自动加密）：
  - 导出文件名: `<ResultDirBaseName>.zip.enc`（例如 `train-001.zip.enc`）
  - HTTP 响应头:
    - `Content-Type`: `application/octet-stream`
    - `Content-Disposition`: `attachment; filename="<ResultDirBaseName>.zip.enc"`
    - `X-TAA-Encrypted`: `true`

---

## 3. 详细架构与实现

### 3.1 `compressDirToZip` 实现细节
在 `internal/controller/route.go` 中新增并替换原有方法：
```go
// compressDirToZip 将目录压缩为 zip 格式的字节切片，并包含软链接越界防御。
func compressDirToZip(srcDir string) ([]byte, error) {
    info, err := os.Stat(srcDir)
    if err != nil {
        return nil, fmt.Errorf("目录不存在: %w", err)
    }
    if !info.IsDir() {
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

        // 安全检查：防止通过软链接逃逸出输出目录
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
        header.Method = zip.Deflate // 显式指定 Deflate 算法压缩

        w, err := zw.CreateHeader(header)
        if err != nil {
            return err
        }

        fileCount++
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
        return nil, err
    }

    if err := zw.Close(); err != nil {
        return nil, err
    }

    return buf.Bytes(), nil
}
```

### 3.2 导出处理链路联动
在 `exportHandler` 中：
1. 调用 `compressDirToZip(record.ResultDir)` 获得压缩字节流。
2. 构造文件名基础后缀 `.zip`。
3. 若需要加密，在 zip 压缩字节流上执行 `SealSM2SM4GCM`，文件名追加 `.enc`，并以流式输出。

---

## 4. 测试与验证策略

1. **测试辅助工具新增**:
   - 在 `internal/controller/handler_test.go` 中实现 `extractZipMap(t *testing.T, zipData []byte) map[string][]byte`，利用 Go `archive/zip` 内存流读取检验各条目内容。
2. **导出断言更新**:
   - `internal/controller/handler_test.go`:
     - 验证各测试子用例的 `Content-Disposition` 均为 `.zip` 或 `.zip.enc`。
     - 提取返回的二进制流，使用 `extractZipMap` 校验文件存在性与正确性。
   - `internal/controller/security_hardening_test.go`:
     - 更新 `TestSecurity_ExportSymlinkEscapeDefense`，验证 `compressDirToZip` 拦截软链接越界的行为。
   - `internal/controller/import_flow_new_test.go`:
     - 更新端到端导出测试，断言 zip 产物解压无误。
3. **文档同步更新**:
   - `docs/taa接口设计文档.md`
   - `docs/TAA状态持久化与崩溃自愈设计文档.md`
