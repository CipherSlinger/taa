# macOS 打包元数据兼容：解压剥离 + 扫描兜底

- **Date**: 2026-11-02
- **Specification Path**: `.claude/specs/2026-11-02-macos-archive-metadata-design.md`
- **Scope**: 模型/数据归档解压、代码审计扫描目标集合
- **Lifecycle Status**: Target Architecture Specification
- **Affected Modules**: `internal/resource`, `internal/codeaudit`, `pkg/archiveentry`（新增）

---

## 1. 背景与现状

macOS 用 Finder / `ditto` / 带 xattr 的 `zip` 打包时，会把扩展属性写成 AppleDouble
文件（`._*`），并放进 `__MACOSX/` 目录；Finder 还会写 `.DS_Store`。这些条目是二进制
元数据，但文件名保留了原扩展名（`__MACOSX/._train.py` 的扩展仍是 `.py`）。

当前解压不做过滤（`internal/resource/archive.go`），审计侧也只在 `SkipDirs` 里排除
构建目录（`internal/codeaudit/scanner.go`），没有排除 `__MACOSX`。

后果链（已实测 semgrep 1.177.0）：

1. semgrep 引擎按扩展名选目标（`semgrep_engine.go` 的 `isSourceFile`），
   `__MACOSX/._train.py` 被当成 Python 源码传给 semgrep。
2. semgrep 退出码 0、`paths.scanned` 也列出该文件，但 `errors` 数组给出
   `code:3, level:warn, type:PartialParsing, "Syntax error ... was unexpected"`。
3. TAA 适配器把任何 `errors` 条目视为扫描不完整（`semgrep_engine.go` `run`），
   返回 `semgrep reported N error(s)`。
4. `GenerateAuditReport` 返回错误，controller 以 `code=2` 上报审计失败
   （`internal/controller/import_processing.go`）。模型包不被删除，但审计结论失败。

这是扫描完整性闸门，不是危险规则命中。

## 2. 目标与非目标

### 2.1 目标

- 归档解压时丢弃 macOS 打包元数据，不落盘、不进入模型目录。
- 过滤规则与打包平台/工具无关：`__MACOSX` 路径段、任意层级 `._*`、`.DS_Store`。
- 覆盖所有服务端解压入口：ZIP、tar、tar.gz；模型导入、FHE、数据分析、
  `getResourceInfo` 经同一组函数，一处生效。
- 审计侧兜底：即使模型目录不是本次解压产生（旧目录、幂等跳过、其他组装路径），
  regex / semgrep / 二进制三个 walk 也不把元数据当作扫描对象。
- 日志记录被剔除的条目数量。

### 2.2 非目标

- 顶层目录归一化（Finder zip 多套一层同名目录），单独跟踪。
- macOS NFD 文件名与配置路径的归一化。
- tar 中 symlink/hardlink 的兼容（当前直接拒绝，行为不变）。
- 7z/rar 等未支持格式。
- SDK/GUI 侧 `pkg/crypto/archive.go` 的独立解压实现（不参与服务端审计）。

## 3. 设计

### 3.1 共享判定

新增 `pkg/archiveentry`，提供唯一判定：

```go
func IsMetadataPath(name string) bool
```

规则：

- 先把 `\` 归一化为 `/`（Windows 打包器的路径写法）。
- 任一路径段大小写不敏感地等于 `__MACOSX` → 元数据（整棵子树丢弃）。
- basename 以 `._` 开头 → AppleDouble。
- basename 等于 `.DS_Store` → Finder 目录索引。

判定只看名字，不看包由哪个平台生成：同一逻辑包可能混有其他平台遗留的元数据。

### 3.2 解压剥离

在 `internal/resource/archive.go` 的条目循环中、`SafeJoinWithBase` 之前过滤：

- `ExtractZipArchive`
- `ExtractTarStream`（tar.gz 也走这里）

被跳过条目计数，循环结束后写一条 `log.Printf`，不做逐条刷屏。文件内容、相对路径、
权限不变；压缩包 SM3 在校验前计算，不受影响。

### 3.3 扫描兜底

三个 walk 在遍历回调里对 `info.Name()` 调用同一判定，目录返回 `filepath.SkipDir`：

- `internal/codeaudit/scanner.go`（regex 引擎的两个入口）
- `internal/codeaudit/semgrep_engine.go` 的 `walkSourceFiles`
- `internal/codeaudit/binary_scanner.go`

同时把 `__MACOSX` 加入 `DefaultConfig().SkipDirs`，`BinaryConfig.SkipDirs` 继承同一集合。

## 4. 验收

- ZIP 与 tar 夹具：真实源码保留，`__MACOSX/._x.py`、任意层级 `._x.py`、`.DS_Store`
  都不落盘。
- 绕过解压直接构造含元数据的目录时，三个 walk 的扫描目标/claim 集合均不含元数据。
- 现有归档、扫描、审计测试全部通过。
- 真实 macOS 产物回归夹具（TODO 6.2 验收）仍需后续用 macOS 实测 zip 补测。
