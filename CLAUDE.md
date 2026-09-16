# TAA Project Guidelines

## 常用命令
- 构建 TAA: `go build -o bin/taa ./cmd/taa`
- 构建 Platform-Mock: `go build -o bin/platform-mock ./cmd/platform-mock`
- 运行测试: `go test ./...`

## 编码与注释规范
- **代码注释**：必须且仅使用英文注释。

## 规划与文档 (Plan & Spec)
- 所有方案设计 (spec) 与实施计划 (plan) 统一保存在 `.claude/specs/` 和 `.claude/plans/` 目录下，严禁存入 `docs/`。

## Agent 与协作规范
- **Subagent 限制**：并发 subagent 数量不得超过 2 个，严禁 subagent 嵌套调用。
- **过程汇报**：工作过程中实时、清晰汇报正在进行的操作与阶段性总结。

## Git 提交规范
- **自动提交**：功能开发或修改完成后，自动执行 Git 提交。
- **提交语言与格式**：提交信息必须使用**英文**，遵循严格的 Conventional Commits 规范（如 `feat(scope): ...`, `docs(guide): ...`）。
- **去除 AI 痕迹**：严禁出现任何 `Co-Authored-By`、`anthropic`、`Claude`、`AI` 或类似的署名及标识。
