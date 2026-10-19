# FHE 回调地址派生与 token 移除：实施计划

日期：2026-10-19
对应 spec：`.claude/specs/2026-10-19-fhe-derived-callback-design.md`

## 步骤

1. **配置层**
   - `internal/config/config.go`：删除 `FHEConfig.CallbackBaseURL/CallbackToken`；删除 `FHECallbackBaseURLAuto`、`IsFHECallbackBaseURLAuto`、`ResolveFHECallbackBaseURL`、`deriveSelfIPv4`、`firstUsableIPv4`；新增 `DeriveFHECallbackBaseURL`。
   - `rejectRemovedKeys` 增加旧键检测；`validateFHEConfig` 必填列表删除两项。
   - `configs/taa-fhe.json` 删除两行。

2. **fhe 运行时**
   - `internal/fhe/config.go`：删除 `CallbackToken`、`TokenMatches`；`Validate` 去掉 token 检查；`CallbackURL()` 去掉 query。
   - `internal/app/taa/app.go`：改用 `DeriveFHECallbackBaseURL(cfg.Addr)`，删除 auto 日志与 token 传参。

3. **回调 handler**
   - `internal/controller/fhe_callback.go`：删除 token 校验；新增环回来源检查；更新注释。

4. **部署脚本与文档**
   - `deploy-fhe.sh`：删除两个环境变量、渲染项、注释、日志。
   - `README.md`、`CHANGELOG.md` 同步。

5. **测试**
   - `internal/config/config_test.go`、`fhe_config_test.go`：移除 token/auto 相关用例，新增派生与旧键拒绝用例。
   - `internal/fhe/config_test.go`、`runner_test.go`：删除 token 字段与 TokenMatches 用例，更新 `CallbackURL` 期望。
   - `internal/controller/fhe_callback_test.go`、`fhe_processing_test.go`：请求改为无 token、`RemoteAddr` 设为环回；新增非环回拒绝用例。
   - `internal/app/taa/fhe_template_test.go`：模板直接加载，不再替换 token。

6. **验证**
   - `go test ./internal/... ./pkg/...`
   - `./deploy-fhe.sh --dry-run`（如环境允许）
   - `git diff --check`

7. **提交**
   - `feat(fhe)!: derive the callback address and drop the callback token`
   - 文档随实现提交；`.claude/` 下文件用 `git add -f`。
