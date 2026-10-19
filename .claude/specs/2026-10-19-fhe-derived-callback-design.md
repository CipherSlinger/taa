# FHE 回调地址改为派生、移除回调 token

日期：2026-10-19
状态：已确认，待实施

## 背景

`fhe.callbackBaseUrl` 与 `fhe.callbackToken` 目前是启动配置的必填项。前者承担两件事：告诉 FHE 服务回调哪个地址，以及通过 `auto` 哨兵在启动时探测本机地址。后者是回调节点的共享 secret，`deploy-fhe.sh` 渲染配置时注入，`taa save` 还会把它烤进镜像。

实际部署中 TAA 与 FHE 服务同机、TAA 使用 host 网络，回调地址可以完全由 `server.addr` 推出；token 也不再需要由部署侧维护。本次把两者从配置中移除，地址在 TAA 内部派生，回调节点不再鉴权。

## 决策

1. **地址固定为环回**：`http://127.0.0.1:{port}`，`port` 取自 `server.addr`（CLI `--addr` 覆盖后的最终值）。不做主机地址探测，不保留 `auto` 哨兵。
2. **不生成 callbackToken**：配置字段与运行时字段一并删除；`callback_url` 不再携带 `?token=`。
3. **回调节点保留但无鉴权**：FHE 仍会回调，TAA 不再校验 token。作为补偿控制，handler 只接受来自环回地址的请求（`RemoteAddr` 为 loopback）。
4. **旧配置键显式拒绝**：沿用仓库 `RemovedSecurity`/`RemovedLLM` 的先例，配置里仍出现 `fhe.callbackBaseUrl` 或 `fhe.callbackToken` 时启动报错，而不是静默忽略——静默忽略等于悄悄关闭鉴权。

## 变更

### 配置层 `internal/config`

- `FHEConfig` 删除 `callbackBaseUrl`、`callbackToken` 两个字段；必填键列表同步删除。
- 新增 `DeriveFHECallbackBaseURL(listenAddr string) (string, error)`：用 `listenAddrPort` 取端口，返回 `http://127.0.0.1:<port>`；`server.addr` 不含端口时返回错误。
- 删除 `FHECallbackBaseURLAuto`、`IsFHECallbackBaseURLAuto`、`ResolveFHECallbackBaseURL`、`deriveSelfIPv4`、`firstUsableIPv4`。
- `rejectRemovedKeys` 增加两个旧键的检测与修复提示。
- `configs/taa-fhe.json` 删除两行。

### 运行时 `internal/fhe` 与 app 装配

- `fhe.Config` 删除 `CallbackToken` 字段与 `TokenMatches` 方法。
- `Validate` 不再要求 token；`CallbackBaseURL` 仍校验为合法 http(s) URL（防御性检查）。
- `CallbackURL()` 返回 `<base>/v1/taa/fheCallback`，无 query。
- `internal/app/taa/app.go` 用 `config.DeriveFHECallbackBaseURL(cfg.Addr)` 构造 runner。

### 回调 handler `internal/controller`

- 删除 token 校验。
- 新增来源检查：`RemoteAddr` 的主机必须是环回地址；否则返回 404（与“不确认端点存在”的既有语义一致）。
- tee 实例 404、请求体上限 4 MiB、解析失败 400、幂等 200 的语义不变。

### 部署与文档

- `deploy-fhe.sh`：删除 `TAA_CALLBACK_BASE_URL`、`TAA_CALLBACK_TOKEN` 两个变量、帮助文本、jq 渲染项、相关注释和日志；渲染后的配置仍以 0600 写入。
- `README.md`：更新 `fhe` 配置表、模板说明、`taa save`/deploy 的渲染说明。
- `CHANGELOG.md`：记录破坏性变更。

## 安全影响

回调节点不再鉴权。任何能到达 `:6001` 的进程都可能伪造任务终态；环回来源限制把可达面收回到本机，但不能区分本机上的不同进程。

这与现有轮询路径正交：即使回调被丢弃或伪造失败，`pollIntervalMs` 轮询仍会从 FHE 服务取回真实终态。伪造回调能提前结束等待，但不会让 FHE 侧真正完成任务；结果文件仍以共享目录中的真实产物为准。

## 验收

- `taa-fhe.json` 不再包含两个字段，且 `LoadStartupConfig` 可直接加载（无需替换 token）。
- `server.addr = ":6001"` 时，下发给 FHE 的 `callback_url` 为 `http://127.0.0.1:6001/v1/taa/fheCallback`。
- 无 token 的 POST 回调返回 200 并推进在途任务；非环回来源返回 404。
- 配置中残留旧键时启动失败并给出修复提示。
- `deploy-fhe.sh --dry-run` 不再引用两个环境变量。
- `go test ./internal/... ./pkg/...` 通过。
