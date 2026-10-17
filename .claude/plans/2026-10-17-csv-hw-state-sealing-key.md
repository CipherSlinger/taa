# 用海光 CSV 硬件 sealing key 密封 TAA 持久状态

## Context

TAA 当前的 `state.sealed` 使用从 SM2 私钥标量 D 派生的 16 字节 SM4 密钥
（`pkg/crypto/seal.go:151`，`SM3(D || "TAA-STATE-SEALING-V1" || 0x00000001)[:16]`）。
私钥以明文 PEM 存在同一目录，密封的信任根与被保护文件同处一地。

`pkg/csvattest` 已实现完整的 CSV 硬件 sealing key 读取路径
（`GetSealingKeyIOCTL` → 会话 MAC/mnonce 校验 → 取 report 偏移 `0x9b4` 的 32 字节），
但今天没有任何生产调用方。本改动把它接入 TAA 的状态密封，使 TEE 生产路径的
密封根来自 CSV 硬件，而不是可被同目录读到的私钥。

用户已确认两项策略：

- **显式配置，不静默回退**：新增 `storage.stateSealingKeySource`，取值 `sm2` / `csv-hw`。
  production / initrd 配 `csv-hw`，拿不到 `/dev/csv-guest` 或 ioctl 失败即启动失败；
  docker / FHE 配 `sm2`。
- **旧状态不迁移**：切换密钥来源后，旧 `state.sealed` 归档为 `.orphaned.<unix>`，
  重建干净状态（复用现有 drift 机制）。

实现完成后按 CLAUDE.md 保存本计划副本到
`.claude/plans/2026-10-17-csv-hw-state-sealing-key.md`（`.claude/` 被忽略，需 `git add -f`）。

## 设计

### 1. 32 字节硬件密钥 → 16 字节 SM4 密钥

`pkg/crypto/seal.go` 新增：

```go
func DeriveSealingKeyFromCSV(hwKey []byte) ([]byte, error)
// SM3(hwKey(32) || "TAA-STATE-SEALING-CSV-V1" || 0x00000001)[:16]
```

- 要求长度恰为 32；拒绝全零密钥（ioctl 成功但 `reserved2` 为零是可能的）。
- 标签与旧派生不同，即使输入字节相同也不会碰撞。

### 2. 状态文件增加明文头，记录密钥来源

新增 `internal/store/sealed_state_header.go`，在现有 SM4-GCM 载荷前加 8 字节：

| 偏移 | 长度 | 值 |
|---|---|---|
| 0 | 4 | magic `"TAAS"` |
| 4 | 1 | 格式版本 `1` |
| 5 | 1 | 1 = `sm2`，2 = `csv-hw` |
| 6 | 2 | 保留，零 |

载荷仍是 `nonce(12) || ciphertext || tag(16)`。

解析规则：**只有所有字段都合法才认为是新格式**；否则整份文件按旧格式（隐式 `sm2`）处理。
旧文件以随机 nonce 开头，全字段误判概率约 2^-56。这样不会把旧文件误判成另一种来源。

`KeySource`、`ErrKeySourceMismatch`、`buildSealedStateHeader`、`splitSealedStateFile`
放在该文件。头不参与 GCM AAD：能改头的人本来就能删文件触发干净重建，信任模型不变。

### 3. StateStore 感知来源

`internal/store/sealed_state.go`：

```go
func NewStateStore(path string, sealingKey []byte, source KeySource) (*StateStore, error)
```

- 校验 16 字节密钥和合法来源。
- `sealStateLocked`：`Encrypt` 后前拼头，再 `AtomicWriteFile(0600)`。
- `unsealStateLocked`：读文件 → `splitSealedStateFile` → 来源不一致返回
  `ErrKeySourceMismatch` → 一致才 `Decrypt`。
- `DetectAndHandleKeyDrift`：
  - 解密成功：正常；
  - `errors.Is(err, os.ErrNotExist)`：重建干净状态；
  - `errors.Is(err, ErrKeySourceMismatch)`：**无论 `isNewKey` 都归档 + 重建**；
  - 其余错误 + `isNewKey`：归档 + 重建；
  - 其余错误 + 旧密钥：保持 fail-closed。
  - 归档块抽成 `archiveAndSealCleanLocked()`，沿用 `.orphaned.<unix>`。

`internal/controller/state_store.go` 的别名与包装器同步加 `source` 参数。

### 4. 配置

`internal/config/config.go`：

- 常量 `StateSealingKeySourceSM2 = "sm2"`、`StateSealingKeySourceCSVHW = "csv-hw"`。
- `StartupConfig.StateSealingKeySource`（`KeysDir` 旁）。
- `startupStorageConfigFile` 增加 `StateSealingKeySource string \`json:"stateSealingKeySource"\``。
- 默认 `sm2`（向后兼容），`applyStartupConfigFile` 中 `TrimSpace + ToLower` 读取。
- `validateStateSealingKeySource`：拒绝未知值；`fhe` + `csv-hw` 直接报错
  （FHE 不是 CSV guest，没有设备）。
- 在 `validateStartupConfig` 中调用。

### 5. 启动接线

新增 `internal/app/taa/sealing_key.go`：

```go
type hardwareSealingKeyFetcher func(keyBuf []byte) error

func fetchCSVHardwareSealingKey(keyBuf []byte) error {
    return csvattest.NewClient().GetSealingKeyIOCTL(keyBuf)
}

func resolveStateSealingKey(source string, privKey *teecrypto.SM2PrivateKey,
    fetch hardwareSealingKeyFetcher) ([]byte, store.KeySource, error)
```

- `sm2`：走旧派生；
- `csv-hw`：32 字节缓冲 → fetch（失败即返回错误，无回退）→ `DeriveSealingKeyFromCSV`
  → `clear(hwKey)`；
- 未知/空来源：报错。

`internal/app/taa/app.go:119-128` 改为：

```go
sealingKey, keySource, err := resolveStateSealingKey(cfg.StateSealingKeySource, keyPair.PrivateKey, fetchCSVHardwareSealingKey)
log.Printf("state sealing key source: %s", keySource)
stateStore, err := store.NewStateStore(statePath, sealingKey, keySource)
keyIsNew := !loaded && keySource == store.KeySourceSM2
drifted, err := stateStore.DetectAndHandleKeyDrift(keyIsNew)
```

`isNewKey` 只表示“SM2 密钥对刚生成”，与硬件密钥无关；不能对 `csv-hw` 传 `!loaded`，
否则会在 SM2 重新生成的启动中误归档同来源文件。归档发生时打印警告（不打印密钥）。

### 6. 配置与文档

- `configs/taa-production.json`、`configs/taa-initrd.json`：`storage.stateSealingKeySource = "csv-hw"`。
- `configs/taa-docker.json`、`configs/taa-fhe.json`：`"sm2"`。
- `README.md`：配置表加一行，说明两种取值、`csv-hw` 硬失败、宿主绑定限制。
- `deploy/guest-build/taa-init.sh:126` 的警告文案更新：设备缺失不再只是“证明降级”，
  还会让 `csv-hw` 启动失败。
- `CHANGELOG.md` 加一条。

注意：旧二进制会静默忽略新配置键并继续用 SM2。二进制与配置必须同批发布。

## 测试

- `pkg/crypto/seal_csv_test.go`：确定性/长度、按文档材料复算、与旧派生域分离、
  错误长度、全零拒绝。
- `internal/store/sealed_state_test.go`：两种来源的头往返、旧文件按 `sm2` 读取、
  头布局、来源不匹配是 typed error、未知来源拒绝；drift 测试：
  `csv-hw` 读旧文件归档、`sm2` 读 `csv-hw` 文件归档、同来源篡改仍 fail-closed。
- `internal/controller/state_store_test.go`、`taa_state_store_integration_test.go`、
  `internal/app/taa/recovery_test.go`：现有构造点补 `KeySourceSM2`。
- `internal/app/taa/sealing_key_test.go`：SM2 与旧派生一致、`csv-hw` 派生正确、
  fetch 失败即 fatal（并断言没有回退到 SM2）、全零拒绝、未知/空来源拒绝。
- `internal/config/config_test.go`：默认值、读取、归一化、未知值拒绝、
  FHE + `csv-hw` 拒绝；更新模板测试并新增四个 shipped 配置的 pin 测试
  （production/initrd = csv-hw，docker/fhe = sm2）。

## 实施顺序

1. `pkg/crypto` 派生 + 测试。
2. `internal/store` 头与来源感知 + 测试。
3. `internal/controller` 包装器与测试调用点。
4. `internal/config` 字段/校验/模板 + 测试。
5. `internal/app/taa` 接线 + 测试。
6. 配置、README、taa-init 警告、CHANGELOG。
7. 全量验证。

## 验证

### 本地

```bash
gofmt -l ./pkg/crypto ./internal/store ./internal/controller ./internal/config ./internal/app/taa
go vet ./pkg/crypto/... ./internal/store/... ./internal/controller/... ./internal/config/... ./internal/app/taa/...
go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/taa ./cmd/taa
```

### 真机 CSV2（172.16.10.178）

1. 静态构建后在 guest 内运行（`tools/csv2-vm/csv2-vm.sh`，guest 内确认
   `/dev/csv-guest` 存在）。用临时 keys 目录、关闭 codeAudit/LLM，避免外部依赖。
2. 先以 `sm2` 启动，确认 `state.sealed` 头部 `TAAS 01 01 00 00`
   （`od -An -v -tx1 -N8`；slim 镜像内没有 `xxd`）。
3. 切到 `csv-hw` 重启：日志出现 `state sealing key source: csv-hw` 与归档警告，
   出现 `.orphaned.*`，新文件头部来源字节为 `02`；再次重启不再归档。
4. 负向：移走 `/dev/csv-guest` 后用 `csv-hw` 启动，必须非零退出并报
   `acquire CSV hardware sealing key`；同来源篡改载荷必须 fail-closed 而不是归档。
5. initrd E2E：重建 initrd（二进制、`taa-initrd.json`、`taa-init.sh` 都变了，
   **需重新计算启动度量**），部署后 Pod Ready + `getAttestation` 返回
   `verifiedPass: true` 即证明硬件路径成功；串口日志确认来源行。
   普通 kata Pod 由外部清单的 postStart 创建节点，`deploy/start.sh` 每 10s 重启
   TAA，可容忍节点就绪延迟；initrd 中 `taa-init` 先建节点再启动 TAA。

## 风险与说明

- CSV2 硬件 sealing key 是**宿主/芯片绑定**的：同一宿主上不同 VM 实测拿到相同密钥，
  它不是 per-VM 身份，不能当租户隔离边界。状态不能跨宿主迁移；跨宿主会因同来源解密
  失败而 fail-closed，恢复方式只能是删除/归档 `state.sealed` 后重建。
- 头是明文的且不参与认证；写入权限与删除权限等价，信任模型未变。
- 除全零检查外无法判断密钥“有用性”；ioctl 只保证会话 MAC 与 mnonce。
- 不修改 `pkg/csvattest`：现有 API 已足够，测试缝隙放在 app 层。
- 无 `csv-hw` 回退路径；FHE/docker 通过显式配置继续用 `sm2`。

## 工作区与提交

- 按 CLAUDE.md 在独立 worktree 中实施（`.claude/worktrees/`，新分支）。
- worktree 缺 `teellm` 子模块：用 `GOWORK=/tmp/taa-worktree-go.work`，其中 `use`
  指向 worktree 根与共享检出的 `teellm`、`teellm/teetls`、`tools/sdk` 绝对路径；
  并在 worktree 内保留空的 `teellm/` 目录。
- 提交信息：`feat(state): seal persistent state with the Hygon CSV hardware key`
  （英文 Conventional Commits，无任何 AI/Co-Authored-By 痕迹）。
- worktree 不能直接合回共享检出的 master；完成后给出已验证的合并/清理命令。
