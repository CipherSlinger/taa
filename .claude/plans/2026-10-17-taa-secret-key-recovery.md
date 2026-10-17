# 注册上报 SM2 私钥密文（taaSecretKey）与 TAASECRETKEY 恢复

## Context

TAA 的 SM2 私钥目前只落在 `storage.keys` 目录。CSV2 部署下该目录位于 guest 内存 rootfs
（`shared_fs=none`），容器/VM 重建即丢失，TAA 会重新生成一对密钥：平台先前拿到的
`taaPublicKey` 永久失效，且平台没有把旧私钥带回来的通道。

用户给定的协议：

- 正常启动：注册 `/v1/taa/register` 时新增 `taaSecretKey`。
  `sk = SM3(CSV sealing key(32 字节) || CONTRACT)[:16]`；
  `ct = SM4-128-GCM(sk, D)`，`D` 为 SM2 私钥的 32 字节裸标量；字段填 `hex(ct)`（120 字符）。
- 恢复启动：读环境变量 `TAASECRETKEY`。非空时取 CSV 硬件 sealing key，按同式派生 `sk`，
  解密得到 `D`，重算公钥 `Q = d·G`，向平台注册且**省略** `taaSecretKey` 字段；
  为空时按原逻辑加载/生成密钥对，并按上式上报 `taaSecretKey`。

用户已确认的四个决策：

1. 加密明文是 32 字节裸标量（不是 PEM）。
2. 非 CSV 环境（`stateSealingKeySource=sm2`，即 docker/FHE）不参与该机制，只用现有
   state sealing key 做运行时崩溃恢复，不填 `taaSecretKey`；此时若设置了
   `TAASECRETKEY` 直接启动失败。
3. `TAASECRETKEY` 与磁盘密钥冲突时环境变量优先，旧密钥文件归档。
4. 恢复模式的注册请求里 `taaSecretKey` 字段缺省（`omitempty`）。

关键性质：`csv-hw` 模式下状态密封密钥由硬件 key 派生（`SM3(hwKey||"TAA-STATE-SEALING-CSV-V1"||0x00000001)[:16]`），
与 SM2 私钥无关，所以恢复/更换 SM2 私钥不会让 `state.sealed` 失效。

## 设计

### 1. `pkg/crypto`：裸标量与 SM2PrivateKey 互转

`pkg/crypto/sm2.go` 新增，复用已有的 `sm2Curve` 与 `parseSM2ECPrivateKey` 的校验路径：

```go
const SM2ScalarSize = 32

// NewSM2PrivateKeyFromScalar validates a fixed 32-byte big-endian scalar in
// (0, N) and derives the matching public key Q = d*G.
func NewSM2PrivateKeyFromScalar(scalar []byte) (*SM2PrivateKey, error)

// ScalarBytes returns D as a zero-padded 32-byte big-endian value.
func (k *SM2PrivateKey) ScalarBytes() []byte
```

（`pkg/crypto/seal.go:200` 的 `D.FillBytes` 写法由此统一。）

### 2. `internal/app/taa/taa_secret.go`：派生 / 封装 / 打开

```go
const taaSecretKeyEnv = "TAASECRETKEY"
const taaSecretKeyCiphertextSize = 12 + 32 + 16 // nonce + scalar + tag

func deriveTAASecretSM4Key(hwKey []byte, contract string) ([]byte, error)
    // 严格要求 hwKey 恰好 32 字节；SM3(hwKey || contract)[:16]
    // 按协议与平台侧完全一致：无域标签、无分隔符，contract 按 UTF-8 原始字节拼接
func sealTAASecretKey(hwKey []byte, contract string, priv *SM2PrivateKey) (string, error)
func openTAASecretKey(hwKey []byte, contract, encoded string) (*SM2PrivateKey, error)
```

- `open`：`TrimSpace` → `hex.DecodeString` → 长度必须 60 → `teecrypto.Decrypt` →
  明文长度必须 32 → `NewSM2PrivateKeyFromScalar`。任何一步失败都返回错误。
- 所有敏感中间量（hwKey 副本之外、`sk`、D、明文）用 `defer clear(...)` 清零；
  派生时先把 `SM3Sum` 的数组整个清掉，只拷出前 16 字节。
- 不打印 `sk`/`D`/明文；日志只允许密文长度，或密文前 8 字节摘要用于与平台侧比对。

### 3. 启动密钥材料统一解析

`internal/app/taa/sealing_key.go` 把 fetch 从 `resolveStateSealingKey` 中拆出，保证 CSV 硬件 key
每次启动只取一次（现有实现若两处各自 fetch 会重复 ioctl 并重复打印指纹）：

```go
func fetchStartupHardwareKey(fetch hardwareSealingKeyFetcher) ([]byte, error)
func resolveStateSealingKey(source string, privKey *SM2PrivateKey, hwKey []byte) ([]byte, store.KeySource, error)
```

新增 `internal/app/taa/startup_keys.go`：

```go
type startupKeyMaterial struct {
    keyPair      *taaKeyPair
    loaded       bool   // 来自磁盘
    recovered    bool   // 来自 TAASECRETKEY
    sealingKey   []byte
    keySource    store.KeySource
    taaSecretKey string // 空表示注册时省略
}

func resolveStartupKeyMaterial(keysDir, source, contract, secretEnv string,
    fetch hardwareSealingKeyFetcher) (*startupKeyMaterial, error)
```

流程：

1. `source == csv-hw` → `fetchStartupHardwareKey`（失败即 fatal，沿用现有“无回退”语义）；
   `source == sm2` → `hwKey = nil`。
2. `secretEnv` 非空：
   - `hwKey == nil` → 报错 `TAASECRETKEY requires storage.stateSealingKeySource=csv-hw`
     （非 CSV 环境不支持恢复）；
   - `openTAASecretKey` 失败 → fatal（认证失败/长度错误/`D` 越界都在此暴露）；
   - `persistRecoveredTAAKeyPair(keysDir, priv)`：
     - 与磁盘现有密钥解析后逐坐标比对，相同则不重写、不归档（幂等，避免每次启动产生 `.bak`）；
     - 不同或文件损坏 → 现有两个 PEM 原子改名成 `<name>.bak.<unix>`，再按
       `writeKeyFileAtomic` 写回（私钥 0600、公钥 0644，复用 app.go 现有函数）；
   - `taaSecretKey` 留空。
3. `secretEnv` 为空：调用现有 `loadOrGenerateTAAKeyPair(keysDir)`（不改语义：
   公私钥不一致、有公钥无私钥仍 fail-closed，因为这是“没有外部输入”的场景）。
4. `resolveStateSealingKey(source, priv, hwKey)`。
5. `csv-hw` 且非恢复模式 → `sealTAASecretKey(hwKey, contract, priv)`；
   `sm2` → 留空并打印一条“non-CSV instance: taaSecretKey is not reported”。
6. 调用方 `defer clear(hwKey)`、`defer clear(sealingKey)`。

`internal/app/taa/app.go`：

- 109–128 行换成一次 `resolveStartupKeyMaterial(keysDir, cfg.StateSealingKeySource,
  cfg.Contract, strings.TrimSpace(os.Getenv(taaSecretKeyEnv)), fetchCSVHardwareSealingKey)`。
- `keyIsNew := !m.loaded && !m.recovered && m.keySource == store.KeySourceSM2`：
  恢复场景绝不触发 state 归档（csv-hw 下 state 与 SM2 私钥无关）。
- 日志区分 `loaded` / `generated` / `recovered TAA SM2 key pair from TAASECRETKEY`
  （恢复时可打印公钥是否与原文件一致），不打印任何秘密。
- CONTRACT 用 `cfg.Contract`：`config.go:776` 已从环境变量 `CONTRACT` 播种、配置文件可覆盖
  （`config.go:860-864`）；仓库两条部署路径最终写入/注入的值都等于部署侧 CONTRACT，
  与平台侧一致。README 中写明该取值路径。

### 4. 注册链路透传

- `internal/platform/register.go`：`registerRequest` 加
  `TaaSecretKey string \`json:"taaSecretKey,omitempty"\``；包级与 `(*Client).NoticeRegister`
  各加一个参数 `taaSecretKey string`。
- `internal/controller/register.go`：`NoticeRegister` 透传；只被测试使用的 `postRegister`
  与其重复的 `registerRequest` 同步加同名字段/参数，避免契约副本漂移（更新 3 处测试调用）。
- `internal/app/taa/app.go:661`：`registerPlatform` 加 `taaSecretKey string`；
  首次注册与 `retryRegister` 闭包使用同一个值。
- `internal/platform/client.go:47` `LogRequestFailure`：打印 payload 前把 JSON 中的
  `taaSecretKey` 替换为 `"<redacted>"`（解析失败则原样打印）。密文不应进日志；
  现有失败 dump 测试只做子串断言，不受影响。

### 5. 平台 mock 与文档

- `tools/platform-mock/internal/store.go`：请求 struct 与 `registerState` 增加
  `taaSecretKey`；`handlers_taa.go` 原样回显/落盘，不做必填校验（非 CSV/恢复模式本就缺省）。
- `docs/api-design.md`：注册参数表增加 `taaSecretKey` 行，写明派生公式、120 hex 字符、
  仅在“CSV 且未从 TAASECRETKEY 恢复”时出现；补一句恢复模式的语义。
- `api/openapi.yaml`：`RegisterRequest.properties` 增加可选 `taaSecretKey`（不进 `required`）。
- `docs/architecture-design.md`：启动流程框补“取硬件 key → 导出/恢复 SM2 私钥”步骤。
- `README.md`：`TAASECRETKEY`、恢复流程（平台保存首次注册的 taaSecretKey；keys 目录丢失后
  注入恢复）、非 CSV 不支持、CONTRACT 变更会导致旧密文解不开。
- `CHANGELOG.md` 一条。

### 部署注入限制（需在文档中写明）

initrd 路径下 TAA 的环境来自 guest 内 `/etc/default/taa.env`（`build-initrd.sh:485-493`
构建期写入，`taa-init.sh:83-85` source），Pod spec 的 env 不会自动到达 initrd 里的 TAA。
因此 `TAASECRETKEY` 在 initrd 部署下需要额外注入通道，本期只实现 TAA 侧读取；
验证先走容器/本地路径，initrd 注入作为后续项单列。

## 测试

- `pkg/crypto/sm2_scalar_test.go`：32 字节往返；`NewSM2PrivateKeyFromScalar(ScalarBytes())`
  公钥不变；长度 0/31/33、`D=0`、`D>=N` 拒绝。
- `internal/app/taa/taa_secret_test.go`：
  - 派生与 `SM3Sum(hwKey||contract)[:16]` 一致，并对固定输入 pin 一个 hex 向量；
  - seal→open 往返得到同一 `D`、同一公钥；密文恰 60 字节、hex 恰 120 字符；
  - 错 contract、错 hwKey、篡改密文、非 60 字节、明文非 32 字节 → 错误；
  - `resolveStartupKeyMaterial`：空 env 正常生成；非空 env 恢复且 `taaSecretKey == ""`；
    环境变量优先（旧文件变 `*.bak.*`）；磁盘密钥相同则不重写；`source=sm2`+env → 报错；
    csv-hw 取 key 失败 → fatal。
- `internal/controller/register_test.go`：现有 7 参数调用补 `""`；新增“含字段”和
  “omitempty 时字段不存在”两条 wire-format 断言。
- `internal/platform`：失败 dump 中 `taaSecretKey` 被 redact、其余字段完整。
- `internal/config` 无需改动（`TAASECRETKEY` 不进配置文件，保持既有“配置不读无关环境变量”测试）。

新增代码注释一律英文。

## 实施顺序

1. `pkg/crypto` 标量 helper + 测试。
2. `taa_secret.go` 派生/封装/打开 + 测试。
3. `sealing_key.go` 拆分 fetch，更新现有 6 个用例。
4. `startup_keys.go` 恢复/归档 + 测试。
5. `app.go` 接线、注册链路透传、`LogRequestFailure` redact + 测试。
6. mock、四份文档、CHANGELOG。
7. 全量验证与真机验证。

## 验证

本地：

```bash
gofmt -l ./pkg/crypto ./internal ./tools/platform-mock
go vet ./...
go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/taa ./cmd/taa
```

（`pkg/crypto/crypto_test.go` 是历史未格式化文件，不要顺手改。）

本地 docker（`source=sm2`）：

- 启动日志出现“non-CSV instance: taaSecretKey is not reported”；mock 的
  `register-state.json` 无 `taaSecretKey` 字段；设置 `TAASECRETKEY` 时启动失败且错误信息明确。

真机 CSV2（172.16.10.178，`source=csv-hw`）：

1. 不设 `TAASECRETKEY` 启动：平台/mock 收到的 `taaSecretKey` 恰 120 hex 字符；用同一
   hwKey+CONTRACT 离线复算，解出的公钥与 TAA 日志公钥一致。
2. 备份并删除 `keys/sm2_private_key.pem`、`sm2_public_key.pem`，把上一步的值作为
   `TAASECRETKEY` 重启：日志为 recovered，公钥与原来相同，注册请求中**没有**
   `taaSecretKey`，`state.sealed` 指纹不变且正常解密。
3. 负向：改一位密文 → 启动非零退出并报 GCM 认证失败；`source=sm2` + `TAASECRETKEY`
   → 启动报错；`TAASECRETKEY` 为奇数长度 hex → 报解码错误。

## 风险与说明

- 协议必须与平台侧逐字节一致：32 字节 hwKey 直接拼 CONTRACT 的 UTF-8 字节，无分隔符/标签，
  SM3 取前 16 字节；SM4-128-GCM nonce 随机且前置，密文 60 字节、hex 小写。
- 同一 hwKey+CONTRACT 下每次启动的 `taaSecretKey` 都不同（随机 nonce），但解出的 `D` 相同；
  平台不能拿密文做实例唯一标识。
- CONTRACT 变更（或硬件 key 变化）会让旧 `TAASECRETKEY` 解不开，启动 fail-closed——符合预期。
- 恢复出的私钥会写盘；下次启动即使 env 仍在也只是重新解密并比对，幂等、不反复归档。
- 非 CSV 环境明确不导出私钥密文，也不接受 `TAASECRETKEY`。

## 工作区与提交

- 按用户要求直接在共享检出 `/home/hjy/taa` 的 master 上实施，不新建 worktree/分支。
- 提交信息：`feat(register): report an SM4-GCM-wrapped TAA key and recover from TAASECRETKEY`
  （英文 Conventional Commits；按用户规则不加任何 Co-Authored-By/AI 署名）。
- 提交后按需重新部署 pod 做真机验证。
