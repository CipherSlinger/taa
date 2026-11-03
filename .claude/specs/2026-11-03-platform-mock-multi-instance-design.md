# platform-mock 并发多实例设计

**日期:** 2026-11-03
**状态:** 已确认，待实现

## 目标

让一个 platform-mock 进程同时服务多个 TAA 实例（tee / fhe / data-anaylsis 均可），实例之间在注册、密钥、上报、进度、日志和控制台视图上完全隔离。单实例是多实例的特例，旧行为保持兼容。

已确认的两个前提：

- 出站地址按**注册请求的来源 IP** 推导，不引入静态实例表。
- 多实例能力**默认开启**，不设开关。

## 非目标

- 不修改 TAA 侧代码，不改 envelope 协议（外层仍是 `{dockerId, cipher, sign}`）。
- 不引入实例鉴权：实例身份仍由“持有该 dockerId 注册时提交的 SM2 私钥”证明。
- 不处理反向代理/端口转发之后的来源 IP 失真；该限制写入文档。
- 不重做控制台视觉，只增加实例选择器。

## 实例身份

实例身份是注册报文里的 `dockerId`。TAA 的每一条出站报文都在 envelope 外层写入它
（`internal/app/taa/app.go:184` 的 `Seal(plaintext, dockerID)`）。

外层的 `dockerId` **只作为选钥提示，不作为身份依据**：

1. 按提示找到该实例的已注册公钥；
2. 用该公钥验签；
3. 验签通过后，读明文里的 `dockerId`；明文与提示都非空且不一致则拒绝；
4. 最终身份取明文 `dockerId`，缺失时退回提示。

即使攻击者伪造提示，也只有持有对应实例私钥才能通过验签，因此不构成越权。

## 状态隔离

### 目录结构

```
<state-dir>/
├── platform-key.json                 # 平台身份（全局唯一）
└── instances/
    ├── i-<sha256(dockerId)[:16]>/
    │   ├── instance.json
    │   ├── register-state.json
    │   ├── report-state.json          # reportResourceRes
    │   ├── reportRes-state.json
    │   ├── reportModelImport-state.json
    │   ├── reportAudit-state.json
    │   ├── reportProgress-state.json
    │   ├── modelLog-state.json
    │   └── taaLog-state.json
    └── i-<sha256(otherId)[:16]>/
```

- 目录名只取 `dockerId` 的 SHA-256 前 16 个十六进制字符，杜绝路径穿越。
- `dockerId` 为空时目录名为 `i-legacy`，仅供迁移和非法注册展示使用。
- `instance.json`：`{dockerId, taaTarget, createdAt, updatedAt}`，用于启动扫描。

每个实例复用现有 store 类型和文件格式，不做跨实例的 map 化改造：

```go
type instanceStores struct {
    dockerID string
    dir      string
    register          *registerStateStore
    reportResourceRes *reportStateStore
    reportRes         *reportStateStore
    reportModelImport *reportStateStore
    reportAudit       *reportStateStore
    progress          *progressStateStore
    modelLog          *modelLogStore
    taaLog            *taaLogStore
}
```

### 实例管理器

新增 `instances.go`：

```go
type instanceManager struct {
    mu       sync.RWMutex
    root     string
    cfg      Config
    byID     map[string]*instanceStores
    scanned  bool
}

func newInstanceManager(stateDir string, cfg Config) *instanceManager
func (m *instanceManager) getOrCreate(dockerID string) *instanceStores
func (m *instanceManager) lookup(dockerID string) *instanceStores
func (m *instanceManager) list() []*instanceStores
func (m *instanceManager) defaultID() string
func (m *instanceManager) resolve(r *http.Request) (*instanceStores, error)
```

- 启动时扫描 `instances/*/instance.json`，惰性加载 store。
- `defaultID()`：最近一次 `Accepted=true` 的注册；没有已接受注册时取最近一次尝试；没有实例时返回空串。
- `resolve(r)`：读取 `?dockerId=`；显式给出但不存在返回 404；未给出返回默认实例；没有任何实例返回 503
  （`no TAA instance registered yet`）。
- 管理器自身的 map 由互斥锁保护；各 store 继续用自己的锁。

### 旧状态迁移

`NewServer` 初始化时：

1. 若 `<state-dir>/instances/` 不存在且存在旧版状态文件（`register-state.json` 等 8 个）：
2. 读旧 `register-state.json` 的 `dockerId`（缺失则用空串）；
3. 创建对应实例目录，把这 8 个文件移动进去，写 `instance.json`；
4. 记录一条迁移日志。

若 `instances/` 已存在而根目录仍有旧状态文件，则不迁移并记录警告，避免覆盖正在使用的实例数据。

`platform-key.json` 不迁移，仍在 `<state-dir>` 根下。

## 密钥管理

`keystore` 从“一把 TAA 公钥”改为“按 dockerId 分表 + 旧单钥回退”：

```go
type keystore struct {
    priv           *teecrypto.SM2PrivateKey
    taaPubs        map[string]*teecrypto.SM2PublicKey // dockerId -> key
    legacyTaaPub   *teecrypto.SM2PublicKey            // 旧文件里的单钥
    userID         []byte
    path           string
}
```

- `platform-key.json` 新增 `taaPublicKeysHex: {dockerId: hex}`，保留 `taaPublicKeyHex` 作为迁移回退。
- `setTaaPublicKey(dockerID, pub)` 只替换该 dockerId 的钥匙；同 dockerId 重注册视为密钥轮换。
- `taaPublicKey(dockerID)`：先查表；未命中时回退 `legacyTaaPub`（若存在），用于兼容旧单实例钥匙文件。
- 出站 `sealForTAA(dockerID, plaintext)` 使用该实例的钥匙；找不到钥匙时报错，不回退明文。

入站：

```go
func (s *keystore) openBody(body []byte) (plaintext []byte, dockerID string, err error)
func (s *keystore) openFromTAAResponse(dockerID string, env *envelope.Envelope) ([]byte, error)
```

- `openBody` 按“外层提示 → 单钥回退 → 验签 → 明文交叉校验”的顺序执行。
- 注册仍走 `openRegister`：只解出 `taaPublicKey` 自验签，认可后由调用方 `setTaaPublicKey(id, pub)`。

## 出站寻址

注册成功时：

```go
target := deriveTAATarget(r.RemoteAddr, cfg.TAAPort)
```

- `RemoteAddr` 取 IP 部分；IPv6 域名加方括号。
- 结果形如 `http://10.244.0.7:6001`，写入 `registerState.TaaTarget`（该结构新增字段）和
  `instance.json`。
- 同一 dockerId 重注册会覆盖地址（实例可能重建）。

解析优先级：

1. 实例数 `<= 1` 且配置了 `-taa-target` → 用静态地址（保持旧单实例行为）。
2. 选中实例有推导地址 → 用它。
3. 配置了 `-taa-target` → 静态地址（多实例下的兜底）。
4. 无实例或以上都缺失 → `discoverTAAAddr(-taa-pod, -taa-ns, -taa-port)`。
5. 仍无地址 → 明确报错，不跨实例借地址。

多实例部署应省略 `-taa-target`，让每个实例走自己的推导地址。

## HTTP API

所有 `/api/*` 接受可选 `?dockerId=`；不传时使用默认实例（最近一次成功注册），保持旧行为。
`lastReportAt` 取四个 report store 中最大的 `ReceivedAt`；日志条数取 `modelLog` / `taaLog`
的 `TotalCount`。

| 端点 | 多实例行为 |
|---|---|
| `GET /api/instances`（新增） | 返回 `{instances: [...], defaultDockerId}`，每项含 dockerId、accepted、receivedAt、taaTarget、lastReportAt、日志条数 |
| `GET /api/register/status` | 选中实例的注册状态 |
| `POST /api/register/reset` | 带 dockerId 清该实例；不带清全部 |
| `/api/reportRes/*` 等各状态/重置端点 | 同上，按实例读写 |
| `GET /api/dashboard/status` | 选中实例的聚合状态，附带实例列表 |
| `GET /api/taa-target` | 选中实例的地址；无实例时退回静态地址或 Pod 发现结果 |
| `POST /api/taa/status`、`getResourceInfo`、`stopTraining`、`/api/fhe/submit` | 用选中实例的地址加封并发送 |
| `/api/upload` | 上传文件仍全局存放；加密回退用的公钥按选中实例取 |
| `/taa/*` 反代 | 用 `?dockerId=` 选目标；转发前从 URL 去掉该参数 |

反代实现：

- 按目标地址缓存 `httputil.ReverseProxy`。
- `ModifyResponse` 从请求 context 取 dockerId，用该实例的钥匙解开 TAA 响应。
- 请求体加封同样按 dockerId 取钥。

## 控制台

- 顶部“TAA 服务地址”旁增加实例下拉框（`id="instanceSelect"`）。只有一个实例时隐藏，外观与现在一致。
- 启动时拉 `/api/instances`；选中项保存在页面全局，切换后刷新仪表盘、日志等轮询。
- 新增 `mockFetch(path, opts)`：自动追加 `dockerId`；所有 `/api/*` 调用改用它。
- `taaFetch` 在目标以 `/taa` 结尾时追加 `dockerId`，反代负责剥离。
- `detectTAAProxy` 保持现有逻辑；多实例下仍将地址设为 `location.origin + '/taa'`，由选择器决定实例。

## 部署脚本

- `deploy-platform-mock.sh`：
  - `--taa-target` 语义改为“单实例固定地址”；省略即多实例推导模式。
  - `--taa-port` 同时作为推导端口（默认 6001）。
  - 帮助文本与 `deploy.md` 同步更新。
- `deploy.sh`：
  - 新增环境变量 `MULTI_INSTANCE=1`。
  - 本地 docker 模式：置位时不传 `--taa-target`。
  - 远端 k8s 模式：置位时跳过单 Pod IP 发现，不传 `--taa-target`。
  - 未置位时行为完全不变。
- `deploy-fhe.sh` 保持单实例，不改。

## 错误处理

- 未注册任何实例时，需要出站的端点返回 503 和明确文案。
- 指定了不存在的 dockerId 返回 404。
- 找不到实例钥匙时返回 502/401（视方向），不回退明文。
- 推导地址失败（来源 IP 不可解析）时，该实例出站请求返回明确错误；注册本身仍然成功。
- 非法或未通过的注册只写入已存在的实例或 legacy 实例，不为陌生 dockerId 创建目录，避免目录膨胀。

## 测试

Go 单测（`go test ./tools/platform-mock/... -race`）：

1. 两个 dockerId 先后注册，两把公钥同时保留；老实例在新实例注册后上报仍验签成功。
2. 两个实例并发注册、并发上报，状态互不覆盖。
3. 用 A 的 dockerId + B 的私钥签名 → 401。
4. 同一 dockerId 重注册只轮换自己的钥匙，不影响其它实例。
5. `deriveTAATarget`：IPv4、IPv6、缺失端口、非法 RemoteAddr。
6. 出站按选中实例加封，发往各自地址。
7. `/taa?dockerId=` 路由到正确后端，转发 URL 不含 dockerId。
8. 旧状态文件 + 旧钥匙文件迁移后，单实例行为不变。
9. `/api/instances`、按实例 dashboard、按实例 reset、reset-all。
10. 现有 `server_test.go` / `keystore_test.go` 全量通过。

前端与脚本：

- index.html 存在 `instanceSelect`；单实例时隐藏的判定有测试覆盖。
- `bash -n deploy-platform-mock.sh deploy.sh`；多实例 dry-run 不传 `--taa-target`。

## 文档

- `tools/platform-mock/README.md`：多实例行为、`?dockerId=`、`/api/instances`、地址推导限制。
- `deploy.md`：多实例部署示例与 `MULTI_INSTANCE=1`。
- `CHANGELOG.md`：记录默认行为变化、迁移方式与已知限制。
