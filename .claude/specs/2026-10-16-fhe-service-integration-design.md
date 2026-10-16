# FHE 服务接入 TAA：把 Latti FHE 作为一类执行后端编排进来

日期：2026-10-16
状态：已实现；远程部署与注册已在真 GPU 宿主上跑通，FHE 任务端到端待跑（见文末「验证状态」）

## 背景

交付包 `latti-fhe-handoff/` 提供了一套已经跑通端到端的平台化 FHE 服务端（cifar-10）：

- 服务端镜像 `latti/latti-server:latest`（`sha256:252fa15c9133…`，417 MB），内含 Python 3.10 + `/app/server`；
- FHE 原生运行时（精简包，约 100 MB），**镜像外挂载**，worker 用 `ctypes` 直接加载 `liblattisense.so`；
- 部署编排 `deploy/docker/`（api / worker / redis 三服务 + node.toml 模板 + run-node.sh）；
- 测试模型 `data/models/cifar10/server/` 与浏览器 WASM 客户端包。

它对上层只提三件事：**读写约定目录 → 算 → 回调通知**。明确声明"不碰 MinIO、不碰鉴权"，
把对象存储与文件上下行留给平台侧。

本设计要做的是**平台侧那一半**：把 FHE 服务作为 TAA 的一类执行后端编排进来。已确认的范围是
**只做 TAA 服务端 + platform-mock 全链**，浏览器/WASM 与产品级前端不在本轮。

FHE 服务**不做代码审计、不做远程证明**——这两条不是省事，是它在密码学上不需要：输入是 FHE 密文
（保护来自同态加密而非 TEE 内存加密），模型是运行时加载的 FHE 层与参数而非用户提供的可执行代码。

## 现场事实（实测，不要再假设）

### 交付包侧

- **运行时的硬件门槛是硬的**：`liblattisense.so` 的 `NEEDED` 含 `libcudart.so.12`、`libcurand.so.10`、
  `librmm.so`；`build-info/manifest.json` 写明 `"cuda": "12.8"`、`"cuda_architecture": "89"`（Ada）。
  即**只能跑在 NVIDIA Ada 卡上**，Hygon DCU（TAA 所在 CSV2 环境的那张卡）跑不了。
- 实测资源（`模型端到端性能验证报告.md`）：单 case GPU 推理 **7.2–7.8 s**；10 case 任务冷启动 **108.9 s**、
  同用户第二任务 **78.6 s**（省掉 28.4 s 的 `import_eval_context`）；worker RSS 峰值 **29.2 GiB**；
  显存池首次上卡按空闲显存 90% 预占 **43,875 MiB / 49,140 MiB**，空闲回落 **515 MiB**；
  单用户真实设备需求约 **15.5 GiB**。
- **公钥体积超出 TAA 现有下载上限**：浏览器 `setup()` 产出的 `eval_context.bin` 实测
  **3,329,929,205 B（3.101 GiB）**，而 TAA 的 `codeAudit.resultCheck.maxFileBytes` 默认
  **3,221,225,472 B（3 GiB）**，同时是 import/importModel 的下载上限——**超出 108,703,733 B（103.7 MiB）**。
  沿用现有上限则公钥根本下不下来。
- 目录约定（容器内 `/data`，宿主机 `HOST_DATA_DIR`），**公钥路径不含 model_id**：
  ```
  models/<model_id>/server/          平台放，FHE 读（activate 热加载）
  keys/<user_id>/eval_context.bin    平台放，FHE 只读不校验
  tasks/<task_id>/input.zip          平台放，条目 <case_id>.ct
  results/<task_id>/output.zip       FHE 写，条目 <case_id>.result.bin
  ```
- 接口前缀 `/api/v1`，**无鉴权**，租户标识走 `X-User-Id` 头：`/health`、`/models`、
  `POST /models/activate?model_id=`、`POST /tasks`、`GET /tasks/{id}`、`/tasks/{id}/events`(SSE)、
  `/tasks/{id}/cancel|heartbeat|continue|delete`、`GET /tasks/{id}/results`、`/results/download`。
  **没有任何上传接口**——输入包必须由别人先落到它本地盘，这是"共享目录"契约存在的原因。
- 任务终态后向 `callback_url` POST 结果 JSON，失败按 **0/1/4/16 s** 退避重试。
- 同用户连续任务会复用常驻解析结果（日志 `Reusing resident server`），`resident_max_servers=4`。
- 交付包自带的 `sha256sum -c SHA256SUMS` **失败**：清单列的是 `client/latti-client-wasm-0.1.0.zip`，
  实际文件是 `client/latti-wasm-0.1.1.zip`。两个大件（镜像、运行时归档）校验 OK。

### TAA 侧（现状，决定了改动落点）

- 外部服务接入**只有一个先例**：`codeAudit.llm`（teellm）。没有通用后端注册表。
- **没有任何对象存储/MinIO 客户端**，也没有共享目录配置项，也没有回调接收端点。这三样都是 FHE 契约的前提。
- 代码审计**已经是建议性的**：`import_processing.go:90` 记录后 `:93` 在后台 goroutine 里跑，
  失败只 WARN（`:620`），import 早已返回成功——审计无法回滚 import，也不阻断训练。
- 远程证明**已经非致命**：`app.go:141` 生成失败写空报告继续（`:574-578`），证书链自校验失败只
  打 WARNING 且 `verifiedPass=false`（`:590-592`），服务照常启动。**没有关掉证明的配置开关。**
- **唯一真会 fail-closed 挡住的是 `export` 的产物泄露检查**：`handler_export.go:86-110`——判定为泄露
  一律 400；**判定缺失**在 `failClosed` 下 500（docker/initrd 模板是 `failClosed=true`）。
- `export` 还硬要求 `ResultDir` 下存在 `training_report.json`（`handler_export.go` 开头 `os.Stat`），
  没有就 404。
- `import` 的资源解密**已经能识别裸 zip 并跳过解密**：`resolvePlaintextResource` 在 URL 非 `.enc`
  结尾时探压缩包魔数（ZIP/GZIP/TAR），命中即原样返回。**免信封在 import 侧不需要改代码。**
- 任务级并发已串行化：`tryAcquireTask`（`route.go:705`）+ `promoteCurrentTaskToTraining`（`route.go:803`），
  已有训练在跑时新任务返回 409。
- `importRequest` 现有字段：`resourceUrl` / `requestId` / `taskId` / `publicKey` / `runtimeConfig`。
- `exportRequest` 现有字段：`publicKey` / `requestId` / `taskId`；"阶段 3 优先用阶段 1 保存的公钥，
  其次用请求携带的 publicKey"，**两者都空则明文导出**。
- 配置分 6 段 `server` / `platform` / `storage` / `model` / `codeAudit` / `attestation`
  （`startupConfigFile`，`config.go:154`）。`server` 段目前只有 `addr`。
- 结果目录命名 `resultDirForRequestTask(root, requestID, taskID)` =
  `<storage.result>/<requestId>-<taskId>`（`import_helpers.go:20`）。
- platform-mock **已经把上传目录挂成 `/files/`**（`server.go:160`），即本地 MinIO 的替身；
  另有 `/taa/` 反向代理到 TAA（`server.go:173`）。

## 关键决策（2026-10-16 与需求方确认）

| # | 决策 |
|---|---|
| 1 | TAA 做**编排网关**：平台仍走现有 `import/switch/export` 契约，文件与任务流转由 TAA 负责；FHE 成为 TAA 的一类任务 |
| 2 | **TAA 与 FHE 同机部署**在 GPU 节点，共享目录就是本地 bind mount；该节点上 TAA 不进 CSV2、不做远程证明 |
| 3 | 平台接口**几乎不改**：模型资源走 `importModel`，公钥与密文包走 `import`（靠新增字段区分），阶段仍走 `switch`，结果走 `export`（执行的真正触发点是 import，见决策 5） |
| 4 | `import` 新增 `evalKeyUrl` + `evalKeyFileHash`；公钥按 **URL 下载、按哈希落盘缓存，命中则不重复下载** |
| 5 | **数据下发（import 落盘）即触发** FHE 任务，与现有训练链路的触发方式同构 |
| 6 | 终态通知**回调驱动 + 轮询兜底** |
| 7 | FHE 路径**免代码审计、免产物泄露检查、免导出信封**；启动期证明在新的 `server.type=fhe` 下显式跳过 |
| 8 | `userId = evalKeyFileHash`，`model_id = modelHash`，**不新增标识字段** |
| 9 | 新建顶层 `deploy-fhe.sh`，对齐 `deploy-llm.sh` 的先例；`deploy.sh` 只管 TAA 本体 |
| 10 | 本轮交付边界：TAA 服务端 + platform-mock 全链；浏览器/WASM 与产品前端不在范围内 |
| 11 | 实例角色由配置 `server.type` 区分，取值 `tee` 或 `fhe` |
| 12 | `evalKeyFileHash` 用 **SM3** |
| 13 | 结果在 `ResultDir` 内以 **`output.zip` 原样保留**（贴合交付包契约），另加 `training_report.json` |
| 14 | 公钥缓存**不自动淘汰** |
| 15 | 回调端点**加鉴权** |
| 16 | 显存与常驻参数**按交付包默认值**（`resident_max_servers=4`，池按空闲 90% 预占），不做调优 |

## 设计

### 1. 部署与目录契约

一台 GPU 节点跑两类东西，共享同一个 bind mount 目录，另有一条 bind 只给 TAA：

```
<host>/
├── deploy/docker/                   FHE 三件套 compose（交付包原样，不改）
├── third_party/latti-ai-runtime/    FHE 原生运行时（容器内只读挂载）
├── var/fhe-data/                    ← 共享数据目录，TAA 与 FHE 都挂（第一条 bind）
│   ├── models/<modelHash>/server/               TAA 写 / FHE 读
│   ├── keys/<evalKeyHash>/eval_context.bin      TAA 写 / FHE 只读
│   ├── tasks/<taskId>/input.zip                 TAA 写 / FHE 读
│   ├── results/<taskId>/output.zip              FHE 写 / TAA 读
│   ├── taa-fhe-keys/<evalKeyHash>/              TAA 私有：公钥缓存（决策 14 不淘汰）
│   └── taa-results/                             TAA 私有：结果副本与 import-index.json
└── var/taa-state/                   ← TAA 私有目录，只挂进 TAA 容器（第二条 bind）
    └── keys/                                     SM2 密钥对与 state.sealed
```

`taa-fhe-keys/` 与 `taa-results/` 不属于 FHE 契约，FHE 侧不读不写。它们必须落在共享目录里，是因为
容器在镜像或 bind 变化时会被重建、可写层随之清空：公钥缓存留在 `/root/taa` 下则每次部署都要重下
3.1 GiB/用户；结果副本与 `import-index.json` 留在 `/root/taa` 下则已完成任务的 export 在重建后
一律 404。

`taa-state/keys/` 同样要持久化，但它要的是**第二条 bind**，不是共享目录那一条。放共享目录也能活过
重建，代价却是把两样东西交给半可信的 FHE 服务去读：一个是 SM2 私钥（这个实例的身份），另一个是
`state.sealed`——`ModelChecksum` 就在密封状态里，丢了实例就会忘记"模型已导入"，此后每次数据下发
都被拒（`尚未导入模型`），而模型包一直躺在 `models/<hash>` 上。TAA 对 `storage.keys` 强制 0700，
但那挡的是非 root 的容器用户，挡不住 root。

**注意**：`deploy-fhe.sh` 渲染时把 `fhe.dataDir` / `fhe.keyCacheDir` / `storage.result` 从
`HOST_DATA_DIR` 派生，把 `storage.keys` 从 `HOST_TAA_STATE_DIR`（默认 `/opt/taa-state`）派生，
并**逐条**断言每个路径落在承载它的那条 bind 之内；两条 bind 也都参与容器的重建判定。任一处漏掉，
覆盖对应变量的部署就会把它悄悄放回容器可写层。`HOST_TAA_STATE_DIR` 另有守卫拒绝它与
`HOST_DATA_DIR`、`HOST_REDIS_DIR`（FHE 挂载的树，防被读）以及 `HOST_RUNTIME_DIR`
（`rsync -a --delete` 的目标，防被删）重叠。

TAA 容器（普通 docker，**非 TEE、无 `/dev/csv-guest`**）挂两条 bind：共享目录挂成配置里的
`fhe.dataDir`，TAA 私有目录挂成 `storage.keys` 的父目录。**TAA 与 FHE 进程看到的共享目录路径必须
一致**——这是整个契约的支点；私有目录则相反，它不进任何 FHE 容器。

`server.type=fhe` 的 TAA 实例与 FHE 三件套同机；`server.type=tee` 的实例保持现状，完全不受影响。

### 2. 配置

`server` 段新增 `type`：

```json
"server": { "addr": ":6001", "type": "fhe" }
```

- 取值仅 `tee` / `fhe`，**缺省 `tee`**（现有三份模板行为不变）。
- 其他取值在启动期**拒绝**，与仓库既有风格一致（`codeScan.engine`、`llm.policy` 都是"不认识就拒"，
  而不是静默退回默认——静默退回会让部署以为跑的是另一套）。

新增 `fhe` 段，**仅当 `server.type=fhe` 时读取**；`type=tee` 下出现该段记 WARN 后忽略：

```json
"fhe": {
  "endpoint": "http://127.0.0.1:58996",
  "dataDir": "/opt/fhe-data",
  "keyCacheDir": "/opt/fhe-data/taa-fhe-keys",
  "callbackBaseUrl": "http://172.16.10.130:6001",
  "callbackToken": "<共享串>",
  "maxEvalKeyBytes": 6442450944,
  "pollIntervalMs": 5000,
  "requestTimeoutMs": 30000,
  "taskTimeoutMs": 1800000,
  "activateModelOnImport": true
}
```

`maxEvalKeyBytes` 是**必须独立存在**的一项：不能复用 `codeAudit.resultCheck.maxFileBytes`
（3 GiB < 公钥 3.101 GiB，见「现场事实」）。这条路径不调用 `GetMaxFileBytes()`。
默认值给 6 GiB，足够容纳将来的参数变更，同时仍是一个有限上界。

`type=fhe` 时 **`endpoint` / `dataDir` / `keyCacheDir` / `callbackBaseUrl` / `callbackToken`
五项都必填且非空**，任一缺失或为空在启动期拒绝。`callbackToken` 尤其不能为空——回调端点无鉴权
等于对同机任意进程开放。`type=tee` 时不校验（该段被忽略）。

新增配置模板 `configs/taa-fhe.json`；`configs/taa-production.json` / `taa-docker.json` /
`taa-initrd.json` **不改**（它们都是 tee 实例）。

#### 2.1 `platform` 段与身份优先级（2026-10-16 补）

模板新增 `platform` 段，作为 FHE 实例注册身份的兜底：

```json
"platform": { "ip": "127.0.0.1:18081", "dockerID": "taa-fhe", "contract": "" }
```

`ip` 指向 platform-mock（**18081 而非 18080**：共享 FHE 宿主上 18080 被 `ccs-node-agent` 占着），
`dockerID` 非空是硬要求——`register.go` 对空 dockerID 直接报错，空值等于永远注册不上。

**优先级按实例类型分叉**（`internal/config.applyFHEIdentityOverride`，排在 `applyStartupConfigFile`
之后）：

| 实例类型 | `PLATFORM_IP` / `DOCKER_ID` | `CONTRACT` |
|---|---|---|
| `tee` | 文件赢（既有行为，三个 tee 模板与既有测试不动） | 文件赢 |
| `fhe` | **环境变量赢**（非空才覆盖，空则回落文件） | 文件赢 |

理由：`tee` 实例的 platform 地址是它被打包时那个部署的一部分；`fhe` 实例则相反——同一个镜像会被
发到任意一台空闲 GPU 宿主，而那台机器上 platform 在哪，写模板的时候不可能知道，所以模板只能是兜底。
两项各自独立判定，只设 `PLATFORM_IP` 不改 `DOCKER_ID` 时，后者仍取文件里的值。

### 3. 接口契约变更

`POST /v1/taa/import` 请求体新增两个字段：

```json
{ "resourceUrl": "<input.zip 的下载地址>",
  "requestId": "...", "taskId": "...",
  "evalKeyUrl": "<eval_context.bin 的下载地址>",
  "evalKeyFileHash": "<SM3 hex, 64 字符>" }
```

规则：

- `server.type=fhe` 时**两个字段必须同时出现**：只给一个 → 400；都不给 → 400
  （该实例只服务 FHE，不跑训练链路）。
- `server.type=tee` 时**出现任一字段即 400**，报文说明该实例类型不接受 FHE 字段。
  不静默忽略——静默忽略会让平台以为任务提交成功。
- `evalKeyUrl` 有两个用途：判分支（非空 ⇒ FHE 任务），以及公钥未缓存时的下载地址。
  已有缓存时**不下载**，但仍要求字段存在（它同时声明了任务类型与期望的 `userId`）。
- `resourceUrl` 指向 `input.zip`（裸 zip）。现有 `resolvePlaintextResource` 会认出压缩包魔数并跳过
  解密，**免信封在 import 侧无需改代码**。

新增 `POST /v1/taa/fheCallback`，注册进 `router.go` 的 `taaRoutes`（走 `postOnly`）。
鉴权：`callbackToken` 以 query 参数携带，TAA 侧**常数时间比对**，不符返回 404（不是 401——
不向未持有 token 的调用方确认这个端点的存在）。

### 4. FHE 任务执行流程

`importHandler` 在 `unwrapDataKeyCipherFromURL` 之后判分支。FHE 分支复用同一把串行闸门
（`tryAcquireTask` / `promoteCurrentTaskToTraining` 不动），因此 FHE 任务与训练任务共享
"同一时刻只有一个任务在跑"的语义。

1. **解析公钥**：`keyCacheDir/<evalKeyHash>` 命中 → 跳过下载。
   未命中 → 从 `evalKeyUrl` 下载（上限 `maxEvalKeyBytes`）到临时文件 → 算 SM3 比对
   `evalKeyFileHash` → 不符即失败并删除临时文件 → 相符则原子 rename 进缓存。
   缓存文件本身是内容寻址的，因此"命中"不需要再校验一遍哈希。
2. **公钥就位**：写 `keys/<evalKeyHash>/eval_context.bin`。同文件系统优先**硬链接**
   （3.1 GiB 不产生拷贝），失败回退为 `copy`。
3. **模型就绪**：`models/<modelHash>/server/` 已由 `importModel` 阶段铺好；
   调 `POST /api/v1/models/activate?model_id=<modelHash>`（幂等，可重复调用）。
4. **输入就位**：下载 `resourceUrl` → 校验是压缩包 → 原子写入 `tasks/<taskId>/input.zip`。
5. **建任务**：`POST /api/v1/tasks`，body
   `{"user_id": "<evalKeyHash>", "model_id": "<modelHash>", "task_id": "<taskId>",
     "callback_url": "<callbackBaseUrl>/v1/taa/fheCallback?token=<callbackToken>",
     "cancel_on_disconnect": false}`，并带 `X-User-Id: <evalKeyHash>` 头。
6. **等终态**：回调优先；同时按 `pollIntervalMs` 轮询 `GET /tasks/{taskId}` 兜底。
   总预算 `taskTimeoutMs`，超时按失败处理并上报。
7. **收结果**：同机直接读 `results/<taskId>/output.zip`；读不到才回落到
   `GET /tasks/{taskId}/results/download`。
8. **落 ResultDir**：`<storage.result>/<requestId>-<taskId>/` 下写入
   `output.zip`（**原样字节**，不解开）+ `training_report.json`。
   报告复用 `buildAndSaveTrainingReport`，于是 `export` 一行都不用改。
9. **上报**：`reportProgress` 用轮询到的已完成 case 数映射百分比；`reportRes` 照旧。

`switch` 保持原样（仍只切阶段并记录），FHE 路径下它对执行**没有影响**——执行由 import 触发。
这一点写进文档，避免平台误以为要先 switch 才能跑。

`importModel` 在 `type=fhe` 下：解压到 `<fhe.dataDir>/models/<modelHash>/server/` 并
（按 `activateModelOnImport`）调 activate，**不进 `beginModelImportAndAudit`、不调 `launchModelAudit`**。
`modelHash` 取该模型包的 SM3（与现有 `setModelChecksum` 同源）。

模型包内的目录层级由交付包定义：解压后必须存在 `server/` 一层，其下是
`ckks_parameter.json` / `task_config.json` / `nn_layers_ct_0.json` / `model_parameters.h5` /
`mega_ag.json` / `task_signature.json`（`node.toml.template` 注释里列的就是这几个）。
解压后若没有 `server/`，视为包结构不符，import 失败并上报——不替它猜层级。

### 5. 免检查的落点

| 检查 | FHE 路径行为 | 实现方式 |
|---|---|---|
| 三层代码审计 | 不跑 | `type=fhe` 的 `importModel` 不进审计分支，也不写"欠一次审计"的 pending 标记 |
| 启动期远程证明 | 显式跳过 | `type=fhe` ⇒ 不尝试生成 CSV 报告（GPU 节点无 `/dev/csv-guest`，尝试必然失败并刷 WARN），注册时 `attestation` 为空、`verifiedPass=false`，日志显式声明"实例类型为 fhe，不提供远程证明" |
| 产物泄露检查 | 不跑 | 不调 `runResultCheck`；改向索引写 `ResultCheck{Passed:true, Details:["skipped: FHE ciphertext result"]}`，使 `export` 的 fail-closed 闸门有解且审计留痕 |
| 导出信封 | 明文导出 | FHE 实例不保存 `ExportPublicKey`（importModel 携带 `publicKey` 时记 WARN 并忽略），`export` 自然落到"无可用公钥 → 明文 zip"分支 |

### 6. 必须一并接的控制面

- **`stopTraining`** → 映射到 `POST /api/v1/tasks/{taskId}/cancel`，否则 FHE 任务停不下来。
- **回调幂等**：FHE 按 0/1/4/16 s 退避重试，同一 `taskId` 的重复回调只推进状态一次。
- **回调与轮询竞争**：单一状态机，谁先到谁推进终态，另一个到达即无操作。
- **重试**：FHE 任务失败后重放同一个 `import` 时，若 `tasks/<taskId>/` 已存在，走
  `POST /api/v1/tasks/{taskId}/continue` 重跑未完成 case，而不是重建任务。

### 7. 代码结构

```
internal/fhe/
├── config.go      fhe 段解析与启动期校验（type 一致性、token 非空、路径存在）
├── client.go      /api/v1 调用（health/models/activate/tasks/results）+ 终态状态机
├── keycache.go    内容寻址公钥缓存：命中判定、下载、SM3 校验、原子落盘
├── layout.go      目录契约：路径构造 + 标识符严格校验
├── callback.go    回调端点：token 比对 + 幂等
└── fhe_test.go    单测；配一个 httptest 起的 fake FHE server 做契约测试
```

改动点：

| 文件 | 改动 |
|---|---|
| `internal/config/config.go` | `server.type` 解析与校验；新增 `fhe` 段 |
| `internal/controller/handler_task.go` | `importRequest` 加两字段；import 分支判定 |
| `internal/controller/handler_task.go`（`modelImportHandler`） | `type=fhe` 的模型落盘与 activate |
| `internal/controller/import_processing.go` | FHE 分支实现（与 `executeTraining` 平级的一支） |
| `internal/controller/router.go` | 注册 `/v1/taa/fheCallback` |
| `internal/controller/handler_export.go` 或 `result_check.go` | FHE 路径写"跳过"裁决 |
| `configs/taa-fhe.json` | 新模板 |
| `README.md` | 配置字段表补 `server.type` 与 `fhe` 段 |

**路径穿越防护是硬要求**：`evalKeyFileHash` 与 `modelHash` 会**直接当目录名用**。
两者都必须校验为 `^[0-9a-f]{64}$`（SM3 十六进制小写），否则平台传 `../../etc` 就能把文件写到
`dataDir` 外。这一条要有独立单测。

### 8. `deploy-fhe.sh`

对齐 `deploy-llm.sh` 的形态，负责 GPU 节点上 FHE 侧的部署：

- 导入 `latti-server` 镜像（`docker load`）、校验 `SHA256SUMS`（**注意 WASM 那条对不上**，见风险）；
- 铺 `third_party/latti-ai-runtime` 到 `HOST_RUNTIME_DIR`，模型资源到共享目录；
- 渲染 `node.toml`（`scripts/render-node-config.sh`）、起 api/worker/redis；
- 预检：`GET /api/v1/health` + 共享目录可写 + `POST /models/activate` 能成功；
- 起 TAA 容器（`type=fhe` 配置 + 共享目录挂载）。

**远程模式（2026-10-16 补）**：FHE 环节要 GPU，真正有意义的端到端只发生在有卡的那台机器上，所以
脚本支持 `--remote` 直接对 `REMOTE_HOST`（默认 `172.16.10.178`，与 `deploy.sh` 同名同默认）跑：

- **逐命令 ssh 包装**：宿主机侧命令全部收敛在 `run` / `run_in` / `host_sh` / `host_capture` /
  `host_detach` / `upload_file` / `upload_tree` 七个原语里，"这条命令在哪台机器上跑"只在这几个
  函数里决定，调用点不必知道。上传后的 bundle 变量重新指向远端副本，于是所有路径表达式天然是远端路径。
- 上传 `latti-fhe-handoff/`、`deploy/start.sh`、本机 `go build` 出来的 `bin/taa` 与
  `bin/platform-mock`（`--skip-build` 复用已有的）。
- 按用户决定，`taa` 二进制由 driver 编译后 `docker cp` 进容器，**不再依赖基础镜像里那份**。
- `-n/--dry-run` 在远程模式下照样可用且**不要求 ssh 连通**：完整打印每条 ssh 命令行。

**终局闸门（这是本轮改动的真正证明）**：TAA 起来之后去 platform-mock 查它记下的注册，
要求 `dockerId` 等于本次运行身份解析出来的那个、且 `accepted=true`。
"TAA 活着"和"平台收到了它的注册"是两件事：注册被拒在 TAA 侧只是 WARNING + 后台重试，
进程看起来完全健康。**闸门必须看 `accepted` 而不只是 `dockerId`**——`registerState` 在注册被拒时
照样会存下 dockerId。

连带的两处：`start_taa_container` 的 `docker run` 注入 `-e PLATFORM_IP` / `-e DOCKER_ID`，
并把"环境变量是否一致"加进重建判定——只比镜像和 binds 的话，一个已存在但没有这两个变量的容器会被
复用，注入的环境永远进不去，注册继续静默失败；platform-mock 用 `-allow-empty-attestation` 起，
因为 `fhe` 实例按设计写空证明，而 mock 默认拒绝空证明。

### 9. platform-mock 扩展

- 复用现有上传目录（已挂成 `/files/`，即本地 MinIO 替身）承载 `eval_context.bin` 与 `input.zip`；
- 新增算 SM3 的能力（TAA 侧 `HashFileSM3` 在 `pkg/crypto`，mock 需要独立实现或调用）；
- 新增"提交 FHE 任务"的界面/接口：上传两个文件 → 算哈希 → 调 TAA `import` 带两字段 →
  展示回调、轮询与 `export` 结果；
- 新增一个 **fake FHE server**（扮演 `/api/v1`），让**没有 GPU 的机器**也能跑通全链契约。
  真端到端（真 GPU、真推理）只能在 A130 上做。

## 风险与边界

1. **显存与常驻默认值可能不成立**（按决策 16 保留交付包默认，此处只记录）：
   实测单用户设备占用约 **15.5 GiB**，而 `resident_max_servers=4` 意味着 4 个用户的常驻上下文
   合计约 **62 GiB**，**超过该卡的 49,140 MiB**。默认池按空闲显存 90% 预占（43.9 GiB）也逼近上限。
   若生产上真出现多个用户同时用，需要显式设 `HEONGPU_DEVICE_POOL_MAX_BYTES` 并调低常驻数。
2. **`userId = evalKeyFileHash` 意味着换公钥即换用户**：浏览器重新 `setup()` 会产生全新哈希 →
   新的 `userId` → FHE 侧新建一份常驻上下文，旧的那份滞留在内存里（`resident_max_servers` 满了才会挤掉）。
   这是决策 8 的固有代价，需要在运维文档里写明"重生成密钥 = 新用户"。
3. **磁盘**：公钥缓存不自动淘汰（决策 14），每个用户 3.1 GiB，且 `keys/<hash>/` 下还会有一份
   （硬链接则共享 inode，成本可忽略；跨文件系统回退为 copy 则会翻倍）。需要按预期用户数预留磁盘。
4. **交付包自身的校验清单是坏的**：`sha256sum -c SHA256SUMS` 因
   `client/latti-client-wasm-0.1.0.zip` 不存在而失败（实际文件名为 `latti-wasm-0.1.1.zip`）。
   两个大件校验 OK。`deploy-fhe.sh` 不能无条件 `sha256sum -c`，需按实际文件名校验或跳过该条。
5. **回调端点鉴权是单共享串**：同机内网、无每任务凭据。够用但不强；若将来 FHE 与 TAA 不再同机，
   需要换成每任务一次性凭据。
6. **`type=fhe` 实例不再有训练链路**：不带 evalKey 字段的 import 会被拒。若将来需要同一实例两种都跑，
   决策 11 的分支逻辑要重做。
7. **无 GPU 的开发机跑不了真链路**：本机（16 核 / 9 GB 内存 / 无卡）只能跑单测与 fake FHE 契约测试；
   真端到端必须在 A130 上做。

## 明确不做（本次范围外）

- 浏览器 WASM 客户端的托管与产品级前端（决策 10）；
- FHE 侧镜像、运行时、compose、node.toml 的任何修改（交付包原样使用）；
- 显存池与常驻参数的调优（决策 16）；
- 通用 `ExecutionBackend` 抽象（评估过，要重构在跑的训练链路，风险不抵本轮收益）；
- OIDC/每任务凭据级别的回调鉴权（决策 15 只要求共享 token）；
- 公钥缓存淘汰策略与容量上限（决策 14 明确不自动淘汰）。

## 测试与验证

单元测试（`internal/fhe`）：

- 公钥缓存：命中跳过下载 / 未命中下载并校验 / SM3 不符拒绝并清理临时文件 / 超 `maxEvalKeyBytes` 拒绝；
- 目录布局：`evalKeyFileHash` 与 `modelHash` 的非法输入（`..`、绝对路径、短哈希、大写、非 hex）全部拒绝；
- 回调：token 不符返回 404 / 重复回调幂等 / 回调与轮询竞争只推进一次终态；
- 状态机：任务失败、超时、cancel 映射；
- 配置：`server.type` 非法值拒绝 / `type=fhe` 缺 `callbackToken` 拒绝 / `type=tee` 带 `fhe` 段记 WARN 忽略。

契约测试：`httptest` 起 fake FHE server，覆盖建任务 → 回调 → 收结果 → 落 ResultDir → export 全链。

集成（本机可做）：platform-mock 扩展 + fake FHE，跑一遍 import → callback → export。

实机（A130，需要 GPU）：真 FHE 栈 + TAA `type=fhe` + mock，跑通 cifar-10 端到端，
对照交付包的 108.9 s / 78.6 s 基线。

**跑测试的方式**：本仓存在既存的并发测试 flaky（异步流水线活过 `t.TempDir()` 清理，约 7.5%，
两侧实测同率），且同一检出里并发跑测试会让结论不可信。因此分步跑、不并行跑整套：

```bash
go test ./internal/fhe/... ./internal/config/... ./internal/controller/...
```

## 验证状态

**已实现。** 截至 2026-10-16：

- `internal/fhe`（client / config / keycache / layout / runner）与 `tools/fake-fhe` 均已落地，
  单元测试与契约测试全绿；`tools/platform-mock` 的 FHE 侧（`handlers_fhe.go`、上传目录、
  注册状态）同样已落地。
- `deploy-fhe.sh` 已能部署 FHE 栈 + TAA `type=fhe` 实例，并支持 `--remote` 到共享 GPU 宿主。
- 身份优先级：`internal/config` 的四条单测覆盖 env 赢 / 文件兜底 / tee 不受影响（
  `TestLoadStartupConfigFHEIdentityEnvironmentWins`、`…FallsBackToFile`、
  `TestLoadStartupConfigTEEIdentityIgnoresEnvironment`、`TestLoadStartupConfigFHEPlatformSection`）。
- 已验证的手段：`bash -n`、本机 `DRY_RUN=1` 与基线逐行 diff（只多出新增行）、
  `DRY_RUN=1 --remote` 逐行审 ssh 命令（不连接）、`go test -count=1 -p 1 ./...` 全绿。
- **178 真机 e2e 已跑通（2026-10-16）**：`./deploy-fhe.sh --remote` 在 172.16.10.178 上一次
  完成 FHE 栈 + platform-mock + TAA `type=fhe` 的部署，注册闸门两次都过：
  - 不注入 `DOCKER_ID` → 平台记到 `taa-fhe`（模板 `platform.dockerID`），即兜底路径；
  - 注入 `DOCKER_ID=taa-fhe-env` → 平台记到 `taa-fhe-env`，而模板里写的是 `taa-fhe`，
    即**环境变量赢**。容器环境、TAA 自身日志（`dockerId=taa-fhe-env`）与 mock 的
    `accepted:true` 三处一致。顺带证实容器重建判定生效（旧容器缺该变量时被重建而非复用）。
  - 首次真机运行暴露并修掉了脚本的一个缺口：`run-node.sh up -d` 返回时应用还没绑端口，
    单次探健康会读到 connection reset（实测约 7 s），已改为 `wait_for_fhe_stack` 有界重试。
- **178 真机 FHE 任务端到端已跑通（2026-10-16）**：importModel（staged + activated 一次成功）
  → import（评估密钥 + 10 case 输入）→ 任务触发 → `completed` **10/10，failed 0**
  → `FHE 结果已落盘`（无 404、无「unknown task」回调告警）→ `reportRes code=0`
  → export **http=200，10,002,232 B**。落盘结果与交付包基线**逐文件** sha256 比对
  **identical=10 / differing=0**。（整包 sha256 不同是假的：基线来自另一个 task，且 zip 存 mtime。）
- **本轮 e2e 的根因修复（`7bf89a6`）**：FHE 服务在最后一个 case 结束的瞬间把任务翻成 `completed`，
  之后才组装 `output.zip`；TAA 恰好在这个亚秒窗口里探了一次结果，404 被当成终态失败并永久置败。
  修法是 `CopyResult` 在有界窗口内等这个 404（`resultReadyWait = 60s`，只对 404 重试，
  共享目录每次重新 stat），真实错误不等待。回归测试
  `TestRunnerCopyResultWaitsForALateResult` / `…DoesNotWaitOutARealFailure` 已入库；
  把 `resultReadyWait` 改回 0 能逐字复现线上失败，说明测试有判别力而非仅通过。
- **platform-mock 控制台已分 TEE / FHE 两种模式（`462a15a`）**：左上角切换 + `body[data-mode]`
  驱动面板显隐，FHE 侧新增投递卡片（从上传目录选评估密钥与输入包、随机 requestId/taskId、
  下发后自动刷新 reportRes 与进度）。切换持久化到 localStorage，`?mode=` 可覆盖。
  真实浏览器四态验证通过（默认 / `?mode=fhe` / `?mode=tee` / 点击切换）；
  投递卡片实测发出的正是 `/api/fhe/submit` 约定的**文件名**而非路径。
- **至此交付包基线对照已完成**，本 spec 无遗留未验证项。**仍未做**：DCU 侧不适用（交付包是 CUDA）；
  多任务并发与失败态（超时、cancel 映射）只在单测覆盖，真机未构造。
