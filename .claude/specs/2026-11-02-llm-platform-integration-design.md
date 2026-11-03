# LLM 侧平台接入（注册 / 心跳 / 日志 / 远程证明）设计

- 日期：2026-11-02
- 状态：已确认
- 范围：`teellm/` 子模块（`teellm-service`）新增平台上报与远程证明接口，并把现有接口统一到 `/v1/llm/*`

## 1. 背景与问题

TAA 与管控平台的交互已经稳定：

- 出方向：`internal/platform` 把明文 JSON 封成 `{dockerId, cipher, sign}`（SM2 加密到平台公钥 +
  TAA 私钥签名），再 POST 到平台的 `/v1/taa/*`。
- 入方向：`/v1/taa/*` 一组 `postOnly + envelopeMiddleware` 路由，平台发来的请求同样要带信封。

LLM（qwen / ollama）部署在**独立的 Kata CSV2 Pod**（`deploy-llm.sh`、`taa-teellm`），
`teellm-service` 目前只对外提供 TEE-TLS 上的 `/v1/verify` 和 `/healthz`，对平台完全不可见：

- 平台不知道这个实例存在，也就无法把它纳入实例列表。
- 平台无法感知它是否还活着。
- `teellm-service` 的运行日志只写进 Pod 内的 `teellm-service.log`，平台拿不到。
- 平台无法主动向它索取远程证明报告。

本设计为 LLM 补齐这四件事，并尽量保持与 TAA 现有接口的形状一致，降低平台侧的适配成本。

## 2. 目标与非目标

### 目标

- LLM 启动后向平台注册，上报 CSV 远程证明报告、公钥与自校验结果。
- 注册成功后维持心跳，平台可据此判断实例存活。
- 周期性把 `teellm-service` 的运行日志批量推送给平台。
- 平台可通过 TEE-TLS 主动向 LLM 索取远程证明。

### 非目标

- **不改 TAA 的任何接口与行为。**
- **不引入外层信封。** LLM 与平台之间全链路是明文 JSON，安全性由 TEE-TLS 的证明握手承担。
- **不做持久化 outbox。** Pod 是每次重建的新 guest，rootfs 在 guest 内存里，落盘没有跨生命周期的意义。
- **不劫持 `log` 包。** 日志通过显式埋点进入上报缓冲。
- **不改 `teetls`。** 新接口复用其现有的 `Config` 证书缓存。

## 3. 关键决策

四项由用户拍板：

1. **入方向分两个监听。** `/v1/llm/verify` 与 `/v1/llm/healthz` 留在现有 `:8443` TEE-TLS 上；
   `/v1/llm/getAttestation` 走新增的明文 `:8444`。两者共用同一个 `teetls.Config` 的证书缓存与
   同一个 `EvidenceProvider`，因此返回的报告与握手实际出示的证书仍是同一份。**这是本设计的
   一次修订**：最初把 `getAttestation` 也放在 `:8443`，后改为明文，理由见 3.1。
2. **全链路不包外层信封。** 入方向跑在 TEE-TLS 上（证明握手已提供机密性、完整性与对端身份），
   出方向直接明文 POST 到平台。
3. **路径统一到 `/v1/llm/*`，含现有的 `/v1/verify` 与 `/healthz`。** 平台现有 `/v1/taa/*` 处理器
   无条件解信封，同一路径下混两种报文形态会让平台必须靠猜；前缀把这个区分放到 URL 上。
   既有的两个接口一并改名，**不保留旧路径**（见 3.2）。
4. **LLM 每次启动重新生成密钥。** 证书与密钥随进程生命周期存在，不持久化、不回收到平台。

### 3.1 `getAttestation` 为什么走明文

在 `:8443` 上，LLM 作为服务端**只出证、不验证**（`main.go` 未开 `VerifyMutualAttestation`）。
握手里那份报告只有在对端客户端开了校验时才被检查——而平台这一侧正是要靠
`getAttestation` 拿报告的地方，用 TEE-TLS 包住它等于用一个不被校验的通道搬运证明。

明文 `:8444` 上，报告的**认证性由报告自身承担**，不由传输层承担：

- 报告里 `userdata[:32] = SM3(证书公钥)`，说明"这份报告绑定了哪把公钥"；
- 注册报文与 `getAttestation` 同时给出这把公钥的 PEM 和这份报告，平台验
  `SM3(PEM 里的公钥) == userdata[:32]` 即可确认二者配套；
- 报告本身用 PEK 签名，`VerifyReportWithOptions` 验到 HRK 根，伪造不了。

因此明文传输不会削弱证明；传输层加密在这里保护的是"报告内容不被旁听"，而报告本来就是
要交给平台存档的公开证据。**代价**写清楚：`:8444` 无任何认证，Pod 网络内能连上的人都能取到
报告。报告不含秘密，但会泄露实例的度量与 ChipID，所以该端口只能在集群内网暴露。

### 3.2 路径改名的影响面

`/v1/verify` → `/v1/llm/verify`，`/healthz` → `/v1/llm/healthz`，直接改名、不做兼容。

| 消费方 | 处理 |
| --- | --- |
| `teellm/server.go:61-62` | mux 注册改为新路径 |
| `teellm/client.go:152,216` | 客户端请求路径改为新路径 |
| `teellm/teellm_test.go`、`teellm/resilience_test.go`、`internal/codeaudit/llm_test.go` | 测试里的路径字符串同步改 |
| `internal/codeaudit`（经 `teellm.Client`） | 无需改，跟着客户端走 |
| `deploy-llm.sh` 就绪探针 | 走 `teellm-service -probe`，内部用 `teellm.Client`，跟着客户端走 |
| `teellm/README.md` | 接口表更新 |

两者在同一个 `go.work` 里，服务端与客户端同时改动，不存在版本错配。代价是：旧镜像的客户端连
新服务（或反之）会 404 / 探针失败，所以 **teellm-service 与 TAA 的镜像必须同批次发布**。

## 4. 结构

```
LLM Pod / teellm-service
├── :8443  TEE-TLS（同一个 teetls.Config，同一张缓存证书）
│   ├── /v1/llm/verify             原 /v1/verify，改名
│   └── /v1/llm/healthz            原 /healthz，改名
│
├── :8444  明文 HTTP
│   └── /v1/llm/getAttestation     新增，平台 → LLM
│
└── 平台上报 goroutine（同进程）
    └── 明文 HTTP POST → 平台
        ├── /v1/llm/register
        ├── /v1/llm/heartbeat
        └── /v1/llm/log
```

**为什么不用独立进程。** 去掉外层信封后，出方向只剩 `net/http` + `encoding/json`，入方向只剩
`teetls.Listen`（已由 `server.go` 提供）+ `csvattest`（`teetls` 已依赖）。`teellm` 子模块本来就有
这些能力，不需要 `taa/internal/platform`，也就不存在模块边界问题。

**两个 listener 共用一份证书缓存。** `teetls.Config.GetOrGenerateCertificateContext` 内部有证书缓存
（`CertCacheTTL`，默认 1 小时）和 `certMu`。`:8444` 的 `getAttestation` handler 持有的是**同一个**
`*teetls.Config` 指针，调用同一个 `GetOrGenerateCertificateContext`，因此：

- 返回的报告与 TEE-TLS 握手实际出示的证书，是同一份；
- 不需要额外取一次硬件报告，也没有"报告与证书对不上"的窗口；
- 只有一个并发路径：`getAttestation` 与握手同时触发首次生成，靠 `certMu` 串行化，两者拿到同一份。

## 5. 报文

### 5.0 既有接口改名（TEE-TLS :8443）

| 旧路径 | 新路径 | 说明 |
| --- | --- | --- |
| `POST /v1/verify` | `POST /v1/llm/verify` | 语义不变 |
| `GET /healthz` | `GET /v1/llm/healthz` | 语义不变 |

### 5.1 `POST /v1/llm/register`（LLM → 平台，明文 JSON）

字段与 TAA 的 `register` 对齐：

```json
{
  "dockerId": "taa-teellm",
  "authInfo": null,
  "taaPublicKey": "-----BEGIN PUBLIC KEY-----\nMFkw...\n-----END PUBLIC KEY-----\n",
  "attestation": "<base64(CSV report)>",
  "attestationValues": "{\"userdata\":\"..\",\"mnonce\":\"..\",\"digest\":\"..\",\"chipId\":\"..\"}",
  "timestamp": "1730000000",
  "verifiedPass": true
}
```

- `taaPublicKey`：**TEE-TLS 证书公钥的 PEM**，取自证书的 `RawSubjectPublicKeyInfo`。格式与 TAA
  现在发的一致（PEM），平台的公钥解析代码可直接复用。语义上它是"本实例出示证明时绑定的签名公钥"。
- `attestationValues`：从**当前缓存证书的证据扩展**反解，不重新取硬件报告。
  `DecodeCSVEvidence(ext.Value)` 得到 `Report` → `csvattest.ParseReport` 取
  `UserData / MNonce / Digest / ChipID`。保证注册报的证明与 `getAttestation` 返回的完全一致。
- `verifiedPass`：用 `HRKCert` / `HSKCekCert` 对报告做一次 `csvattest.VerifyReportWithOptions`
  链验自校验的结果。TAA 的 `buildAttestationResult` 做的是同一件事。
- **不报 `taaSecretKey`**：这是 TAA 用来把包装后的 SM2 私钥交回平台的字段；LLM 没有需要回收的
  SM2 签名私钥，字段直接省略。

### 5.2 `POST /v1/llm/heartbeat`（LLM → 平台，明文 JSON）

```json
{ "dockerId": "taa-teellm", "timestamp": "1730000030" }
```

30 秒一次，只报存活。平台若连续 3 个周期（90 秒）未收到，判离线。不携带健康、模型或度量信息。

### 5.3 `POST /v1/llm/log`（LLM → 平台，明文 JSON）

路径不再沿用 TAA 的 `taaLog` 命名：它是 LLM 自己的运行日志通道，只是**报文字段**与 TAA 对齐。

```json
{
  "dockerId": "taa-teellm",
  "requestId": "system",
  "taskId": "",
  "seqStart": 1042,
  "entries": [
    { "seq": 1042, "message": "[2026-11-02 10:00:00] [INFO] [teellm] ollama ready" }
  ]
}
```

- LLM 没有任务概念：`requestId` 恒为 `"system"`，`taskId` 恒空——与 TAA 空闲期上报的形状一致。
- `message` 用 `Entry.FormatMessage()` 的同一格式（`[时间] [级别] [组件] 正文`），平台展示代码零改动。
- `seq` 从 1 单调递增，每批连续；批量上限沿用 TAA 的 `maxLogBatchSize`。

### 5.4 `POST /v1/llm/getAttestation`（平台 → LLM，明文 HTTP :8444，明文 JSON）

请求：

```json
{ "requestId": "..." }
```

响应：

```json
{
  "msg": "操作成功",
  "result": {
    "requestId": "...",
    "verifiedPass": true,
    "attestation": "<base64(CSV report)>",
    "attestationValues": "{\"userdata\":\"..\",...}",
    "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
  },
  "error": 0
}
```

结构与 TAA 的 `getAttestationHandler` 响应一致，平台解析代码可直接复用；**多一个 `certificate` 字段**。

- `certificate` 是给明文通道补上的那一环：TEE-TLS 上平台本来就在握手里拿到证书，明文上拿不到，
  没有它平台无法验证 `userdata[:32] == SM3(证书公钥)`，报告就退化成一段自说自话的 base64。
  传 PEM 与 `taaPublicKey` 同格式，平台侧一份解析代码两处复用。
- 报告与 `certificate` 同时取自当前缓存证书，**不重新 IOCTL**。理由：证书本身就是从
  `/dev/csv-guest` 出的，报告里的 `userdata` 绑定的是这张证书公钥；重取一份会引入报告与证书
  不匹配的可能，而平台要的正是"证书 ↔ 报告"这条链。
- `requestId` 为空时返回 `400`，与 TAA 的校验一致。
- `verifiedPass` 为自校验结果；校验失败不阻止返回报告，只把 `verifiedPass` 置 `false` 并在 `msg`
  里说明——与 TAA 的降级行为一致。

## 6. 上报器行为

- **注册**：启动时尝试一次；失败则后台退避重试，`1s → 2s → 4s … 60s` 封顶，**不设放弃窗口，一直重试到成功**。
  TAA 的 `retryRegister` 有 5 分钟窗口，这里刻意不同：TAA 的理由是重试日志落在 guest tmpfs 上、
  每次尝试都带完整证明报文；LLM 侧报文小、且只在失败切换点与每第 10 次尝试记一行，不会累积。
  注册是实例在平台上"存在"的唯一途径，有界窗口会让一次长于窗口的平台故障把健康的推理服务
  永久留在平台视野之外——没有记录、心跳被注册信号阻塞、日志推不出去，只能重启 Pod 才能恢复。
  注册成功后每 6 小时重发一次，让平台拿到当前证书对应的公钥与证明；刷新失败同样按这套阶梯
  重试到成功，不会干等下一个周期。
- **心跳**：30 秒 ticker，注册成功后启动。失败只记本地日志，下个周期继续。
- **日志**：内存环形缓冲，容量 2000 条。每 5 秒排空一次批量推送；推送失败把该批**放回队首**，
  下个周期重试；缓冲满时丢最旧。
- **失败不扩散**：所有失败路径只写本地日志（每次失败切换写一行，重复失败不重记；注册阶梯每第
  10 次尝试另记一行），不阻塞推理、不影响 `/v1/llm/healthz`、不让
  TEE-TLS 服务降级。

## 7. 日志采集方式

**显式埋点，不劫持 `log` 包。** 在关键路径调用 `agent.Logs.Add(level, component, msg)`：

- 服务启动与关闭；
- ollama 后端就绪 / 不可用；
- 证明证据降级为 mock；
- 每类上报的连续失败与恢复。

不劫持的理由：`teellm-service` 的 `log` 输出由 supervisor 重定向到 `teellm-service.log`，
`log.SetOutput` 换成 `MultiWriter` 会让同一行日志同时进两套下游，且无级别与组件信息。

代价是未埋点的输出不会上报。这是有意的取舍：先保证上报通道干净，埋点面按需要扩展。

## 8. 代码落点

| 位置 | 变更 |
| --- | --- |
| `teellm/platformagent/`（新增包） | `config.go`、`register.go`、`heartbeat.go`、`logs.go`、`attestation.go`、`reporter.go` |
| `teellm/attestation.go`（新增） | 明文 `:8444` 的 `getAttestation` handler 与它的 listener |
| `teellm/server.go` | mux 改为 `/v1/llm/verify`、`/v1/llm/healthz`；`ServerConfig` 增加 `AttestationAddr`，非空时另起一个明文 listener 挂 `/v1/llm/getAttestation` |
| `teellm/client.go` | 请求路径改为 `/v1/llm/verify`、`/v1/llm/healthz` |
| `teellm/cmd/teellm-service/main.go` | 读配置 `server.attestationAddr` 与 `platform` 段，构造并启动 agent |
| `teellm/configs/teellm-production.json`、`teellm/configs/teellm-docker.json` | `server` 段新增 `attestationAddr`；顶层新增 `platform` 段 |
| `teellm/README.md` | 接口表路径更新、补 `:8444` |
| `build-teellm-image.sh:240` | `EXPOSE 8443` 改为 `EXPOSE 8443 8444` |
| `deploy-llm.sh` | 新增 `TEELLM_ATTESTATION_PORT`（默认 8444）并注入 `server.attestationAddr`；`platform` 段注入 |
| `teellm/go.mod` | **不新增依赖** |

配置段：

```json
"server": {
  "addr": ":8443",
  "attestationAddr": ":8444",
  "readTimeoutSeconds": 60,
  "writeTimeoutSeconds": 60,
  "maxResponseBytes": 1048576
},
"platform": {
  "addr": "http://172.16.10.181:18081",
  "dockerId": "taa-teellm",
  "heartbeatSeconds": 30,
  "logFlushSeconds": 5,
  "registerRefreshSeconds": 21600
}
```

- `server.attestationAddr` 为空表示**不挂载** `getAttestation`（纯推理部署，不留无认证端口）。
  这是与 `platform.addr` 独立的开关：前者是入方向，后者是出方向，可分别关闭。
- `platform.addr` 为空表示不启用上报，明文端口仍按 `attestationAddr` 独立决定是否监听。
- `:8444` 绑在 Pod 内网卡上即可，**不要**放进任何 NodePort / Ingress。

## 9. 与 TAA 的差异（平台需要知道的）

| 项 | TAA | LLM |
| --- | --- | --- |
| 外层信封 | `{dockerId, cipher, sign}` | **无，明文 JSON** |
| 路径 | `/v1/taa/*` | **`/v1/llm/*`**（含原 `/v1/verify`、`/healthz`） |
| 监听 | 全部明文 HTTP `:6001` | 业务口 **TEE-TLS `:8443`**；`getAttestation` **明文 `:8444`** |
| 身份密钥 | 自生成 SM2 密钥对，`taaSecretKey` 可回收 | TEE-TLS 证书密钥对，每次启动新生成，不可回收 |
| `taaSecretKey` | 有（CSV 实例） | **不报** |
| 持久化 | sealed outbox | **无，内存缓冲** |
| 心跳 | 无 | **新增** |
| 证明获取 | `getAttestation` 在信封内 | `getAttestation` 明文，响应多带 `certificate` |

## 10. 验证方式

- `teellm/platformagent` 单测：报文序列化对齐 `internal/platform` 的字段名与 `taaLog` 结构；
  环形缓冲在满与失败回填下的顺序正确；退避序列符合 `1s…60s`。
- `/v1/llm/getAttestation` 的 httptest（明文 listener）：空 `requestId` 返回 400；正常返回里
  `attestation` 能被 `csvattest.ParseReport` 解析，`certificate` 能被
  `teetls.ParseCertificatePEM` 解析，且 `userdata[:32]` 等于 `certificate` 公钥的 SM3 摘要。
- 端到端：对 `tools/platform-mock` 增加 `/v1/llm/*` 的明文处理分支后，跑一次
  `deploy-llm.sh start`，确认注册、心跳、日志三条都在 mock 面板上出现。
- 证明一致性：`curl -s -X POST http://<pod-ip>:8444/v1/llm/getAttestation -d '{"requestId":"x"}'`，
  把拿到的 `attestation` 与注册报文里的 `attestation`、以及 `:8443` 握手出示证书里的报告逐字节比对。
- 端口隔离：确认 `:8444` 未出现在 Pod spec 的 `ports`、Service 或 Ingress 里。
- 路径改名回归：`go test ./teellm/...` 与 `go test ./internal/codeaudit/` 全绿，确认服务端与
  客户端两侧的路径已一致；`deploy-llm.sh start` 的就绪探针（`teellm-service -probe`）通过。