# TAA ↔ 平台 SM2 信封（cipher/sign）改造

**日期**：2026-10-30
**依据**：`docs/taa-agent-delivery.md`（ShowDoc 5977）
**范围**：`internal/platform`、`internal/controller`、`internal/config`、`internal/app/taa`、`pkg/crypto`、`tools/platform-mock`、部署脚本、测试。业务字段与路由不变。

## 一、已确认的决策

| 项 | 决定 |
| :--- | :--- |
| 入站强制范围 | **9 个路由全部**（`/v1/taa/fheCallback` 豁免） |
| `fheCallback` 豁免理由 | 调用方是 FHE 服务，不是平台；拿不到平台私钥。沿用「仅回环地址」限制（token 已在此前改动中移除），威胁模型未变 |
| health/status 探活 | **也发信封**（平台已确认）。部署脚本必须改 TCP 端口探活，无兜底 |
| 无 `PLATFORM_PUBLIC_KEY` | **启动即失败**，无回退、无开关（生产/fhe/本地/mock 一律） |
| 公钥来源 | `PLATFORM_PUBLIC_KEY` 环境变量 + `configs/taa-*.json` 的 `platform.publicKey` |
| SM2 用户 ID | 环境变量 `PLATFORM_SM2_ID`，为空时用默认 `1234567812345678`；不进配置文件 |
| `tools/platform-mock` | 同步改造，保持本地可联调 |
| 响应封装位置 | 改 `writeJSON` 一族（经 request context 取信封会话），74 个调用点不动 |
| `export` 错误路径 | 所有错误分支本就在验签之后，**handler 不改**；错误返回 `{cipher,sign}`（平台已确认接受），成功路径仍是二进制（见 3.6） |

## 二、现状（改动落点）

### 出站：目前全程明文

- `internal/platform/client.go:SendPlatformJSON` — 唯一的发送出口，`payload` 即明文 JSON。
- `internal/platform/register.go:NoticeRegister` — 手工 `json.Marshal(registerRequest)` 后发给 `SendPlatformJSON`。
- `internal/platform/reporter.go` — 5 个上报函数，各自 marshal 后调 `SendPlatformJSON`。
- `internal/controller/report.go:sendPlatformJSON` — 另一条出口（`taa_reporting.go` 的 `ReportTaaLog` 也走它）。
- `SendPlatformJSON` **丢弃了响应体**（只在非 200 时读 4KB 日志）。新协议下 Agent 的应答是明文 `{msg,result,error}`，无需解包，保持现状即可。

**结论**：出站只需在两处 marshal 之后、发送之前插一层封装。封装函数需要 `dockerId`——`Client` 已持有，但 `SendPlatformJSON` 是包级函数，签名要改。

### 入站：全程明文，且校验先于一切

- `internal/controller/router.go:postOnly` — 所有路由的第一道门，只做 POST/CORS。
- 各 handler 自行 `json.NewDecoder(r.Body).Decode(...)`（`handler_task.go:163/295`、`handler_system.go:79/162/211`、`handler_export.go:61`、`fhe_callback.go:54`）。
- `internal/controller/response.go:writeJSON` — 唯一的 JSON 响应出口。

**结论**：入站需要一层「解包 + 验签 → 把明文 body 换回去」，位置必须在 handler 读 body 之前，即 `postOnly` 之后、`handler` 之前。

### 密钥材料现状

- `pkg/crypto` 已有 `EncryptSM2`/`DecryptSM2`（C1C3C2 原始字节，`sm2.go:181/196`）、`SignSM2Signature`/`VerifySM2Signature`（返回 `(r,s) *big.Int`，`sm2.go:211/223`）、`parseSM2Point`（`04||X||Y`，`sm2.go:341`，**未导出**）。
- `SignDigitToSignData(r,s)` / `SignDataToSignDigit(sig)`（gmsm）负责 DER 编解码。
- TAA 私钥已在 `TAAState.SM2PrivateKey`（`route.go:120`），启动时加载或从 `TAASECRETKEY` 恢复（`startup_keys.go`）。
- 平台公钥**没有任何承载字段**——`config.StartupConfig` 里不存在。

## 三、设计

### 3.1 新包：`internal/platform/envelope`

只做编解码，不碰 HTTP：

```go
type Envelope struct {
    DockerID string `json:"dockerId,omitempty"` // 出站必填，入站忽略
    Cipher   string `json:"cipher"`
    Sign     string `json:"sign"`
}

// Keys 是一次封装的全部密钥材料。UserID 由 PLATFORM_SM2_ID 决定，
// 为空时取 crypto.SM2DefaultUserID。构造时解析一次，之后只读。
type Keys struct {
    PlatformPub *crypto.SM2PublicKey
    TAAPriv     *crypto.SM2PrivateKey
    UserID      []byte
}

// Seal 用平台公钥加密 + TAA 私钥签名。返回可直接发送的外层 JSON。
func (k *Keys) Seal(plaintext []byte, dockerID string) ([]byte, error)

// Open 解出 Cipher → 用 TAA 私钥解密 → 用平台公钥验签（明文）→ 返回明文。
// 先验签再返回，调用方拿到的一定是已验签的字节。
func (k *Keys) Open(env *Envelope) ([]byte, error)
```

要点（全部来自文档第三节，逐条对应）：

1. `cipher = base64(SM2_Encrypt(平台公钥, utf8(JSON)))`，C1C3C2 原始字节，不 hex。
2. `sign = base64(DER 字节)`，DER 由 `SignDigitToSignData(r, s)` 生成。
3. **签名对象是明文**，不是 cipher。
4. `Open` 的顺序固定为：base64 解码 cipher → `DecryptSM2` → base64 解码 sign → `SignDataToSignDigit` → `VerifySM2Signature(平台公钥, 明文, r, s)` → 返回明文。
5. **SM2 用户 ID 由 `PLATFORM_SM2_ID` 环境变量决定**，为空时取 `pkg/crypto.SM2DefaultUserID`（`"1234567812345678"`）。
   签名与验签必须使用**同一个** `Keys.UserID`——SM2 的 `ZA = SM3(ENTLA || ID_A || …)` 把 ID 混进了摘要，双方 ID 不一致时验签必然失败，且只报「验签失败」，很难归因（已实测确认交叉验签全 false）。

需要在 `pkg/crypto` 补两个小导出（`internal/` 下无法用未导出符号）：
- `ParseSM2PublicKeyHex(s string)` — 解析 `04||X||Y` 的 hex，复用 `parseSM2Point`。
- `SM2DefaultUserID` 常量 = `"1234567812345678"`。
  显式传参，不要依赖 gmsm 在 `uid` 为空时套用的私有 `default_uid`（`sm2.go:34` 的字节虽然相同，但那是依赖库的实现细节，不是 TAA 的协议参数）。

### 3.2 公钥加载

- `config.StartupConfig` 新增 `PlatformPublicKey string` 和 `PlatformSM2ID string`。
- 环境变量 `PLATFORM_PUBLIC_KEY` 优先（与 `PLATFORM_IP` 一致的做法），`configs/taa-*.json` 的 `platform.publicKey` 兜底。
  **注意**：现有 `platform.ip` 的优先级是「tee 文件优先、fhe 环境优先」（`config.go:486`）。公钥不跟随该不对称——密钥必须可被操作者覆盖，故**环境变量始终优先**。
- `PlatformSM2ID` **只从环境变量 `PLATFORM_SM2_ID` 读，不进配置文件，也没有其他覆盖途径**。为空时取 `crypto.SM2DefaultUserID`。
  刻意不加配置项：这个值必须与平台侧逐字节一致，配置来源越多越容易在某台机器上悄悄不一致；唯一的来源便于排查。
- `PLATFORM_SM2_ID` 按**字符串**处理：`UserID = []byte(os.Getenv("PLATFORM_SM2_ID"))`，即原始 UTF-8 字节，**不做 hex/base64 解码**。
  依据：默认值 `1234567812345678` 本身就是 ASCII 字符串，且 `ZA` 里 `ENTLA = 8 * len(ID)` 用的是字节长度。若平台侧实际约定 hex，此处需改为解码——已在第七节标注。
  不做 trim：ID 是协议参数，前后有空格就是不一致，静默裁剪反而会掩盖配置错误。
- 启动时把公钥解析成 `*crypto.SM2PublicKey`、把 ID 解析成 `[]byte`，组装成 `envelope.Keys` 注入 `TAAState` 与平台客户端。公钥缺失或无法解析即 `return err`（`app.go` 的 `RunWithConfig`）。ID 为空不算错误——那是明确定义的默认值。

### 3.3 出站

在 `platform.SendPlatformJSON` 与 `controller.sendPlatformJSON` 之前各插一层 `Seal`。

为免改 6 个函数的签名，引入进程级 `platform.SetOutboundEnvelope(sealer)`（启动时一次性注入，读写分离后只读）。`SendPlatformJSON` 内：

```go
if sealer := outboundSealer(); sealer != nil {
    payload, err = sealer.Seal(payload)   // 失败则直接返回错误，绝不退回明文
}
```

`platform.NoticeRegister` 已经把 `taaPublicKey` 放在明文里（`register.go:60`），符合文档第四节最后一条，无需改动。

**`SendPlatformJSON` 需要 dockerID**：改为从参数或 sealer 闭包携带。取闭包方案——`Seal` 在构造时绑定 `dockerID`。

### 3.4 入站

新增中间件 `controller.envelopeMiddleware(next http.HandlerFunc) http.HandlerFunc`，在 `RegisterRoutes` 里套在 9 个路由上（`fheCallback` 不套）。

会话只有一个 `*envelopeSession`，它同时承担「封装响应」和「标记请求已验签」两件事：

```go
type envelopeSession struct{ /* 平台公钥 + TAA 私钥 */ }

func envelopeMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        body, err := io.ReadAll(io.LimitReader(r.Body, maxEnvelopeBytes))
        if err != nil { writeEnvelopeError(w, http.StatusBadRequest, "读取请求体失败"); return }

        var env platform.Envelope
        if err := json.Unmarshal(body, &env); err != nil || env.Cipher == "" || env.Sign == "" {
            // 未验签：没有可信会话，但错误响应仍须封装给平台
            writeSealedError(w, http.StatusBadRequest, "请求缺少 cipher/sign")
            return
        }
        plaintext, err := platform.Open(platformPub, taaPriv, &env)
        if err != nil {
            writeSealedError(w, http.StatusUnauthorized, "请求解密或验签失败")
            return
        }

        sess := &envelopeSession{platformPub: platformPub, taaPriv: taaPriv}
        r.Body = io.NopCloser(bytes.NewReader(plaintext))
        // 响应侧通过 writer 包装传递（http.ResponseWriter 无 Context），
        // 请求侧通过 context 传递（供 handler 判断「本请求是否已验签」）。
        next(&envelopeWriter{ResponseWriter: w, sess: sess},
             r.WithContext(withEnvelopeSession(r.Context(), sess)))
    }
}
```

`writeSealedError` 与 `writeJSON` 的封装分支共用同一段 `Seal` 逻辑——因为未验签时还没有会话，直接构造一次性会话封装即可。这样不存在「明文错误响应」这条路径。

三个必须守住的点：

- **先解密验签，再走原逻辑**：handler 拿到的 body 已是明文，现有 `json.Unmarshal` 无需改动。
- **`rawFields` 依然有效**：`importRequest.UnmarshalJSON`（`handler_task.go:84`）统计的是「解密后的明文」字段，与原来语义一致。
- **不能有明文旁路**：`json.Unmarshal` 失败或 `cipher`/`sign` 缺失一律 400，不接受 `{phase:2}` 这类裸 body。

### 3.5 出站响应封装

`writeJSON(w, status, resp)` 改成：

```go
func writeJSON(w http.ResponseWriter, status int, resp apiResponse) {
    if ew, ok := w.(*envelopeWriter); ok {
        plain, err := json.Marshal(resp)          // 注意：不含末尾换行
        if err == nil {
            if sealed, serr := ew.sess.Seal(plain); serr == nil {
                w.Header().Set("Content-Type", "application/json; charset=utf-8")
                w.WriteHeader(status)
                _, _ = w.Write(sealed)
                return
            }
        }
        // 封装失败是 TAA 侧故障（如平台公钥被替换成无效点）。此时不能退回明文——
        // 那等于把业务数据裸奔出去——只能返回 500 且不带业务 result。
        http.Error(w, "response envelope failed", http.StatusInternalServerError)
        return
    }
    /* 原逻辑不变：非信封路径（fheCallback） */
}
```

会话通过包装后的 `http.ResponseWriter` 传递（`http.ResponseWriter` 没有 `Context()`，故用一个薄包装 `envelopeWriter{ResponseWriter, sess}`）。

**注意**：现在 `writeJSON` 用 `json.NewEncoder(w).Encode(resp)`，会追加 `\n`。封装后明文必须字节精确，因此改为 `json.Marshal` + `w.Write`，**明文序列化结果与现状可能有细微差异（无尾随换行）**。测试里若有逐字节比对需一并核对。

### 3.6 `export` 的特殊处理

文档：请求要解密验签，响应仍是二进制。

- 入站：中间件照常解包，handler 拿到明文 `exportRequest`。
- 出站成功：`writeFileStream` 不走 `writeJSON`，天然是二进制，**无需改动**。
- 出站错误：`exportHandler` 的所有错误分支都走 `writeErr`/`writeError` → `writeJSON`，会被自动封装成 `{cipher,sign}`。这与文档「响应仍是二进制」不冲突——那句话约束的是成功路径的产物，错误路径在改造前就已经是 JSON 信封（`apiResponse`），改造后只是外面多了 `cipher/sign`。

**关于「重排校验顺序」**：核实 `handler_export.go` 后确认，所有失败分支（请求解析、索引查询、文件存在性、阶段判定、泄露检查、公钥解析、压缩、加密）**都发生在中间件验签之后**，因为验签在 `handler_export.go:58` 之前就完成了。因此**不存在「未验签就返回错误」的路径**，无需重排。

平台接受错误路径的 `{cipher,sign}` 信封（已确认），故 `exportHandler` 的 14 处 `writeErr`/`writeError` 全部由 `writeJSON` 自动封装，无需按路径分叉。成功路径的 `writeFileStream` 保持原样。

**结论：`export` 不改 handler，只确认中间件挂在它前面。**

### 3.7 部署脚本探活

平台已确认 `health`/`status` 也发信封。**这两条路由因此对任何本地探针不可达**——探针没有平台私钥，签不出合法 `sign`，不存在任何 HTTP 层的替代方案。5 处探针必须改 TCP：

| 文件:行 | 现状 | 改法 |
| :--- | :--- | :--- |
| `deploy.sh:1698` | `curl -X POST .../health` | `bash -c '</dev/tcp/127.0.0.1/6001'` 或 `nc -z` |
| `deploy.sh:1899` | `wait_for_http_ready ... /health` | 新增 `wait_for_tcp_ready`，端口连通即就绪 |
| `deploy-fhe.sh:492/948/1689` | 同 | 同 |
| `deploy-taa-vm.sh:322` | `curl -X POST localhost:6001/health` | 同 |
| `deploy/guest-build/csv2-deploy-command-template.md:322` | 文档示例 | 改成 TCP + 日志尾 |

**代价**：端口通≠业务就绪。TAA 的 `ListenAndServe` 在配置加载、密钥恢复、注册之后才执行，所以「端口可连」确实晚于配置成功——这一点比表面看起来安全。但**注册失败不阻止监听**（`app.go:202` 只告警），因此探活通过也不代表平台已认识这个实例。

改法要求：
1. 新增 `wait_for_tcp_ready`，替代 `wait_for_http_ready` 的 health 用法。
2. 探活通过后**追加一次启动日志确认**（grep `taa service listening`），区分「进程活着」和「配置加载完成」。
3. `deploy.sh` 的失败分支要把日志尾打出来——TCP 探活失败时没有 HTTP 响应体可看，日志是唯一诊断线索。

### 3.8 `tools/platform-mock`

- 新增 `platform.publicKey` 配置项 + 自己的一对 SM2 密钥（mock 需持有**平台私钥**才能给 TAA 下发合法 `sign`，也要持有**TAA 公钥**才能解 TAA 的上报——TAA 公钥从注册请求里拿）。
- 注册回调：解析 `taaPublicKey` 并保存。
- 所有 `proxyJSONToTAA` 调用点改走 `Seal`；所有接收 TAA 上报的 handler 先 `Open`。
- mock 目前**没有**密钥管理，需要新增一个 `keystore.go`（生成/持久化到 `state-dir`）。

## 四、测试影响

这是本次改动最大的一块。

| 项 | 现状 | 影响 |
| :--- | :--- | :--- |
| `postJSON` 辅助（`handler_test.go:153`） | 明文 POST | **150 处调用**，全部需改。集中改辅助函数：让它自动封装，并自动解包响应 |
| `decodeResponse`（`handler_test.go:166`） | 解明文 `apiResponse` | 同上 |
| `setupTestState`（`handler_test.go:72`） | 构造 state | 需注入平台公私钥对；`NewTAAState` 签名会变 |
| `internal/platform` 单测 | 断言明文 body | `client_test.go:24/86` 直接读 body 字段，需先 Open |
| 新增测试 | — | `envelope` 包的往返/篡改/错钥；中间件缺字段/坏签名/明文旁路；export 全错误路径 |

**建议先做**：把 `postJSON`/`decodeResponse` 改成「自动封装/解包」后，150 处调用点应当**大部分无需改动**。先验证这一点，再动业务代码。

## 五、实施顺序

1. `pkg/crypto` 补 `ParseSM2PublicKeyHex` + `SM2DefaultUserID` 常量（纯新增，无风险）。
2. `internal/platform/envelope` 新包 + `Keys{PlatformPub, TAAPriv, UserID}` + 单测（不接线）。
   单测必须覆盖：往返、篡改 cipher/sign、错公钥、**异 UserID 交叉验签失败**、`UserID` 为空时落到 `SM2DefaultUserID`。
3. `internal/config` 加 `PlatformPublicKey` + `PlatformSM2ID`（仅环境变量，无配置文件项）+ 启动解析失败即返回。
4. `internal/controller/response.go` 改 `writeJSON` 族 + 会话包装；`router.go` 挂中间件。
5. 出站 `Seal` 接线（`platform.SendPlatformJSON` + `controller.sendPlatformJSON`）。
6. 核实 `export` 错误路径（3.6），确认无需重排。
7. 测试辅助改造（`postJSON`/`decodeResponse`/`setupTestState`），跑全量。
8. `tools/platform-mock` 改造 + 本地联调。
9. 部署脚本探活改造。
10. 文档：`README.md` 配置字段、`docs/api-design.md` 请求/响应格式、`api/openapi.yaml`。

## 六、风险与未决

1. **`writeJSON` 去掉尾随 `\n`**：若有测试或外部消费者依赖精确字节，会挂。实施第 4 步时先跑一遍测试确认。
2. **部署脚本的探活断档**：改 TCP 后，`deploy.sh` / `deploy-fhe.sh` / `deploy-taa-vm.sh` 在改造完成前会一直探不通——**代码和脚本必须同一次提交**，否则任何一次部署都会卡在就绪等待直到超时。
3. **`SendPlatformJSON` 的 dockerID 传递**：选闭包绑定，但 `platform.ReportRes` 等是包级函数，`dockerID` 从参数来——需确认所有调用点都传了正确值（当前是的）。
4. **`configs/taa-*.json` 全部模板**：加 `publicKey` 字段后，未配置的模板会让 TAA 启动失败。5 个模板（docker / production / fhe / initrd / dataanaylsis）都要更新，否则对应部署形态升级即 crash-loop。
5. **mock 的密钥持久化**：mock 重启后若密钥变化，TAA 缓存的平台公钥就失效。必须落盘到 `state-dir`。
6. **`fheCallback` 的豁免是唯一的明文入口**：它靠「仅回环地址」限制保护。改造后这是整个 TAA 唯一的无信封写入口，需在代码里显式标注豁免原因，避免后续被误认为遗漏。
7. **`PLATFORM_SM2_ID` 配置错误是静默失败**：设错时 TAA 照常启动、照常加密，只有验签失败——而失败点在**接收方**，TAA 侧日志看不到「ID 不一致」。建议启动时把生效的 ID 打进日志（脱敏无必要，ID 是公开参数），便于与平台侧比对。

## 七、外部事实（已确认，无需再问平台）

- **SM2 用户 ID 默认值 = `1234567812345678`**：文档第 138 行原文给出。TAA 侧可用 `PLATFORM_SM2_ID` 覆盖；为空时用该默认值。该值与 gmsm 的 `default_uid`（`sm2.go:34`）逐字节相同，但实现**显式传参**，不依赖依赖库的隐式默认。
  **编码 = 字符串原始 UTF-8 字节**（用户已确认），不做 hex/base64 解码、不做 trim。
  实测确认：同 ID 签名/验签互通，异 ID 交叉验签全部失败；且 SM2 签名带随机数，两次签同一消息结果不同，故「ID 一致」只能靠验签互通证明，不能靠比对签名结果。
- **`export` 的错误响应平台接受 `{cipher,sign}` 信封**：用户已确认。因此 `export` 成功路径走二进制、错误路径走封装 JSON，无需按路径分叉。文档「响应仍是二进制」约束的是成功产物。
- **`health`/`status` 也发信封**：用户已确认。因此这两条路由对本地探针彻底不可达，部署脚本必须同步改 TCP 探活（见 3.7），且无降级路径。