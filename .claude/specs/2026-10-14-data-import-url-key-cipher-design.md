# 数据下发 URL 密钥信封协议改造 — 设计

日期：2026-10-14
状态：待评审

## 1. 背景与目标

当前数据下发（`POST /v1/taa/import`）的密态资源是**单文件**，格式为：

```
WrappedKey(113B) || SM4-GCM Ciphertext(剩余)
```

其中 `WrappedKey = 0x04 || x1(32) || y1(32) || c3(32) || c2(16)`，是 SM2 公钥包裹的 16 字节 SM4 数据密钥；TAA 收到后用自身 SM2 私钥切开信封、再由数据密钥解密密码文（`pkg/crypto/seal.go` 的 `OpenSM2SM4GCM`）。

新协议把密钥信封从文件里移到 URL query：

```
https://host/files/data.sm4?dataKeyCipher=<hex>&<其余参数>
```

下载链接指向的响应体**只含 SM4-GCM 密文**，不再有 113 字节前缀。TAA 需要从 URL 中取出 `dataKeyCipher`、剥离该参数后用剩余 URL 下载密文，再用信封里的数据密钥解密。

目标：

- `/v1/taa/import` 支持新协议；
- 信封格式非法时**在下载前**就失败，不白拉数 GB 流量；
- URL 中未携带 `dataKeyCipher` 时，完全回退到现有逻辑，平台可逐步切换；
- platform-mock 同步支持，保证本地可端到端联调。

非目标：`/v1/taa/importModel` 与 `/v1/taa/getResourceInfo` 不改，继续按「整文件信封」处理。

## 2. 协议规格

### 2.1 URL 形态

| 部分 | 说明 |
| --- | --- |
| 下载链接 | 指向**仅含密文**的资源；剥离 `dataKeyCipher` 后原样用于 HTTP GET |
| `dataKeyCipher` | SM2 数据密钥信封的 hex 编码（C1C3C2 布局） |
| 其余 query | 原样保留（签名类参数不得被改写） |

### 2.2 信封 hex 布局（两种都接受）

| hex 解码后长度 | 处理 |
| --- | --- |
| 112 字节 | 视为 `C1 ‖ C3 ‖ C2`，前缀补 `0x04` 得到 113 字节信封 |
| 113 字节且首字节为 `0x04` | 原样使用 |
| 其他（含 113 字节但首字节非 `0x04`） | 参数错误 |

平台的规范形态是 **112 字节（无 `0x04` 前缀）**；113 字节带前缀的形态为兼容路径。

### 2.3 绑定关系

信封里只有数据密钥，没有密文摘要。信封与密文的绑定是**隐式**的：换掉密文而沿用信封，SM4-GCM 认证标签校验必然失败。因此不需要额外的摘要字段。

## 3. 模块设计

### 3.1 `internal/resource/urlkey.go`（新增）

```go
// SplitDataKeyCipher 剥离 URL 中的 dataKeyCipher 参数，
// 返回可直接下载的 URL 与参数原始 hex 值。
// found=false 表示 URL 未携带该参数，调用方走旧格式回退。
func SplitDataKeyCipher(rawURL string) (cleanURL, hexValue string, found bool, err error)
```

解析规则：

1. 先切出 `#fragment`，尾部原样保留在 `cleanURL` 中。
2. 无 `?` → `found=false`，`cleanURL == rawURL`（逐字节相等）。
3. query 按 `&` 切段；段的 key 取第一个 `=` 之前的部分；key 恰为 `dataKeyCipher` 的段被删除。
4. **其余段逐字节保留顺序与转义**，不做 `url.Values.Encode()` 重编码——重编码会排序并转义，破坏签名类参数。
5. 删除后 query 为空 → 连 `?` 一起去掉。
6. 出现多次 → 返回错误（歧义，不猜第一个）；值为空串 → 返回错误。

该函数只做字符串处理，不校验 hex 内容；hex 与长度校验由 §3.2 负责。

### 3.2 `pkg/crypto`（新增一个函数）

```go
// ParseWrappedDataKeyHex 解析 hex 编码的 SM2 数据密钥信封，兼容 112/113 字节两种布局。
func ParseWrappedDataKeyHex(hexValue string) ([]byte, error)
```

- `hex.DecodeString` 失败 → 错误；
- 长度判定按 §2.2；
- 返回 113 字节信封，满足 `UnwrapKeySM2` 的长度前置校验；
- 错误信息包含实际解码长度，便于定位平台侧问题。

放在 `pkg/crypto` 是因为 `SM2WrappedKeySize` 与 `0x04` 前缀的定义都在本包，补前缀的知识不应散落到其他模块。

### 3.3 `internal/controller`

**同步段**（`handler_task.go` 的 `importHandler`，下载前）：

```go
downloadURL, hexValue, hasKey, err := resource.SplitDataKeyCipher(req.ResourceURL) // err → 400
var dataKey []byte
if hasKey {
    wrapped, err := teecrypto.ParseWrappedDataKeyHex(hexValue)      // err → 400
    dataKey, err = teecrypto.UnwrapKeySM2(s.SM2PrivateKey, wrapped) // err → 400
}
ciphertextPath, size, err := s.downloadToTempFile(downloadURL)
```

**提前解封**是本设计的一处增益：信封解不开（平台用错公钥）在下载前即返回 400，代价是一次微秒级 SM2 运算。传给异步段的是 16 字节 `dataKey`，信封本身不再向下传递。

日志、索引与上报一律使用 `downloadURL`；`dataKeyCipher` 不写入日志或任何落盘文件。

**异步段**（`import_processing.go` 的 `processImportedResource`）增加一个参数：

```go
func (s *TAAState) processImportedResource(
    req importRequest, phase int, isModel bool, ciphertextPath string, dataKey []byte)
```

- `len(dataKey) > 0` → 新路径：读取密文全文件 → 空文件报「密文为空」→ `teecrypto.Decrypt(dataKey, sealed)` → 写临时明文文件；解密失败时错误信息附带 TAA 公钥，与旧路径行为一致。新路径**不做压缩包魔数探测**：携带 `dataKeyCipher` 即声明这是密文，即使文件头恰好是 ZIP/GZIP/TAR 魔数也仍按密文解密，失败即失败，不静默改判为明文。
- `len(dataKey) == 0` → 原样调用 `resolvePlaintextResource`（`.enc` 后缀强制解密 / 压缩包魔数探测 / 明文直通），**现有分支逻辑一个字符不改**。

调用点只有两处：`importHandler` 传 `dataKey`，`modelImportHandler` 传 `nil`。

新增解密函数 `decryptCiphertextWithDataKey(dataKey []byte, ciphertextPath string) (string, error)`，与现有 `decryptResourceToTempFile` 并列，区别是不再从文件头部切信封。

### 3.4 `tools/platform-mock`

「加密上传」增加第三种模式，使本地可联调新协议。

**后端**（`handlers_upload.go`）：

| 模式 | 形态 | 落盘文件名 |
| --- | --- | --- |
| 不加密 | 原样 | `<原名>` |
| 整文件信封（现有） | `SealSM2SM4GCM` 输出整块 | `<原名>.enc` |
| **URL 密钥信封（新增）** | `SealSM2` 返回的 `Envelope`：密文写文件，`WrappedKey` 去掉 `0x04` 前缀后 hex 进 URL | `<原名>.sm4` |

- 表单字段 `encryptMode` 取值 `none` / `envelope` / `urlkey`；保留对旧字段 `encrypt=true|1|on` 的兼容（映射为 `envelope`）。
- 返回体新增 `dataKeyCipher` 字段（仅 `urlkey` 模式），`url` 形如 `http://<host>/files/<name>.sm4?dataKeyCipher=<hex>`。
- 文件扩展名用 `.sm4` 而非 `.enc`：`.enc` 在既有语义里代表「整文件信封」，混用会让其他接口按错误格式处理。

**前端**（`static/index.html` + `static/js/app.js`）：把现有 `#uploadEncryptSwitch` 复选框换成三选一下拉 `#uploadEncryptMode`（不加密 / 整文件信封 / URL 密钥信封）。列表项与提示文案按模式区分。

## 4. 失败时点与错误码

| 场景 | 时点 | 返回 |
| --- | --- | --- |
| `dataKeyCipher` 重复、值为空、hex 非法、长度非法、信封解不开 | 同步，下载前 | 400 |
| 剥离后下载失败 | 同步 | 500，导入索引回滚（沿用现状） |
| 密文为空、GCM 认证失败 | 异步 | `reportImportFailure` → `reportRes` 上报训练失败（沿用现状） |

分界线：**信封自身的格式与可解性在同步段暴露；密文与信封是否配套只能在异步段暴露。**

## 5. 明确不改动

解密之后的全链路保持原样：

- SM3 校验对象是**解密得到的明文归档**，不是密文；
- 解压到内容寻址目录 `DataDir/<sm3>`，同 hash 复用；
- `store.Commit` 写入导入索引；
- 训练触发闸门（`ModelImported` / 无模型导入在飞 / 无训练在飞 / `runtimeConfig` 有效）逐条不变；
- `importModel` 与 `getResourceInfo` 的解密路径不变。

## 6. 测试

| 层 | 用例 |
| --- | --- |
| `SplitDataKeyCipher` | 无参数（`found=false` 且 URL 逐字节相等）；单参数剥离；多参数保序且不改写转义；值含 `%` 转义；含 fragment；删除后 query 为空时 `?` 一并去掉；重复出现报错；空值报错 |
| `ParseWrappedDataKeyHex` | 112B 补前缀；113B 且首字节 `04` 直用；113B 首字节非 `04` 报错；非 hex；奇数长度；111B；114B |
| `post /v1/taa/import` 新协议端到端 | 新 URL → 解密 → 解压入库 → 触发训练（复用现有 httptest 桩） |
| 下载前拦截 | 坏 hex 时断言下载桩请求计数为 0 |
| 回退 | 不带 `dataKeyCipher` 的旧 URL 走原路径，现有测试全绿 |
| 范围护栏 | `importModel` 与 `getResourceInfo` 仍能解「整文件信封」格式 |
| platform-mock | `urlkey` 模式上传返回的 URL 含 `dataKeyCipher`；mock 加密 → TAA 解密的往返一致 |

## 7. 文档

- `docs/api-design.md` §4.2：补 `dataKeyCipher` 说明、请求示例与「仅含密文」的语义。
- `api/openapi.yaml`：`/v1/taa/import` 描述与 `ImportRequest.resourceUrl` 注释同步。
- `docs/architecture-design.md` §5.2：该段现写作「拆分: WrappedKey ‖ SM4-GCM 密文」，需改为描述新协议与回退路径。

## 8. 风险与取舍

| 事项 | 处理 |
| --- | --- |
| URL 重编码破坏签名参数 | 逐段字符串剥离，绝不走 `url.Values.Encode()` |
| 重复参数含义不明 | 显式报错，不猜测 |
| 信封与密文不配套 | 由 SM4-GCM 认证标签兜底，异步暴露 |
| 平台误用其他公钥加密信封 | 提前解封使其在下载前 400 暴露 |
| 新模式 URL 被误用于 `importModel` / `getResourceInfo` | 属于误用，两接口按旧格式报错；mock 用 `.sm4` 后缀降低误配概率 |
