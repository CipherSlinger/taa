# 模型下发 URL 密钥信封协议改造 — 设计

日期：2026-10-14
状态：已实现

## 1. 背景与目标

数据下发（`/v1/taa/import`）此前已改造为「信封进 URL、下载体只含密文」：
`resourceUrl = <下载链接>?dataKeyCipher=<hex C1C3C2>`。同一份设计
（`.claude/specs/2026-10-14-data-import-url-key-cipher-design.md`）当时把
`/v1/taa/importModel` 列为非目标，模型仍按「整文件信封」下发：
下载体是 `WrappedKey(113B) || SM4-GCM 密文`。

本次把模型下发改成与数据下发**同一种协议**，使平台侧只需一套下发逻辑：

- `/v1/taa/importModel` 支持 `?dataKeyCipher=<hex>`：URL 携带 SM2 数据密钥信封，
  下载体只含 SM4-GCM 密文；
- 信封格式非法时**在下载前**失败（400），不白拉数 GB 模型包；
- URL 未携带该参数时**完全回退**到整文件信封，平台可逐接口切换；
- 解密链路的其余部分（解压、SM3 校验、代码审计、上报）不改。

非目标：`/v1/taa/getResourceInfo` 不改，继续按整文件信封处理（它面向数据资源树，
不是模型下发通道）。

## 2. 协议规格

与数据下发完全一致，没有模型专属的字段或变体。见数据侧 spec 的
「2. 协议规格」：URL 形态、信封 hex 的两种布局（112 字节 C1C3C2 / 113 字节带
`0x04` 前缀）、以及「绑定关系是 SM4-GCM 认证标签」这一条。这里只记录模型侧
特有的两点：

| 差异点 | 数据下发 | 模型下发 |
| --- | --- | --- |
| 异步失败上报通道 | `reportRes`（训练失败） | `reportModelImport`（`code=1`，msg 含 `解密资源失败` 与 `taaPublicKey:`） |
| 落库的「下发记录」 | 无（导入索引只存 hash/taskId） | `SavedModelResourceURL`，存**剥离后**的 URL |

## 3. 模块设计

### 3.1 `internal/controller/import_urlkey.go`（新增）

把原先内联在 `importHandler` 里的「剥离参数 + hex 解析 + SM2 解封」抽成一个共享方法：

```go
func (s *TAAState) unwrapDataKeyCipherFromURL(rawURL string) (downloadURL string, dataKey []byte, err error)
```

- 两个 handler 都调用它，协议只有一处实现；
- URL 未携带参数时返回 `(原 URL, nil, nil)`，调用方据此走整文件信封；
- 任何错误都是客户端错误（`CodeInvalidArgument`），调用方**不得下载**；
- 错误文本与原内联实现逐字一致（`dataKeyCipher 解封失败: %v` 的前缀在 helper 内补上），
  以免改动数据侧既有断言与对外文案。

### 3.2 `internal/controller/handler_task.go`

- `importHandler`（数据）：内联块替换为一次 helper 调用，行为不变。
- `modelImportHandler`（模型）：
  - 解析位置在**请求字段校验之后、任何状态写入之前**——早于 phase1 导出公钥保存、
    `ModelImported` 置位、`SavedModelResourceURL` 写入与下载。被拒的请求不留下任何痕迹；
  - 解析后把剥离后的 URL 写回本地请求副本（`req.ResourceURL = resourceURL`）。原因：
    异步成功路径 `beginModelImportAndAudit` → `saveModelSuccessLocked(req.ResourceURL)` 会
    用请求里的 URL **再写一次**下发记录；不写回的话两个写入点对「模型从哪来」的答案不一致，
    且密封状态里会留下信封。写回后下载、日志、legacy 解析分支、落库都统一用剥离后的 URL，
    包装密钥只存在于本次请求的 `dataKey` 里；
  - 写回后立即拦一次「剥离后为空但带了信封」：模型 handler 独有的
    「`resourceUrl` 为空 = 只更新 runtimeConfig」分支不能被这种请求命中（见 §4）；
  - 异步调用从 `processImportedResource(..., nil)` 改为传入 `dataKey`。
- 解密之后的链路（`resolvePlaintextResourceWithDataKey` → `decryptCiphertextWithDataKey` →
  SM3 → `extractArchiveToDir` → `launchModelAudit`）在数据侧改造时已做成端点无关，
  本次一行未改。

## 4. 失败时点与错误码

| 场景 | 时点 | 返回 |
| --- | --- | --- |
| `dataKeyCipher` 重复、值为空、hex 非法、长度非法、信封解不开 | 同步，下载前 | 400，且**不下载、不写任何模型状态** |
| `resourceUrl` 只有信封、剥离后为空（`?dataKeyCipher=<hex>`） | 同步，下载前 | 400（`resourceUrl 缺少下载地址`），**不得**落入「仅 runtimeConfig」分支 |
| 剥离后下载失败 | 同步 | 500，清 `ModelImported`、清下发记录（沿用现状） |
| 密文为空、GCM 认证失败 | 异步 | `reportModelImport` 上报 `code=1`，msg 含 `解密资源失败` 与 `taaPublicKey:` |

末行的第二行值得单列：模型 handler 有一条「`resourceUrl` 为空即只更新 runtimeConfig」的分支，
而 URL 剥离后恰好可能为空，此时该分支会返回 200 并把刚送到的数据密钥丢掉。

## 5. 明确不改动

- `/v1/taa/getResourceInfo`：仍不解析 `dataKeyCipher`，传给它带参数的 URL 会把参数原样转发
  并在整文件信封上失败。它是数据资源树接口，不是模型通道。
- `tools/platform-mock`：上传侧的 `urlkey` 模式与端点无关，模型卡片把上传结果里的 `url`
  原样填进 `resourceUrl`，因此模型下发无需改动即已支持新协议。
- `resolvePlaintextResource` 及其 `.enc` 后缀判定、压缩包魔数探测：只服务 legacy 分支。
- `internal/resource/urlkey.go`、`pkg/crypto.ParseWrappedDataKeyHex`：直接复用，未改。

## 6. 测试

`internal/controller/import_model_urlkey_test.go`（新增，复用数据侧 `urlKeyResource` /
`otherKeyEnvelopeHex` helper）：

| 测试 | 钉住的行为 |
| --- | --- |
| `TestModelImportDecryptsWithDataKeyCipherFromURL` | 端到端：下载请求里没有 `dataKeyCipher`、其余 query（`sign=a%2Fb`）逐字保留、只下载一次、解密后解压进 `ModelDir`、`reportModelImport` `code=0` 且 checksum 是**明文归档**的 SM3、落库 URL 已剥离 |
| `TestModelImportRejectsBadDataKeyCipherBeforeDownloading` | 5 种非法信封（重复/空/非 hex/长度/他人密钥）→ 400 + 下载次数 0 + `ModelImported` 与下发记录都未被改动 |
| `TestModelImportRejectsKeyEnvelopeWithoutDownloadAddress` | `?dataKeyCipher=<hex>`（只有信封、没有下载地址）→ 400 而不是 `200 模型参数命令已导入` |
| `TestModelImportFallsBackToLegacyFormatWithoutDataKeyCipher` | 无参数时整文件信封链路逐字不变 |
| `TestModelImportURLKeyDecryptFailureReportsPublicKey` | 信封合法但密文被篡改 → 同步 200，异步 `reportModelImport` `code=1` 且带 `taaPublicKey:` |

既有模型导入测试（整文件信封、明文压缩包、phase1 流程、审计）全部未改并保持通过。

## 7. 文档

- `docs/api-design.md` / `api/openapi.yaml`：`/v1/taa/importModel` 的 `resourceUrl`、
  两种形态、400 场景与「仅本接口」的作用域说明；
- `docs/architecture-design.md`：解密链路一节说明数据与模型共用该流程；
- `README.md`：密态资源格式一节补 URL 形态；
- 数据侧 spec 的「非目标」一行标注被本 spec 取代（`getResourceInfo` 仍在范围外）。

## 8. 风险与取舍

- **回退是默认**：不带参数的请求走原路径，本次改造对未切换的平台是纯增量。
- **分离两个写入点**：把剥离后的 URL 写回请求副本，是为了让同步与异步两个写入点一致；
  代价是 `modelImportHandler` 里 `req.ResourceURL` 的含义在解析后发生一次变化，
  已在代码就地注释。可选方案（只改同步写入点）会让两者互相覆盖，故否掉。
- **解析提前到状态写入之前**：phase1 请求若信封非法，导出公钥不再被保存。这是有意的——
  被拒请求不产生副作用；平台修好 URL 重发时公钥会随请求再来。
- **模型包体积大**：下载前拦截的价值比数据侧更明显（模型包通常数百 MB 起）。
