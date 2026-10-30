<!-- Source: ShowDoc page 5977 "TAA ↔ Agent 安全交付" (item 53)
     http://192.168.8.225/showdoc/web/#/53?page_id=5977
     Fetched 2026-10-30 15:42; edit here and push back to the page if it changes. -->

# TAA ↔ Agent 报文格式与处理说明

TAA 只需要关注两个方向：

1. TAA 主动请求 Agent（注册、任务结果、模型导入、检查结果、日志、进度）；
2. Agent 请求 TAA（平台下发指令）。

其他平台/Agent 内部流程 TAA 不需要关心。

---

## 一、TAA 请求 Agent（TAA 主动上报）

### TAA 发给 Agent

```json
{
  "dockerId": "xxx",
  "cipher": "base64",
  "sign": "base64"
}
```

`cipher` 里面就是 **TAA 现在发给 Agent 的那份原请求 JSON**，字段一个不改；`sign` 是对这份明文 JSON 的签名。

例如注册：

```json
// 外层
{ "dockerId": "xxx", "cipher": "...", "sign": "..." }

// cipher 解密后的明文（就是原来的注册 body）
{
  "dockerId": "xxx",
  "taaPublicKey": "04...",
  "taaSecretKey": "...",
  "attestation": "...",
  "attestationValues": "...",
  "timestamp": "...",
  "authInfo": {},
  "verifiedPass": false
}
```

上报任务结果、模型导入、检查结果、日志、进度同理：**明文就是原来的 body，不加 `type`，不加别的包装。**

### Agent 返回给 TAA

还是原来的明文信封：

```json
{ "msg": "操作成功", "result": null, "error": 0 }
```

注意：这个返回只代表 **Agent 收下了**，不代表平台验签通过。平台是后续异步验的。所以 TAA 不要根据这个 `error=0` 判断“平台一定认可”。

---

## 二、Agent 请求 TAA（平台下发指令）

### Agent 发给 TAA

```json
{
  "cipher": "base64",
  "sign": "base64"
}
```

`cipher` 解密后，就是该路由原来该收的 body。例如：

```json
// /v1/taa/import
{ "resourceUrl": "...", "type": 1, "envelope": "...", "requestId": "...", "taskId": "...", "publicKey": "..." }

// /v1/taa/switch
{ "phase": 2 }

// /v1/taa/importModel
{ "resourceUrl": "...", "requestId": "...", "publicKey": "...", "runtimeConfig": "{\"commands\":[],\"env\":{}}" }

// /v1/taa/stopTraining
{ "requestId": "...", "taskId": "..." }
```

TAA 每个路由**先解密验签，再按原来的逻辑处理**。带 `cipher` 时，外层可能没有旧字段，不要先校验旧字段。

### TAA 返回给 Agent

JSON 类接口返回：

```json
{ "cipher": "base64", "sign": "base64" }
```

`cipher` 里就是原来的：

```json
{ "msg": "...", "result": ..., "error": 0 }
```

`/v1/taa/export` 例外：请求要解密验签，但响应仍按现在的二进制返回，不包 `{cipher,sign}`。

---

## 三、加解密和签名怎么做

```text
TAA 发出去：
    bytes  = utf8(原请求 JSON)
    sign   = base64(SM2_sign(TAA 私钥, bytes))
    cipher = base64(SM2_encrypt(平台公钥, bytes))
    发送 { "dockerId": "...", "cipher": cipher, "sign": sign }

TAA 收到 Agent 请求：
    bytes  = SM2_decrypt(TAA 私钥, base64_decode(cipher))
    SM2_verify(平台公钥, bytes, base64_decode(sign))
    data   = json.loads(bytes)

TAA 返回给 Agent：
    bytes  = utf8({ "msg": ..., "result": ..., "error": ... })
    sign   = base64(SM2_sign(TAA 私钥, bytes))
    cipher = base64(SM2_encrypt(平台公钥, bytes))
    返回 { "cipher": cipher, "sign": sign }
```

固定格式：

- `cipher`：SM2 C1C3C2 原始密文字节的 base64，不是 hex 再 base64。
- `sign`：SM2 签名 DER 字节的 base64。
- 签名对象是**明文**，不是 `cipher`。
- 验签用解密出来的原始字节，**先验签再 `json.loads`**，不要先解析再重新序列化。
- 平台公钥格式：`04 || X(32B) || Y(32B)` hex。
- SM2 用户 ID 用默认的 `1234567812345678`。

---

## 四、TAA 启动要准备什么

- 读 `PLATFORM_PUBLIC_KEY`（平台公钥）。
- 准备自己的 SM2 密钥对：有 `TAASECRETKEY` 就复用，没有才生成。
- 注册时把 `taaPublicKey` 放在**明文**里（不是只放外层），平台要用它验这次自签名。
- 没有 `PLATFORM_PUBLIC_KEY` 就按旧逻辑发明文。

一句话：**TAA 只是把原来的请求/响应 JSON 拿去做“平台公钥加密 + 自己私钥签名”，外面套 `cipher`/`sign`；收到的请求反过来“自己私钥解密 + 平台公钥验签”后再走原逻辑。路由和业务字段完全不变。**