# TAA

## 目录结构

```text
.
├── internal/controller/route.go      # 平台调用 TAA 的 HTTP 路由和处理函数
├── internal/controller/register.go   # TAA 主动通知平台注册逻辑
├── internal/controller/report.go     # TAA 上报资源结果逻辑
├── internal/controller/platform_client.go # 平台地址与共享 HTTP 客户端
├── cmd/platform-mock/index.html      # 平台模拟器页面
├── cmd/platform-mock/main.go         # 平台模拟器服务端
├── manifest/docker/Dockerfile        # Docker 镜像构建文件
├── .dockerignore                     # Docker 打包上下文过滤
├── main.go                           # 程序入口
├── go.mod                            # Go 模块定义
└── Makefile                          # 本地编译和镜像构建命令
```

## 启动注册

TAA 启动时会先生成随机 SM2 公私钥对（国密标准椭圆曲线密码算法，GB/T 32918-2016），并先调用 attestation helper 生成远程证明报告，再主动调用平台注册地址：

```text
POST http://{PLATFORM_IP}/v1/taa/register
```

请求格式为 `application/json`：

| 字段 | 说明 |
| --- | --- |
| `dockerId` | 取容器启动参数 `DOCKER_ID` |
| `attestation` | 远程证明报告文件内容的 Base64 编码，TAA 启动时固定读取 `attestation.report` |
| `taaPublicKey` | TAA 启动时生成的 SM2 公钥 PEM（国密标准） |
| `attestationValues` | attestation report 核心字段提取的 JSON 字符串，包含 USERDATA、MNONCE、DIGEST、CHIP_ID 等关键字段（hex 编码） |
| `timestamp` | 生成 attestation 时的 Unix 时间戳（秒），与 USERDATA 中的时间戳一致 |
| `verifiedPass` | TAA 验证远程证明报告结果，`true` 表示成功，`false` 表示失败 |
| `authInfo` | 当前固定为 `null` |

attestation 相关配置已固定为代码内默认值：

- 报告文件：`attestation.report`
- helper：`./attestation/get-attestation`
- 生成模式：`auto`

平台返回 HTTP `200` 即表示注册成功；否则服务每 1 秒重试一次。

### USERDATA 构成

attestation report 的 USERDATA 字段（偏移 `0x040`，64 字节）直接写入 TAA 启动时生成的 SM2 公钥裸坐标：

```
USERDATA = taaPublicKey.X(32 bytes) || taaPublicKey.Y(32 bytes)
```

- `taaPublicKey`：TAA 启动时生成的 SM2 公钥（国密标准椭圆曲线密码算法）
- `X` / `Y`：SM2 公钥坐标，分别左侧补零到 32 字节

**安全作用**：
- 身份绑定：将 TAA 公钥与 TEE 硬件报告绑定
- 完整性：attestation 签名保护 USERDATA 不被篡改

### attestationValues 字段

`attestationValues` 为 JSON 字符串，字符串内容包含从 attestation report 中提取的核心字段：

```json
{
  "userdata": "0123456789abcdef...",
  "mnonce": "0123456789abcdef0123456789abcdef",
  "digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "chipId": "CSV-CHIP-ASCII-001"
}
```

`userdata`、`mnonce`、`digest` 为 ANONCE 异或还原后的 hex 编码；`chipId` 为按 ANONCE 还原后的 ASCII 字符串。

## 调试模式

启动时通过 `-debug` 参数开启调试模式（默认关闭）。调试模式下：

- **导入流程**：正常解密和解压资源，但**不执行** `debug.sh` / `train.sh`，**不做代码审计**。解密后的原始包保存在 `resultDir/debug/<taskId>/input.bin`，同时写入 `manifest.json` 记录 phase 和 type。
- **结果报告**：生成模板报告（包含 `"debug_mode": true`），通过 `reportRes` 上报平台。
- **导出接口**：按 taskId 查找调试产物，不再读取 `result.bin`。
  - Phase 1 / 2：无 `publicKey` 时返回明文原始包，有 `publicKey` 时返回 SM2 信封加密后的包。
  - Phase 3：**必须**提供 `publicKey`，否则返回 400；提供后返回加密后的原始包。

```sh
taa -debug -addr :6001
```

## 本地平台模拟器

平台模拟器页面文件：

```text
cmd/platform-mock/index.html
```

服务端会通过 Go `embed` 将该 HTML 打进二进制，因此部署时只需要一个 `platform-mock` 可执行文件。

### 开发运行

```sh
make platform-mock
```

打开：

```text
http://127.0.0.1:8080
```

### 构建部署

构建单文件二进制：

```sh
make platform-mock-build
```

本机部署运行：

```sh
./platform-mock -addr 0.0.0.0:8080
```

如果 Windows 浏览器打不开 `http://127.0.0.1:8080/`，请改用 WSL 的局域网 IP，例如 `http://172.x.x.x:8080/`。启动时终端会打印可访问地址。

后台部署运行：

```sh
nohup ./platform-mock -addr :8080 > platform-mock.log 2>&1 &
```

查看日志：

```sh
tail -f platform-mock.log
```

停止服务：

```sh
pkill -f "platform-mock -addr :8080"
```

模拟器会接收：

```text
POST /v1/taa/register
POST /v1/taa/reportResourceRes
```

当 `/v1/taa/register` 请求中包含 `dockerId`、`attestation`、`taaPublicKey`，且 `authInfo` 可省略或为 `null` 时，模拟器返回 HTTP `200`，并将注册信息持久化到远程服务器本地文件中；浏览器刷新页面后可通过“刷新状态”重新加载最新状态，并展示 attestation 文件名、文件大小、接收时间、原始请求 JSON 和文件内容。

当 `/v1/taa/reportResourceRes` 请求中包含 `dockerId`、`requestId`、`code` 时，模拟器返回 HTTP `200`，并在页面展示上报内容与原始 JSON。

## 本地运行

先启动平台模拟器，再另开终端运行 TAA：

```sh
export PLATFORM_IP=127.0.0.1:8080
export DOCKER_ID=127.0.0.1
make run
```

也可以手动编译运行：

```sh
make taa
./taa -addr :6001
```

程序启动时会自动生成 TAA 的 SM2 公私钥对，先生成 attestation 报告保存到 `attestation.report`，再将公钥和报告一起用于注册请求。

## Docker 构建和运行

构建镜像：

```sh
make docker
```

运行容器时只需要传入平台地址和容器 ID，并挂载远程证明报告文件：

```sh
docker run --rm \
  -e PLATFORM_IP=192.168.3.102:8080 \
  -e DOCKER_ID=127.0.0.1 \
  -v /host/path/attestation.report:/opt/taa/attestation.report:ro \
  -p 6001:6001 \
  taa:latest
```


cd /taatest
PLATFORM_IP=172.16.10.178:8080 \
DOCKER_ID=127.0.0.1 \
nohup ./taa -addr :6001 > /tmp/taa.log 2>&1 < /dev/null &