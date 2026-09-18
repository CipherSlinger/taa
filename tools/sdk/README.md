# teecrypto

面向可信执行环境(TEE)场景的 Go 加解密 SDK。对称加密依赖第三方国密库(`github.com/tjfoc/gmsm`),其余部分保持轻量,可编译为单一可执行文件,便于在 Windows / Linux 上分发。

## 核心能力

| 能力 | 函数 | 算法 |
| --- | --- | --- |
| 生成 SM4 密钥 | `GenerateSM4Key` | crypto/rand,16 字节 |
| 使用指定密钥加密数据 | `Encrypt` | SM4-GCM |
| 使用指定密钥解密数据 | `Decrypt` | SM4-GCM |
| SM2 一步式信封加密 | `SealSM2` / `OpenSM2` | SM4-GCM + SM2 |
| SM2+SM4-GCM 自包含密文 | `SealSM2SM4GCM` / `OpenSM2SM4GCM` | SM4-GCM + SM2 |
| SM2 密钥生成与 PEM 序列化 | `GenerateSM2KeyPair` 等 | SM2 (国密椭圆曲线) |
| SM3 摘要 / HMAC | `SM3Sum` / `HMACSM3` | SM3 (国密哈希) |
| Hygon CSV 远程报告验证 | `attestation.VerifyReport` | SM2 签名 + 证书链 |

## 安装

```bash
go get teecrypto
```

或直接将本目录作为本地 module 使用(`module teecrypto`)。

## 快速开始

```go
import "taa/pkg/crypto"

// 1. 生成 SM4 密钥
key, _ := crypto.GenerateSM4Key()

// 2. 加密数据(密文自带 nonce 与认证标签)
ciphertext, _ := crypto.Encrypt(key, []byte("敏感数据"))

// 3. 解密数据
plaintext, _ := crypto.Decrypt(key, ciphertext)
```

### SM2 信封加密(推荐)

```go
// 生成 SM2 密钥对
priv, _ := crypto.GenerateSM2KeyPair()

// 一步式信封加密:生成 SM4 数据密钥 → SM4-GCM 加密 → SM2 包裹数据密钥
env, _ := crypto.SealSM2(&priv.PublicKey, []byte("大段数据"))
data, _ := crypto.OpenSM2(priv, env)
```

从 PEM 加载 / 导出 SM2 密钥:

```go
pub, _  := crypto.ParseSM2PublicKeyPEM(pubPEM)
priv, _ := crypto.ParseSM2PrivateKeyPEM(privPEM)
pubPEM, _ := crypto.MarshalSM2PublicKeyPEM(pub)
privPEM, _ := crypto.MarshalSM2PrivateKeyPEM(priv)
```


## 密文格式

`Encrypt` 输出为自包含格式,`Decrypt` 无需额外参数即可解析:

```
nonce(12B) || ciphertext || tag(16B)
```

- 每次加密使用随机 nonce,相同明文得到不同密文。
- GCM 的认证标签保证完整性:密钥错误或数据被篡改时 `Decrypt` 返回错误,绝不返回明文。

## 典型信封加密流程

```
加密方(持有公钥)                    解密方 / TEE(持有私钥)
───────────────────────            ──────────────────────────
GenerateSM4Key  ──► 数据密钥
Encrypt(数据密钥, 明文) ─► 密文
SealSM2SM4GCM(公钥, 明文) ─► 自包含密文
     │                                     │
     └────────────── 密文 ───────────────► OpenSM2SM4GCM(私钥, 密文) ─► 明文
```

## 命令行工具

### 交互式 CLI (`cli/`)

自动扫描程序所在目录的 `.pem` 和 `.enc` 文件,交互式选择加密/解密:

```bash
go build -o teecrypto-cli.exe ./cli
```

也支持命令行参数直接执行:

```bash
teecrypto-cli -key pub.pem -input secret.txt
teecrypto-cli -key priv.pem -input secret.txt.enc -mode decrypt
teecrypto-cli -key pub.pem -input data.bin -output data.enc
```

### 子命令 CLI (`cmd/teecrypto-cli/`)

为 Tauri GUI 后端设计的子命令式 CLI,输出 JSON 格式:

```bash
teecrypto-cli genkey --output ./keys
teecrypto-cli encrypt --input data.txt --pubkey pub.pem --output data.enc
teecrypto-cli decrypt --input data.enc --privkey priv.pem --output data.txt
teecrypto-cli verify  --report report.bin [--chain]
teecrypto-cli readfile --path key.pem
```

### Windows 批处理 (`encrypt.bat`)

双击运行,自动检测当前目录下的 `.pem` 公钥和普通文件,交互式选择后执行加密。

## 图形界面

### Tauri GUI(推荐,`gui-tauri/`)

基于 Tauri v2 (Rust + HTML/CSS/JS) 的跨平台 GUI,Fluent Design 2 风格:

```bash
cd gui-tauri && cargo tauri build
```

功能:SM2 密钥管理、文件拖拽加解密、远程报告验证、操作历史记录。

### 旧版 Win32 GUI(已弃用,`gui/` + `cmd/teecrypto-gui/`)

基于 Go 标准库 + Win32 API 的原生 GUI,已迁移至 Tauri 版本。

## 远程报告验证

`attestation` 包提供 Hygon CSV(China Secure Virtualization)远程报告验证:

```go
import "teecrypto/attestation"

result, err := attestation.VerifyReport("report.bin", true)
// result.ReportVerified  — 报告签名是否通过
// result.ChainVerified   — 证书链(HRK→HSK→CEK→PEK)是否通过
// result.ChipIDASCII     — 芯片序列号
```

## 开发命令

```bash
go build ./...          # 编译
go test ./...           # 运行全部测试
go test -run TestSealOpen   # 运行单个测试
go vet ./...            # 静态检查
gofmt -l .              # 检查格式(输出为空即通过)
```

为 Windows 交叉编译:

```bash
GOOS=windows GOARCH=amd64 go build -o teecrypto-cli.exe ./cli
GOOS=windows GOARCH=amd64 go build -o teecrypto-cli.exe ./cmd/teecrypto-cli
```
