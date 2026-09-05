# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

`teecrypto` 是面向可信执行环境(TEE)场景的 Go 加解密 SDK,对称加密依赖第三方国密库(`github.com/tjfoc/gmsm`)。module path 为 `teecrypto`,可交叉编译为单一可执行文件(主要目标平台为 Windows)。

## 常用命令

```bash
go build ./...                 # 编译
go test ./...                  # 运行全部测试
go test -run TestSealOpen      # 运行单个测试(按测试函数名正则匹配)
go test -v ./...               # 详细测试输出
go vet ./...                   # 静态检查
gofmt -l .                     # 列出格式不规范的文件(输出为空即通过)

# 为 Windows 交叉编译
GOOS=windows GOARCH=amd64 go build -o teecrypto-cli.exe ./cli
GOOS=windows GOARCH=amd64 go build -o teecrypto-cli.exe ./cmd/teecrypto-cli

# Tauri GUI (需要 Rust 工具链)
cd gui-tauri && cargo xwin --target x86_64-pc-windows-msvc build --release
```

## 架构

### 共享加密库

仓库根目录 `taa/crypto` 是唯一的实现来源；SDK 通过 `replace taa => ..` 直接复用。

- `sm4.go` — SM4-GCM 对称加解密。`GenerateSM4Key`(16 字节随机密钥)、`Encrypt`、`Decrypt`。私有 `newGCM` 统一做密钥长度校验并构造 AEAD 实例。
- `sm2.go` — SM2 椭圆曲线密钥生成、加解密、PEM 序列化。`GenerateSM2KeyPair`、`EncryptSM2`/`DecryptSM2`、`SealSM2`/`OpenSM2`(SM2 信封加密)、`SealSM2SM4GCM` / `OpenSM2SM4GCM`。
- `sm3.go` — SM3 摘要和 HMAC-SM3。`SM3Sum`、`HMACSM3`。
- `keys.go` — RSA 密钥的生成、PEM 解析与导出。兼容 PKCS#1/PKIX(公钥)与 PKCS#1/PKCS#8(私钥)。
- `archive.go` — tar.gz 归档/解包,用于文件夹加密场景。
- `doc.go` — 包级文档。
- `crypto_test.go` — 覆盖 SM4 往返、SM2 往返、SM2 信封、篡改检测、PEM 序列化等。

### `attestation/` — Hygon CSV 远程报告验证

- `attestation.go` — 解析 Hygon CSV 报告二进制格式,验证 PEK 签名和证书链(HRK→HSK→CEK→PEK)。支持远程下载和本地证书回退。

### `cli/` — 交互式 CLI

自动扫描程序所在目录,交互式选择文件加解密。也支持 `-key`/`-input`/`-output`/`-mode` 命令行参数直接执行。

### `cmd/teecrypto-cli/` — 子命令 CLI(Tauri 后端)

子命令式 CLI,输出 JSON,供 Tauri GUI 调用。子命令: `genkey`、`encrypt`、`decrypt`、`verify`、`readfile`。

### `gui-tauri/` — Tauri GUI(当前推荐)

基于 Tauri v2 (Rust + HTML/CSS/JS) 的跨平台 GUI,Fluent Design 2 风格。`src-tauri/` 为 Rust 后端,`src/` 为前端。

### `gui/` + `cmd/teecrypto-gui/` — 旧版 Win32 GUI(已弃用)

基于 Go 标准库 + Win32 API 的原生 GUI,已迁移至 Tauri 版本。仅在 `*_windows.go` 中调用 Win32 API,非 Windows 平台使用 stub。

### 关键约定

- **密文自包含格式**:`Encrypt` 输出 `nonce(12B) || ciphertext || tag(16B)`,`Decrypt` 据此切分,无需额外传参。修改此布局会破坏向后兼容。
- **算法**:对称统一 SM4-GCM;密钥信封支持 SM2(`SealSM2`/`OpenSM2`, `SealSM2SM4GCM`/`OpenSM2SM4GCM`)。新增算法时应保持 GCM 为默认,避免降级到无认证模式。
- **错误即失败,绝不静默**:解密/解信封失败一律返回 error,不返回部分明文;哨兵错误 `ErrInvalidKeySize`、`ErrCiphertextTooShort` 供调用方按 `errors.Is` 判定。
- 所有随机数(密钥、nonce)均来自 `crypto/rand`。
