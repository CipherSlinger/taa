// Package crypto 提供面向可信执行环境(TEE)场景的对称/混合加密 SDK。
//
// 能力概览:
//
//   - 生成 SM4 密钥                           —— GenerateSM4Key
//   - 使用指定密钥加密数据(SM4-GCM)           —— Encrypt
//   - 使用指定密钥解密数据(SM4-GCM)           —— Decrypt
//   - SM2 密钥信封(SM2 加密)                  —— SealSM2 / OpenSM2
//   - SM2+SM4-GCM 自包含密文                  —— SealSM2SM4GCM / OpenSM2SM4GCM
//   - SM2 密钥生成与 PEM 序列化               —— GenerateSM2KeyPair / ParseSM2*PEM / MarshalSM2*PEM
//   - SM3 摘要与 HMAC                         —— SM3Sum / HMACSM3
//
// 高层的 SealSM2 / OpenSM2 与 SealSM2SM4GCM / OpenSM2SM4GCM 将"生成数据密钥 → 加密数据 →
// 包裹数据密钥"组合为一次调用,是典型的信封加密(envelope encryption)用法。
// SealSM2SM4GCM / OpenSM2SM4GCM 进一步把 SM2 密钥信封和 SM4-GCM 密文拼成单个
// 字节切片,用于文件/接口传输。
//
// 算法选型说明:
//
//   - 对称加密统一使用 SM4-GCM,自带完整性/认证(AEAD),
//     密文格式为 nonce(12B) || ciphertext || tag(16B)。
//   - 密钥信封支持 SM2(SealSM2 / OpenSM2, SealSM2SM4GCM / OpenSM2SM4GCM)。
//   - SM3 用于国密摘要计算,HMACSM3 提供带密钥的消息认证。
//
// 所有随机数(密钥、nonce)均来自 crypto/rand。
package crypto
