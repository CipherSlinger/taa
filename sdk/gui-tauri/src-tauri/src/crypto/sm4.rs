// SM4-GCM symmetric encryption — using RustCrypto sm4 + aes-gcm crates

use aes_gcm::aead::generic_array::typenum::U12;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::AesGcm;
use rand::RngCore;
use sm4::Sm4;

pub const SM4_KEY_SIZE: usize = 16;
const GCM_NONCE_SIZE: usize = 12;
const GCM_TAG_SIZE: usize = 16;
const SEALED_OVERHEAD: usize = GCM_NONCE_SIZE + GCM_TAG_SIZE; // 28 bytes

type Sm4Gcm = AesGcm<Sm4, U12>;

pub fn generate_sm4_key() -> Result<Vec<u8>, String> {
    let mut key = vec![0u8; SM4_KEY_SIZE];
    rand::thread_rng().fill_bytes(&mut key);
    Ok(key)
}

pub fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = new_gcm(key)?;
    let mut nonce = [0u8; GCM_NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(&nonce.into(), Payload { msg: plaintext, aad: &[] })
        .map_err(|e| format!("SM4-GCM 加密失败: {}", e))?;

    // Output: nonce(12B) || ciphertext || tag(16B)
    let mut out = Vec::with_capacity(GCM_NONCE_SIZE + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = new_gcm(key)?;
    if data.len() < SEALED_OVERHEAD {
        return Err("密文长度不足,数据已损坏或格式错误".into());
    }

    let nonce = &data[..GCM_NONCE_SIZE];
    let ciphertext = &data[GCM_NONCE_SIZE..];

    cipher
        .decrypt(nonce.into(), Payload { msg: ciphertext, aad: &[] })
        .map_err(|_| "解密失败(密钥错误或数据被篡改)".into())
}

fn new_gcm(key: &[u8]) -> Result<Sm4Gcm, String> {
    if key.len() != SM4_KEY_SIZE {
        return Err(format!("SM4 密钥必须为 {} 字节", SM4_KEY_SIZE));
    }
    Sm4Gcm::new_from_slice(key).map_err(|e| format!("初始化 SM4-GCM 失败: {}", e))
}
