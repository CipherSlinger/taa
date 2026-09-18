// SM2 envelope encryption — SealSM2SM4GCM / OpenSM2SM4GCM

use super::sm2::{encrypt_sm2, decrypt_sm2, SM2PublicKey, SM2PrivateKey, SM2_WRAPPED_KEY_SIZE};
use super::sm4::{self, SM4_KEY_SIZE};

pub fn seal_sm2_gcm(pub_key: &SM2PublicKey, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let data_key = sm4::generate_sm4_key()?;
    let wrapped_key = wrap_key_sm2(pub_key, &data_key)?;
    let mut sealed = Vec::with_capacity(wrapped_key.len() + plaintext.len() + 28);
    sealed.extend_from_slice(&wrapped_key);
    let encrypted = sm4::encrypt(&data_key, plaintext)?;
    sealed.extend_from_slice(&encrypted);
    Ok(sealed)
}

pub fn open_sm2_gcm(priv_key: &SM2PrivateKey, sealed: &[u8]) -> Result<Vec<u8>, String> {
    if sealed.len() <= SM2_WRAPPED_KEY_SIZE {
        return Err(format!("SM2 密文长度无效: {}", sealed.len()));
    }
    let wrapped_key = &sealed[..SM2_WRAPPED_KEY_SIZE];
    let ciphertext = &sealed[SM2_WRAPPED_KEY_SIZE..];
    let data_key = unwrap_key_sm2(priv_key, wrapped_key)?;
    sm4::decrypt(&data_key, ciphertext)
}

fn wrap_key_sm2(pub_key: &SM2PublicKey, data_key: &[u8]) -> Result<Vec<u8>, String> {
    if data_key.len() != SM4_KEY_SIZE {
        return Err(format!("SM4 密钥必须为 {} 字节", SM4_KEY_SIZE));
    }
    encrypt_sm2(pub_key, data_key)
}

fn unwrap_key_sm2(priv_key: &SM2PrivateKey, envelope: &[u8]) -> Result<Vec<u8>, String> {
    if envelope.len() != SM2_WRAPPED_KEY_SIZE {
        return Err(format!("SM2 密钥信封长度无效: {}", envelope.len()));
    }
    let data_key = decrypt_sm2(priv_key, envelope)?;
    if data_key.len() != SM4_KEY_SIZE {
        return Err(format!("SM4 密钥必须为 {} 字节", SM4_KEY_SIZE));
    }
    Ok(data_key)
}
