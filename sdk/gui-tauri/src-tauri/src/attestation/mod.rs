// Hygon CSV attestation report verification — ported from Go attestation/attestation.go

use serde::Serialize;
use std::fs;
use std::path::Path;
use std::time::Duration;

use crate::crypto::sm2::{verify_sm2, SM2PublicKey};

const REPORT_SIZE: usize = 0x9f4;
const SIGNED_SIZE: usize = 0xb4;
const HRK_CERT_SIZE: usize = 0x340;
const CSV_CERT_SIZE: usize = 0x824;
const HSK_CEK_SIZE: usize = HRK_CERT_SIZE + CSV_CERT_SIZE;

const HRK_CERT_URL: &str = "https://cert.hygon.cn/hrk";
const KDS_CERT_URL: &str = "https://cert.hygon.cn/hsk_cek?snumber=";

// Report offsets
const OFF_PUBKEY_DIGEST: usize = 0x000;
const OFF_VM_ID: usize = 0x020;
const OFF_VM_VERSION: usize = 0x030;
const OFF_USER_DATA: usize = 0x040;
const OFF_MNONCE: usize = 0x080;
const OFF_DIGEST: usize = 0x090;
const OFF_POLICY: usize = 0x0b0;
const OFF_SIG_USAGE: usize = 0x0b4;
const OFF_SIG_ALGO: usize = 0x0b8;
const OFF_ANONCE: usize = 0x0bc;
const OFF_SIG1: usize = 0x0c0;
const OFF_PEK_CERT: usize = 0x150;
const OFF_CHIP_ID: usize = 0x974;
const OFF_RESERVED2: usize = 0x9b4;
const OFF_MAC: usize = 0x9d4;

// Certificate offsets
const OFF_ROOT_KEY_USAGE: usize = 0x024;
const OFF_ROOT_PUB_KEY: usize = 0x040;
const OFF_ROOT_SIG: usize = 0x240;
const OFF_CSV_PUB_KEY_USAGE: usize = 0x008;
const OFF_CSV_PUB_KEY: usize = 0x010;
const OFF_CSV_SIG1_USAGE: usize = 0x414;
const OFF_CSV_SIG1: usize = 0x41c;
const OFF_CSV_SIG2_USAGE: usize = 0x61c;
const OFF_ECC_QX: usize = 0x004;
const OFF_ECC_QY: usize = 0x04c;
const OFF_ECC_UID: usize = 0x094;
const OFF_SIG_R: usize = 0x000;
const OFF_SIG_S: usize = 0x048;

const KEY_USAGE_HRK: u32 = 0x0;
const KEY_USAGE_HSK: u32 = 0x13;
const KEY_USAGE_INVALID: u32 = 0x1000;
const KEY_USAGE_PEK: u32 = 0x1002;
const KEY_USAGE_CEK: u32 = 0x1004;
const CURVE_ID_SM2: u32 = 0x3;

#[derive(Serialize, Clone)]
pub struct VerificationResult {
    pub report_size: usize,
    pub pubkey_digest: String,
    pub vm_id: String,
    pub vm_version: String,
    pub user_data: String,
    pub mnonce: String,
    pub digest: String,
    pub policy: String,
    pub sig_usage: String,
    pub sig_algo: String,
    pub anonce: u32,
    pub signature: String,
    pub pek_cert_size: usize,
    pub chip_id: String,
    pub chip_id_ascii: String,
    pub reserved2: String,
    pub mac: String,
    pub pek_details: CSVCertDetails,
    pub report_verified: bool,
    pub chain_verified: bool,
    pub chain_source: String,
    pub chain_download_note: String,
    pub hrk_url: String,
    pub hsk_cek_url: String,
    pub cert_details: Option<CertChainDetails>,
}

#[derive(Serialize, Clone)]
pub struct PubKeyDetails {
    pub curve_id: u32,
    pub user_id: String,
    pub user_id_hex: String,
    pub qx_hex: String,
    pub qy_hex: String,
}

#[derive(Serialize, Clone)]
pub struct RootCertDetails {
    pub key_usage: String,
    pub pub_key: PubKeyDetails,
    pub self_signature_verified: bool,
    pub signed_by_hrk_verified: bool,
}

#[derive(Serialize, Clone)]
pub struct CSVCertDetails {
    pub pub_key_usage: String,
    pub sig1_usage: String,
    pub sig2_usage: String,
    pub pub_key: PubKeyDetails,
    pub signed_by_hsk_verified: bool,
    pub signed_by_cek_verified: bool,
}

#[derive(Serialize, Clone)]
pub struct CertChainDetails {
    pub hrk: RootCertDetails,
    pub hsk: RootCertDetails,
    pub cek: CSVCertDetails,
    pub pek: CSVCertDetails,
}

pub fn verify_report(report_file: &str, verify_chain: bool) -> Result<VerificationResult, String> {
    let data = fs::read(report_file).map_err(|e| format!("读取报告文件失败: {}", e))?;
    let cert_dir = Path::new(report_file).parent().unwrap_or(Path::new("."));
    verify_report_data(&data, cert_dir, verify_chain)
}

fn verify_report_data(data: &[u8], cert_dir: &Path, verify_chain: bool) -> Result<VerificationResult, String> {
    if data.len() < REPORT_SIZE {
        return Err(format!("报告长度不足: {} bytes, 需要至少 {} bytes", data.len(), REPORT_SIZE));
    }
    let report = &data[..REPORT_SIZE];
    let anonce = u32::from_le_bytes(report[OFF_ANONCE..OFF_ANONCE + 4].try_into().unwrap());

    let pubkey_digest = report[OFF_PUBKEY_DIGEST..OFF_PUBKEY_DIGEST + 32].to_vec();
    let vm_id = report[OFF_VM_ID..OFF_VM_ID + 16].to_vec();
    let vm_version = report[OFF_VM_VERSION..OFF_VM_VERSION + 16].to_vec();
    let signature = report[OFF_SIG1..OFF_SIG1 + 144].to_vec();
    let reserved2 = report[OFF_RESERVED2..OFF_RESERVED2 + 32].to_vec();
    let mac = report[OFF_MAC..OFF_MAC + 32].to_vec();

    let user_data = unmask_words(&report[OFF_USER_DATA..OFF_USER_DATA + 64], anonce);
    let mnonce = unmask_words(&report[OFF_MNONCE..OFF_MNONCE + 16], anonce);
    let digest = unmask_words(&report[OFF_DIGEST..OFF_DIGEST + 32], anonce);
    let chip_id = unmask_words(&report[OFF_CHIP_ID..OFF_CHIP_ID + 64], anonce);
    let pek_cert = unmask_words(&report[OFF_PEK_CERT..OFF_PEK_CERT + CSV_CERT_SIZE], anonce);

    let policy = u32::from_le_bytes(unmask_words(&report[OFF_POLICY..OFF_POLICY + 4], anonce).try_into().unwrap());
    let sig_usage = u32::from_le_bytes(unmask_words(&report[OFF_SIG_USAGE..OFF_SIG_USAGE + 4], anonce).try_into().unwrap());
    let sig_algo = u32::from_le_bytes(unmask_words(&report[OFF_SIG_ALGO..OFF_SIG_ALGO + 4], anonce).try_into().unwrap());

    let chip_id_ascii = chip_id_to_ascii(&chip_id)?;
    let hrk_url = HRK_CERT_URL.to_string();
    let hsk_cek_url = format!("{}{}", KDS_CERT_URL, chip_id_ascii);

    let pek_details = parse_csv_cert_details(&pek_cert)?;
    let pek_pub = parse_hygon_pub_key(&pek_cert[OFF_CSV_PUB_KEY..])?;

    let (r, s) = parse_hygon_signature(&report[OFF_SIG1..]);
    let report_verified = verify_sm2(&pek_pub.key, &pek_pub.user_id, &report[..SIGNED_SIZE], &r, &s);
    if !report_verified {
        return Err("报告签名验证失败".into());
    }

    let mut result = VerificationResult {
        report_size: REPORT_SIZE,
        pubkey_digest: hex::encode(&pubkey_digest),
        vm_id: hex::encode(&vm_id),
        vm_version: hex::encode(&vm_version),
        user_data: hex::encode(&user_data),
        mnonce: hex::encode(&mnonce),
        digest: hex::encode(&digest),
        policy: format!("0x{:08x}", policy),
        sig_usage: format!("0x{:08x}", sig_usage),
        sig_algo: format!("0x{:08x}", sig_algo),
        anonce,
        signature: hex::encode(&signature),
        pek_cert_size: pek_cert.len(),
        chip_id: hex::encode(&chip_id),
        chip_id_ascii: chip_id_ascii.clone(),
        reserved2: hex::encode(&reserved2),
        mac: hex::encode(&mac),
        pek_details,
        report_verified,
        chain_verified: false,
        chain_source: String::new(),
        chain_download_note: String::new(),
        hrk_url,
        hsk_cek_url,
        cert_details: None,
    };

    if verify_chain {
        let certs = load_cert_chain(cert_dir, &chip_id_ascii)?;
        result.chain_source = certs.source.clone();
        result.chain_download_note = certs.download_note.clone();
        result.hrk_url = certs.hrk_url.clone();
        result.hsk_cek_url = certs.hsk_cek_url.clone();

        let details = verify_cert_chain(&certs, &pek_cert)?;
        result.cert_details = Some(details);
        result.chain_verified = true;
    }
    Ok(result)
}

fn unmask_words(data: &[u8], anonce: u32) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    for i in (0..data.len()).step_by(4) {
        if i + 4 <= data.len() {
            let word = u32::from_le_bytes(data[i..i + 4].try_into().unwrap()) ^ anonce;
            out[i..i + 4].copy_from_slice(&word.to_le_bytes());
        }
    }
    out
}

fn chip_id_to_ascii(chip_id: &[u8]) -> Result<String, String> {
    let s = String::from_utf8_lossy(chip_id);
    let trimmed = s.trim().trim_end_matches('\0');
    if trimmed.is_empty() {
        return Err("ChipID 为空".into());
    }
    for b in trimmed.bytes() {
        if b < 0x20 || b > 0x7e {
            return Err(format!("ChipID 包含不可打印字符: 0x{:02x}", b));
        }
    }
    Ok(trimmed.to_string())
}

struct HygonPubKey {
    key: SM2PublicKey,
    user_id: Vec<u8>,
    details: PubKeyDetails,
}

fn parse_hygon_pub_key(data: &[u8]) -> Result<HygonPubKey, String> {
    if data.len() < OFF_ECC_UID + 256 {
        return Err("公钥数据长度不足".into());
    }
    let curve_id = u32::from_le_bytes(data[..4].try_into().unwrap());
    if curve_id != CURVE_ID_SM2 {
        return Err(format!("不支持的曲线 ID: 0x{:x}", curve_id));
    }
    let mut x_bytes = data[OFF_ECC_QX..OFF_ECC_QX + 32].to_vec();
    let mut y_bytes = data[OFF_ECC_QY..OFF_ECC_QY + 32].to_vec();
    x_bytes.reverse();
    y_bytes.reverse();
    let x = num_bigint::BigUint::from_bytes_be(&x_bytes);
    let y = num_bigint::BigUint::from_bytes_be(&y_bytes);

    let uid_data = &data[OFF_ECC_UID..];
    let uid_len = u16::from_le_bytes(uid_data[..2].try_into().unwrap()) as usize;
    if uid_len > uid_data.len() - 2 {
        return Err(format!("SM2 user id 长度无效: {}", uid_len));
    }
    let user_id = uid_data[2..2 + uid_len].to_vec();

    Ok(HygonPubKey {
        key: SM2PublicKey { x, y },
        user_id: user_id.clone(),
        details: PubKeyDetails {
            curve_id,
            user_id: String::from_utf8_lossy(&user_id).to_string(),
            user_id_hex: hex::encode(&user_id),
            qx_hex: hex::encode(&x_bytes),
            qy_hex: hex::encode(&y_bytes),
        },
    })
}

fn parse_hygon_signature(sig: &[u8]) -> (num_bigint::BigUint, num_bigint::BigUint) {
    let mut r_bytes = sig[OFF_SIG_R..OFF_SIG_R + 32].to_vec();
    let mut s_bytes = sig[OFF_SIG_S..OFF_SIG_S + 32].to_vec();
    r_bytes.reverse();
    s_bytes.reverse();
    (
        num_bigint::BigUint::from_bytes_be(&r_bytes),
        num_bigint::BigUint::from_bytes_be(&s_bytes),
    )
}

fn parse_csv_cert_details(cert: &[u8]) -> Result<CSVCertDetails, String> {
    if cert.len() < CSV_CERT_SIZE {
        return Err(format!("证书长度不足: {}", cert.len()));
    }
    let pub_key = parse_hygon_pub_key(&cert[OFF_CSV_PUB_KEY..])?;
    Ok(CSVCertDetails {
        pub_key_usage: format!("0x{:x}", u32::from_le_bytes(cert[OFF_CSV_PUB_KEY_USAGE..OFF_CSV_PUB_KEY_USAGE + 4].try_into().unwrap())),
        sig1_usage: format!("0x{:x}", u32::from_le_bytes(cert[OFF_CSV_SIG1_USAGE..OFF_CSV_SIG1_USAGE + 4].try_into().unwrap())),
        sig2_usage: format!("0x{:x}", u32::from_le_bytes(cert[OFF_CSV_SIG2_USAGE..OFF_CSV_SIG2_USAGE + 4].try_into().unwrap())),
        pub_key: pub_key.details,
        signed_by_hsk_verified: false,
        signed_by_cek_verified: false,
    })
}

fn parse_root_cert_details(cert: &[u8]) -> Result<RootCertDetails, String> {
    if cert.len() < HRK_CERT_SIZE {
        return Err(format!("证书长度不足: {}", cert.len()));
    }
    let pub_key = parse_hygon_pub_key(&cert[OFF_ROOT_PUB_KEY..])?;
    Ok(RootCertDetails {
        key_usage: format!("0x{:x}", u32::from_le_bytes(cert[OFF_ROOT_KEY_USAGE..OFF_ROOT_KEY_USAGE + 4].try_into().unwrap())),
        pub_key: pub_key.details,
        self_signature_verified: false,
        signed_by_hrk_verified: false,
    })
}

struct CertChainInput {
    hrk: Vec<u8>,
    hsk_cek: Vec<u8>,
    source: String,
    download_note: String,
    hrk_url: String,
    hsk_cek_url: String,
}

fn load_cert_chain(cert_dir: &Path, chip_id_ascii: &str) -> Result<CertChainInput, String> {
    let hrk_url = HRK_CERT_URL.to_string();
    let hsk_cek_url = format!("{}{}", KDS_CERT_URL, chip_id_ascii);

    let hrk = download_cert(&hrk_url, HRK_CERT_SIZE);
    let hsk_cek = download_cert(&hsk_cek_url, HSK_CEK_SIZE);

    if hrk.is_ok() && hsk_cek.is_ok() {
        return Ok(CertChainInput {
            hrk: hrk.unwrap(),
            hsk_cek: hsk_cek.unwrap(),
            source: "远程下载".into(),
            download_note: String::new(),
            hrk_url,
            hsk_cek_url,
        });
    }

    let local = load_local_cert_chain(cert_dir);
    if local.is_ok() {
        let mut certs = local.unwrap();
        certs.source = "本地文件（远程下载失败后回退）".into();
        certs.download_note = format!("远程下载失败: HRK={:?}; HSK/CEK={:?}", hrk.err(), hsk_cek.err());
        certs.hrk_url = hrk_url;
        certs.hsk_cek_url = hsk_cek_url;
        return Ok(certs);
    }

    Err(format!(
        "下载证书失败且本地证书不可用(chip_id={}): HRK={:?}; HSK/CEK={:?}; 本地={:?}",
        chip_id_ascii, hrk.err(), hsk_cek.err(), local.err()
    ))
}

fn load_local_cert_chain(cert_dir: &Path) -> Result<CertChainInput, String> {
    let hrk_path = cert_dir.join("hrk.cert");
    let hsk_cek_path = cert_dir.join("hsk_cek.cert");
    let hrk = read_fixed_file(&hrk_path, HRK_CERT_SIZE)?;
    let hsk_cek = read_fixed_file(&hsk_cek_path, HSK_CEK_SIZE)?;
    Ok(CertChainInput {
        hrk,
        hsk_cek,
        source: "本地文件".into(),
        download_note: String::new(),
        hrk_url: String::new(),
        hsk_cek_url: String::new(),
    })
}

fn download_cert(url: &str, expected_size: usize) -> Result<Vec<u8>, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("创建 HTTP 客户端失败: {}", e))?;
    let resp = client.get(url).send().map_err(|e| format!("HTTP 请求失败: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("HTTP 状态码 {}", resp.status()));
    }
    let data = resp.bytes().map_err(|e| format!("读取响应失败: {}", e))?;
    if data.len() < expected_size {
        return Err(format!("证书长度不足: {} bytes, 需要至少 {} bytes", data.len(), expected_size));
    }
    Ok(data[..expected_size].to_vec())
}

fn read_fixed_file(path: &Path, size: usize) -> Result<Vec<u8>, String> {
    let data = fs::read(path).map_err(|e| format!("读取文件失败: {}", e))?;
    if data.len() < size {
        return Err(format!("文件长度不足: {} bytes, 需要至少 {} bytes", data.len(), size));
    }
    Ok(data[..size].to_vec())
}

fn verify_cert_chain(certs: &CertChainInput, pek_cert: &[u8]) -> Result<CertChainDetails, String> {
    if certs.hrk.len() < HRK_CERT_SIZE {
        return Err(format!("hrk.cert 长度不足: {}", certs.hrk.len()));
    }
    if certs.hsk_cek.len() < HSK_CEK_SIZE {
        return Err(format!("hsk_cek.cert 长度不足: {}", certs.hsk_cek.len()));
    }
    let hrk = &certs.hrk[..HRK_CERT_SIZE];
    let hsk = &certs.hsk_cek[..HRK_CERT_SIZE];
    let cek = &certs.hsk_cek[HRK_CERT_SIZE..HSK_CEK_SIZE];

    let mut details = CertChainDetails {
        hrk: parse_root_cert_details(hrk)?,
        hsk: parse_root_cert_details(hsk)?,
        cek: parse_csv_cert_details(cek)?,
        pek: parse_csv_cert_details(pek_cert)?,
    };

    // Verify key usage
    let hrk_usage = u32::from_le_bytes(hrk[OFF_ROOT_KEY_USAGE..OFF_ROOT_KEY_USAGE + 4].try_into().unwrap());
    let hsk_usage = u32::from_le_bytes(hsk[OFF_ROOT_KEY_USAGE..OFF_ROOT_KEY_USAGE + 4].try_into().unwrap());
    let cek_usage = u32::from_le_bytes(cek[OFF_CSV_PUB_KEY_USAGE..OFF_CSV_PUB_KEY_USAGE + 4].try_into().unwrap());
    let pek_usage = u32::from_le_bytes(pek_cert[OFF_CSV_PUB_KEY_USAGE..OFF_CSV_PUB_KEY_USAGE + 4].try_into().unwrap());

    if hrk_usage != KEY_USAGE_HRK { return Err(format!("HRK key_usage 无效: 0x{:x}", hrk_usage)); }
    if hsk_usage != KEY_USAGE_HSK { return Err(format!("HSK key_usage 无效: 0x{:x}", hsk_usage)); }
    if cek_usage != KEY_USAGE_CEK { return Err(format!("CEK pubkey_usage 无效: 0x{:x}", cek_usage)); }
    if pek_usage != KEY_USAGE_PEK { return Err(format!("PEK pubkey_usage 无效: 0x{:x}", pek_usage)); }

    let hrk_pub = parse_hygon_pub_key(&hrk[OFF_ROOT_PUB_KEY..])?;
    let hsk_pub = parse_hygon_pub_key(&hsk[OFF_ROOT_PUB_KEY..])?;
    let cek_pub = parse_hygon_pub_key(&cek[OFF_CSV_PUB_KEY..])?;

    let (r, s) = parse_hygon_signature(&hrk[OFF_ROOT_SIG..]);
    details.hrk.self_signature_verified = verify_sm2(&hrk_pub.key, &hrk_pub.user_id, &hrk[..OFF_ROOT_SIG], &r, &s);
    if !details.hrk.self_signature_verified {
        return Err("HRK 自签名验证失败".into());
    }

    let (r, s) = parse_hygon_signature(&hsk[OFF_ROOT_SIG..]);
    details.hsk.signed_by_hrk_verified = verify_sm2(&hrk_pub.key, &hrk_pub.user_id, &hsk[..OFF_ROOT_SIG], &r, &s);
    if !details.hsk.signed_by_hrk_verified {
        return Err("HRK 验证 HSK 签名失败".into());
    }

    let (r, s) = parse_hygon_signature(&cek[OFF_CSV_SIG1..]);
    details.cek.signed_by_hsk_verified = verify_sm2(&hsk_pub.key, &hsk_pub.user_id, &cek[..OFF_CSV_SIG1_USAGE], &r, &s);
    if !details.cek.signed_by_hsk_verified {
        return Err("HSK 验证 CEK 签名失败".into());
    }

    let (r, s) = parse_hygon_signature(&pek_cert[OFF_CSV_SIG1..]);
    details.pek.signed_by_cek_verified = verify_sm2(&cek_pub.key, &cek_pub.user_id, &pek_cert[..OFF_CSV_SIG1_USAGE], &r, &s);
    if !details.pek.signed_by_cek_verified {
        return Err("CEK 验证 PEK 签名失败".into());
    }

    Ok(details)
}

mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
