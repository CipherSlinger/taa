#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::Deserialize;
use serde_json::{json, Value};
use std::path::PathBuf;

mod crypto;
mod attestation;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileDialogFilter {
    name: String,
    extensions: Vec<String>,
}

fn apply_filters(mut dialog: rfd::FileDialog, filters: Option<Vec<FileDialogFilter>>) -> rfd::FileDialog {
    if let Some(filters) = filters {
        for filter in filters {
            dialog = dialog.add_filter(&filter.name, &filter.extensions);
        }
    }
    dialog
}

#[tauri::command]
fn pick_file(filters: Option<Vec<FileDialogFilter>>) -> Option<String> {
    apply_filters(rfd::FileDialog::new(), filters)
        .pick_file()
        .map(|path| path.display().to_string())
}

#[tauri::command]
fn pick_folder() -> Option<String> {
    rfd::FileDialog::new()
        .pick_folder()
        .map(|path| path.display().to_string())
}

#[tauri::command]
fn save_file(default_name: Option<String>, filters: Option<Vec<FileDialogFilter>>) -> Option<String> {
    let mut dialog = apply_filters(rfd::FileDialog::new(), filters);
    if let Some(default_name) = default_name {
        dialog = dialog.set_file_name(&default_name);
    }
    dialog.save_file().map(|path| path.display().to_string())
}

#[tauri::command]
async fn read_file(path: String) -> Result<String, String> {
    std::fs::read_to_string(&path).map_err(|e| format!("读取文件失败: {}", e))
}

#[tauri::command]
async fn write_file(path: String, content: String) -> Result<(), String> {
    std::fs::write(&path, &content).map_err(|e| format!("写入文件失败: {}", e))
}

#[tauri::command]
fn get_platform() -> String {
    std::env::consts::OS.to_string()
}

// ─── Validation Commands ────────────────────────────────────────────────────

#[tauri::command]
async fn validate_public_key(pem: String) -> Result<Value, String> {
    let pem_bytes = pem.trim().as_bytes();
    match crypto::sm2::parse_sm2_public_key_pem(pem_bytes) {
        Ok(_) => Ok(json!({"valid": true})),
        Err(e) => {
            eprintln!("[validate_public_key] Parse error: {}", e);
            Ok(json!({"valid": false, "error": e}))
        }
    }
}

#[tauri::command]
async fn validate_private_key(pem: String) -> Result<Value, String> {
    let pem_bytes = pem.trim().as_bytes();
    match crypto::sm2::parse_sm2_private_key_pem(pem_bytes) {
        Ok(_) => Ok(json!({"valid": true})),
        Err(e) => {
            eprintln!("[validate_private_key] Parse error: {}", e);
            Ok(json!({"valid": false, "error": e}))
        }
    }
}

// ─── Logging Command ────────────────────────────────────────────────────────

#[tauri::command]
async fn append_log(message: String) -> Result<(), String> {
    use std::fs::OpenOptions;
    use std::io::Write;

    let log_path = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join("teecrypto-gui.log");

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|e| format!("Failed to open log file: {}", e))?;

    writeln!(file, "{}", message)
        .map_err(|e| format!("Failed to write log: {}", e))?;

    Ok(())
}

// ─── Crypto Commands ────────────────────────────────────────────────────────

#[tauri::command]
async fn gen_key(memory: bool, output_dir: Option<String>) -> Result<Value, String> {
    let priv_key = crypto::sm2::generate_sm2_key_pair()?;
    let pub_pem = crypto::sm2::marshal_sm2_public_key_pem(&priv_key.public_key)?;
    let prv_pem = crypto::sm2::marshal_sm2_private_key_pem(&priv_key)?;

    if memory {
        return Ok(json!({
            "publicKey": String::from_utf8(pub_pem).map_err(|e| e.to_string())?,
            "privateKey": String::from_utf8(prv_pem).map_err(|e| e.to_string())?,
        }));
    }

    let dir = output_dir.unwrap_or_else(|| ".".to_string());
    let pub_path = PathBuf::from(&dir).join("public.pem");
    let prv_path = PathBuf::from(&dir).join("private.pem");

    std::fs::write(&pub_path, &pub_pem).map_err(|e| format!("写入公钥文件失败: {}", e))?;
    std::fs::write(&prv_path, &prv_pem).map_err(|e| format!("写入私钥文件失败: {}", e))?;

    Ok(json!({
        "publicKey": pub_path.display().to_string(),
        "privateKey": prv_path.display().to_string(),
    }))
}

#[tauri::command]
async fn encrypt_file(input_path: String, public_key: String) -> Result<Value, String> {
    let pub_pem = resolve_pem(&public_key)?;
    let pub_key = crypto::sm2::parse_sm2_public_key_pem(&pub_pem)?;

    let info = std::fs::metadata(&input_path).map_err(|e| format!("读取输入路径失败: {}", e))?;
    let plaintext = if info.is_dir() {
        let tmp_archive = std::env::temp_dir().join("teecrypto_encrypt_tmp.tar.gz");
        crypto::archive::create_tar_gz(&[PathBuf::from(&input_path)], &tmp_archive)?;
        let data = std::fs::read(&tmp_archive).map_err(|e| format!("读取归档失败: {}", e))?;
        let _ = std::fs::remove_file(&tmp_archive);
        data
    } else {
        std::fs::read(&input_path).map_err(|e| format!("读取输入文件失败: {}", e))?
    };

    let sealed = crypto::envelope::seal_sm2_gcm(&pub_key, &plaintext)?;

    // Write to temp file
    let tmp_path = std::env::temp_dir().join(format!("teecrypto_enc_{}.enc", std::process::id()));
    std::fs::write(&tmp_path, &sealed).map_err(|e| format!("写入临时文件失败: {}", e))?;

    Ok(json!({
        "tempPath": tmp_path.display().to_string(),
        "inputSize": plaintext.len(),
        "outputSize": sealed.len(),
        "isArchive": info.is_dir(),
    }))
}

#[tauri::command]
async fn decrypt_file(input_path: String, private_key: String) -> Result<Value, String> {
    let priv_pem = resolve_pem(&private_key)?;
    let priv_key = crypto::sm2::parse_sm2_private_key_pem(&priv_pem)?;

    let enc_data = std::fs::read(&input_path).map_err(|e| format!("读取密文文件失败: {}", e))?;
    let plaintext = crypto::envelope::open_sm2_gcm(&priv_key, &enc_data)?;

    let is_archive = plaintext.len() >= 2 && plaintext[0] == 0x1f && plaintext[1] == 0x8b;
    let mut temp_dir = String::new();
    let mut tmp_path = String::new();

    if is_archive {
        let tmp_dir = std::env::temp_dir().join(format!("teecrypto_extract_{}", std::process::id()));
        std::fs::create_dir_all(&tmp_dir).map_err(|e| format!("创建临时目录失败: {}", e))?;
        crypto::archive::extract_tar_gz(&plaintext, &tmp_dir)?;
        temp_dir = tmp_dir.display().to_string();
    } else {
        let tmp = std::env::temp_dir().join(format!("teecrypto_dec_{}", std::process::id()));
        std::fs::write(&tmp, &plaintext).map_err(|e| format!("写入临时文件失败: {}", e))?;
        tmp_path = tmp.display().to_string();
    }

    Ok(json!({
        "tempPath": tmp_path,
        "inputSize": enc_data.len(),
        "outputSize": plaintext.len(),
        "isArchive": is_archive,
        "tempDir": temp_dir,
    }))
}

#[tauri::command]
async fn save_output(temp_path: String, output_path: String) -> Result<(), String> {
    let src = std::path::Path::new(&temp_path);
    if !src.exists() {
        return Err(format!("临时文件不存在: {}", temp_path));
    }

    if src.is_dir() {
        copy_dir_recursive(src, std::path::Path::new(&output_path))
            .map_err(|e| format!("保存目录失败: {}", e))?;
        let _ = std::fs::remove_dir_all(&temp_path);
    } else {
        if let Some(parent) = std::path::Path::new(&output_path).parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("创建输出目录失败: {}", e))?;
            }
        }
        let data = std::fs::read(&temp_path)
            .map_err(|e| format!("读取临时文件失败: {}", e))?;
        std::fs::write(&output_path, &data)
            .map_err(|e| format!("保存文件失败: {}", e))?;
        let _ = std::fs::remove_file(&temp_path);
    }
    Ok(())
}

fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            let data = std::fs::read(&src_path)?;
            std::fs::write(&dst_path, &data)?;
        }
    }
    Ok(())
}

#[tauri::command]
async fn verify_report(report_path: String, verify_chain: bool) -> Result<Value, String> {
    let result = attestation::verify_report(&report_path, verify_chain)?;
    Ok(json!({
        "fields": build_field_rows(&result),
    }))
}

fn resolve_pem(arg: &str) -> Result<Vec<u8>, String> {
    let trimmed = arg.trim();
    if trimmed.starts_with("-----BEGIN") {
        Ok(trimmed.as_bytes().to_vec())
    } else {
        std::fs::read(arg).map_err(|e| format!("读取 PEM 文件失败: {}", e))
    }
}

fn build_field_rows(result: &attestation::VerificationResult) -> Vec<Value> {
    let mut rows = Vec::new();
    rows.push(field_row("报告文件", &result.report_size.to_string()));
    rows.push(field_row("报告长度", &format!("{} bytes", result.report_size)));
    rows.push(field_row("PUBKEY_DIGEST (0x000)", &result.pubkey_digest));
    rows.push(field_row("ID (0x020)", &result.vm_id));
    rows.push(field_row("Version (0x030)", &result.vm_version));
    rows.push(field_row("USERDATA (0x040)", &result.user_data));
    rows.push(field_row("MNONCE (0x080)", &result.mnonce));
    rows.push(field_row("DIGEST (0x090)", &result.digest));
    rows.push(field_row("POLICY (0x0B0)", &result.policy));
    rows.push(field_row("SIG_USAGE (0x0B4)", &result.sig_usage));
    rows.push(field_row("SIG_ALGO (0x0B8)", &result.sig_algo));
    rows.push(field_row("ANONCE (0x0BC)", &format!("0x{:08x}", result.anonce)));
    rows.push(field_row("Signature (0x0C0)", &result.signature));
    rows.push(field_row("PEK_CERT (0x150)", &format!("{} bytes", result.pek_cert_size)));
    rows.push(field_row("CHIP_ID (0x974)", &format!("{} ({})", result.chip_id_ascii, result.chip_id)));
    rows.push(field_row("Reserved2 (0x9B4)", &result.reserved2));
    rows.push(field_row("MAC (0x9D4)", &result.mac));

    let verified = if result.report_verified { "验证通过" } else { "验证失败" };
    rows.push(field_row("报告签名", verified));
    rows.push(separator());

    rows.push(field_row("PEK PubKeyUsage", &result.pek_details.pub_key_usage));
    rows.push(field_row("PEK Sig1Usage", &result.pek_details.sig1_usage));
    rows.push(field_row("PEK Sig2Usage", &result.pek_details.sig2_usage));
    rows.push(field_row("PEK CurveID", &format!("0x{:x}", result.pek_details.pub_key.curve_id)));
    rows.push(field_row("PEK UserID", &result.pek_details.pub_key.user_id));
    rows.push(field_row("PEK UserID Hex", &result.pek_details.pub_key.user_id_hex));
    rows.push(field_row("PEK QX", &result.pek_details.pub_key.qx_hex));
    rows.push(field_row("PEK QY", &result.pek_details.pub_key.qy_hex));

    if result.chain_verified {
        if let Some(ref details) = result.cert_details {
            rows.push(separator());
            rows.push(field_row("证书来源", &result.chain_source));
            rows.push(field_row("HRK URL", &result.hrk_url));
            rows.push(field_row("HSK/CEK URL", &result.hsk_cek_url));
            if !result.chain_download_note.is_empty() {
                rows.push(field_row("下载说明", &result.chain_download_note));
            }

            rows.push(separator());
            rows.push(field_row("HRK KeyUsage", &details.hrk.key_usage));
            rows.push(field_row("HRK UserID", &details.hrk.pub_key.user_id));
            rows.push(field_row("HRK QX", &details.hrk.pub_key.qx_hex));
            rows.push(field_row("HRK QY", &details.hrk.pub_key.qy_hex));
            rows.push(field_row("HRK 自签名", if details.hrk.self_signature_verified { "验证通过" } else { "验证失败" }));

            rows.push(separator());
            rows.push(field_row("HSK KeyUsage", &details.hsk.key_usage));
            rows.push(field_row("HSK UserID", &details.hsk.pub_key.user_id));
            rows.push(field_row("HSK QX", &details.hsk.pub_key.qx_hex));
            rows.push(field_row("HSK QY", &details.hsk.pub_key.qy_hex));
            rows.push(field_row("HSK HRK签名", if details.hsk.signed_by_hrk_verified { "验证通过" } else { "验证失败" }));

            rows.push(separator());
            rows.push(field_row("CEK PubKeyUsage", &details.cek.pub_key_usage));
            rows.push(field_row("CEK UserID", &details.cek.pub_key.user_id));
            rows.push(field_row("CEK QX", &details.cek.pub_key.qx_hex));
            rows.push(field_row("CEK QY", &details.cek.pub_key.qy_hex));
            rows.push(field_row("CEK HSK签名", if details.cek.signed_by_hsk_verified { "验证通过" } else { "验证失败" }));

            rows.push(separator());
            rows.push(field_row("PEK (chain) UserID", &details.pek.pub_key.user_id));
            rows.push(field_row("PEK (chain) QX", &details.pek.pub_key.qx_hex));
            rows.push(field_row("PEK (chain) QY", &details.pek.pub_key.qy_hex));
            rows.push(field_row("PEK CEK签名", if details.pek.signed_by_cek_verified { "验证通过" } else { "验证失败" }));

            rows.push(separator());
            rows.push(field_row("证书链", if result.chain_verified { "验证通过" } else { "验证失败" }));
        }
    } else {
        rows.push(field_row("证书链", "未验证"));
    }

    rows
}

fn field_row(name: &str, value: &str) -> Value {
    json!({"name": name, "value": value})
}

fn separator() -> Value {
    json!({"name": "", "value": "", "separator": "true"})
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            pick_file,
            pick_folder,
            save_file,
            read_file,
            write_file,
            get_platform,
            append_log,
            gen_key,
            validate_public_key,
            validate_private_key,
            encrypt_file,
            decrypt_file,
            save_output,
            verify_report,
        ])
        .run(tauri::generate_context!())
        .expect("启动 Tauri 应用失败");
}
