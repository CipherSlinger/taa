// tar.gz archive handling for folder encryption

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tar::{Archive, Builder};

pub fn create_tar_gz(sources: &[PathBuf], output: &Path) -> Result<(), String> {
    if sources.is_empty() {
        return Err("没有要归档的源文件".into());
    }
    let file = fs::File::create(output).map_err(|e| format!("创建输出文件失败: {}", e))?;
    let enc = GzEncoder::new(file, Compression::default());
    let mut tar = Builder::new(enc);

    for source in sources {
        let source = source.canonicalize().map_err(|e| format!("访问路径失败: {}", e))?;
        let base_name = source.file_name().unwrap().to_string_lossy().to_string();
        if source.is_dir() {
            add_dir_to_tar(&mut tar, &source, &base_name)?;
        } else {
            add_file_to_tar(&mut tar, &source, &base_name)?;
        }
    }
    tar.finish().map_err(|e| format!("写入归档失败: {}", e))
}

pub fn extract_tar_gz(data: &[u8], output_dir: &Path) -> Result<(), String> {
    let decoder = GzDecoder::new(data);
    let mut archive = Archive::new(decoder);
    fs::create_dir_all(output_dir).map_err(|e| format!("创建输出目录失败: {}", e))?;
    let clean_output = output_dir.canonicalize().unwrap_or_else(|_| output_dir.to_path_buf());

    for entry in archive.entries().map_err(|e| format!("读取归档失败: {}", e))? {
        let mut entry = entry.map_err(|e| format!("读取归档条目失败: {}", e))?;
        let path = entry.path().map_err(|e| format!("获取路径失败: {}", e))?.to_path_buf();
        let target = clean_output.join(&path);

        if !target.starts_with(&clean_output) {
            return Err(format!("检测到不安全的路径: {}", path.display()));
        }

        match entry.header().entry_type() {
            tar::EntryType::Directory => {
                fs::create_dir_all(&target).map_err(|e| format!("创建目录失败: {}", e))?;
            }
            tar::EntryType::Regular => {
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent).map_err(|e| format!("创建父目录失败: {}", e))?;
                }
                let mut file = fs::File::create(&target).map_err(|e| format!("创建文件失败: {}", e))?;
                std::io::copy(&mut entry, &mut file).map_err(|e| format!("写入文件失败: {}", e))?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn add_dir_to_tar(tar: &mut Builder<GzEncoder<fs::File>>, source: &Path, base_name: &str) -> Result<(), String> {
    for entry in walkdir(source) {
        let path = entry?;
        if path.is_dir() {
            continue;
        }
        let rel = path.strip_prefix(source).map_err(|e| format!("计算相对路径失败: {}", e))?;
        let name_in_archive = Path::new(base_name).join(rel);
        let mut file = fs::File::open(&path).map_err(|e| format!("打开文件失败: {}", e))?;
        tar.append_file(&name_in_archive, &mut file).map_err(|e| format!("写入归档失败: {}", e))?;
    }
    Ok(())
}

fn add_file_to_tar(tar: &mut Builder<GzEncoder<fs::File>>, source: &Path, name: &str) -> Result<(), String> {
    let mut file = fs::File::open(source).map_err(|e| format!("打开文件失败: {}", e))?;
    tar.append_file(name, &mut file).map_err(|e| format!("写入归档失败: {}", e))
}

fn walkdir(dir: &Path) -> Vec<Result<PathBuf, String>> {
    let mut result = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                result.push(Ok(path.clone()));
                if path.is_dir() {
                    result.extend(walkdir(&path));
                }
            }
        }
    }
    result
}
