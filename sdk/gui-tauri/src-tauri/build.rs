use std::{env, fs, path::{Path, PathBuf}};

fn main() {
    let mut attributes = tauri_build::Attributes::new();

    if cfg!(not(windows)) {
        if let Some(rc) = find_windows_resource_compiler() {
            let shim = write_llvm_rc_shim(&rc).expect("failed to write llvm-rc shim");
            env::set_var("RC", &shim);
            println!("cargo:warning=Using llvm-rc shim: {} -> {}", shim.display(), rc.display());

            // On WSL, the shim will convert WSL paths to Windows paths in the resource file
        }
    }

    tauri_build::try_build(attributes).expect("failed to run tauri-build");
}

fn convert_to_windows_path(path: &Path) -> std::io::Result<String> {
    use std::process::Command;

    let output = Command::new("wslpath")
        .arg("-w")
        .arg(path.canonicalize()?)
        .output()?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "wslpath conversion failed",
        ))
    }
}

fn write_llvm_rc_shim(rc: &Path) -> std::io::Result<PathBuf> {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("missing OUT_DIR"));
    let shim = out_dir.join("llvm-rc");
    let script = r#"#!/usr/bin/env bash
set -euo pipefail

if [[ " ${1-} ${2-} ${3-} " == *" -V "* ]] || [[ " ${1-} ${2-} ${3-} " == *" /? "* ]]; then
  printf 'GNU windres (GNU Binutils) 2.40\n'
  exit 0
fi

out=
input=
while (($#)); do
  case "$1" in
    --input)
      input=$2
      shift 2
      ;;
    --output)
      out=$2
      shift 2
      ;;
    --include-dir)
      shift 2
      ;;
    --output-format=coff)
      shift
      ;;
    -D|-I)
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "${out}" || -z "${input}" ]]; then
  echo "windres shim: missing input or output" >&2
  exit 2
fi

# Convert WSL paths in the resource file to Windows paths
input_dir=$(dirname "$input")
tmp_rc="$input_dir/resource-converted.rc"
while IFS= read -r line; do
  if echo "$line" | grep -q 'ICON "/mnt/'; then
    wsl_path=$(echo "$line" | sed 's/.*ICON "//' | sed 's/"//')
    # Copy icon to build directory to avoid path encoding issues
    if [ -f "$wsl_path" ]; then
      cp "$wsl_path" "$input_dir/icon.ico"
      echo "$line" | sed 's|".*"|"icon.ico"|'
    else
      echo "$line"
    fi
  else
    echo "$line"
  fi
done < "$input" > "$tmp_rc"

win_out=$(wslpath -w "$out")
win_tmp=$(wslpath -w "$tmp_rc")
exec '__RC_PATH__' /fo "$win_out" "$win_tmp"
"#.replace("__RC_PATH__", &rc.display().to_string());
    fs::write(&shim, script)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&shim)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&shim, perms)?;
    }

    Ok(shim)
}

fn find_windows_resource_compiler() -> Option<PathBuf> {
    if let Some(rc) = env::var_os("RC") {
        let path = PathBuf::from(rc);
        if path.is_file() {
            return Some(path);
        }
    }

    if let Some(found) = find_in_path("llvm-rc") {
        return Some(found);
    }
    if let Some(found) = find_in_path("llvm-rc.exe") {
        return Some(found);
    }
    if let Some(found) = find_in_path("rc.exe") {
        return Some(found);
    }
    if let Some(found) = find_in_path("windres") {
        return Some(found);
    }
    if let Some(found) = find_in_path("windres.exe") {
        return Some(found);
    }
    if let Some(found) = find_in_path("x86_64-w64-mingw32-windres") {
        return Some(found);
    }
    if let Some(found) = find_in_path("x86_64-w64-mingw32-windres.exe") {
        return Some(found);
    }

    let windows_kits_roots = [
        "/mnt/c/Program Files (x86)/Windows Kits/10/bin",
        "/mnt/c/Program Files/Windows Kits/10/bin",
    ];
    let arches = ["x64", "x86", "arm64"];
    let versions = ["10.0.26100.0", "10.0.22621.0", "10.0.19041.0"];

    for root in windows_kits_roots {
        for version in versions {
            for arch in arches {
                let candidate = Path::new(root).join(version).join(arch).join("rc.exe");
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }

    None
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path).find_map(|dir| {
        let candidate = dir.join(name);
        if candidate.is_file() {
            Some(candidate)
        } else {
            None
        }
    })
}
