#!/usr/bin/env bash
# 构建并可选部署一个包含本仓库 TAA 二进制文件的 Kata CSV initrd。
# 这里的关键设计是：把原始 Kata initrd 解压成 cpio 归档后保持原有内容不动，
# 只向归档末尾追加少量新文件。不要完整解包再重新打包 base initrd，
# 因为其中包含设备节点；普通用户解包设备节点可能失败，并导致 /dev/console
# 等原始条目被静默丢失。
set -euo pipefail

# 流程：先 build，再按需 deploy 和 launch，最后校验 Ready 和 QEMU initrd。

# 按脚本所在目录解析路径，这样从任意工作目录执行脚本都能得到一致结果。
# ROOT_DIR 是仓库根目录，SCRIPT_DIR 是 guest-build/ 目录。
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# 本地构建输入和输出。TAA 启动时会固定调用 ./attestation/get-attestation，
# 因此除了 TAA 主程序，还必须把标准 helper（默认 bin/get-attestation）一起注入 initrd。
# BASE_INITRD 必须是远程原始 Kata CSV initrd，不能是已经注入过 TAA 的输出文件；
# 否则再次追加会产生重复 payload 路径，并以不可控方式改变启动度量。
TAA_SRC="$ROOT_DIR/bin/taa"
ATTESTATION_HELPER_SRC="${ATTESTATION_HELPER_SRC:-$ROOT_DIR/bin/get-attestation}"
BASE_INITRD="$SCRIPT_DIR/base/kata-containers-initrd-confidential-csv.img"
OUT_DIR="$SCRIPT_DIR/out"
INITRD_OUT="$OUT_DIR/kata-containers-initrd-taa-csv.initrd"

# 写入 init wrapper 的运行时配置。TAA_ADDR 有默认值；PLATFORM_IP 和
# DOCKER_ID 在构建时是可选的，因为部分调试场景只需要生成镜像。
# 但 deploy/all 默认会要求 initrd 中已注入 /etc/default/taa.env，避免远程拉起后
# TAA 因缺少注册身份而被跳过。TAA_REQUIRED=1 时，如果 TAA 缺少必要环境或
# 启动后立刻退出，wrapper 不会继续启动 kata-agent，从而让 Pod Ready 校验失败。
TAA_ADDR="${TAA_ADDR:-0.0.0.0:6001}"
TAA_PLATFORM_IP="${TAA_PLATFORM_IP:-}"
TAA_DOCKER_ID="${TAA_DOCKER_ID:-}"
TAA_REQUIRED="${TAA_REQUIRED:-1}"
ALLOW_MISSING_TAA_ENV="${ALLOW_MISSING_TAA_ENV:-0}"

taa_env_file_needed() {
  [[ -n "$TAA_PLATFORM_IP" && -n "$TAA_DOCKER_ID" ]]
}

# 当前海光 CSV 测试主机的远程部署默认值。所有值都可通过环境变量覆盖，
# 因此同一个脚本可以用于其它服务器、其它 Kata 配置或其它 RuntimeClass 名称。
REMOTE_USER="${REMOTE_USER:-osr}"
REMOTE_HOST="${REMOTE_HOST:-172.16.10.178}"
REMOTE="${REMOTE_USER}@${REMOTE_HOST}"
REMOTE_BUNDLE_DIR="${REMOTE_BUNDLE_DIR:-/opt/kata/share/kata-containers/taa-csv-20260901}"
REMOTE_BASE_INITRD_SRC="${REMOTE_BASE_INITRD_SRC:-/opt/kata/share/kata-containers/kata-containers-initrd-confidential-csv.img}"
REMOTE_KERNEL_SRC="${REMOTE_KERNEL_SRC:-/opt/kata/share/kata-containers/vmlinuz-confidential-csv.container}"
REMOTE_OVMF_SRC="${REMOTE_OVMF_SRC:-/opt/kata/share/ovmf/OVMFCSV.fd}"
REMOTE_KATA_CONFIG_SRC="${REMOTE_KATA_CONFIG_SRC:-/opt/kata/share/defaults/kata-containers/configuration-qemu-csv2.toml}"
REMOTE_KATA_CONFIG="${REMOTE_KATA_CONFIG:-/etc/kata-containers/configuration-qemu-csv2-taa.toml}"
KATA_HYPERVISOR_SECTION="${KATA_HYPERVISOR_SECTION:-hypervisor.qemu}"
RUNTIME_HANDLER="${RUNTIME_HANDLER:-kata-qemu-csv2-taa}"
RUNTIME_TYPE="${RUNTIME_TYPE:-io.containerd.kata-qemu-csv2.v2}"
RUNTIME_PATH="${RUNTIME_PATH:-/opt/kata/bin/containerd-shim-kata-v2}"
SNAPSHOTTER="${SNAPSHOTTER:-nydus}"
RESTART_KUBELET="${RESTART_KUBELET:-0}"
TEST_NODE_NAME="${TEST_NODE_NAME:-}"
TEST_POD_NAME="${TEST_POD_NAME:-test-kata-csv2-taa}"
TEST_IMAGE="${TEST_IMAGE:-busybox:latest}"
SKIP_REMOTE_BASE_CHECK="${SKIP_REMOTE_BASE_CHECK:-0}"

# 打印支持的子命令和主要环境变量覆盖项。脚本默认执行 build，
# 因此本地反复调试是安全的；只有显式指定 deploy、launch 或 all 时才会触碰远程服务器。
usage() {
  cat <<EOF
Usage: $0 [build|deploy|launch|all]

Commands:
  build   Build $INITRD_OUT from $BASE_INITRD and inject TAA + init wrapper.
  deploy  Upload the built initrd to $REMOTE and install the remote Kata guest bundle.
  launch  Configure Kata/containerd RuntimeClass on $REMOTE and create a test Pod.
  all     Run build, deploy, then launch.

Environment overrides:
  ATTESTATION_HELPER_SRC=$ATTESTATION_HELPER_SRC
  REMOTE_USER=$REMOTE_USER
  REMOTE_HOST=$REMOTE_HOST
  REMOTE_BUNDLE_DIR=$REMOTE_BUNDLE_DIR
  REMOTE_BASE_INITRD_SRC=$REMOTE_BASE_INITRD_SRC
  REMOTE_KERNEL_SRC=$REMOTE_KERNEL_SRC
  REMOTE_OVMF_SRC=$REMOTE_OVMF_SRC
  REMOTE_KATA_CONFIG_SRC=$REMOTE_KATA_CONFIG_SRC
  REMOTE_KATA_CONFIG=$REMOTE_KATA_CONFIG
  KATA_HYPERVISOR_SECTION=$KATA_HYPERVISOR_SECTION
  RUNTIME_HANDLER=$RUNTIME_HANDLER
  RUNTIME_TYPE=$RUNTIME_TYPE
  RUNTIME_PATH=$RUNTIME_PATH
  SNAPSHOTTER=$SNAPSHOTTER
  RESTART_KUBELET=$RESTART_KUBELET
  TEST_NODE_NAME=$TEST_NODE_NAME
  TEST_POD_NAME=$TEST_POD_NAME
  TEST_IMAGE=$TEST_IMAGE
  TAA_ADDR=$TAA_ADDR
  TAA_PLATFORM_IP=$TAA_PLATFORM_IP
  TAA_DOCKER_ID=$TAA_DOCKER_ID
  TAA_REQUIRED=$TAA_REQUIRED
  ALLOW_MISSING_TAA_ENV=$ALLOW_MISSING_TAA_ENV
  SKIP_REMOTE_BASE_CHECK=$SKIP_REMOTE_BASE_CHECK

Note: TAA starts only when PLATFORM_IP and DOCKER_ID are provided. Set
TAA_PLATFORM_IP and TAA_DOCKER_ID to generate /etc/default/taa.env in initrd.
EOF
}

# 必要命令缺失时尽早失败，并输出清晰错误信息。
# 本地依赖检查和远程主机依赖检查都会使用这个函数。
require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: $1 is not installed or not in PATH" >&2
    exit 1
  fi
}

# gzip 压缩 initrd 的条目清单生成与匹配。
# archive_has_entry 处理单次存在性检查；archive_manifest 把归档展开成一次性的清单，后续可复用。
# manifest_has_entry 和 manifest_print_entry 只在清单上做精确匹配。
archive_has_entry() {
  local img="$1"
  local entry="$2"
  gzip -dc "$img" | cpio -t --quiet | grep -Fxq -- "$entry"
}

archive_manifest() {
  local img="$1"
  local manifest="$2"
  gzip -dc "$img" | cpio -t --quiet > "$manifest"
}

manifest_has_entry() {
  local manifest="$1"
  local entry="$2"
  grep -Fxq -- "$entry" "$manifest"
}

manifest_print_entry() {
  local manifest="$1"
  local entry="$2"
  grep -Fx -- "$entry" "$manifest"
}

# 创建临时状态前先校验所有本地构建输入。TAA 需要 PLATFORM_IP 和 DOCKER_ID
# 成对出现：只给其中一个会导致注册 USERDATA 与平台通知上下文不一致，
# 因此脚本会拒绝这种不完整配置。
check_build_inputs() {
  if [[ ! -x "$TAA_SRC" ]]; then
    echo "error: missing executable TAA binary: $TAA_SRC" >&2
    echo "hint: run 'make taa' from the repository root first" >&2
    exit 1
  fi

  if [[ ! -x "$ATTESTATION_HELPER_SRC" ]]; then
    echo "error: missing executable attestation helper: $ATTESTATION_HELPER_SRC" >&2
    echo "hint: run 'make attestation-ioctl' from the repository root first" >&2
    exit 1
  fi

  if [[ ! -f "$BASE_INITRD" ]]; then
    echo "error: missing base Kata CSV initrd: $BASE_INITRD" >&2
    echo "hint: place kata-containers-initrd-confidential-csv.img under guest-build/base/" >&2
    exit 1
  fi

  if { [[ -n "$TAA_PLATFORM_IP" ]] && [[ -z "$TAA_DOCKER_ID" ]]; } || { [[ -z "$TAA_PLATFORM_IP" ]] && [[ -n "$TAA_DOCKER_ID" ]]; }; then
    echo "error: TAA_PLATFORM_IP and TAA_DOCKER_ID must be set together" >&2
    exit 1
  fi
}

# 远程部署前检查输出镜像是否包含 TAA 所需的注册环境。
check_deploy_inputs() {
  if [[ "$ALLOW_MISSING_TAA_ENV" != "1" ]] && ! archive_has_entry "$INITRD_OUT" "etc/default/taa.env"; then
    echo "error: built initrd does not contain etc/default/taa.env" >&2
    echo "hint: rebuild with TAA_PLATFORM_IP=<ip:port> TAA_DOCKER_ID=<id> $0 build" >&2
    echo "hint: set ALLOW_MISSING_TAA_ENV=1 only if another early-boot path supplies these env vars" >&2
    exit 1
  fi
}

# 检查输入并构建 initrd。该函数不会修改 BASE_INITRD；它会把 base gzip 流复制为
# 临时 cpio 文件，追加 TAA payload 文件，校验候选归档，然后才移动到 INITRD_OUT。
build_initrd() {
  echo "校验输入"
  check_build_inputs
  require_cmd gzip
  require_cmd cpio
  require_cmd install
  require_cmd grep

  echo "准备临时目录"

  # 所有中间文件都放在唯一临时目录中。这里故意使用 EXIT 清理：
  # 即使构建中途校验失败，也会删除临时文件。
  BUILD_WORK_DIR="$(mktemp -d /tmp/taa-initrd-build.XXXXXX)"
  cleanup_build() {
    rm -rf "${BUILD_WORK_DIR:-}"
  }
  trap cleanup_build EXIT

  base_manifest="$BUILD_WORK_DIR/base.manifest"
  archive_manifest "$BASE_INITRD" "$base_manifest"

  echo "拒绝重复注入的 base"

  # 拒绝把已经注入过的镜像当作 base。重复执行具备幂等性，
  # 因为每次都从 BASE_INITRD 开始并覆盖 INITRD_OUT；这个保护用于防止误把
  # 已注入输出文件当作新的 base。
  if manifest_has_entry "$base_manifest" "usr/local/bin/taa" || manifest_has_entry "$base_manifest" "usr/local/bin/taa-init" || manifest_has_entry "$base_manifest" "attestation/get-attestation"; then
    echo "error: base initrd already contains TAA payload paths; refusing to append a duplicate" >&2
    echo "hint: use the original remote Kata CSV initrd as $BASE_INITRD" >&2
    exit 1
  fi

  mkdir -p "$OUT_DIR" "$BUILD_WORK_DIR/extra/usr/local/bin" "$BUILD_WORK_DIR/extra/attestation"

  echo "解包 base initrd"

  # 将压缩的 base initrd 转成原始 cpio 文件，并向该归档追加额外条目。
  # 不解包已有条目，因此原始 Kata 内容、文件元数据、符号链接和设备节点都会保留。
  # attestation/get-attestation 也必须注入，因为 TAA 启动时会固定调用该 helper。
  gzip -dc "$BASE_INITRD" > "$BUILD_WORK_DIR/base.cpio"

  echo "注入 TAA 和 attestation helper"
  install -m 0755 "$TAA_SRC" "$BUILD_WORK_DIR/extra/usr/local/bin/taa"
  install -m 0755 "$ATTESTATION_HELPER_SRC" "$BUILD_WORK_DIR/extra/attestation/get-attestation"

  echo "写入 init wrapper"

  # Kata confidential initrd 使用 kata-agent 作为 init（usr/sbin/init），不是 systemd。
  # 在这个镜像里放 systemd unit 不会被执行。因此 launch 步骤会追加内核参数
  # `init=/usr/local/bin/taa-init`；该 wrapper 在必要环境变量存在时后台启动 TAA，
  # 然后 exec 原始 /sbin/init（它是指向 usr/sbin/init 的符号链接），让 Kata 正常继续启动。
  cat > "$BUILD_WORK_DIR/extra/usr/local/bin/taa-init" <<EOF
#!/bin/sh
set -eu

if [ -f /etc/default/taa.env ]; then
  . /etc/default/taa.env
fi

cd /
TAA_ADDR="\${TAA_ADDR:-$TAA_ADDR}"
TAA_REQUIRED="\${TAA_REQUIRED:-$TAA_REQUIRED}"

fail_taa_required() {
  echo "taa-init: \$1" >/dev/console
  if [ "\$TAA_REQUIRED" = "1" ]; then
    echo "taa-init: TAA_REQUIRED=1; not starting kata-agent" >/dev/console
    while true; do sleep 3600; done
  fi
}

if [ -n "\${PLATFORM_IP:-}" ] && [ -n "\${DOCKER_ID:-}" ]; then
  /usr/local/bin/taa -addr "\$TAA_ADDR" >/tmp/taa.log 2>&1 &
  TAA_PID="\$!"
  sleep 2
  if ! kill -0 "\$TAA_PID" >/dev/null 2>&1; then
    if [ -f /tmp/taa.log ]; then
      cat /tmp/taa.log >/dev/console 2>&1 || true
    fi
    fail_taa_required "TAA exited immediately; see console log above"
  fi
else
  fail_taa_required "PLATFORM_IP or DOCKER_ID missing; skipping TAA start"
fi

exec /sbin/init "\$@"
EOF
  chmod 0755 "$BUILD_WORK_DIR/extra/usr/local/bin/taa-init"

  echo "生成可选 env 文件"

  # 可选环境文件，用于让 initrd 自身提供 TAA 注册目标。
  # 使用 %q 做 shell 转义，避免 taa-init source 该文件时空格或特殊字符被重新解释。
  if taa_env_file_needed; then
    mkdir -p "$BUILD_WORK_DIR/extra/etc/default"
    {
      printf 'export TAA_ADDR=%q\n' "$TAA_ADDR"
      printf 'export PLATFORM_IP=%q\n' "$TAA_PLATFORM_IP"
      printf 'export DOCKER_ID=%q\n' "$TAA_DOCKER_ID"
      printf 'export TAA_REQUIRED=%q\n' "$TAA_REQUIRED"
    } > "$BUILD_WORK_DIR/extra/etc/default/taa.env"
  fi

  echo "追加到 cpio"

  # 只把新增文件追加到复制出的 base cpio。不要把 usr、usr/local、etc/default
  # 这类 base 中已经存在的父目录再次写入归档，否则内核解包追加段时可能用
  # 后出现的目录条目覆盖 base 目录的权限/属主/时间戳。这里显式列出需要追加的
  # 文件，以及 base 中不存在但 helper 路径必需的 attestation 目录。
  append_entries=(
    "attestation"
    "attestation/get-attestation"
    "usr/local/bin/taa"
    "usr/local/bin/taa-init"
  )
  append_missing_parent_dirs() {
    local manifest="$1"
    local path="$2"
    local dir
    local parents=()

    dir="$(dirname "$path")"
    while [[ "$dir" != "." && "$dir" != "/" ]]; do
      parents+=("$dir")
      dir="$(dirname "$dir")"
    done

    for ((i=${#parents[@]} - 1; i >= 0; i--)); do
      if ! manifest_has_entry "$manifest" "${parents[$i]}"; then
        append_entries+=("${parents[$i]}")
      fi
    done
  }
  if taa_env_file_needed; then
    append_missing_parent_dirs "$base_manifest" "etc/default/taa.env"
    append_entries+=("etc/default/taa.env")
  fi
  (
    cd "$BUILD_WORK_DIR/extra"
    printf '%s\n' "${append_entries[@]}" | cpio -o -H newc -R 0:0 -A -F "$BUILD_WORK_DIR/base.cpio" --quiet
  )

  echo "重新压缩并校验"

  # 使用 gzip -n，避免把本地时间戳/文件名写入 gzip 头。
  # 候选文件会先通过校验再发布到 INITRD_OUT，因此失败构建不会覆盖之前可用的输出。
  candidate_manifest="$BUILD_WORK_DIR/initrd.candidate.manifest"
  gzip -n -9 < "$BUILD_WORK_DIR/base.cpio" > "$BUILD_WORK_DIR/initrd.candidate"
  archive_manifest "$BUILD_WORK_DIR/initrd.candidate" "$candidate_manifest"

  for entry in usr/local/bin/taa usr/local/bin/taa-init attestation/get-attestation; do
    if ! manifest_has_entry "$candidate_manifest" "$entry"; then
      echo "error: built initrd is missing $entry" >&2
      exit 1
    fi
  done
  if taa_env_file_needed; then
    if ! manifest_has_entry "$candidate_manifest" "etc/default/taa.env"; then
      echo "error: built initrd is missing etc/default/taa.env" >&2
      exit 1
    fi
  fi

  mv "$BUILD_WORK_DIR/initrd.candidate" "$INITRD_OUT"

  echo "输出结果摘要"

  base_count="$(wc -l < "$base_manifest")"
  out_count="$(wc -l < "$candidate_manifest")"

  echo "base initrd: $BASE_INITRD"
  echo "output initrd: $INITRD_OUT"
  echo "base cpio entries: $base_count"
  echo "output cpio entries: $out_count"
  echo "usr/local/bin/taa"
  manifest_print_entry "$candidate_manifest" "usr/local/bin/taa"
  echo "usr/local/bin/taa-init"
  manifest_print_entry "$candidate_manifest" "usr/local/bin/taa-init"
  echo "attestation/get-attestation"
  manifest_print_entry "$candidate_manifest" "attestation/get-attestation"
  if taa_env_file_needed; then
    echo "etc/default/taa.env"
    manifest_print_entry "$candidate_manifest" "etc/default/taa.env"
  fi
}

# 远程部署。把构建好的 initrd 上传到远程海光 CSV 主机，并安装完整 Kata guest bundle。
# 远程 bundle 包含注入后的 initrd，以及 launch 时 Kata 会引用的 kernel 和 OVMF 固件副本。
deploy_remote() {
  echo "校验输出 initrd"
  if [[ ! -f "$INITRD_OUT" ]]; then
    echo "error: missing built initrd: $INITRD_OUT" >&2
    echo "hint: run '$0 build' first" >&2
    exit 1
  fi
  check_deploy_inputs

  require_cmd scp
  require_cmd ssh
  require_cmd sha256sum
  require_cmd awk

  echo "准备远程临时目录与校验和"

  # 先上传到远程临时目录，再校验 SHA-256 后安装。
  # 这样可以避免不完整上传或 scp 损坏的文件成为 Kata 实际使用的 initrd。
  remote_tmp_dir="$(ssh "$REMOTE" 'mktemp -d /tmp/taa-initrd-deploy.XXXXXX')"
  remote_tmp_dir="${remote_tmp_dir//$'\r'/}"
  remote_tmp_dir="${remote_tmp_dir//$'\n'/}"
  remote_tmp_initrd="$remote_tmp_dir/initramfs.img"
  local_initrd_sha="$(sha256sum "$INITRD_OUT" | awk '{print $1}')"
  local_base_initrd_sha="$(sha256sum "$BASE_INITRD" | awk '{print $1}')"

  echo "上传 initrd to $REMOTE:$remote_tmp_initrd"
  scp "$INITRD_OUT" "$REMOTE:$remote_tmp_initrd"

  echo "安装远程 guest bundle under $REMOTE_BUNDLE_DIR"
  # 为传给远程 shell 的每个参数做转义，避免本地变量在 heredoc 中提前展开。
  remote_args="$(printf '%q ' "$remote_tmp_dir" "$local_initrd_sha" "$local_base_initrd_sha" "$REMOTE_BUNDLE_DIR" "$REMOTE_BASE_INITRD_SRC" "$REMOTE_KERNEL_SRC" "$REMOTE_OVMF_SRC" "$SKIP_REMOTE_BASE_CHECK")"
  ssh "$REMOTE" "bash -s -- $remote_args" <<'REMOTE_DEPLOY'
set -euo pipefail
remote_tmp_dir="$1"
local_initrd_sha="$2"
local_base_initrd_sha="$3"
bundle_dir="$4"
remote_base_initrd_src="$5"
kernel_src="$6"
ovmf_src="$7"
skip_remote_base_check="$8"
remote_initrd="$remote_tmp_dir/initramfs.img"

cleanup_remote() {
  rm -rf "$remote_tmp_dir"
}
trap cleanup_remote EXIT

# 上传后故意在远程侧再次校验。kernel/firmware 路径缺失时，
# 应该在修改任何 containerd/Kata 配置前失败。
echo "校验远程依赖和路径"

for cmd in sudo sha256sum awk; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "error: $cmd is not installed or not in PATH" >&2
    exit 1
  fi
done

echo "校验上传的 initrd、kernel 和 OVMF"

if [[ ! -f "$remote_initrd" ]]; then
  echo "error: uploaded initrd not found: $remote_initrd" >&2
  exit 1
fi
if [[ ! -e "$kernel_src" ]]; then
  echo "error: kernel source not found: $kernel_src" >&2
  exit 1
fi
if [[ ! -e "$ovmf_src" ]]; then
  echo "error: OVMF source not found: $ovmf_src" >&2
  exit 1
fi
if [[ "$skip_remote_base_check" != "1" ]]; then
  if [[ ! -f "$remote_base_initrd_src" ]]; then
    echo "error: remote base initrd not found: $remote_base_initrd_src" >&2
    exit 1
  fi
  remote_base_sha="$(sha256sum "$remote_base_initrd_src" | awk '{print $1}')"
  if [[ "$remote_base_sha" != "$local_base_initrd_sha" ]]; then
    echo "error: local BASE_INITRD does not match remote base initrd" >&2
    echo "local:  $local_base_initrd_sha  $remote_base_initrd_src expected source" >&2
    echo "remote: $remote_base_sha  $remote_base_initrd_src" >&2
    echo "hint: refresh guest-build/base/ from the remote base initrd, or set SKIP_REMOTE_BASE_CHECK=1 if this mismatch is intentional" >&2
    exit 1
  fi
fi

printf '%s  %s\n' "$local_initrd_sha" "$remote_initrd" | sha256sum -c -

sudo mkdir -p "$bundle_dir"
sudo install -o root -g root -m 0644 "$remote_initrd" "$bundle_dir/initramfs.img"
sudo cp -aL "$kernel_src" "$bundle_dir/vmlinuz"
sudo cp -aL "$ovmf_src" "$bundle_dir/OVMF.fd"

ls -lh "$bundle_dir"
REMOTE_DEPLOY
}

# 修改配置、启动测试、等待结果，并在最后做主机级校验。
# 这里创建独立 RuntimeClass，而不是覆盖已有 kata-qemu-csv2 handler；
# 回滚时只需继续使用旧 RuntimeClass，或从 containerd 配置中移除新增 handler。
launch_remote() {
  echo "校验依赖与输入"
  require_cmd ssh

  echo "生成 Kata 配置并写入 $REMOTE"
  remote_args="$(printf '%q ' "$REMOTE_BUNDLE_DIR" "$REMOTE_KATA_CONFIG_SRC" "$REMOTE_KATA_CONFIG" "$KATA_HYPERVISOR_SECTION" "$RUNTIME_HANDLER" "$RUNTIME_TYPE" "$RUNTIME_PATH" "$SNAPSHOTTER" "$RESTART_KUBELET" "$TEST_NODE_NAME" "$TEST_POD_NAME" "$TEST_IMAGE")"
  ssh "$REMOTE" "bash -s -- $remote_args" <<'REMOTE_LAUNCH'
set -euo pipefail
bundle_dir="$1"
kata_config_src="$2"
kata_config="$3"
kata_hypervisor_section="$4"
runtime_handler="$5"
runtime_type="$6"
runtime_path="$7"
snapshotter="$8"
restart_kubelet="$9"
test_node_name="${10}"
test_pod_name="${11}"
test_image="${12}"
containerd_config="/etc/containerd/config.toml"

# 修改 Kata 或 containerd 配置前，先校验主机依赖和 bundle 路径。
# containerd 配置要求是 TOML version 2，与远程 CSV 服务器上观察到的配置格式一致。
for cmd in kubectl sudo grep ps python3 containerd hostname; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "error: $cmd is not installed or not in PATH" >&2
    exit 1
  fi
done

k8s_name_re='^[a-z0-9]([-a-z0-9]*[a-z0-9])?$'
if [[ ! "$runtime_handler" =~ $k8s_name_re ]]; then
  echo "error: RUNTIME_HANDLER must be a Kubernetes DNS label: $runtime_handler" >&2
  exit 1
fi
if [[ ! "$test_pod_name" =~ $k8s_name_re ]]; then
  echo "error: TEST_POD_NAME must be a Kubernetes DNS label: $test_pod_name" >&2
  exit 1
fi
if [[ "$test_image" == *$'\n'* || "$test_image" == *$'\r'* ]]; then
  echo "error: TEST_IMAGE must not contain newlines" >&2
  exit 1
fi

if [[ ! -f "$bundle_dir/initramfs.img" ]]; then
  echo "error: remote initrd not found: $bundle_dir/initramfs.img" >&2
  echo "hint: run deploy first" >&2
  exit 1
fi
if [[ ! -f "$bundle_dir/vmlinuz" ]]; then
  echo "error: remote kernel not found: $bundle_dir/vmlinuz" >&2
  echo "hint: run deploy first" >&2
  exit 1
fi
if [[ ! -f "$bundle_dir/OVMF.fd" ]]; then
  echo "error: remote OVMF not found: $bundle_dir/OVMF.fd" >&2
  echo "hint: run deploy first" >&2
  exit 1
fi
if [[ ! -f "$kata_config_src" ]]; then
  echo "error: source Kata config not found: $kata_config_src" >&2
  exit 1
fi
if [[ ! -f "$containerd_config" ]]; then
  echo "error: containerd config not found: $containerd_config" >&2
  exit 1
fi
if ! grep -qE '^[[:space:]]*version[[:space:]]*=[[:space:]]*2([[:space:]]|$)' "$containerd_config"; then
  echo "error: unsupported containerd config format in $containerd_config" >&2
  exit 1
fi

if [[ -z "$test_node_name" ]]; then
  for candidate in "$(hostname)" "$(hostname -s)"; do
    if kubectl get node "$candidate" >/dev/null 2>&1; then
      test_node_name="$candidate"
      break
    fi
  done
fi
if [[ -z "$test_node_name" ]]; then
  echo "error: could not determine Kubernetes node name for this remote host" >&2
  echo "hint: set TEST_NODE_NAME to the node name shown by 'kubectl get nodes'" >&2
  exit 1
fi
if ! kubectl get node "$test_node_name" >/dev/null 2>&1; then
  echo "error: TEST_NODE_NAME does not exist in Kubernetes: $test_node_name" >&2
  exit 1
fi

tmp_kata_config="$(mktemp /tmp/kata-config.XXXXXX.toml)"
tmp_containerd_config="$(mktemp /tmp/containerd-config.XXXXXX.toml)"
containerd_backup=""
cleanup_launch() {
  rm -f "$tmp_kata_config" "$tmp_containerd_config"
  if [[ -n "$containerd_backup" ]]; then
    sudo rm -f "$containerd_backup" || true
  fi
}
trap cleanup_launch EXIT

# 只改目标 hypervisor 表：切到 bundle、注释掉 image，并设置 init=/usr/local/bin/taa-init。
echo "生成 Kata 配置"
cp "$kata_config_src" "$tmp_kata_config"
python3 - "$tmp_kata_config" "$bundle_dir" "$kata_hypervisor_section" <<'PY'
import json
import re
import shlex
import sys
from pathlib import Path

path = Path(sys.argv[1])
bundle_dir = sys.argv[2]
target_section = sys.argv[3]
lines = path.read_text().splitlines()
out = []
seen = {"kernel": False, "initrd": False, "firmware": False, "kernel_params": False}
in_target = False
target_seen = False

def toml_string(value):
    return json.dumps(value)

def active_key(line, key):
    stripped = line.lstrip()
    return not stripped.startswith("#") and re.match(rf'^\s*{re.escape(key)}\s*=', line)

def table_name(line):
    stripped = line.strip()
    if stripped.startswith("[["):
        return None
    if stripped.startswith("[") and stripped.endswith("]"):
        return stripped[1:-1].strip()
    return None

def emit_missing():
    if not seen["kernel"]:
        out.append(f'kernel = {toml_string(bundle_dir + "/vmlinuz")}')
        seen["kernel"] = True
    if not seen["initrd"]:
        out.append(f'initrd = {toml_string(bundle_dir + "/initramfs.img")}')
        seen["initrd"] = True
    if not seen["firmware"]:
        out.append(f'firmware = {toml_string(bundle_dir + "/OVMF.fd")}')
        seen["firmware"] = True
    if not seen["kernel_params"]:
        out.append('kernel_params = "init=/usr/local/bin/taa-init"')
        seen["kernel_params"] = True

for line in lines:
    table = table_name(line)
    if table is not None:
        if in_target:
            emit_missing()
        in_target = table == target_section
        if in_target:
            target_seen = True
        out.append(line)
        continue

    if not in_target:
        out.append(line)
        continue

    if active_key(line, "image"):
        out.append("# " + line)
        continue
    if active_key(line, "kernel"):
        out.append(f'kernel = {toml_string(bundle_dir + "/vmlinuz")}')
        seen["kernel"] = True
        continue
    if active_key(line, "initrd"):
        out.append(f'initrd = {toml_string(bundle_dir + "/initramfs.img")}')
        seen["initrd"] = True
        continue
    if active_key(line, "firmware"):
        out.append(f'firmware = {toml_string(bundle_dir + "/OVMF.fd")}')
        seen["firmware"] = True
        continue
    if active_key(line, "kernel_params"):
        m = re.match(r'^\s*kernel_params\s*=\s*"([^"]*)"', line)
        if not m:
            raise SystemExit(f"unrecognized kernel_params line: {line}")
        existing = m.group(1).strip()
        params = shlex.split(existing) if existing else []
        params = [p for p in params if not p.startswith("init=")]
        params.insert(0, "init=/usr/local/bin/taa-init")
        out.append(f'kernel_params = {toml_string(" ".join(params))}')
        seen["kernel_params"] = True
        continue
    out.append(line)

if in_target:
    emit_missing()
if not target_seen:
    if out and out[-1].strip():
        out.append("")
    out.append(f'[{target_section}]')
    emit_missing()

path.write_text("\n".join(out) + "\n")
PY
sudo mkdir -p "${kata_config%/*}"
sudo install -o root -g root -m 0644 "$tmp_kata_config" "$kata_config"

# 幂等地新增或替换 containerd runtime handler 配置块。
echo "生成 containerd 配置"
cp "$containerd_config" "$tmp_containerd_config"
python3 - "$tmp_containerd_config" "$kata_config" "$runtime_handler" "$runtime_type" "$runtime_path" "$snapshotter" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
kata_config = sys.argv[2]
runtime_handler = sys.argv[3]
runtime_type = sys.argv[4]
runtime_path = sys.argv[5]
snapshotter = sys.argv[6]

lines = path.read_text().splitlines()
out = []
target = ["plugins", "io.containerd.grpc.v1.cri", "containerd", "runtimes", runtime_handler]

def toml_string(value):
    return json.dumps(value)


def split_table_path(src):
    parts = []
    buf = []
    in_quote = False
    escape = False
    for ch in src:
        if in_quote:
            if escape:
                buf.append(ch)
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_quote = False
            else:
                buf.append(ch)
        else:
            if ch == '"':
                in_quote = True
            elif ch == ".":
                parts.append("".join(buf).strip())
                buf = []
            else:
                buf.append(ch)
    parts.append("".join(buf).strip())
    return parts

def table_path(line):
    stripped = line.strip()
    if stripped.startswith("[["):
        return None
    if stripped.startswith("[") and stripped.endswith("]"):
        return split_table_path(stripped[1:-1].strip())
    return None

def is_target_or_child(path_parts):
    return path_parts is not None and len(path_parts) >= len(target) and path_parts[:len(target)] == target

skip = False
for line in lines:
    path_parts = table_path(line)
    if path_parts is not None:
        skip = is_target_or_child(path_parts)
        if skip:
            continue
    if not skip:
        out.append(line)

handler = f'[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.{toml_string(runtime_handler)}]'
options = f'[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.{toml_string(runtime_handler)}.options]'
if out and out[-1].strip():
    out.append("")
out.extend([
    handler,
    f'runtime_type = {toml_string(runtime_type)}',
])
if runtime_path:
    out.append(f'runtime_path = {toml_string(runtime_path)}')
out.extend([
    'privileged_without_host_devices = true',
    'pod_annotations = ["io.katacontainers.*"]',
])
if snapshotter:
    out.append(f'snapshotter = {toml_string(snapshotter)}')
out.extend([
    "",
    options,
    f'ConfigPath = {toml_string(kata_config)}',
])

path.write_text("\n".join(out) + "\n")
PY

# 重启服务前校验两处配置改写结果。
echo "Kata guest assets in $kata_config:"
grep -nE '^[[:space:]]*(kernel|initrd|firmware|kernel_params)[[:space:]]*=' "$kata_config"
python3 - "$kata_config" "$kata_hypervisor_section" <<'PY'
import re
import sys
from pathlib import Path
path = Path(sys.argv[1])
target = sys.argv[2]
section = None
values = {}
for line in path.read_text().splitlines():
    stripped = line.strip()
    if stripped.startswith("[") and stripped.endswith("]") and not stripped.startswith("[["):
        section = stripped[1:-1].strip()
        continue
    if section != target or stripped.startswith("#"):
        continue
    m = re.match(r'^(image|kernel|initrd|firmware|kernel_params)\s*=\s*(.*)$', stripped)
    if m:
        values[m.group(1)] = m.group(2)
if "image" in values:
    raise SystemExit("active image setting remains in target Kata hypervisor section")
for key in ("kernel", "initrd", "firmware", "kernel_params"):
    if key not in values:
        raise SystemExit(f"missing active {key} in target Kata hypervisor section")
if "init=/usr/local/bin/taa-init" not in values["kernel_params"]:
    raise SystemExit("kernel_params does not contain init=/usr/local/bin/taa-init")
PY

handler_header="[plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.\"$runtime_handler\"]"
handler_options="[plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.\"$runtime_handler\".options]"
if ! grep -qF "$handler_header" "$tmp_containerd_config"; then
  echo "error: containerd runtime handler was not written: $runtime_handler" >&2
  exit 1
fi
if ! grep -qF "ConfigPath = \"$kata_config\"" "$tmp_containerd_config"; then
  echo "error: containerd runtime handler ConfigPath was not updated: $kata_config" >&2
  exit 1
fi
if ! grep -qF "$handler_options" "$tmp_containerd_config"; then
  echo "error: containerd runtime handler options block missing: $runtime_handler" >&2
  exit 1
fi
if ! sudo containerd --config "$tmp_containerd_config" config dump >/dev/null; then
  echo "error: generated containerd config is invalid; original config was not changed" >&2
  exit 1
fi

rollback_containerd() {
  if [[ -n "$containerd_backup" && -f "$containerd_backup" ]]; then
    echo "rolling back containerd config from $containerd_backup" >&2
    sudo install -o root -g root -m 0644 "$containerd_backup" "$containerd_config"
    sudo systemctl restart containerd || true
  fi
}

echo "重启 containerd"

# 重启 containerd；只有需要时才重启 kubelet。
containerd_backup="$(mktemp /tmp/containerd-config.backup.XXXXXX.toml)"
sudo cp -a "$containerd_config" "$containerd_backup"
sudo install -o root -g root -m 0644 "$tmp_containerd_config" "$containerd_config"
if ! sudo systemctl restart containerd; then
  sudo journalctl -u containerd -n 50 --no-pager >&2 || true
  rollback_containerd
  echo "error: containerd restart failed; original config restored" >&2
  exit 1
fi
if ! sudo systemctl is-active --quiet containerd; then
  sudo journalctl -u containerd -n 50 --no-pager >&2 || true
  rollback_containerd
  echo "error: containerd is not active after restart; original config restored" >&2
  exit 1
fi
if [[ "$restart_kubelet" == "1" ]]; then
  echo "可选重启 kubelet"
  sudo systemctl restart kubelet
  if ! sudo systemctl is-active --quiet kubelet; then
    sudo journalctl -u kubelet -n 50 --no-pager >&2 || true
    echo "error: kubelet is not active after restart" >&2
    exit 1
  fi
fi
sudo rm -f "$containerd_backup"
containerd_backup=""

echo "创建 RuntimeClass"

# 创建 RuntimeClass。Pod 会固定调度到当前远程节点。
python3 - "$runtime_handler" <<'PY' | kubectl apply -f -
import json
import sys
handler = sys.argv[1]
print(json.dumps({
    "apiVersion": "node.k8s.io/v1",
    "kind": "RuntimeClass",
    "metadata": {"name": handler},
    "handler": handler,
}))
PY

echo "创建测试 Pod"

kubectl delete pod "$test_pod_name" --ignore-not-found --wait=true
python3 - "$runtime_handler" "$test_pod_name" "$test_node_name" "$test_image" <<'PY' | kubectl apply -f -
import json
import sys
handler, pod_name, node_name, image = sys.argv[1:]
print(json.dumps({
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name": pod_name},
    "spec": {
        "runtimeClassName": handler,
        "nodeName": node_name,
        "restartPolicy": "Never",
        "containers": [{
            "name": "test",
            "image": image,
            "command": ["sh", "-c", "echo hello from kata csv2 taa guest; sleep 3600"],
        }],
    },
}))
PY

echo "等待测试 Pod Ready"

kubectl wait --for=condition=Ready "pod/$test_pod_name" --timeout=180s
kubectl get pod "$test_pod_name" -o wide

# 最后的主机级校验：Pod Ready 只能证明 Kubernetes 接受了 RuntimeClass。
if ps -eo args= | grep -F "qemu" | grep -F "$bundle_dir/initramfs.img" | grep -v grep >/dev/null; then
  echo "verified QEMU is using: $bundle_dir/initramfs.img"
else
  echo "error: test Pod is ready, but QEMU command line with $bundle_dir/initramfs.img was not found on node $test_node_name" >&2
  echo "hint: run: ps -eo args= | grep -F qemu | grep -F '$bundle_dir'" >&2
  exit 1
fi
REMOTE_LAUNCH
}

# 命令分发。默认保持为 build，避免无参数运行脚本时意外写入远程服务器。
cmd="${1:-build}"
case "$cmd" in
  build)
    build_initrd
    ;;
  deploy)
    deploy_remote
    ;;
  launch)
    launch_remote
    ;;
  all)
    build_initrd
    deploy_remote
    launch_remote
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    echo "error: unknown command: $cmd" >&2
    usage >&2
    exit 1
    ;;
esac
