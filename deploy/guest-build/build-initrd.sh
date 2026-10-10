#!/usr/bin/env bash
# 构建并可选部署一个包含本仓库 TAA 二进制文件的 Kata CSV initrd。
# 这里的关键设计是：把原始 Kata initrd 解压成 cpio 归档后保持原有内容不动，
# 只向归档末尾追加少量新文件。不要完整解包再重新打包 base initrd，
# 因为其中包含设备节点；普通用户解包设备节点可能失败，并导致 /dev/console
# 等原始条目被静默丢失。
#
# Two traps, both promoted to hard build-time checks:
#   1. The base initrd must be the real one from the host. The copy that lived in
#      this repo was silently truncated (incomplete gzip stream, `cpio -t` stopped
#      at 265 entries without reporting an error). `check_build_inputs` therefore
#      enforces `gzip -t` and refuses it; use `fetch-base` to pull the real one.
#      For the same reason the historical out/kata-containers-initrd-taa-csv.initrd
#      had a git blob identical to the base: it was a copy, not a build product.
#   2. The injected TAA must be statically linked. The base initrd has no glibc, so
#      a dynamically linked binary cannot start. bin/taa used to be dynamic, which
#      disagreed with the CGO_ENABLED=0 used by the production image.
set -euo pipefail

# 流程：先 build，再按需 deploy 和 launch，最后校验 Ready 和 QEMU initrd。

# 按脚本所在目录解析路径，这样从任意工作目录执行脚本都能得到一致结果。
# SCRIPT_DIR 是 deploy/guest-build，ROOT_DIR 是仓库根（再上两级）。
#
# 这里曾经写的是 $SCRIPT_DIR/.. ——那时 guest-build/ 就在仓库根下，恰好对；
# 它搬到 deploy/ 之后，ROOT_DIR 变成 deploy/，于是 TAA_SRC、配置与证书的默认值
# 全部指向不存在的路径（表现为"缺 build input"，而不是"路径写错了"）。
# 因此下面加一条断言：解析不出仓库根就当场报错，不再静默用错误默认值。
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
if [[ ! -f "$ROOT_DIR/go.mod" ]]; then
  echo "error: repository root not found from $SCRIPT_DIR (no go.mod in $ROOT_DIR)" >&2
  echo "hint: override TAA_SRC / TAA_CONFIG_SRC / TAA_HRK_CERT_SRC / TAA_HSK_CEK_CERT_SRC explicitly" >&2
  exit 1
fi

# Local build inputs and outputs. TAA implements remote attestation natively in
# Go, so no external helper is injected.
# BASE_INITRD must be the original remote Kata CSV initrd, never an
# already-injected output file: appending twice would produce duplicate payload
# paths and change the boot measurement in an uncontrolled way.
#
# These paths are all environment-overridable: it makes it easy to point at a
# real archive kept elsewhere, and it lets the whole build path run end to end
# locally against a small synthetic archive, so the build-time self-checks are
# themselves testable.
TAA_SRC="${TAA_SRC:-$ROOT_DIR/bin/taa}"
TAA_INIT_SRC="${TAA_INIT_SRC:-$SCRIPT_DIR/taa-init.sh}"
TAA_CONFIG_SRC="${TAA_CONFIG_SRC:-$ROOT_DIR/configs/taa-initrd.json}"
TAA_HRK_CERT_SRC="${TAA_HRK_CERT_SRC:-$ROOT_DIR/deploy/certs/hrk.cert}"
TAA_HSK_CEK_CERT_SRC="${TAA_HSK_CEK_CERT_SRC:-$ROOT_DIR/deploy/certs/hsk_cek.cert}"
BASE_INITRD="${BASE_INITRD:-$SCRIPT_DIR/base/kata-containers-initrd-confidential-csv.img}"
OUT_DIR="${OUT_DIR:-$SCRIPT_DIR/out}"
INITRD_OUT="${INITRD_OUT:-$OUT_DIR/kata-containers-initrd-taa-csv.initrd}"

# Runtime configuration written into the init wrapper. These defaults must stay
# in sync with the literal defaults in taa-init.sh: the wrapper is a standalone
# file now (no heredoc, which needed dozens of escaped variables), and build-time
# overrides reach it through /etc/default/taa.env.
# PLATFORM_IP and DOCKER_ID are optional at build time: they only affect
# registration with the management platform, and a failed registration is just a
# warning inside TAA. deploy/all still require the env file by default, because
# the production flow wants registration to succeed.
# With TAA_REQUIRED=1, a TAA that fails to start or fails attestation keeps
# kata-agent from starting, so the Pod stays NotReady.
TAA_ADDR_DEFAULT="0.0.0.0:6001"
TAA_REQUIRED_DEFAULT="1"
TAA_REQUIRE_ATTESTATION_DEFAULT="1"

TAA_ADDR="${TAA_ADDR:-$TAA_ADDR_DEFAULT}"
TAA_PLATFORM_IP="${TAA_PLATFORM_IP:-}"
TAA_DOCKER_ID="${TAA_DOCKER_ID:-}"
TAA_REQUIRED="${TAA_REQUIRED:-$TAA_REQUIRED_DEFAULT}"
# 1 = only release kata-agent once TAA has self-verified its report, which makes
# "the attestation is real" a precondition for the Pod reaching Ready.
TAA_REQUIRE_ATTESTATION="${TAA_REQUIRE_ATTESTATION:-$TAA_REQUIRE_ATTESTATION_DEFAULT}"
ALLOW_MISSING_TAA_ENV="${ALLOW_MISSING_TAA_ENV:-0}"

# The env file carries every runtime switch of the wrapper. It has to be written
# as soon as a registration identity is given, or any switch is explicitly moved
# off its default; otherwise a build-time override would silently do nothing.
taa_env_file_needed() {
  if [[ -n "$TAA_PLATFORM_IP" && -n "$TAA_DOCKER_ID" ]]; then
    return 0
  fi
  [[ "$TAA_ADDR" != "$TAA_ADDR_DEFAULT" ]] && return 0
  [[ "$TAA_REQUIRED" != "$TAA_REQUIRED_DEFAULT" ]] && return 0
  [[ "$TAA_REQUIRE_ATTESTATION" != "$TAA_REQUIRE_ATTESTATION_DEFAULT" ]] && return 0
  return 1
}

# 当前海光 CSV 测试主机的远程部署默认值。所有值都可通过环境变量覆盖，
# 因此同一个脚本可以用于其它服务器、其它 Kata 配置或其它 RuntimeClass 名称。
#
# REMOTE_USER 默认 root：脚本在远端全程用 sudo 改 kata/containerd 配置并重启服务，
# 用非 root 账号就必须额外配好免密 sudo，否则会在改配置的中途失败。登录用公钥，
# 不需要密码（该账号有 pam_faillock，密码认证失败几次就锁）。
REMOTE_USER="${REMOTE_USER:-root}"
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
# The image is pulled by CDH *inside* the guest, which has no route to Docker
# Hub -- measured on 2026-10-10: busybox:latest failed with "error sending
# request for url (https://index.docker.io/...)" after the 180s wait. So the
# default is an image from the registry on the host itself (the same one the
# CoCo Pods already running here pull successfully). It also has to carry curl,
# because `deploy-taa-vm.sh verify` probes TAA from inside the Pod and busybox
# does not ship it.
TEST_IMAGE="${TEST_IMAGE:-172.16.10.178:31313/taa-env:slim-v2-20260916}"
# A CoCo guest pulls the container image itself through CDH, and it trusts the
# registry only if the Pod carries the init-data that configures it (on this
# host cc_init_data embeds a cdh.toml with extra_root_certificates). Without it
# CDH fails the pull with a TLS error and the Pod lands in StartError -- which
# looks like an initrd failure but is not one. Copy the JSON annotations of a
# working Pod when the test image lives behind a private registry:
#   TEST_POD_ANNOTATIONS="$(kubectl get pod <working> -o jsonpath='{.metadata.annotations}')"
TEST_POD_ANNOTATIONS="${TEST_POD_ANNOTATIONS:-{\}}"
SKIP_REMOTE_BASE_CHECK="${SKIP_REMOTE_BASE_CHECK:-0}"

# 打印支持的子命令和主要环境变量覆盖项。脚本默认执行 build，
# 因此本地反复调试是安全的；只有显式指定 deploy、launch 或 all 时才会触碰远程服务器。
usage() {
  cat <<EOF
Usage: $0 [build|fetch-base|deploy|launch|all|print-config]

Commands:
  build       Build $INITRD_OUT from $BASE_INITRD and inject TAA + init wrapper.
  fetch-base  Copy the real base initrd, kernel and OVMF from $REMOTE into $(basename "$SCRIPT_DIR")/base/.
  deploy      Upload the built initrd to $REMOTE and install the remote Kata guest bundle.
  launch      Configure Kata/containerd RuntimeClass on $REMOTE and create a test Pod.
  all         Run build, deploy, then launch.
  print-config  Print the resolved remote/test settings as sourceable KEY=value
                lines. Internal interface for deploy-taa-vm.sh, so that the
                defaults above have exactly one definition.

Environment overrides:
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
  TEST_POD_ANNOTATIONS=$TEST_POD_ANNOTATIONS
  TAA_ADDR=$TAA_ADDR
  TAA_PLATFORM_IP=$TAA_PLATFORM_IP
  TAA_DOCKER_ID=$TAA_DOCKER_ID
  TAA_REQUIRED=$TAA_REQUIRED
  TAA_REQUIRE_ATTESTATION=$TAA_REQUIRE_ATTESTATION
  ALLOW_MISSING_TAA_ENV=$ALLOW_MISSING_TAA_ENV
  SKIP_REMOTE_BASE_CHECK=$SKIP_REMOTE_BASE_CHECK

Local input/output overrides (mainly for testing the build path against a
synthetic archive):
  BASE_INITRD=$BASE_INITRD
  INITRD_OUT=$INITRD_OUT
  TAA_SRC=$TAA_SRC
  TAA_INIT_SRC=$TAA_INIT_SRC
  TAA_CONFIG_SRC=$TAA_CONFIG_SRC

Notes:
  TAA starts whenever /etc/taa/taa-config.json is readable: the config is a hard
  dependency (TAA exits 1 without it). PLATFORM_IP and DOCKER_ID are optional and
  only affect platform registration, which is a warning inside TAA. Set both to
  have /etc/default/taa.env carry them.
  TAA_REQUIRE_ATTESTATION=1 makes the TAA attestation self-verification a
  precondition for starting kata-agent, so a Ready Pod implies a real report.
  The injected TAA must be statically linked; build it with
  CGO_ENABLED=0 GOOS=linux go build -o bin/taa ./cmd/taa
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
# manifest_has_entry 只在清单上做精确匹配。
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

# Validate every local build input before any temporary state is created.
# TAA needs PLATFORM_IP and DOCKER_ID to appear as a pair: supplying only one
# leaves the registration USERDATA inconsistent with the platform notify
# context, so the script refuses that incomplete configuration.
check_build_inputs() {
  if [[ ! -x "$TAA_SRC" ]]; then
    echo "error: missing executable TAA binary: $TAA_SRC" >&2
    echo "hint: build one from the repository root: CGO_ENABLED=0 go build -o bin/taa ./cmd/taa" >&2
    exit 1
  fi

  # The base initrd has no glibc, so a dynamically linked TAA cannot start. It
  # would not fail the build, only the boot -- long after the measurement has
  # been taken -- so it is asserted here instead.
  local taa_file_type
  taa_file_type="$(file -b "$TAA_SRC" 2>/dev/null || true)"
  if [[ "$taa_file_type" != *"statically linked"* ]]; then
    echo "error: TAA binary is not statically linked: $TAA_SRC" >&2
    echo "       file says: ${taa_file_type:-<file(1) produced no output>}" >&2
    echo "hint: rebuild with CGO_ENABLED=0 go build -o bin/taa ./cmd/taa" >&2
    exit 1
  fi

  if [[ ! -f "$BASE_INITRD" ]]; then
    echo "error: missing base Kata CSV initrd: $BASE_INITRD" >&2
    echo "hint: place kata-containers-initrd-confidential-csv.img under guest-build/base/, or run '$0 fetch-base'" >&2
    exit 1
  fi

  # A cpio append into a truncated gzip stream fails silently: the archive is
  # still readable up to the truncation point, so the build would succeed while
  # producing an initrd that lost its tail. Verify the stream first.
  if ! gzip -t "$BASE_INITRD" 2>/dev/null; then
    echo "error: base initrd is not a valid gzip stream (truncated?): $BASE_INITRD" >&2
    echo "hint: run '$0 fetch-base' to copy the real one from $REMOTE" >&2
    exit 1
  fi

  local input
  for input in "$TAA_INIT_SRC" "$TAA_CONFIG_SRC" "$TAA_HRK_CERT_SRC" "$TAA_HSK_CEK_CERT_SRC"; do
    if [[ ! -f "$input" ]]; then
      echo "error: missing build input: $input" >&2
      exit 1
    fi
  done

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
  require_cmd gzip
  require_cmd cpio
  require_cmd install
  require_cmd grep
  require_cmd file
  require_cmd sha256sum
  check_build_inputs

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
  for injected in usr/local/bin/taa usr/local/bin/taa-init etc/taa/taa-config.json; do
    if manifest_has_entry "$base_manifest" "$injected"; then
      echo "error: base initrd already contains TAA payload path $injected; refusing to append a duplicate" >&2
      echo "hint: use the original remote Kata CSV initrd as $BASE_INITRD" >&2
      exit 1
    fi
  done

  mkdir -p "$OUT_DIR" "$BUILD_WORK_DIR/extra/usr/local/bin"

  echo "解包 base initrd"

  # 将压缩的 base initrd 转成原始 cpio 文件，并向该归档追加额外条目。
  # 不解包已有条目，因此原始 Kata 内容、文件元数据、符号链接和设备节点都会保留。
  gzip -dc "$BASE_INITRD" > "$BUILD_WORK_DIR/base.cpio"

  echo "注入 TAA"
  install -m 0755 "$TAA_SRC" "$BUILD_WORK_DIR/extra/usr/local/bin/taa"

  echo "写入 init wrapper 与 TAA 配置"

  # The Kata confidential initrd uses kata-agent as its init (usr/sbin/init), not
  # systemd, so a systemd unit placed in this image would never run. The launch
  # step therefore passes `rdinit=/usr/local/bin/taa-init`: the kernel tries the
  # ramdisk init before init=, so rdinit= is what actually takes effect. The
  # wrapper starts TAA in the background, gates on its attestation verdict, then
  # execs the original /sbin/init (a symlink to usr/sbin/init) so Kata boots on.
  #
  # The wrapper is a standalone repository file rather than an inline heredoc:
  # it keeps ~60 escaped variables out of the build script and makes the logic
  # testable on its own (see test-taa-init.sh).
  install -m 0755 "$TAA_INIT_SRC" "$BUILD_WORK_DIR/extra/usr/local/bin/taa-init"

  # TAA reads its config from a fixed absolute path, so the file has to be part
  # of the measured image. configs/taa-initrd.json is the initrd baseline: the
  # regex engine (no semgrep rules shipped in the initrd) and the cert paths
  # under /etc/taa/certs that the two installs below populate.
  mkdir -p "$BUILD_WORK_DIR/extra/etc/taa/certs"
  install -m 0644 "$TAA_CONFIG_SRC" "$BUILD_WORK_DIR/extra/etc/taa/taa-config.json"
  install -m 0644 "$TAA_HRK_CERT_SRC" "$BUILD_WORK_DIR/extra/etc/taa/certs/hrk.cert"
  install -m 0644 "$TAA_HSK_CEK_CERT_SRC" "$BUILD_WORK_DIR/extra/etc/taa/certs/hsk_cek.cert"

  echo "生成可选 env 文件"

  # Optional environment file, letting the initrd carry its own TAA registration
  # target. %q shell-escapes the values so spaces or metacharacters are not
  # reinterpreted when taa-init sources this file.
  if taa_env_file_needed; then
    mkdir -p "$BUILD_WORK_DIR/extra/etc/default"
    {
      printf 'export TAA_ADDR=%q\n' "$TAA_ADDR"
      printf 'export PLATFORM_IP=%q\n' "$TAA_PLATFORM_IP"
      printf 'export DOCKER_ID=%q\n' "$TAA_DOCKER_ID"
      printf 'export TAA_REQUIRED=%q\n' "$TAA_REQUIRED"
      printf 'export TAA_REQUIRE_ATTESTATION=%q\n' "$TAA_REQUIRE_ATTESTATION"
    } > "$BUILD_WORK_DIR/extra/etc/default/taa.env"
  fi

  echo "追加到 cpio"

  # The appended entries end up inside the measured image, so their metadata has
  # to be a function of the inputs rather than of the builder's umask. `install
  # -m` pins the file modes, but directories created with mkdir and the env file
  # written through a shell redirect would otherwise inherit the umask -- the
  # same script on two hosts would then produce two different measurements for
  # the same inputs.
  # (The archive is not bit-reproducible: newc records each entry's inode number
  # and mtime. That is why the summary prints the output sha256, and why deploy
  # verifies that hash on the remote side instead of rebuilding there.)
  find "$BUILD_WORK_DIR/extra" -type d -exec chmod 0755 {} +
  if taa_env_file_needed; then
    chmod 0644 "$BUILD_WORK_DIR/extra/etc/default/taa.env"
  fi

  # Only new files are appended to the copied base cpio. Parent directories that
  # already exist in the base (usr, usr/local, etc) must not be written again:
  # the kernel unpacks appended segments over the base, so a later directory
  # entry would overwrite the base directory's mode, owner and timestamps.
  append_entries=()

  in_append_entries() {
    local candidate="$1"
    local entry
    for entry in ${append_entries[@]+"${append_entries[@]}"}; do
      if [[ "$entry" == "$candidate" ]]; then
        return 0
      fi
    done
    return 1
  }

  # Queue a file together with every parent directory that is missing from both
  # the base and the queue, parents first. Deduplicating against the queue and
  # not only against the base matters: several new files share etc/taa and
  # etc/taa/certs, and queueing them once per file would append those directory
  # entries two or three times over.
  queue_entry() {
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
      if manifest_has_entry "$manifest" "${parents[$i]}"; then
        continue
      fi
      if in_append_entries "${parents[$i]}"; then
        continue
      fi
      append_entries+=("${parents[$i]}")
    done

    append_entries+=("$path")
  }

  for path in \
    usr/local/bin/taa \
    usr/local/bin/taa-init \
    etc/taa/taa-config.json \
    etc/taa/certs/hrk.cert \
    etc/taa/certs/hsk_cek.cert; do
    queue_entry "$base_manifest" "$path"
  done
  if taa_env_file_needed; then
    queue_entry "$base_manifest" "etc/default/taa.env"
  fi

  (
    cd "$BUILD_WORK_DIR/extra"
    printf '%s\n' "${append_entries[@]}" | cpio -o -H newc -R 0:0 -A -F "$BUILD_WORK_DIR/base.cpio" --quiet
  )

  echo "重新压缩并校验"

  # gzip -n keeps local timestamps and filenames out of the gzip header, so the
  # same inputs produce the same bytes. The candidate is validated before it is
  # published to INITRD_OUT, so a failed build never overwrites a good output.
  candidate_manifest="$BUILD_WORK_DIR/initrd.candidate.manifest"
  gzip -n -9 < "$BUILD_WORK_DIR/base.cpio" > "$BUILD_WORK_DIR/initrd.candidate"
  archive_manifest "$BUILD_WORK_DIR/initrd.candidate" "$candidate_manifest"

  base_count="$(wc -l < "$base_manifest")"
  out_count="$(wc -l < "$candidate_manifest")"

  for entry in "${append_entries[@]}"; do
    if ! manifest_has_entry "$candidate_manifest" "$entry"; then
      echo "error: built initrd is missing $entry" >&2
      exit 1
    fi
  done

  # The archive is append-only, so the entry count has to be exactly the base
  # count plus what was queued. Any other number means something was queued
  # twice or silently dropped -- either way the boot measurement would not be
  # what this build claims it is.
  if [[ "$out_count" -ne "$((base_count + ${#append_entries[@]}))" ]]; then
    echo "error: unexpected entry count in built initrd: base $base_count + ${#append_entries[@]} appended != $out_count" >&2
    exit 1
  fi

  mv "$BUILD_WORK_DIR/initrd.candidate" "$INITRD_OUT"

  echo "输出结果摘要"

  echo "base initrd: $BASE_INITRD"
  echo "base initrd sha256: $(sha256sum "$BASE_INITRD" | awk '{print $1}')"
  echo "base cpio entries: $base_count"
  echo "output initrd: $INITRD_OUT"
  echo "output cpio entries: $out_count"
  echo "appended entries (${#append_entries[@]}):"
  for entry in "${append_entries[@]}"; do
    printf '  %s\n' "$entry"
  done
}

# Copy the authoritative base assets from the host that runs Kata. A committed
# copy of these files goes stale silently -- the initrd that used to live in this
# repository was truncated, and cpio reported no error -- so the host is the only
# authority and this subcommand is how the build obtains its input.
fetch_base() {
  require_cmd scp
  require_cmd ssh
  require_cmd gzip
  require_cmd cpio
  require_cmd sha256sum
  require_cmd awk
  require_cmd stat

  local base_dir="$SCRIPT_DIR/base"
  mkdir -p "$base_dir"

  local initrd_dst="$base_dir/$(basename "$REMOTE_BASE_INITRD_SRC")"
  local kernel_dst="$base_dir/$(basename "$REMOTE_KERNEL_SRC")"
  local ovmf_dst="$base_dir/$(basename "$REMOTE_OVMF_SRC")"

  local src dst pair
  for pair in \
    "$REMOTE_BASE_INITRD_SRC:$initrd_dst" \
    "$REMOTE_KERNEL_SRC:$kernel_dst" \
    "$REMOTE_OVMF_SRC:$ovmf_dst"; do
    src="${pair%%:*}"
    dst="${pair#*:}"

    echo "拉取 $REMOTE:$src"
    # Download beside the target first, then move it into place: a dropped
    # connection must not leave a half-written archive where the build would
    # pick it up as if it were complete.
    if ! scp -q "$REMOTE:$src" "$dst.part"; then
      rm -f "$dst.part"
      echo "error: failed to fetch $src from $REMOTE" >&2
      exit 1
    fi
    mv "$dst.part" "$dst"
  done

  # The initrd is the one input whose silent corruption is invisible downstream,
  # so it is verified rather than merely downloaded.
  if ! gzip -t "$initrd_dst" 2>/dev/null; then
    echo "error: fetched initrd is not a valid gzip stream: $initrd_dst" >&2
    exit 1
  fi

  echo
  echo "base assets in $base_dir:"
  for dst in "$initrd_dst" "$kernel_dst" "$ovmf_dst"; do
    printf '  %s\n    sha256: %s\n    bytes:  %s\n' \
      "$(basename "$dst")" \
      "$(sha256sum "$dst" | awk '{print $1}')" \
      "$(stat -c %s "$dst")"
  done
  printf '  %s\n    cpio entries: %s\n' \
    "$(basename "$initrd_dst")" \
    "$(gzip -dc "$initrd_dst" | cpio -t --quiet | wc -l)"
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

# Every write below goes through sudo, and ssh gives no tty to answer a prompt
# with. Check that privilege is already available rather than discovering it
# halfway through installing the bundle.
if [[ "$(id -u)" -ne 0 ]] && ! sudo -n true 2>/dev/null; then
  echo "error: this SSH account needs passwordless sudo on the host (sudo -n true failed)" >&2
  echo "hint: log in as root, or add a NOPASSWD sudoers entry for this account" >&2
  exit 1
fi

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
  remote_args="$(printf '%q ' "$REMOTE_BUNDLE_DIR" "$REMOTE_KATA_CONFIG_SRC" "$REMOTE_KATA_CONFIG" "$KATA_HYPERVISOR_SECTION" "$RUNTIME_HANDLER" "$RUNTIME_TYPE" "$RUNTIME_PATH" "$SNAPSHOTTER" "$RESTART_KUBELET" "$TEST_NODE_NAME" "$TEST_POD_NAME" "$TEST_IMAGE" "$TEST_POD_ANNOTATIONS")"
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
test_pod_annotations="${13}"
containerd_config="/etc/containerd/config.toml"

# 修改 Kata 或 containerd 配置前，先校验主机依赖和 bundle 路径。
# containerd 配置要求是 TOML version 2，与远程 CSV 服务器上观察到的配置格式一致。
for cmd in kubectl sudo grep ps python3 containerd hostname cmp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "error: $cmd is not installed or not in PATH" >&2
    exit 1
  fi
done

# Least-recoverable step of the flow comes next (a containerd config rewrite and
# restart), so establish that privilege is available before touching anything.
if [[ "$(id -u)" -ne 0 ]] && ! sudo -n true 2>/dev/null; then
  echo "error: this SSH account needs passwordless sudo on the host (sudo -n true failed)" >&2
  echo "hint: log in as root, or add a NOPASSWD sudoers entry for this account" >&2
  exit 1
fi

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
# Validate the annotation JSON before any host config is touched, so a typo
# cannot leave the runtime configured but the Pod uncreatable.
if ! printf '%s' "$test_pod_annotations" |
     python3 -c 'import json, sys; sys.exit(0 if isinstance(json.load(sys.stdin), dict) else 1)' 2>/dev/null; then
  echo "error: TEST_POD_ANNOTATIONS must be a JSON object" >&2
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

# 只改目标 hypervisor 表：切到 bundle、注释掉 image，并设置 rdinit=/usr/local/bin/taa-init。
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
        out.append('kernel_params = "rdinit=/usr/local/bin/taa-init"')
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
        # Strip both keys: init= is dead config once /init exists in the initrd
        # (the kernel tries rdinit= first) and leaving a stale init= would
        # suggest it still has an effect.
        params = [p for p in params if not p.startswith("init=") and not p.startswith("rdinit=")]
        params.insert(0, "rdinit=/usr/local/bin/taa-init")
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
if "rdinit=/usr/local/bin/taa-init" not in values["kernel_params"]:
    raise SystemExit("kernel_params does not contain rdinit=/usr/local/bin/taa-init")
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

containerd_backup=""
if sudo cmp -s "$tmp_containerd_config" "$containerd_config"; then
  # The runtimes map is only read when containerd starts, so an unchanged config
  # needs no restart -- and skipping it keeps the CRI up for the Pods that are
  # already running on this host.
  echo "containerd 配置未变化，跳过重启"
else
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
fi

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
python3 - "$runtime_handler" "$test_pod_name" "$test_node_name" "$test_image" "$test_pod_annotations" <<'PY' | kubectl apply -f -
import json
import sys
handler, pod_name, node_name, image, annotations_json = sys.argv[1:]
annotations = json.loads(annotations_json)
metadata = {"name": pod_name}
if annotations:
    metadata["annotations"] = annotations
print(json.dumps({
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": metadata,
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

# Print why it never became Ready: a bare wait timeout sends the reader back to
# the host for the status the script already has in hand.
if ! kubectl wait --for=condition=Ready "pod/$test_pod_name" --timeout=180s; then
  echo "error: test Pod did not become Ready within 180s; status and events follow" >&2
  kubectl get pod "$test_pod_name" -o wide >&2 || true
  kubectl describe pod "$test_pod_name" 2>&1 | sed -n '/Events:/,$p' >&2 || true
  exit 1
fi
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
  fetch-base)
    fetch_base
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
  print-config)
    # Machine-readable dump of the resolved settings, so a driver script does not
    # have to duplicate (and drift from) the defaults defined above. %q quoting
    # makes the output safe to `eval` even when a value contains spaces.
    for key in REMOTE_USER REMOTE_HOST REMOTE_BUNDLE_DIR REMOTE_BASE_INITRD_SRC \
               REMOTE_KATA_CONFIG_SRC REMOTE_KATA_CONFIG KATA_HYPERVISOR_SECTION \
               RUNTIME_HANDLER RUNTIME_TYPE RUNTIME_PATH SNAPSHOTTER \
               TEST_NODE_NAME TEST_POD_NAME TEST_IMAGE TEST_POD_ANNOTATIONS \
               OUT_DIR INITRD_OUT BASE_INITRD; do
      printf '%s=%q\n' "$key" "${!key}"
    done
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
