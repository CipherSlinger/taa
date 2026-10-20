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

# Renderer support files and the shipped Kata config the rendered config is
# derived from. The template is host-authoritative like the base initrd:
# fetch-base copies it, and `render` refuses to guess when it is missing.
RENDER_DIR="${RENDER_DIR:-$SCRIPT_DIR/render}"
KATA_CONFIG_TEMPLATE="${KATA_CONFIG_TEMPLATE:-$SCRIPT_DIR/base/configuration-qemu-csv2.toml}"

# Optional semgrep payload. configs/taa-initrd.json selects the scan engine, so
# the payload is only required when that config asks for semgrep -- but when it
# does, the guest has to carry its own interpreter and wheels: the base initrd
# has neither python3 nor semgrep, and TAA resolves the semgrep CLI through PATH.
# Build it with build-semgrep-payload.sh; it is gitignored because of its size.
TAA_SEMGREP_PAYLOAD_DIR="${TAA_SEMGREP_PAYLOAD_DIR:-$SCRIPT_DIR/semgrep-payload}"

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
CONTAINERD_CONFIG="${CONTAINERD_CONFIG:-/etc/containerd/config.toml}"
KATA_HYPERVISOR_SECTION="${KATA_HYPERVISOR_SECTION:-hypervisor.qemu}"
RUNTIME_HANDLER="${RUNTIME_HANDLER:-kata-qemu-csv2-taa}"
RUNTIME_TYPE="${RUNTIME_TYPE:-io.containerd.kata-qemu-csv2.v2}"
RUNTIME_PATH="${RUNTIME_PATH:-/opt/kata/bin/containerd-shim-kata-v2}"
SNAPSHOTTER="${SNAPSHOTTER:-nydus}"
RESTART_KUBELET="${RESTART_KUBELET:-0}"
# Default delivery package location. `render` overwrites it; `launch` renders
# into a temporary directory unless LAUNCH_KEEP_DIST=1.
DIST_DIR="${DIST_DIR:-$SCRIPT_DIR/dist/$RUNTIME_HANDLER}"
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
Usage: $0 [build|fetch-base|deploy|render|launch|all|print-config]

Commands:
  build       Build $INITRD_OUT from $BASE_INITRD and inject TAA + init wrapper.
  fetch-base  Copy the real base initrd, kernel, OVMF and shipped Kata config
              from $REMOTE into $(basename "$SCRIPT_DIR")/base/.
  deploy      Upload the built initrd to $REMOTE and install the remote Kata guest bundle.
  render      Render the Kata config, containerd handler, K8s manifests and an
              install script into $DIST_DIR. Local only; no host access.
  launch      Render locally, upload, then install the package on $REMOTE and
              create a test Pod.
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
  SKIP_REMOTE_KATA_TEMPLATE_CHECK=${SKIP_REMOTE_KATA_TEMPLATE_CHECK:-0}
  CONTAINERD_CONFIG=$CONTAINERD_CONFIG
  KATA_CONFIG_TEMPLATE=$KATA_CONFIG_TEMPLATE
  DIST_DIR=$DIST_DIR
  LAUNCH_KEEP_DIST=${LAUNCH_KEEP_DIST:-0}

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
  # -q lets grep exit at the first match, cpio then takes SIGPIPE on its next
  # write, and `pipefail` would turn that 141 into this function's status -- a
  # false "entry is missing" that only appears once the archive is big enough for
  # the match to land well before the end of the listing. Measured on the semgrep
  # initrd: 141 with -q under pipefail, 0 in this form, same image. Turning
  # pipefail off for this pipeline alone keeps the early exit and the correct
  # status at once.
  ( set +o pipefail; gzip -dc "$img" | cpio -t --quiet | grep -Fxq -- "$entry" )
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

# The scan engine is a property of the config being injected rather than a build
# flag, so the payload requirement follows the config. A config naming the
# semgrep engine with no payload in the image would build and boot fine, then
# fail every audit at import time -- far away from the build that caused it.
taa_config_wants_semgrep() {
  grep -qE '"engine"[[:space:]]*:[[:space:]]*"semgrep"' "$TAA_CONFIG_SRC"
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

  # One entry per part of the payload that would be missed silently: the
  # interpreter, both PATH-visible CLI entry points (semgrep dispatches to the
  # OCaml CLI, which falls back to pysemgrep by name), the native scanner, and
  # the rules the engine stats at construction (NewEngine fails the whole audit
  # if the rules path is not a directory).
  if taa_config_wants_semgrep; then
    local payload_entry
    for payload_entry in \
      "rootfs/usr/bin/python3.10" \
      "rootfs/usr/local/bin/semgrep" \
      "rootfs/usr/local/bin/pysemgrep" \
      "rootfs/opt/taa/semgrep/pylib/semgrep/bin/semgrep-core" \
      "rootfs/opt/taa/semgrep/rules/python/rules.yaml"; do
      if [[ ! -e "$TAA_SEMGREP_PAYLOAD_DIR/$payload_entry" ]]; then
        echo "error: $TAA_CONFIG_SRC selects the semgrep engine but the payload is incomplete" >&2
        echo "       missing: $TAA_SEMGREP_PAYLOAD_DIR/$payload_entry" >&2
        echo "hint: run '$SCRIPT_DIR/build-semgrep-payload.sh' to build it" >&2
        exit 1
      fi
    done
  fi
}

# Copy the semgrep payload into the staging tree under the guest paths it will
# occupy. The payload mirrors the guest rootfs, so this is a single copy; `cp -a`
# keeps the modes and symlinks the wheel unpacking produced, none of which the
# builder's umask may touch (everything staged here lands in the measured image).
stage_semgrep_payload() {
  echo "注入 semgrep 载荷"

  local payload_root="$TAA_SEMGREP_PAYLOAD_DIR/rootfs"
  cp -a "$payload_root/." "$BUILD_WORK_DIR/extra/"

  # The payload is the single largest thing in the image (it is why the initrd
  # roughly doubles), so the build reports it rather than leaving the growth to
  # be noticed later as guest memory. Both numbers come out of one walk: `du` and
  # `find | wc -l` would each re-traverse the ~350 MiB tree for a single line.
  local payload_files payload_mib
  read -r payload_files payload_mib < <(
    find "$payload_root" -mindepth 1 -printf '%s\n' |
      awk '{n++; s += $1} END {printf "%d %.1f\n", n, s / 1048576}'
  )
  echo "semgrep 载荷（未压缩，按文件大小计）: ${payload_mib} MiB / ${payload_files} 个文件"
}

# 远程部署前检查输出镜像是否包含 TAA 所需的注册环境，并核对其中烘焙的注册身份。
check_deploy_inputs() {
  if [[ "$ALLOW_MISSING_TAA_ENV" != "1" ]] && ! archive_has_entry "$INITRD_OUT" "etc/default/taa.env"; then
    echo "error: built initrd does not contain etc/default/taa.env" >&2
    rebuild_hint
    echo "hint: set ALLOW_MISSING_TAA_ENV=1 only if another early-boot path supplies these env vars" >&2
    exit 1
  fi
  if [[ "$ALLOW_MISSING_TAA_ENV" != "1" ]]; then
    check_initrd_identity
  fi
}

# The rebuild command that fixes both "the image carries no registration identity"
# and "it carries a different one". Stated once because the values are what the
# operator has to retype; an empty value gets a placeholder, and an empty value is
# exactly what produces the missing-entry case above.
rebuild_hint() {
  echo "hint: 重新构建：TAA_PLATFORM_IP=${TAA_PLATFORM_IP:-<ip:port>} TAA_DOCKER_ID=${TAA_DOCKER_ID:-<id>} $0 build" >&2
}

# taa-init reads /etc/default/taa.env from inside the guest, where nothing about
# the deploying shell's environment can still reach it, so the registration
# address is fixed at build time. An initrd built with different values deploys
# and boots perfectly -- Ready pod, verified attestation -- and then registers
# somewhere else entirely, which is invisible from this side: the only symptom is
# a platform that never hears from TAA. `build` and `deploy` are separate
# commands, so the values that built this image are not necessarily the ones this
# invocation carries; compare them here, at the handoff into deploy, which is also
# the first point at which the image under test is the one being published.
check_initrd_identity() {
  local baked_env baked_platform baked_docker_id want_platform want_docker_id

  # --to-stdout prints the entry instead of extracting it, so there is no temp
  # directory to own and nothing left behind if this exits midway. The whole
  # archive is streamed either way; there is no way to stop cpio early.
  baked_env="$(gzip -dc "$INITRD_OUT" 2>/dev/null |
    cpio -i --to-stdout --quiet etc/default/taa.env 2>/dev/null || true)"

  if [[ -z "$baked_env" ]]; then
    echo "error: 无法从 $INITRD_OUT 中读出 etc/default/taa.env" >&2
    exit 1
  fi

  baked_platform="$(sed -n 's/^export PLATFORM_IP=//p' <<<"$baked_env" | head -n 1)"
  baked_docker_id="$(sed -n 's/^export DOCKER_ID=//p' <<<"$baked_env" | head -n 1)"

  # Compared in the %q form the writer below produces, not as raw values: a value
  # %q decides to quote is stored quoted, and comparing it raw would fail the
  # deploy for a difference that is only escaping.
  want_platform="$(printf '%q' "$TAA_PLATFORM_IP")"
  want_docker_id="$(printf '%q' "$TAA_DOCKER_ID")"

  if [[ "$baked_platform" != "$want_platform" || "$baked_docker_id" != "$want_docker_id" ]]; then
    echo "error: initrd 里烘焙的注册身份与本次调用不一致" >&2
    echo "       initrd: PLATFORM_IP=$baked_platform DOCKER_ID=$baked_docker_id" >&2
    echo "       本次:   PLATFORM_IP=$want_platform DOCKER_ID=$want_docker_id" >&2
    echo "hint: guest 内的 TAA 只认 initrd 里这份，发布出去它就会注册到旧地址且没有任何本地症状" >&2
    rebuild_hint
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
  for injected in usr/local/bin/taa usr/local/bin/taa-init etc/taa/taa-config.json opt/taa/semgrep/MANIFEST; do
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
  # cert paths under /etc/taa/certs that the two installs below populate, and,
  # when that config selects the semgrep engine, the payload staged afterwards
  # under /opt/taa/semgrep plus the interpreter and CLI that run it.
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

  if taa_config_wants_semgrep; then
    stage_semgrep_payload
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

  # Both sets are held in memory rather than asked of the manifest with grep: the
  # payload makes this run thousands of times, and a fork per parent against an
  # 8900-line list is tens of thousands of processes for a lookup bash can do
  # itself. Reading the manifest once is a single pass and no forks at all.
  declare -A base_entries=() appended_entries=()
  while IFS= read -r entry; do
    base_entries["$entry"]=1
  done < "$base_manifest"

  # Queue a file together with every parent directory that is missing from both
  # the base and the queue, parents first. Deduplicating against the queue and
  # not only against the base matters: several new files share etc/taa and
  # etc/taa/certs, and queueing them once per file would append those directory
  # entries two or three times over.
  queue_entry() {
    local path="$1"
    local dir
    local parents=()

    dir="$(dirname "$path")"
    while [[ "$dir" != "." && "$dir" != "/" ]]; do
      parents+=("$dir")
      dir="$(dirname "$dir")"
    done

    local i parent
    for ((i=${#parents[@]} - 1; i >= 0; i--)); do
      parent="${parents[$i]}"
      if [[ -n "${base_entries[$parent]:-}" || -n "${appended_entries[$parent]:-}" ]]; then
        continue
      fi
      appended_entries["$parent"]=1
      append_entries+=("$parent")
    done

    # The path itself is recorded too, not only the parents. A directory reached
    # here as a path is also reached again as the parent of everything under it,
    # and without this line the second visit finds nothing in the set and appends
    # the same directory entry twice -- which the kernel then unpacks over the
    # base's, overwriting the mode and timestamps this whole block exists to
    # preserve. The entry-count check below cannot catch that: both copies are
    # appended and both are counted.
    appended_entries["$path"]=1
    append_entries+=("$path")
  }

  # Enumerate what to append rather than listing it: the semgrep payload alone is
  # thousands of files, and a hand-kept list would drift from whatever the
  # staging steps wrote. A C-locale sort puts every parent ahead of its children,
  # which is what queue_entry relies on when it walks a path's parents.
  while IFS= read -r path; do
    queue_entry "$path"
  done < <(cd "$BUILD_WORK_DIR/extra" && find . -mindepth 1 -printf '%P\n' | LC_ALL=C sort)

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

  # Membership by set rather than by grep, for the same reason as the queueing
  # above: this loop runs once per appended entry, so a fork here would put back
  # the per-entry process the in-memory sets exist to avoid.
  declare -A candidate_entries=()
  while IFS= read -r entry; do
    candidate_entries["$entry"]=1
  done < "$candidate_manifest"

  for entry in "${append_entries[@]}"; do
    if [[ -z "${candidate_entries[$entry]:-}" ]]; then
      echo "error: built initrd is missing $entry" >&2
      exit 1
    fi
  done

  # The append list must not repeat a path. A second entry for the same path is
  # unpacked over the first, so the directory mode and timestamps that the staging
  # step pins would be replaced by those of the later copy, and the measurement
  # would stop being a function of the inputs. The count check below cannot see
  # this -- both copies are appended and both are counted -- but the queueing set
  # can: it holds one key per path queued, and it is already built.
  if [[ "${#appended_entries[@]}" -ne "${#append_entries[@]}" ]]; then
    echo "error: append list repeats a path: ${#appended_entries[@]} distinct of ${#append_entries[@]}" >&2
    exit 1
  fi

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
  # The full list is written next to the image: with the semgrep payload staged
  # it runs to thousands of paths, which is more than a build log should carry but
  # exactly what is needed to audit what the measurement covers.
  entries_file="${INITRD_OUT}.entries"
  printf '%s\n' "${append_entries[@]}" > "$entries_file"
  # Print the list in full while it still fits in a build log, otherwise the head
  # of it; one bound drives both so the truncation can never contradict the
  # "complete list" pointer.
  local max_listed=20
  if [[ "${#append_entries[@]}" -le $((max_listed * 2)) ]]; then
    sed 's/^/  /' "$entries_file"
  else
    head -n "$max_listed" "$entries_file" | sed 's/^/  /'
    echo "  ... （完整清单见 $entries_file）"
  fi
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
  # The shipped CSV2 config is the template `render` rewrites. It is as
  # host-specific as the base initrd, so it is fetched rather than committed.
  local kata_config_dst="$base_dir/$(basename "$REMOTE_KATA_CONFIG_SRC")"

  local src dst pair
  for pair in \
    "$REMOTE_BASE_INITRD_SRC:$initrd_dst" \
    "$REMOTE_KERNEL_SRC:$kernel_dst" \
    "$REMOTE_OVMF_SRC:$ovmf_dst" \
    "$REMOTE_KATA_CONFIG_SRC:$kata_config_dst"; do
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
  for dst in "$initrd_dst" "$kernel_dst" "$ovmf_dst" "$kata_config_dst"; do
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
# ── Kata config template ─────────────────────────────────────────────────────
#
# The rendered Kata config is derived from the host's shipped CSV2 config. That
# file is host-authoritative, like the base initrd, so it is fetched and its
# hash compared before it is used as a template.
ensure_kata_template() {
  require_cmd scp ssh sha256sum

  if [[ ! -f "$KATA_CONFIG_TEMPLATE" ]]; then
    echo "获取 Kata 配置模板: $REMOTE:$REMOTE_KATA_CONFIG_SRC"
    mkdir -p "$(dirname "$KATA_CONFIG_TEMPLATE")"
    if ! scp -q "$REMOTE:$REMOTE_KATA_CONFIG_SRC" "$KATA_CONFIG_TEMPLATE.part"; then
      rm -f "$KATA_CONFIG_TEMPLATE.part"
      echo "error: 无法从 $REMOTE 获取 $REMOTE_KATA_CONFIG_SRC" >&2
      exit 1
    fi
    mv "$KATA_CONFIG_TEMPLATE.part" "$KATA_CONFIG_TEMPLATE"
  fi

  if [[ "${SKIP_REMOTE_KATA_TEMPLATE_CHECK:-0}" == "1" ]]; then
    echo "warning: SKIP_REMOTE_KATA_TEMPLATE_CHECK=1，跳过模板一致性校验" >&2
    return 0
  fi

  local local_sha remote_sha
  local_sha="$(sha256sum "$KATA_CONFIG_TEMPLATE" | awk '{print $1}')"
  remote_sha="$(ssh "$REMOTE" "sha256sum $(printf '%q' "$REMOTE_KATA_CONFIG_SRC") 2>/dev/null | awk '{print \$1}'" || true)"
  remote_sha="${remote_sha//$'\r'/}"
  remote_sha="${remote_sha//$'\n'/}"
  if [[ -z "$remote_sha" ]]; then
    echo "error: 无法读取远端模板 $REMOTE:$REMOTE_KATA_CONFIG_SRC" >&2
    exit 1
  fi
  if [[ "$remote_sha" != "$local_sha" ]]; then
    echo "error: 本地 Kata 配置模板与远端不一致" >&2
    echo "       local:  $local_sha  $KATA_CONFIG_TEMPLATE" >&2
    echo "       remote: $remote_sha  $REMOTE_KATA_CONFIG_SRC" >&2
    echo "hint: 重新运行 $0 fetch-base 刷新模板，或设置 SKIP_REMOTE_KATA_TEMPLATE_CHECK=1" >&2
    exit 1
  fi
  echo "Kata 配置模板一致: $local_sha"
}

# ── Local rendering ──────────────────────────────────────────────────────────
#
# Everything launch used to generate inside the remote heredoc is produced here
# instead, so the very same files can be installed by launch and shipped as a
# delivery package. Rendering never contacts the host.
render_package() {
  local out_dir="$1"
  local template="${2:-$KATA_CONFIG_TEMPLATE}"
  local name_re='^[a-z0-9]([-a-z0-9]*[a-z0-9])?$'

  require_cmd python3 sha256sum awk

  if [[ ! -f "$template" ]]; then
    echo "error: Kata 配置模板缺失: $template" >&2
    echo "hint: 先运行 $0 fetch-base（或指定 KATA_CONFIG_TEMPLATE）" >&2
    exit 1
  fi
  if [[ ! -f "$RENDER_DIR/render.py" || ! -f "$RENDER_DIR/install.sh" ]]; then
    echo "error: 渲染器缺失: $RENDER_DIR" >&2
    exit 1
  fi
  case "$out_dir" in
    /|/opt|/opt/kata|/opt/kata/share|"$SCRIPT_DIR")
      echo "error: 拒绝渲染到共享目录: $out_dir" >&2
      exit 1
      ;;
  esac

  if [[ ! "$RUNTIME_HANDLER" =~ $name_re ]]; then
    echo "error: RUNTIME_HANDLER must be a Kubernetes DNS label: $RUNTIME_HANDLER" >&2
    exit 1
  fi
  if [[ ! "$TEST_POD_NAME" =~ $name_re ]]; then
    echo "error: TEST_POD_NAME must be a Kubernetes DNS label: $TEST_POD_NAME" >&2
    exit 1
  fi
  if [[ "$TEST_IMAGE" == *$'\n'* || "$TEST_IMAGE" == *$'\r'* ]]; then
    echo "error: TEST_IMAGE must not contain newlines" >&2
    exit 1
  fi

  rm -rf "$out_dir"
  mkdir -p "$out_dir/config" "$out_dir/k8s"

  python3 "$RENDER_DIR/render.py" kata-config \
    --template "$template" \
    --section "$KATA_HYPERVISOR_SECTION" \
    --bundle-dir "$REMOTE_BUNDLE_DIR" \
    --out "$out_dir/config/kata-config.toml"

  python3 "$RENDER_DIR/render.py" containerd-fragment \
    --handler "$RUNTIME_HANDLER" \
    --runtime-type "$RUNTIME_TYPE" \
    --runtime-path "$RUNTIME_PATH" \
    --snapshotter "$SNAPSHOTTER" \
    --kata-config "$REMOTE_KATA_CONFIG" \
    --out "$out_dir/config/containerd-runtime-handler.toml"

  python3 "$RENDER_DIR/render.py" k8s \
    --handler "$RUNTIME_HANDLER" \
    --pod "$TEST_POD_NAME" \
    --node "$TEST_NODE_NAME" \
    --image "$TEST_IMAGE" \
    --annotations "$TEST_POD_ANNOTATIONS" \
    --out-dir "$out_dir/k8s"

  # The package is self-contained: the installer and the merger travel with it.
  cp "$RENDER_DIR/render.py" "$out_dir/render.py"
  cp "$RENDER_DIR/install.sh" "$out_dir/install.sh"

  # MEASUREMENT is SM3(OVMF || cmdline || initrd || kernel), so the package
  # records exactly those inputs where it can see them.
  local kernel_params template_sha base_sha initrd_sha kernel_sha ovmf_sha
  local kernel_src="$SCRIPT_DIR/base/$(basename "$REMOTE_KERNEL_SRC")"
  local ovmf_src="$SCRIPT_DIR/base/$(basename "$REMOTE_OVMF_SRC")"
  kernel_params="$(sed -n 's/^kernel_params = "\(.*\)"$/\1/p' "$out_dir/config/kata-config.toml" | head -n 1)"
  template_sha="$(sha256sum "$template" | awk '{print $1}')"
  base_sha=""
  [[ -f "$BASE_INITRD" ]] && base_sha="$(sha256sum "$BASE_INITRD" | awk '{print $1}')"
  initrd_sha=""
  [[ -f "$INITRD_OUT" ]] && initrd_sha="$(sha256sum "$INITRD_OUT" | awk '{print $1}')"
  kernel_sha=""
  [[ -f "$kernel_src" ]] && kernel_sha="$(sha256sum "$kernel_src" | awk '{print $1}')"
  ovmf_sha=""
  [[ -f "$ovmf_src" ]] && ovmf_sha="$(sha256sum "$ovmf_src" | awk '{print $1}')"

  {
    printf 'RUNTIME_HANDLER=%q\n' "$RUNTIME_HANDLER"
    printf 'RUNTIME_TYPE=%q\n' "$RUNTIME_TYPE"
    printf 'RUNTIME_PATH=%q\n' "$RUNTIME_PATH"
    printf 'SNAPSHOTTER=%q\n' "$SNAPSHOTTER"
    printf 'REMOTE_BUNDLE_DIR=%q\n' "$REMOTE_BUNDLE_DIR"
    printf 'REMOTE_KATA_CONFIG=%q\n' "$REMOTE_KATA_CONFIG"
    printf 'CONTAINERD_CONFIG=%q\n' "$CONTAINERD_CONFIG"
    printf 'PACKAGE_KATA_CONFIG=%q\n' "config/kata-config.toml"
    printf 'KATA_CONFIG_TEMPLATE_SRC=%q\n' "$REMOTE_KATA_CONFIG_SRC"
    printf 'KATA_CONFIG_TEMPLATE_SHA256=%q\n' "$template_sha"
    printf 'BASE_INITRD_SRC=%q\n' "$REMOTE_BASE_INITRD_SRC"
    printf 'BASE_INITRD_SHA256=%q\n' "$base_sha"
    printf 'INITRD_OUT=%q\n' "$INITRD_OUT"
    printf 'INITRD_SHA256=%q\n' "$initrd_sha"
    printf 'KERNEL_SHA256=%q\n' "$kernel_sha"
    printf 'OVMF_SHA256=%q\n' "$ovmf_sha"
    printf 'KERNEL_PARAMS=%q\n' "$kernel_params"
    printf 'TEST_POD_NAME=%q\n' "$TEST_POD_NAME"
    printf 'TEST_NODE_NAME=%q\n' "$TEST_NODE_NAME"
    printf 'TEST_IMAGE=%q\n' "$TEST_IMAGE"
    printf 'TEST_POD_ANNOTATIONS=%q\n' "$TEST_POD_ANNOTATIONS"
    printf 'RESTART_KUBELET=%q\n' "$RESTART_KUBELET"
    printf 'TAA_PLATFORM_IP=%q\n' "${TAA_PLATFORM_IP:-}"
    printf 'TAA_DOCKER_ID=%q\n' "${TAA_DOCKER_ID:-}"
  } > "$out_dir/manifest.env"

  cat > "$out_dir/README.md" <<EOF
# TAA-in-initrd 交付包

由 \`build-initrd.sh render\` 生成。TAA 运行在 Kata CSV2 机密 VM 的 initrd 里，
自证通过后才放行 kata-agent。

## 内容

- \`config/kata-config.toml\` — 指向 bundle 的 Kata hypervisor 配置
- \`config/containerd-runtime-handler.toml\` — containerd handler 片段（供审阅）
- \`k8s/runtimeclass.yaml\` / \`k8s/test-pod.yaml\` — 运行时类与测试 Pod
- \`install.sh\` / \`render.py\` — 安装脚本与合并器
- \`manifest.env\` — 本次交付的全部参数与度量输入
- \`SHA256SUMS\` — 包内文件校验和

## 前置条件

- 目标宿主已安装海光 CSV2 可用的 Kata（含 \`$REMOTE_KATA_CONFIG_SRC\`）
- containerd 配置为 TOML \`version = 2\`，并装有 \`$SNAPSHOTTER\` snapshotter
- bundle 已就位：\`$REMOTE_BUNDLE_DIR/{initramfs.img,vmlinuz,OVMF.fd}\`
  （由 \`build-initrd.sh deploy\` 或手工放置）
- kubectl 可用；需要 root 或免密 sudo

## 安装

\`\`\`bash
cd $(basename "$out_dir")
sha256sum -c SHA256SUMS
sudo bash install.sh --dry-run   # 先看会改什么
sudo bash install.sh
\`\`\`

## 使用

创建任意 Pod 时指定：

\`\`\`yaml
spec:
  runtimeClassName: $RUNTIME_HANDLER
\`\`\`

测试 Pod 名：\`$TEST_POD_NAME\`（TAA 在 Pod 网络命名空间的 6001 端口）。

## 度量口径

MEASUREMENT = SM3(OVMF || cmdline || initrd || kernel)。本包记录：

- OVMF: \`$ovmf_sha\`
- kernel: \`$kernel_sha\`
- initrd: \`$initrd_sha\`
- cmdline: \`$kernel_params\`
EOF

  (cd "$out_dir" && find . -type f ! -name SHA256SUMS -print0 |
    LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS)

  echo "交付包: $out_dir"
  local file
  while IFS= read -r file; do
    printf '  %s\n' "${file#"$out_dir"/}"
  done < <(find "$out_dir" -type f | LC_ALL=C sort)
}

launch_remote() {
  require_cmd ssh scp python3

  echo "确保 Kata 配置模板在本地"
  ensure_kata_template

  # The rendered Pod carries nodeName only when it is known. Resolve it now,
  # read-only, so both the launcher and the delivered package agree.
  if [[ -z "$TEST_NODE_NAME" ]]; then
    TEST_NODE_NAME="$(ssh "$REMOTE" 'bash -s' <<'REMOTE_NODE' || true
set -u
for candidate in "$(hostname)" "$(hostname -s)"; do
  if kubectl get node "$candidate" >/dev/null 2>&1; then
    echo "$candidate"
    exit 0
  fi
done
exit 1
REMOTE_NODE
)"
    TEST_NODE_NAME="${TEST_NODE_NAME//$'\r'/}"
    TEST_NODE_NAME="${TEST_NODE_NAME//$'\n'/}"
    if [[ -z "$TEST_NODE_NAME" ]]; then
      echo "error: could not determine Kubernetes node name for $REMOTE" >&2
      echo "hint: set TEST_NODE_NAME to the node name shown by 'kubectl get nodes'" >&2
      exit 1
    fi
  fi
  export TEST_NODE_NAME

  local render_dir
  render_dir="$(mktemp -d /tmp/taa-render.XXXXXX)"
  cleanup_render() { rm -rf "${render_dir:-}"; }
  trap cleanup_render EXIT

  echo "本地渲染"
  render_package "$render_dir"

  if [[ "${LAUNCH_KEEP_DIST:-0}" == "1" ]]; then
    rm -rf "$DIST_DIR"
    mkdir -p "$(dirname "$DIST_DIR")"
    cp -a "$render_dir" "$DIST_DIR"
    echo "保留交付包: $DIST_DIR"
  fi

  echo "上传并安装到 $REMOTE"
  local remote_tmp
  remote_tmp="$(ssh "$REMOTE" 'mktemp -d /tmp/taa-launch.XXXXXX')"
  remote_tmp="${remote_tmp//$'\r'/}"
  remote_tmp="${remote_tmp//$'\n'/}"
  if [[ -z "$remote_tmp" ]]; then
    echo "error: could not create a remote temporary directory" >&2
    exit 1
  fi
  scp -q -r "$render_dir/." "$REMOTE:$remote_tmp/"

  # Forward the explicit skip flags the pre-check already honours: install.sh
  # repeats both checks on the host, and silently dropping an operator override
  # would turn a deliberate bypass into a hard failure.
  local install_flags=""
  [[ "${SKIP_REMOTE_BASE_CHECK:-0}" == "1" ]] && install_flags+=" --skip-base-check"
  [[ "${SKIP_REMOTE_KATA_TEMPLATE_CHECK:-0}" == "1" ]] && install_flags+=" --skip-template-check"

  ssh "$REMOTE" "bash -s -- $(printf '%q ' "$remote_tmp")$install_flags" <<'REMOTE_INSTALL'
set -euo pipefail
pkg="$1"
shift
cleanup() { sudo rm -rf "$pkg"; }
trap cleanup EXIT
sudo bash "$pkg/install.sh" "$@"
REMOTE_INSTALL
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
  render)
    render_package "$DIST_DIR"
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
               CONTAINERD_CONFIG KATA_CONFIG_TEMPLATE DIST_DIR \
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
