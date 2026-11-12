#!/usr/bin/env bash
# 构建并可选部署一个包含本仓库 TAA 二进制文件的 Kata CSV initrd。
# 这里的关键设计是：把原始 Kata initrd 解压成 cpio 归档后保持原有内容不动，
# 只向归档末尾追加少量新文件。不要完整解包再重新打包 base initrd，
# 因为其中包含设备节点；普通用户解包设备节点可能失败，并导致 /dev/console
# 等原始条目被静默丢失。
#
# 追加不再每次都重压整份镜像：base（训练角色再加 semgrep 载荷）先做成缓存的
# “种子镜像”，之后每次构建只把 TAA 压成第二个 gzip member 拼在种子之后。
# 内核按顺序读取每个 gzip member，因此两者等价；成本从分钟级降到秒级。
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
# 它搬到 deploy/ 之后，ROOT_DIR 变成 deploy/，于是 TAA_SRC 与配置的默认值
# 全部指向不存在的路径（表现为"缺 build input"，而不是"路径写错了"）。
# 因此下面加一条断言：解析不出仓库根就当场报错，不再静默用错误默认值。
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
if [[ ! -f "$ROOT_DIR/go.mod" ]]; then
  echo "error: repository root not found from $SCRIPT_DIR (no go.mod in $ROOT_DIR)" >&2
  echo "hint: override TAA_SRC / TAA_CONFIG_SRC explicitly" >&2
  exit 1
fi

# ── Instance role ────────────────────────────────────────────────────────────
#
# One package per role, selected by a bare `taa-<role>` argument (or TAA_ROLE),
# defaulting to taa-train so every existing invocation keeps its meaning. The
# role is not a build flavour: it decides what the guest *is*, so it has to be
# settled before any default is derived from it.
#
# The three roles map onto the CONTRACT_TYPE values TAA itself understands
# (internal/config: 1 tee/train, 2 tee/infer, 3 data analysis). Training and
# inference are the same daemon role -- TAA's own mapping says so -- and differ
# only in what the platform asks the instance to do; the data-analysis role is a
# different role and the loader switches its audit off.
#
# Why each role needs its own package directory and runtime handler: the Kata
# config lives *inside* the package and containerd's ConfigPath points at it, so
# two roles sharing one directory would overwrite each other's boot assets and
# leave a running handler pointing at the other role's kernel. Two roles under
# one handler is the same defect one level up.
#
# One spelling per role downstream. `taa-infer-duc` is accepted because it is an
# easy transposition and was asked for by that name; everything after this point
# only ever sees the canonical `taa-infer-dcu`.
normalize_role() {
  case "$1" in
    taa-infer-duc) echo taa-infer-dcu ;;
    *) echo "$1" ;;
  esac
}

# The role argument is accepted anywhere in argv and removed before dispatch, so
# both `build-initrd.sh taa-infer all` and `build-initrd.sh all taa-infer` work.
TAA_ROLE="$(normalize_role "${TAA_ROLE:-}")"
role_args=()
for role_arg in "$@"; do
  role_arg="$(normalize_role "$role_arg")"
  case "$role_arg" in
    taa-train|taa-infer|taa-analysis|taa-train-dcu|taa-infer-dcu) TAA_ROLE="$role_arg" ;;
    *) role_args+=("$role_arg") ;;
  esac
done
if [[ ${#role_args[@]} -gt 0 ]]; then
  set -- "${role_args[@]}"
else
  set --
fi

# taa-train is the default because that is what this script built before roles
# existed. Its names below are deliberately left exactly as they were: a host
# already running this package has containerd pointing at that directory, and
# renaming it would break the installation on upgrade.
TAA_ROLE="${TAA_ROLE:-taa-train}"

# What the role means to the guest, in one place each.
role_contract_type() {  # CONTRACT_TYPE: 1 train, 2 infer, 3 data analysis
  case "$TAA_ROLE" in
    taa-train|taa-train-dcu) echo 1 ;;
    taa-infer|taa-infer-dcu) echo 2 ;;
    taa-analysis) echo 3 ;;
  esac
}

# Only the training roles carry the semgrep payload. Inference and data analysis
# land or run models that were already audited where they were trained, so
# shipping a 350 MiB Python runtime and scanner into their measured initrd buys
# nothing -- and the data-analysis role never audits at all. The DCU variants
# keep the split: a DCU training guest audits code like any other training one.
role_wants_semgrep() {
  case "$TAA_ROLE" in
    taa-train|taa-train-dcu) return 0 ;;
    *) return 1 ;;
  esac
}

# Handler and delivery directory are per role, so a host can hold all three side
# by side. Both carry the role suffix, including training: a bare `package` or
# `kata-qemu-nondcu-csv2-taa` would read as "the default one" and invite a
# second role to be installed over it. The `nondcu` / `dcu` infix makes the two
# device families explicit and keeps every TAA handler under a shared prefix.
role_runtime_handler() {
  case "$TAA_ROLE" in
    taa-train) echo kata-qemu-nondcu-csv2-taa-train ;;
    taa-infer) echo kata-qemu-nondcu-csv2-taa-infer ;;
    taa-analysis) echo kata-qemu-nondcu-csv2-taa-analysis ;;
    taa-train-dcu) echo kata-qemu-dcu-csv2-taa-train ;;
    taa-infer-dcu) echo kata-qemu-dcu-csv2-taa-infer ;;
  esac
}

# The containerd runtime_type of the Kata class this handler extends. It is a
# property of the *host runtime* the package layers on, not of the role name:
# the plain CSV2 roles extend kata-qemu-csv2, and the DCU roles extend the
# host's hygon-dcu-csv2 class, which is what makes QEMU hand the card through.
role_runtime_type() {
  case "$TAA_ROLE" in
    taa-train-dcu|taa-infer-dcu) echo io.containerd.kata-qemu-hygon-dcu-csv2.v2 ;;
    *) echo io.containerd.kata-qemu-csv2.v2 ;;
  esac
}

role_package_subdir() {
  case "$TAA_ROLE" in
    taa-train) echo package-train ;;
    taa-infer) echo package-infer ;;
    taa-analysis) echo package-analysis ;;
    taa-train-dcu) echo package-train-dcu ;;
    taa-infer-dcu) echo package-infer-dcu ;;
  esac
}

role_test_pod_name() {
  case "$TAA_ROLE" in
    taa-train) echo test-kata-csv2-taa ;;
    taa-infer) echo test-kata-csv2-taa-infer ;;
    taa-analysis) echo test-kata-csv2-taa-analysis ;;
    taa-train-dcu) echo test-kata-hygon-dcu-csv2-taa ;;
    taa-infer-dcu) echo test-kata-hygon-dcu-csv2-taa-infer ;;
  esac
}

# The Pod image follows the role. train and infer share the TAA-free taa-env
# variant (it is built exactly for those two), while the data-analysis role runs
# on the jupyter base whose runtime owns /home/jovyan -- the same base
# deploy-dataanaylsis.sh uses, so the data lands where that role's tasks look
# for it. That image names its user instead of using a numeric id, which under
# the nydus guest-pull snapshotter fails the /etc/passwd lookup before the Pod
# reaches the guest, so the rendered Pod pins a numeric uid for this role only.
role_test_image() {
  case "$TAA_ROLE" in
    taa-train|taa-infer) echo 172.16.10.178:31313/taa-env:v1-train-infer ;;
    taa-analysis) echo 172.16.10.178:31313/jupyter-nologin-full:v2.2 ;;
    # The DCU roles pull a DTK image: the guest runs the Hygon driver and the
    # container needs the matching runtime stack. This is the image the verified
    # DCU test Pod on the same host uses, so it is known to start there.
    taa-train-dcu|taa-infer-dcu) echo 172.16.10.178:31313/vllm:ubuntu-dtk ;;
  esac
}

# Kernel modules the guest must load before anything can use the device. The
# DCU kernel builds hycu out of tree and the base initrd carries neither the
# module tree nor kmod, so the package ships both and taa-init loads them from
# this list, which it receives as taa.taa_modules= on the kernel command line.
role_kernel_modules() {
  case "$TAA_ROLE" in
    taa-train-dcu|taa-infer-dcu) echo hycu ;;
    *) echo "" ;;
  esac
}

# Whether the role's initrd carries the DCU driver tree. This is separate from
# role_kernel_modules: the modules list is identity (it travels on the command
# line), while the payload is a build input that has to be fetched once.
role_wants_dcu_payload() {
  case "$TAA_ROLE" in
    taa-train-dcu|taa-infer-dcu) return 0 ;;
    *) return 1 ;;
  esac
}

# Extended resource the test Pod must request for the card to reach the guest.
# Empty for roles that do not need a device.
role_device_resource() {
  case "$TAA_ROLE" in
    taa-train-dcu|taa-infer-dcu) echo hygon.cn/k100_ai=1 ;;
    *) echo "" ;;
  esac
}

# The guest kernel and Kata template the role boots. The DCU runtime uses its
# own kernel (a different release with the hycu patches) and its own shipped
# config, so both the fetch and the render follow the role instead of taking a
# separate flag that could disagree with the package directory.
role_kernel_src() {
  case "$TAA_ROLE" in
    taa-train-dcu|taa-infer-dcu) echo /opt/kata/share/kata-containers/vmlinuz-hycu-confidential-csv.container ;;
    *) echo /opt/kata/share/kata-containers/vmlinuz-confidential-csv.container ;;
  esac
}

role_kata_config_src() {
  case "$TAA_ROLE" in
    taa-train-dcu|taa-infer-dcu) echo /opt/kata/share/defaults/kata-containers/configuration-qemu-hygon-dcu-csv2.toml ;;
    *) echo /opt/kata/share/defaults/kata-containers/configuration-qemu-csv2.toml ;;
  esac
}

role_test_pod_run_as_user() {
  case "$TAA_ROLE" in
    taa-analysis) echo 0 ;;
    *) echo "" ;;
  esac
}

# Guest RAM for the role, in MiB. This is a runtime floor, not a tuning knob: a
# CSV2 guest's writable root is a tmpfs capped at roughly half the guest RAM, and
# CDH unpacks the container image into it. The base template's 2048 leaves ~1 GiB
# for an image that unpacks to 1.92 GB, so the pull dies with "Failed to unpack
# layer" and the Pod lands in StartError -- which reads like an initrd failure but
# is not one.
#
# The values are the ones measured working on the host, not a formula. The test
# Pod sets no limits, so QEMU's -m is this number alone; with a Pod that does set
# limits.memory, Kata adds it on top.
#   train/infer  10240 -> tmpfs 4.75 GiB for a 2.02 GiB unpack (taa-env,
#                2170275081 B), verified Running with 2.2 GiB used.
#   analysis     20480 -> tmpfs ~10 GiB for a 6.90 GiB unpack
#                (jupyter-nologin-full, 7411037667 B), the size the deployed
#                analysis Pod runs at.
role_default_memory() {
  case "$TAA_ROLE" in
    taa-train|taa-infer) echo 10240 ;;
    taa-analysis) echo 20480 ;;
    # A DCU guest runs the DTK image, which unpacks to roughly the same size as
    # the analysis image above (~6.9 GiB), so it needs the same tmpfs headroom.
    taa-train-dcu|taa-infer-dcu) echo 20480 ;;
  esac
}

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
# The initrd runs the same template as the production Pod. It used to carry a
# copy of its own (configs/taa-initrd.json), which drifted: a field added to one
# template and not the other would build and boot, and only the behaviour in the
# guest would differ. Deployment-specific values that the guest cannot receive
# from the Pod (registration identity, platform key, LLM endpoint) travel through
# /etc/default/taa.env instead, so the file stays role-shaped rather than
# deployment-shaped.
TAA_CONFIG_SRC="${TAA_CONFIG_SRC:-$ROOT_DIR/configs/taa-production.json}"
BASE_INITRD="${BASE_INITRD:-$SCRIPT_DIR/base/kata-containers-initrd-confidential-csv.img}"
OUT_DIR="${OUT_DIR:-$SCRIPT_DIR/out}"
# Per role: the built image differs between roles (the semgrep payload, the
# baked CONTRACT_TYPE), and one shared output file would leave whichever role
# built last as the one every role packages. train keeps the historical name so
# an existing out/ directory is still the train image.
case "$TAA_ROLE" in
  taa-train) INITRD_OUT_DEFAULT="$OUT_DIR/kata-containers-initrd-taa-csv.initrd" ;;
  *) INITRD_OUT_DEFAULT="$OUT_DIR/kata-containers-initrd-${TAA_ROLE}.initrd" ;;
esac
INITRD_OUT="${INITRD_OUT:-$INITRD_OUT_DEFAULT}"
# Cached seed images, one per payload class (see build_initrd). They hold the
# base initrd with the semgrep payload folded in, or without it, and never TAA.
# Overridable so a caller can keep a warm cache outside the checkout.
SEED_DIR="${SEED_DIR:-$OUT_DIR/seeds}"

# Renderer support files. The Kata config template is host-authoritative like
# the base initrd: fetch-base copies it, and `render` refuses to guess when it is
# missing. Its default lives next to REMOTE_KATA_CONFIG_SRC below, because the
# DCU roles use a different template file with a different name.
RENDER_DIR="${RENDER_DIR:-$SCRIPT_DIR/render}"

# Optional semgrep payload. The injected config selects the scan engine, so
# the payload is only required when that config asks for semgrep -- but when it
# does, the guest has to carry its own interpreter and wheels: the base initrd
# has neither python3 nor semgrep, and TAA resolves the semgrep CLI through PATH.
# Build it with build-semgrep-payload.sh; it is gitignored because of its size.
TAA_SEMGREP_PAYLOAD_DIR="${TAA_SEMGREP_PAYLOAD_DIR:-$SCRIPT_DIR/semgrep-payload}"

# DCU driver payload. The hycu modules and their firmware exist only inside the
# DCU guest image's rootfs, and the base initrd has neither them nor kmod, so a
# DCU initrd has to carry the whole tree plus the module loader. fetch-base
# extracts it from the image (see fetch_dcu_payload); the layout mirrors the
# semgrep payload, rootfs/ prefixed by the guest paths it will occupy.
DCU_PAYLOAD_DIR="${DCU_PAYLOAD_DIR:-$SCRIPT_DIR/base/dcu-payload}"
# The installed DCU guest image; fetch-base reads the modules out of it.
DCU_REMOTE_IMAGE="${DCU_REMOTE_IMAGE:-/opt/kata/share/kata-containers/kata-containers-2026-10-27-13:31:15.991899743+0000-63f5ac56d-hycu-csv.img}"

# Runtime configuration written into the init wrapper. These defaults must stay
# in sync with the literal defaults in taa-init.sh: the wrapper is a standalone
# file now (no heredoc, which needed dozens of escaped variables), and build-time
# overrides reach it through /etc/default/taa.env.
# PLATFORM_IP and DOCKER_ID are optional at build time: they only affect
# registration with the management platform, and a failed registration is just a
# warning inside TAA. deploy/all still require the env file by default, because
# the production flow wants registration to succeed.
TAA_ADDR_DEFAULT="0.0.0.0:6001"

TAA_ADDR="${TAA_ADDR:-$TAA_ADDR_DEFAULT}"
TAA_PLATFORM_IP="${TAA_PLATFORM_IP:-}"
TAA_DOCKER_ID="${TAA_DOCKER_ID:-}"
ALLOW_MISSING_TAA_ENV="${ALLOW_MISSING_TAA_ENV:-0}"

# The deployment's startup settings. The Pod's environment cannot reach the
# initrd (TAA starts before kata-agent, and nothing injects env into the guest),
# so they arrive by one of two routes: the kernel command line rendered by
# `render` (`taa.<key>=<value>`, read by taa-init from /proc/cmdline and the one
# that wins), or /etc/default/taa.env baked into the image as the fallback. The
# config file stays the role template; these are the deployment's identity and
# keys.
#
# PLATFORM_PUBLIC_KEY is the one setting TAA cannot start without: every
# platform message is sealed with it, and TAA exits 1 rather than fall back to
# plaintext. Because the guest has no other injection path, a build without it
# produces an initrd that boots but whose TAA exits 1 on every start, so the
# restart loop just backs off and the guest reports nothing useful. The build
# therefore refuses unless it can resolve one.
#
# Resolution order: PLATFORM_PUBLIC_KEY (TAA's own name) > TAA_PLATFORM_PUBLIC_KEY
# > TAA_PLATFORM_KEY_FILE. The key file is read from the platform-mock's state
# file format (field publicKeyHex) or as bare hex, so the mock's own file needs
# no copy-paste step; the default points at the state directory this repository
# uses for the platform-mock on the build host.
TAA_PLATFORM_KEY_FILE="${TAA_PLATFORM_KEY_FILE:-$ROOT_DIR/.local/platform-mock/platform-key.json}"
TAA_PLATFORM_PUBLIC_KEY="${TAA_PLATFORM_PUBLIC_KEY:-${PLATFORM_PUBLIC_KEY:-}}"
# Optional envelope identity overrides and the LLM endpoint. Empty means the
# protocol default (PLATFORM_SM2_ID), the config file (CONTRACT_ID) or the
# endpoint in the config file (TAA_LLM_ENDPOINT).
#
# TAASECRETKEY is carried as well, but it is not a plaintext secret: it is the
# SM4-GCM ciphertext of the private scalar under SM3(csv hardware sealing key ||
# CONTRACT_ID)[:16]. A host that reads the command line cannot decrypt it; it
# can only re-inject the wrapped form, which is precisely the recovery TAA
# implements. The raw private key still never appears here.
TAA_PLATFORM_SM2_ID="${TAA_PLATFORM_SM2_ID:-}"
TAA_CONTRACT_ID="${TAA_CONTRACT_ID:-}"
TAA_SECRET_KEY="${TAASECRETKEY:-}"
# The role sets this, not the operator: it is the one value that makes the guest
# behave as the package's role. Letting an inherited TAA_CONTRACT_TYPE win would
# produce a package whose directory and handler say "infer" while the guest
# audits like a training instance, and nothing downstream would notice. A value
# that disagrees is reported and discarded rather than silently obeyed.
if [[ -n "${TAA_CONTRACT_TYPE:-}" && "$TAA_CONTRACT_TYPE" != "$(role_contract_type)" ]]; then
  echo "warning: 忽略 TAA_CONTRACT_TYPE=$TAA_CONTRACT_TYPE：角色 $TAA_ROLE 固定为 CONTRACT_TYPE=$(role_contract_type)" >&2
fi
TAA_CONTRACT_TYPE="$(role_contract_type)"
TAA_LLM_ENDPOINT="${TAA_LLM_ENDPOINT:-}"
# Kernel modules the guest wrapper loads at boot (comma-separated). It travels as
# taa.taa_modules= on the kernel command line, like the rest of the identity, so
# an operator can change it without rebuilding the measured initrd.
TAA_MODULES="${TAA_MODULES:-$(role_kernel_modules)}"

# Read the platform public key from a key file. The platform-mock persists
# {"privateKeyPem": ..., "publicKeyHex": "04..."}; a file that is just the hex
# string is accepted as well. Nothing here is secret, so reading it from the
# build host is fine -- what this removes is a copy-paste step that, when
# skipped, produced an initrd whose TAA exits at startup.
resolve_platform_public_key() {
  local value=""
  if [[ -n "$TAA_PLATFORM_PUBLIC_KEY" ]]; then
    printf '%s' "$TAA_PLATFORM_PUBLIC_KEY"
    return 0
  fi
  [[ -r "$TAA_PLATFORM_KEY_FILE" ]] || return 1
  value="$(sed -n 's/.*"publicKeyHex"[[:space:]]*:[[:space:]]*"\([0-9a-fA-F]*\)".*/\1/p' "$TAA_PLATFORM_KEY_FILE" | head -n 1)"
  if [[ -z "$value" ]]; then
    value="$(tr -d '[:space:]' < "$TAA_PLATFORM_KEY_FILE" 2>/dev/null || true)"
  fi
  printf '%s' "$value"
}

# Published wire format: 04 || X (32 bytes) || Y (32 bytes), lowercase or upper
# hex. Checked here rather than left to TAA: the failure otherwise only shows up
# after a full boot, as a guest that hangs with a log nobody is looking at.
platform_public_key_valid() {
  [[ "$1" =~ ^04[[:xdigit:]]{128}$ ]]
}

ensure_platform_public_key() {
  if [[ -z "$TAA_PLATFORM_PUBLIC_KEY" ]]; then
    TAA_PLATFORM_PUBLIC_KEY="$(resolve_platform_public_key || true)"
  fi
  if [[ -n "$TAA_PLATFORM_PUBLIC_KEY" ]] && ! platform_public_key_valid "$TAA_PLATFORM_PUBLIC_KEY"; then
    echo "error: 平台 SM2 公钥不是 130 位十六进制（04 || X || Y）" >&2
    echo "       来源: 环境变量 PLATFORM_PUBLIC_KEY / TAA_PLATFORM_PUBLIC_KEY" >&2
    echo "       或文件: $TAA_PLATFORM_KEY_FILE" >&2
    exit 1
  fi
}

# The env file carries every runtime switch of the wrapper. It has to be written
# as soon as a registration identity or the platform key is given, or any switch
# is explicitly moved off its default; otherwise a build-time override would
# silently do nothing.
taa_env_file_needed() {
  if [[ -n "$TAA_PLATFORM_PUBLIC_KEY" ]]; then
    return 0
  fi
  if [[ -n "$TAA_PLATFORM_IP" && -n "$TAA_DOCKER_ID" ]]; then
    return 0
  fi
  [[ "$TAA_ADDR" != "$TAA_ADDR_DEFAULT" ]] && return 0
  [[ -n "$TAA_PLATFORM_SM2_ID$TAA_CONTRACT_ID$TAA_CONTRACT_TYPE$TAA_LLM_ENDPOINT" ]] && return 0
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
REMOTE_BASE_INITRD_SRC="${REMOTE_BASE_INITRD_SRC:-/opt/kata/share/kata-containers/kata-containers-initrd-confidential-csv.img}"
REMOTE_KERNEL_SRC="${REMOTE_KERNEL_SRC:-$(role_kernel_src)}"
REMOTE_OVMF_SRC="${REMOTE_OVMF_SRC:-/opt/kata/share/ovmf/OVMFCSV.fd}"
REMOTE_KATA_CONFIG_SRC="${REMOTE_KATA_CONFIG_SRC:-$(role_kata_config_src)}"
# Where the delivery package lives on the host. The package is a runtime
# dependency, not just a shipping container: it carries the initrd, the kernel
# and the OVMF firmware, the Kata config points at those in-package copies, and
# install.sh reads nothing from the host's own Kata installation. That is what
# makes the package deployable on a machine whose /opt/kata holds different
# files, or none at all, and it is why nothing is copied on the host.
#
# It must stay persistent: the Kata config and the files QEMU boots are inside
# it, so removing it breaks the runtime handler.
#
# One directory per role, all of them role-suffixed. The Kata config names
# absolute paths into this exact directory and containerd resolves that config
# whenever a Pod of the role's handler starts, so two roles sharing it would
# silently boot each other's kernel and initrd.
TAA_IMAGES_DIR="${TAA_IMAGES_DIR:-/root/taa-images}"
REMOTE_PACKAGE_DIR="${REMOTE_PACKAGE_DIR:-$TAA_IMAGES_DIR/$(role_package_subdir)}"
# Derived, never overridable: the rendered kernel/initrd/firmware paths and the
# package's own layout have to name the same directory.
PACKAGE_BUNDLE_SUBDIR="bundle"
REMOTE_BUNDLE_DIR="$REMOTE_PACKAGE_DIR/$PACKAGE_BUNDLE_SUBDIR"
# The Kata config the runtime handler points at (containerd's ConfigPath). It is
# rendered into the delivery package and the handler points at the packaged file,
# so the package is the host's only copy and install.sh installs nothing under
# /etc. Derived, never overridable: package_info resolves ConfigPath back to this
# exact path, so a package rendered with any other value could not install.
PACKAGE_KATA_CONFIG="kata-config.toml"
PACKAGE_IMAGE_SUBDIR="image"
REMOTE_KATA_CONFIG="$REMOTE_PACKAGE_DIR/$PACKAGE_KATA_CONFIG"
CONTAINERD_CONFIG="${CONTAINERD_CONFIG:-/etc/containerd/config.toml}"
KATA_HYPERVISOR_SECTION="${KATA_HYPERVISOR_SECTION:-hypervisor.qemu}"
# Guest RAM, in MiB. A CSV2 guest's writable root is a tmpfs capped at roughly
# half the guest RAM, and the CDH unpacks the container image into it, so this
# has to fit the role's image. Defaulted per role by role_default_memory(); set
# it to override, or to empty to keep the template's value.
KATA_DEFAULT_MEMORY="${KATA_DEFAULT_MEMORY:-$(role_default_memory)}"
RUNTIME_HANDLER="${RUNTIME_HANDLER:-$(role_runtime_handler)}"
RUNTIME_TYPE="${RUNTIME_TYPE:-$(role_runtime_type)}"
RUNTIME_PATH="${RUNTIME_PATH:-/opt/kata/bin/containerd-shim-kata-v2}"
SNAPSHOTTER="${SNAPSHOTTER:-nydus}"
RESTART_KUBELET="${RESTART_KUBELET:-0}"
# Default delivery package location. `render` overwrites it; `launch` renders
# into a temporary directory unless LAUNCH_KEEP_DIST=1.
DIST_DIR="${DIST_DIR:-$SCRIPT_DIR/dist/$RUNTIME_HANDLER}"
TEST_NODE_NAME="${TEST_NODE_NAME:-}"
TEST_POD_NAME="${TEST_POD_NAME:-$(role_test_pod_name)}"
# The numeric uid the rendered test Pod runs as. Empty means "whatever the image
# declares". The data-analysis base names its user (jovyan), and under the nydus
# guest-pull snapshotter containerd resolves that name against an /etc/passwd the
# host-side snapshot does not carry, so the Pod never reaches the guest; a
# numeric uid needs no lookup. See clean-image/Dockerfile for the other half of
# this: images built here set USER 0 for the same reason.
TEST_POD_RUN_AS_USER="${TEST_POD_RUN_AS_USER:-$(role_test_pod_run_as_user)}"
# The image is pulled by CDH *inside* the guest, which has no route to Docker
# Hub -- measured on 2026-10-10: busybox:latest failed with "error sending
# request for url (https://index.docker.io/...)" after the 180s wait. So the
# default is an image from the registry on the host itself (the same one the
# CoCo Pods already running here pull successfully).
#
# The default follows the role. train and infer share the TAA-free taa-env
# variant: TAA already runs from this package's initrd, and an image carrying
# its own copy gives the guest two (see clean-image/Dockerfile for how it is
# built). The earlier default, slim-v2-20260916, is also gone from the registry
# -- only local docker and containerd copies remained, so a fresh host could
# never pull it. The data-analysis role uses the jupyter base instead, whose
# runtime owns /home/jovyan.
TEST_IMAGE="${TEST_IMAGE:-$(role_test_image)}"
# Extended resource the test Pod requests, as NAME=COUNT. Empty for roles that
# need no device. The card is attached through the resource request itself (the
# device plugin's CDI path), so a Pod that omits it boots a guest without a DCU.
TEST_POD_DEVICE_RESOURCE="${TEST_POD_DEVICE_RESOURCE:-$(role_device_resource)}"
# Optional `docker save` archive of TEST_IMAGE. When set, the package carries it
# under image/ and install.sh loads and pushes it if the registry lacks the tag.
# A CoCo guest pulls the image itself through CDH, so the archive has to reach
# the registry, not just the host's docker daemon. Empty means "expect the
# registry to already hold the image".
TEST_IMAGE_ARCHIVE="${TEST_IMAGE_ARCHIVE:-}"
# Extra annotations for the rendered test Pod, as a JSON object.
#
# The one a CoCo guest needs (io.katacontainers.config.runtime.cc_init_data) is
# deliberately not defaulted here: it embeds the CA of the registry on the
# target host, so it is per-host, and it is ~2 KiB of base64 that would bloat
# every render. test/create-test-pod.sh reads it from the host at apply time
# instead, so the operator never passes it. Set this only for annotations that
# genuinely belong to the package.
TEST_POD_ANNOTATIONS="${TEST_POD_ANNOTATIONS:-{\}}"
# Render-time only: the cached base Kata config is compared against the host's
# copy before it is used as a template. install.sh no longer repeats this check;
# the package carries the whole rendered config, so a different host Kata is a
# warning there, not a refusal.
SKIP_KATA_TEMPLATE_CHECK="${SKIP_KATA_TEMPLATE_CHECK:-0}"
# The kernel and OVMF the package ships, and the inputs of the expected CSV2
# MEASUREMENT. render() requires both to exist; the initrd is $INITRD_OUT, so
# `build` has to run first. MEASURE_APPEND replaces the auto-derived QEMU
# -append string.
MEASURE_OVMF="${MEASURE_OVMF:-$SCRIPT_DIR/base/$(basename "$REMOTE_OVMF_SRC")}"
MEASURE_KERNEL="${MEASURE_KERNEL:-$SCRIPT_DIR/base/$(basename "$REMOTE_KERNEL_SRC")}"
# The template follows the same rule as the kernel: its local name is the remote
# file's basename. The DCU roles fetch a differently named template, and a fixed
# name here made the consistency check compare the CPU template with the DCU
# one and fail after the initrd had already been built.
KATA_CONFIG_TEMPLATE="${KATA_CONFIG_TEMPLATE:-$SCRIPT_DIR/base/$(basename "$REMOTE_KATA_CONFIG_SRC")}"
MEASURE_SMP="${MEASURE_SMP:-}"
MEASURE_APPEND="${MEASURE_APPEND:-}"

# 打印支持的子命令和主要环境变量覆盖项。脚本默认执行 build，
# 因此本地反复调试是安全的；只有显式指定 upload、launch 或 all 时才会触碰远程服务器。
usage() {
  cat <<EOF
Usage: $0 [taa-train|taa-infer|taa-analysis|taa-train-dcu|taa-infer-dcu] [build|fetch-base|render|upload|launch|all|print-config]

Role (first word, or TAA_ROLE; default taa-train):
  taa-train     Training instance. CONTRACT_TYPE=1, its own handler and package
                directory, and the only non-DCU role whose initrd carries the
                semgrep payload.
  taa-infer     Inference instance. CONTRACT_TYPE=2, its own handler and package
                directory, no semgrep payload.
  taa-analysis  Data-analysis instance. CONTRACT_TYPE=3, its own handler and
                package directory, the jupyter base image, no semgrep payload.
                Its injected config selects the built-in regex engine instead.
  taa-train-dcu Training instance on the Hygon DCU full-encryption runtime.
                CONTRACT_TYPE=1, handler kata-qemu-dcu-csv2-taa-train,
                the semgrep payload, the DCU kernel and the hycu driver tree.
  taa-infer-dcu Inference on the same DCU runtime. CONTRACT_TYPE=2, no semgrep
                payload, same kernel and driver tree. `taa-infer-duc` is accepted
                as an alias of this role.
  The role decides the default INITRD_OUT, DIST_DIR, RUNTIME_HANDLER,
  RUNTIME_TYPE, REMOTE_KERNEL_SRC, REMOTE_PACKAGE_DIR, TEST_POD_NAME,
  TEST_IMAGE and KATA_DEFAULT_MEMORY; each of those still accepts an explicit
  override.

Commands:
  build       Build $INITRD_OUT from $BASE_INITRD and inject TAA + init wrapper.
              The base (plus the semgrep and DCU payloads the role names) comes
              from a cached seed image under $SEED_DIR, so only TAA is repacked
              on a rerun; a changed base or payload rebuilds the seed once.
  fetch-base  Copy the real base initrd, kernel, OVMF and shipped Kata config
              from $REMOTE into $(basename "$SCRIPT_DIR")/base/. A DCU role also
              extracts the hycu modules, their firmware and kmod out of the DCU
              guest image into base/dcu-payload/.
  render      Render the Kata config, containerd handler, K8s manifests, the
              install script and the guest bundle (initrd, kernel, OVMF) into
              $DIST_DIR. Local only; no host access.
  upload      Render the package and upload the whole thing to
              $REMOTE_PACKAGE_DIR on $REMOTE. No install: the host is only
              given the files, untouched by install.sh.
  launch      Render locally, upload the whole package, then install it on
              $REMOTE. Nothing is copied on the host.
  all         Run build, then launch.
  print-config  Print the resolved remote/test settings as sourceable KEY=value
                lines. Internal interface for deploy-taa-vm.sh, so that the
                defaults above have exactly one definition.

Environment overrides:
  TAA_ROLE=$TAA_ROLE
  RUNTIME_HANDLER=$RUNTIME_HANDLER                    (default: from TAA_ROLE)
  REMOTE_PACKAGE_DIR=$REMOTE_PACKAGE_DIR              (default: from TAA_ROLE)
  TEST_POD_NAME=$TEST_POD_NAME                        (default: from TAA_ROLE)
  TEST_IMAGE=$TEST_IMAGE                              (default: from TAA_ROLE)
  TEST_POD_RUN_AS_USER=${TEST_POD_RUN_AS_USER:-(image default)}
  REMOTE_USER=$REMOTE_USER
  REMOTE_HOST=$REMOTE_HOST
  REMOTE_BASE_INITRD_SRC=$REMOTE_BASE_INITRD_SRC
  REMOTE_KERNEL_SRC=$REMOTE_KERNEL_SRC
  REMOTE_OVMF_SRC=$REMOTE_OVMF_SRC
  REMOTE_KATA_CONFIG_SRC=$REMOTE_KATA_CONFIG_SRC
  REMOTE_KATA_CONFIG=$REMOTE_KATA_CONFIG
                                          (derived; always the packaged copy)
  REMOTE_BUNDLE_DIR                       derived as $REMOTE_PACKAGE_DIR/bundle
  KATA_HYPERVISOR_SECTION=$KATA_HYPERVISOR_SECTION
  KATA_DEFAULT_MEMORY=$KATA_DEFAULT_MEMORY               (default: from TAA_ROLE)
  RUNTIME_TYPE=$RUNTIME_TYPE
  RUNTIME_PATH=$RUNTIME_PATH
  SNAPSHOTTER=$SNAPSHOTTER
  RESTART_KUBELET=$RESTART_KUBELET
  TEST_NODE_NAME=$TEST_NODE_NAME
  TEST_POD_NAME=$TEST_POD_NAME
  TEST_IMAGE=$TEST_IMAGE
  TEST_IMAGE_ARCHIVE=${TEST_IMAGE_ARCHIVE:-(none; the registry must already hold TEST_IMAGE)}
  TEST_POD_DEVICE_RESOURCE=${TEST_POD_DEVICE_RESOURCE:-(none)}
  TEST_POD_ANNOTATIONS=$TEST_POD_ANNOTATIONS
  TAA_ADDR=$TAA_ADDR
  TAA_PLATFORM_IP=$TAA_PLATFORM_IP
  TAA_DOCKER_ID=$TAA_DOCKER_ID
  PLATFORM_PUBLIC_KEY / TAA_PLATFORM_PUBLIC_KEY  平台 SM2 公钥（TAA 必需，见下方说明）
  TAA_PLATFORM_KEY_FILE=$TAA_PLATFORM_KEY_FILE
  TAA_PLATFORM_SM2_ID=$TAA_PLATFORM_SM2_ID
  TAA_CONTRACT_ID=$TAA_CONTRACT_ID
  TAA_CONTRACT_TYPE=$TAA_CONTRACT_TYPE
  TAA_LLM_ENDPOINT=$TAA_LLM_ENDPOINT
  TAA_MODULES=${TAA_MODULES:-(none)}
  DCU_PAYLOAD_DIR=$DCU_PAYLOAD_DIR
  DCU_REMOTE_IMAGE=$DCU_REMOTE_IMAGE
  ALLOW_MISSING_TAA_ENV=$ALLOW_MISSING_TAA_ENV
  SKIP_KATA_TEMPLATE_CHECK=$SKIP_KATA_TEMPLATE_CHECK
  CONTAINERD_CONFIG=$CONTAINERD_CONFIG
  KATA_CONFIG_TEMPLATE=$KATA_CONFIG_TEMPLATE
  DIST_DIR=$DIST_DIR
  LAUNCH_KEEP_DIST=${LAUNCH_KEEP_DIST:-0}

  # render ships these two in the package and computes the expected digest from
  # the packaged copies; the initrd is INITRD_OUT, so `build` has to run first.
  MEASURE_OVMF=$MEASURE_OVMF
  MEASURE_KERNEL=$MEASURE_KERNEL
  MEASURE_SMP=${MEASURE_SMP:-(from default_vcpus)}
  MEASURE_APPEND=${MEASURE_APPEND:-(derived from the rendered config)}

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

  PLATFORM_PUBLIC_KEY is required: TAA seals every platform message with it and
  exits 1 without one. The build reads it from the environment, or from
  TAA_PLATFORM_KEY_FILE (default: the platform-mock state file,
  .local/platform-mock/platform-key.json; it accepts that file's publicKeyHex
  field or a bare hex string). ALLOW_MISSING_TAA_ENV=1 skips the requirement for
  a build that has another injection path.

  These values are not frozen into the image. render (and launch) writes them
  onto the kernel command line as taa.<key>=<value>; taa-init reads that back
  from /proc/cmdline and lets it override the baked /etc/default/taa.env. So
  changing PLATFORM_IP, DOCKER_ID, PLATFORM_PUBLIC_KEY, PLATFORM_SM2_ID,
  CONTRACT_ID, CONTRACT_TYPE or TAA_LLM_ENDPOINT is a re-render plus install,
  not a rebuild: the initrd bytes stay as they are. The command line is part of
  the CSV2 measurement, so the identity is still covered by MEASUREMENT -- but
  it is also visible to the host in QEMU's -append, so secrets belong nowhere
  near it (TAASECRETKEY is never carried at all).
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
  # Multi-member aware: see archive_manifest. A plain `cpio -t | grep` would only
  # ever see the seed's entries and call the TAA member's files missing.
  python3 "$SCRIPT_DIR/initramfs.py" has "$img" "$entry"
}

# A built image is a concatenation of gzip members: the seed (base initrd, plus
# the semgrep payload for the training role) and then the TAA member. Plain
# `cpio -t` stops at the first TRAILER and would report every entry of the TAA
# member as missing, so listing goes through initramfs.py, which slices the file
# at member boundaries. The kernel reads all members, so this is the same view
# the guest gets.
archive_manifest() {
  local img="$1"
  local manifest="$2"
  python3 "$SCRIPT_DIR/initramfs.py" list "$img" > "$manifest"
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

# Both conditions, because either one alone is wrong. The role decides whether a
# payload belongs in this image at all -- inference and data analysis do not
# audit code where it lands, so a 350 MiB interpreter and scanner would only
# raise the measured image -- and the config decides whether the guest will ask
# for one. build_initrd rewrites the injected config for a non-training role, so
# the two agree by construction; this function states the requirement once for
# the build-time check.
initrd_wants_semgrep() {
  role_wants_semgrep && taa_config_wants_semgrep
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
  for input in "$TAA_INIT_SRC" "$TAA_CONFIG_SRC"; do
    if [[ ! -f "$input" ]]; then
      echo "error: missing build input: $input" >&2
      exit 1
    fi
  done

  if { [[ -n "$TAA_PLATFORM_IP" ]] && [[ -z "$TAA_DOCKER_ID" ]]; } || { [[ -z "$TAA_PLATFORM_IP" ]] && [[ -n "$TAA_DOCKER_ID" ]]; }; then
    echo "error: TAA_PLATFORM_IP and TAA_DOCKER_ID must be set together" >&2
    exit 1
  fi

  # TAA exits 1 at startup without the platform public key. An initrd built
  # without one is not "unregistered but working": TAA dies at boot and every
  # later API call fails. Refuse at build time with the sources that can fix it.
  ensure_platform_public_key
  if [[ -z "$TAA_PLATFORM_PUBLIC_KEY" && "$ALLOW_MISSING_TAA_ENV" != "1" ]]; then
    echo "error: 没有平台 SM2 公钥，guest 内的 TAA 会启动即退出" >&2
    echo "hint: 设置 PLATFORM_PUBLIC_KEY=<04||X||Y 的 130 位十六进制>" >&2
    echo "      或 TAA_PLATFORM_KEY_FILE=<含 publicKeyHex 的 JSON 文件>" >&2
    echo "      默认读取: $TAA_PLATFORM_KEY_FILE" >&2
    echo "hint: 只有确认另有注入路径时才用 ALLOW_MISSING_TAA_ENV=1 跳过这一检查" >&2
    exit 1
  fi

  # One entry per part of the payload that would be missed silently: the
  # interpreter, both PATH-visible CLI entry points (semgrep dispatches to the
  # OCaml CLI, which falls back to pysemgrep by name), the native scanner, and
  # the rules the engine stats at construction (NewEngine fails the whole audit
  # if the rules path is not a directory).
  if initrd_wants_semgrep; then
    local payload_entry
    for payload_entry in \
      "rootfs/usr/local/bin/python3.12" \
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

  # A DCU initrd without the driver tree boots fine and then has no card: the
  # hycu modules exist only in the DCU guest image, so the only fix is a fetch.
  if role_wants_dcu_payload; then
    local dcu_release
    dcu_release="$(sed -n 's/^release=//p' "$DCU_PAYLOAD_DIR/SOURCE" 2>/dev/null | head -n 1)"
    if [[ -z "$dcu_release" ]]; then
      echo "error: $TAA_ROLE 需要 DCU 驱动载荷，但 $DCU_PAYLOAD_DIR 尚未取回" >&2
      echo "hint: run '$0 fetch-base'（从 $REMOTE:$DCU_REMOTE_IMAGE 提取 hycu 模块与 kmod）" >&2
      exit 1
    fi
    if [[ ! -x "$DCU_PAYLOAD_DIR/rootfs/usr/bin/kmod" ]] ||
      ! find "$DCU_PAYLOAD_DIR/rootfs/usr/lib/modules/$dcu_release" -name 'hycu.ko' -print -quit |
        grep -q .; then
      echo "error: DCU 驱动载荷不完整（$dcu_release）: $DCU_PAYLOAD_DIR" >&2
      echo "hint: FORCE_DCU_PAYLOAD=1 $0 fetch-base 重新提取" >&2
      exit 1
    fi
  fi
}

# Copy the semgrep payload into the staging tree under the guest paths it will
# occupy. The payload mirrors the guest rootfs, so this is a single copy; `cp -a`
# keeps the modes and symlinks the wheel unpacking produced, none of which the
# builder's umask may touch (everything staged here lands in the measured image).
stage_semgrep_payload() {
  local stage_dir="$1"
  echo "注入 semgrep 载荷"

  local payload_root="$TAA_SEMGREP_PAYLOAD_DIR/rootfs"
  cp -a "$payload_root/." "$stage_dir/"

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

# Copy the DCU driver tree into the staging tree. The payload mirrors the guest
# rootfs (usr/lib/modules, usr/lib/firmware, usr/bin/kmod), so this is one copy.
stage_dcu_payload() {
  local stage_dir="$1"
  echo "注入 DCU 驱动载荷"

  local payload_root="$DCU_PAYLOAD_DIR/rootfs"
  cp -a "$payload_root/." "$stage_dir/"

  local payload_files payload_mib
  read -r payload_files payload_mib < <(
    find "$payload_root" -mindepth 1 -printf '%s\n' |
      awk '{n++; s += $1} END {printf "%d %.1f\n", n, s / 1048576}'
  )
  echo "DCU 载荷（未压缩，按文件大小计）: ${payload_mib} MiB / ${payload_files} 个文件"
}

# Install the injected TAA config into the staging tree.
#
# The training role takes the production template verbatim. The other two carry
# a copy whose `codeAudit.codeScan.engine` is "regex": they ship no semgrep
# payload, so leaving the template's "semgrep" in place would make every boot
# resolve an engine that cannot be constructed, log the fallback warning, and
# run regex anyway. A role that never audits is not worth a per-boot warning; a
# role whose config claims an engine it cannot run is a defect, not a warning.
#
# Only the engine is rewritten. Everything else stays as the production
# template says, so the operator reads one file shape whatever the role.
stage_taa_config() {
  local dst="$1/etc/taa/taa-config.json"
  if role_wants_semgrep; then
    install -m 0644 "$TAA_CONFIG_SRC" "$dst"
    return 0
  fi

  # A substitution rather than a JSON re-encode: the template may carry keys and
  # formatting (comments never, but ordering and spacing do) that a parse and
  # re-dump would silently normalise, and this file is inside the measured image.
  # The pattern is anchored on the key so only the engine's value changes.
  sed -E 's/("engine"[[:space:]]*:[[:space:]]*)"semgrep"/\1"regex"/' \
    "$TAA_CONFIG_SRC" > "$dst.tmp"
  install -m 0644 "$dst.tmp" "$dst"
  rm -f "$dst.tmp"

  if grep -qE '"engine"[[:space:]]*:[[:space:]]*"semgrep"' "$dst"; then
    echo "error: $TAA_ROLE does not carry the semgrep payload but the injected config still selects it" >&2
    echo "       file: $TAA_CONFIG_SRC" >&2
    exit 1
  fi
  echo "注入配置: $TAA_ROLE 角色，扫描引擎改写为 regex（本角色不带 semgrep 载荷）"
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
  echo "hint: 重新构建：TAA_PLATFORM_IP=${TAA_PLATFORM_IP:-<ip:port>} TAA_DOCKER_ID=${TAA_DOCKER_ID:-<id>} \\" >&2
  echo "      PLATFORM_PUBLIC_KEY=<130 hex，或 TAA_PLATFORM_KEY_FILE=<文件>> $0 build" >&2
}

# taa-init reads /etc/default/taa.env from inside the guest as its fallback
# environment. The deployment identity it actually uses comes from the kernel
# command line (rendered by `render`), which overrides that file; a mismatch here
# therefore no longer breaks the deployment. It is still worth reporting: it means
# the image was built for another platform, so if the command-line tokens were
# ever missing the guest would silently fall back to the old address, and the only
# symptom would be a platform that never hears from TAA.
check_initrd_identity() {
  local baked_env baked_platform baked_docker_id baked_public_key
  local want_platform want_docker_id want_public_key

  # Resolve the same way the build did, so a deploy invoked with only the key
  # file (or only the environment variable) still compares like with like.
  ensure_platform_public_key

  # The image is a concatenation of gzip members and the env file lives in the
  # last one, so `gzip -dc | cpio -i` would stop at the seed's TRAILER and read
  # nothing. initramfs.py walks every member; there is no temp directory to own
  # and nothing left behind if this exits midway.
  baked_env="$(python3 "$SCRIPT_DIR/initramfs.py" cat "$INITRD_OUT" etc/default/taa.env 2>/dev/null || true)"

  if [[ -z "$baked_env" ]]; then
    echo "error: 无法从 $INITRD_OUT 中读出 etc/default/taa.env" >&2
    exit 1
  fi

  baked_platform="$(sed -n 's/^export PLATFORM_IP=//p' <<<"$baked_env" | head -n 1)"
  baked_docker_id="$(sed -n 's/^export DOCKER_ID=//p' <<<"$baked_env" | head -n 1)"
  baked_public_key="$(sed -n 's/^export PLATFORM_PUBLIC_KEY=//p' <<<"$baked_env" | head -n 1)"

  # Compared in the %q form the writer below produces, not as raw values: a value
  # %q decides to quote is stored quoted, and comparing it raw would fail the
  # deploy for a difference that is only escaping.
  want_platform="$(printf '%q' "$TAA_PLATFORM_IP")"
  want_docker_id="$(printf '%q' "$TAA_DOCKER_ID")"
  want_public_key="$(printf '%q' "$TAA_PLATFORM_PUBLIC_KEY")"

  if [[ "$baked_platform" != "$want_platform" || "$baked_docker_id" != "$want_docker_id" ]]; then
    echo "warning: initrd 里烘焙的注册身份与本次调用不一致（以内核命令行上的为准）" >&2
    echo "         initrd: PLATFORM_IP=$baked_platform DOCKER_ID=$baked_docker_id" >&2
    echo "         本次:   PLATFORM_IP=$want_platform DOCKER_ID=$want_docker_id" >&2
  fi

  # The platform key is what TAA seals every message with. An image built against
  # a different platform key boots a TAA that registers nothing the platform can
  # read, so the rendered command line must carry the current one.
  if [[ "$baked_public_key" != "$want_public_key" ]]; then
    echo "warning: initrd 里烘焙的平台公钥与本次调用不一致（以内核命令行上的为准）" >&2
    echo "         initrd: PLATFORM_PUBLIC_KEY=${baked_public_key:-<缺失>}" >&2
    echo "         本次:   PLATFORM_PUBLIC_KEY=${want_public_key:-<未解析>}" >&2
  fi
}

# ── Seed images ─────────────────────────────────────────────────────────────
#
# Building an initrd used to mean decompressing the base, appending every
# payload file and gzip -9 over the whole thing again. The semgrep payload alone
# is ~350 MiB and gzip -9 over it costs ~110 s -- paid on every run even though
# neither the base nor the payload had changed.
#
# So the image is split in two. A *seed* is the base initrd with the semgrep
# payload folded in (training role) or without it (the other roles), and no TAA.
# It is built once and cached under $SEED_DIR, keyed by a fingerprint of its
# inputs. Every build then appends TAA -- a few MiB -- as a second gzip member.
#
# The kernel accepts that: concatenated gzip members are independent streams and
# Linux's initramfs unpacker consumes each one in turn. Verified on the Kata
# confidential kernel with two- and three-member images. `cpio` does not read
# past the first member, which is why every inspection goes through
# initramfs.py (see archive_manifest).

seed_kind() {
  local kind="plain"
  if initrd_wants_semgrep; then
    kind="semgrep"
  fi
  if role_wants_dcu_payload; then
    if [[ "$kind" == "semgrep" ]]; then
      kind="semgrep-dcu"
    else
      kind="dcu"
    fi
  fi
  echo "$kind"
}

# Content fingerprint of the payload tree: every path with its type, mode and
# symlink target, plus the hash of every regular file. A rebuild of the payload
# from the same wheels is a no-op; a different build (or a single edited file)
# invalidates the cached seed.
semgrep_payload_fingerprint() {
  local rootfs="$TAA_SEMGREP_PAYLOAD_DIR/rootfs"
  {
    ( cd "$rootfs" && find . -mindepth 1 -printf '%P\t%y\t%m\t%l\n' | LC_ALL=C sort )
    ( cd "$rootfs" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum )
  } | sha256sum | awk '{print $1}'
}

# Content fingerprint of the DCU driver tree, same shape as the semgrep one: a
# re-extraction of the same image is a no-op, a different image or an edited file
# invalidates the cached seed.
dcu_payload_fingerprint() {
  local rootfs="$DCU_PAYLOAD_DIR/rootfs"
  {
    ( cd "$rootfs" && find . -mindepth 1 -printf '%P\t%y\t%m\t%l\n' | LC_ALL=C sort )
    ( cd "$rootfs" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum )
  } | sha256sum | awk '{print $1}'
}

# Everything a cached seed depends on. Bump the format line when the seed layout
# itself changes, so an old cache cannot be mistaken for one built this way.
# (format=3 added the DCU payload and the combined semgrep-dcu seed.)
seed_fingerprint() {
  local kind="$1"
  printf 'format=3\n'
  printf 'base=%s\n' "$(sha256sum "$BASE_INITRD" | awk '{print $1}')"
  case "$kind" in
    semgrep|semgrep-dcu) printf 'semgrep_payload=%s\n' "$(semgrep_payload_fingerprint)" ;;
  esac
  case "$kind" in
    dcu|semgrep-dcu) printf 'dcu_payload=%s\n' "$(dcu_payload_fingerprint)" ;;
  esac
}

# Fill APPEND_ENTRIES with the paths under $1 that the image $2 does not already
# provide, parents before children and each path once.
#
# A directory the image already has is left alone: the kernel unpacks later
# members over earlier ones, so re-declaring an existing directory would replace
# its mode, owner and timestamp with the staging copy's. A *file* that already
# exists is still appended -- that is how a payload overlays a file.
#
# Sets rather than grep against the manifest: with the semgrep payload this runs
# over thousands of paths, and a fork per lookup would dominate the build.
plan_append_entries() {
  local stage_dir="$1"
  local known_manifest="$2"
  APPEND_ENTRIES=()
  local -A known=() queued=()

  while IFS= read -r entry; do
    known["$entry"]=1
  done < "$known_manifest"

  local path dir parents i parent
  # A C-locale sort puts every parent ahead of its children, which the parent
  # walk below relies on.
  while IFS= read -r path; do
    dir="$(dirname "$path")"
    parents=()
    while [[ "$dir" != "." && "$dir" != "/" ]]; do
      parents+=("$dir")
      dir="$(dirname "$dir")"
    done

    for ((i=${#parents[@]} - 1; i >= 0; i--)); do
      parent="${parents[$i]}"
      if [[ -n "${known[$parent]:-}" || -n "${queued[$parent]:-}" ]]; then
        continue
      fi
      queued["$parent"]=1
      APPEND_ENTRIES+=("$parent")
    done

    # The queue set guards this too: a directory reached here as a path is also
    # reached again as the parent of everything under it, and appending it
    # twice would overwrite the entry written by the first copy.
    if [[ -n "${queued[$path]:-}" ]]; then
      continue
    fi
    if [[ -n "${known[$path]:-}" && -d "$stage_dir/$path" ]]; then
      continue
    fi
    queued["$path"]=1
    APPEND_ENTRIES+=("$path")
  done < <( cd "$stage_dir" && find . -mindepth 1 -printf '%P\n' | LC_ALL=C sort )
}

# Write APPEND_ENTRIES from $1 into a newc archive at $2, owned by root. With $3
# set to "append" the archive is appended to instead of created.
write_entries_cpio() {
  local stage_dir="$1"
  local cpio_file="$2"
  local mode="${3:-create}"
  local -a append_flag=()
  if [[ "$mode" == append ]]; then
    append_flag=(-A)
  else
    rm -f "$cpio_file"
  fi
  if [[ "${#APPEND_ENTRIES[@]}" -eq 0 ]]; then
    return 0
  fi
  (
    cd "$stage_dir"
    printf '%s\n' "${APPEND_ENTRIES[@]}" |
      cpio -o -H newc -R 0:0 "${append_flag[@]}" -F "$cpio_file" --quiet
  )
}

# Produce (or reuse) the seed image for $1. Sets SEED_IMAGE and SEED_MANIFEST.
#
# The image is written under a temporary name and moved into place only once it
# is complete, so an interrupted build cannot leave a truncated seed that later
# runs would trust. Reuse requires image, manifest and stamp to agree; anything
# else rebuilds.
ensure_seed() {
  local kind="$1"
  local image="$SEED_DIR/seed-$kind.img"
  local manifest="$SEED_DIR/seed-$kind.manifest"
  local stamp="$image.stamp"
  local want
  want="$(seed_fingerprint "$kind")"

  if [[ -s "$image" && -s "$manifest" && -s "$stamp" && "$(cat "$stamp")" == "$want" ]]; then
    echo "复用 $kind 种子镜像: $image"
    SEED_IMAGE="$image"
    SEED_MANIFEST="$manifest"
    return 0
  fi

  echo "构建 $kind 种子镜像（首次或输入已变化）: $image"

  local seed_work="$BUILD_WORK_DIR/seed-$kind"
  mkdir -p "$seed_work"
  # Written under a temporary name and moved into place only once complete. The
  # paths are registered with the EXIT trap so a failed build leaves no partial
  # image behind for a later run to trust.
  SEED_TMP_IMAGE="$image.tmp.$$"
  SEED_TMP_MANIFEST="$manifest.tmp.$$"
  local image_tmp="$SEED_TMP_IMAGE"
  local manifest_tmp="$SEED_TMP_MANIFEST"

  case "$kind" in
    plain)
      # The base initrd already is the image the other roles need. Copying it
      # keeps the two seeds uniform for the rest of the build, at the cost of
      # one file copy.
      cp "$BASE_INITRD" "$image_tmp"
      cp "$BASE_MANIFEST" "$manifest_tmp"
      ;;
    semgrep|dcu|semgrep-dcu)
      mkdir -p "$seed_work/stage"
      case "$kind" in
        semgrep|semgrep-dcu) stage_semgrep_payload "$seed_work/stage" ;;
      esac
      case "$kind" in
        dcu|semgrep-dcu) stage_dcu_payload "$seed_work/stage" ;;
      esac

      # The staged tree lands in the measured image, so its modes are pinned
      # rather than inherited from the builder's umask. `cp -a` already carries
      # the payload's own modes; only the freshly created directories need it.
      find "$seed_work/stage" -type d -exec chmod 0755 {} +

      plan_append_entries "$seed_work/stage" "$BASE_MANIFEST"

      gzip -dc "$BASE_INITRD" > "$seed_work/base.cpio"
      write_entries_cpio "$seed_work/stage" "$seed_work/base.cpio" append
      gzip -n -9 < "$seed_work/base.cpio" > "$image_tmp"
      archive_manifest "$image_tmp" "$manifest_tmp"
      ;;
    *)
      echo "error: unknown seed kind: $kind" >&2
      exit 1
      ;;
  esac

  gzip -t "$image_tmp"
  mv "$image_tmp" "$image"
  mv "$manifest_tmp" "$manifest"
  printf '%s\n' "$want" > "$stamp.tmp.$$"
  mv "$stamp.tmp.$$" "$stamp"
  SEED_TMP_IMAGE=
  SEED_TMP_MANIFEST=

  SEED_IMAGE="$image"
  SEED_MANIFEST="$manifest"
}

# Build INITRD_OUT from the base initrd plus TAA.
#
# BASE_INITRD is never modified. The cached seed supplies the base (and the
# semgrep payload for the training role); this function stages only TAA, packs
# it as its own gzip member and concatenates that member onto the seed. The
# candidate is validated in full before it is moved over INITRD_OUT, so a failed
# build never replaces a good output.
build_initrd() {
  echo "校验输入"
  require_cmd gzip
  require_cmd cpio
  require_cmd install
  require_cmd grep
  require_cmd file
  require_cmd sha256sum
  require_cmd stat
  require_cmd cmp
  require_cmd python3
  check_build_inputs

  echo "准备临时目录"

  # 所有中间文件都放在唯一临时目录中。这里故意使用 EXIT 清理：
  # 即使构建中途校验失败，也会删除临时文件。
  BUILD_WORK_DIR="$(mktemp -d /tmp/taa-initrd-build.XXXXXX)"
  SEED_TMP_IMAGE=
  SEED_TMP_MANIFEST=
  cleanup_build() {
    rm -rf "${BUILD_WORK_DIR:-}"
    if [[ -n "${SEED_TMP_IMAGE:-}" ]]; then rm -f "$SEED_TMP_IMAGE"; fi
    if [[ -n "${SEED_TMP_MANIFEST:-}" ]]; then rm -f "$SEED_TMP_MANIFEST"; fi
  }
  trap cleanup_build EXIT

  mkdir -p "$OUT_DIR" "$SEED_DIR"

  # The base manifest drives both the duplicate guard and the plain seed, so it
  # is taken once even when a cached seed means the rest of the base is not read.
  BASE_MANIFEST="$BUILD_WORK_DIR/base.manifest"
  archive_manifest "$BASE_INITRD" "$BASE_MANIFEST"

  echo "拒绝重复注入的 base"

  # 拒绝把已经注入过的镜像当作 base。重复执行具备幂等性，
  # 因为每次都从 BASE_INITRD 开始并覆盖 INITRD_OUT；这个保护用于防止误把
  # 已注入输出文件当作新的 base。
  for injected in usr/local/bin/taa usr/local/bin/taa-init etc/taa/taa-config.json opt/taa/semgrep/MANIFEST; do
    if manifest_has_entry "$BASE_MANIFEST" "$injected"; then
      echo "error: base initrd already contains TAA payload path $injected; refusing to append a duplicate" >&2
      echo "hint: use the original remote Kata CSV initrd as $BASE_INITRD" >&2
      exit 1
    fi
  done

  local kind
  kind="$(seed_kind)"
  ensure_seed "$kind"

  local stage="$BUILD_WORK_DIR/taa"
  mkdir -p "$stage/usr/local/bin" "$stage/etc/taa"

  echo "注入 TAA"
  install -m 0755 "$TAA_SRC" "$stage/usr/local/bin/taa"

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
  install -m 0755 "$TAA_INIT_SRC" "$stage/usr/local/bin/taa-init"

  # TAA reads its config from a fixed absolute path, so the file has to be part
  # of the measured image. Training injects configs/taa-production.json as-is;
  # a non-training role injects a copy whose scan engine is the built-in regex
  # one, because no semgrep payload is seeded for it (see role_wants_semgrep).
  # Left selecting semgrep, the guest would log a fallback warning at every boot
  # and run the weaker engine anyway -- the config should say what runs.
  stage_taa_config "$stage"

  # The `python`/`python3` names are not added here: the semgrep payload ships
  # them next to its interpreter (see build-semgrep-payload.sh), so they exist
  # exactly in the images that carry Python. Adding them unconditionally would
  # put dangling links in the plain seed and turn "python is not installed" into
  # "python exists but cannot run".

  echo "生成可选 env 文件"

  # The guest-side fallback environment, written at build time. %q shell-escapes
  # the values so spaces or metacharacters are not reinterpreted when taa-init
  # sources this file. The kernel-command-line tokens rendered by `render` take
  # precedence over every name below; this file only has to be usable if they are
  # ever missing, which is why check_initrd_identity still reports a mismatch.
  if taa_env_file_needed; then
    mkdir -p "$stage/etc/default"
    {
      printf 'export TAA_ADDR=%q\n' "$TAA_ADDR"
      printf 'export PLATFORM_IP=%q\n' "$TAA_PLATFORM_IP"
      printf 'export DOCKER_ID=%q\n' "$TAA_DOCKER_ID"
      printf 'export PLATFORM_PUBLIC_KEY=%q\n' "$TAA_PLATFORM_PUBLIC_KEY"
      printf 'export PLATFORM_SM2_ID=%q\n' "$TAA_PLATFORM_SM2_ID"
      printf 'export CONTRACT_ID=%q\n' "$TAA_CONTRACT_ID"
      printf 'export CONTRACT_TYPE=%q\n' "$TAA_CONTRACT_TYPE"
      printf 'export TAA_LLM_ENDPOINT=%q\n' "$TAA_LLM_ENDPOINT"
    } > "$stage/etc/default/taa.env"
  fi

  # Staged entries end up inside the measured image, so their metadata has to be
  # a function of the inputs rather than of the builder's umask. `install -m`
  # pins the file modes; directories created with mkdir and the env file written
  # through a shell redirect would otherwise inherit the umask.
  # (The image is not bit-reproducible: newc records each entry's inode number
  # and mtime. That is why the summary prints the output sha256, and why deploy
  # verifies that hash on the remote side instead of rebuilding there.)
  find "$stage" -type d -exec chmod 0755 {} +
  if taa_env_file_needed; then
    chmod 0644 "$stage/etc/default/taa.env"
  fi

  echo "打包 TAA 成员"

  plan_append_entries "$stage" "$SEED_MANIFEST"
  write_entries_cpio "$stage" "$BUILD_WORK_DIR/taa.cpio" create
  gzip -n -9 < "$BUILD_WORK_DIR/taa.cpio" > "$BUILD_WORK_DIR/taa.cpio.gz"

  echo "拼接种子镜像并校验"

  local candidate="$BUILD_WORK_DIR/initrd.candidate"

  # The member must be a complete gzip stream before it is concatenated: a
  # truncated member still yields a readable image (the kernel stops wherever
  # decompression ends), but with contents this build never vouched for.
  if ! gzip -t "$BUILD_WORK_DIR/taa.cpio.gz" 2>/dev/null; then
    echo "error: TAA member is not a valid gzip stream" >&2
    exit 1
  fi

  cat "$SEED_IMAGE" "$BUILD_WORK_DIR/taa.cpio.gz" > "$candidate"

  # The seed half is verified by identity rather than by relisting it: it has to
  # be byte-for-byte the cached seed, which was fully listed when it was built
  # and whose stamp still matches its inputs. Relisting 160 MiB here would only
  # re-derive what the seed's own build already proved.
  local seed_size member_size candidate_size
  seed_size="$(stat -c %s "$SEED_IMAGE")"
  member_size="$(stat -c %s "$BUILD_WORK_DIR/taa.cpio.gz")"
  candidate_size="$(stat -c %s "$candidate")"
  if [[ "$candidate_size" -ne $((seed_size + member_size)) ]]; then
    echo "error: built initrd is not seed + TAA member: $candidate_size != $seed_size + $member_size" >&2
    exit 1
  fi
  if ! cmp -s -n "$seed_size" "$SEED_IMAGE" "$candidate"; then
    echo "error: built initrd does not start with the seed image bytes" >&2
    exit 1
  fi

  # The member must carry exactly the planned entries: a dropped path would
  # silently weaken the image, a repeated one would be unpacked over the first
  # and make the measurement depend on ordering. Both show up as a set mismatch.
  local member_manifest="$BUILD_WORK_DIR/taa.member.manifest"
  archive_manifest "$BUILD_WORK_DIR/taa.cpio.gz" "$member_manifest"
  printf '%s\n' "${APPEND_ENTRIES[@]}" | LC_ALL=C sort > "$BUILD_WORK_DIR/taa.expected"
  LC_ALL=C sort "$member_manifest" > "$BUILD_WORK_DIR/taa.actual"
  if ! cmp -s "$BUILD_WORK_DIR/taa.expected" "$BUILD_WORK_DIR/taa.actual"; then
    echo "error: TAA member entries do not match the planned list" >&2
    diff -u "$BUILD_WORK_DIR/taa.expected" "$BUILD_WORK_DIR/taa.actual" | head -n 40 >&2 || true
    exit 1
  fi

  local seed_count out_count
  seed_count="$(wc -l < "$SEED_MANIFEST")"
  out_count="$((seed_count + ${#APPEND_ENTRIES[@]}))"

  mv "$candidate" "$INITRD_OUT"

  echo "输出结果摘要"

  echo "base initrd: $BASE_INITRD"
  echo "base initrd sha256: $(sha256sum "$BASE_INITRD" | awk '{print $1}')"
  echo "seed: $SEED_IMAGE ($kind)"
  echo "seed cpio entries: $seed_count"
  echo "output initrd: $INITRD_OUT"
  echo "output cpio entries: $out_count"
  echo "appended entries (${#APPEND_ENTRIES[@]}):"
  # The list is written next to the image so the measurement's added paths can
  # be audited later; with the payload in the seed it stays short.
  entries_file="${INITRD_OUT}.entries"
  printf '%s\n' "${APPEND_ENTRIES[@]}" > "$entries_file"
  sed 's/^/  /' "$entries_file"
  echo "seed entries are in $SEED_MANIFEST"
}

# Copy the authoritative base assets from the host that runs Kata. A committed
# copy of these files goes stale silently -- the initrd that used to live in this
# repository was truncated, and cpio reported no error -- so the host is the only
# authority and this subcommand is how the build obtains its input.
# Fetch the DCU driver payload (hycu modules, firmware, kmod) out of the installed
# DCU guest image. The tree is stored under $DCU_PAYLOAD_DIR/rootfs, mirroring the
# guest paths it will occupy and the layout of the semgrep payload, so the seed
# builder can append it with the same walker.
#
# Reuse is keyed on a SOURCE file and the module directory; FORCE_DCU_PAYLOAD=1
# re-extracts. The remote helper (fetch-dcu-payload.sh) writes progress to stderr
# and the archive to stdout, so the archive is captured into a temporary file
# here and only then unpacked -- a dropped connection cannot leave a half-written
# tree that a later seed would trust.
fetch_dcu_payload() {
  local base_dir="$1"
  local dst="$base_dir/dcu-payload"
  local tree="$dst/rootfs"

  require_cmd ssh
  require_cmd tar
  require_cmd sha256sum
  require_cmd sed

  if [[ -s "$dst/SOURCE" && -d "$tree/usr/lib/modules" && "${FORCE_DCU_PAYLOAD:-0}" != "1" ]]; then
    echo "复用 DCU 驱动载荷: $dst（FORCE_DCU_PAYLOAD=1 可强制重新提取）"
    return 0
  fi

  echo "从 $REMOTE:$DCU_REMOTE_IMAGE 提取 DCU 内核模块、固件和 kmod"
  local image_sha
  if ! image_sha="$(ssh "$REMOTE" "sha256sum $(printf '%q' "$DCU_REMOTE_IMAGE")" 2>/dev/null | awk '{print $1}')" ||
    [[ -z "$image_sha" ]]; then
    echo "error: 无法读取 DCU guest 镜像: $REMOTE:$DCU_REMOTE_IMAGE" >&2
    exit 1
  fi

  local archive="$base_dir/dcu-payload.tar.zst.part"
  if ! ssh "$REMOTE" bash -s -- "$DCU_REMOTE_IMAGE" \
    <"$SCRIPT_DIR/fetch-dcu-payload.sh" >"$archive"; then
    rm -f "$archive"
    echo "error: 从 $REMOTE:$DCU_REMOTE_IMAGE 提取 DCU 载荷失败" >&2
    exit 1
  fi

  rm -rf "$dst"
  mkdir -p "$tree"
  if ! tar --zstd -xf "$archive" -C "$tree"; then
    rm -f "$archive"
    rm -rf "$dst"
    echo "error: 解包 DCU 载荷失败: $archive" >&2
    exit 1
  fi
  rm -f "$archive"

  local release="" candidate
  for candidate in "$tree"/usr/lib/modules/*; do
    [[ -d "$candidate" ]] || continue
    case "$(basename "$candidate")" in
      *hycu*) release="$(basename "$candidate")" && break ;;
    esac
  done
  if [[ -z "$release" ]] || [[ ! -x "$tree/usr/bin/kmod" ]]; then
    rm -rf "$dst"
    echo "error: DCU 载荷缺少 hycu 模块树或 kmod" >&2
    exit 1
  fi

  {
    printf 'image=%s\n' "$DCU_REMOTE_IMAGE"
    printf 'image_sha256=%s\n' "$image_sha"
    printf 'release=%s\n' "$release"
    printf 'fetched=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >"$dst/SOURCE"

  local payload_files payload_mib
  read -r payload_files payload_mib < <(
    find "$tree" -mindepth 1 -printf '%s\n' |
      awk '{n++; s += $1} END {printf "%d %.1f\n", n, s / 1048576}'
  )
  echo "DCU 载荷: $release, ${payload_mib} MiB / ${payload_files} 个文件"
  echo "  modules.dep: $( [[ -f "$tree/usr/lib/modules/$release/modules.dep" ]] && echo present || echo missing )"
}

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

  # The DCU roles boot a different kernel and need the out-of-tree hycu driver,
  # which only exists inside the DCU guest image. Fetching the image's module
  # tree is part of the role's base assets, not a separate step an operator has
  # to remember.
  if role_wants_dcu_payload; then
    fetch_dcu_payload "$base_dir"
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

  if [[ "$SKIP_KATA_TEMPLATE_CHECK" == "1" ]]; then
    echo "warning: SKIP_KATA_TEMPLATE_CHECK=1，跳过模板一致性校验" >&2
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
    echo "hint: 重新运行 $0 fetch-base 刷新模板，或设置 SKIP_KATA_TEMPLATE_CHECK=1" >&2
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
  if [[ ! -f "$RENDER_DIR/render.py" || ! -f "$RENDER_DIR/install.sh" ||
        ! -f "$RENDER_DIR/uninstall.sh" ||
        ! -f "$RENDER_DIR/create-test-pod.sh" || ! -f "$RENDER_DIR/delete-test-pod.sh" ]]; then
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

  # The guest's deployment identity travels on the kernel command line. taa-init
  # parses `taa.<key>=<value>` out of /proc/cmdline and lets those values override
  # the build-time env file. Kata appends a Pod's `kernel_params` annotation to
  # the runtime config's own parameters, so the tokens are written into the test
  # Pod's annotation below: the identity belongs to the Pod that runs, not to
  # every Pod sharing the runtime. Changing it is an edit of that manifest plus
  # `test/create-test-pod.sh`, with no rebuild and no package re-render. The
  # command line is part of the CSV2 measurement, so the identity is still
  # covered by the attested value -- see the notes in taa-init.sh.
  #
  # Built and validated before the package directory is touched: a bad value must
  # fail the render, not leave a half-written package or destroy the previous one.
  local -a kernel_params=()
  local resolved_public_key
  resolved_public_key="$(resolve_platform_public_key || true)"
  if [[ -n "$resolved_public_key" ]] && ! platform_public_key_valid "$resolved_public_key"; then
    echo "error: 平台 SM2 公钥格式不对（期望 04 + 128 位十六进制）: $resolved_public_key" >&2
    exit 1
  fi
  add_kernel_param() {
    local key="$1" value="$2"
    [[ -n "$value" ]] || return 0
    if [[ "$value" == *[[:space:]]* ]]; then
      echo "error: $key 含空白字符，无法写进内核命令行: $value" >&2
      exit 1
    fi
    kernel_params+=("taa.$key=$value")
  }
  add_kernel_param platform_ip "$TAA_PLATFORM_IP"
  add_kernel_param docker_id "$TAA_DOCKER_ID"
  add_kernel_param platform_public_key "$resolved_public_key"
  add_kernel_param platform_sm2_id "$TAA_PLATFORM_SM2_ID"
  add_kernel_param contract_id "$TAA_CONTRACT_ID"
  add_kernel_param contract_type "$TAA_CONTRACT_TYPE"
  add_kernel_param taa_llm_endpoint "$TAA_LLM_ENDPOINT"
  add_kernel_param taa_addr "$TAA_ADDR"
  # Not a TAA setting: taa-init consumes it before starting TAA. It rides the
  # same identity channel so the module list is part of the measured command
  # line and can be changed without rebuilding the initrd.
  add_kernel_param taa_modules "$TAA_MODULES"
  # Optional key recovery: the wrapped private scalar, never the raw key. The
  # token is the environment variable's own name in lower case, as every token
  # now is; taa-init upper-cases it back to TAASECRETKEY before starting TAA.
  add_kernel_param taasecretkey "$TAA_SECRET_KEY"

  # The package carries the three files QEMU boots. Shipping them is what lets
  # the same package be deployed on a host whose Kata installation lives
  # elsewhere, or does not exist: install.sh takes the kernel, initrd and OVMF
  # from the package and never copies anything out of the host's own tree.
  # Checked before the output directory is touched, so a missing input fails the
  # render instead of leaving a package that would not boot.
  require_cmd python3
  check_deploy_inputs
  local asset_src
  for asset_src in "$INITRD_OUT" "$MEASURE_KERNEL" "$MEASURE_OVMF"; do
    if [[ ! -f "$asset_src" ]]; then
      echo "error: 交付包缺少 guest 资产: $asset_src" >&2
      echo "hint: initrd 由 '$0 build' 生成；kernel/OVMF 由 '$0 fetch-base' 取到 $(dirname "$MEASURE_KERNEL")" >&2
      exit 1
    fi
  done

  # The Pod's image travels with the package when one is supplied. A CoCo guest
  # pulls it through CDH from the registry the Pod names, so the archive is not
  # for the host's docker: install.sh imports it and pushes it to that registry
  # only when the registry is missing the tag. Without an archive the package
  # still installs, it just requires the image to be there already.
  #
  # Resolved before $out_dir is touched: a missing archive must fail the render,
  # not leave a half-written package or destroy the previous one.
  local archive_name=""
  if [[ -n "$TEST_IMAGE_ARCHIVE" ]]; then
    if [[ ! -f "$TEST_IMAGE_ARCHIVE" ]]; then
      echo "error: TEST_IMAGE_ARCHIVE does not exist: $TEST_IMAGE_ARCHIVE" >&2
      exit 1
    fi
    archive_name="$(python3 "$RENDER_DIR/render.py" image-archive-name \
      --image "$TEST_IMAGE" --like "$TEST_IMAGE_ARCHIVE")"
  fi

  rm -rf "$out_dir"
  mkdir -p "$out_dir/config" "$out_dir/k8s" "$out_dir/test" "$out_dir/$PACKAGE_BUNDLE_SUBDIR"
  if [[ -n "$archive_name" ]]; then
    mkdir -p "$out_dir/$PACKAGE_IMAGE_SUBDIR"
    cp "$TEST_IMAGE_ARCHIVE" "$out_dir/$PACKAGE_IMAGE_SUBDIR/$archive_name"
  fi

  cp -L "$INITRD_OUT" "$out_dir/$PACKAGE_BUNDLE_SUBDIR/initramfs.img"
  cp -L "$MEASURE_KERNEL" "$out_dir/$PACKAGE_BUNDLE_SUBDIR/vmlinuz"
  cp -L "$MEASURE_OVMF" "$out_dir/$PACKAGE_BUNDLE_SUBDIR/OVMF.fd"

  local -a memory_args=()
  [[ -n "$KATA_DEFAULT_MEMORY" ]] && memory_args=(--memory-mib "$KATA_DEFAULT_MEMORY")
  python3 "$RENDER_DIR/render.py" kata-config \
    --template "$template" \
    --section "$KATA_HYPERVISOR_SECTION" \
    --bundle-dir "$REMOTE_BUNDLE_DIR" \
    "${memory_args[@]+"${memory_args[@]}"}" \
    --out "$out_dir/$PACKAGE_KATA_CONFIG"

  python3 "$RENDER_DIR/render.py" containerd-fragment \
    --handler "$RUNTIME_HANDLER" \
    --runtime-type "$RUNTIME_TYPE" \
    --runtime-path "$RUNTIME_PATH" \
    --snapshotter "$SNAPSHOTTER" \
    --kata-config "$REMOTE_KATA_CONFIG" \
    --out "$out_dir/config/containerd-runtime-handler.toml"

  local -a run_as_args=()
  [[ -n "$TEST_POD_RUN_AS_USER" ]] && run_as_args=(--run-as-user "$TEST_POD_RUN_AS_USER")
  local -a device_args=()
  [[ -n "$TEST_POD_DEVICE_RESOURCE" ]] && device_args=(--device-resource "$TEST_POD_DEVICE_RESOURCE")
  # The identity tokens become the Pod's kernel_params annotation, which Kata
  # appends to the config's own parameters at VM start. Writing them here rather
  # than into the config is what makes the identity per-Pod: a consumer Pod that
  # does not carry the annotation runs without it.
  local -a identity_args=()
  local param
  for param in ${kernel_params[@]+"${kernel_params[@]}"}; do
    identity_args+=(--kernel-param "$param")
  done
  python3 "$RENDER_DIR/render.py" k8s \
    --handler "$RUNTIME_HANDLER" \
    --pod "$TEST_POD_NAME" \
    --node "$TEST_NODE_NAME" \
    --image "$TEST_IMAGE" \
    --annotations "$TEST_POD_ANNOTATIONS" \
    "${identity_args[@]+"${identity_args[@]}"}" \
    "${run_as_args[@]+"${run_as_args[@]}"}" \
    "${device_args[@]+"${device_args[@]}"}" \
    --out-dir "$out_dir/k8s" \
    --pod-dir "$out_dir/test"

  # The package is self-contained: the installer and its reverse travel with it.
  # Neither the renderer nor the measurement helper does: each host script
  # carries the code it needs in a block embedded in it, so the package has one
  # fewer file that must survive the trip.
  cp "$RENDER_DIR/install.sh" "$out_dir/install.sh"
  cp "$RENDER_DIR/uninstall.sh" "$out_dir/uninstall.sh"
  cp "$RENDER_DIR/create-test-pod.sh" "$out_dir/test/create-test-pod.sh"
  cp "$RENDER_DIR/delete-test-pod.sh" "$out_dir/test/delete-test-pod.sh"

  # MEASUREMENT is SM3(OVMF || hashes-table), and the table hashes the exact
  # QEMU -append string plus the initrd and kernel. All three inputs are the
  # package's own copies, so the recorded value describes the bytes the package
  # will boot rather than whatever happens to sit in base/ at render time.
  local measure_hex="" measure_b64="" measure_cmdline="" measure_smp=""
  if [[ -n "$MEASURE_APPEND" ]]; then
    if [[ "$MEASURE_APPEND" == *$'\n'* || "$MEASURE_APPEND" == *$'\r'* ]]; then
      echo "error: MEASURE_APPEND must be a single line without CR/LF" >&2
      exit 1
    fi
    measure_cmdline="$MEASURE_APPEND"
  else
    local -a smp_args=()
    [[ -n "$MEASURE_SMP" ]] && smp_args=(--smp "$MEASURE_SMP")
    measure_cmdline="$(python3 "$RENDER_DIR/measure.py" cmdline \
      --config "$out_dir/$PACKAGE_KATA_CONFIG" \
      --section "$KATA_HYPERVISOR_SECTION" \
      "${smp_args[@]}")"
    # Kata appends the Pod's kernel_params annotation to the config's parameters,
    # so the identity tokens are part of the measured -append. The annotation is
    # read back from the rendered Pod rather than re-derived here, so an
    # operator-provided kernel_params in TEST_POD_ANNOTATIONS is included in the
    # same order Kata will use.
    local pod_kernel_params
    pod_kernel_params="$(python3 "$RENDER_DIR/render.py" pod-kernel-params \
      --pod "$out_dir/test/test-pod.yaml")"
    if [[ -n "$pod_kernel_params" ]]; then
      measure_cmdline="$measure_cmdline $pod_kernel_params"
    fi
  fi
  # measure.py takes the command line as a file, but the package does not ship
  # that file: only the resulting digest is quoted. A temporary copy keeps the
  # input byte-exact without leaving behind a `cmdline.txt` that would go stale
  # the moment the test Pod's annotation changes.
  local measure_cmdline_file measure_out
  measure_cmdline_file="$(mktemp /tmp/taa-cmdline.XXXXXX.txt)"
  printf '%s\n' "$measure_cmdline" > "$measure_cmdline_file"
  if ! measure_out="$(python3 "$RENDER_DIR/measure.py" digest \
    --ovmf "$out_dir/$PACKAGE_BUNDLE_SUBDIR/OVMF.fd" \
    --kernel "$out_dir/$PACKAGE_BUNDLE_SUBDIR/vmlinuz" \
    --initrd "$out_dir/$PACKAGE_BUNDLE_SUBDIR/initramfs.img" \
    --cmdline "$measure_cmdline_file")"; then
    rm -f "$measure_cmdline_file"
    echo "error: 计算预期 MEASUREMENT 失败" >&2
    exit 1
  fi
  rm -f "$measure_cmdline_file"
  measure_hex="$(sed -n 's/^hex=//p' <<<"$measure_out")"
  measure_b64="$(sed -n 's/^base64=//p' <<<"$measure_out")"
  measure_smp="$(sed -n 's/.*nr_cpus=\([0-9][0-9]*\).*/\1/p' <<<"$measure_cmdline")"
  if [[ -z "$measure_hex" || -z "$measure_b64" ]]; then
    echo "error: measure.py 未输出度量值: $measure_out" >&2
    exit 1
  fi

  # The digests the README quotes. The bundle files are hashed where they land
  # in the package, so the numbers describe what will actually boot.
  local initrd_sha kernel_sha ovmf_sha
  initrd_sha="$(sha256sum "$out_dir/$PACKAGE_BUNDLE_SUBDIR/initramfs.img" | awk '{print $1}')"
  kernel_sha="$(sha256sum "$out_dir/$PACKAGE_BUNDLE_SUBDIR/vmlinuz" | awk '{print $1}')"
  ovmf_sha="$(sha256sum "$out_dir/$PACKAGE_BUNDLE_SUBDIR/OVMF.fd" | awk '{print $1}')"

  local measure_section measure_status="computed"
  measure_section="$(cat <<MEASURE
## 预期 MEASUREMENT

CSV2 的启动度量是 \`SM3(OVMF || 哈希表)\`：哈希表里按 cmdline、initrd、kernel
三项各放一个 SHA256，cmdline 是 QEMU 实际 \`-append\` 的字节（末尾换行替换为 NUL）。

- smp（\`nr_cpus=\`）：\`$measure_smp\`
- OVMF SHA256：\`$ovmf_sha\`
- kernel SHA256：\`$kernel_sha\`
- initrd SHA256：\`$initrd_sha\`

预期值：

- hex：\`$measure_hex\`
- base64：\`$measure_b64\`

运行 \`test/create-test-pod.sh\` 时，它会从 QEMU 进程的 \`/proc/<pid>/cmdline\` 取
实际 \`-append\`，用脚本内嵌的同一套 SM3 计算重算，并打印预期与实际的 hex/base64。
需要独立复核时，可用海光的 \`csv-measure.py\`（本包的计算与它等价，只是不依赖 pysmx）。

再与 guest 报告里的 digest（\`getAttestation\` 的 attestationValues，已解掩码）对照。
cmdline 里的 \`nr_cpus\` 与调试参数由 Kata 版本决定；若与本包预测不一致，
以 \`/proc\` 里取到的实际 cmdline 重算结果为准。
MEASURE
)"

  cat > "$out_dir/README.md" <<EOF
# TAA-in-initrd 交付包

TAA 运行在 Kata CSV2 机密 VM 的 initrd 里，自证通过后才放行 kata-agent。

本包的实例角色：**\`$TAA_ROLE\`**（CONTRACT_TYPE=\`$TAA_CONTRACT_TYPE\`，runtime handler
\`$RUNTIME_HANDLER\`，安装位置 \`$REMOTE_PACKAGE_DIR\`）。三个角色各有自己的 handler 与
安装目录，可以并存于同一台宿主；同一个 handler 下不能混装两个角色。只有
\`taa-train\` 的 initrd 带 semgrep 载荷，其余角色的扫描引擎为 \`regex\`。

## 内容

- \`$PACKAGE_BUNDLE_SUBDIR/{initramfs.img,vmlinuz,OVMF.fd}\` — **QEMU 实际启动用的
  三个文件**。Kata 配置里的 \`kernel\`/\`initrd\`/\`firmware\` 直接指向包内这几份，
  宿主机自己的 \`/opt/kata/share/...\` 一律不读、不复制
- \`$PACKAGE_KATA_CONFIG\` — 指向包内 bundle 的 Kata hypervisor 配置；runtime handler
  的 ConfigPath 就指向它，安装脚本也从这里读安装所需的全部参数
- \`config/containerd-runtime-handler.toml\` — 本包 handler 的片段（供审阅，安装脚本
  从这里解析 handler 名、runtime、snapshotter 与 ConfigPath）
- \`k8s/runtimeclass.yaml\` — 运行时类：Pod 用 \`runtimeClassName\` 选中本 handler。使用该
  runtime 的每个 Pod 都需要它，由 install.sh 安装
- \`test/\` — 测试 Pod：\`test-pod.yaml\`、\`create-test-pod.sh\`（创建并等待 Ready，
  核对 QEMU 用的 initrd 与 MEASUREMENT）、\`delete-test-pod.sh\`（删除测试 Pod）。
  **部署身份就写在 \`test-pod.yaml\` 的 \`kernel_params\` 注解里**（见下文）。
  CoCo 客户机由 CDH 自己拉镜像，注册表 CA 经 \`cc_init_data\` 注解投递，而这个值逐宿主
  不同，所以包里不带它：创建脚本在宿主机上读一条填进去
- \`install.sh\` / \`uninstall.sh\` — 安装与卸载脚本（见下文）。它们各自内嵌读取本包的
  一小段 Python（解析 handler 片段、Kata 配置、Pod 清单与 containerd drop-in），
  包里不再有单独的渲染器文件；\`test/create-test-pod.sh\` 同样把 MEASUREMENT 的计算
  内嵌在自己身上，不单独带度量脚本
$(if [[ -n "$TEST_IMAGE_ARCHIVE" ]]; then printf -- '- `%s/` — 测试 Pod 镜像的 `docker save` 归档。CoCo guest 由 CDH 自己从 registry 拉镜像，宿主机 docker 不在那条路径上，所以 install.sh 会先查 registry，缺这个 tag 时导入归档并推送过去\n' "$PACKAGE_IMAGE_SUBDIR"; fi)
- \`SHA256SUMS\` — 不可变文件的校验和（\`test/test-pod.yaml\` 不在其中：它是运维要改
  的文件，部署身份就在里面）

包内**不含**完整的 containerd runtimes 快照：所有 TAA 交付包共用包目录上一级的
\`zz-taa-runtimes.toml\`（默认 \`/root/taa-images/zz-taa-runtimes.toml\`，可用
\`TAA_RUNTIMES_FILE\` 覆盖）。**首次安装时生成**：宿主 \`/etc/containerd/conf.d/\`
中最后生效的那份 runtimes 文件（排除 TAA 自己的 drop-in）加上本包 handler；之后任何
包安装都读写这同一份，不再从宿主重新采集，这样 \`uninstall.sh\` 摘掉本包 handler 时
不会丢别的包 handler。安装时把快照拷到
\`/etc/containerd/conf.d/zz-taa-runtimes.toml\`（已存在则覆盖）。containerd 用最后一个
定义 runtimes 的 import 整个替换 CRI 插件树，只写本包 handler 会删掉宿主其它
runtime，所以该文件必须带全量快照；不要手工编辑。

## 前置条件

- 目标宿主已安装海光 CSV2 可用的 Kata（shim 与 containerd 配置模板；包内已带
  kernel/initrd/OVMF，宿主缺这几份文件不影响安装）
- containerd 配置为 TOML \`version = 2\`，并装有 \`$SNAPSHOTTER\` snapshotter
- kubectl 可用；需要 root 或免密 sudo

## 安装

\`\`\`bash
scp -r <local-package>/. root@<host>:$REMOTE_PACKAGE_DIR/
ssh root@<host> 'cd $REMOTE_PACKAGE_DIR && sha256sum -c SHA256SUMS'
ssh root@<host> 'cd $REMOTE_PACKAGE_DIR && bash install.sh --dry-run'
ssh root@<host> 'cd $REMOTE_PACKAGE_DIR && bash install.sh'
ssh root@<host> 'cd $REMOTE_PACKAGE_DIR && bash test/create-test-pod.sh'
\`\`\`

install.sh 依次完成：校验 \`SHA256SUMS\`、检查包内 Kata 配置、把 runtime handler
写入 TAA 自有 drop-in（首次从宿主最后生效的 runtimes 文件采集快照，之后读写包目录
上一级的共享快照；校验生效配置后重启 containerd）、必要时把测试镜像导入 registry、
创建 RuntimeClass。它**不改部署身份**：身份在 Pod 的注解里，不随安装变化。
\`--dry-run\` 只打印，不落盘。

卸载用 \`uninstall.sh\`，它是 containerd 这一步的反操作：从
\`/etc/containerd/conf.d/zz-taa-runtimes.toml\` 中删掉本包 handler（其它 TAA 包
的 handler 保留），写回共享快照并覆盖安装；若文件里不再有任何 TAA handler，则删除
该 drop-in，让 containerd 回到宿主自己的配置，最后重启 containerd。RuntimeClass
与镜像不由它删除。

ConfigPath 指向包内这份配置：这台宿主上该 runtime 的 Kata 配置就是包里的这一份，
删除或替换目录前先用 \`uninstall.sh\` 把 runtime handler 摘掉。

## 部署身份（写在 Pod 注解里）

平台地址、dockerId、平台公钥、LLM 端点等身份，是 \`test-pod.yaml\` 上的一条注解：
\`io.katacontainers.config.hypervisor.kernel_params\`，值为空格分隔的
\`taa.<key>=<value>\`。Kata 在创建 VM 时把它**追加**到
\`$PACKAGE_KATA_CONFIG\` 的 \`kernel_params\` 之后，guest 内的 taa-init 再从
\`/proc/cmdline\` 读回这些值，覆盖镜像里烘焙的 \`/etc/default/taa.env\`。

所以换一台平台、换一个 dockerId 或者换一个 LLM 端点，只需要在宿主机上编辑这条注解：

\`\`\`bash
vi $(basename "$out_dir")/test/test-pod.yaml
sudo bash test/create-test-pod.sh
\`\`\`

\`install.sh\` 不参与身份：注解只在新建 Pod 时被读取，重建 Pod 后生效，不用重装、
不用重新渲染、不用重传。删掉注解里的一个 token，对应参数就从命令行上消失；
整条注解为空时 TAA 没有注册身份：Pod 能起来，但平台注册会失败。

**注意：身份是每个 Pod 各自的。** 使用本 runtime 的其它 Pod（由平台或运维创建）
必须带上同一条注解，否则它不会继承测试 Pod 的身份。\`install.sh\` 结束时会打印
本包当前的身份注解，可直接复制到消费方 Pod 的 YAML 里。

键名就是环境变量名的全小写形式（\`taa.taa_llm_endpoint\` 对应
\`TAA_LLM_ENDPOINT\`，\`taa.taasecretkey\` 对应 \`TAASECRETKEY\`）：taa-init 把
\`taa.\` 之后的部分全部大写后 export，不再维护白名单。渲染侧已经对值做过严格校验
（空值、含空白字符的值会让 render 直接失败），所以注解里每个 token 都是合法的。
渲染时写入的键：

\`\`\`
taa.platform_ip  taa.docker_id  taa.platform_public_key  taa.platform_sm2_id
taa.contract_id  taa.contract_type  taa.taa_llm_endpoint  taa.taa_addr
taa.taa_modules  taa.taasecretkey（可选）
\`\`\`

\`taa.taasecretkey\` 是平台保存的私钥密文（SM4-GCM 包裹，密钥是 CSV 硬件密封密钥
派生的 SM4 密钥），不是明文私钥；命令行对宿主机可见，但宿主只能把它重放回 TAA，
无法解密出私钥。

内核命令行本身也在 CSV2 度量范围内，所以身份也算进 MEASUREMENT：
\`test/create-test-pod.sh\` 按当前的配置 **加上 Pod 注解** 重算预期值，再与 QEMU
实际的 \`-append\` 比对。同时它在宿主机的 \`ps\` 与 QEMU 日志里可见，密钥类内容
不要走这条通路。

## 使用

创建任意 Pod 时指定 runtime，并带上与测试 Pod 相同的身份注解：

\`\`\`yaml
metadata:
  annotations:
    io.katacontainers.config.hypervisor.kernel_params: "taa.platform_ip=... taa.docker_id=... ..."
spec:
  runtimeClassName: $RUNTIME_HANDLER
\`\`\`

测试 Pod 名：\`$TEST_POD_NAME\`（TAA 在 Pod 网络命名空间的 6001 端口）。

$measure_section
EOF

  # The test Pod is excluded: its kernel_params annotation is the deployment
  # identity, the one file an operator is meant to edit on the target host.
  # Everything else is immutable, including the Kata config -- install.sh no
  # longer re-renders it and refuses to run if any pinned file differs.
  (cd "$out_dir" && find . -type f ! -name SHA256SUMS \
    ! -path "./test/test-pod.yaml" -print0 |
    LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS)

  echo "交付包: $out_dir"
  local file
  while IFS= read -r file; do
    printf '  %s\n' "${file#"$out_dir"/}"
  done < <(find "$out_dir" -type f | LC_ALL=C sort)
}

# The rendered Pod carries nodeName only when it is known. Resolve it now,
# read-only, so both the launcher and the delivered package agree.
resolve_test_node_name() {
  [[ -n "$TEST_NODE_NAME" ]] && return 0
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
  export TEST_NODE_NAME
}

# A rendered copy kept outside the temporary directory, for inspecting or handing
# the exact package to somebody else.
keep_render_copy() {
  local dir="$1"
  [[ "${LAUNCH_KEEP_DIST:-0}" == "1" ]] || return 0
  rm -rf "$DIST_DIR"
  mkdir -p "$(dirname "$DIST_DIR")"
  cp -a "$dir" "$DIST_DIR"
  echo "保留交付包: $DIST_DIR"
}

# Upload a rendered package and make it the one at $REMOTE_PACKAGE_DIR. The host
# is only written here: scp cannot sudo, so the bytes land in a temporary
# directory first and are moved into place as root. Nothing is installed, and no
# file is copied anywhere else on the host -- the Kata config and the files QEMU
# boots are read straight out of this directory.
upload_package_dir() {
  local local_dir="$1"
  require_cmd ssh scp

  local remote_tmp
  remote_tmp="$(ssh "$REMOTE" 'mktemp -d /tmp/taa-upload.XXXXXX')"
  remote_tmp="${remote_tmp//$'\r'/}"
  remote_tmp="${remote_tmp//$'\n'/}"
  if [[ -z "$remote_tmp" ]]; then
    echo "error: could not create a remote temporary directory" >&2
    exit 1
  fi

  echo "上传交付包到 $REMOTE"
  if ! scp -q -r "$local_dir/." "$REMOTE:$remote_tmp/"; then
    ssh "$REMOTE" "rm -rf $(printf '%q' "$remote_tmp")" || true
    echo "error: 上传失败，未改动 $REMOTE_PACKAGE_DIR" >&2
    exit 1
  fi

  ssh "$REMOTE" "bash -s -- $(printf '%q ' "$remote_tmp" "$REMOTE_PACKAGE_DIR")" <<'REMOTE_UPLOAD'
set -euo pipefail
staging="$1"
package_dir="$2"

cleanup() { sudo rm -rf "$staging"; }
trap cleanup EXIT

sudo mkdir -p "$(dirname "$package_dir")"
sudo rm -rf "$package_dir"
sudo mv "$staging" "$package_dir"
trap - EXIT
REMOTE_UPLOAD

  echo "交付包已就位: $REMOTE:$REMOTE_PACKAGE_DIR"
}

# Steps 3-4 of the flow: render on this machine, then upload the whole package.
# Deliberately does not run install.sh, so a package can be placed on a host that
# is not ready to take it (another handler still in use, a different operator
# doing the install) without touching containerd or kata.
upload_remote() {
  require_cmd ssh scp python3

  echo "确保 Kata 配置模板在本地"
  ensure_kata_template
  resolve_test_node_name

  local render_dir
  render_dir="$(mktemp -d /tmp/taa-render.XXXXXX)"
  cleanup_render() { rm -rf "${render_dir:-}"; }
  trap cleanup_render EXIT

  echo "本地渲染"
  render_package "$render_dir"
  keep_render_copy "$render_dir"

  upload_package_dir "$render_dir"

  echo
  echo "尚未安装。在该宿主机上安装："
  echo "  ssh $REMOTE 'cd $REMOTE_PACKAGE_DIR && sudo bash install.sh'"
  echo "或直接跑 '$0 launch'（渲染 + 上传 + 安装）"
}

launch_remote() {
  require_cmd ssh scp python3

  echo "确保 Kata 配置模板在本地"
  ensure_kata_template
  resolve_test_node_name

  local render_dir
  render_dir="$(mktemp -d /tmp/taa-render.XXXXXX)"
  cleanup_render() { rm -rf "${render_dir:-}"; }
  trap cleanup_render EXIT

  echo "本地渲染"
  render_package "$render_dir"
  keep_render_copy "$render_dir"

  upload_package_dir "$render_dir"

  ssh "$REMOTE" "bash -s -- $(printf '%q ' "$REMOTE_PACKAGE_DIR")" <<'REMOTE_INSTALL'
set -euo pipefail
package_dir="$1"

sudo bash "$package_dir/install.sh"

echo
echo "交付包已保留: $package_dir"
echo "创建测试 Pod: sudo bash $package_dir/test/create-test-pod.sh"
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
  render)
    render_package "$DIST_DIR"
    ;;
  upload)
    upload_remote
    ;;
  launch)
    launch_remote
    ;;
  all)
    build_initrd
    launch_remote
    ;;
  print-config)
    # Machine-readable dump of the resolved settings, so a driver script does not
    # have to duplicate (and drift from) the defaults defined above. %q quoting
    # makes the output safe to `eval` even when a value contains spaces.
    for key in TAA_ROLE TAA_CONTRACT_TYPE TAA_MODULES REMOTE_USER REMOTE_HOST REMOTE_BUNDLE_DIR REMOTE_PACKAGE_DIR \
               REMOTE_BASE_INITRD_SRC REMOTE_KERNEL_SRC MEASURE_KERNEL \
               REMOTE_KATA_CONFIG_SRC REMOTE_KATA_CONFIG PACKAGE_KATA_CONFIG \
               KATA_HYPERVISOR_SECTION KATA_DEFAULT_MEMORY \
               RUNTIME_HANDLER RUNTIME_TYPE RUNTIME_PATH SNAPSHOTTER \
               CONTAINERD_CONFIG KATA_CONFIG_TEMPLATE DIST_DIR \
               TEST_NODE_NAME TEST_POD_NAME TEST_IMAGE TEST_IMAGE_ARCHIVE TEST_POD_ANNOTATIONS \
               TEST_POD_RUN_AS_USER TEST_POD_DEVICE_RESOURCE \
               DCU_PAYLOAD_DIR DCU_REMOTE_IMAGE \
               OUT_DIR INITRD_OUT SEED_DIR BASE_INITRD; do
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
