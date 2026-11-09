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
# The role argument is accepted anywhere in argv and removed before dispatch, so
# both `build-initrd.sh taa-infer all` and `build-initrd.sh all taa-infer` work.
TAA_ROLE="${TAA_ROLE:-}"
role_args=()
for role_arg in "$@"; do
  case "$role_arg" in
    taa-train|taa-infer|taa-analysis) TAA_ROLE="$role_arg" ;;
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
    taa-train) echo 1 ;;
    taa-infer) echo 2 ;;
    taa-analysis) echo 3 ;;
  esac
}

# Only the training role carries the semgrep payload. Both other roles land or
# run models that were already audited where they were trained, so shipping a
# 350 MiB Python runtime and scanner into their measured initrd buys nothing --
# and the data-analysis role never audits at all.
role_wants_semgrep() {
  [[ "$TAA_ROLE" == "taa-train" ]]
}

# Handler and delivery directory are per role, so a host can hold all three side
# by side. Both carry the role suffix, including training: a bare `package` or
# `kata-qemu-csv2-taa` would read as "the default one" and invite a second role
# to be installed over it.
role_runtime_handler() {
  case "$TAA_ROLE" in
    taa-train) echo kata-qemu-csv2-taa-train ;;
    taa-infer) echo kata-qemu-csv2-taa-infer ;;
    taa-analysis) echo kata-qemu-csv2-taa-analysis ;;
  esac
}

role_package_subdir() {
  case "$TAA_ROLE" in
    taa-train) echo package-train ;;
    taa-infer) echo package-infer ;;
    taa-analysis) echo package-analysis ;;
  esac
}

role_test_pod_name() {
  case "$TAA_ROLE" in
    taa-train) echo test-kata-csv2-taa ;;
    taa-infer) echo test-kata-csv2-taa-infer ;;
    taa-analysis) echo test-kata-csv2-taa-analysis ;;
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
  esac
}

role_test_pod_run_as_user() {
  case "$TAA_ROLE" in
    taa-analysis) echo 0 ;;
    *) echo "" ;;
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

# Renderer support files and the shipped Kata config the rendered config is
# derived from. The template is host-authoritative like the base initrd:
# fetch-base copies it, and `render` refuses to guess when it is missing.
RENDER_DIR="${RENDER_DIR:-$SCRIPT_DIR/render}"
KATA_CONFIG_TEMPLATE="${KATA_CONFIG_TEMPLATE:-$SCRIPT_DIR/base/configuration-qemu-csv2.toml}"

# Optional semgrep payload. The injected config selects the scan engine, so
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
# produces an initrd that boots, hangs the Pod at "TAA exited immediately", and
# reports nothing useful. The build therefore refuses unless it can resolve one.
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
# endpoint in the config file (TAA_LLM_ENDPOINT). TAASECRETKEY is deliberately
# not carried: it is secret material, not deployment identity.
TAA_PLATFORM_SM2_ID="${TAA_PLATFORM_SM2_ID:-}"
TAA_CONTRACT_ID="${TAA_CONTRACT_ID:-}"
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
REMOTE_KERNEL_SRC="${REMOTE_KERNEL_SRC:-/opt/kata/share/kata-containers/vmlinuz-confidential-csv.container}"
REMOTE_OVMF_SRC="${REMOTE_OVMF_SRC:-/opt/kata/share/ovmf/OVMFCSV.fd}"
REMOTE_KATA_CONFIG_SRC="${REMOTE_KATA_CONFIG_SRC:-/opt/kata/share/defaults/kata-containers/configuration-qemu-csv2.toml}"
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
PACKAGE_KATA_CONFIG="config/kata-config.toml"
PACKAGE_IMAGE_SUBDIR="image"
REMOTE_KATA_CONFIG="$REMOTE_PACKAGE_DIR/$PACKAGE_KATA_CONFIG"
CONTAINERD_CONFIG="${CONTAINERD_CONFIG:-/etc/containerd/config.toml}"
KATA_HYPERVISOR_SECTION="${KATA_HYPERVISOR_SECTION:-hypervisor.qemu}"
# Guest RAM, in MiB. This is a runtime dependency, not a tuning knob: a CSV2
# guest's writable root is a tmpfs capped at roughly half the guest RAM, and the
# CDH unpacks the container image into it. The base template's 2048 leaves ~1 GiB
# for an image that unpacks to 1.92 GB, so the pull fails with "Failed to unpack
# layer" and the Pod lands in StartError -- which reads like an initrd failure
# but is not one. Empty means "keep the template's value".
KATA_DEFAULT_MEMORY="${KATA_DEFAULT_MEMORY:-}"
RUNTIME_HANDLER="${RUNTIME_HANDLER:-$(role_runtime_handler)}"
RUNTIME_TYPE="${RUNTIME_TYPE:-io.containerd.kata-qemu-csv2.v2}"
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
# Optional `docker save` archive of TEST_IMAGE. When set, the package carries it
# under image/ and install.sh loads and pushes it if the registry lacks the tag.
# A CoCo guest pulls the image itself through CDH, so the archive has to reach
# the registry, not just the host's docker daemon. Empty means "expect the
# registry to already hold the image".
TEST_IMAGE_ARCHIVE="${TEST_IMAGE_ARCHIVE:-}"
# A CoCo guest pulls the container image itself through CDH, and it trusts the
# registry only if the Pod carries the init-data that configures it (on this
# host cc_init_data embeds a cdh.toml with extra_root_certificates). Without it
# CDH fails the pull with a TLS error and the Pod lands in StartError -- which
# looks like an initrd failure but is not one. Copy the JSON annotations of a
# working Pod when the test image lives behind a private registry:
#   TEST_POD_ANNOTATIONS="$(kubectl get pod <working> -o jsonpath='{.metadata.annotations}')"
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
MEASURE_SMP="${MEASURE_SMP:-}"
MEASURE_APPEND="${MEASURE_APPEND:-}"

# 打印支持的子命令和主要环境变量覆盖项。脚本默认执行 build，
# 因此本地反复调试是安全的；只有显式指定 upload、launch 或 all 时才会触碰远程服务器。
usage() {
  cat <<EOF
Usage: $0 [taa-train|taa-infer|taa-analysis] [build|fetch-base|render|upload|launch|all|print-config]

Role (first word, or TAA_ROLE; default taa-train):
  taa-train     Training instance. CONTRACT_TYPE=1, its own handler and package
                directory, and the only role whose initrd carries the semgrep
                payload.
  taa-infer     Inference instance. CONTRACT_TYPE=2, its own handler and package
                directory, no semgrep payload.
  taa-analysis  Data-analysis instance. CONTRACT_TYPE=3, its own handler and
                package directory, the jupyter base image, no semgrep payload.
                Its injected config selects the built-in regex engine instead.
  The role decides the default INITRD_OUT, DIST_DIR, RUNTIME_HANDLER,
  REMOTE_PACKAGE_DIR, TEST_POD_NAME and TEST_IMAGE; each of those still accepts
  an explicit override.

Commands:
  build       Build $INITRD_OUT from $BASE_INITRD and inject TAA + init wrapper.
  fetch-base  Copy the real base initrd, kernel, OVMF and shipped Kata config
              from $REMOTE into $(basename "$SCRIPT_DIR")/base/.
  render      Render the Kata config, containerd handler, K8s manifests, the
              install script and the guest bundle (initrd, kernel, OVMF) into
              $DIST_DIR. Local only; no host access.
  upload      Render the package and upload the whole thing to
              $REMOTE_PACKAGE_DIR on $REMOTE. No install: the host is only
              given the files, untouched by install.sh.
  launch      Render locally, upload the whole package, then install it on
              $REMOTE and create a test Pod. Nothing is copied on the host.
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
  KATA_DEFAULT_MEMORY=${KATA_DEFAULT_MEMORY:-(keep the template's default_memory)}
  RUNTIME_TYPE=$RUNTIME_TYPE
  RUNTIME_PATH=$RUNTIME_PATH
  SNAPSHOTTER=$SNAPSHOTTER
  RESTART_KUBELET=$RESTART_KUBELET
  TEST_NODE_NAME=$TEST_NODE_NAME
  TEST_POD_NAME=$TEST_POD_NAME
  TEST_IMAGE=$TEST_IMAGE
  TEST_IMAGE_ARCHIVE=${TEST_IMAGE_ARCHIVE:-(none; the registry must already hold TEST_IMAGE)}
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
  local dst="$BUILD_WORK_DIR/extra/etc/taa/taa-config.json"
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
  # of the measured image. Training injects configs/taa-production.json as-is;
  # a non-training role injects a copy whose scan engine is the built-in regex
  # one, because no semgrep payload is staged for it (see role_wants_semgrep).
  # Left selecting semgrep, the guest would log a fallback warning at every boot
  # and run the weaker engine anyway -- the config should say what runs.
  mkdir -p "$BUILD_WORK_DIR/extra/etc/taa"
  stage_taa_config

  echo "生成可选 env 文件"

  # The guest-side fallback environment, written at build time. %q shell-escapes
  # the values so spaces or metacharacters are not reinterpreted when taa-init
  # sources this file. The kernel-command-line tokens rendered by `render` take
  # precedence over every name below; this file only has to be usable if they are
  # ever missing, which is why check_initrd_identity still reports a mismatch.
  if taa_env_file_needed; then
    mkdir -p "$BUILD_WORK_DIR/extra/etc/default"
    {
      printf 'export TAA_ADDR=%q\n' "$TAA_ADDR"
      printf 'export PLATFORM_IP=%q\n' "$TAA_PLATFORM_IP"
      printf 'export DOCKER_ID=%q\n' "$TAA_DOCKER_ID"
      printf 'export PLATFORM_PUBLIC_KEY=%q\n' "$TAA_PLATFORM_PUBLIC_KEY"
      printf 'export PLATFORM_SM2_ID=%q\n' "$TAA_PLATFORM_SM2_ID"
      printf 'export CONTRACT_ID=%q\n' "$TAA_CONTRACT_ID"
      printf 'export CONTRACT_TYPE=%q\n' "$TAA_CONTRACT_TYPE"
      printf 'export TAA_LLM_ENDPOINT=%q\n' "$TAA_LLM_ENDPOINT"
    } > "$BUILD_WORK_DIR/extra/etc/default/taa.env"
  fi

  if initrd_wants_semgrep; then
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
  # not only against the base matters: several new files share the same parent
  # directory, and queueing them once per file would append that directory
  # entry two or three times over.
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

  # The guest's deployment identity travels on the kernel command line. taa-init
  # parses `taa.<key>=<value>` out of /proc/cmdline and lets those values override
  # the build-time env file, so changing the platform address, docker id, key or
  # endpoint is a re-render (`launch`) rather than a rebuild: the initrd's bytes,
  # and with them its MEASUREMENT, stay as they are. The command line is part of
  # the CSV2 measurement too, so the identity is still covered by the attested
  # value -- see the notes in taa-init.sh.
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
  add_kernel_param llm_endpoint "$TAA_LLM_ENDPOINT"
  add_kernel_param addr "$TAA_ADDR"

  # The package carries the three files QEMU boots. Shipping them is what lets
  # the same package be deployed on a host whose Kata installation lives
  # elsewhere, or does not exist: install.sh takes the kernel, initrd and OVMF
  # from the package and never copies anything out of the host's own tree.
  # Checked before the output directory is touched, so a missing input fails the
  # render instead of leaving a package that would not boot.
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
  mkdir -p "$out_dir/config" "$out_dir/k8s" "$out_dir/$PACKAGE_BUNDLE_SUBDIR"
  if [[ -n "$archive_name" ]]; then
    mkdir -p "$out_dir/$PACKAGE_IMAGE_SUBDIR"
    cp "$TEST_IMAGE_ARCHIVE" "$out_dir/$PACKAGE_IMAGE_SUBDIR/$archive_name"
  fi

  cp -L "$INITRD_OUT" "$out_dir/$PACKAGE_BUNDLE_SUBDIR/initramfs.img"
  cp -L "$MEASURE_KERNEL" "$out_dir/$PACKAGE_BUNDLE_SUBDIR/vmlinuz"
  cp -L "$MEASURE_OVMF" "$out_dir/$PACKAGE_BUNDLE_SUBDIR/OVMF.fd"

  # The one file an operator is meant to edit on the target host. install.sh
  # re-renders the Kata config from it, so changing a platform address, docker
  # id or endpoint is one edit plus a re-run -- no rebuild, no re-upload, and the
  # initrd's bytes (and therefore its measurement) stay as they are. The format
  # is the command line itself rather than `NAME=value` env syntax: it is not
  # sourceable, and what it holds is exactly what the kernel will be given.
  {
    cat <<'IDENTITY'
# TAA 部署身份：每行一个 `taa.<key>=<value>`，原样写进内核命令行。
# 改完本文件后重新执行 `sudo bash install.sh` 即生效：install.sh 会按它重新
# 渲染 config/kata-config.toml 并重建测试 Pod，不需要回构建机重新 render。
# 只允许下列 8 个键；值不能含空白字符；删掉一行就是去掉对应参数。
#   taa.platform_ip  taa.docker_id  taa.platform_public_key  taa.platform_sm2_id
#   taa.contract_id  taa.contract_type  taa.llm_endpoint  taa.addr
# 不要在这里放密钥：内核命令行在宿主机的 `ps` 与日志里可见。
IDENTITY
    local param
    for param in ${kernel_params[@]+"${kernel_params[@]}"}; do
      printf '%s\n' "$param"
    done
  } > "$out_dir/config/env.txt"

  local -a memory_args=()
  [[ -n "$KATA_DEFAULT_MEMORY" ]] && memory_args=(--memory-mib "$KATA_DEFAULT_MEMORY")
  python3 "$RENDER_DIR/render.py" kata-config \
    --template "$template" \
    --section "$KATA_HYPERVISOR_SECTION" \
    --bundle-dir "$REMOTE_BUNDLE_DIR" \
    --param-file "$out_dir/config/env.txt" \
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
  python3 "$RENDER_DIR/render.py" k8s \
    --handler "$RUNTIME_HANDLER" \
    --pod "$TEST_POD_NAME" \
    --node "$TEST_NODE_NAME" \
    --image "$TEST_IMAGE" \
    --annotations "$TEST_POD_ANNOTATIONS" \
    "${run_as_args[@]+"${run_as_args[@]}"}" \
    --out-dir "$out_dir/k8s"

  # The package is self-contained: the installer, the merger and the
  # measurement helper travel with it.
  cp "$RENDER_DIR/render.py" "$out_dir/render.py"
  cp "$RENDER_DIR/measure.py" "$out_dir/measure.py"
  cp "$RENDER_DIR/install.sh" "$out_dir/install.sh"

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
      --config "$out_dir/config/kata-config.toml" \
      --section "$KATA_HYPERVISOR_SECTION" \
      "${smp_args[@]}")"
  fi
  printf '%s\n' "$measure_cmdline" > "$out_dir/cmdline.txt"

  local measure_out
  if ! measure_out="$(python3 "$RENDER_DIR/measure.py" digest \
    --ovmf "$out_dir/$PACKAGE_BUNDLE_SUBDIR/OVMF.fd" \
    --kernel "$out_dir/$PACKAGE_BUNDLE_SUBDIR/vmlinuz" \
    --initrd "$out_dir/$PACKAGE_BUNDLE_SUBDIR/initramfs.img" \
    --cmdline "$out_dir/cmdline.txt")"; then
    echo "error: 计算预期 MEASUREMENT 失败" >&2
    exit 1
  fi
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
- cmdline 原文：\`cmdline.txt\`
- OVMF SHA256：\`$ovmf_sha\`
- kernel SHA256：\`$kernel_sha\`
- initrd SHA256：\`$initrd_sha\`

预期值：

- hex：\`$measure_hex\`
- base64：\`$measure_b64\`

安装后 \`install.sh\` 会从 QEMU 进程的 \`/proc/<pid>/cmdline\` 取实际 \`-append\`，
用包内 \`measure.py\` 重算并打印。也可以手工重算：

\`\`\`bash
pid=\$(ps -eo pid=,args= | grep -F qemu | grep -F "$REMOTE_BUNDLE_DIR/initramfs.img" | awk '{print \$1}' | head -1)
tr '\\0' '\\n' < /proc/\$pid/cmdline | grep -A1 '^-append\$' | tail -n1 > /tmp/append
echo >> /tmp/append
python3 measure.py digest --ovmf "$REMOTE_BUNDLE_DIR/OVMF.fd" \\
  --kernel "$REMOTE_BUNDLE_DIR/vmlinuz" \\
  --initrd "$REMOTE_BUNDLE_DIR/initramfs.img" --cmdline /tmp/append
\`\`\`

再与 guest 报告里的 digest（\`getAttestation\` 的 attestationValues，已解掩码）对照。
cmdline 里的 \`nr_cpus\` 与调试参数由 Kata 版本决定；若与本包预测不一致，
以 \`/proc\` 里取到的实际 cmdline 重算结果为准。
MEASURE
)"

  cat > "$out_dir/README.md" <<EOF
# TAA-in-initrd 交付包

由 \`build-initrd.sh render\` 生成。TAA 运行在 Kata CSV2 机密 VM 的 initrd 里，
自证通过后才放行 kata-agent。

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
- \`config/containerd-runtime-handler.toml\` — containerd handler 片段（供审阅，安装脚本
  从这里解析 handler 名、runtime、snapshotter 与 ConfigPath）
- \`k8s/runtimeclass.yaml\` / \`k8s/test-pod.yaml\` — 运行时类与测试 Pod（安装脚本从后者
  读 Pod 名与节点名）
- \`install.sh\` / \`render.py\` / \`measure.py\` — 安装脚本、合并器与度量计算器
$(if [[ -n "$TEST_IMAGE_ARCHIVE" ]]; then printf -- '- `%s/` — 测试 Pod 镜像的 `docker save` 归档。CoCo guest 由 CDH 自己从 registry 拉镜像，宿主机 docker 不在那条路径上，所以 install.sh 会先查 registry，缺这个 tag 时导入归档并推送过去\n' "$PACKAGE_IMAGE_SUBDIR"; fi)
- \`config/env.txt\` — **可在宿主机上编辑的部署身份**（见下文）
- \`SHA256SUMS\` — 不可变文件的校验和（\`config/env.txt\` 与由它渲染的
  \`$PACKAGE_KATA_CONFIG\` 不在其中，这两个文件本来就允许在宿主机上改）
$([[ -f "$out_dir/cmdline.txt" ]] && echo '- `cmdline.txt` — 计算预期度量所用的 QEMU `-append` 原文')

## 前置条件

- 目标宿主已安装海光 CSV2 可用的 Kata（shim 与 containerd 配置模板；包内已带
  kernel/initrd/OVMF，宿主缺这几份文件不影响安装）
- containerd 配置为 TOML \`version = 2\`，并装有 \`$SNAPSHOTTER\` snapshotter
- kubectl 可用；需要 root 或免密 sudo

## 安装

交付包必须整体放在 \`$REMOTE_PACKAGE_DIR\`（Kata 配置里的路径按这个位置渲染），
直接解压/拷贝整棵目录即可，不要在宿主上再复制里面的文件：

\`\`\`bash
scp -r <local-package>/. root@<host>:$REMOTE_PACKAGE_DIR/
ssh root@<host> 'cd $REMOTE_PACKAGE_DIR && sha256sum -c SHA256SUMS'
ssh root@<host> 'cd $REMOTE_PACKAGE_DIR && bash install.sh --dry-run'
ssh root@<host> 'cd $REMOTE_PACKAGE_DIR && bash install.sh'
\`\`\`

ConfigPath 指向包内这份配置，install.sh 不会再往 \`/etc\` 拷一份：包（配置 + 启动
文件）就是宿主机上唯一的副本，删除或替换它之前必须先把 runtime handler 摘掉。

## 部署身份（在宿主机上改）

平台地址、dockerId、平台公钥、LLM 端点等身份，每行一个 \`taa.<key>=<value>\`
写在 \`config/env.txt\` 里。install.sh 用它重新渲染 \`$PACKAGE_KATA_CONFIG\`
的 \`kernel_params\`，guest 内的 taa-init 再从 \`/proc/cmdline\` 读回这些值，覆盖
镜像里烘焙的 \`/etc/default/taa.env\`。

所以换一台平台、换一个 dockerId 或者换一个 LLM 端点，只需要在宿主机上：

\`\`\`bash
vi $(basename "$out_dir")/config/env.txt
sudo bash install.sh
\`\`\`

install.sh 会重渲染配置、删掉旧 Pod 再重建（新 Pod 才会带上新的命令行），
不需要回构建机重新 render，也不需要重建 initrd。env.txt 里删掉一行，
对应的参数就会从命令行上消失。

只允许这 8 个键，写错键名、重复键、空值或含空白字符的值都会让 install.sh
直接报错退出，不会带上一个 guest 会静默忽略的参数：

\`\`\`
taa.platform_ip  taa.docker_id  taa.platform_public_key  taa.platform_sm2_id
taa.contract_id  taa.contract_type  taa.llm_endpoint  taa.addr
\`\`\`

内核命令行本身也在 CSV2 度量范围内，所以改身份改的是 MEASUREMENT：install.sh
第 7 步会按当前配置重算预期值，再与 QEMU 实际的 \`-append\` 比对。同时它在宿主机的
\`ps\` 与 QEMU 日志里可见，密钥类内容不要走这条通路。

身份只在新建 Pod 时被 QEMU 读入：install.sh 会删掉旧 Pod 再重建，新身份在重建
的 Pod 上生效；其他已经在运行的 Pod 不受影响。

## 使用

创建任意 Pod 时指定：

\`\`\`yaml
spec:
  runtimeClassName: $RUNTIME_HANDLER
\`\`\`

测试 Pod 名：\`$TEST_POD_NAME\`（TAA 在 Pod 网络命名空间的 6001 端口）。

$measure_section
EOF

  # The editable identity file and the config rendered from it are excluded:
  # both are supposed to change on the target host, and install.sh refuses to
  # run if any *immutable* file differs from its recorded digest.
  (cd "$out_dir" && find . -type f ! -name SHA256SUMS \
    ! -path "./config/env.txt" ! -path "./$PACKAGE_KATA_CONFIG" -print0 |
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
  echo "或直接跑 '$0 launch'（渲染 + 上传 + 安装并拉起测试 Pod）"
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
echo "在该宿主机上重建测试 Pod: sudo bash $package_dir/install.sh"
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
    for key in TAA_ROLE TAA_CONTRACT_TYPE REMOTE_USER REMOTE_HOST REMOTE_BUNDLE_DIR REMOTE_PACKAGE_DIR \
               REMOTE_BASE_INITRD_SRC \
               REMOTE_KATA_CONFIG_SRC REMOTE_KATA_CONFIG PACKAGE_KATA_CONFIG \
               KATA_HYPERVISOR_SECTION KATA_DEFAULT_MEMORY \
               RUNTIME_HANDLER RUNTIME_TYPE RUNTIME_PATH SNAPSHOTTER \
               CONTAINERD_CONFIG KATA_CONFIG_TEMPLATE DIST_DIR \
               TEST_NODE_NAME TEST_POD_NAME TEST_IMAGE TEST_IMAGE_ARCHIVE TEST_POD_ANNOTATIONS \
               TEST_POD_RUN_AS_USER \
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
