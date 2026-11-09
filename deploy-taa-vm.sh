#!/usr/bin/env bash
# Prepare the TAA-in-initrd delivery package and put it on the Kata CSV2 host.
#
# There is one behaviour and no subcommands: compile TAA, build the initrd,
# render the package locally, upload it whole to the host. It does not install
# anything -- the host is left untouched apart from having the files in place --
# and the last line it prints is the command that installs there.
#
# Usage: ./deploy-taa-vm.sh [taa-train|taa-infer|taa-analysis]
#        ./deploy-taa-vm.sh --help   (this text)
#
# The role argument selects which package this run prepares and defaults to
# taa-train. Each role gets its own initrd (CONTRACT_TYPE, plus the semgrep
# payload for taa-train only), its own delivery directory on the host and its
# own runtime handler, so the three can be installed side by side; see the role
# section of build-initrd.sh. Nothing else about the flow changes.
#
# The mechanics stay under deploy/guest-build/: build-initrd.sh assembles the
# initrd, fetches base assets, renders the package and performs the upload, and
# its `launch` command installs on the host. This script only supplies the
# environment those steps need and runs the fixed push sequence; it resolves
# every setting by asking build-initrd.sh for them (`print-config`), so the
# defaults have exactly one definition and cannot drift.
#
# One property worth preserving when editing this file: nothing touches the host
# before the preflight below. A run that is going to fail should fail on this
# side of the ssh.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# This script lives at the repository root, but the build it drives lives under
# deploy/guest-build/. Assert we really are at the root: every relative path
# below (bin/taa, the guest-build scripts) silently points at nothing otherwise.
if [[ ! -f "$SCRIPT_DIR/go.mod" ]]; then
  echo "error: deploy-taa-vm.sh must sit at the repository root (no go.mod in $SCRIPT_DIR)" >&2
  exit 1
fi

GUEST_BUILD_DIR="$SCRIPT_DIR/deploy/guest-build"
BUILD_INITRD="$GUEST_BUILD_DIR/build-initrd.sh"
TAA_BIN="$SCRIPT_DIR/bin/taa"

if [[ ! -x "$BUILD_INITRD" ]]; then
  echo "error: $BUILD_INITRD not found or not executable" >&2
  exit 1
fi

# ── Host-side install root ───────────────────────────────────────────────────
#
# Everything this flow puts on the target host lives under one directory, with
# one subdirectory per role:
#
#   $TAA_IMAGES_DIR/package-train/     taa-train
#   $TAA_IMAGES_DIR/package-infer/     taa-infer
#   $TAA_IMAGES_DIR/package-analysis/  taa-analysis
#
# each holding the rendered delivery package including its bundle/
# (initramfs.img, vmlinuz, OVMF.fd).
#
# The package is the runtime dependency, not just a shipping container: the Kata
# config points at its bundle/, so the host never needs its own copies of those
# files and nothing is copied on the host. It also ships install.sh and the
# test/ scripts, so the host can be re-installed and its test Pod recreated
# without another build, render or upload:
#
#   sudo bash /root/taa-images/<role-dir>/install.sh
#   sudo bash /root/taa-images/<role-dir>/test/create-test-pod.sh
#
# The per-role subdirectory (`package-train`, `package-infer`, ...) is decided in
# build-initrd.sh, so this default only supplies the root. Naming the leaf here
# would give the driver a second copy of the role mapping, and a run of one role
# would install over another's package.
TAA_IMAGES_DIR="${TAA_IMAGES_DIR:-/root/taa-images}"
export TAA_IMAGES_DIR
if [[ -n "${REMOTE_PACKAGE_DIR:-}" ]]; then
  export REMOTE_PACKAGE_DIR
fi

# The binary build-initrd.sh injects. Defaulted and exported here so the
# preflight's static-link check and the build itself read the same file, even
# when an operator overrides TAA_SRC.
TAA_SRC="${TAA_SRC:-$TAA_BIN}"
export TAA_SRC
TAA_BIN="$TAA_SRC"

# Pull the resolved settings from build-initrd.sh instead of restating them here.
# That output is %q-quoted, so this eval is safe even for values with spaces.
eval "$("$BUILD_INITRD" print-config)"

REMOTE="${REMOTE_USER}@${REMOTE_HOST}"

# ── Test identity ────────────────────────────────────────────────────────────
#
# TAA registers itself with the management platform using PLATFORM_IP and
# DOCKER_ID. In production the platform injects both into the container
# environment; a CSV2 guest has no such injection, so this flow bakes them into
# /etc/default/taa.env at build time instead. Defaulted here so a bare run needs
# no environment set -- and here rather than in build-initrd.sh,
# where an empty value is meaningful ("the operator did not ask for a
# registration") and drives its own check.
#
# The default is the platform-mock on the Kata host itself. The address is
# written out rather than derived from REMOTE_HOST, so pointing this run at a
# platform somewhere else is only an override of TAA_PLATFORM_IP. DOCKER_ID must
# stay unique per instance or the platform sees two instances sharing one
# identity -- the id in production looks like the 32-hex value the platform
# allocates, but any stable string works, and a failed registration is only a
# warning (it does not stop TAA from starting).
PLATFORM_PORT="${PLATFORM_PORT:-18081}"
TAA_PLATFORM_IP="${TAA_PLATFORM_IP:-172.16.10.178:${PLATFORM_PORT}}"
TAA_DOCKER_ID="${TAA_DOCKER_ID:-kata-csv2-taa-test-0001}"
# The Tier-2 gateway address. The config template carries one too, but it is a
# Pod IP that belongs to the deployment the template was last edited for; the
# guest cannot be told apart from it at boot, so this flow pins the endpoint
# explicitly. Override TAA_LLM_ENDPOINT to point at another gateway.
TAA_LLM_ENDPOINT="${TAA_LLM_ENDPOINT:-https://172.16.10.178:18443}"
export TAA_PLATFORM_IP TAA_DOCKER_ID TAA_LLM_ENDPOINT

# TAA seals every request it sends to the platform with the platform's SM2 public
# key, and the platform decrypts it with the matching private key, so the key
# baked into the package must belong to the platform at TAA_PLATFORM_IP. A
# mismatch is silent from both ends: the platform answers 401 without logging
# the rejection, and the guest retries forever, so the only symptom is a
# registration that never appears. The key is therefore read from the platform
# itself (see resolve_platform_public_key below) rather than from a copy on the
# build host, which is how the two drifted apart before.
#
# GET on this path is a read. POST on it rotates the platform key pair, which
# would invalidate every image built against the old one -- never use it here.
PLATFORM_KEY_ENDPOINT="${PLATFORM_KEY_ENDPOINT:-http://${TAA_PLATFORM_IP}/api/crypto/generate-key}"

# ── Arguments ────────────────────────────────────────────────────────────────
#
# One behaviour, no subcommands: prepare the package and put it on the host.
# Anything that decides *what* to run lives in deploy/guest-build/build-initrd.sh
# (build, fetch-base, render, upload, launch); this script only runs the fixed
# push sequence the team uses.
usage() {
  sed -n '2,/^set -euo pipefail$/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'
}

# The role is passed straight through to build-initrd.sh, which owns the
# mapping and the defaults, so there is nothing to restate here -- only to
# reject early, before any build work, if the argument is not one.
case "${1:-}" in
  "") ;;
  -h|--help) usage; exit 0 ;;
  taa-train|taa-infer|taa-analysis) export TAA_ROLE="$1" ;;
  *)
    echo "error: unknown role or argument: $1" >&2
    echo "hint: ./deploy-taa-vm.sh [taa-train|taa-infer|taa-analysis]; '$0 --help' explains the flow" >&2
    exit 1
    ;;
esac

require_cmd() {
  local cmd
  for cmd in "$@"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "error: $cmd is not installed or not in PATH" >&2
      exit 1
    fi
  done
}

# ── Platform public key ──────────────────────────────────────────────────────
#
# Pins the platform's SM2 public key for this build. An explicitly given key or
# key file wins, so an offline run or a platform that is not running can still
# be packaged; otherwise the key is read from the platform the guest will
# actually talk to, which is the only copy guaranteed to decrypt what the guest
# sends. Exporting PLATFORM_PUBLIC_KEY is what carries it into build-initrd.sh
# (as a child process) and from there onto the rendered kernel command line.
resolve_platform_public_key() {
  if [[ -n "${PLATFORM_PUBLIC_KEY:-}" || -n "${TAA_PLATFORM_PUBLIC_KEY:-}" ]]; then
    echo "平台公钥：使用显式给出的值"
    return 0
  fi
  if [[ -n "${TAA_PLATFORM_KEY_FILE:-}" ]]; then
    echo "平台公钥：取自 $TAA_PLATFORM_KEY_FILE"
    return 0
  fi
  # ALLOW_MISSING_TAA_ENV is an explicit "this package does not register", so a
  # platform that is not there is not a reason to fail the build.
  if [[ "${ALLOW_MISSING_TAA_ENV:-0}" == "1" ]]; then
    echo "平台公钥：ALLOW_MISSING_TAA_ENV=1，跳过（不注册）"
    return 0
  fi

  require_cmd curl
  local body hex
  if ! body="$(curl -fsS --max-time 10 "$PLATFORM_KEY_ENDPOINT")"; then
    echo "error: 读取平台公钥失败: $PLATFORM_KEY_ENDPOINT" >&2
    echo "hint: 平台（platform-mock）需要在该地址运行；也可以显式给出" >&2
    echo "      PLATFORM_PUBLIC_KEY=<04+128 位十六进制> 或 TAA_PLATFORM_KEY_FILE=<含 publicKeyHex 的文件>" >&2
    exit 1
  fi
  hex="$(sed -n 's/.*"publicKeyHex"[[:space:]]*:[[:space:]]*"\([0-9a-fA-F]*\)".*/\1/p' <<<"$body" | head -n 1)"
  if [[ ! "$hex" =~ ^04[[:xdigit:]]{128}$ ]]; then
    echo "error: $PLATFORM_KEY_ENDPOINT 未返回合法的 SM2 公钥（04 + 128 位十六进制）: ${hex:-<空>}" >&2
    exit 1
  fi
  PLATFORM_PUBLIC_KEY="$hex"
  export PLATFORM_PUBLIC_KEY
  echo "平台公钥：$PLATFORM_KEY_ENDPOINT → ${hex:0:16}…"
}

# ── Remote privilege ─────────────────────────────────────────────────────────
#
# The upload writes into the remote package directory through sudo, and ssh
# hands the remote shell no tty to answer a prompt with. Worth checking before
# the local build too: a run that cannot finish should not spend a minute
# building first.
check_remote_sudo() {
  local mode
  if ! mode="$(ssh "$REMOTE" 'bash -s' <<'REMOTE_SUDO'
set -u
if [[ "$(id -u)" -eq 0 ]]; then
  echo "已以 root 登录"
  exit 0
fi
if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
  echo "非 root，但有免密 sudo"
  exit 0
fi
exit 1
REMOTE_SUDO
  )"; then
    echo "error: $REMOTE 无法免密提权，上传会失败" >&2
    echo "hint: 以 root 登录（默认 REMOTE_USER=root），或给该账号配 NOPASSWD sudoers 条目" >&2
    exit 1
  fi
  echo "远端提权：$mode"
}

# ── Compile before injecting ─────────────────────────────────────────────────
#
# The initrd is just a container for whatever bin/taa holds at build time, so an
# un-rebuilt binary is injected silently and only shows up as a guest that
# behaves like the previous revision. Compile into the same path the build
# reads, and publish atomically: a failed compile must not leave a truncated
# binary behind for the next run to inject.
#
# Two deliberate skips. A TAA_SRC pointing somewhere other than the default
# repository binary is an explicit "use this file" (and is what keeps the
# offline tests offline). TAA_SKIP_GO_BUILD=1 is a deliberate "use what is
# already there".
build_taa_binary() {
  if [[ "$TAA_BIN" != "$SCRIPT_DIR/bin/taa" ]]; then
    echo "TAA_SRC=$TAA_BIN，跳过重新编译"
    return 0
  fi
  if [[ "${TAA_SKIP_GO_BUILD:-0}" == "1" ]]; then
    echo "warning: TAA_SKIP_GO_BUILD=1，跳过重新编译，注入的是现有 bin/taa" >&2
    return 0
  fi
  require_cmd go
  echo "重新编译 TAA（CGO_ENABLED=0 GOOS=linux）"
  local tmp_bin="${TAA_BIN}.tmp.$$"
  rm -f "$tmp_bin"
  if ! ( cd "$SCRIPT_DIR" && CGO_ENABLED=0 GOOS=linux go build -o "$tmp_bin" ./cmd/taa ); then
    rm -f "$tmp_bin"
    echo "error: TAA 编译失败，未改动 $TAA_BIN" >&2
    exit 1
  fi
  chmod 0755 "$tmp_bin"
  mv -f "$tmp_bin" "$TAA_BIN"
  echo "bin/taa sha256: $(sha256sum "$TAA_BIN" | awk '{print $1}')"
}

# ── Preflight ────────────────────────────────────────────────────────────────
#
# Runs before anything is built or uploaded. Each check is something the flow
# cannot recover from later, so failing now is strictly cheaper than failing
# halfway through a build or an upload.
preflight() {
  require_cmd file ssh
  if [[ ! -f "$BASE_INITRD" ]]; then
    echo "error: base initrd 缺失: $BASE_INITRD" >&2
    echo "hint: 先跑 $BUILD_INITRD fetch-base" >&2
    exit 1
  fi
  # Before the build: the key is baked into the image and rendered onto the
  # kernel command line, so it has to be resolved before either happens.
  resolve_platform_public_key
  check_remote_sudo

  # The package must carry a registration identity; render refuses to package
  # an initrd without one. Surface that here with both ways out, rather than
  # letting it fail after a full build. Whether the identity baked into the
  # image matches this invocation is only a warning, reported by
  # build-initrd.sh where the image is packaged: the identity the guest actually
  # uses is the one render puts on the kernel command line.
  if [[ "${ALLOW_MISSING_TAA_ENV:-0}" != "1" ]]; then
    if [[ -z "${TAA_PLATFORM_IP:-}" || -z "${TAA_DOCKER_ID:-}" ]]; then
      echo "error: TAA_PLATFORM_IP 与 TAA_DOCKER_ID 需要成对给出（交付包要求 initrd 内含 etc/default/taa.env）" >&2
      echo "hint: 二者都给，或显式设置 ALLOW_MISSING_TAA_ENV=1 放弃平台注册" >&2
      exit 1
    fi
  fi

  # Compile last: a run that cannot build must not spend time compiling first.
  build_taa_binary
  if [[ ! -f "$TAA_BIN" ]]; then
    echo "error: bin/taa 缺失: $TAA_BIN" >&2
    echo "hint: CGO_ENABLED=0 GOOS=linux go build -o bin/taa ./cmd/taa" >&2
    exit 1
  fi
  if ! file -b "$TAA_BIN" | grep -q 'statically linked'; then
    echo "error: bin/taa 是动态链接的；base initrd 里没有 glibc，注入后起不来" >&2
    echo "hint: CGO_ENABLED=0 GOOS=linux go build -o bin/taa ./cmd/taa" >&2
    exit 1
  fi
}

# ── The push sequence ────────────────────────────────────────────────────────
#
# 1. compile TAA and build the initrd          (build-initrd.sh build)
# 2. render the package locally and upload it  (build-initrd.sh upload)
#
# The host is left exactly as it was apart from having the files in place: no
# containerd edit, no RuntimeClass, no Pod. Install there with the command this
# prints at the end, as often as needed.
preflight

echo "=== 1/3 编译 TAA 并构建 initrd ==="
"$BUILD_INITRD" build
echo
echo "=== 2/3 本地渲染并上传交付包到 $REMOTE ==="
"$BUILD_INITRD" upload
echo
echo "=== 3/3 未安装 ==="
echo "在宿主机上安装：ssh $REMOTE 'cd $REMOTE_PACKAGE_DIR && sudo bash install.sh'"
echo "       测试 Pod：ssh $REMOTE 'cd $REMOTE_PACKAGE_DIR && sudo bash test/create-test-pod.sh'"
