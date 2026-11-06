#!/usr/bin/env bash
# End-to-end driver for the "TAA inside the Kata CSV2 initrd" flow.
#
# Lives at the repository root so the whole flow is one command from the top of
# the tree; the build it drives stays under deploy/guest-build/.
#
# build-initrd.sh stays the authority on the mechanics (how the initrd is
# assembled, what gets written on the host, how the test Pod is launched). This
# script only decides which steps run in what order, supplies the environment
# they need, and adds the one step build-initrd.sh deliberately does not have:
# teardown. It resolves every setting by asking build-initrd.sh for them
# (`print-config`), so the defaults have exactly one definition and cannot drift.
#
# Commands:
#   up      build -> launch -> verify             (the whole flow)
#   build | launch | fetch-base                   (single steps, passed through)
#   render  Render the delivery package locally (Kata config, containerd
#           fragment + merger, K8s manifests, install.sh, checksums). No host
#           access; also what `launch` renders before uploading.
#   verify  Read-only: TCP liveness + startup-log attestation self-check.
#   delete  Remove everything this flow installed on the host, including the
#           test Pod. Supports --dry-run.
#
# Two properties worth preserving when editing this file:
#   1. Nothing that mutates the host runs before the preflight below. A run that
#      is going to fail should fail on this side of the ssh.
#   2. `delete` only ever removes the TAA-specific names. The original Kata
#      config, the original containerd runtime handler and the base initrd are
#      read (and their hashes compared before/after) but never written.
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
# Everything this flow puts on the target host lives under one directory:
#
#   $TAA_IMAGES_DIR/package/   the rendered delivery package, including its
#                              bundle/ (initramfs.img, vmlinuz, OVMF.fd)
#
# The package is the runtime dependency, not just a shipping container: the Kata
# config points at its bundle/, so the host never needs its own copies of those
# files and nothing is copied on the host. It also ships install.sh, so the test
# Pod can be recreated there by running
#
#   sudo bash /root/taa-images/package/install.sh
#
# without another build, render or upload.
#
# REMOTE_PACKAGE_DIR is exported *before* print-config is consulted below.
# build-initrd.sh resolves its defaults from the environment and runs as a child
# process, so exporting here is what makes the value the flow actually uses; the
# bundle directory is derived from it there and is not separately configurable.
TAA_IMAGES_DIR="${TAA_IMAGES_DIR:-/root/taa-images}"
export REMOTE_PACKAGE_DIR="${REMOTE_PACKAGE_DIR:-$TAA_IMAGES_DIR/package}"

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
# /etc/default/taa.env at build time instead. Defaulted here so `up` is one word
# with no environment to remember -- and here rather than in build-initrd.sh,
# where an empty value is meaningful ("the operator did not ask for a
# registration") and drives its own check.
#
# The platform (platform-mock) runs on its own host, not on the Kata host, so the
# default points at that address instead of following REMOTE_HOST; override
# TAA_PLATFORM_IP to register against a platform somewhere else. DOCKER_ID must
# stay unique per instance or the platform sees two instances sharing one
# identity -- the id in production looks like the 32-hex value the platform
# allocates, but any stable string works, and a failed registration is only a
# warning (it does not stop TAA from starting).
PLATFORM_PORT="${PLATFORM_PORT:-18080}"
TAA_PLATFORM_IP="${TAA_PLATFORM_IP:-172.16.10.116:${PLATFORM_PORT}}"
TAA_DOCKER_ID="${TAA_DOCKER_ID:-kata-csv2-taa-test-0001}"
# The Tier-2 gateway address. The config template carries one too, but it is a
# Pod IP that belongs to the deployment the template was last edited for; the
# guest cannot be told apart from it at boot, so this flow pins the endpoint
# explicitly. Override TAA_LLM_ENDPOINT to point at another gateway.
TAA_LLM_ENDPOINT="${TAA_LLM_ENDPOINT:-https://172.16.10.116:8443}"
export TAA_PLATFORM_IP TAA_DOCKER_ID TAA_LLM_ENDPOINT

# The shipped runtime handler. `delete` refuses to touch a runtime that points at
# it, because that one belongs to the host, not to this flow.
PROTECTED_HANDLER="${PROTECTED_HANDLER:-kata-qemu-csv2}"
CONTAINERD_CONFIG="${CONTAINERD_CONFIG:-/etc/containerd/config.toml}"
# Container name created by the test Pod manifest in build-initrd.sh.
TEST_CONTAINER_NAME="${TEST_CONTAINER_NAME:-test}"

DRY_RUN=0

usage() {
  cat <<EOF
Usage: $0 <command> [options]

Commands:
  up            生成 initrd -> 打包上传 -> 配置并拉起测试 Pod -> 验证 TAA（推荐入口）
  build         只构建本地 initrd（等价于 build-initrd.sh build）
  render        只在本地生成交付包（Kata 配置 / 可编辑的部署身份 / containerd
                handler / K8s YAML / 安装脚本 / 校验和 / initrd+内核+OVMF），
                不访问宿主机
  launch        本地渲染 -> 整包上传 -> 在远端安装并拉起测试 Pod（宿主上不复制任何文件）
  fetch-base    从远端拉取权威 base 资产（等价于 build-initrd.sh fetch-base）
  verify        只读校验：TCP 探活 + 启动日志里的证明自检结论
  delete        删除本流程在远端安装的全部产物与测试 Pod
  print-config  打印解析后的实际取值（KEY=%q，可直接 eval），用来确认这次会用什么
  help          显示本帮助

Options:
  -n, --dry-run   仅用于 delete：只打印将要删除的内容，不做任何改动
  -f, --force     仅用于 delete：跳过"该 RuntimeClass 仍被其它 Pod 使用"的拒绝

Environment:
  REMOTE_USER=$REMOTE_USER          SSH 账号（需免密 sudo）
  REMOTE_HOST=$REMOTE_HOST
  TAA_IMAGES_DIR=$TAA_IMAGES_DIR    （宿主侧统一安装根目录）
  REMOTE_PACKAGE_DIR=$REMOTE_PACKAGE_DIR
                                          （交付包位置；bundle 就在包内 bundle/，
                                          不可单独指定）
  TEST_POD_NAME=$TEST_POD_NAME
  TEST_IMAGE=$TEST_IMAGE
  TEST_NODE_NAME=$TEST_NODE_NAME
  TEST_POD_ANNOTATIONS=$TEST_POD_ANNOTATIONS
  TAA_PLATFORM_IP=$TAA_PLATFORM_IP        （默认指向平台主机，端口 PLATFORM_PORT=$PLATFORM_PORT）
  TAA_DOCKER_ID=$TAA_DOCKER_ID            （每个实例必须唯一；覆盖 PLATFORM_PORT 可换平台端口）
  TAA_LLM_ENDPOINT=$TAA_LLM_ENDPOINT      （Tier-2 网关地址；覆盖 configs/taa-production.json 里的 endpoint）
  PLATFORM_PUBLIC_KEY=<130 hex>           （平台 SM2 公钥；TAA 必需，见下）
  TAA_PLATFORM_KEY_FILE=<file>           （可选；默认 .local/platform-mock/platform-key.json，
                                          未给 PLATFORM_PUBLIC_KEY 时从这里读 publicKeyHex）
  TAA_PLATFORM_SM2_ID / TAA_CONTRACT_ID / TAA_CONTRACT_TYPE
                                          （可选，随身份写进交付包的 config/identity.txt）
  RUNTIME_HANDLER=$RUNTIME_HANDLER
  REMOTE_KATA_CONFIG=$REMOTE_KATA_CONFIG
                                          （runtime handler 的 ConfigPath；默认就是交付包里的
                                          $PACKAGE_KATA_CONFIG，宿主机不再另存一份）
  TAA_SRC=$TAA_SRC                （指向其它二进制时跳过重新编译）
  TAA_SKIP_GO_BUILD=${TAA_SKIP_GO_BUILD:-0}     （=1 跳过编译，直接注入现有 bin/taa）

  build/up 会先重新编译 TAA（CGO_ENABLED=0 GOOS=linux go build），
  再把新的 bin/taa 注入 initrd，避免注入上一次的旧二进制。

Layout on the host (defaults):
  $REMOTE_PACKAGE_DIR/            launch 上传的整份交付包（含 install.sh）
    bundle/initramfs.img|vmlinuz|OVMF.fd   QEMU 直接启动的三份文件

  Kata 配置本身就在交付包里（$PACKAGE_KATA_CONFIG），containerd 的 ConfigPath
  直接指向它，内核/initrd/OVMF 也指向包内 bundle/，宿主机 /opt/kata 与 /etc 下
  都不再需要这几位文件。因此交付包是运行期依赖：删包之前要先用 '$0 delete'
  摘掉 handler。整包 scp 过去即可部署，宿主上不复制任何文件。

  launch 完成后交付包会保留，重建测试 Pod 只需在该宿主机上执行：
    sudo bash $REMOTE_PACKAGE_DIR/install.sh

  换部署身份（平台地址 / dockerId / 公钥 / LLM 端点 …）不需要回到本机重新 render：
  在宿主机上编辑 $REMOTE_PACKAGE_DIR/config/identity.txt，再跑一次 install.sh 即可。
  它会按该文件重渲染 $PACKAGE_KATA_CONFIG、重算预期度量，并删旧 Pod 后重建。

CoCo note: on this host a CoCo Pod also needs the cc_init_data annotation, or the
in-guest CDH cannot pull the image and the Pod lands in StartError. 'up' and
'launch' fetch that single key from an already-running CoCo Pod when
TEST_POD_ANNOTATIONS is unset. Only that one key is copied: the runtime-handler
key would hijack the runtime, and an empty hypervisor kernel_params would erase
the rdinit= that starts TAA.
EOF
}

require_cmd() {
  local cmd
  for cmd in "$@"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "error: $cmd is not installed or not in PATH" >&2
      exit 1
    fi
  done
}

# The resolved settings, in the same KEY=%q form build-initrd.sh prints them, so
# `eval "$(./deploy-taa-vm.sh print-config)"` works from a shell and the test
# suite can assert on real values instead of grepping the source.
print_config() {
  local key
  for key in REMOTE_USER REMOTE_HOST REMOTE PLATFORM_PORT TAA_PLATFORM_IP \
             TAA_DOCKER_ID TAA_LLM_ENDPOINT RUNTIME_HANDLER RUNTIME_TYPE SNAPSHOTTER \
             CONTAINERD_CONFIG KATA_CONFIG_TEMPLATE DIST_DIR TAA_IMAGES_DIR \
             REMOTE_BUNDLE_DIR REMOTE_PACKAGE_DIR REMOTE_KATA_CONFIG \
             TEST_POD_NAME TEST_NODE_NAME TEST_IMAGE TEST_POD_ANNOTATIONS \
             INITRD_OUT; do
    printf '%s=%q\n' "$key" "${!key}"
  done
}

# ── Remote privilege ─────────────────────────────────────────────────────────
#
# Every mutating step writes host configuration through sudo, and ssh hands the
# remote shell no tty to answer a prompt with. Worth checking before the local
# build too: a run that cannot finish should not spend a minute building first.
# Cached, because `up` preflights several steps and this costs an ssh each time.
SUDO_CHECKED=0
check_remote_sudo() {
  [[ "$SUDO_CHECKED" == "1" ]] && return 0
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
    echo "error: $REMOTE 无法免密提权，流程会改到一半失败" >&2
    echo "hint: 以 root 登录（默认 REMOTE_USER=root），或给该账号配 NOPASSWD sudoers 条目" >&2
    exit 1
  fi
  SUDO_CHECKED=1
  echo "远端提权：$mode"
}

# ── CoCo annotation discovery ────────────────────────────────────────────────
#
# The image is pulled by the CDH inside the guest, so the registry CA has to
# reach it through the Pod's cc_init_data annotation. Reuse the value an
# already-running CoCo Pod carries rather than asking the operator to paste a
# multi-kilobyte base64 blob. Only that single key is taken.
derive_cc_init_data() {
  local derived
  derived="$(ssh "$REMOTE" 'bash -s' <<'REMOTE_DERIVE' || true
set -euo pipefail
command -v kubectl >/dev/null 2>&1 || exit 1
# The dots inside the annotation key are escaped for jsonpath. Inside this
# quoted heredoc the backslashes reach the remote shell unchanged.
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.annotations.io\.katacontainers\.config\.runtime\.cc_init_data}{"\n"}{end}' 2>/dev/null |
  awk 'NF {print; exit}'
REMOTE_DERIVE
)"
  derived="${derived//$'\r'/}"
  derived="${derived//$'\n'/}"
  [[ -n "$derived" ]] || return 1
  # Build the JSON here rather than by hand, so a value containing a quote or a
  # backslash cannot produce malformed JSON.
  python3 -c 'import json, sys; print(json.dumps({"io.katacontainers.config.runtime.cc_init_data": sys.argv[1]}))' "$derived"
}

ensure_pod_annotations() {
  if [[ "$TEST_POD_ANNOTATIONS" != "{}" ]]; then
    echo "使用已给出的 TEST_POD_ANNOTATIONS"
    return 0
  fi
  echo "TEST_POD_ANNOTATIONS 未设置，尝试从远端已有 CoCo Pod 复用 cc_init_data"
  local derived
  if derived="$(derive_cc_init_data)"; then
    TEST_POD_ANNOTATIONS="$derived"
    export TEST_POD_ANNOTATIONS
    echo "已取到 cc_init_data（共 ${#TEST_POD_ANNOTATIONS} 字节 JSON）"
  else
    echo "warning: 远端未找到任何带 cc_init_data 的 Pod" >&2
    echo "warning: guest 内 CDH 将无法拉取镜像，测试 Pod 很可能停在 StartError" >&2
    echo "hint: 手动指定 TEST_POD_ANNOTATIONS，或先跑通一个 CoCo Pod 再重试" >&2
  fi
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
# Runs before any host mutation. Each check here is something the flow cannot
# recover from later, so failing now is strictly cheaper than failing mid-way.
preflight() {
  local step="$1"

  case "$step" in
    build|up)
      require_cmd file
      if [[ ! -f "$BASE_INITRD" ]]; then
        echo "error: base initrd 缺失: $BASE_INITRD" >&2
        echo "hint: 先跑 $0 fetch-base" >&2
        exit 1
      fi
      # After the base check on purpose: a run that cannot build must not spend
      # time compiling first.
      build_taa_binary
      local taa_bin="$TAA_BIN"
      if [[ ! -f "$taa_bin" ]]; then
        echo "error: bin/taa 缺失: $taa_bin" >&2
        echo "hint: CGO_ENABLED=0 GOOS=linux go build -o bin/taa ./cmd/taa" >&2
        exit 1
      fi
      if ! file -b "$taa_bin" | grep -q 'statically linked'; then
        echo "error: bin/taa 是动态链接的；base initrd 里没有 glibc，注入后起不来" >&2
        echo "hint: CGO_ENABLED=0 GOOS=linux go build -o bin/taa ./cmd/taa" >&2
        exit 1
      fi
      ;;
  esac

  case "$step" in
    launch|up)
      require_cmd ssh
      check_remote_sudo
      # The initrd must carry a registration identity or render refuses to
      # package it. Surface that here with both ways out, rather than letting it
      # fail after a full build. Whether the identity it carries matches this
      # invocation is reported (not enforced) in build-initrd.sh, where the image
      # is packaged: `up` builds first, so judging the image here would look at
      # the previous build. The identity the guest actually uses is the one
      # `render` puts on the kernel command line.
      if [[ "${ALLOW_MISSING_TAA_ENV:-0}" != "1" ]]; then
        if [[ -z "${TAA_PLATFORM_IP:-}" || -z "${TAA_DOCKER_ID:-}" ]]; then
          echo "error: TAA_PLATFORM_IP 与 TAA_DOCKER_ID 需要成对给出（交付包要求 initrd 内含 etc/default/taa.env）" >&2
          echo "hint: 二者都给，或显式设置 ALLOW_MISSING_TAA_ENV=1 放弃平台注册" >&2
          exit 1
        fi
      fi
      ensure_pod_annotations
      if [[ "$TEST_IMAGE" == "busybox:latest" ]]; then
        echo "note: 这台宿主的 guest 拉不到 Docker Hub（实测 CDH 报 error sending request for index.docker.io）" >&2
        echo "note: 本地 registry 里有 172.16.10.178:31313/taa-env:slim-v2-20260916（verify 用 guest 内的 /dev/tcp 与 /tmp/taa.log，不需要 curl）" >&2
      fi
      ;;
  esac
}

# ── Registration identity on the kernel command line ─────────────────────────
#
# Nothing about this shell's environment reaches the guest: TAA is the initrd's
# first process, started before kata-agent and before the Pod's environment
# exists. `render` therefore writes the deployment identity into the Kata config as
# kernel_params tokens (taa.<key>=<value>), QEMU passes them on -append, and
# taa-init reads them from /proc/cmdline, overriding the /etc/default/taa.env baked
# into the image. That is what makes an identity change a re-render rather than a
# rebuild.
#
# The comparison between the identity baked into an image and the one this
# invocation asks for still lives in build-initrd.sh (check_initrd_identity), next
# to the code that writes that file. It is a warning now, not a refusal: the
# rendered command line wins. It runs when render packages the image, not in the
# preflight above, because in the `up` path the preflight runs before the build
# and would always be looking at the previous image.

# ── verify ───────────────────────────────────────────────────────────────────
#
# Covers acceptance criteria 5 and 6 of the spec: TAA answers, and it hands back
# a report it has verified itself. Every route under /v1/taa/ is POST-only.
verify_remote() {
  require_cmd ssh python3
  echo "校验 pod/$TEST_POD_NAME 内的 TAA（$REMOTE）"

  local out
  out="$(ssh "$REMOTE" "bash -s -- $(printf '%q ' "$TEST_POD_NAME" "$TEST_CONTAINER_NAME")" <<'REMOTE_VERIFY'
set -euo pipefail
pod="$1"
container="$2"
command -v kubectl >/dev/null 2>&1 || { echo "error: kubectl not found" >&2; exit 1; }

if ! kubectl get pod "$pod" >/dev/null 2>&1; then
  echo "error: pod/$pod 不存在，先跑 launch 或 up" >&2
  exit 1
fi

# The Pod's netns is the guest's netns, so TAA is reachable on localhost.
#
# Everything under /v1/taa/ except fheCallback is now sealed with an SM2
# {cipher,sign} envelope. This script holds no platform private key to sign a
# request and no TAA private key to open the reply, so the API is not a checking
# surface available to an operator at all. What is left is a TCP connect, which
# is still a real gate: TAA reaches ListenAndServe only after config loading,
# key recovery and the first registration attempt have all returned.
#
# The startup log is NOT reachable from here in the initrd flow: TAA runs as the
# guest's first userspace process and writes /tmp/taa.log in the GUEST, while
# this exec lands in a container whose /tmp is its own tmpfs. So the log checks
# below are best-effort and only warn -- a hard failure on an unreachable file
# would report "verification failed" for a perfectly healthy instance.
echo "--- liveness ---"
# /dev/tcp is a bash feature: busybox ash does not have it, and a slim image may
# carry any of bash, python3 or nc depending on what it was built for. Try each
# in turn rather than assume, so a missing client reports "cannot probe" instead
# of "TAA is down".
if kubectl exec "$pod" -c "$container" -- bash -c 'exec 3<>/dev/tcp/127.0.0.1/6001' 2>/dev/null \
   || kubectl exec "$pod" -c "$container" -- python3 -c 'import socket; socket.create_connection(("127.0.0.1", 6001), timeout=5).close()' 2>/dev/null \
   || kubectl exec "$pod" -c "$container" -- nc -z -w 2 127.0.0.1 6001 2>/dev/null; then
  echo "OK:   tcp 127.0.0.1:6001 accepts connections"
else
  echo "error: 127.0.0.1:6001 不接受连接，或容器内没有可用于探测的客户端（bash/python3/nc）" >&2
  echo "hint: TAA 在 guest 内，日志是 guest 的 /tmp/taa.log（容器里的 /tmp 是另一份）" >&2
  kubectl exec "$pod" -c "$container" -- tail -n 60 /tmp/taa.log 2>/dev/null || true
  exit 1
fi
echo

echo "--- startup log (best effort) ---"
if kubectl exec "$pod" -c "$container" -- sh -c "test -f /tmp/taa.log" 2>/dev/null; then
  if kubectl exec "$pod" -c "$container" -- sh -c "grep -q 'taa service listening on' /tmp/taa.log" 2>/dev/null; then
    echo "OK:   listener logged itself"
  else
    echo "WARN: 容器内 /tmp/taa.log 里没有 'taa service listening on'（端口已开，可能是旧进程或启动未完成）"
  fi
  kubectl exec "$pod" -c "$container" -- sh -c "grep -i 'attestation\|service listening' /tmp/taa.log | tail -n 20" 2>/dev/null || true
else
  echo "WARN: 容器内没有 /tmp/taa.log —— TAA 在 guest init ns，它的日志在 guest 的 /tmp/taa.log。"
  echo "      要读它需要 kata debug console（agent.debug_console_enabled = true + kata-runtime exec）。"
  echo "      本流程无法从容器侧读到，故仅作提示，不影响校验结论。"
fi
echo
REMOTE_VERIFY
)"

  # The remote side already reduced each check to an OK/error line and exits
  # non-zero on the first failure, so this parse only has to turn that into the
  # exit status a caller can branch on. Written to a file rather than passed
  # with -c so the program can use quotes freely.
  local prog rc=0
  prog="$(mktemp /tmp/taa-verify.XXXXXX.py)"
  cat > "$prog" <<'PY'
import sys

text = sys.stdin.read()

# Only the script's own verdict lines count. The log excerpt below them is
# diagnostic output and regularly contains the word "error", so matching it
# anywhere in the line would fail a healthy run.
failures = [line for line in text.splitlines() if line.startswith("FAIL:") or line.startswith("error:")]
oks = [line for line in text.splitlines() if line.startswith("OK:")]

for line in oks:
    print(line)
for line in failures:
    print(line)

# An empty answer is a failure, not a pass: ssh to a live host that ran nothing
# would otherwise look like verification succeeded.
if not oks:
    print("FAIL: 远端没有返回任何校验结果")
    sys.exit(1)
if failures:
    sys.exit(1)
sys.exit(0)
PY
  printf '%s' "$out" | python3 "$prog" || rc=$?
  rm -f "$prog"
  return "$rc"
}

# ── delete ───────────────────────────────────────────────────────────────────
#
# Removes everything `up` installed. The guards in the remote script are the
# point of this function: this runs on a shared host, so a wrong variable here
# would take down a runtime other people are using.
delete_remote() {
  require_cmd ssh
  if [[ "$DRY_RUN" == "1" ]]; then
    echo "dry-run：只打印将要删除的内容，不做任何改动"
  fi
  local remote_args
  remote_args="$(printf '%q ' "$REMOTE_BUNDLE_DIR" "$REMOTE_BASE_INITRD_SRC" "$REMOTE_KATA_CONFIG_SRC" \
    "$REMOTE_KATA_CONFIG" "$RUNTIME_HANDLER" "$PROTECTED_HANDLER" "$CONTAINERD_CONFIG" \
    "$TEST_POD_NAME" "$DRY_RUN" "${FORCE_DELETE:-0}" "${REMOTE_PACKAGE_DIR:-}")"
  ssh "$REMOTE" "bash -s -- $remote_args" <<'REMOTE_DELETE'
set -euo pipefail
bundle_dir="$1"
base_initrd_src="$2"
kata_config_src="$3"
kata_config="$4"
runtime_handler="$5"
protected_handler="$6"
containerd_config="$7"
test_pod_name="$8"
dry_run="$9"
force_delete="${10}"
package_dir="${11}"

for cmd in kubectl sudo grep python3 cmp sha256sum awk; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "error: $cmd is not installed or not in PATH" >&2
    exit 1
  fi
done

# Establish privilege before the first mutation, for the same reason the other
# steps do: ssh cannot answer a sudo prompt.
if [[ "$(id -u)" -ne 0 ]] && ! sudo -n true 2>/dev/null; then
  echo "error: this SSH account needs passwordless sudo on the host (sudo -n true failed)" >&2
  echo "hint: log in as root, or add a NOPASSWD sudoers entry for this account" >&2
  exit 1
fi

# run <cmd...>: the single mutation point. In dry-run it only prints.
run() {
  if [[ "$dry_run" == "1" ]]; then
    printf 'dry-run: %s\n' "$*"
  else
    "$@"
  fi
}

echo "== 删除前的安全校验 =="

# Guard 1: never target the shipped config or the shipped handler.
if [[ "$kata_config" == "$kata_config_src" ]]; then
  echo "error: REMOTE_KATA_CONFIG 指向出厂 Kata 配置，拒绝操作: $kata_config" >&2
  exit 1
fi
if [[ "$runtime_handler" == "$protected_handler" ]]; then
  echo "error: RUNTIME_HANDLER 是出厂 handler，拒绝删除: $runtime_handler" >&2
  exit 1
fi
# Guard 2: never remove a directory that also holds the base initrd, and never
# aim at a top-level directory by accident. The bundle normally lives *inside*
# the delivery package now, so that containment is expected and handled in step
# 5; a bundle directory outside the package is a leftover from the old layout and
# gets its own guards.
case "$package_dir" in
  /|/root|/root/taa-images|/opt|/opt/kata|/opt/kata/share|/opt/kata/share/kata-containers|"$(dirname "$base_initrd_src")")
    echo "error: REMOTE_PACKAGE_DIR 指向共享目录，拒绝删除: $package_dir" >&2
    exit 1
    ;;
esac
if [[ "$bundle_dir" != "$package_dir" && "$bundle_dir" != "$package_dir"/* ]]; then
  case "$bundle_dir" in
    ""|/|/root|/root/taa-images|/opt|/opt/kata|/opt/kata/share|/opt/kata/share/kata-containers|"$(dirname "$base_initrd_src")")
      echo "error: REMOTE_BUNDLE_DIR 指向共享目录，拒绝删除: $bundle_dir" >&2
      exit 1
      ;;
  esac
  if [[ "$package_dir" == "$bundle_dir"/* ]]; then
    echo "error: 交付包位于 bundle 目录内，拒绝删除: $bundle_dir / $package_dir" >&2
    exit 1
  fi
fi

# Guard 3: refuse while other Pods still use this RuntimeClass. Deleting it would
# break them, and they are not ours to break. kubectl's jsonpath has no filter
# expressions, so filter the name/runtimeClassName pairs with awk. A kubectl that
# cannot list Pods at all fails closed rather than guessing.
if ! kubectl get pods -A >/dev/null 2>&1; then
  echo "error: kubectl 无法列出 Pod，无法确认 $runtime_handler 是否仍被占用" >&2
  exit 1
fi
other_pods="$(kubectl get pods -A \
  -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.runtimeClassName}{"\n"}{end}' |
  awk -v h="$runtime_handler" -v p="$test_pod_name" '$2 == h && $1 != p {print $1}')"
if [[ -n "${other_pods//[[:space:]]/}" ]]; then
  if [[ "$force_delete" != "1" ]]; then
    echo "error: RuntimeClass $runtime_handler 仍被以下 Pod 使用，拒绝删除：" >&2
    printf '%s\n' "$other_pods" >&2
    echo "hint: 先处理这些 Pod，或用 $0 delete --force 强行继续" >&2
    exit 1
  fi
  echo "warning: --force，RuntimeClass 仍被占用，继续删除" >&2
fi

# Record what must survive this command, so it can be proven afterwards.
orig_kata_sha_before=""
[[ -f "$kata_config_src" ]] && orig_kata_sha_before="$(sha256sum "$kata_config_src" | awk '{print $1}')"
base_sha_before=""
[[ -f "$base_initrd_src" ]] && base_sha_before="$(sha256sum "$base_initrd_src" | awk '{print $1}')"

echo
echo "== 1. 测试 Pod =="
if kubectl get pod "$test_pod_name" >/dev/null 2>&1; then
  if [[ "$dry_run" == "1" ]]; then
    echo "dry-run: kubectl delete pod $test_pod_name"
  else
    kubectl delete pod "$test_pod_name" --ignore-not-found --wait=true --timeout=90s || true
    # A VM-backed Pod whose guest is wedged will not answer the graceful delete;
    # fall back to force so a broken test Pod cannot block the teardown.
    if kubectl get pod "$test_pod_name" >/dev/null 2>&1; then
      echo "warning: pod 未在 90s 内退出，改用强制删除" >&2
      kubectl delete pod "$test_pod_name" --force --grace-period=0 || true
    fi
  fi
else
  echo "pod/$test_pod_name 不存在，跳过"
fi

echo
echo "== 2. RuntimeClass =="
if kubectl get runtimeclass "$runtime_handler" >/dev/null 2>&1; then
  run kubectl delete runtimeclass "$runtime_handler" --ignore-not-found
else
  echo "RuntimeClass $runtime_handler 不存在，跳过"
fi

echo
echo "== 3. containerd runtime handler =="
if [[ ! -f "$containerd_config" ]]; then
  echo "warning: 找不到 $containerd_config，跳过" >&2
else
  tmp_containerd="$(mktemp /tmp/containerd-config.delete.XXXXXX.toml)"
  trap 'rm -f "$tmp_containerd"' EXIT
  sudo cp "$containerd_config" "$tmp_containerd"
  # Drop the handler's own table and any child table (…​.options) with it. This is
  # the same table-path walk the launch step uses, so the two agree on what one
  # block is.
  #
  # The marker comments below delimit this program so test-deploy-taa-vm.sh can
  # extract and run it against a fixture: this is the only code in the flow that
  # rewrites a config file the whole host depends on.
  # BEGIN containerd-handler-strip
  sudo python3 - "$tmp_containerd" "$runtime_handler" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
handler = sys.argv[2]
target = ["plugins", "io.containerd.grpc.v1.cri", "containerd", "runtimes", handler]


def split_table_path(src):
    parts, buf, in_quote, escape = [], [], False, False
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


out, skip = [], False
for line in path.read_text().splitlines():
    parts = table_path(line)
    if parts is not None:
        skip = len(parts) >= len(target) and parts[:len(target)] == target
        if skip:
            continue
    if not skip:
        out.append(line)

# Collapse the blank lines the removal leaves at the end of the file.
while out and not out[-1].strip():
    out.pop()
path.write_text("\n".join(out) + "\n")
PY
  # END containerd-handler-strip

  if sudo cmp -s "$tmp_containerd" "$containerd_config"; then
    echo "containerd 配置里没有 $runtime_handler，跳过重启"
  elif [[ "$dry_run" == "1" ]]; then
    echo "dry-run: 从 $containerd_config 移除 runtime handler $runtime_handler 并重启 containerd"
  else
    echo "移除 runtime handler 并重启 containerd"
    backup="$(mktemp /tmp/containerd-config.backup.XXXXXX.toml)"
    sudo cp -a "$containerd_config" "$backup"
    sudo install -o root -g root -m 0644 "$tmp_containerd" "$containerd_config"
    if ! sudo systemctl restart containerd || ! sudo systemctl is-active --quiet containerd; then
      sudo journalctl -u containerd -n 50 --no-pager >&2 || true
      echo "error: containerd 重启失败，回滚配置" >&2
      sudo install -o root -g root -m 0644 "$backup" "$containerd_config"
      sudo systemctl restart containerd || true
      sudo rm -f "$backup"
      exit 1
    fi
    sudo rm -f "$backup"
    echo "containerd 已重启"
  fi
fi

echo
echo "== 4. Kata 配置 =="
# With a persistent package the handler points at the packaged file, so the
# config goes away with the package in step 6. The handler is already gone by
# now, which is the order that matters: nothing may still reference the file
# when it disappears.
if [[ -n "$package_dir" && "$kata_config" == "$package_dir"/* ]]; then
  echo "$kata_config 位于交付包内，随交付包删除"
elif [[ -f "$kata_config" ]]; then
  run sudo rm -f "$kata_config"
else
  echo "$kata_config 不存在，跳过"
fi

echo
echo "== 5. remote bundle =="
if [[ "$bundle_dir" == "$package_dir" || "$bundle_dir" == "$package_dir"/* ]]; then
  echo "$bundle_dir 位于交付包内，随交付包删除"
elif [[ -d "$bundle_dir" ]]; then
  echo "将删除旧布局的独立 bundle $bundle_dir:"
  sudo ls -1 "$bundle_dir" 2>/dev/null | sed 's/^/  /' || true
  run sudo rm -rf "$bundle_dir"
else
  echo "$bundle_dir 不存在，跳过"
fi

echo
echo "== 6. 交付包 =="
if [[ -d "$package_dir" ]]; then
  echo "将删除 $package_dir:"
  sudo ls -1 "$package_dir" 2>/dev/null | sed 's/^/  /' || true
  run sudo rm -rf "$package_dir"
  # Drop the install root only if it is empty. rmdir itself is the guard:
  # anything somebody else put beside the package keeps it in place.
  run sudo rmdir "$(dirname "$package_dir")" 2>/dev/null || true
else
  echo "$package_dir 不存在，跳过"
fi

echo
echo "== 7. 回归核对（本次操作不该改动的东西）=="
if [[ -n "$orig_kata_sha_before" ]]; then
  orig_kata_sha_after="$(sha256sum "$kata_config_src" | awk '{print $1}')"
  if [[ "$orig_kata_sha_after" == "$orig_kata_sha_before" ]]; then
    echo "OK: 出厂 Kata 配置未变: $orig_kata_sha_after"
  else
    echo "error: 出厂 Kata 配置被改动了！" >&2
    echo "  before: $orig_kata_sha_before" >&2
    echo "  after:  $orig_kata_sha_after" >&2
    exit 1
  fi
fi
if [[ -n "$base_sha_before" ]]; then
  base_sha_after="$(sha256sum "$base_initrd_src" | awk '{print $1}')"
  if [[ "$base_sha_after" == "$base_sha_before" ]]; then
    echo "OK: base initrd 未变: $base_sha_after"
  else
    echo "error: base initrd 被改动了！" >&2
    exit 1
  fi
fi

echo
if [[ "$dry_run" == "1" ]]; then
  echo "dry-run 结束：以上内容尚未删除"
else
  echo "清理完成"
fi
REMOTE_DELETE
}

# ── dispatch ─────────────────────────────────────────────────────────────────
cmd="${1:-help}"
shift || true

# delete takes its own options, so parse them here rather than for every command.
if [[ "$cmd" == "delete" ]]; then
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -n|--dry-run) DRY_RUN=1 ;;
      -f|--force) FORCE_DELETE=1 ;;
      -h|--help) usage; exit 0 ;;
      *) echo "error: unknown option for delete: $1" >&2; exit 1 ;;
    esac
    shift
  done
elif [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

case "$cmd" in
  up)
    preflight build
    preflight launch
    echo "=== 1/3 构建 initrd 并打包上传 ==="
    "$BUILD_INITRD" build
    echo
    echo "=== 2/3 配置运行时并拉起测试 Pod（整包安装到 $REMOTE）==="
    "$BUILD_INITRD" launch
    echo
    echo "=== 3/3 校验 TAA ==="
    verify_remote
    echo
    echo "全流程完成。清理用：$0 delete（先看 $0 delete --dry-run）"
    ;;
  build|launch|fetch-base|render)
    case "$cmd" in
      build) preflight build ;;
      launch) preflight launch ;;
    esac
    exec "$BUILD_INITRD" "$cmd"
    ;;
  verify)
    verify_remote
    ;;
  delete)
    delete_remote
    ;;
  print-config)
    print_config
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
