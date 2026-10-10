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
#   up      build -> deploy -> launch -> verify   (the whole flow)
#   build | deploy | launch | fetch-base          (single steps, passed through)
#   verify  Read-only: ask the running TAA for a health answer and a report.
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

# Pull the resolved settings from build-initrd.sh instead of restating them here.
# That output is %q-quoted, so this eval is safe even for values with spaces.
eval "$("$BUILD_INITRD" print-config)"

REMOTE="${REMOTE_USER}@${REMOTE_HOST}"

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
  up            生成 initrd -> 上传部署 -> 配置并拉起测试 Pod -> 验证 TAA（推荐入口）
  build         只构建本地 initrd（等价于 build-initrd.sh build）
  deploy        只上传并安装远程 bundle（等价于 build-initrd.sh deploy）
  launch        只配置 Kata/containerd 并拉起测试 Pod（等价于 build-initrd.sh launch）
  fetch-base    从远端拉取权威 base 资产（等价于 build-initrd.sh fetch-base）
  verify        只读校验：向 Pod 内 TAA 要健康应答与证明报告
  delete        删除本流程在远端安装的全部产物与测试 Pod
  help          显示本帮助

Options:
  -n, --dry-run   仅用于 delete：只打印将要删除的内容，不做任何改动
  -f, --force     仅用于 delete：跳过"该 RuntimeClass 仍被其它 Pod 使用"的拒绝

Environment:
  REMOTE_USER=$REMOTE_USER          SSH 账号（需免密 sudo）
  REMOTE_HOST=$REMOTE_HOST
  REMOTE_BUNDLE_DIR=$REMOTE_BUNDLE_DIR
  TEST_POD_NAME=$TEST_POD_NAME
  TEST_IMAGE=$TEST_IMAGE
  TEST_NODE_NAME=$TEST_NODE_NAME
  TEST_POD_ANNOTATIONS=$TEST_POD_ANNOTATIONS
  TAA_PLATFORM_IP / TAA_DOCKER_ID   deploy/up 需要（或用 ALLOW_MISSING_TAA_ENV=1 显式放弃注册）
  RUNTIME_HANDLER=$RUNTIME_HANDLER

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
    deploy|up)
      require_cmd ssh
      check_remote_sudo
      # The initrd must carry a registration identity or deploy refuses to
      # publish it. Surface that here with both ways out, rather than letting it
      # fail after a full build.
      if [[ "${ALLOW_MISSING_TAA_ENV:-0}" != "1" ]]; then
        if [[ -z "${TAA_PLATFORM_IP:-}" || -z "${TAA_DOCKER_ID:-}" ]]; then
          echo "error: TAA_PLATFORM_IP 与 TAA_DOCKER_ID 需要成对给出（deploy 要求 initrd 内含 etc/default/taa.env）" >&2
          echo "hint: 二者都给，或显式设置 ALLOW_MISSING_TAA_ENV=1 放弃平台注册" >&2
          exit 1
        fi
      fi
      ;;
  esac

  case "$step" in
    launch|up)
      require_cmd ssh
      check_remote_sudo
      ensure_pod_annotations
      if [[ "$TEST_IMAGE" == "busybox:latest" ]]; then
        echo "note: TEST_IMAGE 仍是 busybox:latest；镜像由 guest 内的 CDH 拉取，拉不动会白等 180s" >&2
        echo "note: 这台宿主可直接用 172.16.10.178:31313/taa-env:slim-v2-20260916" >&2
      fi
      ;;
  esac
}

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
echo "--- health ---"
if ! kubectl exec "$pod" -c "$container" -- curl -sS -X POST localhost:6001/v1/taa/health; then
  echo "error: /v1/taa/health 无应答；容器内可能没有 curl，或 TAA 没起来" >&2
  exit 1
fi
echo
echo "--- getAttestation ---"
kubectl exec "$pod" -c "$container" -- \
  curl -sS -X POST localhost:6001/v1/taa/getAttestation \
    -H 'Content-Type: application/json' \
    -d '{"requestId":"deploy-taa-vm"}'
echo
REMOTE_VERIFY
)"

  # The raw envelopes are printed above for the reader; this parse supplies the
  # exit status a script can rely on. Written to a file rather than passed with
  # -c so the program can use quotes freely.
  local prog rc=0
  prog="$(mktemp /tmp/taa-verify.XXXXXX.py)"
  cat > "$prog" <<'PY'
import base64
import json
import sys

text = sys.stdin.read()

# The remote output interleaves two JSON envelopes with human-readable markers,
# so pick out the balanced top-level objects instead of splitting on lines.
bodies, depth, start = [], 0, None
for i, ch in enumerate(text):
    if ch == "{":
        if depth == 0:
            start = i
        depth += 1
    elif ch == "}":
        depth -= 1
        if depth == 0 and start is not None:
            bodies.append(text[start:i + 1])
            start = None

if not bodies:
    print("FAIL: 没有解析到任何 JSON 应答")
    sys.exit(1)

ok = True
health = json.loads(bodies[0])
if health.get("error") != 0 or health.get("msg") != "ok":
    print("FAIL: health 应答异常: error={} msg={}".format(health.get("error"), health.get("msg")))
    ok = False
else:
    phase = (health.get("result") or {}).get("phaseName")
    print("OK:   health msg=ok phaseName={}".format(phase))

if len(bodies) < 2:
    print("FAIL: 没有拿到 getAttestation 应答")
    sys.exit(1)

att = json.loads(bodies[1])
if att.get("error") != 0:
    print("FAIL: getAttestation error={} msg={}".format(att.get("error"), att.get("msg")))
    sys.exit(1)

result = att.get("result") or {}
if not result.get("verifiedPass"):
    print("FAIL: verifiedPass=false msg={}".format(att.get("msg")))
    ok = False
else:
    print("OK:   verifiedPass=true")

report = base64.b64decode(result.get("attestation") or "")
print("      attestation report = {} bytes".format(len(report)))

values = result.get("attestationValues") or "{}"
if isinstance(values, str):
    values = json.loads(values)
print("      chipId      = {}".format(values.get("chipId")))
print("      MEASUREMENT = {}".format(values.get("digest")))

sys.exit(0 if ok else 1)
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
    "$TEST_POD_NAME" "$DRY_RUN" "${FORCE_DELETE:-0}")"
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
# aim at a top-level directory by accident.
case "$bundle_dir" in
  /|/opt|/opt/kata|/opt/kata/share|/opt/kata/share/kata-containers|"$(dirname "$base_initrd_src")")
    echo "error: REMOTE_BUNDLE_DIR 指向共享目录，拒绝删除: $bundle_dir" >&2
    exit 1
    ;;
esac

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
if [[ -f "$kata_config" ]]; then
  run sudo rm -f "$kata_config"
else
  echo "$kata_config 不存在，跳过"
fi

echo
echo "== 5. remote bundle =="
if [[ -d "$bundle_dir" ]]; then
  echo "将删除 $bundle_dir:"
  sudo ls -1 "$bundle_dir" 2>/dev/null | sed 's/^/  /' || true
  run sudo rm -rf "$bundle_dir"
else
  echo "$bundle_dir 不存在，跳过"
fi

echo
echo "== 6. 回归核对（本次操作不该改动的东西）=="
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
    preflight deploy
    preflight launch
    echo "=== 1/4 构建 initrd ==="
    "$BUILD_INITRD" build
    echo
    echo "=== 2/4 部署到 $REMOTE ==="
    "$BUILD_INITRD" deploy
    echo
    echo "=== 3/4 配置运行时并拉起测试 Pod ==="
    "$BUILD_INITRD" launch
    echo
    echo "=== 4/4 校验 TAA ==="
    verify_remote
    echo
    echo "全流程完成。清理用：$0 delete（先看 $0 delete --dry-run）"
    ;;
  build|deploy|launch|fetch-base)
    case "$cmd" in
      build) preflight build ;;
      deploy) preflight deploy ;;
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
  -h|--help|help)
    usage
    ;;
  *)
    echo "error: unknown command: $cmd" >&2
    usage >&2
    exit 1
    ;;
esac
