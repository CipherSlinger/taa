#!/usr/bin/env bash
set -euo pipefail

# ── ANSI Colors & Terminal Capability ────────────────────────
if [[ -t 1 ]]; then
  IS_TTY=true
  RED='\033[38;5;203m'
  GREEN='\033[38;5;48m'
  YELLOW='\033[38;5;215m'
  BLUE='\033[38;5;75m'
  CYAN='\033[38;5;45m'
  PURPLE='\033[38;5;141m'
  BOLD='\033[1m'
  DIM='\033[2m'
  MUTED='\033[38;5;244m'
  NC='\033[0m' # No Color
else
  IS_TTY=false
  RED=''
  GREEN=''
  YELLOW=''
  BLUE=''
  CYAN=''
  PURPLE=''
  BOLD=''
  DIM=''
  MUTED=''
  NC=''
fi

SPIN_FRAMES=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
CURRENT_SPINNER_PID=""
CURRENT_STEP_NAME=""
LAST_FAILED_TASK=""
LAST_ERR_LINE=""
LAST_ERR_CMD=""
TEMP_EXPORT_FILE=""
TEMP_BUILDER_CONTAINER=""

cursor_hide() { [[ "$IS_TTY" == true ]] && printf "\033[?25l" 2>/dev/null || true; }
cursor_show() { [[ "$IS_TTY" == true ]] && printf "\033[?25h" 2>/dev/null || true; }

handle_err() {
  LAST_ERR_LINE="${1:-unknown}"
  LAST_ERR_CMD="${2:-unknown}"
}
trap 'handle_err $LINENO "$BASH_COMMAND"' ERR

cleanup_display() {
  local exit_code=$?
  cursor_show
  if [[ -n "${CURRENT_SPINNER_PID:-}" ]]; then
    kill "$CURRENT_SPINNER_PID" 2>/dev/null || true
    wait "$CURRENT_SPINNER_PID" 2>/dev/null || true
    CURRENT_SPINNER_PID=""
  fi
  if [[ -n "${TEMP_EXPORT_FILE:-}" && -f "$TEMP_EXPORT_FILE" ]]; then
    rm -f "$TEMP_EXPORT_FILE" 2>/dev/null || true
  fi
  if [[ -n "${TEMP_TAA_POD_MANIFEST:-}" && -f "$TEMP_TAA_POD_MANIFEST" ]]; then
    rm -f "$TEMP_TAA_POD_MANIFEST" 2>/dev/null || true
  fi
  if [[ -n "${TEMP_BUILDER_CONTAINER:-}" ]]; then
    docker rm -f "$TEMP_BUILDER_CONTAINER" >/dev/null 2>&1 || true
    TEMP_BUILDER_CONTAINER=""
  fi

  if [[ $exit_code -ne 0 ]]; then
    echo "" >&2
    echo -e "${RED}╭──────────────────────────────────────────────────────────────────╮${NC}" >&2
    echo -e "${RED}│${NC}  ${BOLD}${RED}Deployment Terminated with Error (exit code: ${exit_code})${NC}" >&2
    if [[ -n "${CURRENT_STEP_NAME:-}" ]]; then
      echo -e "${RED}│${NC}  Failed step : ${BOLD}${CURRENT_STEP_NAME}${NC}" >&2
    fi
    if [[ -n "${LAST_FAILED_TASK:-}" ]]; then
      echo -e "${RED}│${NC}  Failed task : ${YELLOW}${LAST_FAILED_TASK}${NC}" >&2
    elif [[ -n "${LAST_ERR_LINE:-}" && -n "${LAST_ERR_CMD:-}" ]]; then
      echo -e "${RED}│${NC}  Failed line : ${BOLD}${LAST_ERR_LINE}${NC} (${DIM}${LAST_ERR_CMD}${NC})" >&2
    fi
    if [[ -f "/tmp/taa-deploy-last-error.log" ]]; then
      echo -e "${RED}│${NC}  Error log   : ${MUTED}/tmp/taa-deploy-last-error.log${NC}" >&2
    fi
    echo -e "${RED}╰──────────────────────────────────────────────────────────────────╯${NC}" >&2
  fi
}
trap cleanup_display EXIT INT TERM

# Kubernetes target: the TAA Pod lives in the osr namespace by default. --pod names a Pod the
# deployment must not create or delete; when it is not given, it owns a Pod of its own and
# create brings it up on the remote host (see create_taa_pod). TARGET_POD and TARGET_NAMESPACE in
# the environment are refused; both are command-line options now.
TARGET_NAMESPACE_ENV_WAS_SET="${TARGET_NAMESPACE+set}"
TARGET_NAMESPACE="osr"
TARGET_POD_ENV_WAS_SET="${TARGET_POD+set}"
TARGET_POD=""
TARGET_POD_WAS_SET=""
TAA_POD_NAME="${TAA_POD_NAME:-taa-deploy}"

# Project and remote host: local source tree, SSH login, and the remote working directory.
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REMOTE_USER="${REMOTE_USER:-root}"
REMOTE_HOST="${REMOTE_HOST:-172.16.10.178}"
REMOTE_DIR="${REMOTE_DIR:-/root/taa}"

# Parameters of the Pod created when --pod was not given. The defaults mirror the production
# TAA Pod on the host (kata-qemu-csv2, 3 CPU, 98Gi), because CSV2 encrypted memory is sized from
# the limits and is resident from boot.
#
# The image the Pod runs. --image sets it; when the operator does not, a fresh build of this
# tree is pushed before the Pod exists, so the Pod never starts from a stale binary.
TAA_IMAGE="${REMOTE_HOST}:31313/taa-env:slim-v2"
TAA_IMAGE_WAS_SET=""
# Registry and repository the auto-built image is pushed to. The date tag follows the repository's
# packaging rule (<repo>:<YYYYMMDD>, see DEFAULT_SAVE_IMAGE).
TAA_IMAGE_REGISTRY="${TAA_IMAGE_REGISTRY:-${REMOTE_HOST}:31313}"
TAA_POD_IMAGE_REPO="${TAA_POD_IMAGE_REPO:-taa-train-infer}"
# Pull policy written into a Pod this deployment creates. The auto-built image is a mutable
# same-day tag, so a Pod must not accept a cached copy of it; a pinned TAA_IMAGE keeps the
# cheaper IfNotPresent.
TAA_POD_PULL_POLICY_WAS_SET="${TAA_POD_PULL_POLICY:+set}"
TAA_POD_PULL_POLICY="${TAA_POD_PULL_POLICY:-IfNotPresent}"
TAA_POD_NODE="${TAA_POD_NODE:-hygon-master}"
TAA_POD_RUNTIME_CLASS="${TAA_POD_RUNTIME_CLASS:-kata-qemu-csv2}"
TAA_POD_CPU="${TAA_POD_CPU:-3}"
TAA_POD_MEMORY="${TAA_POD_MEMORY:-60Gi}"
# The instance role the Pod runs, injected as CONTRACT_TYPE. This script creates the tee and
# data-analysis roles only: 1 (tee training) and 2 (tee inference) both select the ordinary tee
# role -- the difference is carried by the requests, not by the daemon -- and 3 selects data
# analysis, whose landing directory and audit switches then follow from the role instead of from a
# rendered config. The fhe role (4) belongs to deploy-fhe.sh, which creates its own Pod from a
# different base image. 1 is the default here, and because a Pod's environment is immutable,
# changing the role means recreating the Pod.
TAA_POD_CONTRACT_TYPE="${TAA_POD_CONTRACT_TYPE:-1}"
# A fresh CSV2 Pod boots its guest before it can pull the image inside it, so this is longer than
# the 120s readiness timeout the deployment uses once the Pod already exists.
TAA_POD_READY_TIMEOUT="${TAA_POD_READY_TIMEOUT:-600}"
# How long to let the card sit idle before the Pod's VM is killed. A DCU that was computing when
# its guest went away can leave state the next guest's probe cannot recover from: the card has no
# reset (the fixup module sets NO_BUS_RESET and the function reports FLReset-), so the next guest
# fails in `gfx_v9_0_hw_init` (`RLC ucode load fail`, probe -110), the driver never initialises,
# the CDI hook writes no spec and the Pod dies in "failed to inject devices after CDI timeout of
# 100 seconds" while the card itself is fine. Measured on 172.16.10.178: a Pod deleted 111s after
# its last matmul handed the card over cleanly, one deleted 18s after its last matmul wedged the
# next guest. 90 is therefore a choice between two measured points, not a threshold. The host has
# no signal for "the card is still computing" (the guest's MSI is delivered through irqbypass and
# never reaches the host), so a fixed wait is all that is available. 0 skips the wait.
TAA_DCU_QUIESCE_SECONDS="${TAA_DCU_QUIESCE_SECONDS:-90}"
# Optional escape hatch for hosts with no CoCo Pod to copy the annotation from; leave empty to
# derive it from a running Pod (see derive_cc_init_data).
TAA_POD_CC_INIT_DATA="${TAA_POD_CC_INIT_DATA:-}"
# Identity registered with the platform. The Pod name is stable across redeploys, which keeps the
# instance the platform sees from changing on every deployment.
TAA_POD_DOCKER_ID="${TAA_POD_DOCKER_ID:-}"
# NodePort that publishes this instance's TAA listener on the cluster node, so a platform that
# is not on the cluster network can dial it. Every Pod this deployment creates gets a Service
# of its own (see ensure_taa_service); the port has to be stable, because the platform records
# the address, so it is allocated here rather than left to Kubernetes. Empty means "not
# published", which keeps the old behaviour for deployments that reach the Pod by its own IP.
TAA_SERVICE_NODE_PORT="${TAA_SERVICE_NODE_PORT:-}"
# Labels the Service selects this Pod by. It is the registered identity rather than the Pod
# name: the platform's inventory, the Service's selector and the registration all name the same
# instance, and a Pod recreated under the same DOCKER_ID is picked up without touching the
# Service.
TAA_INSTANCE_LABEL_KEY="taa-instance-id"
# The platform's SM2 public key (hex, 04 || X || Y). TAA seals every message it sends and refuses
# to start without it, and the remote config path drops the `platform` block, so a Pod can only
# receive it through its environment. PLATFORM_PUBLIC_KEY is read too: that is the name TAA itself
# uses, and the one the platform-mock tells the operator to set.
TAA_POD_PLATFORM_PUBLIC_KEY="${TAA_POD_PLATFORM_PUBLIC_KEY:-${PLATFORM_PUBLIC_KEY:-}}"
# Where the key is read from when the operator did not supply it. The platform-mock persists it in
# its state directory (whose default is the remote deployment directory), and that file is the
# same one the mock's startup banner points at.
TAA_POD_PLATFORM_KEY_FILE="${TAA_POD_PLATFORM_KEY_FILE:-$REMOTE_DIR/platform-key.json}"
# Fallback source for the CoCo initdata blob when no running Pod carries it: the vendor initdata
# file on the host. It is compressed and base64-encoded exactly as the vendor's own Pod template
# does, so the guest sees the same value whether the blob was copied from a Pod or rendered here.
TAA_POD_INITDATA_FILE="${TAA_POD_INITDATA_FILE:-/root/test/deployment/tools/build-and-install/test-hygon-coco/initdata.v1.toml}"
TAA_POD_TEMPLATE="${TAA_POD_TEMPLATE:-$PROJECT_DIR/deploy/manifest/k8s/taa-pod.yaml.tmpl}"
TEMP_TAA_POD_MANIFEST=""

# Platform address that TAA registers with. The platform itself is deployed separately with
# deploy-platform-mock.sh (or is the production control plane); this script only tells TAA where
# to find it.
PLATFORM_PORT="${PLATFORM_PORT:-18080}"
REMOTE_PLATFORM_IP="${REMOTE_PLATFORM_IP:-${REMOTE_HOST}:${PLATFORM_PORT}}"

# 本地构建产物：TAA 的二进制文件名和本地路径。
BINARY_NAME="${BINARY_NAME:-taa}"
TAA_BINARY_PATH="${TAA_BINARY_PATH:-$PROJECT_DIR/bin/$BINARY_NAME}"

# 远程容器目录：TAA 容器内的工作目录，以及 attestation report 文件路径。
TAA_WORKDIR="${TAA_WORKDIR:-/root/taa}"
# The role's own autostart file. Every role installs exactly one file and the image's
# ENTRYPOINT is `bash <container path>`, so the file alone decides what starts. The tee
# role uses the plain supervisor; the data-analysis wrapper exports its combined one.
TAA_SUPERVISOR_SOURCE="${TAA_SUPERVISOR_SOURCE:-$PROJECT_DIR/deploy/taa-supervisor.sh}"
TAA_SUPERVISOR_CONTAINER="$TAA_WORKDIR/taa-supervisor.sh"
TAA_PORT=6001
ATT_REPORT_FILE="${TAA_WORKDIR}/attestation.report"
K_NS="${TARGET_NAMESPACE:+-n $TARGET_NAMESPACE}"

# TAA 容器运行参数：监听地址、注册用容器标识和日志路径。
TAA_CONTAINER_ADDR=":${TAA_PORT}"
# TAA 程序固定读取工作目录下的 taa-config.json，脚本侧文件名必须保持一致。
TAA_CONFIG_FILE="taa-config.json"
TAA_PRODUCTION_CONFIG_TEMPLATE="${TAA_PRODUCTION_CONFIG_TEMPLATE:-$PROJECT_DIR/configs/taa-production.json}"
REMOTE_TAA_CONFIG_PATH="${REMOTE_TAA_CONFIG_PATH:-$REMOTE_DIR/$TAA_CONFIG_FILE}"
CONTAINER_TAA_CONFIG_PATH="${CONTAINER_TAA_CONFIG_PATH:-$TAA_WORKDIR/$TAA_CONFIG_FILE}"
# The vendor certificate chain TAA uses to anchor its attestation report and the TEE-LLM
# handshake. TAA reads it from $TAA_WORKDIR/certs, so every path that builds or updates a
# container must install these files, and a missing one has to fail loudly.
DEPLOY_CERTS_DIR="${DEPLOY_CERTS_DIR:-$PROJECT_DIR/deploy/certs}"
CONTAINER_CERTS_DIR="${CONTAINER_CERTS_DIR:-$TAA_WORKDIR/certs}"
CONTRACT_ID="${CONTRACT_ID:-}"
TAA_LOG_FILE="${TAA_LOG_FILE:-$TAA_WORKDIR/taa.log}"
CLI_MODEL=""
TAA_READY_TIMEOUT="${TAA_READY_TIMEOUT:-120}"
TAA_READY_INTERVAL="${TAA_READY_INTERVAL:-2}"

# Semgrep payload for the code scan engine. TAA resolves the engine at startup: with
# codeAudit.codeScan.engine=semgrep a missing rules path makes it fall back to the built-in regex
# engine and log a warning, so the deployment would quietly lose the semgrep tier rather than
# fail visibly. The kata pod image ships python3 and tar but neither the semgrep CLI nor any
# rules, so a remote deploy has to provision both.
# The engine runtime is a fixed third-party payload and travels as an archive that is expected to
# sit on the remote host (build it with deploy/guest-build/build-semgrep-payload-container.sh and
# copy it over, or point SEMGREP_BUNDLE at a local copy to have it uploaded). The rules are not
# part of it: they evolve with every commit, so they are streamed from this checkout instead.
REMOTE_SEMGREP_BUNDLE="${REMOTE_SEMGREP_BUNDLE:-$REMOTE_DIR/semgrep-bundle.tar.gz}"
SEMGREP_BUNDLE="${SEMGREP_BUNDLE:-}"
SEMGREP_RULES_SOURCE="${SEMGREP_RULES_SOURCE:-$PROJECT_DIR/teeaudit/models/audit/semgrep/rules}"

# The container-shaped semgrep payload, built by deploy/guest-build/build-semgrep-payload-container.sh.
# It carries site-packages and the semgrep wrapper but not the rules, which are streamed separately
# from $SEMGREP_RULES_SOURCE so a rules edit does not force a payload rebuild. It is extracted with
# `tar -xzf - -C /`, so packaging needs no network -- unlike a pip install.
SEMGREP_PAYLOAD_BUNDLE="${SEMGREP_PAYLOAD_BUNDLE:-$PROJECT_DIR/deploy/guest-build/out/semgrep-bundle.tar.gz}"
TAA_SEMGREP_DIR="${TAA_SEMGREP_DIR:-/opt/taa/semgrep}"
SEMGREP_VERSION="${SEMGREP_VERSION:-1.177.0}"

# Whether the paths above provision the engine the config template selects. "auto" honors the
# template. "skip" leaves the image or pod untouched even when the template names semgrep: the
# data-analysis role keeps production's codeAudit block verbatim, and its loader turns the whole
# audit off at startup anyway, so installing the payload there would only bloat the image.
TAA_SCAN_ENGINE_PROVISION="${TAA_SCAN_ENGINE_PROVISION:-auto}"

# 远程 SSH 密码：通过 REMOTE_PASSWORD 覆盖；置空时启动脚本会交互式询问。
REMOTE_PASSWORD="${REMOTE_PASSWORD:-Osrd@2026}"

DEPLOY_TAA=true
STEP=0

LOCAL_RUN_DIR="${LOCAL_RUN_DIR:-$PROJECT_DIR/.local/run}"
REMOTE_TAA_CONFIG_SOURCE="${REMOTE_TAA_CONFIG_SOURCE:-$LOCAL_RUN_DIR/remote-$TAA_CONFIG_FILE}"
SAVE_DATE_TAG="$(date +%Y%m%d)"
BASE_DOCKER_IMAGE_ARCHIVE="${BASE_DOCKER_IMAGE_ARCHIVE:-$PROJECT_DIR/deploy/base/taa-env-slim-v2.tar.gz}"
BASE_DOCKER_IMAGE="${BASE_DOCKER_IMAGE:-taa-env:slim-v2}"
# Packaging names follow one rule across this repository: <repo>:<YYYYMMDD>, with the archive
# named after the image (<repo>-<YYYYMMDD>.tar.gz) under deploy/out. The tag carries only the
# date, never the base image's tag, so the packaged image is not mistaken for the base it was
# derived from (deploy-fhe.sh and the builder built into deploy-llm.sh follow the same rule). The
# name is independent of BASE_DOCKER_IMAGE: pointing --base at another image changes what goes in,
# not what comes out, and a role that needs its own repository sets TAA_POD_IMAGE_REPO once and
# gets the same name from both `save` and `create`.
DEFAULT_SAVE_IMAGE="${TAA_POD_IMAGE_REPO}:${SAVE_DATE_TAG}"
DEFAULT_SAVE_ARCHIVE="$PROJECT_DIR/deploy/out/${TAA_POD_IMAGE_REPO}-${SAVE_DATE_TAG}.tar.gz"
CUSTOM_SAVE_IMAGE=""
CUSTOM_SAVE_ARCHIVE=""
CUSTOM_BASE_ARCHIVE=""
CUSTOM_SAVE_CONFIG=""
# TEE-LLM gateway endpoint written into taa's config. The gateway does not run on the machine that
# writes the config: it is deployed as a Kata CSV2 Pod on the remote host (see deploy-llm.sh), which
# prints the Pod IP to use, so this is set explicitly in practice. LLM_IP is the preferred variable;
# TAA_LLM_ENDPOINT is still read so that callers written before the rename keep working. Empty means
# "keep the endpoint the config template names".
LLM_IP="${LLM_IP:-${TAA_LLM_ENDPOINT:-}}"

banner() {
  local title="$1"
  local subtitle="${2:-}"
  echo ""
  echo -e "${CYAN}╭──────────────────────────────────────────────────────────────────╮${NC}"
  echo -e "${CYAN}│${NC}  ${BOLD}${title}${NC}"
  if [[ -n "$subtitle" ]]; then
    echo -e "${CYAN}│${NC}  ${DIM}${subtitle}${NC}"
  fi
  echo -e "${CYAN}╰──────────────────────────────────────────────────────────────────╯${NC}"
}

# Messages may carry color codes of their own (e.g. a dimmed "(took 3s)" suffix). printf
# expands backslash escapes only in the format string, so passing such a message through %s
# prints the escapes literally. Route the message through %b to have them interpreted.
step() {
  STEP=$((STEP + 1))
  CURRENT_STEP_NAME="$1"
  LAST_FAILED_TASK=""
  printf "  ${PURPLE}◆${NC} ${CYAN}[%02d]${NC} ${BOLD}%b${NC}\n" "$STEP" "$1"
}

info()    { printf "   ${GREEN}✓${NC} %b\n" "$1"; }
warn()    { printf "   ${YELLOW}⚠${NC} %b\n" "$1"; }
err()     { printf "   ${RED}✗${NC} %b\n" "$1" >&2; }
detail()  { printf "     ${MUTED}↳ %b${NC}\n" "$1"; }

spin_task() {
  local label="$1"
  shift
  local logfile
  logfile="$(mktemp /tmp/deploy_task.XXXXXX)"

  if [[ "$IS_TTY" != true ]]; then
    local rc=0
    if "$@" >"$logfile" 2>&1; then
      info "$label"
      rm -f "$logfile"
      return 0
    else
      rc=$?
      LAST_FAILED_TASK="$label"
      err "$label (failed with exit code $rc)"
      if [[ -f "$logfile" ]]; then
        local err_dump="/tmp/taa-deploy-last-error.log"
        cp -f "$logfile" "$err_dump" 2>/dev/null || true
        local line_count
        line_count=$(wc -l < "$logfile" 2>/dev/null || echo "0")
        if (( line_count > 50 )); then
          echo -e "   ${YELLOW}↳ Last 50 lines of task log (total ${line_count} lines):${NC}" >&2
          tail -n 50 "$logfile" | sed 's/^/     /' >&2 || tail -n 50 "$logfile" >&2
        else
          echo -e "   ${YELLOW}↳ Task log:${NC}" >&2
          sed 's/^/     /' "$logfile" >&2 || cat "$logfile" >&2
        fi
        detail "Full error log captured at $err_dump"
        rm -f "$logfile"
      fi
      return $rc
    fi
  fi

  cursor_hide
  local start_ts
  start_ts=$(date +%s)

  "$@" >"$logfile" 2>&1 &
  local pid=$!
  CURRENT_SPINNER_PID=$pid
  local i=0
  local spin_len=${#SPIN_FRAMES[@]}

  while kill -0 "$pid" 2>/dev/null; do
    local now
    now=$(date +%s)
    local elapsed=$((now - start_ts))
    local frame="${SPIN_FRAMES[$i]}"
    printf "\r   ${CYAN}%s${NC} %s ${DIM}(%ds)...${NC}" "$frame" "$label" "$elapsed"
    i=$(( (i + 1) % spin_len ))
    sleep 0.08
  done

  local rc=0
  wait "$pid" || rc=$?
  CURRENT_SPINNER_PID=""
  cursor_show
  printf "\r\033[K"

  local total_elapsed=$(( $(date +%s) - start_ts ))
  if [[ $rc -eq 0 ]]; then
    info "$label ${DIM}(took ${total_elapsed}s)${NC}"
    rm -f "$logfile"
    return 0
  else
    LAST_FAILED_TASK="$label"
    err "$label (failed after ${total_elapsed}s, exit code $rc)"
    if [[ -f "$logfile" ]]; then
      local err_dump="/tmp/taa-deploy-last-error.log"
      cp -f "$logfile" "$err_dump" 2>/dev/null || true
      local line_count
      line_count=$(wc -l < "$logfile" 2>/dev/null || echo "0")
      if (( line_count > 50 )); then
        echo -e "   ${YELLOW}↳ Last 50 lines of task log (total ${line_count} lines):${NC}" >&2
        tail -n 50 "$logfile" | sed 's/^/     /' >&2 || tail -n 50 "$logfile" >&2
      else
        echo -e "   ${YELLOW}↳ Task log:${NC}" >&2
        sed 's/^/     /' "$logfile" >&2 || cat "$logfile" >&2
      fi
      detail "Full error log captured at $err_dump"
      rm -f "$logfile"
    fi
    return $rc
  fi
}

# ── Container helpers (k8s) ────────────────────────────────
# 在容器内执行命令（通过 remote_ssh 在远程宿主机上操作）。
container_exec() {
  echo "kubectl $K_NS exec '$TARGET_POD' --"
}

# 在容器内以交互输入流式执行命令（支持 stdin 管道传入）。
container_exec_i() {
  echo "kubectl $K_NS exec -i '$TARGET_POD' --"
}

# 从远程宿主机复制文件到容器内。
container_cp() {
  echo "kubectl $K_NS cp '$1' '$TARGET_POD':'$2'"
}

SSH_OPTS=(
  -q
  -o LogLevel=ERROR
  -o StrictHostKeyChecking=accept-new
  -o UserKnownHostsFile="$HOME/.ssh/known_hosts"
)

ensure_remote_ssh() {
  if [[ -z "$REMOTE_PASSWORD" ]]; then
    read -rsp "Password for ${REMOTE_USER}@${REMOTE_HOST}: " REMOTE_PASSWORD
    echo
  fi
  if ! command -v sshpass >/dev/null 2>&1; then
    err "sshpass is required for password-based copy. Install it or set up SSH keys."
    exit 1
  fi
}

remote_ssh() {
  ensure_remote_ssh
  sshpass -p "$REMOTE_PASSWORD" ssh "${SSH_OPTS[@]}" "${REMOTE_USER}@${REMOTE_HOST}" "$@"
}

check_remote_connectivity() {
  ensure_remote_ssh
  if ! sshpass -p "$REMOTE_PASSWORD" ssh "${SSH_OPTS[@]}" -o ConnectTimeout=5 "${REMOTE_USER}@${REMOTE_HOST}" "true" 2>/dev/null; then
    err "cannot connect to remote host ${REMOTE_USER}@${REMOTE_HOST} via SSH (connection timed out or authentication failed)"
    detail "Please check network connection, REMOTE_HOST ($REMOTE_HOST), or REMOTE_PASSWORD credentials."
    exit 1
  fi
  info "remote host SSH connection verified: ${REMOTE_USER}@${REMOTE_HOST}"
}

# Prints success when the target Pod exists. Unlike check_remote_pod this never exits: the stop
# path has to tolerate a Pod that is already gone.
remote_pod_exists() {
  remote_ssh "kubectl $K_NS get pod '$TARGET_POD' >/dev/null 2>&1"
}

# The role a CONTRACT_TYPE value selects, using the same mapping TAA applies
# (internal/config: 1 and 2 both mean tee). Only the roles this script creates are
# mapped; an empty or unrecognised value prints nothing.
contract_type_role() {
  case "${1:-}" in
    1|2) printf 'tee' ;;
    3) printf 'data-anaylsis' ;;
  esac
}

# deploy.sh creates the tee and data-analysis Pods. The fhe role needs a different base image and
# a different set of injected values, so it belongs to deploy-fhe.sh; accepting 4 here would write
# a manifest this deployment cannot serve.
validate_pod_contract_type() {
  case "$TAA_POD_CONTRACT_TYPE" in
    1|2|3) ;;
    4)
      err "TAA_POD_CONTRACT_TYPE=4 selects the fhe role, which deploy.sh does not create"
      detail "deploy-fhe.sh creates FHE Pods. deploy.sh creates the tee (1, 2) and data-analysis (3) roles."
      exit 1
      ;;
    *)
      err "TAA_POD_CONTRACT_TYPE must be 1, 2 or 3 (got '$TAA_POD_CONTRACT_TYPE')"
      detail "1 tee training, 2 tee inference, 3 data analysis."
      exit 1
      ;;
  esac
}

# Prints the CONTRACT_TYPE the target Pod was created with, or nothing when it carries none (a Pod
# created before the role was injected, which TAA therefore runs as tee).
pod_contract_type() {
  remote_ssh "kubectl $K_NS get pod '$TARGET_POD' -o jsonpath='{.spec.containers[0].env[?(@.name==\"CONTRACT_TYPE\")].value}' 2>/dev/null" || true
}

# A Pod's environment is immutable, so the role it was created with is the role it keeps. Reusing
# an existing Pod for a deployment that asked for another role would install this tree's files into
# an instance that still runs the old role, and since the role now comes from the environment
# rather than from the config, nothing later in the flow would notice.
require_matching_role() {
  local existing existing_role wanted_role
  existing="$(pod_contract_type)"
  existing="${existing//[$'\r\n']/}"
  wanted_role="$(contract_type_role "$TAA_POD_CONTRACT_TYPE")"
  # No CONTRACT_TYPE means tee: that is how TAA interprets a Pod that carries none.
  existing_role="$(contract_type_role "${existing:-1}")"
  if [[ -n "$wanted_role" && "$existing_role" != "$wanted_role" ]]; then
    err "TAA Pod '$TARGET_POD' runs the '$existing_role' role (CONTRACT_TYPE=${existing:-unset}), not '$wanted_role' (CONTRACT_TYPE=$TAA_POD_CONTRACT_TYPE)"
    detail "A Pod's environment cannot be changed in place. Use a different TAA_POD_NAME, or delete and recreate the Pod."
    exit 1
  fi
}

# True when the value is the platform's published wire format: 04 || X(32B) || Y(32B), hex.
is_platform_public_key() {
  [[ "$1" =~ ^04[[:xdigit:]]{128}$ ]]
}

# Fills TAA_POD_PLATFORM_PUBLIC_KEY when the operator did not supply it, from the key file the
# platform keeps on the remote host. The value is public material, so reading it from the host is
# not a secret-handling problem; what it removes is a copy-paste step that, when skipped, produced
# a Pod that booted into a crash loop. A value that does not parse is refused here rather than at
# TAA's first startup, because the failure would otherwise only surface after a full guest boot.
resolve_platform_public_key() {
  if [[ -z "$TAA_POD_PLATFORM_PUBLIC_KEY" ]]; then
    TAA_POD_PLATFORM_PUBLIC_KEY="$(remote_ssh bash -s -- "$TAA_POD_PLATFORM_KEY_FILE" <<'REMOTE_KEY' || true
set -euo pipefail
file="$1"
[ -r "$file" ] || exit 1
sed -n 's/.*"publicKeyHex"[[:space:]]*:[[:space:]]*"\([0-9a-fA-F]*\)".*/\1/p' "$file" | head -n 1
REMOTE_KEY
)"
    TAA_POD_PLATFORM_PUBLIC_KEY="${TAA_POD_PLATFORM_PUBLIC_KEY//$'\r'/}"
    TAA_POD_PLATFORM_PUBLIC_KEY="${TAA_POD_PLATFORM_PUBLIC_KEY//$'\n'/}"
    if [[ -n "$TAA_POD_PLATFORM_PUBLIC_KEY" ]]; then
      info "platform public key read from ${REMOTE_HOST}:$TAA_POD_PLATFORM_KEY_FILE"
    fi
  fi
  if [[ -n "$TAA_POD_PLATFORM_PUBLIC_KEY" ]] && ! is_platform_public_key "$TAA_POD_PLATFORM_PUBLIC_KEY"; then
    err "the platform SM2 public key is not in the expected wire format"
    detail "Expected 130 hex characters: 04 followed by X and Y (32 bytes each)."
    detail "Source: ${TAA_POD_PLATFORM_KEY_FILE} on ${REMOTE_HOST}, or PLATFORM_PUBLIC_KEY / TAA_POD_PLATFORM_PUBLIC_KEY."
    exit 1
  fi
}

# Reads the cc_init_data annotation off a CoCo Pod that already runs on the remote host. The
# guest's CDH needs it to trust the local registry's self-signed certificate when it pulls the
# image -- the host's own trust does not carry into the guest -- and a Pod without it stops in
# StartError. Only that one annotation is ever copied: the runtime-handler key would hijack the
# runtime, and an empty hypervisor kernel_params value would erase the rdinit= that boots the
# guest. Prints the bare value; the caller substitutes it into the manifest.
derive_cc_init_data() {
  if [[ -n "$TAA_POD_CC_INIT_DATA" ]]; then
    printf '%s' "$TAA_POD_CC_INIT_DATA"
    return 0
  fi
  local derived
  derived="$(remote_ssh 'bash -s' <<'REMOTE_DERIVE' || true
set -euo pipefail
command -v kubectl >/dev/null 2>&1 || exit 1
# The dots inside the annotation key are escaped for jsonpath. Inside this quoted heredoc the
# backslashes reach the remote shell unchanged.
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.annotations.io\.katacontainers\.config\.runtime\.cc_init_data}{"\n"}{end}' 2>/dev/null |
  awk 'NF {print; exit}'
REMOTE_DERIVE
)"
  derived="${derived//$'\r'/}"
  derived="${derived//$'\n'/}"
  if [[ -z "$derived" ]]; then
    # Nothing to copy from. The vendor initdata file on the host is the same input the vendor's
    # own Pod template compresses, so rendering it here yields the value the guest needs without
    # requiring an unrelated CoCo Pod to exist first.
    derived="$(remote_ssh bash -s -- "$TAA_POD_INITDATA_FILE" <<'REMOTE_INITDATA' || true
set -euo pipefail
file="$1"
[ -r "$file" ] || exit 1
gzip -c "$file" | base64 -w0
REMOTE_INITDATA
)"
    derived="${derived//$'\r'/}"
    derived="${derived//$'\n'/}"
    if [[ -n "$derived" ]]; then
      # stderr, not stdout: this function's stdout is the annotation value itself, and a progress
      # line in it would land inside the rendered manifest.
      printf "   ${GREEN}✓${NC} cc_init_data rendered from %s:%s (no running CoCo Pod to copy it from)\n" \
        "$REMOTE_HOST" "$TAA_POD_INITDATA_FILE" >&2
    fi
  fi
  if [[ -z "$derived" ]]; then
    err "could not obtain the cc_init_data annotation on ${REMOTE_USER}@${REMOTE_HOST}"
    detail "Without it the guest's CDH cannot pull the image and the new Pod stops in StartError."
    detail "Looked for a running CoCo Pod and for $TAA_POD_INITDATA_FILE on the host."
    detail "Bring up any CoCo Pod once (deploy-taa-vm.sh up), pass TAA_POD_CC_INIT_DATA=<base64>, or point TAA_POD_INITDATA_FILE at the initdata file."
    exit 1
  fi
  printf '%s' "$derived"
}

# Escapes what is special on the right-hand side of a sed s||| expression, so a Pod name or an id
# containing &, \ or | cannot corrupt the rendered manifest.
sed_escape() {
  printf '%s' "$1" | sed -e 's/[\\&|]/\\&/g'
}

# Stops the daemon inside the target Pod and holds the supervisor there: the `manual` file keeps
# it from restarting, then the process is signalled. Called right after a Pod is created (so the
# binary baked into the image never serves the deployment window) and again before the update.
pause_remote_taa() {
  remote_ssh "$(container_exec) sh -lc 'touch \"$TAA_WORKDIR/manual\" && pkill -x taa >/dev/null 2>&1 || true; killall taa >/dev/null 2>&1 || true'"
}

# Builds the production TAA image from this tree, uploads it to the registry, and points the new
# Pod at it. The tag carries today's date and is therefore mutable: when the registry already
# holds a different build under that tag, its manifest is deleted and the tag repushed; when the
# content is identical the push is skipped. Sets TAA_IMAGE and TAA_POD_PULL_POLICY.
#
# Reuses save_local_docker_image so the image a Pod runs is assembled by the same code path as a
# packaged production image (base archive, supervisor, scan engine, static binary, config).
build_and_push_taa_pod_image() {
  require_command docker
  if ! docker info >/dev/null 2>&1; then
    err "the docker daemon is not reachable, so the Pod image cannot be built"
    detail "Pass --image to deploy a prebuilt image instead."
    exit 1
  fi

  local tag="$SAVE_DATE_TAG"
  local local_image="$TAA_POD_IMAGE_REPO:$tag"
  local registry_image="$TAA_IMAGE_REGISTRY/$TAA_POD_IMAGE_REPO:$tag"
  local archive="$PROJECT_DIR/deploy/out/taa-pod-$tag.tar.gz"

  step "building the TAA image for the new Pod ($local_image)"
  local saved_image="$CUSTOM_SAVE_IMAGE" saved_archive="$CUSTOM_SAVE_ARCHIVE"
  CUSTOM_SAVE_IMAGE="$local_image"
  CUSTOM_SAVE_ARCHIVE="$archive"
  save_local_docker_image
  CUSTOM_SAVE_IMAGE="$saved_image"
  CUSTOM_SAVE_ARCHIVE="$saved_archive"

  local local_id
  local_id="$(docker image inspect --format '{{.Id}}' "$local_image" 2>/dev/null || true)"
  if [[ -z "$local_id" ]]; then
    err "the built image '$local_image' is missing"
    exit 1
  fi

  local remote_archive="/tmp/taa-pod-$tag.$$.tar.gz"
  step "uploading the image to ${REMOTE_USER}@${REMOTE_HOST} and updating ${registry_image}"
  sshpass -p "$REMOTE_PASSWORD" scp "${SSH_OPTS[@]}" "$archive" "${REMOTE_USER}@${REMOTE_HOST}:$remote_archive"

  local result
  if ! result="$(remote_ssh bash -s -- "$remote_archive" "$local_image" "$registry_image" "$local_id" "$TAA_IMAGE_REGISTRY" "$TAA_POD_IMAGE_REPO" "$tag" <<'REMOTE_PUSH'
set -euo pipefail
archive="$1"; local_image="$2"; registry_image="$3"; local_id="$4"
registry="$5"; repo="$6"; tag="$7"
trap 'rm -f "$archive"' EXIT

docker load -i "$archive" >/dev/null
docker tag "$local_image" "$registry_image"

manifest_url="https://$registry/v2/$repo/manifests/$tag"
accept="Accept: application/vnd.docker.distribution.manifest.v2+json"
# The config digest in a schema2 manifest is the image ID Docker reports locally, so comparing
# the two answers "does the registry already hold exactly this build?".
remote_config="$(curl -sk --max-time 10 -H "$accept" "$manifest_url" 2>/dev/null |
  grep -o 'sha256:[0-9a-f]\{64\}' | head -n 1 || true)"
if [[ -n "$remote_config" && "$remote_config" == "$local_id" ]]; then
  echo "UNCHANGED"
  exit 0
fi

old_digest="$(curl -skI --max-time 10 -H "$accept" "$manifest_url" 2>/dev/null |
  awk 'tolower($1) == "docker-content-digest:" {print $2}' | tr -d '\r' | tail -n 1 || true)"
if [[ -n "$old_digest" ]]; then
  # Best effort: a registry with deletion disabled answers 405, and the push below still
  # replaces the tag atomically.
  curl -sk -X DELETE --max-time 15 "$registry/v2/$repo/manifests/$old_digest" >/dev/null 2>&1 || true
fi
docker push "$registry_image" >/dev/null
echo "PUSHED"
REMOTE_PUSH
)"; then
    err "failed to upload or push the TAA image to ${registry_image}"
    detail "Check that ${REMOTE_HOST} can push to ${TAA_IMAGE_REGISTRY}, or pass --image with a prebuilt image."
    exit 1
  fi

  case "$result" in
    *PUSHED*)    info "image pushed: $registry_image" ;;
    *UNCHANGED*) info "the registry already holds this build; tag kept: $registry_image" ;;
    *)
      err "unexpected result while updating $registry_image"
      detail "$result"
      exit 1
      ;;
  esac

  TAA_IMAGE="$registry_image"
  # A same-day tag is mutable: the Pod must fetch the manifest instead of trusting a cached copy.
  # An explicit TAA_POD_PULL_POLICY stays the operator's choice.
  if [[ -z "$TAA_POD_PULL_POLICY_WAS_SET" ]]; then
    TAA_POD_PULL_POLICY="Always"
  fi
  rm -f "$archive"
}

# Creates the deployment-owned TAA Pod. Reached only when --pod was not given and no Pod with
# that name exists, so an immutable-Pod rewrite cannot happen here. The rendered manifest uses |
# as the delimiter because the injected base64 value contains / and + but never |.
# Kubernetes label values are restricted to 63 characters of [A-Za-z0-9._-], and a DOCKER_ID
# outside that would make the Pod manifest invalid — a failure that would otherwise surface only
# after the image was built and pushed. Checked before anything is built.
validate_instance_label() {
  local id="$1"
  if [[ -z "$id" ]]; then
    err "the instance label value is empty"
    detail "DOCKER_ID (or the Pod name, when DOCKER_ID is unset) becomes the taa-instance-id label."
    exit 1
  fi
  if (( ${#id} > 63 )); then
    err "DOCKER_ID '$id' is ${#id} characters, longer than the 63 a Kubernetes label value allows"
    exit 1
  fi
  if [[ ! "$id" =~ ^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$ ]]; then
    err "DOCKER_ID '$id' cannot be a Kubernetes label value"
    detail "Allowed: alphanumerics, '-', '_' and '.', starting and ending with an alphanumeric."
    exit 1
  fi
}

# ensure_taa_service publishes the instance's TAA listener on the cluster node. The platform
# records this address, so it has to survive the Pod being recreated: the Service selects the
# taa-instance-id label rather than the Pod name, so a replacement Pod with the same DOCKER_ID
# joins the same Service without an edit here.
#
# applied rather than created because the Service outlives the Pod on purpose: after a delete
# it has no endpoints, and the next create fills them in.
ensure_taa_service() {
  local docker_id="$1" pod_namespace="$2" name
  if [[ -z "$TAA_SERVICE_NODE_PORT" ]]; then
    info "no NodePort Service (TAA_SERVICE_NODE_PORT is empty); the instance is reachable at its Pod IP only"
    return 0
  fi
  if [[ ! "$TAA_SERVICE_NODE_PORT" =~ ^[0-9]+$ ]] || (( TAA_SERVICE_NODE_PORT < 30000 || TAA_SERVICE_NODE_PORT > 32767 )); then
    err "TAA_SERVICE_NODE_PORT=$TAA_SERVICE_NODE_PORT is not a NodePort number (30000-32767)"
    exit 1
  fi
  # A Service name has to be a DNS-1035 label, which is stricter than the Pod label: it must
  # start with a letter and may not contain '.', while a DOCKER_ID produced from a sha may.
  name="taa-$(printf '%s' "$docker_id" | tr '._' '--' | tr 'A-Z' 'a-z')"
  if (( ${#name} > 63 )); then
    err "the Service name '$name' derived from DOCKER_ID is longer than 63 characters"
    detail "Leave TAA_SERVICE_NODE_PORT empty to reach the Pod by its own address, or shorten DOCKER_ID."
    exit 1
  fi
  step "publishing $docker_id on node port $TAA_SERVICE_NODE_PORT (Service $name)"
  local manifest
  manifest="$(cat <<EOF
apiVersion: v1
kind: Service
metadata:
  name: $name
  namespace: $pod_namespace
  labels:
    app: taa
spec:
  type: NodePort
  selector:
    $TAA_INSTANCE_LABEL_KEY: "$docker_id"
  ports:
    - name: taa
      port: $TAA_PORT
      targetPort: $TAA_PORT
      protocol: TCP
      nodePort: $TAA_SERVICE_NODE_PORT
EOF
)"
  # apply, because a recreated Pod with the same DOCKER_ID must reuse the Service and its port.
  # A port already bound by another Service makes this fail, and the Pod is left running: the
  # publishing is what failed, not the instance, so the message names the port rather than
  # implying the deployment is broken.
  if ! printf '%s\n' "$manifest" | remote_ssh "kubectl $K_NS apply -f -"; then
    err "could not publish $docker_id on node port $TAA_SERVICE_NODE_PORT"
    detail "Another Service may already own that port. Pick a free one and retry, or leave TAA_SERVICE_NODE_PORT empty to skip publishing."
    detail "Existing NodePorts: kubectl $K_NS get svc -o wide"
    exit 1
  fi
  info "NodePort $TAA_SERVICE_NODE_PORT -> $docker_id:$TAA_PORT (http://${REMOTE_HOST}:${TAA_SERVICE_NODE_PORT})"
}

create_taa_pod() {
  require_file "TAA Pod template" "$TAA_POD_TEMPLATE"
  # An image named explicitly is the operator's decision and is used as given. Otherwise the Pod
  # runs a fresh build of this tree, pushed before the Pod exists so it never starts stale.
  if [[ -z "$TAA_IMAGE_WAS_SET" ]]; then
    build_and_push_taa_pod_image
  fi
  local cc_init_data docker_id pod_namespace
  # An empty namespace in the manifest is not the same as "the context's namespace", so resolve
  # what kubectl itself would use. The common case (the default osr namespace) never gets here.
  pod_namespace="$TARGET_NAMESPACE"
  if [[ -z "$pod_namespace" ]]; then
    pod_namespace="$(remote_ssh "kubectl config view --minify -o jsonpath='{..namespace}' 2>/dev/null" || true)"
    pod_namespace="${pod_namespace:-default}"
  fi
  cc_init_data="$(derive_cc_init_data)"
  docker_id="${TAA_POD_DOCKER_ID:-$TARGET_POD}"
  validate_instance_label "$docker_id"
  if [[ -z "${CONTRACT_ID:-}" ]]; then
    warn "CONTRACT_ID is empty; the Pod will register without a contract id"
  fi
  # Refused before the manifest is applied: TAA validates the key at startup and exits, so a Pod
  # created without it would boot, crash-loop, and cost a full guest boot to diagnose. The key is
  # read from the host when the operator did not export it, so in the common case nothing is left
  # for them to remember.
  resolve_platform_public_key
  if [[ -z "$TAA_POD_PLATFORM_PUBLIC_KEY" ]]; then
    err "PLATFORM_PUBLIC_KEY is not set, so the new TAA Pod could not start"
    detail "TAA seals every platform message and refuses to start without the platform's SM2 public key."
    detail "It was not found in ${REMOTE_HOST}:$TAA_POD_PLATFORM_KEY_FILE either."
    detail "Export it first: PLATFORM_PUBLIC_KEY=<hex starting with 04> $(basename "$0") create"
    exit 1
  fi
  TEMP_TAA_POD_MANIFEST="$(mktemp /tmp/taa-pod.XXXXXX.yaml)"
  sed -e "s|__POD_NAME__|$(sed_escape "$TARGET_POD")|g" \
      -e "s|__NAMESPACE__|$(sed_escape "$pod_namespace")|g" \
      -e "s|__NODE_NAME__|$(sed_escape "$TAA_POD_NODE")|g" \
      -e "s|__IMAGE__|$(sed_escape "$TAA_IMAGE")|g" \
      -e "s|__RUNTIME_CLASS__|$(sed_escape "$TAA_POD_RUNTIME_CLASS")|g" \
      -e "s|__PULL_POLICY__|$(sed_escape "$TAA_POD_PULL_POLICY")|g" \
      -e "s|__CPU__|$(sed_escape "$TAA_POD_CPU")|g" \
      -e "s|__MEMORY__|$(sed_escape "$TAA_POD_MEMORY")|g" \
      -e "s|__CONTRACT_TYPE__|$(sed_escape "$TAA_POD_CONTRACT_TYPE")|g" \
      -e "s|__CC_INIT_DATA__|$(sed_escape "$cc_init_data")|g" \
      -e "s|__TAA_INSTANCE_ID__|$(sed_escape "$docker_id")|g" \
      -e "s|__DOCKER_ID__|$(sed_escape "$docker_id")|g" \
      -e "s|__PLATFORM_IP__|$(sed_escape "$REMOTE_PLATFORM_IP")|g" \
      -e "s|__PLATFORM_PUBLIC_KEY__|$(sed_escape "$TAA_POD_PLATFORM_PUBLIC_KEY")|g" \
      -e "s|__CONTRACT_ID__|$(sed_escape "${CONTRACT_ID:-}")|g" \
      "$TAA_POD_TEMPLATE" > "$TEMP_TAA_POD_MANIFEST"
  step "creating the TAA Pod $TARGET_POD (runtimeClassName: $TAA_POD_RUNTIME_CLASS, node: $TAA_POD_NODE, image: $TAA_IMAGE)"
  # create, not apply: the name was verified absent a moment ago, and create turns a race with
  # another operator into an error instead of silently rewriting a Pod whose spec is immutable.
  if ! remote_ssh "kubectl $K_NS create -f -" < "$TEMP_TAA_POD_MANIFEST"; then
    if ! remote_pod_exists; then
      err "failed to create TAA Pod '$TARGET_POD'"
      exit 1
    fi
    info "TAA Pod '$TARGET_POD' already exists; reusing it"
  fi
  rm -f "$TEMP_TAA_POD_MANIFEST"
  TEMP_TAA_POD_MANIFEST=""
  # Long, because the guest boots before it can pull the image. Dumping the events first keeps a
  # timeout diagnosable, which a bare "timed out" is not.
  if ! remote_ssh "kubectl $K_NS wait --for=condition=Ready --timeout=${TAA_POD_READY_TIMEOUT}s pod/'$TARGET_POD'"; then
    err "TAA Pod '$TARGET_POD' did not become Ready within ${TAA_POD_READY_TIMEOUT}s"
    remote_ssh "kubectl $K_NS describe pod '$TARGET_POD' | tail -n 40" || true
    detail "The Pod is left in place for inspection: kubectl $K_NS describe pod '$TARGET_POD'"
    exit 1
  fi
  # The device is the point of this Pod: without it TAA cannot produce a real CSV attestation,
  # and the absence is silent rather than an error inside the container.
  if ! remote_ssh "$(container_exec) test -e /dev/csv-guest"; then
    err "TAA Pod '$TARGET_POD' has no /dev/csv-guest, so it cannot produce a real CSV attestation"
    detail "Expected runtimeClassName $TAA_POD_RUNTIME_CLASS. Pod left running for inspection:"
    detail "kubectl $K_NS exec '$TARGET_POD' -- ls -l /dev/csv*"
    exit 1
  fi
  # The image's ENTRYPOINT has already started the daemon baked into it. Left running, it would
  # register and accept a request with the old binary during the scan-engine provisioning, and
  # the deployment's later pause would come after that window.
  step "holding the daemon baked into the new Pod"
  pause_remote_taa || true
  ensure_taa_service "$docker_id" "$pod_namespace"
  info "TAA Pod created and Ready: $TARGET_POD"
}

# Gives the DCU a quiet period before the Pod's VM is killed. See TAA_DCU_QUIESCE_SECONDS for the
# failure it avoids and the measured points behind the default. The check is remote because the
# card may not be local to the host running this script; only the display/co-processor functions
# count, since Hygon root complexes and bridges share the vendor id.
#
# This wait is the one that actually runs on the deploy.sh path. The Pod template carries a
# preStop hook that waits the same amount again, for teardowns that do not go through this script
# (the platform's CRD, a bare kubectl delete); the two are additive, which is deliberate because
# a preStop is a kubelet exec and has not been verified to run in this Kata guest.
dcu_quiet_before_delete() {
  local seconds="$TAA_DCU_QUIESCE_SECONDS" card
  if (( seconds <= 0 )); then
    warn "TAA_DCU_QUIESCE_SECONDS=$seconds; deleting without a DCU quiet period"
    return 0
  fi
  card="$(remote_ssh 'for dev in /sys/bus/pci/devices/*; do
    [ "$(cat "$dev/vendor" 2>/dev/null)" = "0x1d94" ] || continue
    case "$(cat "$dev/class" 2>/dev/null)" in
      0x03*|0x0b40*) echo "$dev"; break ;;
    esac
  done' 2>/dev/null || true)"
  if [[ -z "$card" ]]; then
    info "no Hygon DCU on the remote host; deleting without a quiet period"
    return 0
  fi
  step "giving the DCU ${seconds}s of quiet before its VM is killed"
  remote_ssh "sleep $seconds"
}

# Deletes the deployment-owned TAA Pod. Destructive by design: the guest's writable layer -- the
# data, keys and models the deployment put there -- goes with it, which is why this only runs when
# the Pod is one this deployment created (--pod was not given).
delete_taa_pod() {
  step "deleting the deployment-owned TAA Pod ($TARGET_POD in $TARGET_NAMESPACE)"
  dcu_quiet_before_delete
  # The timeout covers two waits: the quiet period above and the Pod's own preStop quiet period
  # (90s in the template), plus a margin for the guest to actually shut down. A shorter timeout
  # would fall into the forced delete below and kill the VM before the preStop finished, which is
  # the one path this whole mechanism exists to avoid.
  remote_ssh "kubectl $K_NS delete pod '$TARGET_POD' --ignore-not-found --wait=true --timeout=210s" || true
  # A VM-backed Pod whose guest is wedged will not answer a graceful delete; fall back to force so
  # a broken Pod cannot block the teardown. Its memory is host-resident, so leaving it costs GiB.
  if remote_pod_exists; then
    warn "Pod '$TARGET_POD' did not exit within 210s; forcing deletion"
    remote_ssh "kubectl $K_NS delete pod '$TARGET_POD' --force --grace-period=0" || true
  fi
  if remote_pod_exists; then
    err "Pod '$TARGET_POD' is still present after a forced delete"
    exit 1
  fi
  # The Service is named after the identity the Pod registered with, so it is found from the
  # same value. Removing it keeps the NodePort from lingering as a route to nothing; a redeploy
  # recreates both. Tolerated as missing because a Pod created without publishing has none.
  local docker_id
  docker_id="${TAA_POD_DOCKER_ID:-$TARGET_POD}"
  remote_ssh "kubectl $K_NS delete svc 'taa-$(printf '%s' "$docker_id" | tr '._' '--' | tr 'A-Z' 'a-z')' --ignore-not-found" >/dev/null 2>&1 || true
  info "TAA Pod '$TARGET_POD' deleted (its writable layer goes with it)"
}

# Removes every TEE-LLM and ollama artifact a base image may carry, then asserts each one is gone.
# The list is enumerated from the combined images this repository produces
# (taa-train-infer:<date>, taa-fhe:<date>), not guessed.
# A base image that never carried teellm makes every rm a no-op and every assertion
# pass, so the same code covers both the slim base and a previously combined image.
strip_teellm_from_image() {
  local container="$1"
  step "removing TEE-LLM and ollama artifacts from the image"
  docker exec -i "$container" sh -lc '
    rm -rf /root/taa/ollama \
           /root/taa/ollama-qwen \
           /root/taa/ollama-qwen2.5-coder-0.5b \
           /root/taa/teellm-service \
           /root/taa/teellm-docker.json \
           /root/taa/start-teellm.sh \
           /root/taa/.start-teellm.lock \
           /root/taa/configs/teellm-docker.json \
           /root/taa/configs/teellm-production.json \
           /root/taa/configs/models.json
  ' >/dev/null

  local leftovers="" path
  for path in \
    /root/taa/ollama /root/taa/ollama-qwen /root/taa/ollama-qwen2.5-coder-0.5b \
    /root/taa/teellm-service /root/taa/teellm-docker.json /root/taa/start-teellm.sh \
    /root/taa/.start-teellm.lock /root/taa/configs/teellm-docker.json \
    /root/taa/configs/teellm-production.json /root/taa/configs/models.json; do
    if docker exec -i "$container" sh -lc "test -e '$path'"; then
      leftovers="${leftovers}${path} "
    fi
  done
  if [[ -n "$leftovers" ]]; then
    err "TEE-LLM artifacts survived removal and would ship inside the image"
    detail "still present: ${leftovers% }"
    exit 1
  fi
  info "no TEE-LLM or ollama artifacts remain in the image"
}

# Renders the taa-config.json a packaged image carries into <out_path> and records the model it
# selected in RENDERED_CONFIG_MODEL. Split out of save_local_docker_image so that create can hold
# the Pod's copy against exactly the file the image was built from, instead of re-deriving it with
# a second copy of these rules that could drift.
render_image_config() {
  local out_path="$1" template="$2"
  local target_model
  if [[ -n "$CLI_MODEL" ]]; then
    target_model="$CLI_MODEL"
  else
    target_model="$(get_taa_config_llm_model "$template")"
    if [[ -z "$target_model" ]]; then
      target_model="qwen2.5-coder:3b"
    fi
  fi

  ensure_parent_dir "$out_path"

  # The result path is /opt/taa/output/result and not /opt/taa/output, matching every template: a
  # non-empty model_output_dir overwrites the template's value rather than falling back to it, so
  # passing the output root here silently rewrote model.output.result and results landed beside
  # log/ and progress/ instead of in their own directory. The remote path passes empty for both
  # staging paths and therefore kept the template's value -- which is how the two deployments came
  # to disagree about the same key.
  #
  # The LLM endpoint is passed empty for the same reason: empty means "leave the template alone".
  # What the packaging host could answer is not the address the shipped image will use -- the Pod
  # IP changes when the Pod is recreated, and loopback is only right when the gateway shares taa's
  # network namespace -- so baking it in replaced the template's endpoint with a guess. The image
  # carries exactly the endpoint configs/taa-production.json names; a deployment that needs a
  # different one sets LLM_IP at container startup, which still overrides it.
  # storage.data is left to the template ("") on purpose: deploy-dataanaylsis.sh
  # renders its copy to /home/jovyan/systemAuthData, where the jupyter runtime
  # reads imported files, while the shared template keeps /root/taa/data -- the
  # value the override used to force anyway.
  write_taa_config "$out_path" "$template" \
    ":6001" "" "" "" \
    "/root/taa/models" "" "/root/taa/results" \
    "" "$target_model" \
    false "/opt/taa/input" "/opt/taa/output/result" "/root/taa/keys"
  RENDERED_CONFIG_MODEL="$target_model"
}

# Renders the taa-config.json update installs into an existing Pod: this deployment's model and
# LLM endpoint, and no identity block, because the Pod environment carries the identity.
render_deploy_config() {
  local out_path="$1"
  write_taa_config "$out_path" "$TAA_PRODUCTION_CONFIG_TEMPLATE" \
    "$TAA_CONTAINER_ADDR" "$REMOTE_PLATFORM_IP" "${REMOTE_DOCKER_ID:-}" "${CONTRACT_ID:-}" \
    "$TAA_WORKDIR/models" "" "$TAA_WORKDIR/results" \
    "${LLM_IP:-}" "$(resolve_target_model)" false "" "" "$TAA_WORKDIR/keys"
}

save_local_docker_image() {
  local base_archive="${CUSTOM_BASE_ARCHIVE:-$BASE_DOCKER_IMAGE_ARCHIVE}"
  local base_image="${BASE_DOCKER_IMAGE}"
  local prod_config_template="${CUSTOM_SAVE_CONFIG:-$TAA_PRODUCTION_CONFIG_TEMPLATE}"
  local target_image="${CUSTOM_SAVE_IMAGE:-$DEFAULT_SAVE_IMAGE}"
  local target_archive="${CUSTOM_SAVE_ARCHIVE:-$DEFAULT_SAVE_ARCHIVE}"

  banner "Packaging Production Docker Image" "Base: $(basename "$base_archive") + Config: $(basename "$prod_config_template") → Tag: $target_image"

  step "checking docker environment"
  require_command docker
  docker info >/dev/null 2>&1 || { err "docker daemon is not running or accessible"; exit 1; }

  step "verifying base docker image: $base_image"
  if ! docker image inspect "$base_image" >/dev/null 2>&1; then
    require_file "base docker image archive not found" "$base_archive"
    info "base image '$base_image' not present locally; importing from $base_archive"
    spin_task "loading base docker image from $(basename "$base_archive")" docker load -i "$base_archive"
    if ! docker image inspect "$base_image" >/dev/null 2>&1; then
      err "failed to find or import base image '$base_image' from $base_archive"
      exit 1
    fi
    info "base image imported successfully: $base_image"
  else
    info "base image '$base_image' verified"
  fi

  step "building taa daemon"
  ensure_go_compiler
  ensure_parent_dir "$TAA_BINARY_PATH"
  # Static build, matching deploy/manifest/docker/Dockerfile: the packaging host's glibc is not
  # necessarily the image's, and the saved binary must not depend on the two happening to match.
  spin_task "building taa daemon from ./cmd/taa" env CGO_ENABLED=0 GOOS=linux go build -o "$TAA_BINARY_PATH" ./cmd/taa
  require_file "build failed: taa binary" "$TAA_BINARY_PATH"
  info "taa binary ready"

  step "preparing production configuration from $(basename "$prod_config_template")"
  require_file "production config template not found" "$prod_config_template"

  local prod_config_source="$LOCAL_RUN_DIR/export-production-taa-config.json"
  render_image_config "$prod_config_source" "$prod_config_template"
  info "production config prepared for image (model: $RENDERED_CONFIG_MODEL)"

  step "creating ephemeral container to assemble image"
  local builder_container="taa-builder-prod-$$"
  TEMP_BUILDER_CONTAINER="$builder_container"

  spin_task "initializing container directories" bash -c '
    set -euo pipefail
    # Detached on purpose. Everything below reaches into this container with `docker exec`, which a
    # stopped container refuses; the previous foreground form ran its init command and exited, so the
    # container was already stopped by the next line. `docker cp` and `docker commit` work either
    # way, which is why this went unnoticed until the packaging steps needed an exec.
    # --user root for the same reason as the runtime container: the assembly steps
    # below create /root/taa and /opt/taa, which an unprivileged base-image user
    # cannot write. The committed image declares USER root so the same layout is
    # usable when the image is started directly.
    docker run -d --name "$1" --user root --entrypoint bash "$2" -c "sleep infinity" >/dev/null
    docker exec -i "$1" bash -c "
      rm -f /root/taa/manual /root/taa/taa.log 2>/dev/null || true
      mkdir -p /root/taa/models /root/taa/data /root/taa/results /root/taa/certs /root/taa/keys /opt/taa/input /opt/taa/output
      chmod 700 /root/taa/keys
    "
  ' _ "$builder_container" "$base_image"

  # Order matters: the engine is provisioned before the binary and config are copied so the image is
  # assembled once, and the role's supervisor is installed from the repository rather than inherited --
  # save never copied it, so whatever the base image happened to carry became the ENTRYPOINT.
  strip_teellm_from_image "$builder_container"

  step "installing the TAA supervisor"
  spin_task "copying $(basename "$TAA_SUPERVISOR_SOURCE") into the image" \
    docker cp "$TAA_SUPERVISOR_SOURCE" "$builder_container:$TAA_SUPERVISOR_CONTAINER"

  provision_local_scan_engine "$builder_container" "$prod_config_template"

  step "deploying taa binary and production config"
  require_file "vendor attestation certificate (hrk)" "$DEPLOY_CERTS_DIR/hrk.cert"
  require_file "vendor attestation certificate (hsk_cek)" "$DEPLOY_CERTS_DIR/hsk_cek.cert"
  spin_task "copying runtime files into container" bash -c '
    set -euo pipefail
    docker cp "$1" "$2:/root/taa/taa"
    docker cp "$3" "$2:/root/taa/taa-config.json"
    docker cp "$4" "$2:/root/taa/certs/hrk.cert"
    docker cp "$5" "$2:/root/taa/certs/hsk_cek.cert"
  ' _ "$TAA_BINARY_PATH" "$builder_container" "$prod_config_source" \
    "$DEPLOY_CERTS_DIR/hrk.cert" "$DEPLOY_CERTS_DIR/hsk_cek.cert"

  step "committing container to production image: $target_image"
  local commit_msg="Production image packaged from base $(basename "$base_archive") with $(basename "$prod_config_template") at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  spin_task "committing image state ($target_image)" \
    docker commit \
      -c "ENTRYPOINT [\"bash\", \"$TAA_SUPERVISOR_CONTAINER\"]" \
      -c 'CMD []' \
      -c 'USER root' \
      -c "WORKDIR $TAA_WORKDIR" \
      -c 'EXPOSE 6001' \
      -m "$commit_msg" \
      "$builder_container" "$target_image"

  docker rm -f "$builder_container" >/dev/null 2>&1 || true
  TEMP_BUILDER_CONTAINER=""

  local image_id image_size image_size_mb
  image_id=$(docker image inspect --format '{{.Id}}' "$target_image" 2>/dev/null | cut -d: -f2 | cut -c1-12 || echo "")
  image_size=$(docker image inspect --format '{{.Size}}' "$target_image" 2>/dev/null || echo "0")
  image_size_mb=$(awk -v b="$image_size" 'BEGIN { printf "%.2f", b / 1048576 }')
  info "image committed: $target_image (id: $image_id, size: ${image_size_mb}MB)"

  step "exporting image to archive: $target_archive"
  ensure_parent_dir "$target_archive"
  local tmp_archive="${target_archive}.tmp.$$"
  TEMP_EXPORT_FILE="$tmp_archive"

  local compressor="gzip"
  if command -v pigz >/dev/null 2>&1; then
    compressor="pigz"
  fi

  if [[ "$target_archive" == *.tar.gz || "$target_archive" == *.tgz ]]; then
    spin_task "saving and compressing image with $compressor" bash -c '
      set -euo pipefail
      if [[ "$3" == "pigz" ]]; then
        docker save "$1" | pigz -c > "$2"
      else
        docker save "$1" | gzip -c > "$2"
      fi
    ' _ "$target_image" "$tmp_archive" "$compressor"
  else
    spin_task "saving uncompressed image archive" docker save -o "$tmp_archive" "$target_image"
  fi

  mv -f "$tmp_archive" "$target_archive"
  TEMP_EXPORT_FILE=""

  local archive_size archive_mb
  archive_size=$(stat -c %s "$target_archive" 2>/dev/null || echo "0")
  archive_mb=$(awk -v b="$archive_size" 'BEGIN { printf "%.2f", b / 1048576 }')
  info "image archive saved: $target_archive (${archive_mb}MB)"

  banner "Production Image Export Complete" "Successfully packaged base archive with production configuration"
  echo -e "  ${BOLD}${CYAN}● Production Docker Image${NC}  ${DIM}(Packaged & Archived)${NC}"
  echo -e "    ${MUTED}↳ Base Archive     :${NC} ${BOLD}${base_archive}${NC}"
  echo -e "    ${MUTED}↳ Base Image       :${NC} ${base_image}"
  echo -e "    ${MUTED}↳ Config Applied   :${NC} ${BOLD}${prod_config_template}${NC}"
  echo -e "    ${MUTED}↳ Target Model     :${NC} ${PURPLE}${RENDERED_CONFIG_MODEL}${NC}"
  echo -e "    ${MUTED}↳ Image Tag (Date) :${NC} ${BOLD}${GREEN}${target_image}${NC}"
  echo -e "    ${MUTED}↳ Image ID         :${NC} ${image_id}"
  echo -e "    ${MUTED}↳ Uncompressed     :${NC} ${image_size_mb} MB"
  echo -e "    ${MUTED}↳ Export Archive   :${NC} ${BOLD}${target_archive}${NC}"
  if [[ "$target_archive" == *.tar.gz || "$target_archive" == *.tgz ]]; then
    echo -e "    ${MUTED}↳ Compressed Size  :${NC} ${BOLD}${archive_mb} MB${NC} ${DIM}(${compressor})${NC}"
  else
    echo -e "    ${MUTED}↳ Archive Size     :${NC} ${BOLD}${archive_mb} MB${NC}"
  fi
  echo ""
}

usage() {
  cat <<EOF
Usage: $(basename "$0") [create|update|start|stop|probe|delete|save] [--pod <name>] [--namespace <ns>] [--model <name>]

This script deploys to the remote Kata CSV2 Pod over SSH and kubectl.

Actions (mutually exclusive, default: create):
  create    Build the production image from this tree, create the Kata CSV2 Pod, verify that what
            the Pod carries is exactly this build, and start taa (default action).
  update    Install the current build into an existing Pod: upload the binary and a re-rendered
            config, pause, replace, resume. Never creates a Pod.
  start     Start taa inside an existing Pod. Copies nothing.
  stop      Stop taa inside an existing Pod. The Pod is left in place.
  probe     Wait for taa to answer inside an existing Pod; exits non-zero on timeout.
  delete    Delete the Pod this deployment created, together with its guest writable layer.
  save      Package base image archive ($BASE_DOCKER_IMAGE_ARCHIVE) with production config ($TAA_PRODUCTION_CONFIG_TEMPLATE),
            commit with a date-stamped tag ($DEFAULT_SAVE_IMAGE), and export to an image archive ($DEFAULT_SAVE_ARCHIVE).
            This is a standalone packaging action and does not deploy anything (e.g. $(basename "$0") save).

Options:
  --pod <name>
      Address the existing Pod <name> (update, start, stop, probe). The named Pod is never created
      or deleted by this script, so create and delete refuse it.
  --namespace <ns>
      Kubernetes namespace of the target Pod (default: osr).
  --model <name> (or --model=<name>)
      Explicitly specify the LLM audit model (overriding config files).
  --port <port>
      Port TAA listens on inside the Pod (default: 6001).
  --remote-password <password>
      SSH password for the remote host. Without it the script prompts.
  --archive <path>
      Customize the exported archive file destination (save).
  --image <tag>
      Image create runs the Pod from (no build, presence-only verification), or the image tag save
      produces. Without it, create builds the production image from this tree and save names it
      <repo>:<today>.
  --base-archive <path> (or --base <path>)
      Specify a custom base image archive (save).
  --save-config <path>
      Specify an alternate production configuration template (save, and create's verification).

Note: the platform (or platform-mock) is deployed separately with deploy-platform-mock.sh,
and Qwen / Ollama / TEE-LLM with deploy-llm.sh.

Pod lifecycle:
  Only create brings a Pod into existence. Without --pod it owns the dedicated Kata CSV2 Pod
  (default name: TAA_POD_NAME, i.e. taa-deploy): create builds the production image from the
  current tree, pushes it as TAA_IMAGE_REGISTRY/TAA_POD_IMAGE_REPO:<today>, creates the Pod and
  verifies the binary, supervisor and config inside against this tree -- a mismatch fails the run
  and is listed, never patched. An existing Pod is kept and verified, because its guest writable
  layer holds the SM2 key pair, the sealed state and the imported data; delete removes it. A Pod
  named through --pod is only ever updated, started, stopped or probed.
  Identity (PLATFORM_IP, DOCKER_ID, PLATFORM_PUBLIC_KEY, CONTRACT_ID) is injected into the Pod as
  environment variables at create time; it is not written into taa-config.json and not verified.
  The Pod's LLM endpoint comes from taa-config.json, which update rewrites.

Examples:
  # Remote deployment (Kubernetes Pod + SSH)
  $(basename "$0")
  $(basename "$0") create --model qwen2.5-coder:7b
  $(basename "$0") update
  $(basename "$0") start
  $(basename "$0") probe
  $(basename "$0") stop
  $(basename "$0") delete

  # Production image packaging (no deployment)
  $(basename "$0") save
  $(basename "$0") save --image taa-train-infer:$(date +%Y%m%d)
  $(basename "$0") save --archive /tmp/taa-env-production.tar.gz

Environment overrides:
  # Kubernetes / Pod
  TAA_POD_NAME=${TAA_POD_NAME}
      --pod 未给出时创建/复用的 Pod 名称（默认 taa-deploy）。
  TAA_IMAGE_REGISTRY=${TAA_IMAGE_REGISTRY}
      自动构建镜像推送到的 registry（默认 <REMOTE_HOST>:31313）。
  TAA_POD_IMAGE_REPO=${TAA_POD_IMAGE_REPO}
      自动构建镜像的仓库名（默认 taa-train-infer，tag 为当天日期 YYYYMMDD）。
  TAA_POD_PULL_POLICY=${TAA_POD_PULL_POLICY}
      新建 Pod 的 imagePullPolicy；自动构建的当天 tag 会强制 Always，显式设置则尊重原值。
  TAA_POD_NODE=${TAA_POD_NODE}
      新建 Pod 绑定的节点（默认 hygon-master）。
  TAA_POD_RUNTIME_CLASS=${TAA_POD_RUNTIME_CLASS}
      新建 Pod 的 RuntimeClass（默认 kata-qemu-csv2）。
  TAA_POD_CONTRACT_TYPE=${TAA_POD_CONTRACT_TYPE}
      新建 Pod 的实例角色，写入 CONTRACT_TYPE（默认 1）：1 tee 训练、2 tee 推理（1 和 2 都落到
      普通 tee 角色）、3 数据分析。数据分析角色的数据落盘目录与审计开关由角色决定。fhe 角色
      不在这里创建，由 deploy-fhe.sh 负责。Pod 的环境变量不能原地修改，换角色只能重建 Pod。
  TAA_POD_CPU=${TAA_POD_CPU}
  TAA_POD_MEMORY=${TAA_POD_MEMORY}
      新建 Pod 的 CPU/内存 limits（默认 3 / 98Gi；CSV2 加密内存按 limits 常驻）。
  TAA_POD_READY_TIMEOUT=${TAA_POD_READY_TIMEOUT}
      等待新建 Pod Ready 的秒数（默认 600）。
  TAA_DCU_QUIESCE_SECONDS=${TAA_DCU_QUIESCE_SECONDS}
      删除 Pod 前让 DCU 静默的秒数（默认 90）。DCU 在计算中被销毁 VM 后无法复位，会弄脏卡、
      导致下一个 guest 探测失败（RLC ucode load fail / -110）；实测 111s 后删干净、18s 后删弄脏，
      90 是两点之间的取值而非阈值。宿主看不到卡是否在计算（MSI 走 irqbypass），只能定时等待。
      置 0 跳过；宿主上无 DCU 时自动跳过。Pod 模板另有等长的 preStop 兜底，两者叠加。
  TAA_POD_CC_INIT_DATA=<base64>
      cc_init_data 注解；置空时先取宿主上已有 CoCo Pod 的注解，取不到再用 TAA_POD_INITDATA_FILE
      渲染（与厂商 Pod 模板同一做法），都拿不到才报错。
  TAA_POD_INITDATA_FILE=${TAA_POD_INITDATA_FILE}
      宿主机上的 initdata 文件，作为 cc_init_data 的兜底来源（gzip + base64 后写入注解）。
  TAA_POD_DOCKER_ID=<id>
      注册到平台的 DOCKER_ID；置空时使用 Pod 名称。同时作为 Pod 的 taa-instance-id 标签值，
      因此必须是合法的 Kubernetes label（≤63 字符，字母数字/-/_/.，首尾为字母数字）。
  TAA_SERVICE_NODE_PORT=<30000-32767>
      把该实例的 TAA 监听端口以 NodePort 发布到集群节点，并创建一个以 DOCKER_ID 为选择器的
      Service。平台不在集群网络时（例如 platform-mock 部署在另一台主机）必须用它：TAA 注册
      报文的源地址会被 NAT 改写，平台推导出的地址只会指向那台 NAT 主机。地址形如
      http://<REMOTE_HOST>:<port>，实例重建后不变。置空则不创建 Service（只能按 Pod IP 访问）；
      与已占用的 NodePort 冲突时创建失败，Pod 本身不受影响。
  TAA_INSTANCE_LABEL_KEY=${TAA_INSTANCE_LABEL_KEY}
      Service 用来选中该 Pod 的标签键（默认 taa-instance-id）。
  TAA_POD_PLATFORM_PUBLIC_KEY=<hex>
      平台 SM2 公钥（04||X||Y 的 hex）；也可直接用 PLATFORM_PUBLIC_KEY。两者都未设置时，
      从 TAA_POD_PLATFORM_KEY_FILE 自动读取；仍读不到才拒绝创建（TAA 缺它会启动即 FATAL）。
  TAA_POD_PLATFORM_KEY_FILE=${TAA_POD_PLATFORM_KEY_FILE}
      宿主机上保存平台公钥的文件（读 publicKeyHex 字段，默认 <REMOTE_DIR>/platform-key.json，
      即 platform-mock 的默认状态目录）。

  # Remote host / SSH
  REMOTE_USER=${REMOTE_USER}
      远程宿主机 SSH 登录用户名。
  REMOTE_HOST=${REMOTE_HOST}
      远程宿主机 IP 或主机名。
  REMOTE_DIR=${REMOTE_DIR}
      远程宿主机上的部署工作目录。
  REMOTE_PASSWORD=<password>
      SSH 密码覆盖项；置空时脚本会交互式询问。

  # Platform address observed by TAA
  # The platform itself (or platform-mock) is deployed separately with deploy-platform-mock.sh.
  PLATFORM_PORT=${PLATFORM_PORT}
      TAA 访问 platform 使用的端口（默认 18080）。
  REMOTE_PLATFORM_IP=${REMOTE_PLATFORM_IP}
      TAA 容器访问 platform 使用的完整地址（默认 <REMOTE_HOST>:<PLATFORM_PORT>）。

  # TAA service / attestation
  BINARY_NAME=${BINARY_NAME}
      TAA 二进制文件名。
  TAA_BINARY_PATH=${TAA_BINARY_PATH}
      本地 TAA 二进制文件路径。
  TAA_WORKDIR=${TAA_WORKDIR}
      TAA 在目标容器内的工作目录。
  TAA_CONTAINER_ADDR=${TAA_CONTAINER_ADDR}
      写入 TAA 配置文件的容器内监听地址与端口。
  TAA_PRODUCTION_CONFIG_TEMPLATE=${TAA_PRODUCTION_CONFIG_TEMPLATE}
      TAA 配置模板（远程部署与打包镜像都用它）。
  CONTRACT_ID=${CONTRACT_ID}
      写入配置文件的合约 ID（可选，正式场景通常由运行环境注入）。
  TAA_KEEP_MANUAL=${TAA_KEEP_MANUAL:-false}
      远程部署后是否保持容器 manual 挂起状态而不自启（默认 false）。
  REMOTE_SEMGREP_BUNDLE=$REMOTE_SEMGREP_BUNDLE
      宿主上的 semgrep 引擎 payload 归档；配置选中 semgrep 引擎但容器里没有时从这里注入。
  SEMGREP_BUNDLE=${SEMGREP_BUNDLE:-<未设置>}
      本地 semgrep 引擎 payload 归档；设置后会先上传到宿主再注入，留空则要求宿主上已存在。
  SEMGREP_RULES_SOURCE=$SEMGREP_RULES_SOURCE
      注入容器的代码扫描规则目录，按配置里的 codeAudit.codeScan.rulesPath 落位。
  SEMGREP_PAYLOAD_BUNDLE=$SEMGREP_PAYLOAD_BUNDLE
      save 打包时解包进镜像的 semgrep 容器 payload（由
      deploy/guest-build/build-semgrep-payload-container.sh 产出）。
  TAA_SEMGREP_DIR=$TAA_SEMGREP_DIR
      镜像内 semgrep 的安装根目录（pylib 与规则所在位置）。
  SEMGREP_VERSION=$SEMGREP_VERSION
      期望的 semgrep 版本；与 payload 包内 MANIFEST 记录的版本不一致时报错。
  TAA_SCAN_ENGINE_PROVISION=${TAA_SCAN_ENGINE_PROVISION}
      扫描引擎注入模式：auto（默认，按模板选择注入）或 skip（不注入，供运行时按角色关掉
      审计的场景使用，例如数据分析）。
  TAA_READY_TIMEOUT=${TAA_READY_TIMEOUT}
      等待服务就绪的最长时间（秒）。
  TAA_READY_INTERVAL=${TAA_READY_INTERVAL}
      服务就绪检测轮询间隔（秒）。
EOF
}

ensure_parent_dir() {
  mkdir -p "$(dirname "$1")"
}

# confirm_taa_listening CMD runs CMD (which should print the tail of TAA's log)
# after a successful TCP probe and looks for the startup line. Without it a stale
# process from a previous run, or a listener that is up but short of the
# configuration step, looks the same as a healthy daemon -- the probe alone
# cannot tell them apart. The command is a string because the caller reaches the
# log through kubectl exec over SSH.
confirm_taa_listening() {
  local tail_cmd="$1"
  local haystack
  haystack=$(eval "$tail_cmd" 2>/dev/null || true)
  grep -q 'taa service listening on' <<<"$haystack"
}

require_file() {
  local label="$1"
  local path="$2"
  [[ -f "$path" ]] || { err "$label: file not found ($path)"; exit 1; }
}

require_dir() {
  local label="$1"
  local path="$2"
  [[ -d "$path" ]] || { err "$label: directory not found ($path)"; exit 1; }
}

require_command() {
  local name="$1"
  command -v "$name" >/dev/null 2>&1 || { err "command '$name' is required but not installed or not in PATH"; exit 1; }
}

# The daemon is built twice in one `create`: once into the image and once to verify what the Pod
# carries, and the two files are compared byte for byte. They can only match when both builds use
# the same compiler, so the toolchain is chosen once per run and kept: picking again on a host
# that has both a local Go and the snap one prepended the other the second time, and a perfectly
# good image then failed its own verification with two different hashes.
ensure_go_compiler() {
  if [[ -n "${TAA_GO_COMPILER_READY:-}" ]]; then
    return 0
  fi

  # Prefer a locally installed newer Go (e.g. /usr/local/go/bin, /snap/bin).
  for candidate in /usr/local/go/bin /snap/bin; do
    if [[ -x "$candidate/go" ]]; then
      local current_go
      current_go=$(command -v go 2>/dev/null || echo "")
      if [[ "$current_go" != "$candidate/go" ]]; then
        export PATH="$candidate:$PATH"
        break
      fi
    fi
  done

  if ! command -v go >/dev/null 2>&1; then
    err "go compiler is required but not found in PATH"
    exit 1
  fi

  if [[ -f "$PROJECT_DIR/go.mod" ]]; then
    local req_ver
    req_ver=$(awk '/^go [0-9]/ {print $2}' "$PROJECT_DIR/go.mod" | head -n 1)
    if [[ -n "$req_ver" ]]; then
      local cur_ver
      cur_ver=$(GOTOOLCHAIN=local go version 2>/dev/null | awk '{print $3}' | sed 's/^go//' || echo "")
      if [[ -n "$cur_ver" ]]; then
        local cur_major cur_minor req_major req_minor
        cur_major=$(echo "$cur_ver" | cut -d. -f1)
        cur_minor=$(echo "$cur_ver" | cut -d. -f2)
        req_major=$(echo "$req_ver" | cut -d. -f1)
        req_minor=$(echo "$req_ver" | cut -d. -f2)
        if (( cur_major < req_major || (cur_major == req_major && cur_minor < req_minor) )); then
          warn "Current local go version ($cur_ver) is lower than go.mod requirement ($req_ver)."
          warn "If offline, toolchain auto-download will fail. Ensure a Go $req_ver+ compiler is installed and exported in PATH."
        fi
      fi
    fi
  fi

  TAA_GO_COMPILER_READY=1
}

get_taa_config_llm_model() {
  local template="$1"
  if [[ -f "$template" ]]; then
    python3 - "$template" <<'PY' 2>/dev/null || true
import json, sys
try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        data = json.load(f)
    model = ((data.get("codeAudit") or {}).get("llm") or {}).get("model")
    if model and isinstance(model, str) and model.strip():
        print(model.strip())
except Exception:
    pass
PY
  fi
}

# Reads the code scan engine and its rules path out of a TAA config template and prints them as
# one line, "<engine> <rulesPath>". An empty engine means the template does not set the key, which
# is what a deployment that never configured the engine looks like; the caller decides what that
# implies. Nothing is printed when the template cannot be read or parsed, so a malformed template
# cannot make this look like "engine disabled".
taa_scan_engine_requirements() {
  local template="$1"
  if [[ ! -f "$template" ]]; then
    return 0
  fi
  python3 - "$template" <<'PY' 2>/dev/null || true
import json, sys
try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        cfg = json.load(f)
    code_audit = cfg.get("codeAudit") or {}
    code_scan = code_audit.get("codeScan") or {}
    engine = code_scan.get("engine") or ""
    rules = code_scan.get("rulesPath") or ""
    if isinstance(engine, str) and isinstance(rules, str):
        print("%s %s" % (engine.strip(), rules.strip()))
except Exception:
    pass
PY
}

# Streams a local directory or file into the container as the destination path. The archive is
# built in memory and unpacked by the container's own tar, so nothing is staged on the remote host
# and the destination name is decided here rather than by how `kubectl cp` names directories.
stream_local_path_to_container() {
  local source="$1"
  local destination="$2"
  local source_parent source_name destination_parent destination_name
  source_parent="$(dirname "$source")"
  source_name="$(basename "$source")"
  destination_parent="$(dirname "$destination")"
  destination_name="$(basename "$destination")"
  tar -czf - --transform "s|^${source_name}|${destination_name}|" -C "$source_parent" "$source_name" \
    | remote_ssh "$(container_exec_i) sh -lc 'mkdir -p $destination_parent && rm -rf $destination && tar -xzf - -C $destination_parent'"
}

# The docker twin of stream_local_path_to_container: copies a local path into a running local
# container under a destination name decided here. `docker cp` would otherwise name the destination
# after the source's own basename, and copying a directory into an existing one nests it instead of
# replacing it -- which is why the destination is removed first.
docker_cp_into_container() {
  local container="$1"
  local source="$2"
  local destination="$3"
  docker exec -i "$container" sh -lc "mkdir -p '$(dirname "$destination")' && rm -rf '$destination'" >/dev/null
  docker cp "$source" "$container:$destination" >/dev/null
}

# Every semgrep invocation in here is offline and bounded, and both halves are load-bearing.
# semgrep reaches for the network before it does any work: it resolves semgrep.dev for a version
# check, and some commands download from it outright. A TAA container has no route off the host and
# no reachable resolver, so that lookup is never answered and the process sits in getaddrinfo;
# AppSession retries on top of it with a 16/32/64s backoff, making one unflagged call cost a
# minute or more. `semgrep --validate` does not even get that far -- see below. The flags stop
# those calls from starting at all; the bound is what keeps a payload built before this was fixed
# -- like the one already inside a running pod -- from hanging the deploy instead of failing it.
# `timeout` is coreutils and a slim image may still not ship it, so the bound degrades to running
# unbounded rather than to failing, which would misreport a healthy engine as missing.
SEMGREP_OFFLINE_TIMEOUT="${SEMGREP_OFFLINE_TIMEOUT:-90}"
SEMGREP_OFFLINE_PREAMBLE="bounded() { if command -v timeout >/dev/null 2>&1; then timeout $SEMGREP_OFFLINE_TIMEOUT \"\$@\"; else \"\$@\"; fi; }
SEMGREP_SEND_METRICS=off; SEMGREP_ENABLE_VERSION_CHECK=0; export SEMGREP_SEND_METRICS SEMGREP_ENABLE_VERSION_CHECK"

# The verification scans a two-line probe with the same argv taa's engine runs at audit time,
# including the --max-memory cap, and demands what the engine demands of that run: exit 0, nothing
# in semgrep's error list, the target actually read, and a rule that still matches it. The probe
# calls os.system, which the shipped CMD_001 rule matches, so a rules tree that loads but matches
# nothing is caught here rather than showing up later as an audit that quietly finds nothing.
#
# `semgrep --validate` is the obvious check and the wrong one: before validating anything it loads
# the registry-hosted metacheck pack (p/semgrep-rule-lints) unconditionally, and no flag or
# environment variable skips that. Offline the download fails and takes the command with it --
# measured inside a kata pod, exit code 2 after about 200 seconds, which is precisely the failure
# this step used to report. This scan argv answers in seconds there. The max-memory value is kept
# in step with DefaultSemgrepMaxMemoryMB in internal/codeaudit/semgrep_engine.go.
SEMGREP_VERIFY_MAX_MEMORY="${SEMGREP_VERIFY_MAX_MEMORY:-1024}"
SEMGREP_VERIFY_BODY='
probe=/tmp/taa-deploy-probe.py
out=/tmp/taa-deploy-probe.json
err=/tmp/taa-deploy-probe.err
rm -f "$out" "$err"
printf "import os\nos.system(1)\n" > "$probe"
bounded semgrep scan --config $rules_path --json --quiet --disable-version-check --no-git-ignore --max-memory $max_memory "$probe" > "$out" 2> "$err"
rc=$?
if [ "$rc" -ne 0 ]; then
  echo "FAIL rc=$rc $(printf %s "$(cat "$err")" | tr "\n" " " | cut -c1-300)"
  exit 0
fi
verdict=$(python3 - "$out" <<PY
import json, sys
try:
    data = json.load(open(sys.argv[1]))
except Exception as exc:
    print("FAIL rc=0 semgrep output was not JSON: %s" % exc); sys.exit(0)
errors = data.get("errors") or []
scanned = (data.get("paths") or {}).get("scanned") or []
results = data.get("results") or []
if errors:
    print("FAIL rc=0 semgrep reported %d error(s): %s" % (len(errors), errors[0].get("message", "")))
elif not scanned:
    print("FAIL rc=0 semgrep read none of the file(s) it was given")
elif not results:
    print("FAIL rc=0 the rules matched nothing in the probe; the rule set may not be usable")
else:
    print("OK findings=%d scanned=%d" % (len(results), len(scanned)))
PY
)
version=$(bounded semgrep --version --disable-version-check 2>/dev/null | head -n 1)
echo "$verdict version=${version:-unknown}"'

# Makes sure the code scan engine the config selects actually works inside the container. The
# engine is resolved by taa at startup and is fail-open for semgrep: a missing rules path leaves
# the audit on the built-in regex engine with a warning, and a missing CLI fails every scan the
# adapter runs. Neither shows up as an error -- the first looks like a healthy start, the second
# like a failed audit -- so provisioning is checked here rather than left to the pod's logs.
# Probing first keeps a redeploy onto an already-provisioned pod free.
provision_remote_scan_engine() {
  local template="$1"
  local engine="" rules_path=""
  read -r engine rules_path <<<"$(taa_scan_engine_requirements "$template")"

  if [[ "$TAA_SCAN_ENGINE_PROVISION" == "skip" ]]; then
    info "code scan engine provisioning skipped (TAA_SCAN_ENGINE_PROVISION=skip)"
    return 0
  fi

  if [[ "$engine" != "semgrep" ]]; then
    info "code scan engine '${engine:-unset}' needs no semgrep payload"
    return 0
  fi

  if [[ -z "$rules_path" ]]; then
    err "codeAudit.codeScan.rulesPath is empty in $(basename "$template") but codeAudit.codeScan.engine=semgrep"
    detail "Without it taa falls back to its built-in path relative to the working directory, which does not exist in the container."
    detail "Set codeAudit.codeScan.rulesPath (the shipped templates use $CONTAINER_TAA_CONFIG_PATH's directory, e.g. /opt/taa/semgrep/rules)."
    exit 1
  fi

  local probe state engine_present rules_present
  probe="$SEMGREP_OFFLINE_PREAMBLE
e=no; r=no
command -v semgrep >/dev/null 2>&1 && bounded semgrep --version --disable-version-check >/dev/null 2>&1 && e=yes
test -e $rules_path && r=yes
echo engine=\$e rules=\$r"
  state="$(remote_ssh "$(container_exec) sh -lc '$probe'" 2>/dev/null || echo 'engine=no rules=no')"
  engine_present="${state#engine=}"; engine_present="${engine_present%% *}"
  rules_present="${state##*rules=}"

  if [[ "$engine_present" == "yes" && "$rules_present" == "yes" ]]; then
    info "code scan engine already provisioned inside container (rules: $rules_path)"
  else
    if [[ "$engine_present" != "yes" ]]; then
      warn "semgrep is not installed in the container; taa would fall back to the regex engine at startup"
      if [[ -n "$SEMGREP_BUNDLE" ]]; then
        require_file "semgrep payload bundle not found" "$SEMGREP_BUNDLE"
        spin_task "uploading semgrep payload to ${REMOTE_HOST} ($(du -h "$SEMGREP_BUNDLE" 2>/dev/null | cut -f1))" \
          sshpass -p "$REMOTE_PASSWORD" scp "${SSH_OPTS[@]}" "$SEMGREP_BUNDLE" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_SEMGREP_BUNDLE.new"
        remote_ssh "mv '$REMOTE_SEMGREP_BUNDLE.new' '$REMOTE_SEMGREP_BUNDLE'"
      fi
      if ! remote_ssh "test -f '$REMOTE_SEMGREP_BUNDLE'"; then
        err "semgrep payload bundle not found: ${REMOTE_HOST}:$REMOTE_SEMGREP_BUNDLE"
        detail "Build it with 'deploy/guest-build/build-semgrep-payload-container.sh', then copy the archive there:"
        detail "  scp <bundle>.tar.gz ${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_SEMGREP_BUNDLE"
        detail "Or point SEMGREP_BUNDLE at a local archive and rerun; it will be uploaded for you."
        exit 1
      fi
      # Read the archive on the remote host instead of streaming it across SSH a second time.
      spin_task "installing semgrep into the container from $REMOTE_SEMGREP_BUNDLE" \
        remote_ssh "cat '$REMOTE_SEMGREP_BUNDLE' | $(container_exec_i) sh -lc 'tar -xzf - -C /'"
    fi

    if [[ "$rules_present" != "yes" ]]; then
      warn "code scan rules are missing in the container at $rules_path"
      require_dir "semgrep rules not found" "$SEMGREP_RULES_SOURCE"
      spin_task "copying code scan rules into the container ($rules_path)" \
        stream_local_path_to_container "$SEMGREP_RULES_SOURCE" "$rules_path"
    fi
  fi

  # Presence is not proof, and the probe above cannot tell the two apart: the payload can be
  # extracted and the rules in place while semgrep still cannot run them in this container, which
  # is a state the probe reports as provisioned. The check therefore runs on every deploy rather
  # than only after an install, and its output is kept instead of discarded, because the failure it
  # has to explain is usually semgrep's own.
  local verify_script verify_out engine_version
  verify_script="$SEMGREP_OFFLINE_PREAMBLE
rules_path=$rules_path
max_memory=$SEMGREP_VERIFY_MAX_MEMORY
$SEMGREP_VERIFY_BODY"
  verify_out="$(remote_ssh "$(container_exec) sh -lc '$verify_script'" 2>&1 || true)"

  if [[ "$verify_out" == OK\ * ]]; then
    engine_version="${verify_out##*version=}"
    info "code scan engine ready inside container: semgrep ${engine_version:-unknown} (rules: $rules_path)"
  else
    err "code scan engine verification failed inside the container"
    detail "${verify_out:-no output from the container}"
    detail "Checked with the argv taa runs at audit time: semgrep scan --config $rules_path --json --quiet --disable-version-check --no-git-ignore --max-memory $SEMGREP_VERIFY_MAX_MEMORY <probe.py>"
    detail "semgrep reaches for the network before it scans, and a container with no route off the host answers none of it; every check in this step is offline and bounded (${SEMGREP_OFFLINE_TIMEOUT}s) for that reason."
    exit 1
  fi
}

# The image-packaging twin of provision_remote_scan_engine, run against the ephemeral builder container
# so the engine lands in the committed image. Same detection, same payload, same verification probe:
# presence is not proof, because the payload can be extracted and the rules in place while semgrep
# still cannot run them in this image -- a state the cheap probe reports as provisioned. Unlike the
# remote path nothing is installed over the network; the payload is extracted from an archive.
provision_local_scan_engine() {
  local container="$1"
  local template="$2"
  local engine="" rules_path=""
  read -r engine rules_path <<<"$(taa_scan_engine_requirements "$template")"

  if [[ "$TAA_SCAN_ENGINE_PROVISION" == "skip" ]]; then
    info "code scan engine provisioning skipped (TAA_SCAN_ENGINE_PROVISION=skip)"
    return 0
  fi

  if [[ "$engine" != "semgrep" ]]; then
    info "code scan engine '${engine:-unset}' needs no semgrep payload"
    return 0
  fi

  if [[ -z "$rules_path" ]]; then
    err "codeAudit.codeScan.rulesPath is empty in $(basename "$template") but codeAudit.codeScan.engine=semgrep"
    detail "Without it taa falls back to its built-in path relative to the working directory, which does not exist in the image."
    detail "Set codeAudit.codeScan.rulesPath (the shipped templates use a path under $TAA_SEMGREP_DIR, e.g. $TAA_SEMGREP_DIR/rules)."
    exit 1
  fi

  step "provisioning the $engine code scan engine in the image"
  local probe state engine_present rules_present
  probe="$SEMGREP_OFFLINE_PREAMBLE
e=no; r=no
command -v semgrep >/dev/null 2>&1 && bounded semgrep --version --disable-version-check >/dev/null 2>&1 && e=yes
test -e $rules_path && r=yes
echo engine=\$e rules=\$r"
  state="$(docker exec -i "$container" sh -lc "$probe" 2>/dev/null || echo 'engine=no rules=no')"
  engine_present="${state#engine=}"; engine_present="${engine_present%% *}"
  rules_present="${state##*rules=}"

  if [[ "$engine_present" == "yes" && "$rules_present" == "yes" ]]; then
    info "code scan engine already provisioned in the image (rules: $rules_path)"
  else
    if [[ "$engine_present" != "yes" ]]; then
      require_file "semgrep payload bundle not found; build it with deploy/guest-build/build-semgrep-payload-container.sh" "$SEMGREP_PAYLOAD_BUNDLE"
      local bundle_version=""
      # The MANIFEST is colon-separated ("semgrep_version: 1.177.0", written by
      # build-semgrep-payload-container.sh), not the whitespace-separated form an earlier version of
      # this check assumed -- which matched nothing and quietly downgraded the gate to a warning.
      bundle_version="$(tar -xzOf "$SEMGREP_PAYLOAD_BUNDLE" opt/taa/semgrep/MANIFEST 2>/dev/null \
        | awk -F':' '$1 == "semgrep_version" { gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit }')" || true
      if [[ -z "$bundle_version" ]]; then
        warn "payload bundle carries no readable opt/taa/semgrep/MANIFEST; its version was not checked"
      elif [[ "$bundle_version" != "$SEMGREP_VERSION" ]]; then
        err "semgrep payload bundle holds $bundle_version but this build expects $SEMGREP_VERSION"
        detail "Rebuild it: deploy/guest-build/build-semgrep-payload-container.sh"
        exit 1
      fi

      spin_task "extracting semgrep payload into the image" bash -c '
        set -euo pipefail
        docker cp "$1" "$2:/tmp/taa-semgrep-payload.tar.gz"
        docker exec -i "$2" sh -lc "tar -xzf /tmp/taa-semgrep-payload.tar.gz -C / && rm -f /tmp/taa-semgrep-payload.tar.gz"
      ' _ "$SEMGREP_PAYLOAD_BUNDLE" "$container"

      if ! docker exec -i "$container" sh -lc "test -d '$TAA_SEMGREP_DIR/pylib'"; then
        err "payload extracted but $TAA_SEMGREP_DIR/pylib is missing"
        detail "The bundle is expected to carry opt/taa/semgrep/pylib; rebuild it with deploy/guest-build/build-semgrep-payload-container.sh"
        exit 1
      fi
    fi

    if [[ "$rules_present" != "yes" ]]; then
      require_dir "semgrep rules not found" "$SEMGREP_RULES_SOURCE"
      spin_task "copying code scan rules into the image ($rules_path)" \
        docker_cp_into_container "$container" "$SEMGREP_RULES_SOURCE" "$rules_path"
    fi
  fi

  local verify_script verify_out engine_version
  verify_script="$SEMGREP_OFFLINE_PREAMBLE
rules_path=$rules_path
max_memory=$SEMGREP_VERIFY_MAX_MEMORY
$SEMGREP_VERIFY_BODY"
  verify_out="$(docker exec -i "$container" sh -lc "$verify_script" 2>&1 || true)"
  # The probe leaves its own files behind and semgrep leaves its state behind: the probe script, its
  # JSON and its stderr in /tmp, an empty /tmp/semgrep-mcp, and /root/.semgrep -- created on
  # semgrep's first run and carrying an anonymous_user_id generated on the packaging host. This
  # container is about to be committed, so without this all of it ships inside the image. Measured,
  # not guessed: a filesystem diff of the packaged image against its base names exactly these paths.
  docker exec -i "$container" sh -lc \
    'rm -rf /tmp/taa-deploy-probe.py /tmp/taa-deploy-probe.json /tmp/taa-deploy-probe.err /tmp/semgrep-mcp /root/.semgrep' >/dev/null 2>&1 || true

  if [[ "$verify_out" == OK\ * ]]; then
    engine_version="${verify_out##*version=}"
    info "code scan engine ready in the image: semgrep ${engine_version:-unknown} (rules: $rules_path)"
  else
    err "code scan engine verification failed in the image"
    detail "${verify_out:-no output from the container}"
    detail "Checked with the argv taa runs at audit time: semgrep scan --config $rules_path --json --quiet --disable-version-check --no-git-ignore --max-memory $SEMGREP_VERIFY_MAX_MEMORY <probe.py>"
    detail "semgrep reaches for the network before it scans; every check in this step is offline and bounded (${SEMGREP_OFFLINE_TIMEOUT}s) for that reason."
    exit 1
  fi
}

resolve_target_model() {
  if [[ -n "$CLI_MODEL" ]]; then
    printf '%s' "$CLI_MODEL"
    return 0
  fi
  local model
  model="$(get_taa_config_llm_model "$TAA_PRODUCTION_CONFIG_TEMPLATE")"
  if [[ -n "$model" ]]; then
    printf '%s' "$model"
    return 0
  fi
  printf '%s' "qwen2.5-coder:3b"
}

write_taa_config() {
  local path="$1"
  local template="$2"
  local addr="$3"
  local platform_ip="$4"
  local docker_id="$5"
  local contract="$6"
  local model_dir="$7"
  local data_dir="$8"
  local result_dir="$9"
  local llm_endpoint="${10}"
  local llm_model="${11}"
  local include_identity="${12}"
  local model_input_dir="${13:-}"
  local model_output_dir="${14:-}"
  local keys_dir="${15:-}"

  require_file "taa config template not found" "$template"
  require_command python3
  ensure_parent_dir "$path"
  python3 - "$template" "$path" "$addr" "$platform_ip" "$docker_id" "$contract" "$model_dir" "$data_dir" "$result_dir" "$llm_endpoint" "$llm_model" "$include_identity" "$model_input_dir" "$model_output_dir" "$keys_dir" <<'PY'
import json
import os
import sys

(
    template,
    path,
    addr,
    platform_ip,
    docker_id,
    contract,
    model_dir,
    data_dir,
    result_dir,
    llm_endpoint,
    llm_model,
    include_identity,
    model_input_dir,
    model_output_dir,
    keys_dir,
) = sys.argv[1:16]

with open(template, "r", encoding="utf-8") as f:
    cfg = json.load(f)

server = cfg.setdefault("server", {})
if addr:
    server["addr"] = addr
cfg.pop("addr", None)

storage = cfg.setdefault("storage", {})
if model_dir:
    storage["model"] = model_dir
if data_dir:
    storage["data"] = data_dir
if result_dir:
    storage["result"] = result_dir
if keys_dir:
    storage["keys"] = keys_dir
for key in ("modelDir", "dataDir", "resultDir", "keysDir"):
    cfg.pop(key, None)

if model_input_dir or model_output_dir:
    model = cfg.setdefault("model", {})
    if model_input_dir:
        model["input"] = model_input_dir
    if model_output_dir:
        output = model.setdefault("output", {})
        output["result"] = model_output_dir
for key in ("modelInputDir", "modelOutputDir", "modelLogDir", "modelProgressDir"):
    cfg.pop(key, None)

if include_identity == "true":
    platform = cfg.setdefault("platform", {})
    if platform_ip:
        platform["ip"] = platform_ip
    if docker_id:
        platform["dockerID"] = docker_id
    platform["contract"] = contract
else:
    cfg.pop("platform", None)
for key in ("platformIP", "dockerID", "contract"):
    cfg.pop(key, None)

for key in ("securityScan", "resultCheck"):
    if key in cfg and not isinstance(cfg[key], dict):
        cfg.pop(key, None)

llm = cfg.setdefault("codeAudit", {}).setdefault("llm", {})
if llm_endpoint:
    llm["endpoint"] = llm_endpoint
if llm_model:
    llm["model"] = llm_model
llm.pop("dir", None)

with open(path, "w", encoding="utf-8") as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
    f.write("\n")
PY
}

ACTION=""

if [[ $# -eq 0 ]]; then
  # create is the one-shot path: build, create the Pod, verify what it carries, start.
  ACTION="create"
else
  while [[ $# -gt 0 ]]; do
    arg="$1"
    case "$arg" in
      docker|local|local-docker)
        err "the '$arg' mode has been removed. This script deploys to the remote Kata CSV2 Pod only."
        usage >&2
        exit 1
        ;;
      create|update|start|stop|probe|delete|save)
        if [[ -n "$ACTION" && "$ACTION" != "$arg" ]]; then
          err "cannot specify multiple actions ($ACTION and $arg)"
          usage >&2
          exit 1
        fi
        ACTION="$arg"
        ;;
      --pod=*)
        TARGET_POD="${arg#*=}"
        if [[ -z "$TARGET_POD" ]]; then
          err "--pod requires a Pod name argument"
          usage >&2
          exit 1
        fi
        TARGET_POD_WAS_SET="set"
        ;;
      --pod)
        shift
        if [[ $# -eq 0 || "$1" == -* ]]; then
          err "--pod requires a Pod name argument"
          usage >&2
          exit 1
        fi
        TARGET_POD="$1"
        TARGET_POD_WAS_SET="set"
        ;;
      --namespace=*)
        TARGET_NAMESPACE="${arg#*=}"
        if [[ -z "$TARGET_NAMESPACE" ]]; then
          err "--namespace requires a namespace argument"
          usage >&2
          exit 1
        fi
        ;;
      --namespace)
        shift
        if [[ $# -eq 0 || "$1" == -* ]]; then
          err "--namespace requires a namespace argument"
          usage >&2
          exit 1
        fi
        TARGET_NAMESPACE="$1"
        ;;
      --archive=*)
        CUSTOM_SAVE_ARCHIVE="${arg#*=}"
        ;;
      --archive)
        shift
        if [[ $# -eq 0 || "$1" == -* ]]; then
          err "$arg requires a file path argument"
          usage >&2
          exit 1
        fi
        CUSTOM_SAVE_ARCHIVE="$1"
        ;;
      --image=*)
        TAA_IMAGE="${arg#*=}"
        TAA_IMAGE_WAS_SET="set"
        CUSTOM_SAVE_IMAGE="$TAA_IMAGE"
        ;;
      --image)
        shift
        if [[ $# -eq 0 || "$1" == -* ]]; then
          err "$arg requires an image name argument"
          usage >&2
          exit 1
        fi
        TAA_IMAGE="$1"
        TAA_IMAGE_WAS_SET="set"
        CUSTOM_SAVE_IMAGE="$TAA_IMAGE"
        ;;
      --base-archive=*|--base=*)
        CUSTOM_BASE_ARCHIVE="${arg#*=}"
        ;;
      --base-archive|--base)
        shift
        if [[ $# -eq 0 || "$1" == -* ]]; then
          err "$arg requires a base archive path argument"
          usage >&2
          exit 1
        fi
        CUSTOM_BASE_ARCHIVE="$1"
        ;;
      --save-config=*)
        CUSTOM_SAVE_CONFIG="${arg#*=}"
        ;;
      --save-config)
        shift
        if [[ $# -eq 0 || "$1" == -* ]]; then
          err "$arg requires a config path argument"
          usage >&2
          exit 1
        fi
        CUSTOM_SAVE_CONFIG="$1"
        ;;
      --remote-password=*)
        REMOTE_PASSWORD="${arg#*=}"
        ;;
      --remote-password)
        shift
        if [[ $# -eq 0 || "$1" == -* ]]; then
          err "$arg requires a password argument"
          usage >&2
          exit 1
        fi
        REMOTE_PASSWORD="$1"
        ;;
      --port=*)
        TAA_PORT="${arg#*=}"
        TAA_CONTAINER_ADDR=":${TAA_PORT}"
        ;;
      --port)
        shift
        if [[ $# -eq 0 || "$1" == -* ]]; then
          err "$arg requires a port argument"
          usage >&2
          exit 1
        fi
        TAA_PORT="$1"
        TAA_CONTAINER_ADDR=":${TAA_PORT}"
        ;;
      platform-mock)
        err "platform-mock is no longer deployed by this script; use ./deploy-platform-mock.sh start"
        exit 1
        ;;
      --model=*)
        CLI_MODEL="${arg#*=}"
        ;;
      --model)
        shift
        if [[ $# -eq 0 || "$1" == -* ]]; then
          err "--model requires a model name argument"
          usage >&2
          exit 1
        fi
        CLI_MODEL="$1"
        ;;
      -h|--help|help)
        usage
        exit 0
        ;;
      *)
        err "unknown argument: $arg"
        usage >&2
        exit 1
        ;;
    esac
    shift
  done

  ACTION="${ACTION:-create}"
fi

# TARGET_POD and TARGET_NAMESPACE in the environment were removed. Silently ignoring them would
# aim the run at a Pod or namespace the caller did not name, so refuse before anything touches the
# remote host.
if [[ -n "$TARGET_POD_ENV_WAS_SET" ]]; then
  err "TARGET_POD is no longer supported; pass --pod <name> instead"
  usage >&2
  exit 1
fi
if [[ -n "$TARGET_NAMESPACE_ENV_WAS_SET" ]]; then
  err "TARGET_NAMESPACE is no longer supported; pass --namespace <ns> instead"
  usage >&2
  exit 1
fi

# Resolve the effective Pod name. TAA is the only thing deployed here, so when --pod is absent the
# Pod this script owns and creates is the target.
if [[ -z "${TARGET_POD:-}" ]]; then
  TARGET_POD="$TAA_POD_NAME"
fi

# create and delete are the two actions that change which Pods exist, and both only ever act on the
# Pod this deployment owns. Naming a Pod with --pod says "use this one, do not touch its lifecycle",
# so the pairing is refused rather than resolved either way.
if [[ -n "$TARGET_POD_WAS_SET" ]]; then
  case "$ACTION" in
    create)
      err "create creates the Pod this deployment owns; it cannot be combined with --pod"
      detail "Drop --pod to create '$TAA_POD_NAME', or name an existing Pod and use update, start or stop."
      exit 1
      ;;
    delete)
      err "delete only removes the Pod this deployment created; '$TARGET_POD' was named with --pod"
      detail "An explicitly named Pod belongs to the operator. Delete it with kubectl if that is intended."
      exit 1
      ;;
  esac
fi

cd "$PROJECT_DIR"

wait_for_remote_taa_ready() {
  local wait_start_ts
  wait_start_ts=$(date +%s)
  local ready_attempts=$(( (TAA_READY_TIMEOUT + TAA_READY_INTERVAL - 1) / TAA_READY_INTERVAL ))
  local taa_ready=false
  cursor_hide
  local spin_len=${#SPIN_FRAMES[@]}
  local i=0
  for ((attempt=1; attempt<=ready_attempts; attempt++)); do
    # TCP inside the Pod's network namespace: its /v1/taa/health now requires an
    # SM2 envelope that a local probe cannot produce. The Pod netns is the
    # guest's, so 127.0.0.1 here is the daemon.
    #
    # bash, not sh: /dev/tcp is a bash feature, and the image's /bin/sh is dash,
    # where the redirection fails with "cannot open /dev/tcp/..." no matter what
    # is listening. deploy-taa-vm.sh carries the same probe and the same reason.
    if remote_ssh "$(container_exec) bash -c 'exec 3<>/dev/tcp/127.0.0.1/$TAA_PORT' >/dev/null 2>&1"; then
      taa_ready=true
      break
    fi
    if [[ "$IS_TTY" == true ]]; then
      local now
      now=$(date +%s)
      local elapsed=$((now - wait_start_ts))
      local frame="${SPIN_FRAMES[$i]}"
      printf "\r   ${CYAN}%s${NC} waiting for remote taa service to become ready ${DIM}(%ds / %ds)...${NC}" "$frame" "$elapsed" "$TAA_READY_TIMEOUT"
      i=$(( (i + 1) % spin_len ))
    fi
    sleep "$TAA_READY_INTERVAL"
  done
  cursor_show
  printf "\r\033[K"
  if [[ "$taa_ready" == true ]]; then
    local total_elapsed=$(( $(date +%s) - wait_start_ts ))
    info "remote taa ready: tcp 127.0.0.1:$TAA_PORT ${DIM}(took ${total_elapsed}s)${NC}"
    # A reachable port only proves a listener; the log line is what shows the
    # daemon that owns it finished loading its configuration.
    if ! confirm_taa_listening "remote_ssh \"\$(container_exec) sh -lc 'tail -n 200 $TAA_LOG_FILE'\""; then
      warn "remote taa port is open but the 'taa service listening on' line was not found in $TAA_LOG_FILE"
    fi
    return 0
  else
    err "remote taa did not become ready within ${TAA_READY_TIMEOUT}s"
    remote_ssh "$(container_exec) tail -n 50 $TAA_LOG_FILE || true"
    return 1
  fi
}

# start, stop, probe and update all act on a Pod that must already exist. None of them creates one:
# that is what create is for, and guessing would put a second confidential VM on the host.
require_remote_pod() {
  local want_ready="${1:-}"
  if ! remote_pod_exists; then
    err "TAA Pod '$TARGET_POD' does not exist in namespace '${TARGET_NAMESPACE:-default}'"
    detail "Create it first: $(basename "$0") create"
    exit 1
  fi
  # A wedged or restarting Pod turns into a clear error here rather than a misleading readiness
  # timeout after the binary has already been replaced.
  if [[ "$want_ready" == "ready" ]]; then
    if ! remote_ssh "kubectl $K_NS wait --for=condition=Ready --timeout=30s pod/'$TARGET_POD' >/dev/null 2>&1"; then
      err "TAA Pod '$TARGET_POD' exists but did not become Ready within 30s"
      remote_ssh "kubectl $K_NS describe pod '$TARGET_POD' | tail -n 20" || true
      detail "If it is wedged, replace it with: $(basename "$0") delete"
      exit 1
    fi
  fi
}

# Builds the local artifacts the image is assembled from, into the same paths save_local_docker_image
# uses. create needs a reference even when the Pod already exists and no image had to be built.
prepare_image_reference() {
  local template="${CUSTOM_SAVE_CONFIG:-$TAA_PRODUCTION_CONFIG_TEMPLATE}"
  require_file "production config template not found" "$template"
  ensure_go_compiler
  ensure_parent_dir "$TAA_BINARY_PATH"
  spin_task "building taa daemon from ./cmd/taa" env CGO_ENABLED=0 GOOS=linux go build -o "$TAA_BINARY_PATH" ./cmd/taa
  require_file "build failed: taa binary" "$TAA_BINARY_PATH"
  render_image_config "$LOCAL_RUN_DIR/export-production-taa-config.json" "$template"
}

# Streams a file out of the Pod and hashes it here, so the check does not depend on a hashing tool
# existing inside the guest image.
pod_file_sha256() {
  local path="$1"
  remote_ssh "$(container_exec) sh -lc \"cat '$path'\"" 2>/dev/null | sha256sum | awk '{print $1}' || true
}

VERIFY_FAILURES=()

verify_pod_file() {
  local label="$1" pod_path="$2"; shift 2
  local candidate want="" got
  if ! remote_ssh "$(container_exec) test -s '$pod_path'" >/dev/null 2>&1; then
    VERIFY_FAILURES+=("$label: not present in the Pod ($pod_path)")
    return 0
  fi
  got="$(pod_file_sha256 "$pod_path")"
  # Several references are accepted when a file has more than one legitimate rendering: the hash
  # only has to match one of them.
  for candidate in "$@"; do
    local candidate_sha
    candidate_sha="$(sha256sum "$candidate" | awk '{print $1}')"
    if [[ -z "$want" ]]; then
      want="$candidate_sha"
    fi
    if [[ "$candidate_sha" == "$got" ]]; then
      return 0
    fi
  done
  VERIFY_FAILURES+=("$label: the Pod carries ${got:0:12}, this tree built ${want:0:12} ($pod_path)")
}

# create opens the Pod and reports what is wrong inside it; it never repairs, because a defective
# image is a build problem and patching it here would make the next create look healthy while the
# image stayed wrong. Identity is not checked: it arrives as Pod environment variables by design.
verify_pod_contents() {
  step "verifying that Pod '$TARGET_POD' runs this tree's build"
  VERIFY_FAILURES=()

  if [[ -n "$TAA_IMAGE_WAS_SET" ]]; then
    # --image names a build made elsewhere; this tree has nothing to hold it against.
    info "--image was given, so only the presence of the payload is checked"
    local spec label path
    for spec in "taa binary:$TAA_WORKDIR/taa" "taa supervisor:$TAA_SUPERVISOR_CONTAINER" \
                "taa config:$CONTAINER_TAA_CONFIG_PATH" \
                "taa hrk cert:$CONTAINER_CERTS_DIR/hrk.cert" \
                "taa hsk_cek cert:$CONTAINER_CERTS_DIR/hsk_cek.cert"; do
      label="${spec%%:*}"; path="${spec#*:}"
      remote_ssh "$(container_exec) test -s '$path'" >/dev/null 2>&1 ||
        VERIFY_FAILURES+=("$label: not present in the Pod ($path)")
    done
  else
    prepare_image_reference
    # The Pod's config legitimately has two renderings: the one create baked in, and the one update
    # installs, which may carry an LLM endpoint taken from this deployment's environment.
    render_deploy_config "$LOCAL_RUN_DIR/deploy-taa-config.json"
    verify_pod_file "taa binary" "$TAA_WORKDIR/taa" "$TAA_BINARY_PATH"
    verify_pod_file "taa supervisor" "$TAA_SUPERVISOR_CONTAINER" "$TAA_SUPERVISOR_SOURCE"
    verify_pod_file "taa config" "$CONTAINER_TAA_CONFIG_PATH" \
      "$LOCAL_RUN_DIR/export-production-taa-config.json" "$LOCAL_RUN_DIR/deploy-taa-config.json"
    verify_pod_file "taa hrk cert" "$CONTAINER_CERTS_DIR/hrk.cert" "$DEPLOY_CERTS_DIR/hrk.cert"
    verify_pod_file "taa hsk_cek cert" "$CONTAINER_CERTS_DIR/hsk_cek.cert" "$DEPLOY_CERTS_DIR/hsk_cek.cert"
  fi

  # Presence, not a run: semgrep's own verification belongs to provisioning, where a failure can
  # still be repaired. Here a missing engine means the image was assembled wrong.
  #
  # A deployment that skipped provisioning on purpose (the data-analysis role, whose audit is off)
  # has no engine to find, so it is not checked against one: the template still selects semgrep,
  # but nothing was installed for it.
  local engine="" rules_path=""
  if [[ "$TAA_SCAN_ENGINE_PROVISION" != "skip" ]]; then
    read -r engine rules_path <<<"$(taa_scan_engine_requirements "${CUSTOM_SAVE_CONFIG:-$TAA_PRODUCTION_CONFIG_TEMPLATE}")"
  fi
  if [[ "$engine" == "semgrep" ]]; then
    remote_ssh "$(container_exec) sh -lc 'command -v semgrep >/dev/null 2>&1'" >/dev/null 2>&1 ||
      VERIFY_FAILURES+=("semgrep CLI: not installed in the Pod, so audits would fall back to regex")
    if [[ -n "$rules_path" ]]; then
      remote_ssh "$(container_exec) test -e '$rules_path'" >/dev/null 2>&1 ||
        VERIFY_FAILURES+=("semgrep rules: missing at $rules_path inside the Pod")
    fi
  fi

  if (( ${#VERIFY_FAILURES[@]} > 0 )); then
    err "Pod verification failed: '$TARGET_POD' is not running the build from this tree"
    local item
    for item in "${VERIFY_FAILURES[@]}"; do
      detail "  $item"
    done
    detail "Nothing was copied into the Pod: create verifies the image instead of patching it."
    detail "Run '$(basename "$0") delete' to remove it, then '$(basename "$0")' to rebuild and recreate."
    exit 1
  fi
  info "the Pod carries this tree's taa binary, supervisor and configuration"
}

if [[ "$ACTION" == "stop" ]]; then
  banner "Stopping Services"
  check_remote_connectivity
  require_remote_pod
  step "stopping taa inside Pod '$TARGET_POD'"
  pause_remote_taa || warn "could not signal taa inside Pod '$TARGET_POD' (it may not be running)"
  info "taa stopped; the Pod is left in place (use 'delete' to remove it)"
  exit 0
fi

if [[ "$ACTION" == "start" ]]; then
  banner "Starting Services"
  check_remote_connectivity
  require_remote_pod
  step "releasing the supervisor inside Pod '$TARGET_POD'"
  if ! remote_ssh "$(container_exec) sh -lc 'rm -f \"$TAA_WORKDIR/manual\"'"; then
    err "could not release the supervisor inside Pod '$TARGET_POD'"
    exit 1
  fi
  wait_for_remote_taa_ready || exit 1
  exit 0
fi

if [[ "$ACTION" == "probe" ]]; then
  banner "Probing TAA Service"
  check_remote_connectivity
  require_remote_pod
  wait_for_remote_taa_ready || exit 1
  exit 0
fi

if [[ "$ACTION" == "delete" ]]; then
  banner "Deleting the TAA Pod"
  check_remote_connectivity
  if ! remote_pod_exists; then
    info "TAA Pod '$TARGET_POD' does not exist; nothing to delete"
    exit 0
  fi
  # A wedged guest cannot be signalled; that must not block removing a Pod this deployment owns.
  pause_remote_taa || warn "could not signal taa inside Pod '$TARGET_POD' (it may not be running)"
  delete_taa_pod
  exit 0
fi

if [[ "$ACTION" == "save" ]]; then
  save_local_docker_image
  exit 0
fi

if [[ "$ACTION" == "create" ]]; then
  validate_pod_contract_type
  banner "Creating the TAA Pod" "Host: ${REMOTE_USER}@${REMOTE_HOST} | Pod: ${TARGET_POD}"
  check_remote_connectivity
  require_file "taa supervisor script missing" "$TAA_SUPERVISOR_SOURCE"
  step "checking remote target pod: ${TARGET_POD} (${TARGET_NAMESPACE:-default})"
  if remote_pod_exists; then
    # The guest's writable layer holds the SM2 key pair, the sealed state and the imported data, so
    # an existing Pod is kept and verified rather than replaced under the operator.
    info "TAA Pod '$TARGET_POD' already exists; verifying it instead of creating a second one"
    require_matching_role
  else
    create_taa_pod
  fi
  verify_pod_contents
  if [[ "${TAA_KEEP_MANUAL:-false}" == true ]]; then
    warn "TAA_KEEP_MANUAL is enabled; leaving taa paused"
  else
    step "starting taa inside Pod '$TARGET_POD'"
    remote_ssh "$(container_exec) sh -lc 'rm -f \"$TAA_WORKDIR/manual\"'"
    wait_for_remote_taa_ready || exit 1
    remote_ssh "$(container_exec) sh -lc 'tail -n 50 $TAA_LOG_FILE || true'"
  fi
  banner "Pod Created and Verified" "Pod: ${TARGET_POD} | Namespace: ${TARGET_NAMESPACE:-default}"
  echo -e "  ${BOLD}${CYAN}● TAA Secure Enclave Daemon${NC}  ${DIM}(In-Container Daemon)${NC}"
  echo -e "    ${MUTED}↳ Pod         :${NC} ${TARGET_POD} ${DIM}(${TARGET_NAMESPACE:-default})${NC}"
  echo -e "    ${MUTED}↳ Workdir     :${NC} ${TAA_WORKDIR}"
  echo -e "    ${MUTED}↳ Config      :${NC} ${CONTAINER_TAA_CONFIG_PATH}"
  echo -e "    ${MUTED}↳ Log file    :${NC} ${TAA_LOG_FILE}"
  echo -e "    ${MUTED}↳ Identity    :${NC} Pod environment (${REMOTE_PLATFORM_IP}, ${TAA_POD_DOCKER_ID:-$TARGET_POD})"
  echo ""
  exit 0
fi

# Everything below installs into an existing Pod. It never creates one: that is create's job, and a
# second confidential VM is not something to bring up as a side effect of a file copy.
CONTAINER_LABEL="${TARGET_POD}"
REMOTE_DOCKER_ID="${REMOTE_DOCKER_ID:-$CONTAINER_LABEL}"

DEPLOY_COMPONENTS="taa "
DEPLOY_TARGET_DESC="${REMOTE_USER}@${REMOTE_HOST}"
TARGET_MODEL="$(resolve_target_model)"
banner "Updating TAA in Pod ${TARGET_POD}" "Host: ${DEPLOY_TARGET_DESC} | Target model: ${TARGET_MODEL}"

if [[ "$DEPLOY_TAA" == true ]]; then
  ensure_go_compiler
  ensure_parent_dir "$TAA_BINARY_PATH"
  spin_task "building taa daemon from ./cmd/taa" env CGO_ENABLED=0 GOOS=linux go build -o "$TAA_BINARY_PATH" ./cmd/taa
fi

if [[ "$DEPLOY_TAA" == true ]]; then
  require_file "build verification failed (taa binary missing)" "$TAA_BINARY_PATH"
  require_file "taa supervisor script missing" "$TAA_SUPERVISOR_SOURCE"
fi

ensure_remote_ssh

step "checking remote host connectivity: ${REMOTE_USER}@${REMOTE_HOST}"
check_remote_connectivity

if [[ "$DEPLOY_TAA" == true ]]; then
  step "checking remote target pod: ${TARGET_POD} (${TARGET_NAMESPACE:-default})"
  require_remote_pod ready
fi

if [[ "$DEPLOY_TAA" == true ]]; then
  TAA_CONFIG_TEMPLATE="$TAA_PRODUCTION_CONFIG_TEMPLATE"
  step "writing remote taa config from $(basename "$TAA_CONFIG_TEMPLATE")"
  # storage.data stays as the template says (see save_local_docker_image).
  render_deploy_config "$REMOTE_TAA_CONFIG_SOURCE"

  step "uploading taa and config to remote host"
  require_file "vendor attestation certificate (hrk)" "$DEPLOY_CERTS_DIR/hrk.cert"
  require_file "vendor attestation certificate (hsk_cek)" "$DEPLOY_CERTS_DIR/hsk_cek.cert"
  sshpass -p "$REMOTE_PASSWORD" scp "${SSH_OPTS[@]}" "$TAA_BINARY_PATH" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/$BINARY_NAME.new"
  sshpass -p "$REMOTE_PASSWORD" scp "${SSH_OPTS[@]}" "$REMOTE_TAA_CONFIG_SOURCE" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_TAA_CONFIG_PATH.new"
  remote_ssh "mkdir -p '$REMOTE_DIR/certs'"
  sshpass -p "$REMOTE_PASSWORD" scp "${SSH_OPTS[@]}" "$DEPLOY_CERTS_DIR/hrk.cert" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/certs/hrk.cert"
  sshpass -p "$REMOTE_PASSWORD" scp "${SSH_OPTS[@]}" "$DEPLOY_CERTS_DIR/hsk_cek.cert" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/certs/hsk_cek.cert"

  step "replacing remote taa and config"
  remote_ssh "mv '$REMOTE_DIR/$BINARY_NAME.new' '$REMOTE_DIR/$BINARY_NAME' && mv '$REMOTE_TAA_CONFIG_PATH.new' '$REMOTE_TAA_CONFIG_PATH' && chmod +x '$REMOTE_DIR/$BINARY_NAME'"

  # Before the running taa is disturbed: failing here leaves the previous daemon serving instead
  # of replacing it with one whose configured engine silently degraded to regex.
  step "provisioning code scan engine inside container"
  provision_remote_scan_engine "$TAA_CONFIG_TEMPLATE"

  step "pausing old taa inside container for update"
  pause_remote_taa
  old_taa_alive=true
  for _ in {1..30}; do
    if ! remote_ssh "$(container_exec) sh -lc 'pgrep -x taa >/dev/null 2>&1'"; then
      old_taa_alive=false
      break
    fi
    sleep 1
  done
  if [[ "$old_taa_alive" == true ]]; then
    # Writing the new binary over a running one would leave the old image serving the port while
    # every later check -- port open, log line present -- still passes.
    err "the old taa inside '$TARGET_POD' is still running; refusing to replace its binary"
    detail "Inspect it with: kubectl $K_NS exec '$TARGET_POD' -- ps -ef | grep taa"
    exit 1
  fi

  step "copying runtime files into container"
  remote_ssh "$(container_exec) sh -lc 'mkdir -p $CONTAINER_CERTS_DIR'"
  remote_ssh "$(container_cp "$REMOTE_DIR/$BINARY_NAME" "$TAA_WORKDIR/$BINARY_NAME")"
  remote_ssh "$(container_cp "$REMOTE_TAA_CONFIG_PATH" "$CONTAINER_TAA_CONFIG_PATH")"
  remote_ssh "$(container_cp "$REMOTE_DIR/certs/hrk.cert" "$CONTAINER_CERTS_DIR/hrk.cert")"
  remote_ssh "$(container_cp "$REMOTE_DIR/certs/hsk_cek.cert" "$CONTAINER_CERTS_DIR/hsk_cek.cert")"
  remote_ssh "$(container_exec) sh -lc 'chmod +x $TAA_WORKDIR/$BINARY_NAME'"

  step "verifying copied files inside container"
  remote_ssh "$(container_exec) sh -lc 'ls -l $TAA_WORKDIR/$BINARY_NAME $CONTAINER_TAA_CONFIG_PATH 2>/dev/null'"

  step "checking attestation prerequisites inside container"
  if ! remote_ssh "$(container_exec) sh -lc 'test -e /dev/csv-guest'" 2>/dev/null; then
    warn "/dev/csv-guest not found in container — attestation will fail (expected in non-TEE Docker)"
  fi

  step "checking production identity env inside container"
  remote_ssh "$(container_exec) sh -lc 'test -n "\${PLATFORM_IP:-}" && test -n "\${DOCKER_ID:-}" || { echo PLATFORM_IP and DOCKER_ID must be injected in production mode; exit 1; }'"

  if [[ "${TAA_KEEP_MANUAL:-false}" == true ]]; then
    warn "TAA_KEEP_MANUAL is enabled; leaving taa manual mode paused"
  else
    step "restoring taa service inside container"
    remote_ssh "$(container_exec) sh -lc 'rm -f "$TAA_WORKDIR/manual"'"
  fi

  if [[ "${TAA_KEEP_MANUAL:-false}" == false ]]; then
    step "waiting for taa service to become ready"
    wait_for_remote_taa_ready
  fi

  remote_ssh "$(container_exec) sh -lc 'tail -n 50 $TAA_LOG_FILE || true'"
fi

banner "Update Complete" "Pod '${TARGET_POD}' runs the build from this tree"
if [[ "$DEPLOY_TAA" == true ]]; then
  echo -e "  ${BOLD}${CYAN}● TAA Secure Enclave Daemon${NC}  ${DIM}(In-Container Daemon)${NC}"
  echo -e "    ${MUTED}↳ Container  :${NC} ${CONTAINER_LABEL}:${TAA_WORKDIR} (addr ${TAA_CONTAINER_ADDR})"
  echo -e "    ${MUTED}↳ Remote Bin :${NC} ${REMOTE_HOST}:${REMOTE_DIR}/${BINARY_NAME}"
  echo -e "    ${MUTED}↳ Config     :${NC} ${CONTAINER_TAA_CONFIG_PATH}"
  echo -e "    ${MUTED}↳ Log file   :${NC} ${TAA_LOG_FILE}"
  echo -e "    ${MUTED}↳ Platform   :${NC} ${REMOTE_PLATFORM_IP}"
  echo -e "    ${MUTED}↳ Attestation:${NC} ${ATT_REPORT_FILE}"
  echo ""
fi
