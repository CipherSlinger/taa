#!/usr/bin/env bash
set -euo pipefail

DEBUG=${DEBUG:-false} # 调试模式，使用 platform-mock 测试，与正式目录不同，避免污染正式环境

# ── ANSI Colors ─────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m' # No Color

# Kubernetes 目标：默认部署到 osr 命名空间下的指定 TAA Pod。
TARGET_NAMESPACE="${TARGET_NAMESPACE:-osr}"
TARGET_POD="${TARGET_POD:-taa-env-slim-v2-1-0062040056ca0130-8695d7b6cf-sdl5m}"

# 项目与远程宿主机：本地源码目录、SSH 登录信息和远程工作目录。
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REMOTE_USER="${REMOTE_USER:-root}"
REMOTE_HOST="${REMOTE_HOST:-172.16.10.178}"
REMOTE_DIR="${REMOTE_DIR:-/root/taa}"

# Platform: 平台的监听端口
if [[ ${DEBUG} == false ]]; then
  # Platform：远程平台模拟器的监听端口、绑定地址，以及 TAA 容器访问平台的地址。
  PLATFORM_PORT="${PLATFORM_PORT:-18080}"
else
  # Platform Mock：远程平台模拟器的监听端口、绑定地址，以及 TAA 容器访问平台的地址。
  PLATFORM_PORT="${PLATFORM_PORT:-28080}"
fi
PLATFORM_ADDR="${PLATFORM_ADDR:-0.0.0.0:${PLATFORM_PORT}}"
REMOTE_PLATFORM_IP="${REMOTE_PLATFORM_IP:-${REMOTE_HOST}:${PLATFORM_PORT}}"

# 本地构建产物：TAA、Platform Mock 与 attestation helper 的二进制文件名和本地路径。
BINARY_NAME="${BINARY_NAME:-taa}"
TAA_BINARY_PATH="${TAA_BINARY_PATH:-$PROJECT_DIR/bin/$BINARY_NAME}"
MOCK_BINARY_NAME="${MOCK_BINARY_NAME:-platform-mock}"
MOCK_BINARY_PATH="${MOCK_BINARY_PATH:-$PROJECT_DIR/bin/$MOCK_BINARY_NAME}"

# 远程证明文件：attestation helper、HRK 证书、HSK/CEK 证书的本地源路径。
ATT_DIR="${ATT_DIR:-$PROJECT_DIR/attestation}"
ATT_HELPER_SOURCE="${ATT_HELPER_SOURCE:-$PROJECT_DIR/bin/get-attestation}"
ATT_HRK_SOURCE="${ATT_HRK_SOURCE:-$ATT_DIR/hrk.cert}"
ATT_HSK_SOURCE="${ATT_HSK_SOURCE:-$ATT_DIR/hsk_cek.cert}"

# 远程容器目录：TAA 容器内的工作目录、attestation helper 和证书路径，以及 attestation report 文件路径。
if [[ ${DEBUG} == false ]]; then
  CON_WORKDIR="${CON_WORKDIR:-/root/taa}"
  CON_PORT=6001
else
  CON_WORKDIR="${CON_WORKDIR:-/root/taadebug}"
  CON_PORT=9001
fi
ATT_REPORT_FILE="${CON_WORKDIR}/attestation.report"
K_NS="${TARGET_NAMESPACE:+-n $TARGET_NAMESPACE}"

# Docker 部署模式：设为 "docker" 时通过 docker exec/cp 操作容器而非 kubectl。
DEPLOY_MODE="${DEPLOY_MODE:-k8s}"
TARGET_CONTAINER="${TARGET_CONTAINER:-brave_shockley}"
# TAA 容器运行参数：容器内工作目录、监听地址、注册用容器标识和日志路径。
TAA_CONTAINER_WORKDIR="${TAA_CONTAINER_WORKDIR:-${CON_WORKDIR}}"
TAA_CONTAINER_ADDR="${TAA_CONTAINER_ADDR:-:${CON_PORT}}"
TAA_LOG_FILE="${TAA_LOG_FILE:-/tmp/taa.log}"
# Ollama / Qwen：本地离线包、远程缓存目录、容器内目录、服务监听和模型配置。
OLLAMA_LOCAL_DIR="${OLLAMA_LOCAL_DIR:-$PROJECT_DIR/models/audit/ollama-qwen2.5-coder-0.5b}"
OLLAMA_DIR_NAME="${OLLAMA_DIR_NAME:-$(basename "$OLLAMA_LOCAL_DIR")}"
REMOTE_OLLAMA_DIR="${REMOTE_OLLAMA_DIR:-$REMOTE_DIR/$OLLAMA_DIR_NAME}"
CONTAINER_OLLAMA_DIR="${CONTAINER_OLLAMA_DIR:-$TAA_CONTAINER_WORKDIR/$OLLAMA_DIR_NAME}"
OLLAMA_HOST="${OLLAMA_HOST:-127.0.0.1:11434}"
OLLAMA_MODEL="${OLLAMA_MODEL:-qwen2.5-coder:0.5b}"
OLLAMA_LOG_FILE="${OLLAMA_LOG_FILE:-/tmp/ollama.log}"
OLLAMA_READY_TIMEOUT="${OLLAMA_READY_TIMEOUT:-120}"
OLLAMA_READY_INTERVAL="${OLLAMA_READY_INTERVAL:-2}"

# 远程 SSH 密码：通过 TARGET_PASSWORD 覆盖；置空时启动脚本会交互式询问。
PASSWORD="${TARGET_PASSWORD:-Osrd@2026}"

DEPLOY_LOCAL=false
DEPLOY_PLATFORM_MOCK=false
DEPLOY_TAA=false
DEPLOY_QWEN=false
DOCKER_ARG=false
SELECTED_COMPONENT=false
STEP=0

LOCAL_PLATFORM_STATE_DIR="${LOCAL_PLATFORM_STATE_DIR:-$PROJECT_DIR/.local/platform-mock}"
LOCAL_PLATFORM_PORT="${LOCAL_PLATFORM_PORT:-18080}"
LOCAL_PLATFORM_BIND="${LOCAL_PLATFORM_BIND:-0.0.0.0:${LOCAL_PLATFORM_PORT}}"
LOCAL_PLATFORM_IP="${LOCAL_PLATFORM_IP:-127.0.0.1:${LOCAL_PLATFORM_PORT}}"
LOCAL_PLATFORM_URL="${LOCAL_PLATFORM_URL:-http://127.0.0.1:${LOCAL_PLATFORM_PORT}}"
LOCAL_RUNTIME_DIR="${LOCAL_RUNTIME_DIR:-$PROJECT_DIR/.local/taa}"
LOCAL_RUN_DIR="${LOCAL_RUN_DIR:-$PROJECT_DIR/.local/run}"
LOCAL_TAA_MODEL_DIR="${LOCAL_TAA_MODEL_DIR:-$LOCAL_RUNTIME_DIR/models}"
LOCAL_TAA_DATA_DIR="${LOCAL_TAA_DATA_DIR:-$LOCAL_RUNTIME_DIR/data}"
LOCAL_TAA_RESULT_DIR="${LOCAL_TAA_RESULT_DIR:-$LOCAL_RUNTIME_DIR/results}"
LOCAL_TAA_PORT="${LOCAL_TAA_PORT:-6001}"
LOCAL_TAA_URL="${LOCAL_TAA_URL:-http://127.0.0.1:${LOCAL_TAA_PORT}}"
LOCAL_TAA_BIND="${LOCAL_TAA_BIND:-:${LOCAL_TAA_PORT}}"
LOCAL_PLATFORM_LOG_FILE="${LOCAL_PLATFORM_LOG_FILE:-$PROJECT_DIR/.local/logs/platform-mock.log}"
LOCAL_TAA_LOG_FILE="${LOCAL_TAA_LOG_FILE:-$PROJECT_DIR/.local/logs/taa.log}"
LOCAL_OLLAMA_LOG_FILE="${LOCAL_OLLAMA_LOG_FILE:-$PROJECT_DIR/.local/logs/ollama.log}"
LOCAL_OLLAMA_URL="${LOCAL_OLLAMA_URL:-http://${OLLAMA_HOST}}"
LOCAL_DOCKER_ID="${LOCAL_DOCKER_ID:-127.0.0.1}"

banner() {
  echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${BOLD}${CYAN}  $1${NC}"
  echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

step() {
  STEP=$((STEP + 1))
  echo -e "${DIM}──${NC} ${BOLD}${BLUE}[$STEP]${NC} ${BOLD}$1${NC}"
}

info()    { echo -e "   ${GREEN}✓${NC} $1"; }
warn()    { echo -e "   ${YELLOW}⚠${NC} $1"; }
err()     { echo -e "   ${RED}✗${NC} $1" >&2; }

# ── Container helpers (docker / k8s) ───────────────────────
# 在容器内执行命令（通过 remote_ssh 在远程宿主机上操作）。
container_exec() {
  if [[ "$DEPLOY_MODE" == "docker" ]]; then
    echo "docker exec -i '$TARGET_CONTAINER'"
  else
    echo "kubectl $K_NS exec '$TARGET_POD' --"
  fi
}

# 从远程宿主机复制文件到容器内。
container_cp() {
  if [[ "$DEPLOY_MODE" == "docker" ]]; then
    echo "docker cp '$1' '$TARGET_CONTAINER':'$2'"
  else
    echo "kubectl $K_NS cp '$1' '$TARGET_POD':'$2'"
  fi
}

usage() {
  cat <<EOF
Usage: $(basename "$0") [docker] [local] [platform-mock] [taa] [qwen]

Without arguments, all three components are deployed remotely.
Pass docker to switch deploy mode to Docker; pass local to start the
full stack on the local machine. When no component names are given,
taa and qwen are deployed into the target container by default.
Provide one or more names to deploy them separately.
Examples:
  $(basename "$0") docker
  $(basename "$0") docker taa qwen
  $(basename "$0") local
  $(basename "$0") platform-mock
  $(basename "$0") taa
  $(basename "$0") qwen
  $(basename "$0") platform-mock taa
  $(basename "$0") platform-mock taa qwen

Environment overrides:
  # Deploy mode
  DEPLOY_MODE=${DEPLOY_MODE}
      部署模式：k8s（通过 kubectl 操作 Pod）或 docker（通过 docker 操作容器）。
  TARGET_CONTAINER=${TARGET_CONTAINER}
      Docker 模式下的目标容器名称。

  # Kubernetes / Pod (DEPLOY_MODE=k8s)
  TARGET_POD=${TARGET_POD}
      目标 TAA Pod 名称。
  TARGET_NAMESPACE=${TARGET_NAMESPACE}
      Kubernetes 命名空间；置空时使用当前/默认命名空间。

  # Remote host / SSH
  REMOTE_USER=${REMOTE_USER}
      远程宿主机 SSH 登录用户名。
  REMOTE_HOST=${REMOTE_HOST}
      远程宿主机 IP 或主机名。
  REMOTE_DIR=${REMOTE_DIR}
      远程宿主机上的部署工作目录。
  TARGET_PASSWORD=<password>
      SSH 密码覆盖项；置空时脚本会交互式询问。

  # Platform Mock
  PLATFORM_PORT=${PLATFORM_PORT}
      Platform Mock 监听端口。
  PLATFORM_ADDR=${PLATFORM_ADDR}
      Platform Mock 绑定地址。
  REMOTE_PLATFORM_IP=${REMOTE_PLATFORM_IP}
      TAA 容器访问 Platform Mock 使用的地址。
  MOCK_BINARY_PATH=${MOCK_BINARY_PATH}
      本地 Platform Mock 二进制文件路径。

  # TAA service / attestation
  BINARY_NAME=${BINARY_NAME}
      TAA 二进制文件名。
  TAA_BINARY_PATH=${TAA_BINARY_PATH}
      本地 TAA 二进制文件路径。
  TAA_CONTAINER_WORKDIR=${TAA_CONTAINER_WORKDIR}
      TAA 在目标容器内的工作目录。
  TAA_CONTAINER_ADDR=${TAA_CONTAINER_ADDR}
      TAA 服务在容器内监听的地址与端口。
  ATT_DIR=${ATT_DIR}
      本地 attestation helper 和证书目录。

  # Ollama / Qwen
  OLLAMA_LOCAL_DIR=${OLLAMA_LOCAL_DIR}
      本地 Ollama / Qwen 离线包目录。
  OLLAMA_HOST=${OLLAMA_HOST}
      Ollama 在容器内监听的地址与端口。
  OLLAMA_MODEL=${OLLAMA_MODEL}
      启动检查使用的 Qwen 模型名称。
  OLLAMA_READY_TIMEOUT=${OLLAMA_READY_TIMEOUT}
      等待 Ollama 就绪的最长时间（秒）。
  OLLAMA_READY_INTERVAL=${OLLAMA_READY_INTERVAL}
      Ollama 就绪检测轮询间隔（秒）。
EOF
}

ensure_parent_dir() {
  mkdir -p "$(dirname "$1")"
}

stop_pidfile() {
  local name="$1"
  local pidfile="$2"
  if [[ -f "$pidfile" ]]; then
    local pid
    pid=$(<"$pidfile")
    if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
      warn "stopping old $name (pid $pid)"
      kill "$pid" 2>/dev/null || true
      for _ in {1..50}; do
        if ! kill -0 "$pid" 2>/dev/null; then
          break
        fi
        sleep 0.1
      done
      kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$pidfile"
  fi
}

start_local_background() {
  local name="$1"
  local pidfile="$2"
  local logfile="$3"
  shift 3

  ensure_parent_dir "$pidfile"
  ensure_parent_dir "$logfile"
  stop_pidfile "$name" "$pidfile"

  nohup "$@" >"$logfile" 2>&1 < /dev/null &
  local pid=$!
  echo "$pid" >"$pidfile"
  info "started $name (pid $pid)"
}

http_probe() {
  local method="$1"
  local url="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsS -X "$method" "$url" >/dev/null
    return $?
  fi
  if command -v wget >/dev/null 2>&1; then
    if [[ "$method" == "POST" ]]; then
      wget -q -O - --method=POST --body-data='' "$url" >/dev/null
    else
      wget -q -O - "$url" >/dev/null
    fi
    return $?
  fi
  return 127
}

wait_for_http_ready() {
  local label="$1"
  local method="$2"
  local url="$3"
  local timeout_seconds="$4"
  local interval_seconds="$5"
  local logfile="${6:-}"
  local attempts=$(( (timeout_seconds + interval_seconds - 1) / interval_seconds ))

  for ((i = 1; i <= attempts; i++)); do
    if http_probe "$method" "$url"; then
      info "$label ready: $url"
      return 0
    fi
    sleep "$interval_seconds"
  done

  err "$label did not become ready within ${timeout_seconds}s: $url"
  if [[ -n "$logfile" && -f "$logfile" ]]; then
    echo -e "   ${YELLOW}↳${NC} ${label} log:"
    tail -n 60 "$logfile" || true
  fi
  return 1
}

require_file() {
  local label="$1"
  local path="$2"
  [[ -f "$path" ]] || { err "$label: $path"; exit 1; }
}

require_dir() {
  local label="$1"
  local path="$2"
  [[ -d "$path" ]] || { err "$label: $path"; exit 1; }
}

if [[ $# -eq 0 ]]; then
  DEPLOY_PLATFORM_MOCK=true
  DEPLOY_TAA=true
  DEPLOY_QWEN=true
else
  for arg in "$@"; do
    case "$arg" in
      docker)
        DEPLOY_MODE="docker"
        DOCKER_ARG=true
        ;;
      local)
        DEPLOY_LOCAL=true
        DEPLOY_PLATFORM_MOCK=true
        DEPLOY_TAA=true
        DEPLOY_QWEN=true
        SELECTED_COMPONENT=true
        ;;
      platform-mock)
        DEPLOY_PLATFORM_MOCK=true
        SELECTED_COMPONENT=true
        ;;
      taa)
        DEPLOY_TAA=true
        SELECTED_COMPONENT=true
        ;;
      qwen)
        DEPLOY_QWEN=true
        SELECTED_COMPONENT=true
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        err "unknown argument: $arg"
        usage >&2
        exit 1
        ;;
    esac
  done

  if [[ "$SELECTED_COMPONENT" == false ]]; then
    if [[ "$DOCKER_ARG" == true ]]; then
      DEPLOY_TAA=true
      DEPLOY_QWEN=true
    else
      DEPLOY_PLATFORM_MOCK=true
      DEPLOY_TAA=true
      DEPLOY_QWEN=true
    fi
  fi
fi

cd "$PROJECT_DIR"

# 用户可见的平台标签：DEBUG 模式显示 "platform-mock"，生产模式显示 "platform"
PLATFORM_LABEL="platform"
if [[ "$DEBUG" == true || "$DEPLOY_LOCAL" == true ]]; then
  PLATFORM_LABEL="platform-mock"
fi

# 容器标识显示名：docker 模式显示容器名，k8s 模式显示 Pod 名。
if [[ "$DEPLOY_MODE" == "docker" ]]; then
  CONTAINER_LABEL="${TARGET_CONTAINER}"
else
  CONTAINER_LABEL="${TARGET_POD}"
fi

DEPLOY_COMPONENTS=""
[[ "$DEPLOY_PLATFORM_MOCK" == true ]] && DEPLOY_COMPONENTS+="$PLATFORM_LABEL "
[[ "$DEPLOY_TAA" == true ]] && DEPLOY_COMPONENTS+="taa "
[[ "$DEPLOY_QWEN" == true ]] && DEPLOY_COMPONENTS+="qwen "
DEPLOY_TARGET_DESC="${REMOTE_USER}@${REMOTE_HOST}"
[[ "$DEPLOY_LOCAL" == true ]] && DEPLOY_TARGET_DESC="local machine"
banner "Deploying: ${DEPLOY_COMPONENTS}→ ${DEPLOY_TARGET_DESC}"

if [[ "$DEPLOY_PLATFORM_MOCK" == true ]]; then
  make MOCK_BINARY="$MOCK_BINARY_PATH" platform-mock-build
fi
if [[ "$DEPLOY_TAA" == true ]]; then
  make TAA_BINARY="$TAA_BINARY_PATH" taa
  make attestation-ioctl
fi

if [[ "$DEPLOY_PLATFORM_MOCK" == true && ! -f "$MOCK_BINARY_PATH" ]]; then
  err "build failed: $MOCK_BINARY_PATH not found"
  exit 1
fi
if [[ "$DEPLOY_TAA" == true ]]; then
  require_file "build failed" "$TAA_BINARY_PATH"
  require_file "build failed" "$ATT_HELPER_SOURCE"
  require_file "build failed" "$ATT_HRK_SOURCE"
  require_file "build failed" "$ATT_HSK_SOURCE"
fi

if [[ "$DEPLOY_QWEN" == true ]]; then
  require_dir "ollama package not found" "$OLLAMA_LOCAL_DIR"
  require_file "ollama package is incomplete" "$OLLAMA_LOCAL_DIR/ollama"
  require_file "ollama package is incomplete" "$OLLAMA_LOCAL_DIR/start-ollama.sh"
  require_dir "ollama package is incomplete" "$OLLAMA_LOCAL_DIR/models/models"
  require_dir "ollama package is incomplete" "$OLLAMA_LOCAL_DIR/lib/ollama"
  info "ollama package: $(du -sh "$OLLAMA_LOCAL_DIR" | awk '{print $1}') at $OLLAMA_LOCAL_DIR"
fi

if [[ "$DEPLOY_LOCAL" == true ]]; then
  step "preparing local runtime directories"
  mkdir -p "$LOCAL_PLATFORM_STATE_DIR" "$LOCAL_RUNTIME_DIR/attestation" "$LOCAL_TAA_MODEL_DIR" "$LOCAL_TAA_DATA_DIR" "$LOCAL_TAA_RESULT_DIR"
  cp "$ATT_HELPER_SOURCE" "$LOCAL_RUNTIME_DIR/attestation/get-attestation"
  cp "$ATT_HRK_SOURCE" "$LOCAL_RUNTIME_DIR/hrk.cert"
  cp "$ATT_HSK_SOURCE" "$LOCAL_RUNTIME_DIR/hsk_cek.cert"
  chmod +x "$LOCAL_RUNTIME_DIR/attestation/get-attestation"

  step "starting local platform-mock on ${LOCAL_PLATFORM_BIND}"
  start_local_background "platform-mock" "$LOCAL_RUN_DIR/platform-mock.pid" "$LOCAL_PLATFORM_LOG_FILE" \
    "$MOCK_BINARY_PATH" -addr "$LOCAL_PLATFORM_BIND" -state-dir "$LOCAL_PLATFORM_STATE_DIR" -taa-target "$LOCAL_TAA_URL" -allow-empty-attestation
  wait_for_http_ready "platform-mock" GET "$LOCAL_PLATFORM_URL/api/register/status" "$OLLAMA_READY_TIMEOUT" "$OLLAMA_READY_INTERVAL" "$LOCAL_PLATFORM_LOG_FILE"

  step "starting local ollama"
  start_local_background "ollama" "$LOCAL_RUN_DIR/ollama.pid" "$LOCAL_OLLAMA_LOG_FILE" \
    sh -lc "cd '$OLLAMA_LOCAL_DIR' && exec env OLLAMA_HOST='$OLLAMA_HOST' OLLAMA_MODELS='$OLLAMA_LOCAL_DIR/models/models' OLLAMA_LIBRARY_PATH='$OLLAMA_LOCAL_DIR/lib/ollama' ./start-ollama.sh"
  wait_for_http_ready "ollama" GET "$LOCAL_OLLAMA_URL/api/tags" "$OLLAMA_READY_TIMEOUT" "$OLLAMA_READY_INTERVAL" "$LOCAL_OLLAMA_LOG_FILE"

  step "starting local taa"
  start_local_background "taa" "$LOCAL_RUN_DIR/taa.pid" "$LOCAL_TAA_LOG_FILE" \
    sh -lc "cd '$LOCAL_RUNTIME_DIR' && exec env PLATFORM_IP='$LOCAL_PLATFORM_IP' DOCKER_ID='$LOCAL_DOCKER_ID' OLLAMA_DIR='$OLLAMA_LOCAL_DIR' SECURITY_LLM_ENDPOINT='$LOCAL_OLLAMA_URL' SECURITY_LLM_MODEL='$OLLAMA_MODEL' MODEL_DIR='$LOCAL_TAA_MODEL_DIR' DATA_DIR='$LOCAL_TAA_DATA_DIR' RESULT_DIR='$LOCAL_TAA_RESULT_DIR' '$TAA_BINARY_PATH' -addr '$LOCAL_TAA_BIND'"
  wait_for_http_ready "taa" POST "$LOCAL_TAA_URL/v1/taa/health" "$OLLAMA_READY_TIMEOUT" "$OLLAMA_READY_INTERVAL" "$LOCAL_TAA_LOG_FILE"

  echo ""
  banner "Deploy Complete"
  info "${BOLD}platform-mock${NC} → ${LOCAL_PLATFORM_URL}"
  echo -e "     ${DIM}state:${NC} ${LOCAL_PLATFORM_STATE_DIR}"
  echo -e "     ${DIM}log:${NC}   ${LOCAL_PLATFORM_LOG_FILE}"
  info "${BOLD}taa${NC} → ${LOCAL_TAA_URL}"
  echo -e "     ${DIM}cwd:${NC}   ${LOCAL_RUNTIME_DIR}"
  echo -e "     ${DIM}log:${NC}   ${LOCAL_TAA_LOG_FILE}"
  echo -e "     ${DIM}model:${NC} ${LOCAL_TAA_MODEL_DIR}"
  echo -e "     ${DIM}data:${NC}  ${LOCAL_TAA_DATA_DIR}"
  echo -e "     ${DIM}result:${NC} ${LOCAL_TAA_RESULT_DIR}"
  info "${BOLD}ollama${NC} → ${LOCAL_OLLAMA_URL}"
  echo -e "     ${DIM}log:${NC}   ${LOCAL_OLLAMA_LOG_FILE}"
  echo -e "     ${DIM}model:${NC} ${OLLAMA_LOCAL_DIR}"
  echo ""
  exit 0
fi

if [[ -z "$PASSWORD" ]]; then
  read -rsp "Password for ${REMOTE_USER}@${REMOTE_HOST}: " PASSWORD
  echo
fi

if ! command -v sshpass >/dev/null 2>&1; then
  err "sshpass is required for password-based copy. Install it or set up SSH keys."
  exit 1
fi

SSH_OPTS=(
  -q
  -o LogLevel=ERROR
  -o StrictHostKeyChecking=accept-new
  -o UserKnownHostsFile="$HOME/.ssh/known_hosts"
)

remote_ssh() {
  sshpass -p "$PASSWORD" ssh "${SSH_OPTS[@]}" "${REMOTE_USER}@${REMOTE_HOST}" "$@"
}

sync_ollama_to_remote() {
  step "syncing ollama package to remote host"
  remote_ssh "mkdir -p '$REMOTE_OLLAMA_DIR'"

  if command -v rsync >/dev/null 2>&1 && remote_ssh "command -v rsync >/dev/null 2>&1"; then
    sshpass -p "$PASSWORD" rsync -a --delete --partial --info=progress2 \
      -e "ssh -q -o LogLevel=ERROR -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$HOME/.ssh/known_hosts" \
      "$OLLAMA_LOCAL_DIR/" \
      "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_OLLAMA_DIR/"
  else
    warn "rsync not available; falling back to scp -r (full 4GB+ upload)"
    remote_ssh "rm -rf '$REMOTE_OLLAMA_DIR.new' && mkdir -p '$REMOTE_DIR'"
    sshpass -p "$PASSWORD" scp -r "${SSH_OPTS[@]}" "$OLLAMA_LOCAL_DIR" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_OLLAMA_DIR.new"
    remote_ssh "rm -rf '$REMOTE_OLLAMA_DIR' && mv '$REMOTE_OLLAMA_DIR.new' '$REMOTE_OLLAMA_DIR'"
  fi

  remote_ssh "test -f '$REMOTE_OLLAMA_DIR/ollama' && test -f '$REMOTE_OLLAMA_DIR/start-ollama.sh' && test -d '$REMOTE_OLLAMA_DIR/models/models' && test -d '$REMOTE_OLLAMA_DIR/lib/ollama'"
}

copy_ollama_to_container() {
  step "copying ollama package into container"
  remote_ssh "$(container_exec) sh -lc 'command -v tar >/dev/null 2>&1 || { echo kubectl cp requires tar inside the container; exit 1; }'"
  remote_ssh "$(container_exec) sh -lc 'rm -rf '$CONTAINER_OLLAMA_DIR' && mkdir -p '$TAA_CONTAINER_WORKDIR''"

  local pkg_size
  pkg_size=$(du -sh "$REMOTE_OLLAMA_DIR" 2>/dev/null | cut -f1 || echo "unknown")
  info "transferring $pkg_size from $REMOTE_OLLAMA_DIR to $CONTAINER_LABEL:$CONTAINER_OLLAMA_DIR"

  # Show progress while container cp runs
  local spin='-\|/'
  local i=0
  remote_ssh "$(container_cp "$REMOTE_OLLAMA_DIR" "$CONTAINER_OLLAMA_DIR")" &
  local cp_pid=$!

  while kill -0 "$cp_pid" 2>/dev/null; do
    printf "\r   ${GREEN}✓${NC} transferring... %s" "${spin:i++%${#spin}:1}"
    sleep 0.2
  done
  printf "\r   ${GREEN}✓${NC} transfer complete, setting permissions\n"

  wait "$cp_pid" || { err "container cp failed"; return 1; }

  remote_ssh "$(container_exec) sh -lc 'chmod +x '$CONTAINER_OLLAMA_DIR/ollama' '$CONTAINER_OLLAMA_DIR/start-ollama.sh' && test -x '$CONTAINER_OLLAMA_DIR/ollama' && test -f '$CONTAINER_OLLAMA_DIR/start-ollama.sh' && test -d '$CONTAINER_OLLAMA_DIR/models/models' && test -d '$CONTAINER_OLLAMA_DIR/lib/ollama''"

  # Create symlink for hardcoded dynamic linker path
  # The ollama binary expects /taatest/ollama-qwen2.5-coder-0.5b/lib/glibc/ld-linux-x86-64.so.2
  local hardcoded_path="/taatest/ollama-qwen2.5-coder-0.5b"
  if [[ "$CONTAINER_OLLAMA_DIR" != "$hardcoded_path" ]]; then
    step "creating symlink for dynamic linker compatibility"
    remote_ssh "$(container_exec) sh -lc 'mkdir -p /taatest && rm -rf $hardcoded_path && ln -s '$CONTAINER_OLLAMA_DIR' $hardcoded_path'"
  fi
}

start_ollama_and_wait() {
  step "starting ollama inside container"
  remote_ssh "$(container_exec) sh -lc 'cd '$CONTAINER_OLLAMA_DIR' && OLLAMA_HOST='$OLLAMA_HOST' nohup ./start-ollama.sh > '$OLLAMA_LOG_FILE' 2>&1 < /dev/null & sleep 1; tail -n 30 '$OLLAMA_LOG_FILE' || true'"

  step "waiting for ollama to become ready"
  local ready_attempts=$(( (OLLAMA_READY_TIMEOUT + OLLAMA_READY_INTERVAL - 1) / OLLAMA_READY_INTERVAL ))
  remote_ssh "$(container_exec) sh -lc '
    i=0
    max=$ready_attempts
    while [ \"\$i\" -lt \"\$max\" ]; do
      if command -v curl >/dev/null 2>&1; then
        curl -fsS http://$OLLAMA_HOST/api/tags >/dev/null && '$CONTAINER_OLLAMA_DIR/ollama' list | grep -q '$OLLAMA_MODEL' && exit 0
      elif command -v wget >/dev/null 2>&1; then
        wget -q -O - http://$OLLAMA_HOST/api/tags >/dev/null && '$CONTAINER_OLLAMA_DIR/ollama' list | grep -q '$OLLAMA_MODEL' && exit 0
      else
        '$CONTAINER_OLLAMA_DIR/ollama' list 2>/dev/null | grep -q '$OLLAMA_MODEL' && exit 0
      fi
      i=\$((i + 1))
      sleep '$OLLAMA_READY_INTERVAL'
    done
    echo ollama did not become ready within '$OLLAMA_READY_TIMEOUT' seconds
    echo --- ollama log ---
    tail -n 100 '$OLLAMA_LOG_FILE' || true
    echo --- processes ---
    ps || true
    echo --- ports ---
    ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null || netstat -ltn 2>/dev/null || true
    echo --- ollama files ---
    ls -l '$CONTAINER_OLLAMA_DIR' || true
    ls -ld '$CONTAINER_OLLAMA_DIR/models/models' '$CONTAINER_OLLAMA_DIR/lib/ollama' || true
    ldd '$CONTAINER_OLLAMA_DIR/ollama' 2>/dev/null || true
    exit 1
  '"
  remote_ssh "$(container_exec) sh -lc '$CONTAINER_OLLAMA_DIR/ollama list || true'"
}

if [[ "$DEPLOY_PLATFORM_MOCK" == true ]]; then
  step "stopping old remote $PLATFORM_LABEL"
  remote_ssh "mkdir -p '$REMOTE_DIR'; pkill -x '$MOCK_BINARY_NAME' >/dev/null 2>&1 || true"

  step "uploading $PLATFORM_LABEL to remote host"
  sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$MOCK_BINARY_PATH" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/$MOCK_BINARY_NAME.new"

  step "replacing remote $PLATFORM_LABEL"
  remote_ssh "mv '$REMOTE_DIR/$MOCK_BINARY_NAME.new' '$REMOTE_DIR/$MOCK_BINARY_NAME' && chmod +x '$REMOTE_DIR/$MOCK_BINARY_NAME'"

  # 在远程主机上获取 TAA 容器/Pod IP，直接传给平台（避免平台运行时 kubectl 失败）
  TAA_POD_IP=""
  if [[ "$DEPLOY_MODE" == "docker" ]]; then
    TAA_POD_IP=$(remote_ssh "docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' '$TARGET_CONTAINER' 2>/dev/null" || echo "")
  else
    TAA_POD_IP=$(remote_ssh "kubectl $K_NS get pod '$TARGET_POD' -o jsonpath='{.status.podIP}' 2>/dev/null" || echo "")
  fi
  TAA_TARGET_ARG=""
  if [[ -n "$TAA_POD_IP" ]]; then
    TAA_TARGET_ARG="-taa-target http://${TAA_POD_IP}:${CON_PORT}"
    echo "  discovered TAA container IP: $TAA_POD_IP"
  else
    echo "  warning: could not discover TAA container IP, falling back to -taa-pod auto-discovery"
    TAA_TARGET_ARG="-taa-pod '$TARGET_POD' -taa-ns '$TARGET_NAMESPACE'"
  fi

  step "starting remote $PLATFORM_LABEL on ${PLATFORM_ADDR}"
  remote_ssh "nohup '$REMOTE_DIR/$MOCK_BINARY_NAME' -addr '$PLATFORM_ADDR' $TAA_TARGET_ARG > '$REMOTE_DIR/platform-mock.log' 2>&1 < /dev/null &"

  sleep 1

  step "checking remote $PLATFORM_LABEL status"
  remote_ssh "ss -ltnp | grep ':${PLATFORM_PORT}' || true"
  remote_ssh "tail -n 10 '$REMOTE_DIR/platform-mock.log' || true"
  remote_ssh "curl -fsS 'http://127.0.0.1:${PLATFORM_PORT}/api/register/status' >/dev/null && echo '$PLATFORM_LABEL status endpoint is ready'"
fi

if [[ "$DEPLOY_TAA" == true ]]; then
  step "pausing taa inside container"
  TAA_MANUAL_WAS_PRESENT=false
  if remote_ssh "$(container_exec) sh -lc 'test -e /root/taa/manual'"; then
    TAA_MANUAL_WAS_PRESENT=true
    info "taa manual mode already enabled; leaving it paused during deployment"
  else
    remote_ssh "$(container_exec) sh -lc 'touch /root/taa/manual'"
    info "taa autostart paused for deployment"
  fi
  remote_ssh "$(container_exec) sh -lc 'pkill -x taa >/dev/null 2>&1 || true; killall taa >/dev/null 2>&1 || true'"
  for _ in {1..30}; do
    if ! remote_ssh "$(container_exec) sh -lc 'pgrep -x taa >/dev/null 2>&1'"; then
      break
    fi
    sleep 1
  done

  step "uploading taa and attestation helper to remote host"
  sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$TAA_BINARY_PATH" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/$BINARY_NAME.new"
  sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$ATT_HELPER_SOURCE" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/get-attestation.new"
  sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$ATT_HRK_SOURCE" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/hrk.cert.new"
  sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$ATT_HSK_SOURCE" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/hsk_cek.cert.new"

  step "replacing remote taa and attestation helper"
  remote_ssh "mv '$REMOTE_DIR/$BINARY_NAME.new' '$REMOTE_DIR/$BINARY_NAME' && mv '$REMOTE_DIR/get-attestation.new' '$REMOTE_DIR/get-attestation' && mv '$REMOTE_DIR/hrk.cert.new' '$REMOTE_DIR/hrk.cert' && mv '$REMOTE_DIR/hsk_cek.cert.new' '$REMOTE_DIR/hsk_cek.cert' && chmod +x '$REMOTE_DIR/$BINARY_NAME' '$REMOTE_DIR/get-attestation'"

  step "copying runtime files into container"
  remote_ssh "$(container_exec) sh -lc 'mkdir -p $TAA_CONTAINER_WORKDIR/attestation'"
  remote_ssh "$(container_cp "$REMOTE_DIR/$BINARY_NAME" "$TAA_CONTAINER_WORKDIR/$BINARY_NAME")"
  remote_ssh "$(container_cp "$REMOTE_DIR/get-attestation" "$TAA_CONTAINER_WORKDIR/attestation/get-attestation")"
  remote_ssh "$(container_cp "$REMOTE_DIR/hrk.cert" "$TAA_CONTAINER_WORKDIR/hrk.cert")"
  remote_ssh "$(container_cp "$REMOTE_DIR/hsk_cek.cert" "$TAA_CONTAINER_WORKDIR/hsk_cek.cert")"
  remote_ssh "$(container_exec) sh -lc 'chmod +x $TAA_CONTAINER_WORKDIR/$BINARY_NAME $TAA_CONTAINER_WORKDIR/attestation/get-attestation'"

  step "verifying copied files inside container"
  remote_ssh "$(container_exec) sh -lc 'ls -l $TAA_CONTAINER_WORKDIR/$BINARY_NAME $TAA_CONTAINER_WORKDIR/attestation/get-attestation $TAA_CONTAINER_WORKDIR/hrk.cert $TAA_CONTAINER_WORKDIR/hsk_cek.cert 2>/dev/null'"

  step "checking attestation helper prerequisites inside container"
  remote_ssh "$(container_exec) sh -lc 'test -x $TAA_CONTAINER_WORKDIR/attestation/get-attestation && test -f $TAA_CONTAINER_WORKDIR/hrk.cert && test -f $TAA_CONTAINER_WORKDIR/hsk_cek.cert'"
  if ! remote_ssh "$(container_exec) sh -lc 'test -e /dev/csv-guest'" 2>/dev/null; then
    warn "/dev/csv-guest not found in container — attestation will fail (expected in non-TEE Docker)"
  fi

  if [[ "$TAA_MANUAL_WAS_PRESENT" == false ]]; then
    step "restoring taa service inside container"
    remote_ssh "$(container_exec) sh -lc 'rm -f /root/taa/manual'"
    step "waiting for taa service to become ready"
    ready_attempts=$(( (OLLAMA_READY_TIMEOUT + OLLAMA_READY_INTERVAL - 1) / OLLAMA_READY_INTERVAL ))
    remote_ssh "$(container_exec) sh -lc '
      i=0
      max=$ready_attempts
      while [ "\$i" -lt "\$max" ]; do
        if curl -fsS -X POST http://127.0.0.1:$CON_PORT/v1/taa/health >/dev/null 2>&1; then
          exit 0
        fi
        i=\$((i + 1))
        sleep $OLLAMA_READY_INTERVAL
      done
      echo taa did not become ready within ${OLLAMA_READY_TIMEOUT}s
      tail -n 50 $TAA_LOG_FILE || true
      exit 1
    '"
  else
    warn "taa was already paused before deployment; leaving manual mode enabled"
  fi

  remote_ssh "$(container_exec) sh -lc 'tail -n 50 $TAA_LOG_FILE || true'"
fi

if [[ "$DEPLOY_QWEN" == true ]]; then
  step "stopping old ollama inside container (will be started by TAA at runtime)"
  remote_ssh "$(container_exec) sh -lc 'killall ollama >/dev/null 2>&1 || true; pkill -x ollama >/dev/null 2>&1 || true; killall llama-server >/dev/null 2>&1 || true; pkill -x llama-server >/dev/null 2>&1 || true'"

  sync_ollama_to_remote
  copy_ollama_to_container
  # ollama 启动由 TAA 服务在 main.go 的 ensureQwenAvailable() 自动处理
fi

echo ""
banner "Deploy Complete"
if [[ "$DEPLOY_PLATFORM_MOCK" == true ]]; then
  info "${BOLD}${PLATFORM_LABEL}${NC} → ${REMOTE_HOST}:${PLATFORM_PORT}"
fi
if [[ "$DEPLOY_TAA" == true ]]; then
  info "${BOLD}taa${NC} → ${CONTAINER_LABEL}:${TAA_CONTAINER_WORKDIR} (addr ${TAA_CONTAINER_ADDR})"
  echo -e "     ${DIM}host:${NC} ${REMOTE_HOST}:${REMOTE_DIR}/${BINARY_NAME}"
  echo -e "     ${DIM}log:${NC}  ${TAA_LOG_FILE}"
  echo -e "     ${DIM}platform:${NC} ${REMOTE_PLATFORM_IP}"
  echo -e "     ${DIM}attestation:${NC} ${ATT_REPORT_FILE}"
fi
if [[ "$DEPLOY_QWEN" == true ]]; then
  info "${BOLD}ollama${NC} → ${CONTAINER_LABEL}:${CONTAINER_OLLAMA_DIR} (auto-start by TAA)"
fi
echo ""
