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
TARGET_POD="${TARGET_POD:-taa-env-slim-v2-20260906-800277a02e047abd-dfbd65cd-zst7g}"

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

# TAA 容器运行参数：容器内工作目录、监听地址、注册用容器标识和日志路径。
TAA_CONTAINER_WORKDIR="${TAA_CONTAINER_WORKDIR:-${CON_WORKDIR}}"
TAA_CONTAINER_ADDR="${TAA_CONTAINER_ADDR:-:${CON_PORT}}"
# TAA 程序固定读取工作目录下的 taa-config.json，脚本侧文件名必须保持一致。
TAA_CONFIG_FILE="taa-config.json"
TAA_LOCAL_CONFIG_TEMPLATE="${TAA_LOCAL_CONFIG_TEMPLATE:-$PROJECT_DIR/configs/taa-local.json}"
TAA_DEBUG_CONFIG_TEMPLATE="${TAA_DEBUG_CONFIG_TEMPLATE:-$PROJECT_DIR/configs/taa-debug.json}"
TAA_PRODUCTION_CONFIG_TEMPLATE="${TAA_PRODUCTION_CONFIG_TEMPLATE:-$PROJECT_DIR/configs/taa-production.json}"
REMOTE_TAA_CONFIG_PATH="${REMOTE_TAA_CONFIG_PATH:-$REMOTE_DIR/$TAA_CONFIG_FILE}"
CONTAINER_TAA_CONFIG_PATH="${CONTAINER_TAA_CONFIG_PATH:-$TAA_CONTAINER_WORKDIR/$TAA_CONFIG_FILE}"
CONTRACT="${CONTRACT:-}"
if [[ "$DEBUG" == true ]]; then
  TAA_LOG_FILE="${TAA_LOG_FILE:-$TAA_CONTAINER_WORKDIR/taa.log}"
else
  TAA_LOG_FILE="${TAA_LOG_FILE:-/tmp/taa.log}"
fi
# Ollama / Qwen：本地离线包、远程缓存目录、容器内目录、服务监听和模型配置。
OLLAMA_LOCAL_DIR="${OLLAMA_LOCAL_DIR:-$PROJECT_DIR/models/audit/ollama-qwen2.5-coder-0.5b}"
OLLAMA_DIR_NAME="${OLLAMA_DIR_NAME:-$(basename "$OLLAMA_LOCAL_DIR")}"
REMOTE_OLLAMA_DIR="${REMOTE_OLLAMA_DIR:-$REMOTE_DIR/$OLLAMA_DIR_NAME}"
REMOTE_OLLAMA_ARCHIVE="${REMOTE_OLLAMA_ARCHIVE:-$REMOTE_DIR/$OLLAMA_DIR_NAME.tar.gz}"
CONTAINER_OLLAMA_DIR="${CONTAINER_OLLAMA_DIR:-$TAA_CONTAINER_WORKDIR/$OLLAMA_DIR_NAME}"
CONTAINER_OLLAMA_ARCHIVE="${CONTAINER_OLLAMA_ARCHIVE:-$TAA_CONTAINER_WORKDIR/$OLLAMA_DIR_NAME.tar.gz}"
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
SELECTED_COMPONENT=false
STEP=0

LOCAL_PLATFORM_STATE_DIR="${LOCAL_PLATFORM_STATE_DIR:-$PROJECT_DIR/.local/platform-mock}"
if [[ "$DEBUG" == true ]]; then
  LOCAL_PLATFORM_PORT="${LOCAL_PLATFORM_PORT:-28080}"
else
  LOCAL_PLATFORM_PORT="${LOCAL_PLATFORM_PORT:-18080}"
fi
LOCAL_PLATFORM_BIND="${LOCAL_PLATFORM_BIND:-0.0.0.0:${LOCAL_PLATFORM_PORT}}"
LOCAL_PLATFORM_IP="${LOCAL_PLATFORM_IP:-127.0.0.1:${LOCAL_PLATFORM_PORT}}"
LOCAL_PLATFORM_URL="${LOCAL_PLATFORM_URL:-http://127.0.0.1:${LOCAL_PLATFORM_PORT}}"
LOCAL_PLATFORM_UPLOAD_DIR="${LOCAL_PLATFORM_UPLOAD_DIR:-$PROJECT_DIR/uploads}"
LOCAL_RUN_DIR="${LOCAL_RUN_DIR:-$PROJECT_DIR/.local/run}"
REMOTE_TAA_CONFIG_SOURCE="${REMOTE_TAA_CONFIG_SOURCE:-$LOCAL_RUN_DIR/remote-$TAA_CONFIG_FILE}"
LOCAL_DOCKER_CONFIG_SOURCE="${LOCAL_DOCKER_CONFIG_SOURCE:-$LOCAL_RUN_DIR/local-$TAA_CONFIG_FILE}"
LOCAL_TAA_PORT="${LOCAL_TAA_PORT:-$CON_PORT}"
LOCAL_TAA_URL="${LOCAL_TAA_URL:-http://127.0.0.1:${LOCAL_TAA_PORT}}"
LOCAL_PLATFORM_LOG_FILE="${LOCAL_PLATFORM_LOG_FILE:-$PROJECT_DIR/.local/logs/platform-mock.log}"
LOCAL_TAA_LOG_FILE="${LOCAL_TAA_LOG_FILE:-$PROJECT_DIR/.local/logs/taa.log}"
LOCAL_OLLAMA_LOG_FILE="${LOCAL_OLLAMA_LOG_FILE:-$PROJECT_DIR/.local/logs/ollama.log}"
LOCAL_OLLAMA_URL="${LOCAL_OLLAMA_URL:-http://${OLLAMA_HOST}}"
LOCAL_DOCKER_CONTAINER="${LOCAL_DOCKER_CONTAINER:-taa-env-slim-v2}"
LOCAL_DOCKER_IMAGE_ARCHIVE="${LOCAL_DOCKER_IMAGE_ARCHIVE:-$PROJECT_DIR/deploy/taa-env-slim-v2.tar.gz}"
LOCAL_DOCKER_IMAGE="${LOCAL_DOCKER_IMAGE:-taa-env:slim-v2}"
LOCAL_DOCKER_NETWORK="${LOCAL_DOCKER_NETWORK:-host}"
LOCAL_DOCKER_INPUT_DIR="${LOCAL_DOCKER_INPUT_DIR:-/opt/taa/input}"
LOCAL_DOCKER_OUTPUT_DIR="${LOCAL_DOCKER_OUTPUT_DIR:-/opt/taa/output}"
FORCE_QWEN_COPY="${FORCE_QWEN_COPY:-false}"

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

# ── Container helpers (k8s) ────────────────────────────────
# 在容器内执行命令（通过 remote_ssh 在远程宿主机上操作）。
container_exec() {
  echo "kubectl $K_NS exec '$TARGET_POD' --"
}

# 从远程宿主机复制文件到容器内。
container_cp() {
  echo "kubectl $K_NS cp '$1' '$TARGET_POD':'$2'"
}

ensure_local_docker_container() {
  step "checking local docker image: $LOCAL_DOCKER_IMAGE"
  if ! docker image inspect "$LOCAL_DOCKER_IMAGE" >/dev/null 2>&1; then
    if [[ -f "$LOCAL_DOCKER_IMAGE_ARCHIVE" ]]; then
      step "loading local docker image from $LOCAL_DOCKER_IMAGE_ARCHIVE"
      docker load -i "$LOCAL_DOCKER_IMAGE_ARCHIVE"
    else
      warn "image '$LOCAL_DOCKER_IMAGE' not found and archive '$LOCAL_DOCKER_IMAGE_ARCHIVE' does not exist"
    fi
  fi

  step "checking local docker container: $LOCAL_DOCKER_CONTAINER"
  if docker ps -a --format '{{.Names}}' | grep -Eq "^${LOCAL_DOCKER_CONTAINER}\$"; then
    local current_image
    current_image=$(docker inspect --format '{{.Config.Image}}' "$LOCAL_DOCKER_CONTAINER" 2>/dev/null || true)
    local current_image_id
    current_image_id=$(docker inspect --format '{{.Image}}' "$LOCAL_DOCKER_CONTAINER" 2>/dev/null || true)
    local target_image_id
    target_image_id=$(docker image inspect --format '{{.Id}}' "$LOCAL_DOCKER_IMAGE" 2>/dev/null || true)

    local image_mismatch=false
    if [[ -n "$current_image" && "$current_image" != "$LOCAL_DOCKER_IMAGE" ]]; then
      image_mismatch=true
    elif [[ -n "$target_image_id" && -n "$current_image_id" && "$current_image_id" != "$target_image_id" ]]; then
      image_mismatch=true
    fi

    if [[ "$image_mismatch" == true ]]; then
      warn "container $LOCAL_DOCKER_CONTAINER image mismatch (current: $current_image, expected: $LOCAL_DOCKER_IMAGE)"
      info "recreating container $LOCAL_DOCKER_CONTAINER using $LOCAL_DOCKER_IMAGE"
      docker rm -f "$LOCAL_DOCKER_CONTAINER" >/dev/null
    fi
  fi

  if docker ps --format '{{.Names}}' | grep -Eq "^${LOCAL_DOCKER_CONTAINER}\$"; then
    info "local docker container is already running: $LOCAL_DOCKER_CONTAINER"
  elif docker ps -a --format '{{.Names}}' | grep -Eq "^${LOCAL_DOCKER_CONTAINER}\$"; then
    info "starting stopped local docker container: $LOCAL_DOCKER_CONTAINER"
    docker start "$LOCAL_DOCKER_CONTAINER" >/dev/null
  else
    info "creating and starting local docker container: $LOCAL_DOCKER_CONTAINER (image: $LOCAL_DOCKER_IMAGE, network: $LOCAL_DOCKER_NETWORK)"
    docker run -d --name "$LOCAL_DOCKER_CONTAINER" --network "$LOCAL_DOCKER_NETWORK" --entrypoint tail "$LOCAL_DOCKER_IMAGE" -f /dev/null >/dev/null
  fi

  # 在容器工作目录标记 manual 模式，防止镜像内置的 start.sh 自启动造成端口竞争
  docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "mkdir -p '$TAA_CONTAINER_WORKDIR' && touch '$TAA_CONTAINER_WORKDIR/manual'" >/dev/null 2>&1 || true

  if ! docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "command -v python3 >/dev/null 2>&1"; then
    step "installing python3 inside container: $LOCAL_DOCKER_CONTAINER"
    docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 < /dev/null" || {
      err "failed to install python3 in container $LOCAL_DOCKER_CONTAINER; ensure base image has python3 or network access is available"
      exit 1
    }
  fi
  docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "if ! command -v python >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then ln -s \$(which python3) /usr/local/bin/python; fi" >/dev/null 2>&1 || true
  local py_ver
  if ! py_ver=$(docker exec -i "$LOCAL_DOCKER_CONTAINER" python3 --version 2>&1); then
    err "python3 runtime check failed inside container $LOCAL_DOCKER_CONTAINER: $py_ver"
    exit 1
  fi
  info "container python runtime: $py_ver"
}

usage() {
  cat <<EOF
Usage: $(basename "$0") [local] [start|stop] [platform-mock] [taa] [qwen]

Without arguments, all three components are deployed remotely via Kubernetes.
Pass local to deploy TAA and its dependencies into a local Docker container
for testing, with platform-mock running locally on host.
Pass start or stop to control service lifecycle (default: start).
When no component names are given, all three components are deployed by default.
Provide one or more names to deploy them separately.
Examples:
  $(basename "$0") local start
  $(basename "$0") local stop
  $(basename "$0") local
  $(basename "$0") local taa
  $(basename "$0") local qwen
  $(basename "$0") local platform-mock
  $(basename "$0") local taa qwen
  $(basename "$0") platform-mock
  $(basename "$0") taa
  $(basename "$0") qwen
  $(basename "$0") platform-mock taa
  $(basename "$0") platform-mock taa qwen

Environment overrides:
  # Local mode (local)
  LOCAL_DOCKER_CONTAINER=${LOCAL_DOCKER_CONTAINER}
      本地 Docker 目标容器名称（默认 taa-env-slim-v2）。
  LOCAL_DOCKER_IMAGE_ARCHIVE=${LOCAL_DOCKER_IMAGE_ARCHIVE}
      本地基础镜像归档文件路径（默认 deploy/taa-env-slim-v2.tar.gz）。
  LOCAL_DOCKER_IMAGE=${LOCAL_DOCKER_IMAGE}
      本地 Docker 基础镜像名称（默认 taa-env:slim-v2）。
  LOCAL_DOCKER_NETWORK=${LOCAL_DOCKER_NETWORK}
      本地 Docker 容器网络模式（默认 host）。
  FORCE_QWEN_COPY=${FORCE_QWEN_COPY}
      设为 true 时强制重新将 ollama/qwen 完整离线包拷贝进容器。

  # Kubernetes / Pod (Remote mode)
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
  LOCAL_PLATFORM_PORT=${LOCAL_PLATFORM_PORT}
      本地 Platform Mock 监听端口。
  LOCAL_PLATFORM_UPLOAD_DIR=${LOCAL_PLATFORM_UPLOAD_DIR}
      Platform Mock 上传与静态文件服务目录（默认 $PROJECT_DIR/uploads）。
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
      写入 TAA 配置文件的容器内监听地址与端口。
  TAA_LOCAL_CONFIG_TEMPLATE=${TAA_LOCAL_CONFIG_TEMPLATE}
      local 场景 TAA 配置模板。
  TAA_DEBUG_CONFIG_TEMPLATE=${TAA_DEBUG_CONFIG_TEMPLATE}
      debug 场景 TAA 配置模板。
  TAA_PRODUCTION_CONFIG_TEMPLATE=${TAA_PRODUCTION_CONFIG_TEMPLATE}
      正式非 debug 场景 TAA 配置模板。
  CONTRACT=${CONTRACT}
      debug/local 场景写入配置文件的合约 ID；正式非 debug 场景由运行环境注入（预留可选）。
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
      pkill -P "$pid" 2>/dev/null || true
      kill "$pid" 2>/dev/null || true
      for _ in {1..50}; do
        if ! kill -0 "$pid" 2>/dev/null; then
          break
        fi
        sleep 0.1
      done
      pkill -9 -P "$pid" 2>/dev/null || true
      kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$pidfile"
  fi
}

stop_selected_local_processes() {
  [[ "$DEPLOY_TAA" == true ]] && stop_pidfile "taa" "$LOCAL_RUN_DIR/taa.pid"
  [[ "$DEPLOY_PLATFORM_MOCK" == true ]] && stop_pidfile "platform-mock" "$LOCAL_RUN_DIR/platform-mock.pid"
  [[ "$DEPLOY_QWEN" == true ]] && stop_pidfile "ollama" "$LOCAL_RUN_DIR/ollama.pid"
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

require_command() {
  local name="$1"
  command -v "$name" >/dev/null 2>&1 || { err "$name is required"; exit 1; }
}

select_taa_config_template() {
  if [[ "$DEPLOY_LOCAL" == true ]]; then
    printf '%s' "$TAA_LOCAL_CONFIG_TEMPLATE"
  elif [[ "$DEBUG" == true ]]; then
    printf '%s' "$TAA_DEBUG_CONFIG_TEMPLATE"
  else
    printf '%s' "$TAA_PRODUCTION_CONFIG_TEMPLATE"
  fi
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
  local llm_dir="${10}"
  local llm_endpoint="${11}"
  local llm_model="${12}"
  local include_identity="${13}"
  local model_input_dir="${14:-}"
  local model_output_dir="${15:-}"
  local keys_dir="${16:-}"

  require_file "taa config template not found" "$template"
  require_command python3
  ensure_parent_dir "$path"
  python3 - "$template" "$path" "$addr" "$platform_ip" "$docker_id" "$contract" "$model_dir" "$data_dir" "$result_dir" "$llm_dir" "$llm_endpoint" "$llm_model" "$include_identity" "$model_input_dir" "$model_output_dir" "$keys_dir" <<'PY'
import json
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
    llm_dir,
    llm_endpoint,
    llm_model,
    include_identity,
    model_input_dir,
    model_output_dir,
    keys_dir,
) = sys.argv[1:17]

with open(template, "r", encoding="utf-8") as f:
    cfg = json.load(f)

cfg["addr"] = addr
cfg["modelDir"] = model_dir
cfg["dataDir"] = data_dir
cfg["resultDir"] = result_dir
if model_input_dir:
    cfg["modelInputDir"] = model_input_dir
if model_output_dir:
    cfg["modelOutputDir"] = model_output_dir
if keys_dir:
    cfg["keysDir"] = keys_dir

if include_identity == "true":
    cfg["platformIP"] = platform_ip
    cfg["dockerID"] = docker_id
    cfg["contract"] = contract
else:
    for key in ("platformIP", "dockerID", "contract"):
        cfg.pop(key, None)

llm = cfg.setdefault("llm", {})
llm["endpoint"] = llm_endpoint
llm["model"] = llm_model
llm["dir"] = llm_dir

with open(path, "w", encoding="utf-8") as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
    f.write("\n")
PY
}

ACTION="start"

if [[ $# -eq 0 ]]; then
  DEPLOY_PLATFORM_MOCK=true
  DEPLOY_TAA=true
  DEPLOY_QWEN=true
else
  for arg in "$@"; do
    case "$arg" in
      local|local-docker)
        DEPLOY_LOCAL=true
        ;;
      start)
        ACTION="start"
        ;;
      stop)
        ACTION="stop"
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
  done

  if [[ "$SELECTED_COMPONENT" == false ]]; then
    DEPLOY_PLATFORM_MOCK=true
    DEPLOY_TAA=true
    DEPLOY_QWEN=true
  fi
fi

cd "$PROJECT_DIR"

if [[ "$ACTION" == "stop" ]]; then
  banner "Stopping Services"
  if [[ "$DEPLOY_LOCAL" == true ]]; then
    step "stopping local processes"
    stop_selected_local_processes
    if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -Eq "^${LOCAL_DOCKER_CONTAINER}\$"; then
      if [[ "$DEPLOY_TAA" == true ]]; then
        docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "pkill -x '$BINARY_NAME' >/dev/null 2>&1 || true; killall '$BINARY_NAME' >/dev/null 2>&1 || true" 2>/dev/null || true
      fi
      if [[ "$DEPLOY_QWEN" == true ]]; then
        docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "pkill -x ollama >/dev/null 2>&1 || true; pkill -x llama-server >/dev/null 2>&1 || true" 2>/dev/null || true
      fi
    fi
  else
    step "stopping remote processes"
    if [[ "$DEPLOY_PLATFORM_MOCK" == true ]]; then
      remote_ssh "pkill -x '$MOCK_BINARY_NAME' >/dev/null 2>&1 || true"
    fi
    if [[ "$DEPLOY_TAA" == true ]]; then
      remote_ssh "$(container_exec) sh -lc 'touch /root/taa/manual && pkill -x taa >/dev/null 2>&1 || true; killall taa >/dev/null 2>&1 || true'"
    fi
    if [[ "$DEPLOY_QWEN" == true ]]; then
      remote_ssh "$(container_exec) sh -lc 'killall ollama >/dev/null 2>&1 || true; pkill -x ollama >/dev/null 2>&1 || true; killall llama-server >/dev/null 2>&1 || true; pkill -x llama-server >/dev/null 2>&1 || true'"
    fi
  fi
  info "all target services stopped cleanly"
  exit 0
fi

# 用户可见的平台标签：DEBUG 模式显示 "platform-mock"，生产模式显示 "platform"
PLATFORM_LABEL="platform"
if [[ "$DEBUG" == true || "$DEPLOY_LOCAL" == true ]]; then
  PLATFORM_LABEL="platform-mock"
fi

# 容器标识显示名：local 模式显示本地容器名，k8s 模式显示 Pod 名。
if [[ "$DEPLOY_LOCAL" == true ]]; then
  CONTAINER_LABEL="${LOCAL_DOCKER_CONTAINER}"
else
  CONTAINER_LABEL="${TARGET_POD}"
fi
REMOTE_DOCKER_ID="${REMOTE_DOCKER_ID:-$CONTAINER_LABEL}"

DEPLOY_COMPONENTS=""
[[ "$DEPLOY_PLATFORM_MOCK" == true ]] && DEPLOY_COMPONENTS+="$PLATFORM_LABEL "
[[ "$DEPLOY_TAA" == true ]] && DEPLOY_COMPONENTS+="taa "
[[ "$DEPLOY_QWEN" == true ]] && DEPLOY_COMPONENTS+="qwen "
DEPLOY_TARGET_DESC="${REMOTE_USER}@${REMOTE_HOST}"
if [[ "$DEPLOY_LOCAL" == true ]]; then
  DEPLOY_TARGET_DESC="local docker (${LOCAL_DOCKER_CONTAINER})"
fi
banner "Deploying: ${DEPLOY_COMPONENTS}→ ${DEPLOY_TARGET_DESC}"

if [[ "$DEPLOY_PLATFORM_MOCK" == true ]]; then
  make MOCK_BINARY="$MOCK_BINARY_PATH" platform-mock-build
fi
if [[ "$DEPLOY_QWEN" == true ]]; then
  require_dir "ollama package not found" "$OLLAMA_LOCAL_DIR"
  require_file "ollama package is incomplete" "$OLLAMA_LOCAL_DIR/ollama"
  require_file "ollama package is incomplete" "$OLLAMA_LOCAL_DIR/start-ollama.sh"
  require_dir "ollama package is incomplete" "$OLLAMA_LOCAL_DIR/models/models"
  require_dir "ollama package is incomplete" "$OLLAMA_LOCAL_DIR/lib/ollama"
  info "ollama package: $(du -sh "$OLLAMA_LOCAL_DIR" | awk '{print $1}') at $OLLAMA_LOCAL_DIR"
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


if [[ "$DEPLOY_LOCAL" == true ]]; then
  require_command docker
  docker info >/dev/null 2>&1 || { err "docker daemon is not running or accessible"; exit 1; }

  # 如果需要部署 taa 或 qwen，先确保容器已就绪
  if [[ "$DEPLOY_TAA" == true || "$DEPLOY_QWEN" == true ]]; then
    ensure_local_docker_container
  fi

  # 1. 启动本地 platform-mock（若包含 platform-mock）
  if [[ "$DEPLOY_PLATFORM_MOCK" == true ]]; then
    step "preparing local platform-mock runtime directory"
    mkdir -p "$LOCAL_PLATFORM_STATE_DIR" "$LOCAL_PLATFORM_UPLOAD_DIR" "$LOCAL_RUN_DIR"

    step "starting local platform-mock on ${LOCAL_PLATFORM_BIND}"
    start_local_background "platform-mock" "$LOCAL_RUN_DIR/platform-mock.pid" "$LOCAL_PLATFORM_LOG_FILE" \
      "$MOCK_BINARY_PATH" -addr "$LOCAL_PLATFORM_BIND" -state-dir "$LOCAL_PLATFORM_STATE_DIR" -upload-dir "$LOCAL_PLATFORM_UPLOAD_DIR" -taa-target "$LOCAL_TAA_URL" -allow-empty-attestation
    wait_for_http_ready "platform-mock" GET "$LOCAL_PLATFORM_URL/api/register/status" "$OLLAMA_READY_TIMEOUT" "$OLLAMA_READY_INTERVAL" "$LOCAL_PLATFORM_LOG_FILE"
  fi

  # 2. 部署 qwen / ollama 进本地容器
  if [[ "$DEPLOY_QWEN" == true ]]; then
    step "preparing ollama/qwen dependencies inside container"
    stop_pidfile "ollama" "$LOCAL_RUN_DIR/ollama.pid"
    pkill -f "$OLLAMA_LOCAL_DIR/ollama" >/dev/null 2>&1 || true
    docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc 'pkill -x ollama >/dev/null 2>&1 || true; pkill -x llama-server >/dev/null 2>&1 || true'
    for _ in {1..20}; do
      if ! docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "pgrep -x ollama >/dev/null 2>&1"; then
        break
      fi
      sleep 0.2
    done

    docker exec -i "$LOCAL_DOCKER_CONTAINER" mkdir -p "$TAA_CONTAINER_WORKDIR"

    need_copy=true
    if [[ "$FORCE_QWEN_COPY" == false ]]; then
      if docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "test -f '$CONTAINER_OLLAMA_DIR/ollama' && test -f '$CONTAINER_OLLAMA_DIR/start-ollama.sh' && test -d '$CONTAINER_OLLAMA_DIR/models/models' && test -d '$CONTAINER_OLLAMA_DIR/lib/ollama'"; then
        need_copy=false
        info "ollama package already present inside container ($CONTAINER_OLLAMA_DIR)"
      fi
    fi

    if [[ "$need_copy" == true ]]; then
      step "copying ollama package into container ($LOCAL_DOCKER_CONTAINER:$CONTAINER_OLLAMA_DIR)"
      info "transferring offline bundle into container (large model weights may take a moment)..."
      docker exec -i "$LOCAL_DOCKER_CONTAINER" rm -rf "$CONTAINER_OLLAMA_DIR"
      if command -v tar >/dev/null 2>&1 && docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "command -v tar >/dev/null 2>&1"; then
        tar -C "$(dirname "$OLLAMA_LOCAL_DIR")" -cf - "$(basename "$OLLAMA_LOCAL_DIR")" | docker exec -i "$LOCAL_DOCKER_CONTAINER" tar -xf - -C "$TAA_CONTAINER_WORKDIR"
      else
        docker cp "$OLLAMA_LOCAL_DIR" "$LOCAL_DOCKER_CONTAINER:$CONTAINER_OLLAMA_DIR"
      fi
      info "ollama package transfer completed"
    fi

    docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "chmod +x '$CONTAINER_OLLAMA_DIR/ollama' '$CONTAINER_OLLAMA_DIR/start-ollama.sh'"

    # 动态链接器兼容软链接
    hardcoded_path="/taatest/ollama-qwen2.5-coder-0.5b"
    if [[ "$CONTAINER_OLLAMA_DIR" != "$hardcoded_path" ]]; then
      step "creating symlink for dynamic linker compatibility inside container"
      docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "mkdir -p /taatest && rm -rf '$hardcoded_path' && ln -s '$CONTAINER_OLLAMA_DIR' '$hardcoded_path'"
    fi

    step "starting ollama inside container"
    docker exec -d "$LOCAL_DOCKER_CONTAINER" sh -lc "cd '$CONTAINER_OLLAMA_DIR' && exec env OLLAMA_HOST='$OLLAMA_HOST' OLLAMA_MODELS='$CONTAINER_OLLAMA_DIR/models/models' OLLAMA_LIBRARY_PATH='$CONTAINER_OLLAMA_DIR/lib/ollama' ./start-ollama.sh > '$OLLAMA_LOG_FILE' 2>&1"
    if ! wait_for_http_ready "ollama" GET "$LOCAL_OLLAMA_URL/api/tags" "$OLLAMA_READY_TIMEOUT" "$OLLAMA_READY_INTERVAL"; then
      echo -e "   ${YELLOW}↳${NC} ollama container log (${OLLAMA_LOG_FILE}):"
      docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "tail -n 60 '$OLLAMA_LOG_FILE' 2>/dev/null || true"
      exit 1
    fi
  fi

  # 3. 部署 taa 进本地容器
  if [[ "$DEPLOY_TAA" == true ]]; then
    step "preparing runtime directories inside container"
    docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "mkdir -p '$TAA_CONTAINER_WORKDIR/models' '$TAA_CONTAINER_WORKDIR/data' '$TAA_CONTAINER_WORKDIR/results' '$TAA_CONTAINER_WORKDIR/attestation' '$TAA_CONTAINER_WORKDIR/keys' '$LOCAL_DOCKER_INPUT_DIR' '$LOCAL_DOCKER_OUTPUT_DIR' && chmod 700 '$TAA_CONTAINER_WORKDIR/keys'"

    step "copying taa binary, attestation helper, and certificates into container"
    docker cp "$TAA_BINARY_PATH" "$LOCAL_DOCKER_CONTAINER:$TAA_CONTAINER_WORKDIR/$BINARY_NAME"
    docker cp "$ATT_HELPER_SOURCE" "$LOCAL_DOCKER_CONTAINER:$TAA_CONTAINER_WORKDIR/attestation/get-attestation"
    docker cp "$ATT_HRK_SOURCE" "$LOCAL_DOCKER_CONTAINER:$TAA_CONTAINER_WORKDIR/hrk.cert"
    docker cp "$ATT_HSK_SOURCE" "$LOCAL_DOCKER_CONTAINER:$TAA_CONTAINER_WORKDIR/hsk_cek.cert"
    docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "chmod +x '$TAA_CONTAINER_WORKDIR/$BINARY_NAME' '$TAA_CONTAINER_WORKDIR/attestation/get-attestation'"

    step "checking attestation helper prerequisites inside container"
    if ! docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc 'test -e /dev/csv-guest' 2>/dev/null; then
      warn "/dev/csv-guest not found in container — attestation will fail (expected in non-TEE Docker)"
    fi

    TAA_CONFIG_TEMPLATE="$(select_taa_config_template)"
    step "writing taa config for local docker from $(basename "$TAA_CONFIG_TEMPLATE")"
    ensure_parent_dir "$LOCAL_DOCKER_CONFIG_SOURCE"
    write_taa_config "$LOCAL_DOCKER_CONFIG_SOURCE" "$TAA_CONFIG_TEMPLATE" "$TAA_CONTAINER_ADDR" "$LOCAL_PLATFORM_IP" "$LOCAL_DOCKER_CONTAINER" "$CONTRACT" "$TAA_CONTAINER_WORKDIR/models" "$TAA_CONTAINER_WORKDIR/data" "$TAA_CONTAINER_WORKDIR/results" "$CONTAINER_OLLAMA_DIR" "$LOCAL_OLLAMA_URL" "$OLLAMA_MODEL" true "$LOCAL_DOCKER_INPUT_DIR" "$LOCAL_DOCKER_OUTPUT_DIR" "$TAA_CONTAINER_WORKDIR/keys"
    docker cp "$LOCAL_DOCKER_CONFIG_SOURCE" "$LOCAL_DOCKER_CONTAINER:$CONTAINER_TAA_CONFIG_PATH"

    step "stopping old taa"
    stop_pidfile "taa" "$LOCAL_RUN_DIR/taa.pid"
    pkill -f "$TAA_BINARY_PATH" >/dev/null 2>&1 || true
    docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "pkill -x '$BINARY_NAME' >/dev/null 2>&1 || true; killall '$BINARY_NAME' >/dev/null 2>&1 || true"
    for _ in {1..30}; do
      if ! docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "pgrep -x '$BINARY_NAME' >/dev/null 2>&1"; then
        break
      fi
      sleep 0.2
    done

    step "starting taa inside container"
    docker exec -d "$LOCAL_DOCKER_CONTAINER" sh -lc "cd '$TAA_CONTAINER_WORKDIR' && nohup '$TAA_CONTAINER_WORKDIR/$BINARY_NAME' > '$TAA_LOG_FILE' 2>&1 &"

    step "waiting for taa service to become ready"
    if ! wait_for_http_ready "taa" POST "$LOCAL_TAA_URL/v1/taa/health" "$OLLAMA_READY_TIMEOUT" "$OLLAMA_READY_INTERVAL"; then
      echo -e "   ${YELLOW}↳${NC} taa container log (${TAA_LOG_FILE}):"
      docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "tail -n 60 '$TAA_LOG_FILE' 2>/dev/null || true"
      exit 1
    fi
  fi

  echo ""
  banner "Deploy Complete (Local)"
  if [[ "$DEPLOY_PLATFORM_MOCK" == true ]]; then
    info "${BOLD}platform-mock${NC} → ${LOCAL_PLATFORM_URL}"
    echo -e "     ${DIM}state:${NC}   ${LOCAL_PLATFORM_STATE_DIR}"
    echo -e "     ${DIM}uploads:${NC} ${LOCAL_PLATFORM_UPLOAD_DIR}"
    echo -e "     ${DIM}log:${NC}     ${LOCAL_PLATFORM_LOG_FILE}"
  fi
  if [[ "$DEPLOY_QWEN" == true ]]; then
    info "${BOLD}ollama${NC} → ${LOCAL_DOCKER_CONTAINER}:${CONTAINER_OLLAMA_DIR} (${LOCAL_OLLAMA_URL})"
  fi
  if [[ "$DEPLOY_TAA" == true ]]; then
    info "${BOLD}taa${NC} → ${LOCAL_DOCKER_CONTAINER}:${TAA_CONTAINER_WORKDIR} (${LOCAL_TAA_URL})"
    echo -e "     ${DIM}container:${NC} ${LOCAL_DOCKER_CONTAINER}"
    echo -e "     ${DIM}config:${NC}    ${CONTAINER_TAA_CONFIG_PATH}"
    echo -e "     ${DIM}log:${NC}       ${TAA_LOG_FILE}"
    echo -e "     ${DIM}keys:${NC}      ${LOCAL_DOCKER_CONTAINER}:$TAA_CONTAINER_WORKDIR/keys"
    echo -e "     ${DIM}platform:${NC}  ${LOCAL_PLATFORM_IP}"
    echo -e "     ${DIM}attestation:${NC} ${ATT_REPORT_FILE}"
  fi
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
  step "copying ollama archive into container"
  remote_ssh "$(container_exec) sh -lc 'command -v tar >/dev/null 2>&1 || { echo kubectl cp requires tar inside the container; exit 1; }'"
  remote_ssh "command -v tar >/dev/null 2>&1 || { echo remote tar is required to package ollama; exit 1; }"
  remote_ssh "rm -f '$REMOTE_OLLAMA_ARCHIVE' && tar -C '$REMOTE_DIR' -czf '$REMOTE_OLLAMA_ARCHIVE' '$OLLAMA_DIR_NAME'"
  remote_ssh "$(container_exec) sh -lc 'rm -rf '$CONTAINER_OLLAMA_DIR' '$CONTAINER_OLLAMA_ARCHIVE' && mkdir -p '$TAA_CONTAINER_WORKDIR''"

  local archive_size
  archive_size=$(remote_ssh "du -sh '$REMOTE_OLLAMA_ARCHIVE' 2>/dev/null | cut -f1" 2>/dev/null || echo "unknown")
  info "transferring $archive_size archive from $REMOTE_OLLAMA_ARCHIVE to $CONTAINER_LABEL:$CONTAINER_OLLAMA_ARCHIVE"

  # Show progress while container cp runs
  local spin='-\|/'
  local i=0
  remote_ssh "$(container_cp "$REMOTE_OLLAMA_ARCHIVE" "$CONTAINER_OLLAMA_ARCHIVE")" &
  local cp_pid=$!

  while kill -0 "$cp_pid" 2>/dev/null; do
    printf "\r   ${GREEN}✓${NC} transferring... %s" "${spin:i++%${#spin}:1}"
    sleep 0.2
  done
  printf "\r   ${GREEN}✓${NC} transfer complete, extracting archive\n"

  wait "$cp_pid" || { err "container cp failed"; return 1; }

  remote_ssh "$(container_exec) sh -lc 'tar -xzf '$CONTAINER_OLLAMA_ARCHIVE' -C '$TAA_CONTAINER_WORKDIR' && rm -f '$CONTAINER_OLLAMA_ARCHIVE' && chmod +x '$CONTAINER_OLLAMA_DIR/ollama' '$CONTAINER_OLLAMA_DIR/start-ollama.sh' && test -x '$CONTAINER_OLLAMA_DIR/ollama' && test -f '$CONTAINER_OLLAMA_DIR/start-ollama.sh' && test -d '$CONTAINER_OLLAMA_DIR/models/models' && test -d '$CONTAINER_OLLAMA_DIR/lib/ollama''"
  remote_ssh "rm -f '$REMOTE_OLLAMA_ARCHIVE'"

  # Create symlink for hardcoded dynamic linker path
  # The ollama binary expects /taatest/ollama-qwen2.5-coder-0.5b/lib/glibc/ld-linux-x86-64.so.2
  local hardcoded_path="/taatest/ollama-qwen2.5-coder-0.5b"
  if [[ "$CONTAINER_OLLAMA_DIR" != "$hardcoded_path" ]]; then
    step "creating symlink for dynamic linker compatibility"
    remote_ssh "$(container_exec) sh -lc 'mkdir -p /taatest && rm -rf $hardcoded_path && ln -s '$CONTAINER_OLLAMA_DIR' $hardcoded_path'"
  fi
}

if [[ "$DEPLOY_PLATFORM_MOCK" == true ]]; then
  step "stopping old remote $PLATFORM_LABEL"
  remote_ssh "mkdir -p '$REMOTE_DIR'; pkill -x '$MOCK_BINARY_NAME' >/dev/null 2>&1 || true"

  step "uploading $PLATFORM_LABEL to remote host"
  sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$MOCK_BINARY_PATH" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/$MOCK_BINARY_NAME.new"

  step "replacing remote $PLATFORM_LABEL"
  remote_ssh "mv '$REMOTE_DIR/$MOCK_BINARY_NAME.new' '$REMOTE_DIR/$MOCK_BINARY_NAME' && chmod +x '$REMOTE_DIR/$MOCK_BINARY_NAME'"

  # 在远程主机上获取 TAA Pod IP，直接传给平台（避免平台运行时 kubectl 失败）
  TAA_POD_IP=$(remote_ssh "kubectl $K_NS get pod '$TARGET_POD' -o jsonpath='{.status.podIP}' 2>/dev/null" || echo "")
  TAA_TARGET_ARG=""
  if [[ -n "$TAA_POD_IP" ]]; then
    TAA_TARGET_ARG="-taa-target http://${TAA_POD_IP}:${CON_PORT}"
    echo "  discovered TAA Pod IP: $TAA_POD_IP"
  else
    echo "  warning: could not discover TAA Pod IP, falling back to -taa-pod auto-discovery"
    TAA_TARGET_ARG="-taa-pod '$TARGET_POD' -taa-ns '$TARGET_NAMESPACE' -taa-port '$CON_PORT'"
  fi

  step "starting remote $PLATFORM_LABEL on ${PLATFORM_ADDR}"
  remote_ssh "nohup '$REMOTE_DIR/$MOCK_BINARY_NAME' -addr '$PLATFORM_ADDR' $TAA_TARGET_ARG > '$REMOTE_DIR/platform-mock.log' 2>&1 < /dev/null &"

  sleep 1

  step "checking remote $PLATFORM_LABEL status"
  remote_ssh "ss -ltnp | grep ':${PLATFORM_PORT}' || true"
  remote_ssh "tail -n 10 '$REMOTE_DIR/platform-mock.log' || true"
  remote_ssh "curl -fsS 'http://127.0.0.1:${PLATFORM_PORT}/api/register/status' >/dev/null && echo '$PLATFORM_LABEL status endpoint is ready'"
fi

if [[ "$DEPLOY_QWEN" == true ]]; then
  step "stopping old ollama inside container (will be used by TAA at runtime)"
  remote_ssh "$(container_exec) sh -lc 'killall ollama >/dev/null 2>&1 || true; pkill -x ollama >/dev/null 2>&1 || true; killall llama-server >/dev/null 2>&1 || true; pkill -x llama-server >/dev/null 2>&1 || true'"

  sync_ollama_to_remote
  copy_ollama_to_container
  # ensureQwenAvailable() 会在 TAA 启动时自动拉起 ollama（包已先同步完成）
fi


if [[ "$DEPLOY_TAA" == true ]]; then
  TAA_CONFIG_TEMPLATE="$(select_taa_config_template)"
  step "writing remote taa config from $(basename "$TAA_CONFIG_TEMPLATE")"
  INCLUDE_TAA_IDENTITY=true
  if [[ "$DEBUG" == false ]]; then
    INCLUDE_TAA_IDENTITY=false
  fi
  write_taa_config "$REMOTE_TAA_CONFIG_SOURCE" "$TAA_CONFIG_TEMPLATE" "$TAA_CONTAINER_ADDR" "$REMOTE_PLATFORM_IP" "$REMOTE_DOCKER_ID" "$CONTRACT" "$TAA_CONTAINER_WORKDIR/models" "$TAA_CONTAINER_WORKDIR/data" "$TAA_CONTAINER_WORKDIR/results" "$TAA_CONTAINER_WORKDIR/$OLLAMA_DIR_NAME" "http://127.0.0.1:11434" "$OLLAMA_MODEL" "$INCLUDE_TAA_IDENTITY" "" "" "$TAA_CONTAINER_WORKDIR/keys"

  step "uploading taa, config, and attestation helper to remote host"
  sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$TAA_BINARY_PATH" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/$BINARY_NAME.new"
  sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$REMOTE_TAA_CONFIG_SOURCE" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_TAA_CONFIG_PATH.new"
  sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$ATT_HELPER_SOURCE" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/get-attestation.new"
  sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$ATT_HRK_SOURCE" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/hrk.cert.new"
  sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$ATT_HSK_SOURCE" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/hsk_cek.cert.new"

  step "replacing remote taa, config, and attestation helper"
  remote_ssh "mv '$REMOTE_DIR/$BINARY_NAME.new' '$REMOTE_DIR/$BINARY_NAME' && mv '$REMOTE_TAA_CONFIG_PATH.new' '$REMOTE_TAA_CONFIG_PATH' && mv '$REMOTE_DIR/get-attestation.new' '$REMOTE_DIR/get-attestation' && mv '$REMOTE_DIR/hrk.cert.new' '$REMOTE_DIR/hrk.cert' && mv '$REMOTE_DIR/hsk_cek.cert.new' '$REMOTE_DIR/hsk_cek.cert' && chmod +x '$REMOTE_DIR/$BINARY_NAME' '$REMOTE_DIR/get-attestation'"

  TAA_MANUAL_WAS_PRESENT=false
  step "copying runtime files into container"
  remote_ssh "$(container_exec) sh -lc 'mkdir -p $TAA_CONTAINER_WORKDIR/attestation'"
  remote_ssh "$(container_cp "$REMOTE_DIR/$BINARY_NAME" "$TAA_CONTAINER_WORKDIR/$BINARY_NAME")"
  remote_ssh "$(container_cp "$REMOTE_TAA_CONFIG_PATH" "$CONTAINER_TAA_CONFIG_PATH")"
  remote_ssh "$(container_cp "$REMOTE_DIR/get-attestation" "$TAA_CONTAINER_WORKDIR/attestation/get-attestation")"
  remote_ssh "$(container_cp "$REMOTE_DIR/hrk.cert" "$TAA_CONTAINER_WORKDIR/hrk.cert")"
  remote_ssh "$(container_cp "$REMOTE_DIR/hsk_cek.cert" "$TAA_CONTAINER_WORKDIR/hsk_cek.cert")"
  remote_ssh "$(container_exec) sh -lc 'chmod +x $TAA_CONTAINER_WORKDIR/$BINARY_NAME $TAA_CONTAINER_WORKDIR/attestation/get-attestation'"

  step "verifying copied files inside container"
  remote_ssh "$(container_exec) sh -lc 'ls -l $TAA_CONTAINER_WORKDIR/$BINARY_NAME $CONTAINER_TAA_CONFIG_PATH $TAA_CONTAINER_WORKDIR/attestation/get-attestation $TAA_CONTAINER_WORKDIR/hrk.cert $TAA_CONTAINER_WORKDIR/hsk_cek.cert 2>/dev/null'"

  step "checking attestation helper prerequisites inside container"
  remote_ssh "$(container_exec) sh -lc 'test -x $TAA_CONTAINER_WORKDIR/attestation/get-attestation && test -f $TAA_CONTAINER_WORKDIR/hrk.cert && test -f $TAA_CONTAINER_WORKDIR/hsk_cek.cert'"
  if ! remote_ssh "$(container_exec) sh -lc 'test -e /dev/csv-guest'" 2>/dev/null; then
    warn "/dev/csv-guest not found in container — attestation will fail (expected in non-TEE Docker)"
  fi

  if [[ "$DEBUG" == false ]]; then
    step "checking production identity env inside container"
    remote_ssh "$(container_exec) sh -lc 'test -n \"\${PLATFORM_IP:-}\" && test -n \"\${DOCKER_ID:-}\" || { echo PLATFORM_IP and DOCKER_ID must be injected in production non-debug mode; exit 1; }'"
  fi

  if [[ "$DEBUG" == true ]]; then
    step "starting debug taa inside container"
    remote_ssh "$(container_exec) sh -lc 'pkill -x taa >/dev/null 2>&1 || true; killall taa >/dev/null 2>&1 || true'"
    remote_ssh "$(container_exec) sh -lc 'mkdir -p $TAA_CONTAINER_WORKDIR/models $TAA_CONTAINER_WORKDIR/data $TAA_CONTAINER_WORKDIR/results && cd $TAA_CONTAINER_WORKDIR && nohup $TAA_CONTAINER_WORKDIR/$BINARY_NAME > $TAA_LOG_FILE 2>&1 < /dev/null &'"
  else
    step "pausing taa inside container"
    if remote_ssh "$(container_exec) sh -lc 'test -e /root/taa/manual'"; then
      TAA_MANUAL_WAS_PRESENT=true
      info "taa manual mode already enabled; leaving it paused during deployment"
    else
      TAA_MANUAL_WAS_PRESENT=false
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
  fi

  if [[ "$DEBUG" == true || "$TAA_MANUAL_WAS_PRESENT" == false ]]; then
    if [[ "$DEBUG" == false ]]; then
      step "restoring taa service inside container"
      remote_ssh "$(container_exec) sh -lc 'rm -f /root/taa/manual'"
    fi

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

echo ""
banner "Deploy Complete"
if [[ "$DEPLOY_PLATFORM_MOCK" == true ]]; then
  info "${BOLD}${PLATFORM_LABEL}${NC} → ${REMOTE_HOST}:${PLATFORM_PORT}"
fi
if [[ "$DEPLOY_QWEN" == true ]]; then
  info "${BOLD}ollama${NC} → ${CONTAINER_LABEL}:${CONTAINER_OLLAMA_DIR} (auto-start by TAA)"
fi
if [[ "$DEPLOY_TAA" == true ]]; then
  info "${BOLD}taa${NC} → ${CONTAINER_LABEL}:${TAA_CONTAINER_WORKDIR} (addr ${TAA_CONTAINER_ADDR})"
  echo -e "     ${DIM}host:${NC} ${REMOTE_HOST}:${REMOTE_DIR}/${BINARY_NAME}"
  echo -e "     ${DIM}config:${NC} ${CONTAINER_TAA_CONFIG_PATH}"
  echo -e "     ${DIM}log:${NC}  ${TAA_LOG_FILE}"
  echo -e "     ${DIM}platform:${NC} ${REMOTE_PLATFORM_IP}"
  echo -e "     ${DIM}attestation:${NC} ${ATT_REPORT_FILE}"
fi
echo ""
