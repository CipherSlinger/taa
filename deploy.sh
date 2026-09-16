#!/usr/bin/env bash
set -euo pipefail

DEBUG=${DEBUG:-false} # 调试模式，使用 platform-mock 测试，与正式目录不同，避免污染正式环境

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
TEMP_FILELIST=""

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
  if [[ -n "${TEMP_FILELIST:-}" && -f "$TEMP_FILELIST" ]]; then
    rm -f "$TEMP_FILELIST" 2>/dev/null || true
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

# Kubernetes 目标：默认部署到 osr 命名空间下的指定 TAA Pod。
TARGET_NAMESPACE="${TARGET_NAMESPACE:-osr}"
TARGET_POD="${TARGET_POD:-taa-env-slim-v2-20260911-a8d03c05ede05cdc-75847bd476-wx999}"

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

# 本地构建产物：TAA 与 Platform Mock 的二进制文件名和本地路径。
BINARY_NAME="${BINARY_NAME:-taa}"
TAA_BINARY_PATH="${TAA_BINARY_PATH:-$PROJECT_DIR/bin/$BINARY_NAME}"
MOCK_BINARY_NAME="${MOCK_BINARY_NAME:-platform-mock}"
MOCK_BINARY_PATH="${MOCK_BINARY_PATH:-$PROJECT_DIR/bin/$MOCK_BINARY_NAME}"

# 远程证明文件：HRK 证书、HSK/CEK 证书的本地源路径。
CERT_DIR="${CERT_DIR:-$PROJECT_DIR/deploy/certs}"
ATT_HRK_SOURCE="${ATT_HRK_SOURCE:-$CERT_DIR/hrk.cert}"
ATT_HSK_SOURCE="${ATT_HSK_SOURCE:-$CERT_DIR/hsk_cek.cert}"

# 远程容器目录：TAA 容器内的工作目录和证书路径，以及 attestation report 文件路径。
if [[ ${DEBUG} == false ]]; then
  CON_WORKDIR="${CON_WORKDIR:-/root/taa}"
  CON_PORT="${CON_PORT:-6001}"
else
  CON_WORKDIR="${CON_WORKDIR:-/root/taadebug}"
  CON_PORT="${CON_PORT:-9001}"
fi
ATT_REPORT_FILE="${CON_WORKDIR}/attestation.report"
K_NS="${TARGET_NAMESPACE:+-n $TARGET_NAMESPACE}"

# TAA 容器运行参数：容器内工作目录、监听地址、注册用容器标识和日志路径。
TAA_CONTAINER_WORKDIR="${TAA_CONTAINER_WORKDIR:-${CON_WORKDIR}}"
TAA_CONTAINER_ADDR="${TAA_CONTAINER_ADDR:-:${CON_PORT}}"
# TAA 程序固定读取工作目录下的 taa-config.json，脚本侧文件名必须保持一致。
TAA_CONFIG_FILE="taa-config.json"
TAA_LOCAL_CONFIG_TEMPLATE="${TAA_LOCAL_CONFIG_TEMPLATE:-$PROJECT_DIR/configs/taa-local.json}"
TAA_DOCKER_CONFIG_TEMPLATE="${TAA_DOCKER_CONFIG_TEMPLATE:-$PROJECT_DIR/configs/taa-docker.json}"
TAA_DEBUG_CONFIG_TEMPLATE="${TAA_DEBUG_CONFIG_TEMPLATE:-$PROJECT_DIR/configs/taa-debug.json}"
TAA_PRODUCTION_CONFIG_TEMPLATE="${TAA_PRODUCTION_CONFIG_TEMPLATE:-$PROJECT_DIR/configs/taa-production.json}"
REMOTE_TAA_CONFIG_PATH="${REMOTE_TAA_CONFIG_PATH:-$REMOTE_DIR/$TAA_CONFIG_FILE}"
CONTAINER_TAA_CONFIG_PATH="${CONTAINER_TAA_CONFIG_PATH:-$TAA_CONTAINER_WORKDIR/$TAA_CONFIG_FILE}"
CONTRACT="${CONTRACT:-}"
TAA_LOG_FILE="${TAA_LOG_FILE:-$TAA_CONTAINER_WORKDIR/taa.log}"
# Ollama / Qwen：本地离线包、远程缓存目录、容器内目录、服务监听和模型配置。
OLLAMA_LOCAL_DIR="${OLLAMA_LOCAL_DIR:-$PROJECT_DIR/models/audit/ollama-qwen}"
OLLAMA_DIR_NAME="${OLLAMA_DIR_NAME:-$(basename "$OLLAMA_LOCAL_DIR")}"
REMOTE_OLLAMA_DIR="${REMOTE_OLLAMA_DIR:-$REMOTE_DIR/$OLLAMA_DIR_NAME}"
REMOTE_OLLAMA_ARCHIVE="${REMOTE_OLLAMA_ARCHIVE:-$REMOTE_DIR/$OLLAMA_DIR_NAME.tar.gz}"
CONTAINER_OLLAMA_DIR="${CONTAINER_OLLAMA_DIR:-$TAA_CONTAINER_WORKDIR/$OLLAMA_DIR_NAME}"
CONTAINER_OLLAMA_ARCHIVE="${CONTAINER_OLLAMA_ARCHIVE:-$TAA_CONTAINER_WORKDIR/$OLLAMA_DIR_NAME.tar.gz}"
OLLAMA_HOST="${OLLAMA_HOST:-127.0.0.1:11434}"
ENV_OLLAMA_MODEL="${OLLAMA_MODEL:-}"
CLI_MODEL=""
OLLAMA_MODEL=""
OLLAMA_LOG_FILE="${OLLAMA_LOG_FILE:-/tmp/ollama.log}"
OLLAMA_READY_TIMEOUT="${OLLAMA_READY_TIMEOUT:-120}"
OLLAMA_READY_INTERVAL="${OLLAMA_READY_INTERVAL:-2}"

# 远程 SSH 密码：通过 TARGET_PASSWORD 覆盖；置空时启动脚本会交互式询问。
PASSWORD="${TARGET_PASSWORD:-Osrd@2026}"

DEPLOY_LOCAL=false
DEPLOY_DOCKER=false
DEPLOY_REMOTE=false
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
LOCAL_PLATFORM_UPLOAD_DIR="${LOCAL_PLATFORM_UPLOAD_DIR:-$PROJECT_DIR/.local/upload}"
LOCAL_RUN_DIR="${LOCAL_RUN_DIR:-$PROJECT_DIR/.local/run}"
LOCAL_RUNTIME_DIR="${LOCAL_RUNTIME_DIR:-$PROJECT_DIR/.local/taa}"
LOCAL_TAA_CONFIG_PATH="${LOCAL_TAA_CONFIG_PATH:-$LOCAL_RUNTIME_DIR/$TAA_CONFIG_FILE}"
LOCAL_TAA_MODEL_DIR="${LOCAL_TAA_MODEL_DIR:-$LOCAL_RUNTIME_DIR/models}"
LOCAL_TAA_DATA_DIR="${LOCAL_TAA_DATA_DIR:-$LOCAL_RUNTIME_DIR/data}"
LOCAL_TAA_RESULT_DIR="${LOCAL_TAA_RESULT_DIR:-$LOCAL_RUNTIME_DIR/results}"
LOCAL_TAA_INPUT_DIR="${LOCAL_TAA_INPUT_DIR:-$LOCAL_RUNTIME_DIR/input}"
LOCAL_TAA_OUTPUT_DIR="${LOCAL_TAA_OUTPUT_DIR:-$LOCAL_RUNTIME_DIR/output}"
LOCAL_TAA_KEYS_DIR="${LOCAL_TAA_KEYS_DIR:-$LOCAL_RUNTIME_DIR/keys}"
REMOTE_TAA_CONFIG_SOURCE="${REMOTE_TAA_CONFIG_SOURCE:-$LOCAL_RUN_DIR/remote-$TAA_CONFIG_FILE}"
LOCAL_DOCKER_CONFIG_SOURCE="${LOCAL_DOCKER_CONFIG_SOURCE:-$LOCAL_RUN_DIR/docker-$TAA_CONFIG_FILE}"
LOCAL_TAA_PORT="${LOCAL_TAA_PORT:-$CON_PORT}"
LOCAL_TAA_BIND="${LOCAL_TAA_BIND:-:${LOCAL_TAA_PORT}}"
LOCAL_TAA_URL="${LOCAL_TAA_URL:-http://127.0.0.1:${LOCAL_TAA_PORT}}"
LOCAL_PLATFORM_LOG_FILE="${LOCAL_PLATFORM_LOG_FILE:-$PROJECT_DIR/.local/logs/platform-mock.log}"
LOCAL_TAA_LOG_FILE="${LOCAL_TAA_LOG_FILE:-$PROJECT_DIR/.local/logs/taa.log}"
LOCAL_OLLAMA_LOG_FILE="${LOCAL_OLLAMA_LOG_FILE:-$PROJECT_DIR/.local/logs/ollama.log}"
LOCAL_OLLAMA_URL="${LOCAL_OLLAMA_URL:-http://${OLLAMA_HOST}}"
LOCAL_DOCKER_CONTAINER="${LOCAL_DOCKER_CONTAINER:-taa-env-slim-v2}"
LOCAL_DOCKER_IMAGE_ARCHIVE="${LOCAL_DOCKER_IMAGE_ARCHIVE:-$PROJECT_DIR/deploy/taa-env-slim-v2.tar.gz}"
LOCAL_DOCKER_IMAGE="${LOCAL_DOCKER_IMAGE:-taa-env:slim-v2}"
SAVE_DATE_TAG="$(date +%Y%m%d)"
BASE_DOCKER_IMAGE_ARCHIVE="${BASE_DOCKER_IMAGE_ARCHIVE:-$LOCAL_DOCKER_IMAGE_ARCHIVE}"
BASE_DOCKER_IMAGE="${BASE_DOCKER_IMAGE:-$LOCAL_DOCKER_IMAGE}"
DEFAULT_SAVE_IMAGE="${BASE_DOCKER_IMAGE}-${SAVE_DATE_TAG}"
DEFAULT_SAVE_ARCHIVE="$PROJECT_DIR/deploy/taa-env-slim-v2-${SAVE_DATE_TAG}.tar.gz"
CUSTOM_SAVE_IMAGE=""
CUSTOM_SAVE_ARCHIVE=""
CUSTOM_BASE_ARCHIVE=""
CUSTOM_BASE_IMAGE=""
CUSTOM_SAVE_CONFIG=""
LOCAL_DOCKER_NETWORK="${LOCAL_DOCKER_NETWORK:-host}"
LOCAL_DOCKER_INPUT_DIR="${LOCAL_DOCKER_INPUT_DIR:-/opt/taa/input}"
LOCAL_DOCKER_OUTPUT_DIR="${LOCAL_DOCKER_OUTPUT_DIR:-/opt/taa/output}"
FORCE_QWEN_COPY="${FORCE_QWEN_COPY:-false}"
OLLAMA_PRUNE_SYNC="${OLLAMA_PRUNE_SYNC:-true}"
SAVE_CLEAN="${SAVE_CLEAN:-false}"

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

step() {
  STEP=$((STEP + 1))
  CURRENT_STEP_NAME="$1"
  LAST_FAILED_TASK=""
  printf "  ${PURPLE}◆${NC} ${CYAN}[%02d]${NC} ${BOLD}%s${NC}\n" "$STEP" "$1"
}

info()    { printf "   ${GREEN}✓${NC} %s\n" "$1"; }
warn()    { printf "   ${YELLOW}⚠${NC} %s\n" "$1"; }
err()     { printf "   ${RED}✗${NC} %s\n" "$1" >&2; }
detail()  { printf "     ${MUTED}↳ %s${NC}\n" "$1"; }

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
  if [[ "$DEPLOY_LOCAL" == true || "$DEPLOY_DOCKER" == true ]]; then
    return 0
  fi
  if [[ -z "$PASSWORD" ]]; then
    read -rsp "Password for ${REMOTE_USER}@${REMOTE_HOST}: " PASSWORD
    echo
  fi
  if ! command -v sshpass >/dev/null 2>&1; then
    err "sshpass is required for password-based copy. Install it or set up SSH keys."
    exit 1
  fi
}

remote_ssh() {
  ensure_remote_ssh
  sshpass -p "$PASSWORD" ssh "${SSH_OPTS[@]}" "${REMOTE_USER}@${REMOTE_HOST}" "$@"
}

check_remote_connectivity() {
  if [[ "$DEPLOY_LOCAL" == true || "$DEPLOY_DOCKER" == true ]]; then
    return 0
  fi
  ensure_remote_ssh
  if ! sshpass -p "$PASSWORD" ssh "${SSH_OPTS[@]}" -o ConnectTimeout=5 "${REMOTE_USER}@${REMOTE_HOST}" "true" 2>/dev/null; then
    err "cannot connect to remote host ${REMOTE_USER}@${REMOTE_HOST} via SSH (connection timed out or authentication failed)"
    detail "Please check network connection, REMOTE_HOST ($REMOTE_HOST), or TARGET_PASSWORD credentials."
    exit 1
  fi
  info "remote host SSH connection verified: ${REMOTE_USER}@${REMOTE_HOST}"
}

check_remote_pod() {
  if [[ "$DEPLOY_LOCAL" == true || "$DEPLOY_DOCKER" == true ]]; then
    return 0
  fi
  if ! remote_ssh "kubectl $K_NS get pod '$TARGET_POD' >/dev/null 2>&1"; then
    err "target pod '$TARGET_POD' not found in namespace '${TARGET_NAMESPACE:-default}' on remote host"
    detail "Please check TARGET_POD or run 'kubectl get pods -n ${TARGET_NAMESPACE:-default}' on the remote host to check running pods."
    exit 1
  fi
  info "remote target pod verified: ${TARGET_POD} (namespace: ${TARGET_NAMESPACE:-default})"
}

ensure_local_docker_container() {
  step "checking local docker image: $LOCAL_DOCKER_IMAGE"
  if ! docker image inspect "$LOCAL_DOCKER_IMAGE" >/dev/null 2>&1; then
    if [[ -f "$LOCAL_DOCKER_IMAGE_ARCHIVE" ]]; then
      spin_task "loading local docker image from $LOCAL_DOCKER_IMAGE_ARCHIVE" docker load -i "$LOCAL_DOCKER_IMAGE_ARCHIVE"
    else
      warn "image '$LOCAL_DOCKER_IMAGE' not found and archive '$LOCAL_DOCKER_IMAGE_ARCHIVE' does not exist"
    fi
  else
    info "local docker image verified: $LOCAL_DOCKER_IMAGE"
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
    spin_task "installing python3 inside container: $LOCAL_DOCKER_CONTAINER" \
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

save_local_docker_image() {
  local base_archive="${CUSTOM_BASE_ARCHIVE:-$BASE_DOCKER_IMAGE_ARCHIVE}"
  local base_image="${CUSTOM_BASE_IMAGE:-$BASE_DOCKER_IMAGE}"
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
  spin_task "building taa daemon from ./cmd/taa" go build -o "$TAA_BINARY_PATH" ./cmd/taa
  require_file "build failed: taa binary" "$TAA_BINARY_PATH"
  require_file "certificate missing: hrk.cert" "$ATT_HRK_SOURCE"
  require_file "certificate missing: hsk_cek.cert" "$ATT_HSK_SOURCE"
  info "binaries and attestation certificates ready"

  step "preparing production configuration from $(basename "$prod_config_template")"
  require_file "production config template not found" "$prod_config_template"

  local target_model
  if [[ -n "$CLI_MODEL" ]]; then
    target_model="$CLI_MODEL"
  else
    target_model="$(get_taa_config_llm_model "$prod_config_template")"
    if [[ -z "$target_model" ]]; then
      target_model="qwen2.5-coder:3b"
    fi
  fi

  local prod_config_source="$LOCAL_RUN_DIR/export-production-taa-config.json"
  ensure_parent_dir "$prod_config_source"

  write_taa_config "$prod_config_source" "$prod_config_template" \
    ":6001" "" "" "" \
    "/root/taa/models" "/root/taa/data" "/root/taa/results" \
    "/root/taa/ollama-qwen" "http://127.0.0.1:11434" "$target_model" \
    false "/opt/taa/input" "/opt/taa/output" "/opt/taa/keys"
  info "production config prepared for image (model: $target_model)"

  local has_llm_enabled="false"
  has_llm_enabled=$(python3 -c "import json, sys; print(str(bool((json.load(open(sys.argv[1])).get('llm') or {}).get('enabled', False))).lower())" "$prod_config_template" 2>/dev/null || echo "false")

  local model_meta=""
  local model_mb="0"
  if [[ "$has_llm_enabled" == "true" ]]; then
    step "verifying offline ollama bundle and model weights: $target_model"
    require_dir "ollama package not found" "$OLLAMA_LOCAL_DIR"
    require_file "ollama binary missing" "$OLLAMA_LOCAL_DIR/ollama"
    require_file "start-ollama.sh missing" "$OLLAMA_LOCAL_DIR/start-ollama.sh"
    require_dir "ollama lib directory missing" "$OLLAMA_LOCAL_DIR/lib/ollama"
    require_dir "ollama models directory missing" "$OLLAMA_LOCAL_DIR/models/models"

    model_meta="$(resolve_ollama_model_artifacts "$OLLAMA_LOCAL_DIR" "$target_model" "json")"
    model_mb="$(python3 -c 'import sys, json; print(json.loads(sys.argv[1])["weight_mb"])' "$model_meta" 2>/dev/null || echo "0")"
    info "target model '$target_model' weights verified (${model_mb}MB)"
  fi

  step "creating ephemeral container to assemble image"
  local builder_container="taa-builder-prod-$$"
  TEMP_BUILDER_CONTAINER="$builder_container"

  local target_model_slug=""
  if [[ -n "$target_model" ]]; then
    target_model_slug="ollama-${target_model//[:\/]/-}"
  fi

  spin_task "initializing container directories and symlinks" docker run --name "$builder_container" --entrypoint bash "$base_image" -c "
    rm -f /root/taa/manual /root/taa/taa.log /tmp/ollama.log 2>/dev/null || true
    mkdir -p /root/taa/models /root/taa/data /root/taa/results /root/taa/certs /root/taa/ollama-qwen /opt/taa/keys /opt/taa/input /opt/taa/output /taatest
    chmod 700 /opt/taa/keys
    ln -sfn /root/taa/ollama-qwen /taatest/ollama-qwen2.5-coder-0.5b
    ln -sfn /root/taa/ollama-qwen /root/taa/ollama-qwen2.5-coder-0.5b
    if [[ -n "$target_model_slug" ]]; then
      ln -sfn /root/taa/ollama-qwen "/root/taa/$target_model_slug"
      ln -sfn /root/taa/ollama-qwen "/taatest/$target_model_slug"
    fi
  "

  step "deploying taa binary, certificates, and production config"
  spin_task "copying runtime files into container" bash -c '
    set -euo pipefail
    docker cp "$1" "$2:/root/taa/taa"
    docker cp "$3" "$2:/root/taa/certs/hrk.cert"
    docker cp "$4" "$2:/root/taa/certs/hsk_cek.cert"
    docker cp "$5" "$2:/root/taa/taa-config.json"
  ' _ "$TAA_BINARY_PATH" "$builder_container" "$ATT_HRK_SOURCE" "$ATT_HSK_SOURCE" "$prod_config_source"

  if [[ "$has_llm_enabled" == "true" ]]; then
    step "deploying ollama runtime and model '$target_model' into container"
    local tmp_filelist="$LOCAL_RUN_DIR/ollama_files_$$.txt"
    ensure_parent_dir "$tmp_filelist"
    TEMP_FILELIST="$tmp_filelist"
    resolve_ollama_model_artifacts "$OLLAMA_LOCAL_DIR" "$target_model" "full" > "$tmp_filelist"
    local file_count
    file_count=$(wc -l < "$tmp_filelist")
    if [[ "$file_count" -eq 0 ]]; then
      err "failed to resolve any files for model '$target_model' in $OLLAMA_LOCAL_DIR"
      exit 1
    fi

    spin_task "streaming ollama package and model weights (${model_mb}MB, $file_count items)" bash -c '
      set -euo pipefail
      tar -C "$1" --exclude="*cuda*" -cf - -T "$3" | docker cp - "$2:/root/taa/ollama-qwen"
    ' _ "$OLLAMA_LOCAL_DIR" "$builder_container" "$tmp_filelist"
    rm -f "$tmp_filelist"
    TEMP_FILELIST=""
    info "ollama bundle successfully injected into /root/taa/ollama-qwen"
  fi

  step "committing container to production image: $target_image"
  local commit_msg="Production image packaged from base $(basename "$base_archive") with $(basename "$prod_config_template") at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  spin_task "committing image state ($target_image)" \
    docker commit \
      -c 'ENTRYPOINT ["bash", "/root/taa/start.sh"]' \
      -c 'CMD []' \
      -c 'WORKDIR /root/taa' \
      -c 'EXPOSE 6001 11434' \
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
  echo -e "    ${MUTED}↳ Target Model     :${NC} ${PURPLE}${target_model}${NC} ${DIM}(${model_mb} MB)${NC}"
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
Usage: $(basename "$0") [docker|remote] [start|stop|save] [platform-mock] [taa] [qwen] [--model <name>]

Running modes (mutually exclusive, default: remote):
  docker    Deploy TAA and its dependencies into a local Docker container for testing, with platform-mock running locally on host.
  remote    Deploy remotely via Kubernetes Pod and SSH (default mode).

Actions (mutually exclusive, default: start):
  start     Deploy and start services (default action).
  stop      Stop target running services.
  save      Package base image archive ($BASE_DOCKER_IMAGE_ARCHIVE) with production config ($TAA_PRODUCTION_CONFIG_TEMPLATE),
            commit with a date-stamped tag ($DEFAULT_SAVE_IMAGE), and export to an image archive ($DEFAULT_SAVE_ARCHIVE).
            NOTE: save action is ONLY valid in docker mode (e.g. $(basename "$0") docker save).

Options:
  --model <name> (or --model=<name>)
      Explicitly specify the LLM audit model (overriding config files).
  --archive <path> (or --output <path>, -o <path>)
      Customize the exported archive file destination (docker save).
  --image <tag> (or --tag <tag>)
      Customize the committed image tag name (docker save).
  --base-archive <path> (or --base <path>)
      Specify a custom base image archive (docker save).
  --config <path>
      Specify an alternate production configuration template (docker save).
  --container <name>
      Specify local Docker container name (docker mode).

Component selection:
  When no component names are given, target components are deployed by default (in remote production mode with DEBUG=false, platform-mock is omitted to avoid port 18080 conflict with ccs-node-agent).
  Provide one or more component names (platform-mock, taa, qwen) to deploy or operate on them separately.

Examples:
  # Docker mode (local Docker container)
  $(basename "$0") docker start
  $(basename "$0") docker start --model qwen3:8b
  $(basename "$0") docker stop
  $(basename "$0") docker save
  $(basename "$0") docker save --tag taa-env:slim-v2-$(date +%Y%m%d)
  $(basename "$0") docker save -o /tmp/taa-env-production.tar.gz
  $(basename "$0") docker
  $(basename "$0") docker taa
  $(basename "$0") docker qwen
  $(basename "$0") docker platform-mock
  $(basename "$0") docker taa qwen

  # Remote mode (Kubernetes / SSH)
  $(basename "$0") remote start
  $(basename "$0") remote stop
  $(basename "$0") remote
  $(basename "$0") remote taa
  $(basename "$0") remote qwen
  $(basename "$0") remote platform-mock
  $(basename "$0") remote taa qwen
  $(basename "$0") taa
  $(basename "$0") qwen

Environment overrides:
  # Docker mode (docker)
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
  OLLAMA_PRUNE_SYNC=${OLLAMA_PRUNE_SYNC}
      启用按需模型打包与增量同步（默认 true），仅拷贝/同步 OLLAMA_MODEL 指定模型与运行时依赖。

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
      Platform Mock 上传与静态文件服务目录（默认 $PROJECT_DIR/.local/upload）。
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
  TAA_DEBUG_CONFIG_TEMPLATE=${TAA_DEBUG_CONFIG_TEMPLATE}
      debug 场景 TAA 配置模板。
  TAA_PRODUCTION_CONFIG_TEMPLATE=${TAA_PRODUCTION_CONFIG_TEMPLATE}
      正式非 debug 场景 TAA 配置模板。
  CONTRACT=${CONTRACT}
      debug 场景写入配置文件的合约 ID；正式非 debug 场景由运行环境注入（预留可选）。
  CERT_DIR=${CERT_DIR}
      本地 attestation 证书目录。
  TAA_KEEP_MANUAL=${TAA_KEEP_MANUAL:-false}
      远程部署后是否保持容器 manual 挂起状态而不自启（默认 false）。

  # Ollama / Qwen
  OLLAMA_LOCAL_DIR=${OLLAMA_LOCAL_DIR}
      本地 Ollama / Qwen 离线包目录。
  OLLAMA_HOST=${OLLAMA_HOST}
      Ollama 在容器内监听的地址与端口。
  OLLAMA_MODEL=${OLLAMA_MODEL}
      启动检查使用的 Qwen 模型名称（若未通过环境或参数指定，优先从当前部署模式对应的配置文件模板读取）。
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
    curl -fsS -X "$method" "$url" >/dev/null 2>&1
    return $?
  fi
  if command -v wget >/dev/null 2>&1; then
    if [[ "$method" == "POST" ]]; then
      wget -q -O - --method=POST --body-data='' "$url" >/dev/null 2>&1
    else
      wget -q -O - "$url" >/dev/null 2>&1
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
  local interval_seconds="${5:-2}"
  local logfile="${6:-}"

  if [[ "$IS_TTY" != true ]]; then
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
  fi

  cursor_hide
  local start_ts
  start_ts=$(date +%s)
  local i=0
  local spin_len=${#SPIN_FRAMES[@]}
  local last_probe=0
  local probe_ok=false

  while true; do
    local now
    now=$(date +%s)
    local elapsed=$((now - start_ts))

    if (( now - last_probe >= interval_seconds )) || (( last_probe == 0 )); then
      if http_probe "$method" "$url"; then
        probe_ok=true
        break
      fi
      last_probe=$now
    fi

    if (( elapsed >= timeout_seconds )); then
      break
    fi

    local frame="${SPIN_FRAMES[$i]}"
    printf "\r   ${CYAN}%s${NC} waiting for %s service to become ready ${DIM}(%ds / %ds)...${NC}" "$frame" "$label" "$elapsed" "$timeout_seconds"
    i=$(( (i + 1) % spin_len ))
    sleep 0.08
  done

  cursor_show
  printf "\r\033[K"

  local total_elapsed=$(( $(date +%s) - start_ts ))
  if [[ "$probe_ok" == true ]]; then
    info "$label ready: $url ${DIM}(took ${total_elapsed}s)${NC}"
    return 0
  else
    err "$label did not become ready within ${timeout_seconds}s: $url"
    if [[ -n "$logfile" && -f "$logfile" ]]; then
      echo -e "   ${YELLOW}↳${NC} ${label} log:"
      tail -n 60 "$logfile" || true
    fi
    return 1
  fi
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

verify_ollama_binary() {
  local binary="$1"
  local output rc

  chmod +x "$binary" 2>/dev/null || true
  if command -v timeout >/dev/null 2>&1; then
    output=$(timeout 10 "$binary" --version 2>&1) || rc=$?
  else
    output=$("$binary" --version 2>&1) || rc=$?
  fi
  rc=${rc:-0}

  if [[ $rc -ne 0 ]]; then
    err "ollama binary is invalid or incomplete: $binary"
    if [[ -n "$output" ]]; then
      detail "$output"
    fi
    detail "Please replace the offline Ollama package with a complete Linux x86_64 binary."
    exit 1
  fi
}

ensure_go_compiler() {
  # 优先检测本地已安装的高版本 Go 路径（例如 /usr/local/go/bin、/snap/bin）
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
}

select_taa_config_template() {
  if [[ "$DEPLOY_LOCAL" == true ]]; then
    printf '%s' "$TAA_LOCAL_CONFIG_TEMPLATE"
  elif [[ "$DEPLOY_DOCKER" == true ]]; then
    if [[ -f "$TAA_DOCKER_CONFIG_TEMPLATE" ]]; then
      printf '%s' "$TAA_DOCKER_CONFIG_TEMPLATE"
    else
      printf '%s' "$TAA_LOCAL_CONFIG_TEMPLATE"
    fi
  elif [[ "$DEBUG" == true ]]; then
    printf '%s' "$TAA_DEBUG_CONFIG_TEMPLATE"
  else
    printf '%s' "$TAA_PRODUCTION_CONFIG_TEMPLATE"
  fi
}

get_taa_config_llm_model() {
  local template="$1"
  if [[ -f "$template" ]]; then
    python3 - "$template" <<'PY' 2>/dev/null || true
import json, sys
try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        data = json.load(f)
    model = (data.get("llm") or {}).get("model")
    if model and isinstance(model, str) and model.strip():
        print(model.strip())
except Exception:
    pass
PY
  fi
}

resolve_target_ollama_model() {
  if [[ -n "$CLI_MODEL" ]]; then
    printf '%s' "$CLI_MODEL"
    return 0
  fi
  local template
  template="$(select_taa_config_template)"
  local model
  model="$(get_taa_config_llm_model "$template")"
  if [[ -n "$model" ]]; then
    printf '%s' "$model"
    return 0
  fi
  if [[ -n "$ENV_OLLAMA_MODEL" ]]; then
    printf '%s' "$ENV_OLLAMA_MODEL"
    return 0
  fi
  printf '%s' "qwen2.5-coder:0.5b"
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

workdir = "/root/taa"
if model_dir and "/" in model_dir:
    workdir = model_dir.rsplit("/", 1)[0]

attestation = cfg.setdefault("attestation", {})
attestation["hrkCertPath"] = f"{workdir}/certs/hrk.cert"
attestation["hskCekCertPath"] = f"{workdir}/certs/hsk_cek.cert"

with open(path, "w", encoding="utf-8") as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
    f.write("\n")
PY
}

resolve_ollama_model_artifacts() {
  local dir="$1"
  local model="$2"
  local mode="${3:-full}"
  local dest_prefix="${4:-}"
  require_command python3
  python3 - "$dir" "$model" "$mode" "$dest_prefix" <<'PY'
import os, sys, json

ollama_dir = sys.argv[1]
model_name = sys.argv[2]
mode = sys.argv[3] if len(sys.argv) > 3 else "full"
dest_prefix = sys.argv[4] if len(sys.argv) > 4 else ""

if ":" in model_name:
    base_name, tag = model_name.split(":", 1)
else:
    base_name, tag = model_name, "latest"

parts = base_name.split("/")
if len(parts) == 1:
    manifest_rel = os.path.join("models", "models", "manifests", "registry.ollama.ai", "library", parts[0], tag)
elif len(parts) == 2:
    manifest_rel = os.path.join("models", "models", "manifests", "registry.ollama.ai", parts[0], parts[1], tag)
else:
    manifest_rel = os.path.join("models", "models", "manifests", *parts, tag)

manifest_full = os.path.join(ollama_dir, manifest_rel)
if not os.path.isfile(manifest_full):
    candidates = []
    manifests_root = os.path.join(ollama_dir, "models", "models", "manifests")
    if os.path.isdir(manifests_root):
        for root, dirs, files in os.walk(manifests_root):
            for f in files:
                if f == tag and os.path.basename(root) == parts[-1]:
                    candidates.append(os.path.relpath(os.path.join(root, f), ollama_dir))
    if candidates:
        manifest_rel = candidates[0]
        manifest_full = os.path.join(ollama_dir, manifest_rel)
    else:
        sys.stderr.write(f"Error: model '{model_name}' manifest not found at {manifest_full}\n")
        sys.exit(1)

with open(manifest_full, "r", encoding="utf-8") as fp:
    data = json.load(fp)

blobs = []
if "config" in data and "digest" in data["config"]:
    blobs.append(data["config"]["digest"].replace(":", "-"))
for layer in data.get("layers", []):
    if "digest" in layer:
        blobs.append(layer["digest"].replace(":", "-"))

blobs = sorted(list(set(blobs)))
blob_rel_paths = []
weight_bytes = 0
for b in blobs:
    p = os.path.join("models", "models", "blobs", b)
    full_p = os.path.join(ollama_dir, p)
    if not os.path.isfile(full_p):
        sys.stderr.write(f"Error: missing required blob for model '{model_name}': {full_p}\n")
        sys.exit(1)
    blob_rel_paths.append(p)
    weight_bytes += os.path.getsize(full_p)

base_items = ["ollama", "start-ollama.sh", "lib"]
for opt in ["models/cache", "models/models/cache", "models/models/id_ed25519", "models/models/id_ed25519.pub"]:
    if os.path.exists(os.path.join(ollama_dir, opt)):
        base_items.append(opt)

model_only_items = [manifest_rel] + blob_rel_paths
full_items = base_items + model_only_items

if mode == "json":
    res = {
        "manifest_rel": manifest_rel,
        "blobs_rel": blob_rel_paths,
        "weight_mb": round(weight_bytes / (1024 * 1024), 2),
        "base_items": base_items,
        "model_only_items": model_only_items,
        "full_items": full_items
    }
    print(json.dumps(res))
elif mode == "model_only":
    for it in model_only_items:
        print(it)
elif mode == "base_only":
    for it in base_items:
        print(it)
elif mode == "check_model_sh":
    prefix = dest_prefix.rstrip("/") + "/" if dest_prefix else ""
    tests = [f'test -s "{prefix}{manifest_rel}"']
    for b in blob_rel_paths:
        tests.append(f'test -s "{prefix}{b}"')
    print(" && ".join(tests))
else:
    for it in full_items:
        print(it)
PY
}

ACTION=""

if [[ $# -eq 0 ]]; then
  DEPLOY_PLATFORM_MOCK=true
  DEPLOY_TAA=true
  DEPLOY_QWEN=true
  ACTION="start"
  DEPLOY_REMOTE=true
else
  while [[ $# -gt 0 ]]; do
    arg="$1"
    case "$arg" in
      docker)
        DEPLOY_DOCKER=true
        ;;
      local|local-docker)
        err "'$arg' mode has been removed. Please use 'docker' for local container deployment or 'remote' for remote deployment."
        usage >&2
        exit 1
        ;;
      remote)
        DEPLOY_REMOTE=true
        ;;
      start)
        if [[ -n "$ACTION" && "$ACTION" != "start" ]]; then
          err "cannot specify multiple actions (start/stop/save)"
          usage >&2
          exit 1
        fi
        ACTION="start"
        ;;
      stop)
        if [[ -n "$ACTION" && "$ACTION" != "stop" ]]; then
          err "cannot specify multiple actions (start/stop/save)"
          usage >&2
          exit 1
        fi
        ACTION="stop"
        ;;
      save)
        if [[ -n "$ACTION" && "$ACTION" != "save" ]]; then
          err "cannot specify multiple actions (start/stop/save)"
          usage >&2
          exit 1
        fi
        ACTION="save"
        ;;
      --clean|--prune)
        SAVE_CLEAN=true
        ;;
      --archive=*|--output=*)
        CUSTOM_SAVE_ARCHIVE="${arg#*=}"
        LOCAL_DOCKER_IMAGE_ARCHIVE="${arg#*=}"
        ;;
      --archive|--output|-o)
        shift
        if [[ $# -eq 0 || "$1" == -* ]]; then
          err "$arg requires a file path argument"
          usage >&2
          exit 1
        fi
        CUSTOM_SAVE_ARCHIVE="$1"
        LOCAL_DOCKER_IMAGE_ARCHIVE="$1"
        ;;
      --image=*|--tag=*)
        CUSTOM_SAVE_IMAGE="${arg#*=}"
        LOCAL_DOCKER_IMAGE="${arg#*=}"
        ;;
      --image|--tag)
        shift
        if [[ $# -eq 0 || "$1" == -* ]]; then
          err "$arg requires an image name argument"
          usage >&2
          exit 1
        fi
        CUSTOM_SAVE_IMAGE="$1"
        LOCAL_DOCKER_IMAGE="$1"
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
      --config=*)
        CUSTOM_SAVE_CONFIG="${arg#*=}"
        ;;
      --config)
        shift
        if [[ $# -eq 0 || "$1" == -* ]]; then
          err "$arg requires a config path argument"
          usage >&2
          exit 1
        fi
        CUSTOM_SAVE_CONFIG="$1"
        ;;
      --container=*)
        LOCAL_DOCKER_CONTAINER="${arg#*=}"
        ;;
      --container)
        shift
        if [[ $# -eq 0 || "$1" == -* ]]; then
          err "$arg requires a container name argument"
          usage >&2
          exit 1
        fi
        LOCAL_DOCKER_CONTAINER="$1"
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

  ACTION="${ACTION:-start}"

  mode_count=0
  [[ "$DEPLOY_LOCAL" == true ]] && ((mode_count++)) || true
  [[ "$DEPLOY_DOCKER" == true ]] && ((mode_count++)) || true
  [[ "$DEPLOY_REMOTE" == true ]] && ((mode_count++)) || true

  if (( mode_count > 1 )); then
    err "cannot specify multiple deploy modes (local, docker, remote are mutually exclusive)"
    usage >&2
    exit 1
  fi

  if (( mode_count == 0 )); then
    if [[ "$ACTION" == "save" ]]; then
      err "save action is only supported in docker mode"
      detail "Use '$(basename "$0") docker save' to package and export the production Docker image archive."
      exit 1
    fi
    DEPLOY_REMOTE=true
  fi

  if [[ "$SELECTED_COMPONENT" == false ]]; then
    if [[ "$DEBUG" == false && "$DEPLOY_LOCAL" == false && "$DEPLOY_DOCKER" == false ]]; then
      # 正式远程部署模式下，宿主机已有生产管控平台 (如 ccs-node-agent) 监听 18080，默认不部署 platform-mock
      DEPLOY_PLATFORM_MOCK=false
    else
      DEPLOY_PLATFORM_MOCK=true
    fi
    DEPLOY_TAA=true
    DEPLOY_QWEN=true
  fi

  if [[ "$DEPLOY_PLATFORM_MOCK" == true && "$DEPLOY_LOCAL" == false && "$DEPLOY_DOCKER" == false && "$DEBUG" == false && "$PLATFORM_PORT" == "18080" ]]; then
    warn "远程宿主机 18080 端口通常由生产平台 (如 ccs-node-agent) 占用；若需调试 platform-mock，建议设置 DEBUG=true (使用 28080 端口) 或指定 PLATFORM_PORT"
  fi
fi

cd "$PROJECT_DIR"

wait_for_remote_taa_ready() {
  local wait_start_ts
  wait_start_ts=$(date +%s)
  local ready_attempts=$(( (OLLAMA_READY_TIMEOUT + OLLAMA_READY_INTERVAL - 1) / OLLAMA_READY_INTERVAL ))
  local taa_ready=false
  cursor_hide
  local spin_len=${#SPIN_FRAMES[@]}
  local i=0
  for ((attempt=1; attempt<=ready_attempts; attempt++)); do
    if remote_ssh "$(container_exec) curl -fsS -X POST http://127.0.0.1:$CON_PORT/v1/taa/health >/dev/null 2>&1"; then
      taa_ready=true
      break
    fi
    if [[ "$IS_TTY" == true ]]; then
      local now
      now=$(date +%s)
      local elapsed=$((now - wait_start_ts))
      local frame="${SPIN_FRAMES[$i]}"
      printf "\r   ${CYAN}%s${NC} waiting for remote taa service to become ready ${DIM}(%ds / %ds)...${NC}" "$frame" "$elapsed" "$OLLAMA_READY_TIMEOUT"
      i=$(( (i + 1) % spin_len ))
    fi
    sleep "$OLLAMA_READY_INTERVAL"
  done
  cursor_show
  printf "\r\033[K"
  if [[ "$taa_ready" == true ]]; then
    local total_elapsed=$(( $(date +%s) - wait_start_ts ))
    info "remote taa ready: http://127.0.0.1:$CON_PORT/v1/taa/health ${DIM}(took ${total_elapsed}s)${NC}"
    return 0
  else
    err "remote taa did not become ready within ${OLLAMA_READY_TIMEOUT}s"
    remote_ssh "$(container_exec) tail -n 50 $TAA_LOG_FILE || true"
    return 1
  fi
}

if [[ "$ACTION" == "stop" ]]; then
  banner "Stopping Services"
  if [[ "$DEPLOY_LOCAL" == true ]]; then
    step "stopping local host processes"
    stop_selected_local_processes
  elif [[ "$DEPLOY_DOCKER" == true ]]; then
    step "stopping docker services"
    [[ "$DEPLOY_PLATFORM_MOCK" == true ]] && stop_pidfile "platform-mock" "$LOCAL_RUN_DIR/platform-mock.pid"
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
      remote_ssh "$(container_exec) sh -lc 'touch \"$TAA_CONTAINER_WORKDIR/manual\" && pkill -x taa >/dev/null 2>&1 || true; killall taa >/dev/null 2>&1 || true'"
    fi
    if [[ "$DEPLOY_QWEN" == true ]]; then
      remote_ssh "$(container_exec) sh -lc 'killall ollama >/dev/null 2>&1 || true; pkill -x ollama >/dev/null 2>&1 || true; killall llama-server >/dev/null 2>&1 || true; pkill -x llama-server >/dev/null 2>&1 || true'"
    fi
  fi
  info "all target services stopped cleanly"
  exit 0
fi

if [[ "$ACTION" == "save" ]]; then
  if [[ "$DEPLOY_DOCKER" != true ]]; then
    err "save action is only supported in docker mode"
    detail "Use '$(basename "$0") docker save' to package and export the production Docker image archive."
    exit 1
  fi
  save_local_docker_image
  exit 0
fi

# 用户可见的平台标签：DEBUG 模式显示 "platform-mock"，生产模式显示 "platform"
PLATFORM_LABEL="platform"
if [[ "$DEBUG" == true || "$DEPLOY_LOCAL" == true || "$DEPLOY_DOCKER" == true ]]; then
  PLATFORM_LABEL="platform-mock"
fi

# 容器标识显示名：docker 模式显示本地容器名，local 模式显示 local host，k8s 模式显示 Pod 名。
if [[ "$DEPLOY_DOCKER" == true ]]; then
  CONTAINER_LABEL="${LOCAL_DOCKER_CONTAINER}"
elif [[ "$DEPLOY_LOCAL" == true ]]; then
  CONTAINER_LABEL="local host"
else
  CONTAINER_LABEL="${TARGET_POD}"
fi
REMOTE_DOCKER_ID="${REMOTE_DOCKER_ID:-$CONTAINER_LABEL}"

DEPLOY_COMPONENTS=""
[[ "$DEPLOY_PLATFORM_MOCK" == true ]] && DEPLOY_COMPONENTS+="$PLATFORM_LABEL "
[[ "$DEPLOY_TAA" == true ]] && DEPLOY_COMPONENTS+="taa "
[[ "$DEPLOY_QWEN" == true ]] && DEPLOY_COMPONENTS+="qwen "
DEPLOY_TARGET_DESC="${REMOTE_USER}@${REMOTE_HOST}"
if [[ "$DEPLOY_DOCKER" == true ]]; then
  DEPLOY_TARGET_DESC="local docker (${LOCAL_DOCKER_CONTAINER})"
elif [[ "$DEPLOY_LOCAL" == true ]]; then
  DEPLOY_TARGET_DESC="local host"
fi
OLLAMA_MODEL="$(resolve_target_ollama_model)"
banner "Deploying: ${DEPLOY_COMPONENTS}→ ${DEPLOY_TARGET_DESC}" "Target model: ${OLLAMA_MODEL}"

if [[ "$DEPLOY_PLATFORM_MOCK" == true ]]; then
  ensure_go_compiler
  ensure_parent_dir "$MOCK_BINARY_PATH"
  spin_task "building platform-mock from ./cmd/platform-mock" go build -o "$MOCK_BINARY_PATH" ./cmd/platform-mock
fi
if [[ "$DEPLOY_QWEN" == true ]]; then
  require_dir "ollama package not found" "$OLLAMA_LOCAL_DIR"
  require_file "ollama package is incomplete" "$OLLAMA_LOCAL_DIR/ollama"
  require_file "ollama package is incomplete" "$OLLAMA_LOCAL_DIR/start-ollama.sh"
  require_dir "ollama package is incomplete" "$OLLAMA_LOCAL_DIR/models/models"
  require_dir "ollama package is incomplete" "$OLLAMA_LOCAL_DIR/lib/ollama"
  verify_ollama_binary "$OLLAMA_LOCAL_DIR/ollama"
  if [[ "$OLLAMA_PRUNE_SYNC" == true ]]; then
    model_meta="$(resolve_ollama_model_artifacts "$OLLAMA_LOCAL_DIR" "$OLLAMA_MODEL" "json")"
    model_mb="$(python3 -c 'import sys, json; print(json.loads(sys.argv[1])["weight_mb"])' "$model_meta" 2>/dev/null || echo "unknown")"
    info "ollama package: $OLLAMA_LOCAL_DIR (target model: $OLLAMA_MODEL, weights: ${model_mb}MB, prune sync: enabled)"
  else
    info "ollama package: $(du -sh "$OLLAMA_LOCAL_DIR" | awk '{print $1}') at $OLLAMA_LOCAL_DIR (full sync)"
  fi
fi

if [[ "$DEPLOY_TAA" == true ]]; then
  ensure_go_compiler
  ensure_parent_dir "$TAA_BINARY_PATH"
  spin_task "building taa daemon from ./cmd/taa" go build -o "$TAA_BINARY_PATH" ./cmd/taa
fi

if [[ "$DEPLOY_PLATFORM_MOCK" == true && ! -f "$MOCK_BINARY_PATH" ]]; then
  err "build failed: $MOCK_BINARY_PATH not found"
  exit 1
fi
if [[ "$DEPLOY_TAA" == true ]]; then
  require_file "build verification failed (taa binary missing)" "$TAA_BINARY_PATH"
  require_file "certificate missing" "$ATT_HRK_SOURCE"
  require_file "certificate missing" "$ATT_HSK_SOURCE"
fi


deploy_platform_mock() {
  step "preparing local platform-mock runtime directory"
  mkdir -p "$LOCAL_PLATFORM_STATE_DIR" "$LOCAL_PLATFORM_UPLOAD_DIR" "$LOCAL_RUN_DIR"
  info "runtime directories ready: $LOCAL_PLATFORM_STATE_DIR"

  step "starting local platform-mock on ${LOCAL_PLATFORM_BIND}"
  start_local_background "platform-mock" "$LOCAL_RUN_DIR/platform-mock.pid" "$LOCAL_PLATFORM_LOG_FILE" \
    "$MOCK_BINARY_PATH" -addr "$LOCAL_PLATFORM_BIND" -state-dir "$LOCAL_PLATFORM_STATE_DIR" -upload-dir "$LOCAL_PLATFORM_UPLOAD_DIR" -taa-target "$LOCAL_TAA_URL" -allow-empty-attestation
  wait_for_http_ready "platform-mock" GET "$LOCAL_PLATFORM_URL/api/register/status" "$OLLAMA_READY_TIMEOUT" "$OLLAMA_READY_INTERVAL" "$LOCAL_PLATFORM_LOG_FILE"
}

deploy_docker_qwen() {
  step "preparing ollama/qwen dependencies inside container"
  stop_pidfile "ollama" "$LOCAL_RUN_DIR/ollama.pid"
  pkill -f "$OLLAMA_LOCAL_DIR/ollama" >/dev/null 2>&1 || true
  docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc 'pkill -x ollama >/dev/null 2>&1 || true; pkill -x llama-server >/dev/null 2>&1 || true' >/dev/null 2>&1 || true
  for _ in {1..20}; do
    if ! docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "pgrep -x ollama >/dev/null 2>&1"; then
      break
    fi
    sleep 0.2
  done

  docker exec -i "$LOCAL_DOCKER_CONTAINER" mkdir -p "$TAA_CONTAINER_WORKDIR"

  if [[ "$OLLAMA_PRUNE_SYNC" == true ]]; then
    local model_meta model_mb check_script has_base_runtime has_lib has_model
    model_meta="$(resolve_ollama_model_artifacts "$OLLAMA_LOCAL_DIR" "$OLLAMA_MODEL" "json")"
    model_mb="$(python3 -c 'import sys, json; print(json.loads(sys.argv[1])["weight_mb"])' "$model_meta")"
    check_script="$(resolve_ollama_model_artifacts "$OLLAMA_LOCAL_DIR" "$OLLAMA_MODEL" "check_model_sh" "$CONTAINER_OLLAMA_DIR")"

    has_base_runtime=false
    has_lib=false
    has_model=false

    if docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "test -f '$CONTAINER_OLLAMA_DIR/ollama' && test -f '$CONTAINER_OLLAMA_DIR/start-ollama.sh' && test -f '$CONTAINER_OLLAMA_DIR/lib/ollama/libllama-server-impl.so'"; then
      has_base_runtime=true
    fi
    if docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "test -f '$CONTAINER_OLLAMA_DIR/lib/ollama/libllama-server-impl.so'"; then
      has_lib=true
    fi
    if docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "$check_script" >/dev/null 2>&1; then
      has_model=true
    fi

    if [[ "$FORCE_QWEN_COPY" == false && "$has_base_runtime" == true && "$has_model" == true ]]; then
      info "ollama runtime and target model '$OLLAMA_MODEL' (${model_mb}MB) already present in container ($CONTAINER_OLLAMA_DIR)"
    elif [[ "$FORCE_QWEN_COPY" == false && "$has_base_runtime" == true && "$has_model" == false ]]; then
      step "incrementally copying model '$OLLAMA_MODEL' (${model_mb}MB) into container"
      docker exec -i "$LOCAL_DOCKER_CONTAINER" mkdir -p "$CONTAINER_OLLAMA_DIR"
      local qwen_filelist="$LOCAL_RUN_DIR/docker_qwen_files_$$.txt"
      ensure_parent_dir "$qwen_filelist"
      resolve_ollama_model_artifacts "$OLLAMA_LOCAL_DIR" "$OLLAMA_MODEL" "model_only" > "$qwen_filelist"
      spin_task "transferring model weights (${model_mb}MB) into container" bash -c '
        set -euo pipefail
        tar -C "$1" -cf - -T "$2" | docker exec -i "$3" tar -xf - -C "$4"
      ' _ "$OLLAMA_LOCAL_DIR" "$qwen_filelist" "$LOCAL_DOCKER_CONTAINER" "$CONTAINER_OLLAMA_DIR"
      rm -f "$qwen_filelist"
      info "incremental model transfer completed"
    else
      step "copying pruned ollama runtime and model '$OLLAMA_MODEL' (${model_mb}MB) into container"
      docker exec -i "$LOCAL_DOCKER_CONTAINER" mkdir -p "$CONTAINER_OLLAMA_DIR"
      local qwen_filelist="$LOCAL_RUN_DIR/docker_qwen_files_$$.txt"
      ensure_parent_dir "$qwen_filelist"
      if [[ "$FORCE_QWEN_COPY" == true ]]; then
        docker exec -i "$LOCAL_DOCKER_CONTAINER" rm -rf "$CONTAINER_OLLAMA_DIR"
        docker exec -i "$LOCAL_DOCKER_CONTAINER" mkdir -p "$CONTAINER_OLLAMA_DIR"
        resolve_ollama_model_artifacts "$OLLAMA_LOCAL_DIR" "$OLLAMA_MODEL" "full" > "$qwen_filelist"
        spin_task "transferring pruned ollama bundle into container" bash -c '
          set -euo pipefail
          tar -C "$1" -cf - -T "$2" | docker exec -i "$3" tar -xf - -C "$4"
        ' _ "$OLLAMA_LOCAL_DIR" "$qwen_filelist" "$LOCAL_DOCKER_CONTAINER" "$CONTAINER_OLLAMA_DIR"
      elif [[ "$has_lib" == true ]]; then
        info "reusing existing lib directory in container, copying runtime binaries and model"
        {
          echo "ollama"
          echo "start-ollama.sh"
          for opt in "models/cache" "models/models/cache" "models/models/id_ed25519" "models/models/id_ed25519.pub"; do
            [[ -e "$OLLAMA_LOCAL_DIR/$opt" ]] && echo "$opt"
          done
          resolve_ollama_model_artifacts "$OLLAMA_LOCAL_DIR" "$OLLAMA_MODEL" "model_only"
        } > "$qwen_filelist"
        spin_task "transferring runtime binaries and model weights" bash -c '
          set -euo pipefail
          tar -C "$1" -cf - -T "$2" | docker exec -i "$3" tar -xf - -C "$4"
        ' _ "$OLLAMA_LOCAL_DIR" "$qwen_filelist" "$LOCAL_DOCKER_CONTAINER" "$CONTAINER_OLLAMA_DIR"
      else
        resolve_ollama_model_artifacts "$OLLAMA_LOCAL_DIR" "$OLLAMA_MODEL" "full" > "$qwen_filelist"
        spin_task "transferring full ollama bundle into container" bash -c '
          set -euo pipefail
          tar -C "$1" -cf - -T "$2" | docker exec -i "$3" tar -xf - -C "$4"
        ' _ "$OLLAMA_LOCAL_DIR" "$qwen_filelist" "$LOCAL_DOCKER_CONTAINER" "$CONTAINER_OLLAMA_DIR"
      fi
      rm -f "$qwen_filelist"
      info "ollama package transfer completed"
    fi
  else
    local need_copy=true
    if [[ "$FORCE_QWEN_COPY" == false ]]; then
      if docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "test -f '$CONTAINER_OLLAMA_DIR/ollama' && test -f '$CONTAINER_OLLAMA_DIR/start-ollama.sh' && test -d '$CONTAINER_OLLAMA_DIR/models/models' && test -d '$CONTAINER_OLLAMA_DIR/lib/ollama'"; then
        need_copy=false
        info "ollama package already present inside container ($CONTAINER_OLLAMA_DIR)"
      fi
    fi

    if [[ "$need_copy" == true ]]; then
      step "copying ollama package into container ($LOCAL_DOCKER_CONTAINER:$CONTAINER_OLLAMA_DIR)"
      docker exec -i "$LOCAL_DOCKER_CONTAINER" rm -rf "$CONTAINER_OLLAMA_DIR"
      spin_task "transferring offline bundle into container" bash -c '
        set -euo pipefail
        if command -v tar >/dev/null 2>&1 && docker exec -i "$1" sh -lc "command -v tar >/dev/null 2>&1"; then
          tar -C "$(dirname "$2")" -cf - "$(basename "$2")" | docker exec -i "$1" tar -xf - -C "$3"
        else
          docker cp "$2" "$1:$4"
        fi
      ' _ "$LOCAL_DOCKER_CONTAINER" "$OLLAMA_LOCAL_DIR" "$TAA_CONTAINER_WORKDIR" "$CONTAINER_OLLAMA_DIR"
      info "ollama package transfer completed"
    fi
  fi

  docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "chmod +x '$CONTAINER_OLLAMA_DIR/ollama' '$CONTAINER_OLLAMA_DIR/start-ollama.sh'"

  # 动态链接器及向后兼容��链接
  local hardcoded_path="/taatest/ollama-qwen2.5-coder-0.5b"
  if [[ "$CONTAINER_OLLAMA_DIR" != "$hardcoded_path" ]]; then
    step "creating symlink for dynamic linker compatibility inside container"
    docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "mkdir -p /taatest && rm -rf '$hardcoded_path' && ln -s '$CONTAINER_OLLAMA_DIR' '$hardcoded_path'"
    info "symlink created: $hardcoded_path → $CONTAINER_OLLAMA_DIR"
  fi
  local legacy_container_path="$TAA_CONTAINER_WORKDIR/ollama-qwen2.5-coder-0.5b"
  if [[ "$CONTAINER_OLLAMA_DIR" != "$legacy_container_path" ]]; then
    docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "rm -rf '$legacy_container_path' && ln -s '$CONTAINER_OLLAMA_DIR' '$legacy_container_path'"
  fi

  step "starting ollama inside container"
  docker exec -d "$LOCAL_DOCKER_CONTAINER" sh -lc "cd '$CONTAINER_OLLAMA_DIR' && exec env OLLAMA_HOST='$OLLAMA_HOST' OLLAMA_MODELS='$CONTAINER_OLLAMA_DIR/models/models' OLLAMA_LIBRARY_PATH='$CONTAINER_OLLAMA_DIR/lib/ollama' ./start-ollama.sh > '$OLLAMA_LOG_FILE' 2>&1"
  if ! wait_for_http_ready "ollama" GET "$LOCAL_OLLAMA_URL/api/tags" "$OLLAMA_READY_TIMEOUT" "$OLLAMA_READY_INTERVAL"; then
    echo -e "   ${YELLOW}↳${NC} ollama container log (${OLLAMA_LOG_FILE}):"
    docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "tail -n 60 '$OLLAMA_LOG_FILE' 2>/dev/null || true"
    exit 1
  fi
}

deploy_docker_taa() {
  step "preparing runtime directories inside container"
  docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "mkdir -p '$TAA_CONTAINER_WORKDIR/models' '$TAA_CONTAINER_WORKDIR/data' '$TAA_CONTAINER_WORKDIR/results' '$TAA_CONTAINER_WORKDIR/certs' '$TAA_CONTAINER_WORKDIR/keys' '$LOCAL_DOCKER_INPUT_DIR' '$LOCAL_DOCKER_OUTPUT_DIR' && chmod 700 '$TAA_CONTAINER_WORKDIR/keys'" >/dev/null 2>&1
  info "runtime directories initialized: $TAA_CONTAINER_WORKDIR"

  step "copying taa binary and certificates into container"
  spin_task "copying binary and certificates into container" bash -c '
    set -euo pipefail
    docker cp "$1" "$2:$3/$4" >/dev/null
    docker cp "$5" "$2:$3/certs/hrk.cert" >/dev/null
    docker cp "$6" "$2:$3/certs/hsk_cek.cert" >/dev/null
    docker exec -i "$2" sh -lc "chmod +x \"$3/$4\"" >/dev/null
  ' _ "$TAA_BINARY_PATH" "$LOCAL_DOCKER_CONTAINER" "$TAA_CONTAINER_WORKDIR" "$BINARY_NAME" "$ATT_HRK_SOURCE" "$ATT_HSK_SOURCE"

  step "checking attestation prerequisites inside container"
  if ! docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc 'test -e /dev/csv-guest' 2>/dev/null; then
    warn "/dev/csv-guest not found in container — attestation will fail (expected in non-TEE Docker)"
  else
    info "attestation device /dev/csv-guest verified"
  fi

  TAA_CONFIG_TEMPLATE="$(select_taa_config_template)"
  step "writing taa config for docker from $(basename "$TAA_CONFIG_TEMPLATE")"
  ensure_parent_dir "$LOCAL_DOCKER_CONFIG_SOURCE"
  write_taa_config "$LOCAL_DOCKER_CONFIG_SOURCE" "$TAA_CONFIG_TEMPLATE" "$TAA_CONTAINER_ADDR" "$LOCAL_PLATFORM_IP" "$LOCAL_DOCKER_CONTAINER" "$CONTRACT" "$TAA_CONTAINER_WORKDIR/models" "$TAA_CONTAINER_WORKDIR/data" "$TAA_CONTAINER_WORKDIR/results" "$CONTAINER_OLLAMA_DIR" "$LOCAL_OLLAMA_URL" "$OLLAMA_MODEL" true "$LOCAL_DOCKER_INPUT_DIR" "$LOCAL_DOCKER_OUTPUT_DIR" "$TAA_CONTAINER_WORKDIR/keys"
  docker cp "$LOCAL_DOCKER_CONFIG_SOURCE" "$LOCAL_DOCKER_CONTAINER:$CONTAINER_TAA_CONFIG_PATH" >/dev/null
  info "config written to container: $CONTAINER_TAA_CONFIG_PATH"

  step "stopping old taa inside container"
  stop_pidfile "taa" "$LOCAL_RUN_DIR/taa.pid"
  pkill -f "$TAA_BINARY_PATH" >/dev/null 2>&1 || true
  docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "pkill -x '$BINARY_NAME' >/dev/null 2>&1 || true; killall '$BINARY_NAME' >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
  for _ in {1..30}; do
    if ! docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "pgrep -x '$BINARY_NAME' >/dev/null 2>&1"; then
      break
    fi
    sleep 0.2
  done
  info "stopped previous taa daemon"

  step "starting taa inside container"
  docker exec -d "$LOCAL_DOCKER_CONTAINER" sh -lc "cd '$TAA_CONTAINER_WORKDIR' && nohup '$TAA_CONTAINER_WORKDIR/$BINARY_NAME' > '$TAA_LOG_FILE' 2>&1 &"

  step "waiting for taa service to become ready"
  if ! wait_for_http_ready "taa" POST "$LOCAL_TAA_URL/v1/taa/health" "$OLLAMA_READY_TIMEOUT" "$OLLAMA_READY_INTERVAL"; then
    echo -e "   ${YELLOW}↳${NC} taa container log (${TAA_LOG_FILE}):"
    docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "tail -n 60 '$TAA_LOG_FILE' 2>/dev/null || true"
    exit 1
  fi
}

if [[ "$DEPLOY_DOCKER" == true ]]; then
  require_command docker
  docker info >/dev/null 2>&1 || { err "docker daemon is not running or accessible"; exit 1; }

  # 如果需要部署 taa 或 qwen，先确保容器已就绪
  if [[ "$DEPLOY_TAA" == true || "$DEPLOY_QWEN" == true ]]; then
    ensure_local_docker_container
  fi

  # 1. 启动本地 platform-mock（若包含 platform-mock）
  if [[ "$DEPLOY_PLATFORM_MOCK" == true ]]; then
    deploy_platform_mock
  fi

  # 2. 部署 qwen / ollama 进本地容器
  if [[ "$DEPLOY_QWEN" == true ]]; then
    deploy_docker_qwen
  fi

  # 3. 部署 taa 进本地容器
  if [[ "$DEPLOY_TAA" == true ]]; then
    deploy_docker_taa
  fi

  banner "Deploy Complete (Docker)" "All requested services are running in Docker container and verified healthy"
  if [[ "$DEPLOY_PLATFORM_MOCK" == true ]]; then
    echo -e "  ${BOLD}${CYAN}● Platform Mock${NC}  ${DIM}(API & Storage Emulator)${NC}"
    echo -e "    ${MUTED}↳ Endpoint   :${NC} ${BOLD}${LOCAL_PLATFORM_URL}${NC}"
    echo -e "    ${MUTED}↳ State dir  :${NC} ${LOCAL_PLATFORM_STATE_DIR}"
    echo -e "    ${MUTED}↳ Upload dir :${NC} ${LOCAL_PLATFORM_UPLOAD_DIR}"
    echo -e "    ${MUTED}↳ Log file   :${NC} ${LOCAL_PLATFORM_LOG_FILE}"
    echo ""
  fi
  if [[ "$DEPLOY_QWEN" == true ]]; then
    echo -e "  ${BOLD}${CYAN}● Ollama / Qwen Runtime${NC}  ${DIM}(In-Container Service)${NC}"
    echo -e "    ${MUTED}↳ Endpoint   :${NC} ${BOLD}${LOCAL_OLLAMA_URL}${NC}"
    echo -e "    ${MUTED}↳ Target LLM :${NC} ${PURPLE}${OLLAMA_MODEL}${NC}"
    echo -e "    ${MUTED}↳ Path       :${NC} ${LOCAL_DOCKER_CONTAINER}:${CONTAINER_OLLAMA_DIR}"
    echo ""
  fi
  if [[ "$DEPLOY_TAA" == true ]]; then
    echo -e "  ${BOLD}${CYAN}● TAA Secure Enclave Daemon${NC}  ${DIM}(In-Container Daemon)${NC}"
    echo -e "    ${MUTED}↳ Health API :${NC} ${BOLD}${LOCAL_TAA_URL}/v1/taa/health${NC}"
    echo -e "    ${MUTED}↳ Container  :${NC} ${LOCAL_DOCKER_CONTAINER}"
    echo -e "    ${MUTED}↳ Config     :${NC} ${CONTAINER_TAA_CONFIG_PATH}"
    echo -e "    ${MUTED}↳ Log file   :${NC} ${TAA_LOG_FILE}"
    echo -e "    ${MUTED}↳ Keys dir   :${NC} ${LOCAL_DOCKER_CONTAINER}:${TAA_CONTAINER_WORKDIR}/keys"
    echo -e "    ${MUTED}↳ Platform   :${NC} ${LOCAL_PLATFORM_IP}"
    echo -e "    ${MUTED}↳ Attestation:${NC} ${ATT_REPORT_FILE}"
    echo ""
  fi
  exit 0
fi

ensure_remote_ssh

sync_ollama_to_remote() {
  step "syncing ollama package to remote host"
  remote_ssh "mkdir -p '$REMOTE_OLLAMA_DIR'"

  if [[ "$OLLAMA_PRUNE_SYNC" == true ]]; then
    local model_meta model_mb
    model_meta="$(resolve_ollama_model_artifacts "$OLLAMA_LOCAL_DIR" "$OLLAMA_MODEL" "json")"
    model_mb="$(python3 -c 'import sys, json; print(json.loads(sys.argv[1])["weight_mb"])' "$model_meta")"
    info "pruning sync for model '$OLLAMA_MODEL' (${model_mb}MB) to remote host"

    # 若远程宿主机已有历史 0.5b 包的运行库且目标目录尚无 lib，优先复用避免重复跨网络传输数 GB 依赖库
    if remote_ssh "test -d '$REMOTE_DIR/ollama-qwen2.5-coder-0.5b/lib/ollama' && ! test -d '$REMOTE_OLLAMA_DIR/lib/ollama'"; then
      info "reusing existing lib on remote host from ollama-qwen2.5-coder-0.5b"
      remote_ssh "mkdir -p '$REMOTE_OLLAMA_DIR/lib' && cp -r -n '$REMOTE_DIR/ollama-qwen2.5-coder-0.5b/lib/ollama' '$REMOTE_OLLAMA_DIR/lib/'"
    fi

    local list_tmp
    list_tmp="$(mktemp /tmp/ollama_files.XXXXXX)"
    trap 'rm -f "$list_tmp"' EXIT INT TERM
    resolve_ollama_model_artifacts "$OLLAMA_LOCAL_DIR" "$OLLAMA_MODEL" "full" > "$list_tmp"

    if command -v rsync >/dev/null 2>&1 && remote_ssh "command -v rsync >/dev/null 2>&1"; then
      sshpass -p "$PASSWORD" rsync -a -r --exclude='*cuda*' --files-from="$list_tmp" --partial --info=progress2 \
        -e "ssh -q -o LogLevel=ERROR -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$HOME/.ssh/known_hosts" \
        "$OLLAMA_LOCAL_DIR/" \
        "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_OLLAMA_DIR/"
    else
      warn "rsync not available; streaming pruned tar archive to remote host"
      tar -C "$OLLAMA_LOCAL_DIR" --exclude='*cuda*' -czf - -T "$list_tmp" | \
        sshpass -p "$PASSWORD" ssh "${SSH_OPTS[@]}" "${REMOTE_USER}@${REMOTE_HOST}" "tar -xzf - -C '$REMOTE_OLLAMA_DIR'"
    fi
    rm -f "$list_tmp"
    trap - EXIT INT TERM
  else
    if command -v rsync >/dev/null 2>&1 && remote_ssh "command -v rsync >/dev/null 2>&1"; then
      sshpass -p "$PASSWORD" rsync -a -r --exclude='*cuda*' --delete --partial --info=progress2 \
        -e "ssh -q -o LogLevel=ERROR -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$HOME/.ssh/known_hosts" \
        "$OLLAMA_LOCAL_DIR/" \
        "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_OLLAMA_DIR/"
    else
      warn "rsync not available; falling back to scp -r (full 4GB+ upload)"
      remote_ssh "rm -rf '$REMOTE_OLLAMA_DIR.new' && mkdir -p '$REMOTE_DIR'"
      sshpass -p "$PASSWORD" scp -r "${SSH_OPTS[@]}" "$OLLAMA_LOCAL_DIR" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_OLLAMA_DIR.new"
      remote_ssh "rm -rf '$REMOTE_OLLAMA_DIR' && mv '$REMOTE_OLLAMA_DIR.new' '$REMOTE_OLLAMA_DIR'"
    fi
  fi

  if ! remote_ssh "test -f '$REMOTE_OLLAMA_DIR/ollama' && test -f '$REMOTE_OLLAMA_DIR/start-ollama.sh' && test -d '$REMOTE_OLLAMA_DIR/models/models' && test -f '$REMOTE_OLLAMA_DIR/lib/ollama/libllama-server-impl.so'"; then
    err "remote ollama package verification failed: missing required components in $REMOTE_OLLAMA_DIR (ollama, start-ollama.sh, models/models, lib/ollama/libllama-server-impl.so)"
    exit 1
  fi
  info "ollama package verified on remote host ($REMOTE_OLLAMA_DIR)"
}

copy_ollama_to_container() {
  step "checking ollama package inside container"
  remote_ssh "$(container_exec) sh -lc 'command -v tar >/dev/null 2>&1 || { echo kubectl exec requires tar inside the container; exit 1; }'"
  remote_ssh "command -v tar >/dev/null 2>&1 || { echo remote tar is required to package ollama; exit 1; }"

  # 清理容器内历史下载与测试临时文件，避免空间不足
  remote_ssh "$(container_exec) sh -lc 'rm -f /tmp/taa-download-* /tmp/taa-plaintext-* 2>/dev/null || true; rm -rf /tmp/taa-resource-info-* 2>/dev/null || true'"

  local legacy_container_path="$TAA_CONTAINER_WORKDIR/ollama-qwen2.5-coder-0.5b"
  if [[ "$CONTAINER_OLLAMA_DIR" != "$legacy_container_path" ]]; then
    if remote_ssh "$(container_exec) sh -lc 'test -d \"$legacy_container_path/lib/ollama\" && ! test -L \"$legacy_container_path\" && ! test -d \"$CONTAINER_OLLAMA_DIR/lib/ollama\"'" >/dev/null 2>&1; then
      info "migrating existing ollama runtime from $legacy_container_path to $CONTAINER_OLLAMA_DIR"
      remote_ssh "$(container_exec) sh -lc 'mkdir -p \"$TAA_CONTAINER_WORKDIR\" && if [ ! -d \"$CONTAINER_OLLAMA_DIR\" ]; then mv \"$legacy_container_path\" \"$CONTAINER_OLLAMA_DIR\"; ln -s \"$CONTAINER_OLLAMA_DIR\" \"$legacy_container_path\"; elif [ ! -d \"$CONTAINER_OLLAMA_DIR/lib\" ]; then cp -r -n \"$legacy_container_path/lib\" \"$CONTAINER_OLLAMA_DIR/\"; fi'"
    fi
  fi

  if [[ "$OLLAMA_PRUNE_SYNC" == true ]]; then
    local model_meta model_mb check_script has_base_runtime has_lib has_model
    model_meta="$(resolve_ollama_model_artifacts "$OLLAMA_LOCAL_DIR" "$OLLAMA_MODEL" "json")"
    model_mb="$(python3 -c 'import sys, json; print(json.loads(sys.argv[1])["weight_mb"])' "$model_meta")"
    check_script="$(resolve_ollama_model_artifacts "$OLLAMA_LOCAL_DIR" "$OLLAMA_MODEL" "check_model_sh" "$CONTAINER_OLLAMA_DIR")"

    has_base_runtime=false
    has_lib=false
    has_model=false

    if remote_ssh "$(container_exec) sh -lc 'test -f \"$CONTAINER_OLLAMA_DIR/ollama\" && test -f \"$CONTAINER_OLLAMA_DIR/start-ollama.sh\" && test -f \"$CONTAINER_OLLAMA_DIR/lib/ollama/libllama-server-impl.so\"'" >/dev/null 2>&1; then
      has_base_runtime=true
    fi
    if remote_ssh "$(container_exec) sh -lc 'test -f \"$CONTAINER_OLLAMA_DIR/lib/ollama/libllama-server-impl.so\"'" >/dev/null 2>&1; then
      has_lib=true
    fi
    if remote_ssh "$(container_exec) sh -lc '$check_script'" >/dev/null 2>&1; then
      has_model=true
    fi

    if [[ "$FORCE_QWEN_COPY" == false && "$has_base_runtime" == true && "$has_model" == true ]]; then
      info "ollama runtime and target model '$OLLAMA_MODEL' (${model_mb}MB) already present in container ($CONTAINER_OLLAMA_DIR)"
    elif [[ "$FORCE_QWEN_COPY" == false && "$has_base_runtime" == true && "$has_model" == false ]]; then
      step "stream-copying model '$OLLAMA_MODEL' (${model_mb}MB) into container ($CONTAINER_LABEL:$CONTAINER_OLLAMA_DIR)"
      remote_ssh "$(container_exec) sh -lc 'mkdir -p \"$CONTAINER_OLLAMA_DIR\"'"
      local file_list
      file_list="$(resolve_ollama_model_artifacts "$OLLAMA_LOCAL_DIR" "$OLLAMA_MODEL" "model_only")"
      remote_ssh "set -o pipefail; tar -b 1024 -C '$REMOTE_OLLAMA_DIR' -cf - -T - | $(container_exec_i) tar -xf - -C '$CONTAINER_OLLAMA_DIR'" <<< "$file_list" || {
        err "failed to stream ollama model into container"
        exit 1
      }
      info "incremental model stream transfer completed"
    else
      step "stream-copying pruned ollama runtime and model '$OLLAMA_MODEL' (${model_mb}MB) into container ($CONTAINER_LABEL:$CONTAINER_OLLAMA_DIR)"
      remote_ssh "$(container_exec) sh -lc 'mkdir -p \"$CONTAINER_OLLAMA_DIR\"'"
      local file_list
      if [[ "$FORCE_QWEN_COPY" == false && "$has_lib" == true ]]; then
        info "reusing existing lib directory in container, copying runtime binaries and model"
        file_list=$({
          echo "ollama"
          echo "start-ollama.sh"
          for opt in "models/cache" "models/models/cache" "models/models/id_ed25519" "models/models/id_ed25519.pub"; do
            [[ -e "$OLLAMA_LOCAL_DIR/$opt" ]] && echo "$opt"
          done
          resolve_ollama_model_artifacts "$OLLAMA_LOCAL_DIR" "$OLLAMA_MODEL" "model_only"
        })
      else
        file_list="$(resolve_ollama_model_artifacts "$OLLAMA_LOCAL_DIR" "$OLLAMA_MODEL" "full")"
      fi
      remote_ssh "set -o pipefail; tar -b 1024 -C '$REMOTE_OLLAMA_DIR' --exclude='*cuda*' -cf - -T - | $(container_exec_i) tar -xf - -C '$CONTAINER_OLLAMA_DIR'" <<< "$file_list" || {
        err "failed to stream ollama package into container"
        exit 1
      }
      info "ollama package stream transfer completed"
    fi
  else
    step "stream-copying full ollama archive into container ($CONTAINER_LABEL:$CONTAINER_OLLAMA_DIR)"
    remote_ssh "$(container_exec) sh -lc 'rm -rf \"$CONTAINER_OLLAMA_DIR\" && mkdir -p \"$TAA_CONTAINER_WORKDIR\"'"
    remote_ssh "set -o pipefail; tar -b 1024 -C '$REMOTE_DIR' --exclude='*cuda*' -cf - '$OLLAMA_DIR_NAME' | $(container_exec_i) tar -xf - -C '$TAA_CONTAINER_WORKDIR'" || {
      err "failed to stream full ollama archive into container"
      exit 1
    }
    info "full ollama stream transfer completed"
  fi

  remote_ssh "$(container_exec) sh -lc 'chmod +x \"$CONTAINER_OLLAMA_DIR/ollama\" \"$CONTAINER_OLLAMA_DIR/start-ollama.sh\"'"

  # 容器内完整性校验
  if ! remote_ssh "$(container_exec) sh -lc 'test -x \"$CONTAINER_OLLAMA_DIR/ollama\" && test -f \"$CONTAINER_OLLAMA_DIR/start-ollama.sh\" && test -d \"$CONTAINER_OLLAMA_DIR/models/models\" && test -f \"$CONTAINER_OLLAMA_DIR/lib/ollama/libllama-server-impl.so\"'"; then
    err "container ollama package verification failed: one or more required components missing in $CONTAINER_OLLAMA_DIR (ollama, start-ollama.sh, models/models, lib/ollama/libllama-server-impl.so)"
    exit 1
  fi

  # Create symlink for hardcoded dynamic linker path and backward compatibility
  local hardcoded_path="/taatest/ollama-qwen2.5-coder-0.5b"
  if [[ "$CONTAINER_OLLAMA_DIR" != "$hardcoded_path" ]]; then
    step "creating symlink for dynamic linker compatibility"
    remote_ssh "$(container_exec) sh -lc 'mkdir -p /taatest && ln -sfn \"$CONTAINER_OLLAMA_DIR\" \"$hardcoded_path\"'"
  fi
  if [[ "$CONTAINER_OLLAMA_DIR" != "$legacy_container_path" ]]; then
    remote_ssh "$(container_exec) sh -lc 'ln -sfn \"$CONTAINER_OLLAMA_DIR\" \"$legacy_container_path\"'"
  fi

  local verify_script
  verify_script="$(resolve_ollama_model_artifacts "$OLLAMA_LOCAL_DIR" "$OLLAMA_MODEL" "check_model_sh" "$CONTAINER_OLLAMA_DIR")"
  if ! remote_ssh "$(container_exec) sh -lc '$verify_script'"; then
    err "container model verification failed for target model '$OLLAMA_MODEL' in $CONTAINER_OLLAMA_DIR"
    exit 1
  fi
  info "ollama package and model '$OLLAMA_MODEL' verified inside container"
}

step "checking remote host connectivity: ${REMOTE_USER}@${REMOTE_HOST}"
check_remote_connectivity

if [[ "$DEPLOY_TAA" == true || "$DEPLOY_QWEN" == true ]]; then
  step "checking remote target pod: ${TARGET_POD} (${TARGET_NAMESPACE})"
  check_remote_pod
fi

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

  step "uploading taa, config, and certificates to remote host"
  sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$TAA_BINARY_PATH" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/$BINARY_NAME.new"
  sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$REMOTE_TAA_CONFIG_SOURCE" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_TAA_CONFIG_PATH.new"
  sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$ATT_HRK_SOURCE" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/hrk.cert.new"
  sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$ATT_HSK_SOURCE" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/hsk_cek.cert.new"

  step "replacing remote taa, config, and certificates"
  remote_ssh "mv '$REMOTE_DIR/$BINARY_NAME.new' '$REMOTE_DIR/$BINARY_NAME' && mv '$REMOTE_TAA_CONFIG_PATH.new' '$REMOTE_TAA_CONFIG_PATH' && mv '$REMOTE_DIR/hrk.cert.new' '$REMOTE_DIR/hrk.cert' && mv '$REMOTE_DIR/hsk_cek.cert.new' '$REMOTE_DIR/hsk_cek.cert' && chmod +x '$REMOTE_DIR/$BINARY_NAME'"

  step "pausing old taa inside container for update"
  if [[ "$DEBUG" == true ]]; then
    remote_ssh "$(container_exec) sh -lc 'pkill -x taa >/dev/null 2>&1 || true; killall taa >/dev/null 2>&1 || true'"
  else
    remote_ssh "$(container_exec) sh -lc 'touch \"$TAA_CONTAINER_WORKDIR/manual\" && pkill -x taa >/dev/null 2>&1 || true; killall taa >/dev/null 2>&1 || true'"
  fi
  for _ in {1..30}; do
    if ! remote_ssh "$(container_exec) sh -lc 'pgrep -x taa >/dev/null 2>&1'"; then
      break
    fi
    sleep 1
  done

  step "copying runtime files into container"
  remote_ssh "$(container_exec) sh -lc 'mkdir -p $TAA_CONTAINER_WORKDIR/certs'"
  remote_ssh "$(container_cp "$REMOTE_DIR/$BINARY_NAME" "$TAA_CONTAINER_WORKDIR/$BINARY_NAME")"
  remote_ssh "$(container_cp "$REMOTE_TAA_CONFIG_PATH" "$CONTAINER_TAA_CONFIG_PATH")"
  remote_ssh "$(container_cp "$REMOTE_DIR/hrk.cert" "$TAA_CONTAINER_WORKDIR/certs/hrk.cert")"
  remote_ssh "$(container_cp "$REMOTE_DIR/hsk_cek.cert" "$TAA_CONTAINER_WORKDIR/certs/hsk_cek.cert")"
  remote_ssh "$(container_exec) sh -lc 'chmod +x $TAA_CONTAINER_WORKDIR/$BINARY_NAME'"

  step "verifying copied files inside container"
  remote_ssh "$(container_exec) sh -lc 'ls -l $TAA_CONTAINER_WORKDIR/$BINARY_NAME $CONTAINER_TAA_CONFIG_PATH $TAA_CONTAINER_WORKDIR/certs/hrk.cert $TAA_CONTAINER_WORKDIR/certs/hsk_cek.cert 2>/dev/null'"

  step "checking attestation prerequisites inside container"
  remote_ssh "$(container_exec) sh -lc 'test -f $TAA_CONTAINER_WORKDIR/certs/hrk.cert && test -f $TAA_CONTAINER_WORKDIR/certs/hsk_cek.cert'"
  if ! remote_ssh "$(container_exec) sh -lc 'test -e /dev/csv-guest'" 2>/dev/null; then
    warn "/dev/csv-guest not found in container — attestation will fail (expected in non-TEE Docker)"
  fi

  if [[ "$DEBUG" == false ]]; then
    step "checking production identity env inside container"
    remote_ssh "$(container_exec) sh -lc 'test -n \"\${PLATFORM_IP:-}\" && test -n \"\${DOCKER_ID:-}\" || { echo PLATFORM_IP and DOCKER_ID must be injected in production non-debug mode; exit 1; }'"
  fi

  if [[ "$DEBUG" == true ]]; then
    step "starting debug taa inside container"
    remote_ssh "$(container_exec) sh -lc 'mkdir -p $TAA_CONTAINER_WORKDIR/models $TAA_CONTAINER_WORKDIR/data $TAA_CONTAINER_WORKDIR/results $TAA_CONTAINER_WORKDIR/certs && cd $TAA_CONTAINER_WORKDIR && nohup $TAA_CONTAINER_WORKDIR/$BINARY_NAME > $TAA_LOG_FILE 2>&1 < /dev/null &'"
  else
    if [[ "${TAA_KEEP_MANUAL:-false}" == true ]]; then
      warn "TAA_KEEP_MANUAL is enabled; leaving taa manual mode paused"
    else
      step "restoring taa service inside container"
      remote_ssh "$(container_exec) sh -lc 'rm -f \"$TAA_CONTAINER_WORKDIR/manual\"'"
    fi
  fi

  if [[ "$DEBUG" == true || "${TAA_KEEP_MANUAL:-false}" == false ]]; then
    step "waiting for taa service to become ready"
    wait_for_remote_taa_ready
  fi

  remote_ssh "$(container_exec) sh -lc 'tail -n 50 $TAA_LOG_FILE || true'"
fi

banner "Deploy Complete (Remote)" "All remote services deployed and verified healthy"
if [[ "$DEPLOY_PLATFORM_MOCK" == true ]]; then
  echo -e "  ${BOLD}${CYAN}● ${PLATFORM_LABEL}${NC}  ${DIM}(Remote Host Service)${NC}"
  echo -e "    ${MUTED}↳ Endpoint   :${NC} ${BOLD}${REMOTE_HOST}:${PLATFORM_PORT}${NC}"
  echo ""
fi
if [[ "$DEPLOY_QWEN" == true ]]; then
  echo -e "  ${BOLD}${CYAN}● Ollama / Qwen Runtime${NC}  ${DIM}(In-Container Service)${NC}"
  echo -e "    ${MUTED}↳ Target LLM :${NC} ${PURPLE}${OLLAMA_MODEL}${NC}"
  echo -e "    ${MUTED}↳ Location   :${NC} ${CONTAINER_LABEL}:${CONTAINER_OLLAMA_DIR}"
  echo ""
fi
if [[ "$DEPLOY_TAA" == true ]]; then
  echo -e "  ${BOLD}${CYAN}● TAA Secure Enclave Daemon${NC}  ${DIM}(In-Container Daemon)${NC}"
  echo -e "    ${MUTED}↳ Container  :${NC} ${CONTAINER_LABEL}:${TAA_CONTAINER_WORKDIR} (addr ${TAA_CONTAINER_ADDR})"
  echo -e "    ${MUTED}↳ Remote Bin :${NC} ${REMOTE_HOST}:${REMOTE_DIR}/${BINARY_NAME}"
  echo -e "    ${MUTED}↳ Config     :${NC} ${CONTAINER_TAA_CONFIG_PATH}"
  echo -e "    ${MUTED}↳ Log file   :${NC} ${TAA_LOG_FILE}"
  echo -e "    ${MUTED}↳ Platform   :${NC} ${REMOTE_PLATFORM_IP}"
  echo -e "    ${MUTED}↳ Attestation:${NC} ${ATT_REPORT_FILE}"
  echo ""
fi
