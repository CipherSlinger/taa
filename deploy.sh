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
TARGET_POD="${TARGET_POD:-taa-env-slim-v2-20260916-506ca9a0790167bf-768d54479-m8b9z}"

# 项目与远程宿主机：本地源码目录、SSH 登录信息和远程工作目录。
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REMOTE_USER="${REMOTE_USER:-root}"
REMOTE_HOST="${REMOTE_HOST:-172.16.10.178}"
REMOTE_DIR="${REMOTE_DIR:-/root/taa}"

# Platform：远程平台模拟器的监听端口、绑定地址，以及 TAA 容器访问平台的地址。
PLATFORM_PORT="${PLATFORM_PORT:-18080}"
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
CON_WORKDIR="${CON_WORKDIR:-/root/taa}"
CON_PORT="${CON_PORT:-6001}"
ATT_REPORT_FILE="${CON_WORKDIR}/attestation.report"
K_NS="${TARGET_NAMESPACE:+-n $TARGET_NAMESPACE}"

# TAA 容器运行参数：容器内工作目录、监听地址、注册用容器标识和日志路径。
TAA_CONTAINER_WORKDIR="${TAA_CONTAINER_WORKDIR:-${CON_WORKDIR}}"
TAA_CONTAINER_ADDR="${TAA_CONTAINER_ADDR:-:${CON_PORT}}"
# TAA 程序固定读取工作目录下的 taa-config.json，脚本侧文件名必须保持一致。
TAA_CONFIG_FILE="taa-config.json"
TAA_DOCKER_CONFIG_TEMPLATE="${TAA_DOCKER_CONFIG_TEMPLATE:-$PROJECT_DIR/configs/taa-docker.json}"
TAA_PRODUCTION_CONFIG_TEMPLATE="${TAA_PRODUCTION_CONFIG_TEMPLATE:-$PROJECT_DIR/configs/taa-production.json}"
REMOTE_TAA_CONFIG_PATH="${REMOTE_TAA_CONFIG_PATH:-$REMOTE_DIR/$TAA_CONFIG_FILE}"
CONTAINER_TAA_CONFIG_PATH="${CONTAINER_TAA_CONFIG_PATH:-$TAA_CONTAINER_WORKDIR/$TAA_CONFIG_FILE}"
CONTRACT_ID="${CONTRACT_ID:-}"
TAA_LOG_FILE="${TAA_LOG_FILE:-$TAA_CONTAINER_WORKDIR/taa.log}"
CLI_MODEL=""
READY_TIMEOUT="${READY_TIMEOUT:-120}"
READY_INTERVAL="${READY_INTERVAL:-2}"

# Semgrep payload for the code scan engine. TAA resolves the engine fail-closed: with
# codeAudit.codeScan.engine=semgrep the rules path must exist or the daemon exits FATAL at startup
# and the supervisor restarts it every 10s. The kata pod image ships python3 and tar but neither
# the semgrep CLI nor any rules, so a remote deploy has to provision both.
# The engine runtime is a fixed third-party payload and travels as an archive that is expected to
# sit on the remote host (build it with deploy/guest-build/build-semgrep-payload-container.sh and
# copy it over, or point SEMGREP_BUNDLE at a local copy to have it uploaded). The rules are not
# part of it: they evolve with every commit, so they are streamed from this checkout instead.
REMOTE_SEMGREP_BUNDLE="${REMOTE_SEMGREP_BUNDLE:-$REMOTE_DIR/semgrep-bundle.tar.gz}"
SEMGREP_BUNDLE="${SEMGREP_BUNDLE:-}"
SEMGREP_RULES_SOURCE="${SEMGREP_RULES_SOURCE:-$PROJECT_DIR/models/audit/semgrep/rules}"

# The container-shaped semgrep payload, built by deploy/guest-build/build-semgrep-payload-container.sh.
# It carries site-packages and the semgrep wrapper but not the rules, which are streamed separately
# from $SEMGREP_RULES_SOURCE so a rules edit does not force a payload rebuild. It is extracted with
# `tar -xzf - -C /`, so packaging needs no network -- unlike a pip install.
SEMGREP_PAYLOAD_BUNDLE="${SEMGREP_PAYLOAD_BUNDLE:-$PROJECT_DIR/deploy/guest-build/out/semgrep-bundle.tar.gz}"
CONTAINER_SEMGREP_DIR="${CONTAINER_SEMGREP_DIR:-/opt/taa/semgrep}"
SEMGREP_VERSION="${SEMGREP_VERSION:-1.177.0}"

# 远程 SSH 密码：通过 TARGET_PASSWORD 覆盖；置空时启动脚本会交互式询问。
PASSWORD="${TARGET_PASSWORD:-Osrd@2026}"

DEPLOY_DOCKER=false
DEPLOY_REMOTE=false
DEPLOY_PLATFORM_MOCK=false
DEPLOY_TAA=false
SELECTED_COMPONENT=false
STEP=0

# Best-effort routable IPv4 address of this host, empty when none can be determined.
# The primary lookup asks the kernel which source address it would use to leave the host, which
# naturally skips loopback and the docker bridges that "hostname -I" also reports; that list is
# only the fallback. Every command is guarded so a missing tool cannot abort the script under
# "set -e".
detect_local_host_ip() {
  local ip=""
  if command -v ip >/dev/null 2>&1; then
    ip="$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit }}' || true)"
  fi
  if [[ -z "$ip" ]] && command -v hostname >/dev/null 2>&1; then
    ip="$(hostname -I 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i !~ /^127\./) { print $i; exit }}' || true)"
  fi
  printf '%s' "$ip"
}

LOCAL_PLATFORM_STATE_DIR="${LOCAL_PLATFORM_STATE_DIR:-$PROJECT_DIR/.local/platform-mock}"
LOCAL_PLATFORM_PORT="${LOCAL_PLATFORM_PORT:-18080}"
LOCAL_PLATFORM_BIND="${LOCAL_PLATFORM_BIND:-0.0.0.0:${LOCAL_PLATFORM_PORT}}"
LOCAL_PLATFORM_IP="${LOCAL_PLATFORM_IP:-127.0.0.1:${LOCAL_PLATFORM_PORT}}"
LOCAL_PLATFORM_URL="${LOCAL_PLATFORM_URL:-http://127.0.0.1:${LOCAL_PLATFORM_PORT}}"
LOCAL_PLATFORM_UPLOAD_DIR="${LOCAL_PLATFORM_UPLOAD_DIR:-$PROJECT_DIR/.local/upload}"
LOCAL_RUN_DIR="${LOCAL_RUN_DIR:-$PROJECT_DIR/.local/run}"
REMOTE_TAA_CONFIG_SOURCE="${REMOTE_TAA_CONFIG_SOURCE:-$LOCAL_RUN_DIR/remote-$TAA_CONFIG_FILE}"
LOCAL_DOCKER_CONFIG_SOURCE="${LOCAL_DOCKER_CONFIG_SOURCE:-$LOCAL_RUN_DIR/docker-$TAA_CONFIG_FILE}"
LOCAL_TAA_PORT="${LOCAL_TAA_PORT:-$CON_PORT}"
LOCAL_TAA_BIND="${LOCAL_TAA_BIND:-:${LOCAL_TAA_PORT}}"
# TAA publishes on the host network, so it answers on loopback and on the host's routable
# address alike. Prefer the routable one: platform-mock prints this value verbatim as its
# "TAA proxy" badge, and 127.0.0.1 is meaningless to anyone reading that page from another
# machine. Loopback remains the fallback for hosts with no routable address.
LOCAL_HOST_IP="${LOCAL_HOST_IP:-$(detect_local_host_ip)}"
LOCAL_TAA_URL="${LOCAL_TAA_URL:-http://${LOCAL_HOST_IP:-127.0.0.1}:${LOCAL_TAA_PORT}}"
LOCAL_PLATFORM_LOG_FILE="${LOCAL_PLATFORM_LOG_FILE:-$PROJECT_DIR/.local/logs/platform-mock.log}"
LOCAL_DOCKER_CONTAINER="${LOCAL_DOCKER_CONTAINER:-taa-env-slim-v2}"
LOCAL_DOCKER_IMAGE_ARCHIVE="${LOCAL_DOCKER_IMAGE_ARCHIVE:-$PROJECT_DIR/deploy/base/taa-env-slim-v2.tar.gz}"
LOCAL_DOCKER_IMAGE="${LOCAL_DOCKER_IMAGE:-taa-env:slim-v2}"
SAVE_DATE_TAG="$(date +%Y%m%d)"
BASE_DOCKER_IMAGE_ARCHIVE="${BASE_DOCKER_IMAGE_ARCHIVE:-$LOCAL_DOCKER_IMAGE_ARCHIVE}"
BASE_DOCKER_IMAGE="${BASE_DOCKER_IMAGE:-$LOCAL_DOCKER_IMAGE}"
# Packaging names follow one rule across this repository: <repo>:<YYYYMMDD>, with the archive
# named after the image (<repo>-<YYYYMMDD>.tar.gz) under deploy/out. The tag carries only the
# date, never the base image's tag, so the packaged image is not mistaken for the base it was
# derived from (deploy-dataanaylsis.sh, deploy-fhe.sh and build-teellm-image.sh follow the same
# rule). The name is independent of BASE_DOCKER_IMAGE: pointing --base at another image changes
# what goes in, not what comes out.
DEFAULT_SAVE_IMAGE="taa-train-infer:${SAVE_DATE_TAG}"
DEFAULT_SAVE_ARCHIVE="$PROJECT_DIR/deploy/out/taa-train-infer-${SAVE_DATE_TAG}.tar.gz"
CUSTOM_SAVE_IMAGE=""
CUSTOM_SAVE_ARCHIVE=""
CUSTOM_BASE_ARCHIVE=""
CUSTOM_BASE_IMAGE=""
CUSTOM_SAVE_CONFIG=""
LOCAL_DOCKER_NETWORK="${LOCAL_DOCKER_NETWORK:-host}"
# TEE-LLM gateway endpoint written into taa's config. The gateway does not run on the machine that
# writes the config: it is deployed as a Kata CSV2 Pod on the remote host (see deploy-llm.sh), which
# prints the Pod IP to use, so this is set explicitly in practice. LLM_IP is the preferred variable;
# TAA_LLM_ENDPOINT is still read so that callers written before the rename keep working. Empty means
# "keep the endpoint the config template names"; the local docker start path falls back to loopback,
# which is correct when the gateway shares taa's network namespace.
TAA_TEELLM_PORT="${TAA_TEELLM_PORT:-8443}"
LLM_IP="${LLM_IP:-${TAA_LLM_ENDPOINT:-}}"
LOCAL_DOCKER_INPUT_DIR="${LOCAL_DOCKER_INPUT_DIR:-/opt/taa/input}"
# The result directory itself, not the output root: this value becomes model.output.result, and all
# three templates put it one level down (/opt/taa/output/result) so results do not share a directory
# with log/ and progress/ -- the three-way split this deployment itself creates. Passing the root
# here was the same slip as in the save path, and it produced a different layout from the template
# in both places. TAA creates whichever of the three directories it needs, so pre-creating only this
# one is enough.
LOCAL_DOCKER_OUTPUT_DIR="${LOCAL_DOCKER_OUTPUT_DIR:-/opt/taa/output/result}"

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
  if [[ "$DEPLOY_DOCKER" == true ]]; then
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
  if [[ "$DEPLOY_DOCKER" == true ]]; then
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
  if [[ "$DEPLOY_DOCKER" == true ]]; then
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
    # --user root: TAA always lives under /root/taa, while a base image may default
    # to an unprivileged user (jupyter-nologin-full runs as jovyan). Without this the
    # very next mkdir and every later exec fail with EACCES. Harmless on a base image
    # that already runs as root.
    docker run -d --name "$LOCAL_DOCKER_CONTAINER" --network "$LOCAL_DOCKER_NETWORK" --user root --entrypoint tail "$LOCAL_DOCKER_IMAGE" -f /dev/null >/dev/null
  fi

  # 在容器工作目录标记 manual 模式，防止镜像内置的 taa-supervisor.sh 自启动造成端口竞争
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

# Removes every TEE-LLM and ollama artifact a base image may carry, then asserts each one is gone.
# The list is enumerated from the combined images this repository produces
# (taa-train-infer:<date>, taa-fhe:<date>, taa-dataanaylsis:<date>), not guessed.
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
  # Static build, matching deploy/manifest/docker/Dockerfile: the packaging host's glibc is not
  # necessarily the image's, and the saved binary must not depend on the two happening to match.
  spin_task "building taa daemon from ./cmd/taa" env CGO_ENABLED=0 GOOS=linux go build -o "$TAA_BINARY_PATH" ./cmd/taa
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
  # storage.data is left to the template ("") on purpose: the data-anaylsis
  # template points it at /home/jovyan/systemAuthData, where imported files must
  # land, while every other template keeps /root/taa/data -- the value the
  # override used to force anyway.
  write_taa_config "$prod_config_source" "$prod_config_template" \
    ":6001" "" "" "" \
    "/root/taa/models" "" "/root/taa/results" \
    "" "$target_model" \
    false "/opt/taa/input" "/opt/taa/output/result" "/root/taa/keys"
  info "production config prepared for image (model: $target_model)"

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
  # assembled once, and the supervisor is installed from the repository rather than inherited --
  # save never copied taa-supervisor.sh, so whatever the base image happened to carry became the ENTRYPOINT.
  strip_teellm_from_image "$builder_container"

  step "installing the TAA supervisor"
  spin_task "copying deploy/taa-supervisor.sh into the image" \
    docker cp "$PROJECT_DIR/deploy/taa-supervisor.sh" "$builder_container:/root/taa/taa-supervisor.sh"

  provision_local_scan_engine "$builder_container" "$prod_config_template"

  step "deploying taa binary, certificates, and production config"
  spin_task "copying runtime files into container" bash -c '
    set -euo pipefail
    docker cp "$1" "$2:/root/taa/taa"
    docker cp "$3" "$2:/root/taa/certs/hrk.cert"
    docker cp "$4" "$2:/root/taa/certs/hsk_cek.cert"
    docker cp "$5" "$2:/root/taa/taa-config.json"
  ' _ "$TAA_BINARY_PATH" "$builder_container" "$ATT_HRK_SOURCE" "$ATT_HSK_SOURCE" "$prod_config_source"

  step "committing container to production image: $target_image"
  local commit_msg="Production image packaged from base $(basename "$base_archive") with $(basename "$prod_config_template") at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  spin_task "committing image state ($target_image)" \
    docker commit \
      -c 'ENTRYPOINT ["bash", "/root/taa/taa-supervisor.sh"]' \
      -c 'CMD []' \
      -c 'USER root' \
      -c 'WORKDIR /root/taa' \
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
  echo -e "    ${MUTED}↳ Target Model     :${NC} ${PURPLE}${target_model}${NC}"
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
Usage: $(basename "$0") [docker|remote] [start|stop|save] [platform-mock] [taa] [--model <name>]

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
  When no component names are given, target components are deployed by default (in remote mode, platform-mock is omitted to avoid port 18080 conflict with ccs-node-agent).
  Provide one or more component names (platform-mock, taa) to deploy or operate on them separately.
  Note: Qwen / Ollama / TEE-LLM inference service is managed independently via deploy-llm.sh.

Examples:
  # Docker mode (local Docker container)
  $(basename "$0") docker start
  $(basename "$0") docker start --model qwen2.5-coder:7b
  $(basename "$0") docker stop
  $(basename "$0") docker save
  $(basename "$0") docker save --tag taa-train-infer:$(date +%Y%m%d)
  $(basename "$0") docker save -o /tmp/taa-env-production.tar.gz
  $(basename "$0") docker
  $(basename "$0") docker taa
  $(basename "$0") docker platform-mock
  $(basename "$0") docker taa platform-mock

  # Remote mode (Kubernetes / SSH)
  $(basename "$0") remote start
  $(basename "$0") remote stop
  $(basename "$0") remote
  $(basename "$0") remote taa
  $(basename "$0") remote platform-mock
  $(basename "$0") taa

Environment overrides:
  # Docker mode (docker)
  LOCAL_DOCKER_CONTAINER=${LOCAL_DOCKER_CONTAINER}
      本地 Docker 目标容器名称（默认 taa-env-slim-v2）。
  LOCAL_DOCKER_IMAGE_ARCHIVE=${LOCAL_DOCKER_IMAGE_ARCHIVE}
      本地基础镜像归档文件路径（默认 deploy/base/taa-env-slim-v2.tar.gz）。
  LOCAL_DOCKER_IMAGE=${LOCAL_DOCKER_IMAGE}
      本地 Docker 基础镜像名称（默认 taa-env:slim-v2）。
  LOCAL_DOCKER_NETWORK=${LOCAL_DOCKER_NETWORK}
      本地 Docker 容器网络模式（默认 host）。

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
  TAA_DOCKER_CONFIG_TEMPLATE=${TAA_DOCKER_CONFIG_TEMPLATE}
      docker 场景 TAA 配置模板。
  TAA_PRODUCTION_CONFIG_TEMPLATE=${TAA_PRODUCTION_CONFIG_TEMPLATE}
      正式远程场景 TAA 配置模板。
  CONTRACT_ID=${CONTRACT_ID}
      写入配置文件的合约 ID（可选，正式场景通常由运行环境注入）。
  CERT_DIR=${CERT_DIR}
      本地 attestation 证书目录。
  TAA_KEEP_MANUAL=${TAA_KEEP_MANUAL:-false}
      远程部署后是否保持容器 manual 挂起状态而不自启（默认 false）。
  REMOTE_SEMGREP_BUNDLE=$REMOTE_SEMGREP_BUNDLE
      宿主上的 semgrep 引擎 payload 归档；配置选中 semgrep 引擎但容器里没有时从这里注入。
  SEMGREP_BUNDLE=${SEMGREP_BUNDLE:-<未设置>}
      本地 semgrep 引擎 payload 归档；设置后会先上传到宿主再注入，留空则要求宿主上已存在。
  SEMGREP_RULES_SOURCE=$SEMGREP_RULES_SOURCE
      注入容器的代码扫描规则目录，按配置里的 codeAudit.codeScan.rulesPath 落位。
  SEMGREP_PAYLOAD_BUNDLE=$SEMGREP_PAYLOAD_BUNDLE
      docker save 打包时解包进镜像的 semgrep 容器 payload（由
      deploy/guest-build/build-semgrep-payload-container.sh 产出）。
  CONTAINER_SEMGREP_DIR=$CONTAINER_SEMGREP_DIR
      镜像内 semgrep 的安装根目录（pylib 与规则所在位置）。
  SEMGREP_VERSION=$SEMGREP_VERSION
      期望的 semgrep 版本；与 payload 包内 MANIFEST 记录的版本不一致时报错。
  READY_TIMEOUT=${READY_TIMEOUT}
      等待服务就绪的最长时间（秒）。
  READY_INTERVAL=${READY_INTERVAL}
      服务就绪检测轮询间隔（秒）。
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
  sleep 0.2
  if ! kill -0 "$pid" 2>/dev/null; then
    err "$name process died immediately after launch (pid $pid)"
    if [[ -f "$logfile" ]]; then
      echo -e "   ${YELLOW}↳${NC} ${name} log:" >&2
      tail -n 20 "$logfile" >&2 || true
    fi
    exit 1
  fi
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
  if [[ "$DEPLOY_DOCKER" == true ]]; then
    printf '%s' "$TAA_DOCKER_CONFIG_TEMPLATE"
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
# engine is resolved by taa at startup and is fail-closed: a missing rules path is a FATAL exit,
# and the supervisor then restarts the daemon every 10s while the readiness gate keeps failing --
# an unprovisioned engine therefore looks exactly like a hung service. Probing first keeps a
# redeploy onto an already-provisioned pod free.
provision_remote_scan_engine() {
  local template="$1"
  local engine="" rules_path=""
  read -r engine rules_path <<<"$(taa_scan_engine_requirements "$template")"

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
      warn "semgrep is not installed in the container; taa would exit FATAL and restart every 10s"
      if [[ -n "$SEMGREP_BUNDLE" ]]; then
        require_file "semgrep payload bundle not found" "$SEMGREP_BUNDLE"
        spin_task "uploading semgrep payload to ${REMOTE_HOST} ($(du -h "$SEMGREP_BUNDLE" 2>/dev/null | cut -f1))" \
          sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$SEMGREP_BUNDLE" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_SEMGREP_BUNDLE.new"
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

# The docker-mode twin of provision_remote_scan_engine, run against the ephemeral builder container
# so the engine lands in the committed image. Same detection, same payload, same verification probe:
# presence is not proof, because the payload can be extracted and the rules in place while semgrep
# still cannot run them in this image -- a state the cheap probe reports as provisioned. Unlike the
# remote path nothing is installed over the network; the payload is extracted from an archive.
provision_local_scan_engine() {
  local container="$1"
  local template="$2"
  local engine="" rules_path=""
  read -r engine rules_path <<<"$(taa_scan_engine_requirements "$template")"

  if [[ "$engine" != "semgrep" ]]; then
    info "code scan engine '${engine:-unset}' needs no semgrep payload"
    return 0
  fi

  if [[ -z "$rules_path" ]]; then
    err "codeAudit.codeScan.rulesPath is empty in $(basename "$template") but codeAudit.codeScan.engine=semgrep"
    detail "Without it taa falls back to its built-in path relative to the working directory, which does not exist in the image."
    detail "Set codeAudit.codeScan.rulesPath (the shipped templates use a path under $CONTAINER_SEMGREP_DIR, e.g. $CONTAINER_SEMGREP_DIR/rules)."
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

      if ! docker exec -i "$container" sh -lc "test -d '$CONTAINER_SEMGREP_DIR/pylib'"; then
        err "payload extracted but $CONTAINER_SEMGREP_DIR/pylib is missing"
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
  local template
  template="$(select_taa_config_template)"
  local model
  model="$(get_taa_config_llm_model "$template")"
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

workdir = "/root/taa"
if model_dir:
    cleaned = model_dir.rstrip("/")
    if "/" in cleaned:
        workdir = os.path.dirname(cleaned)

attestation = cfg.setdefault("attestation", {})
attestation["hrkCertPath"] = f"{workdir}/certs/hrk.cert"
attestation["hskCekCertPath"] = f"{workdir}/certs/hsk_cek.cert"

with open(path, "w", encoding="utf-8") as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
    f.write("\n")
PY
}

ACTION=""

if [[ $# -eq 0 ]]; then
  DEPLOY_PLATFORM_MOCK=true
  DEPLOY_TAA=true
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
        info "Qwen/Ollama/TEE-LLM is now independently managed by teellm submodule."
        info "To deploy TEE-LLM, please execute: ./deploy-llm.sh"
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
  [[ "$DEPLOY_DOCKER" == true ]] && ((mode_count++)) || true
  [[ "$DEPLOY_REMOTE" == true ]] && ((mode_count++)) || true

  if (( mode_count > 1 )); then
    err "cannot specify multiple deploy modes (docker and remote are mutually exclusive)"
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
    if [[ "$DEPLOY_DOCKER" == false ]]; then
      # 正式远程部署模式下，宿主机已有生产管控平台 (如 ccs-node-agent) 监听 18080，默认不部署 platform-mock
      DEPLOY_PLATFORM_MOCK=false
    else
      DEPLOY_PLATFORM_MOCK=true
    fi
    DEPLOY_TAA=true
  fi

  if [[ "$DEPLOY_PLATFORM_MOCK" == true && "$DEPLOY_DOCKER" == false && "$PLATFORM_PORT" == "18080" ]]; then
    warn "远程宿主机 18080 端口通常由生产平台 (如 ccs-node-agent) 占用；若需部署 platform-mock，建议指定 PLATFORM_PORT"
  fi
fi

cd "$PROJECT_DIR"

wait_for_remote_taa_ready() {
  local wait_start_ts
  wait_start_ts=$(date +%s)
  local ready_attempts=$(( (READY_TIMEOUT + READY_INTERVAL - 1) / READY_INTERVAL ))
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
      printf "\r   ${CYAN}%s${NC} waiting for remote taa service to become ready ${DIM}(%ds / %ds)...${NC}" "$frame" "$elapsed" "$READY_TIMEOUT"
      i=$(( (i + 1) % spin_len ))
    fi
    sleep "$READY_INTERVAL"
  done
  cursor_show
  printf "\r\033[K"
  if [[ "$taa_ready" == true ]]; then
    local total_elapsed=$(( $(date +%s) - wait_start_ts ))
    info "remote taa ready: http://127.0.0.1:$CON_PORT/v1/taa/health ${DIM}(took ${total_elapsed}s)${NC}"
    return 0
  else
    err "remote taa did not become ready within ${READY_TIMEOUT}s"
    remote_ssh "$(container_exec) tail -n 50 $TAA_LOG_FILE || true"
    return 1
  fi
}

if [[ "$ACTION" == "stop" ]]; then
  banner "Stopping Services"
  if [[ "$DEPLOY_DOCKER" == true ]]; then
    step "stopping docker services"
    if [[ "$DEPLOY_PLATFORM_MOCK" == true ]]; then
      stop_pidfile "platform-mock" "$LOCAL_RUN_DIR/platform-mock.pid"
      pkill -f "$MOCK_BINARY_PATH" >/dev/null 2>&1 || true
    fi
    if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -Eq "^${LOCAL_DOCKER_CONTAINER}\$"; then
      if [[ "$DEPLOY_TAA" == true ]]; then
        docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "touch '$TAA_CONTAINER_WORKDIR/manual'; pkill -f '[s]tart\.sh' >/dev/null 2>&1 || true; pkill -x '$BINARY_NAME' >/dev/null 2>&1 || true; killall '$BINARY_NAME' >/dev/null 2>&1 || true" 2>/dev/null || true
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

# 用户可见的平台标签：docker 模式显示 "platform-mock"，远程模式显示 "platform"
PLATFORM_LABEL="platform"
if [[ "$DEPLOY_DOCKER" == true ]]; then
  PLATFORM_LABEL="platform-mock"
fi

# 容器标识显示名：docker 模式显示本地容器名，k8s 模式显示 Pod 名。
if [[ "$DEPLOY_DOCKER" == true ]]; then
  CONTAINER_LABEL="${LOCAL_DOCKER_CONTAINER}"
else
  CONTAINER_LABEL="${TARGET_POD}"
fi
REMOTE_DOCKER_ID="${REMOTE_DOCKER_ID:-$CONTAINER_LABEL}"

DEPLOY_COMPONENTS=""
[[ "$DEPLOY_PLATFORM_MOCK" == true ]] && DEPLOY_COMPONENTS+="$PLATFORM_LABEL "
[[ "$DEPLOY_TAA" == true ]] && DEPLOY_COMPONENTS+="taa "
DEPLOY_TARGET_DESC="${REMOTE_USER}@${REMOTE_HOST}"
if [[ "$DEPLOY_DOCKER" == true ]]; then
  DEPLOY_TARGET_DESC="local docker (${LOCAL_DOCKER_CONTAINER})"
fi
TARGET_MODEL="$(resolve_target_model)"
banner "Deploying: ${DEPLOY_COMPONENTS}→ ${DEPLOY_TARGET_DESC}" "Target model: ${TARGET_MODEL}"

if [[ "$DEPLOY_PLATFORM_MOCK" == true ]]; then
  ensure_go_compiler
  ensure_parent_dir "$MOCK_BINARY_PATH"
  spin_task "building platform-mock from ./tools/platform-mock/cmd/platform-mock" go build -o "$MOCK_BINARY_PATH" ./tools/platform-mock/cmd/platform-mock
fi

if [[ "$DEPLOY_TAA" == true ]]; then
  ensure_go_compiler
  ensure_parent_dir "$TAA_BINARY_PATH"
  spin_task "building taa daemon from ./cmd/taa" env CGO_ENABLED=0 GOOS=linux go build -o "$TAA_BINARY_PATH" ./cmd/taa
fi

if [[ "$DEPLOY_PLATFORM_MOCK" == true && ! -f "$MOCK_BINARY_PATH" ]]; then
  err "build failed: $MOCK_BINARY_PATH not found"
  exit 1
fi
if [[ "$DEPLOY_TAA" == true ]]; then
  require_file "build verification failed (taa binary missing)" "$TAA_BINARY_PATH"
  require_file "taa supervisor script missing" "$PROJECT_DIR/deploy/taa-supervisor.sh"
  require_file "certificate missing" "$ATT_HRK_SOURCE"
  require_file "certificate missing" "$ATT_HSK_SOURCE"
fi


deploy_platform_mock() {
  step "preparing local platform-mock runtime directory"
  mkdir -p "$LOCAL_PLATFORM_STATE_DIR" "$LOCAL_PLATFORM_UPLOAD_DIR" "$LOCAL_RUN_DIR"
  info "runtime directories ready: $LOCAL_PLATFORM_STATE_DIR"

  step "stopping previous local platform-mock"
  stop_pidfile "platform-mock" "$LOCAL_RUN_DIR/platform-mock.pid"
  pkill -f "$MOCK_BINARY_PATH" >/dev/null 2>&1 || true
  for _ in {1..30}; do
    if ! pgrep -f "$MOCK_BINARY_PATH" >/dev/null 2>&1; then
      break
    fi
    sleep 0.1
  done

  step "starting local platform-mock on ${LOCAL_PLATFORM_BIND}"
  start_local_background "platform-mock" "$LOCAL_RUN_DIR/platform-mock.pid" "$LOCAL_PLATFORM_LOG_FILE" \
    "$MOCK_BINARY_PATH" -addr "$LOCAL_PLATFORM_BIND" -state-dir "$LOCAL_PLATFORM_STATE_DIR" -upload-dir "$LOCAL_PLATFORM_UPLOAD_DIR" -taa-target "$LOCAL_TAA_URL" -allow-empty-attestation
  wait_for_http_ready "platform-mock" GET "$LOCAL_PLATFORM_URL/api/register/status" "$READY_TIMEOUT" "$READY_INTERVAL" "$LOCAL_PLATFORM_LOG_FILE"
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
  docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "test -f '$TAA_CONTAINER_WORKDIR/certs/hrk.cert' && test -f '$TAA_CONTAINER_WORKDIR/certs/hsk_cek.cert'" >/dev/null
  if ! docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc 'test -e /dev/csv-guest' 2>/dev/null; then
    warn "/dev/csv-guest not found in container — attestation will fail (expected in non-TEE Docker)"
  else
    info "attestation device /dev/csv-guest verified"
  fi

  TAA_CONFIG_TEMPLATE="$(select_taa_config_template)"
  step "writing taa config for docker from $(basename "$TAA_CONFIG_TEMPLATE")"
  ensure_parent_dir "$LOCAL_DOCKER_CONFIG_SOURCE"
  local target_llm_endpoint="${LLM_IP:-https://127.0.0.1:${TAA_TEELLM_PORT}}"
  info "taa llm endpoint: $target_llm_endpoint"
  # storage.data stays as the template says (see save_local_docker_image).
  write_taa_config "$LOCAL_DOCKER_CONFIG_SOURCE" "$TAA_CONFIG_TEMPLATE" \
    "$TAA_CONTAINER_ADDR" "$LOCAL_PLATFORM_IP" "$LOCAL_DOCKER_CONTAINER" "$CONTRACT_ID" \
    "$TAA_CONTAINER_WORKDIR/models" "" "$TAA_CONTAINER_WORKDIR/results" \
    "$target_llm_endpoint" "$TARGET_MODEL" true \
    "$LOCAL_DOCKER_INPUT_DIR" "$LOCAL_DOCKER_OUTPUT_DIR" "$TAA_CONTAINER_WORKDIR/keys"
  docker cp "$LOCAL_DOCKER_CONFIG_SOURCE" "$LOCAL_DOCKER_CONTAINER:$CONTAINER_TAA_CONFIG_PATH" >/dev/null
  info "config written to container: $CONTAINER_TAA_CONFIG_PATH"

  step "deploying taa daemon script into container"
  docker cp "$PROJECT_DIR/deploy/taa-supervisor.sh" "$LOCAL_DOCKER_CONTAINER:$TAA_CONTAINER_WORKDIR/taa-supervisor.sh"
  docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "chmod +x '$TAA_CONTAINER_WORKDIR/taa-supervisor.sh'"

  step "stopping old taa and daemon wrapper inside container"
  stop_pidfile "taa" "$LOCAL_RUN_DIR/taa.pid"
  pkill -f "$TAA_BINARY_PATH" >/dev/null 2>&1 || true
  docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "touch '$TAA_CONTAINER_WORKDIR/manual'; pkill -f '[s]tart\.sh' >/dev/null 2>&1 || true; pkill -x '$BINARY_NAME' >/dev/null 2>&1 || true; killall '$BINARY_NAME' >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
  local stopped=false
  # The bracket keeps pgrep from matching the shell running the pattern itself. The daemon
  # is checked through ps instead of `pgrep -x`: a zombie keeps its comm (only its cmdline
  # is emptied), and this container's PID 1 is an idle `tail -f /dev/null` that never reaps
  # an orphan, so one dead taa would keep this loop reporting "still running" until the
  # timeout and then "force-kill" a process that is already gone.
  for _ in {1..30}; do
    if ! docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "pgrep -f '[s]tart\.sh' >/dev/null 2>&1 || ps -eo stat=,comm= | awk -v n='$BINARY_NAME' '\$1 !~ /^Z/ && \$2 == n { f=1 } END { exit !f }'"; then
      stopped=true
      break
    fi
    sleep 0.2
  done
  if [[ "$stopped" != true ]]; then
    warn "taa or taa-supervisor.sh did not terminate gracefully; force-killing"
    docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "pkill -9 -f '[s]tart\.sh' >/dev/null 2>&1 || true; pkill -9 -x '$BINARY_NAME' >/dev/null 2>&1 || true; killall -9 '$BINARY_NAME' >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
    sleep 0.5
  fi
  info "stopped previous taa daemon and instances"

  step "starting taa supervisor inside container"
  docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "rm -f '$TAA_CONTAINER_WORKDIR/manual'"
  docker exec -d "$LOCAL_DOCKER_CONTAINER" sh -lc "cd '$TAA_CONTAINER_WORKDIR' && nohup bash ./taa-supervisor.sh >/dev/null 2>&1 &"

  step "waiting for taa service to become ready"
  if ! wait_for_http_ready "taa" POST "$LOCAL_TAA_URL/v1/taa/health" "$READY_TIMEOUT" "$READY_INTERVAL"; then
    echo -e "   ${YELLOW}↳${NC} taa container log (${TAA_LOG_FILE}):"
    docker exec -i "$LOCAL_DOCKER_CONTAINER" sh -lc "tail -n 60 '$TAA_LOG_FILE' 2>/dev/null || true"
    exit 1
  fi
}

if [[ "$DEPLOY_DOCKER" == true ]]; then
  require_command docker
  docker info >/dev/null 2>&1 || { err "docker daemon is not running or accessible"; exit 1; }

  # 如果需要部署 taa，先确保容器已就绪
  if [[ "$DEPLOY_TAA" == true ]]; then
    ensure_local_docker_container
  fi

  # 1. 启动本地 platform-mock（若包含 platform-mock）
  if [[ "$DEPLOY_PLATFORM_MOCK" == true ]]; then
    deploy_platform_mock
  fi

  # 2. 部署 taa 进本地容器
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

step "checking remote host connectivity: ${REMOTE_USER}@${REMOTE_HOST}"
check_remote_connectivity

if [[ "$DEPLOY_TAA" == true ]]; then
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

if [[ "$DEPLOY_TAA" == true ]]; then
  TAA_CONFIG_TEMPLATE="$(select_taa_config_template)"
  step "writing remote taa config from $(basename "$TAA_CONFIG_TEMPLATE")"
  INCLUDE_TAA_IDENTITY=false
  # storage.data stays as the template says (see save_local_docker_image).
  write_taa_config "$REMOTE_TAA_CONFIG_SOURCE" "$TAA_CONFIG_TEMPLATE" \
    "$TAA_CONTAINER_ADDR" "$REMOTE_PLATFORM_IP" "$REMOTE_DOCKER_ID" "$CONTRACT_ID" \
    "$TAA_CONTAINER_WORKDIR/models" "" "$TAA_CONTAINER_WORKDIR/results" \
    "${LLM_IP:-}" "$TARGET_MODEL" "$INCLUDE_TAA_IDENTITY" "" "" "$TAA_CONTAINER_WORKDIR/keys"

  step "uploading taa, config, and certificates to remote host"
  sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$TAA_BINARY_PATH" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/$BINARY_NAME.new"
  sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$REMOTE_TAA_CONFIG_SOURCE" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_TAA_CONFIG_PATH.new"
  sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$ATT_HRK_SOURCE" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/hrk.cert.new"
  sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$ATT_HSK_SOURCE" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/hsk_cek.cert.new"

  step "replacing remote taa, config, and certificates"
  remote_ssh "mv '$REMOTE_DIR/$BINARY_NAME.new' '$REMOTE_DIR/$BINARY_NAME' && mv '$REMOTE_TAA_CONFIG_PATH.new' '$REMOTE_TAA_CONFIG_PATH' && mv '$REMOTE_DIR/hrk.cert.new' '$REMOTE_DIR/hrk.cert' && mv '$REMOTE_DIR/hsk_cek.cert.new' '$REMOTE_DIR/hsk_cek.cert' && chmod +x '$REMOTE_DIR/$BINARY_NAME'"

  # Before the running taa is disturbed: an unprovisioned engine is a startup FATAL, so failing
  # here leaves the previous daemon serving instead of trading it for a restart loop.
  step "provisioning code scan engine inside container"
  provision_remote_scan_engine "$TAA_CONFIG_TEMPLATE"

  step "pausing old taa inside container for update"
  remote_ssh "$(container_exec) sh -lc 'touch "$TAA_CONTAINER_WORKDIR/manual" && pkill -x taa >/dev/null 2>&1 || true; killall taa >/dev/null 2>&1 || true'"
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

  step "checking production identity env inside container"
  remote_ssh "$(container_exec) sh -lc 'test -n "\${PLATFORM_IP:-}" && test -n "\${DOCKER_ID:-}" || { echo PLATFORM_IP and DOCKER_ID must be injected in production mode; exit 1; }'"

  if [[ "${TAA_KEEP_MANUAL:-false}" == true ]]; then
    warn "TAA_KEEP_MANUAL is enabled; leaving taa manual mode paused"
  else
    step "restoring taa service inside container"
    remote_ssh "$(container_exec) sh -lc 'rm -f "$TAA_CONTAINER_WORKDIR/manual"'"
  fi

  if [[ "${TAA_KEEP_MANUAL:-false}" == false ]]; then
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
