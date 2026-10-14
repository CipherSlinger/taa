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
TEMP_FILELIST=""
TEMP_CONFIG_FILE=""
TRAP_SUPPRESS_DEPLOYMENT_BANNER=false
STEP=0

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
  if [[ -n "${TEMP_FILELIST:-}" && -f "$TEMP_FILELIST" ]]; then
    rm -f "$TEMP_FILELIST" 2>/dev/null || true
  fi
  if [[ -n "${TEMP_CONFIG_FILE:-}" && -f "$TEMP_CONFIG_FILE" ]]; then
    rm -f "$TEMP_CONFIG_FILE" 2>/dev/null || true
  fi

  if [[ $exit_code -ne 0 && "${TRAP_SUPPRESS_DEPLOYMENT_BANNER:-false}" != "true" ]]; then
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
    if [[ -f "/tmp/teellm-deploy-last-error.log" ]]; then
      echo -e "${RED}│${NC}  Error log   : ${MUTED}/tmp/teellm-deploy-last-error.log${NC}" >&2
    fi
    echo -e "${RED}╰──────────────────────────────────────────────────────────────────╯${NC}" >&2
  fi
}
trap cleanup_display EXIT INT TERM

banner() {
  local title="$1"
  local subtitle="${2:-}"
  echo ""
  echo -e "${CYAN}╭──────────────────────────────────────────────────────────────────╮${NC}"
  echo -e "${CYAN}│${NC}  ${BOLD}${title}${NC}"
  if [[ -n "$subtitle" ]]; then
    echo -e "${CYAN}│${NC}  ${DIM}${subtitle}${NC}"
  fi
  echo -e "${CYAN}╰───────────────────────────────────────────────────────────────────╯${NC}"
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
  logfile="$(mktemp /tmp/teellm_task.XXXXXX)"

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
        local err_dump="/tmp/teellm-deploy-last-error.log"
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
      local err_dump="/tmp/teellm-deploy-last-error.log"
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

# ── Project & Environment Defaults ───────────────────────────
# This script sits at the TAA repository root. The TEE-LLM service it deploys -- its sources,
# config templates, model bundle and supervisor script -- lives in the teellm submodule, so
# every path below that used to be relative to the old teellm/ home now goes through TEELLM_DIR.
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEELLM_DIR="${TEELLM_DIR:-$PROJECT_DIR/teellm}"

# Docker runtime settings
# The TEE-LLM service runs in its own container, separate from TAA, so that the two
# processes no longer share a network namespace: TAA reaches the gateway by container
# IP instead of 127.0.0.1.
LOCAL_DOCKER_CONTAINER="${LOCAL_DOCKER_CONTAINER:-taa-teellm}"
# Container targeted by remote-docker mode. Every container-specific path below
# ($CON_WORKDIR, $CONTAINER_OLLAMA_DIR) describes that container too, since the layout inside
# a TAA environment container does not depend on where its daemon runs.
REMOTE_DOCKER_CONTAINER="${REMOTE_DOCKER_CONTAINER:-taa-env-slim-v2}"
CON_WORKDIR="${CON_WORKDIR:-/root/taa}"
CONTAINER_OLLAMA_DIR="${CONTAINER_OLLAMA_DIR:-/root/taa/ollama}"
# Older image revisions ship the same ollama bundle under this name. It carries the identical
# runtime (only the model set differs), so a container that still has it can be migrated into
# $CONTAINER_OLLAMA_DIR instead of streaming the runtime in again.
CONTAINER_LEGACY_OLLAMA_DIR="${CONTAINER_LEGACY_OLLAMA_DIR:-$CON_WORKDIR/ollama-qwen2.5-coder-0.5b}"

# TEE-LLM and Ollama ports & endpoints
TEELLM_PORT="${TEELLM_PORT:-8443}"
TEELLM_LOG_FILE="${TEELLM_LOG_FILE:-$CON_WORKDIR/teellm-service.log}"
OLLAMA_HOST="${OLLAMA_HOST:-127.0.0.1:11434}"
OLLAMA_LOG_FILE="${OLLAMA_LOG_FILE:-/tmp/ollama.log}"
OLLAMA_READY_TIMEOUT="${OLLAMA_READY_TIMEOUT:-120}"
OLLAMA_READY_INTERVAL="${OLLAMA_READY_INTERVAL:-2}"
FORCE_QWEN_COPY="${FORCE_QWEN_COPY:-false}"
OLLAMA_PRUNE_SYNC="${OLLAMA_PRUNE_SYNC:-true}"

# Kubernetes & Remote settings
TARGET_NAMESPACE="${TARGET_NAMESPACE:-osr}"
TARGET_POD="${TARGET_POD:-taa-env-slim-v2-20260916-b2038037072e1052-54f554445c-n2pnv}"
REMOTE_HOST="${REMOTE_HOST:-172.16.10.178}"
REMOTE_USER="${REMOTE_USER:-root}"
PASSWORD="${TARGET_PASSWORD:-${PASSWORD:-Osrd@2026}}"
REMOTE_DIR="${REMOTE_DIR:-/root/taa}"
OLLAMA_DIR_NAME="$(basename "$CONTAINER_OLLAMA_DIR")"
REMOTE_OLLAMA_DIR="${REMOTE_OLLAMA_DIR:-$REMOTE_DIR/$OLLAMA_DIR_NAME}"
# Staging area on the remote host for files that have to be copied into a remote container:
# docker cp resolves both of its arguments on the daemon's host, so uploads land here first.
REMOTE_STAGE_DIR="${REMOTE_STAGE_DIR:-$REMOTE_DIR/stage}"
K_NS="${TARGET_NAMESPACE:+-n $TARGET_NAMESPACE}"

SSH_OPTS=(
  -q
  -o LogLevel=ERROR
  -o StrictHostKeyChecking=accept-new
  -o UserKnownHostsFile="$HOME/.ssh/known_hosts"
)

container_exec() {
  echo "kubectl $K_NS exec '$TARGET_POD' --"
}

container_exec_i() {
  echo "kubectl $K_NS exec -i '$TARGET_POD' --"
}

container_cp() {
  echo "kubectl $K_NS cp '$1' '$TARGET_POD':'$2'"
}

# ── Container Target Abstraction ──────────────────────────────
# Two targets deploy the TEE-LLM service into a plain container: the local docker daemon
# (docker mode) and the docker daemon on the remote host (remote-docker mode, which is how the
# service gets into a TAA environment container such as taa-env-slim-v2 on 172.16.10.178).
# TARGET_CONTAINER names the container in both cases and REMOTE_CONTAINER_MODE says which
# daemon owns it, so the deployment body below is written once and runs against either.

# Quotes one argument so a POSIX shell re-parses it as a single word. Single-quote escaping is
# used rather than printf's %q because scripts handed to `sh -lc` can span several lines, and %q
# would encode those with bash-only ANSI-C quoting.
shq() {
  printf "'%s'" "${1//\'/\'\\\'\'}"
}

# Runs a docker subcommand against the target daemon. In remote-docker mode every argument is
# re-quoted and handed to the remote shell, which keeps multi-word `sh -lc` scripts intact
# across the SSH hop; stdin and stdout stay connected, so tar streams keep working.
dk() {
  if [[ "$REMOTE_CONTAINER_MODE" != true ]]; then
    docker "$@"
    return
  fi
  local quoted="" arg
  for arg in "$@"; do
    quoted+=" $(shq "$arg")"
  done
  remote_ssh "docker$quoted"
}

# Copies a local file into the target container at path $2. In remote-docker mode the daemon
# resolves paths on the remote host, so the file is uploaded to $REMOTE_STAGE_DIR first and
# copied into the container from there; $3 optionally names the staged copy, which keeps
# temporary local names (mktemp) out of the remote host's staging directory.
ctr_cp_in() {
  local local_path="$1" container_path="$2" staged_name="${3:-$(basename "$1")}"
  if [[ "$REMOTE_CONTAINER_MODE" != true ]]; then
    docker cp "$local_path" "$TARGET_CONTAINER:$container_path"
    return
  fi
  local staged="$REMOTE_STAGE_DIR/$staged_name"
  remote_ssh "mkdir -p '$REMOTE_STAGE_DIR'"
  sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$local_path" "${REMOTE_USER}@${REMOTE_HOST}:$staged"
  remote_ssh "docker cp '$staged' '$TARGET_CONTAINER:$container_path'"
}

# Streams the files named in $2 (paths relative to $1) directly into $3 inside the target
# container, so multi-GB model weights never have to fit on disk anywhere in between.
stream_files_into_container() {
  tar -b 1024 -C "$1" -cf - -T "$2" | dk exec -i "$TARGET_CONTAINER" tar -xf - -C "$3"
}

# llama-server links against the soname forms of its libraries (libllama-common.so.0,
# libllama.so.0, libmtmd.so.0, libggml.so.0, libggml-base.so.0) and carries RUNPATH=$ORIGIN,
# so the loader looks for those exact names next to the binary. The offline ollama bundle
# ships only the fully versioned files (libllama-common.so.0.1.2, ...), so the lookup misses,
# the binary exits 127, ollama answers 500 and teellm's healthz reports 503. Recreate the
# soname symlinks from whatever versions the bundle actually carries, so this keeps working
# across bundle upgrades. The caller passes the lib directory as the first argument; the
# script prints how many links it created.
ollama_soname_fix_script() {
  cat <<'SONAME_FIX'
d="$1"
n=0
for f in "$d"/lib*.so.*; do
  [ -e "$f" ] || continue
  [ -L "$f" ] && continue
  b="${f##*/}"
  stem="${b%%.so.*}"
  rest="${b#*.so.}"
  [ "$rest" = "$b" ] && continue
  s="$stem.so.${rest%%.*}"
  if [ ! -e "$d/$s" ]; then ln -sf "$b" "$d/$s"; n=$((n+1)); fi
done
echo "$n"
SONAME_FIX
}

ensure_remote_ssh() {
  if [[ "$DEPLOY_DOCKER" == true ]]; then
    return 0
  fi
  if [[ -z "$PASSWORD" ]]; then
    read -rsp "Password for ${REMOTE_USER}@${REMOTE_HOST}: " PASSWORD
    echo
  fi
  if ! command -v sshpass >/dev/null 2>&1; then
    err "sshpass is required for password-based authentication. Install sshpass or configure SSH keys."
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
    err "cannot connect to remote host ${REMOTE_USER}@${REMOTE_HOST} via SSH (timeout or authentication failed)"
    detail "Please verify network connectivity, REMOTE_HOST ($REMOTE_HOST), or password credentials."
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
    detail "Please check TARGET_POD or run 'kubectl get pods -n ${TARGET_NAMESPACE:-default}' on remote host."
    exit 1
  fi
  info "remote target pod verified: ${TARGET_POD} (namespace: ${TARGET_NAMESPACE:-default})"
}

ensure_go_compiler() {
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
}

# Verifies the target container exists and is running. It never creates one: in docker mode the
# container comes from a packaged image, and in remote-docker mode it is the environment
# container already running on the remote host.
ensure_target_container() {
  local where="local docker daemon"
  if [[ "$REMOTE_CONTAINER_MODE" == true ]]; then
    where="docker daemon on ${REMOTE_USER}@${REMOTE_HOST}"
  fi

  step "checking container on $where: $TARGET_CONTAINER"
  if dk ps --format '{{.Names}}' | grep -Eq "^${TARGET_CONTAINER}\$"; then
    info "container is currently running: $TARGET_CONTAINER"
  elif dk ps -a --format '{{.Names}}' | grep -Eq "^${TARGET_CONTAINER}\$"; then
    info "starting stopped container: $TARGET_CONTAINER"
    dk start "$TARGET_CONTAINER" >/dev/null
  else
    err "docker container '$TARGET_CONTAINER' does not exist on $where"
    detail "Please start or load the container image first (e.g. via taa deploy.sh docker start)."
    exit 1
  fi

  # Mark manual flag to avoid port conflict from legacy image scripts
  dk exec -i "$TARGET_CONTAINER" sh -lc "mkdir -p '$CON_WORKDIR' && touch '$CON_WORKDIR/manual-teellm'" >/dev/null 2>&1 || true
}

# Echoes "<image> <status> <ip>" for the target container. Empty fields are left blank, and a
# host-networked container reports no IP at all.
container_facts() {
  local raw image status ip
  raw="$(dk inspect -f '{{.Config.Image}} {{.State.Status}} {{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$TARGET_CONTAINER" 2>/dev/null | head -n 1)"
  image="${raw%% *}"
  raw="${raw#* }"
  status="${raw%% *}"
  ip="$(printf '%s' "${raw#* }" | tr -d ' \n')"
  printf '%s %s %s\n' "$image" "$status" "$ip"
}

# Prints the target container and its gateway endpoints, then the values a follow-up taa
# deployment needs. TAA reaches the gateway either by container IP (separate containers on the
# same host) or over loopback (same network namespace), so both endpoints are printed.
print_container_summary() {
  local where="$1" image status ip
  read -r image status ip < <(container_facts)

  echo -e "  ${BOLD}${CYAN}● Target Container${NC}  ${DIM}(${where})${NC}"
  echo -e "    ${MUTED}↳ Container  :${NC} ${BOLD}${TARGET_CONTAINER}${NC}${status:+ ${DIM}(${status})${NC}}"
  [[ -n "$image" ]] && echo -e "    ${MUTED}↳ Image      :${NC} ${image}"
  if [[ -n "$ip" ]]; then
    echo -e "    ${MUTED}↳ Container IP:${NC} ${ip}"
  else
    echo -e "    ${MUTED}↳ Network    :${NC} host (no container IP; gateway binds on the host itself)"
  fi
  echo -e "    ${MUTED}↳ Endpoint (inside the container)     :${NC} ${BOLD}https://127.0.0.1:${TEELLM_PORT}${NC}"
  echo -e "    ${MUTED}↳ Endpoint (host / other containers)  :${NC} ${BOLD}https://${ip:-127.0.0.1}:${TEELLM_PORT}${NC}"
  echo -e "    ${MUTED}↳ Config     :${NC} ${CON_WORKDIR}/configs/teellm-docker.json"
  echo -e "    ${MUTED}↳ Log file   :${NC} ${TEELLM_LOG_FILE}"
  echo ""
  echo -e "  ${BOLD}${CYAN}● Ollama / Qwen Engine${NC}  ${DIM}(In-Container Daemon)${NC}"
  echo -e "    ${MUTED}↳ Endpoint   :${NC} ${BOLD}http://${OLLAMA_HOST}${NC}"
  echo -e "    ${MUTED}↳ Model      :${NC} ${PURPLE}${OLLAMA_MODEL}${NC}"
  echo -e "    ${MUTED}↳ Path       :${NC} ${TARGET_CONTAINER}:${CONTAINER_OLLAMA_DIR}"
  echo -e "    ${MUTED}↳ Log file   :${NC} ${OLLAMA_LOG_FILE}"
  echo ""
  echo -e "  ${BOLD}${CYAN}● Next: deploy taa against this container${NC}"
  echo -e "    ${MUTED}↳ TAA_LLM_ENDPOINT, taa sharing the container:${NC} ${BOLD}https://127.0.0.1:${TEELLM_PORT}${NC}"
  echo -e "    ${MUTED}↳ TAA_LLM_ENDPOINT, taa elsewhere on the host:${NC} ${BOLD}https://${ip:-127.0.0.1}:${TEELLM_PORT}${NC}"
  if [[ "$REMOTE_CONTAINER_MODE" == true ]]; then
    echo -e "    ${MUTED}↳ Shell      :${NC} ssh ${REMOTE_USER}@${REMOTE_HOST} 'docker exec -it ${TARGET_CONTAINER} bash'"
    echo -e "    ${MUTED}↳ Re-probe   :${NC} $(basename "$0") remote-docker probe"
  else
    echo -e "    ${MUTED}↳ Shell      :${NC} docker exec -it ${TARGET_CONTAINER} bash"
    echo -e "    ${MUTED}↳ Re-probe   :${NC} $(basename "$0") docker probe"
  fi
  echo ""
}

# ── Ollama Discovery, Binary Check & Artifact Resolver ─────────

resolve_ollama_local_dir() {
  if [[ -n "${OLLAMA_LOCAL_DIR:-}" ]]; then
    printf '%s' "$OLLAMA_LOCAL_DIR"
    return 0
  fi
  if [[ -n "${CLI_OLLAMA_DIR:-}" ]]; then
    printf '%s' "$CLI_OLLAMA_DIR"
    return 0
  fi
  if [[ -d "$TEELLM_DIR/models/ollama" ]]; then
    printf '%s' "$TEELLM_DIR/models/ollama"
    return 0
  fi
  printf '%s' "$TEELLM_DIR/models/ollama"
}

verify_ollama_binary() {
  local binary="$1"
  local output rc=0

  if [[ ! -f "$binary" ]]; then
    err "ollama binary not found: $binary"
    exit 1
  fi

  # Detect HTML 404 or corrupted download headers
  if head -n 1 "$binary" 2>/dev/null | grep -qiE "<!DOCTYPE|<html|404 Not Found"; then
    err "ollama binary appears to be an HTML page or corrupted download: $binary"
    exit 1
  fi

  chmod +x "$binary" 2>/dev/null || true

  if command -v timeout >/dev/null 2>&1; then
    output=$(timeout 10 "$binary" --version 2>&1) || rc=$?
  else
    output=$("$binary" --version 2>&1) || rc=$?
  fi

  if [[ $rc -ne 0 ]]; then
    err "ollama binary is invalid or incompatible (exit code $rc): $binary"
    if [[ -n "$output" ]]; then
      detail "$output"
    fi
    detail "Please provide a complete Linux x86_64 Ollama binary."
    exit 1
  fi
}

resolve_ollama_model_artifacts() {
  local dir="$1"
  local model="$2"
  local mode="${3:-full}"
  local dest_prefix="${4:-}"
  require_command python3
  python3 - "$dir" "$model" "$mode" "$dest_prefix" <<'PY'
import os, sys, json, re

ollama_dir = sys.argv[1]
model_name = sys.argv[2]
mode = sys.argv[3] if len(sys.argv) > 3 else "full"
dest_prefix = sys.argv[4] if len(sys.argv) > 4 else ""

MODEL_NAME_PATTERN = r'^[a-zA-Z0-9_.-]+(/[a-zA-Z0-9_.-]+)*(:[a-zA-Z0-9_.-]+)?$'
if not re.match(MODEL_NAME_PATTERN, model_name):
    sys.stderr.write(f"error: invalid model name format: {model_name}\n")
    sys.exit(1)

if ":" in model_name:
    base_name, tag = model_name.split(":", 1)
else:
    base_name, tag = model_name, "latest"

parts = base_name.split("/")
manifests_root = os.path.join(ollama_dir, "models", "models", "manifests")
if len(parts) == 1:
    manifest_rel = os.path.join("models", "models", "manifests", "registry.ollama.ai", "library", parts[0], tag)
elif len(parts) == 2:
    manifest_rel = os.path.join("models", "models", "manifests", "registry.ollama.ai", parts[0], parts[1], tag)
else:
    manifest_rel = os.path.join("models", "models", "manifests", *parts, tag)

manifest_full = os.path.join(ollama_dir, manifest_rel)
manifests_root_real = os.path.realpath(manifests_root)
manifest_real = os.path.realpath(manifest_full)
if not (manifest_real == manifests_root_real or manifest_real.startswith(manifests_root_real + os.sep)):
    sys.stderr.write(f"error: directory traversal detected: {model_name}\n")
    sys.exit(1)

if not os.path.isfile(manifest_full):
    candidates = []
    if os.path.isdir(manifests_root):
        for root, dirs, files in os.walk(manifests_root):
            for f in files:
                if f == tag and os.path.basename(root) == parts[-1]:
                    cand = os.path.join(root, f)
                    cand_real = os.path.realpath(cand)
                    if cand_real == manifests_root_real or cand_real.startswith(manifests_root_real + os.sep):
                        candidates.append(os.path.relpath(cand, ollama_dir))
    if candidates:
        manifest_rel = candidates[0]
        manifest_full = os.path.join(ollama_dir, manifest_rel)
    else:
        sys.stderr.write(f"error: model '{model_name}' manifest not found at {manifest_full}\n")
        sys.exit(1)

try:
    with open(manifest_full, "r", encoding="utf-8") as fp:
        data = json.load(fp)
except (json.JSONDecodeError, OSError) as e:
    sys.stderr.write(f"error: failed to parse manifest '{manifest_full}': {e}\n")
    sys.exit(1)

expected_sizes = {}
blobs = []
if "config" in data and "digest" in data["config"]:
    b = data["config"]["digest"].replace(":", "-")
    blobs.append(b)
    if "size" in data["config"]:
        expected_sizes[b] = data["config"]["size"]
for layer in data.get("layers", []):
    if "digest" in layer:
        b = layer["digest"].replace(":", "-")
        blobs.append(b)
        if "size" in layer:
            expected_sizes[b] = layer["size"]

blobs = sorted(list(set(blobs)))
if not blobs:
    sys.stderr.write(f"error: model '{model_name}' manifest contains no layers or blobs\n")
    sys.exit(1)

blob_rel_paths = []
weight_bytes = 0
blobs_dir = os.path.join(ollama_dir, "models", "models", "blobs")
for b in blobs:
    if not re.match(r"^sha256-[a-f0-9]{64}$", b):
        sys.stderr.write(f"error: invalid blob digest format: {b}\n")
        sys.exit(1)
    p = os.path.join("models", "models", "blobs", b)
    full_p = os.path.join(ollama_dir, p)
    if not os.path.isfile(full_p):
        sys.stderr.write(f"error: missing required blob for model '{model_name}': {full_p}\n")
        sys.exit(1)
    actual_size = os.path.getsize(full_p)
    expected_size = expected_sizes.get(b)
    if expected_size is not None and actual_size != expected_size:
        sys.stderr.write(f"error: corrupted blob '{b}' for model '{model_name}': expected {expected_size} bytes, got {actual_size} bytes\n")
        sys.exit(1)
    blob_rel_paths.append(p)
    weight_bytes += actual_size

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
        b_name = os.path.basename(b)
        exp_sz = expected_sizes.get(b_name)
        if exp_sz is not None:
            tests.append(f'test -f "{prefix}{b}" && test "$(( $(wc -c < "{prefix}{b}" 2>/dev/null || echo 0) ))" -eq {exp_sz}')
        else:
            tests.append(f'test -s "{prefix}{b}"')
    print(" && ".join(tests))
else:
    for it in full_items:
        print(it)
PY
}

resolve_target_model() {
  if [[ -n "$CLI_MODEL" ]]; then
    printf '%s' "$CLI_MODEL"
    return 0
  fi
  if [[ -n "${OLLAMA_MODEL:-}" ]]; then
    printf '%s' "$OLLAMA_MODEL"
    return 0
  fi
  local cfg_file
  if [[ "$DEPLOY_DOCKER" == true ]]; then
    cfg_file="${TEELLM_CONFIG_PATH:-$TEELLM_DIR/configs/teellm-docker.json}"
  else
    cfg_file="${TEELLM_CONFIG_PATH:-$TEELLM_DIR/configs/teellm-production.json}"
  fi
  if [[ -f "$cfg_file" ]]; then
    local m
    m=$(python3 -c 'import sys, json; print((json.load(open(sys.argv[1])) or {}).get("backend", {}).get("defaultModel", ""))' "$cfg_file" 2>/dev/null || true)
    if [[ -n "$m" ]]; then
      printf '%s' "$m"
      return 0
    fi
  fi
  printf '%s' "qwen2.5-coder:3b"
}

resolve_certificates() {
  local hrk=""
  local hsk=""

  if [[ -n "${ATT_HRK_SOURCE:-}" && -f "$ATT_HRK_SOURCE" ]]; then
    hrk="$ATT_HRK_SOURCE"
  elif [[ -f "$PROJECT_DIR/deploy/certs/hrk.cert" ]]; then
    hrk="$PROJECT_DIR/deploy/certs/hrk.cert"
  elif [[ -f "$TEELLM_DIR/certs/hrk.cert" ]]; then
    hrk="$TEELLM_DIR/certs/hrk.cert"
  elif [[ -f "$PROJECT_DIR/certs/hrk.cert" ]]; then
    hrk="$PROJECT_DIR/certs/hrk.cert"
  fi

  if [[ -n "${ATT_HSK_SOURCE:-}" && -f "$ATT_HSK_SOURCE" ]]; then
    hsk="$ATT_HSK_SOURCE"
  elif [[ -f "$PROJECT_DIR/deploy/certs/hsk_cek.cert" ]]; then
    hsk="$PROJECT_DIR/deploy/certs/hsk_cek.cert"
  elif [[ -f "$TEELLM_DIR/certs/hsk_cek.cert" ]]; then
    hsk="$TEELLM_DIR/certs/hsk_cek.cert"
  elif [[ -f "$PROJECT_DIR/certs/hsk_cek.cert" ]]; then
    hsk="$PROJECT_DIR/certs/hsk_cek.cert"
  fi

  echo "$hrk $hsk"
}

prepare_config() {
  local template="$1"
  local output_file="$2"
  local model="$3"
  local port="$4"
  local hrk_path="${5:-}"
  local hsk_path="${6:-}"

  require_file "teellm config template" "$template"
  require_command python3

  python3 - "$template" "$output_file" "$model" "$port" "$hrk_path" "$hsk_path" <<'PY'
import json, sys

template_path, output_path, model, port, hrk_path, hsk_path = sys.argv[1:7]
with open(template_path, "r", encoding="utf-8") as f:
    cfg = json.load(f)

if model:
    cfg.setdefault("backend", {})["defaultModel"] = model
if port:
    cfg.setdefault("server", {})["addr"] = f":{port}"
if hrk_path:
    cfg.setdefault("attestation", {})["hrkCertPath"] = hrk_path
if hsk_path:
    cfg.setdefault("attestation", {})["hskCekCertPath"] = hsk_path

with open(output_path, "w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)
    f.write("\n")
PY
}

# ── Models Management Command ─────────────────────────────────

show_models_usage() {
  cat <<EOF
Usage: $(basename "$0") models <command> [options]

Manage offline LLM models, inspect readiness, and switch active profiles.

Commands:
  list                 List available models with profile details and readiness.
  info <model>         Display detailed profile and verify all blob artifacts.
  switch <model>       Verify readiness and atomically switch active model.
  help                 Display this models help documentation.

Options:
  --ollama-dir <path>  Specify local directory containing offline Ollama bundle.
  -h, --help           Display this help documentation.

Examples:
  $(basename "$0") models list
  $(basename "$0") models info qwen2.5-coder:3b
  $(basename "$0") models switch qwen2.5-coder:3b
EOF
}

handle_models_command() {
  TRAP_SUPPRESS_DEPLOYMENT_BANNER=true
  local target_ollama_dir=""
  local subcmd=""
  local model_arg=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --ollama-dir=*)
        target_ollama_dir="${1#*=}"
        ;;
      --ollama-dir)
        shift
        if [[ $# -eq 0 || "$1" == -* ]]; then
          err "--ollama-dir requires a directory path argument"
          exit 1
        fi
        target_ollama_dir="$1"
        ;;
      -h|--help)
        show_models_usage
        return 0
        ;;
      list|info|switch|help)
        if [[ -z "$subcmd" ]]; then
          subcmd="$1"
        elif [[ -z "$model_arg" ]]; then
          model_arg="$1"
        fi
        ;;
      *)
        if [[ -z "$subcmd" ]]; then
          subcmd="$1"
        elif [[ -z "$model_arg" ]]; then
          model_arg="$1"
        else
          err "unexpected argument: $1"
          show_models_usage >&2
          exit 1
        fi
        ;;
    esac
    shift
  done

  if [[ -z "$subcmd" || "$subcmd" == "help" ]]; then
    show_models_usage
    return 0
  fi

  if [[ -z "$target_ollama_dir" ]]; then
    target_ollama_dir="$(resolve_ollama_local_dir)"
  fi

  require_command python3

  case "$subcmd" in
    list)
      python3 - "$target_ollama_dir" "$TEELLM_DIR" <<'PY'
import os, sys, json, re

ollama_dir = sys.argv[1]
project_dir = sys.argv[2]
models_json_path = os.path.join(project_dir, "configs", "models.json")
docker_cfg_path = os.path.join(project_dir, "configs", "teellm-docker.json")
prod_cfg_path = os.path.join(project_dir, "configs", "teellm-production.json")

catalog_data = {}
active_model = ""
if os.path.isfile(models_json_path):
    try:
        with open(models_json_path, "r", encoding="utf-8") as f:
            catalog_data = json.load(f)
            active_model = catalog_data.get("activeModel", "")
    except Exception:
        pass

if not active_model and os.path.isfile(docker_cfg_path):
    try:
        with open(docker_cfg_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
            active_model = cfg.get("backend", {}).get("defaultModel", "")
    except Exception:
        pass

if not active_model and os.path.isfile(prod_cfg_path):
    try:
        with open(prod_cfg_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
            active_model = cfg.get("backend", {}).get("defaultModel", "")
    except Exception:
        pass

manifests_dir = os.path.join(ollama_dir, "models", "models", "manifests")
blobs_dir = os.path.join(ollama_dir, "models", "models", "blobs")

discovered_manifests = {}
if os.path.isdir(manifests_dir):
    for root, dirs, files in os.walk(manifests_dir):
        for f in files:
            mpath = os.path.join(root, f)
            rel = os.path.relpath(mpath, manifests_dir)
            parts = rel.split(os.sep)
            if parts and parts[0] == "registry.ollama.ai":
                parts = parts[1:]
            if parts and parts[0] == "library":
                parts = parts[1:]
            if len(parts) >= 2:
                model_id = f"{'/'.join(parts[:-1])}:{parts[-1]}"
            elif len(parts) == 1:
                model_id = parts[0]
            else:
                continue
            discovered_manifests[model_id] = mpath

all_model_ids = []
if "models" in catalog_data and isinstance(catalog_data["models"], dict):
    for mid in catalog_data["models"].keys():
        if mid not in all_model_ids:
            all_model_ids.append(mid)

for mid in sorted(discovered_manifests.keys()):
    if mid not in all_model_ids:
        all_model_ids.append(mid)

rows = []
for mid in all_model_ids:
    profile = catalog_data.get("models", {}).get(mid, {})
    family = profile.get("family", "")
    if not family:
        family = mid.split(":")[0] if ":" in mid else mid
    params = profile.get("parameterSize", "-")
    ctx = str(profile.get("options", {}).get("num_ctx", "-"))

    mpath = discovered_manifests.get(mid)
    disk_size_str = "-"
    status = "not found"

    if not mpath and os.path.isdir(manifests_dir):
        if ":" in mid:
            bname, tag = mid.split(":", 1)
        else:
            bname, tag = mid, "latest"
        parts = bname.split("/")
        if len(parts) == 1:
            candidate = os.path.join(manifests_dir, "registry.ollama.ai", "library", parts[0], tag)
        elif len(parts) == 2:
            candidate = os.path.join(manifests_dir, "registry.ollama.ai", parts[0], parts[1], tag)
        else:
            candidate = os.path.join(manifests_dir, *parts, tag)
        if os.path.isfile(candidate):
            mpath = candidate

    if mpath and os.path.isfile(mpath):
        try:
            with open(mpath, "r", encoding="utf-8") as fp:
                mdata = json.load(fp)
            blobs = []
            expected_sizes = {}
            if "config" in mdata and "digest" in mdata["config"]:
                d = mdata["config"]["digest"].replace(":", "-")
                blobs.append(d)
                if "size" in mdata["config"]:
                    expected_sizes[d] = mdata["config"]["size"]
            for layer in mdata.get("layers", []):
                if "digest" in layer:
                    d = layer["digest"].replace(":", "-")
                    blobs.append(d)
                    if "size" in layer:
                        expected_sizes[d] = layer["size"]
            blobs = sorted(list(set(blobs)))

            missing_count = 0
            corrupt_count = 0
            total_bytes = 0
            for b in blobs:
                if not re.match(r"^sha256-[a-f0-9]{64}$", b):
                    missing_count += 1
                    continue
                bp = os.path.join(blobs_dir, b)
                if os.path.isfile(bp):
                    actual_sz = os.path.getsize(bp)
                    total_bytes += actual_sz
                    exp_sz = expected_sizes.get(b)
                    if exp_sz is not None and actual_sz != exp_sz:
                        corrupt_count += 1
                else:
                    missing_count += 1

            if total_bytes >= 1024 * 1024 * 1024:
                disk_size_str = f"{total_bytes / (1024 * 1024 * 1024):.2f} GB"
            elif total_bytes > 0:
                disk_size_str = f"{total_bytes / (1024 * 1024):.2f} MB"
            else:
                disk_size_str = "0 MB"

            if corrupt_count > 0 and missing_count > 0:
                status = f"corrupt {corrupt_count}b, missing {missing_count}b"
            elif corrupt_count > 0:
                status = f"corrupt {corrupt_count}b"
            elif missing_count > 0:
                status = f"missing {missing_count}b"
            elif len(blobs) > 0:
                status = "ready"
            else:
                status = "empty"
        except Exception:
            status = "corrupted"

    is_active = (mid == active_model)
    active_str = "* (active)" if is_active else ""
    rows.append((mid, family, params, disk_size_str, ctx, status, active_str))

headers = ["MODEL", "FAMILY", "PARAMS", "DISK SIZE", "CTX", "STATUS", "ACTIVE"]
col_widths = [len(h) for h in headers]
for row in rows:
    for i, val in enumerate(row):
        col_widths[i] = max(col_widths[i], len(val))

header_line = " | ".join(f"{headers[i]:<{col_widths[i]}}" for i in range(len(headers)))
sep_line = "-+-".join("-" * col_widths[i] for i in range(len(headers)))
print(header_line)
print(sep_line)
for row in rows:
    row_line = " | ".join(f"{row[i]:<{col_widths[i]}}" for i in range(len(headers)))
    print(row_line)
PY
      ;;
    info)
      if [[ -z "$model_arg" ]]; then
        err "model name argument is required for 'models info'"
        show_models_usage >&2
        exit 1
      fi
      local info_rc=0
      python3 - "$target_ollama_dir" "$TEELLM_DIR" "$model_arg" <<'PY' || info_rc=$?
import os, sys, json, re

ollama_dir = sys.argv[1]
project_dir = sys.argv[2]
model_name = sys.argv[3]

MODEL_NAME_PATTERN = r'^[a-zA-Z0-9_.-]+(/[a-zA-Z0-9_.-]+)*(:[a-zA-Z0-9_.-]+)?$'
if not re.match(MODEL_NAME_PATTERN, model_name):
    sys.stderr.write(f"error: invalid model name format: {model_name}\n")
    sys.exit(1)

models_json_path = os.path.join(project_dir, "configs", "models.json")
catalog_data = {}
if os.path.isfile(models_json_path):
    try:
        with open(models_json_path, "r", encoding="utf-8") as f:
            catalog_data = json.load(f)
    except Exception:
        pass

if ":" in model_name:
    base_name, tag = model_name.split(":", 1)
else:
    base_name, tag = model_name, "latest"

parts = base_name.split("/")
manifests_root = os.path.join(ollama_dir, "models", "models", "manifests")
if len(parts) == 1:
    std_rel = os.path.join("models", "models", "manifests", "registry.ollama.ai", "library", parts[0], tag)
elif len(parts) == 2:
    std_rel = os.path.join("models", "models", "manifests", "registry.ollama.ai", parts[0], parts[1], tag)
else:
    std_rel = os.path.join("models", "models", "manifests", *parts, tag)

manifest_rel = std_rel
manifest_full = os.path.join(ollama_dir, std_rel)

manifests_root_real = os.path.realpath(manifests_root)
manifest_real = os.path.realpath(manifest_full)
if not (manifest_real == manifests_root_real or manifest_real.startswith(manifests_root_real + os.sep)):
    sys.stderr.write(f"error: directory traversal detected: {model_name}\n")
    sys.exit(1)

if not os.path.isfile(manifest_full):
    if os.path.isdir(manifests_root):
        for root, dirs, files in os.walk(manifests_root):
            for f in files:
                if f == tag and os.path.basename(root) == parts[-1]:
                    cand = os.path.join(root, f)
                    cand_real = os.path.realpath(cand)
                    if cand_real == manifests_root_real or cand_real.startswith(manifests_root_real + os.sep):
                        manifest_full = cand
                        manifest_rel = os.path.relpath(manifest_full, ollama_dir)
                        break
            if manifest_full and os.path.isfile(manifest_full):
                break

profile = catalog_data.get("models", {}).get(model_name)
print(f"Model: {model_name}")
if profile:
    family = profile.get("family", "-")
    param_size = profile.get("parameterSize", "-")
    rec_ram = str(profile.get("recommendedRamGB", "-"))
    if rec_ram != "-":
        rec_ram += " GB"
    timeout_val = str(profile.get("timeoutSeconds", "-"))
    if timeout_val != "-":
        timeout_val += "s"
    ctx = str(profile.get("options", {}).get("num_ctx", "-"))
    desc = profile.get("description", "")

    print(f"  Family:           {family}")
    print(f"  Parameter Size:   {param_size}")
    print(f"  Recommended RAM:  {rec_ram}")
    print(f"  Timeout:          {timeout_val}")
    print(f"  Context Window:   {ctx}")
    if desc:
        print(f"  Description:      {desc}")
    if "options" in profile and profile["options"]:
        print("  Runtime Options:")
        for k, v in profile["options"].items():
            print(f"    {k}: {v}")
else:
    print("  Profile:          (No profile configured in teellm/configs/models.json)")

print("")
print("Storage & Artifacts:")
if not manifest_full or not os.path.isfile(manifest_full):
    print(f"  Manifest:         Not found on disk ({std_rel})")
    print(f"  Status:           Error: Manifest not found for model '{model_name}'")
    sys.exit(1)

print(f"  Manifest:         {manifest_rel}")

try:
    with open(manifest_full, "r", encoding="utf-8") as fp:
        mdata = json.load(fp)
except (json.JSONDecodeError, OSError) as e:
    sys.stderr.write(f"error: failed to parse manifest '{manifest_full}': {e}\n")
    sys.exit(1)

blobs = []
expected_sizes = {}
if "config" in mdata and "digest" in mdata["config"]:
    d = mdata["config"]["digest"].replace(":", "-")
    blobs.append(("config", d))
    if "size" in mdata["config"]:
        expected_sizes[d] = mdata["config"]["size"]
for layer in mdata.get("layers", []):
    if "digest" in layer:
        media_type = layer.get("mediaType", "layer").split(".")[-1]
        d = layer["digest"].replace(":", "-")
        blobs.append((media_type, d))
        if "size" in layer:
            expected_sizes[d] = layer["size"]

if not blobs:
    sys.stderr.write(f"error: model '{model_name}' manifest contains no layers or blobs\n")
    sys.exit(1)

blobs_dir = os.path.join(ollama_dir, "models", "models", "blobs")
verified_blobs = 0
total_bytes = 0
missing_blobs = []
mismatched_blobs = []

def format_size(bytes_val):
    if bytes_val >= 1024 * 1024 * 1024:
        return f"{bytes_val / (1024 * 1024 * 1024):.2f} GB"
    elif bytes_val >= 1024 * 1024:
        return f"{bytes_val / (1024 * 1024):.2f} MB"
    elif bytes_val >= 1024:
        return f"{bytes_val / 1024:.2f} KB"
    else:
        return f"{bytes_val} B"

print("  Blobs:")
for btype, bdigest in blobs:
    if not re.match(r"^sha256-[a-f0-9]{64}$", bdigest):
        print(f"    - {bdigest} ({btype}) [INVALID DIGEST]")
        missing_blobs.append(bdigest)
        continue
    bpath = os.path.join(blobs_dir, bdigest)
    if os.path.isfile(bpath):
        size = os.path.getsize(bpath)
        total_bytes += size
        exp_sz = expected_sizes.get(bdigest)
        s_str = format_size(size)
        if exp_sz is not None and size != exp_sz:
            mismatched_blobs.append((bdigest, exp_sz, size))
            exp_str = format_size(exp_sz)
            print(f"    - {bdigest[:19]}... ({btype}, actual {s_str}, expected {exp_str}) [SIZE MISMATCH]")
        else:
            verified_blobs += 1
            print(f"    - {bdigest[:19]}... ({btype}, {s_str}) [OK]")
    else:
        missing_blobs.append(bdigest)
        print(f"    - {bdigest[:19]}... ({btype}) [MISSING]")

tot_str = format_size(total_bytes)
if missing_blobs or mismatched_blobs:
    details = []
    if missing_blobs:
        details.append(f"{len(missing_blobs)} missing")
    if mismatched_blobs:
        details.append(f"{len(mismatched_blobs)} size mismatch")
    print(f"  Status:           Incomplete / Size mismatch: {', '.join(details)} out of {len(blobs)} blobs ({tot_str} on disk)")
    sys.exit(1)
else:
    print(f"  Status:           Ready: All {len(blobs)} blobs present on disk ({tot_str})")
PY
      if [[ $info_rc -ne 0 ]]; then
        exit $info_rc
      fi
      ;;
    switch)
      if [[ -z "$model_arg" ]]; then
        err "model name argument is required for 'models switch'"
        show_models_usage >&2
        exit 1
      fi
      local switch_output=""
      local switch_rc=0
      switch_output=$(python3 - "$target_ollama_dir" "$TEELLM_DIR" "$model_arg" <<'PY'
import os, sys, json, re

ollama_dir = sys.argv[1]
project_dir = sys.argv[2]
model_name = sys.argv[3]

MODEL_NAME_PATTERN = r'^[a-zA-Z0-9_.-]+(/[a-zA-Z0-9_.-]+)*(:[a-zA-Z0-9_.-]+)?$'
if not re.match(MODEL_NAME_PATTERN, model_name):
    sys.stderr.write(f"error: invalid model name format: {model_name}\n")
    sys.exit(1)

if ":" in model_name:
    base_name, tag = model_name.split(":", 1)
else:
    base_name, tag = model_name, "latest"

parts = base_name.split("/")
manifests_root = os.path.join(ollama_dir, "models", "models", "manifests")
if len(parts) == 1:
    std_rel = os.path.join("models", "models", "manifests", "registry.ollama.ai", "library", parts[0], tag)
elif len(parts) == 2:
    std_rel = os.path.join("models", "models", "manifests", "registry.ollama.ai", parts[0], parts[1], tag)
else:
    std_rel = os.path.join("models", "models", "manifests", *parts, tag)

manifest_rel = std_rel
manifest_full = os.path.join(ollama_dir, std_rel)

manifests_root_real = os.path.realpath(manifests_root)
manifest_real = os.path.realpath(manifest_full)
if not (manifest_real == manifests_root_real or manifest_real.startswith(manifests_root_real + os.sep)):
    sys.stderr.write(f"error: directory traversal detected: {model_name}\n")
    sys.exit(1)

if not os.path.isfile(manifest_full):
    if os.path.isdir(manifests_root):
        for root, dirs, files in os.walk(manifests_root):
            for f in files:
                if f == tag and os.path.basename(root) == parts[-1]:
                    cand = os.path.join(root, f)
                    cand_real = os.path.realpath(cand)
                    if cand_real == manifests_root_real or cand_real.startswith(manifests_root_real + os.sep):
                        manifest_full = cand
                        manifest_rel = os.path.relpath(manifest_full, ollama_dir)
                        break
            if manifest_full and os.path.isfile(manifest_full):
                break

if not manifest_full or not os.path.isfile(manifest_full):
    sys.stderr.write(f"error: model '{model_name}' manifest not found on disk ({manifest_rel})\n")
    sys.exit(1)

try:
    with open(manifest_full, "r", encoding="utf-8") as fp:
        mdata = json.load(fp)
except (json.JSONDecodeError, OSError) as e:
    sys.stderr.write(f"error: failed to parse manifest '{manifest_full}': {e}\n")
    sys.exit(1)

blobs = []
expected_sizes = {}
if "config" in mdata and "digest" in mdata["config"]:
    d = mdata["config"]["digest"].replace(":", "-")
    blobs.append(d)
    if "size" in mdata["config"]:
        expected_sizes[d] = mdata["config"]["size"]
for layer in mdata.get("layers", []):
    if "digest" in layer:
        d = layer["digest"].replace(":", "-")
        blobs.append(d)
        if "size" in layer:
            expected_sizes[d] = layer["size"]

blobs = sorted(list(set(blobs)))

if not blobs:
    sys.stderr.write(f"error: model '{model_name}' manifest contains no layers or blobs\n")
    sys.exit(1)

blobs_dir = os.path.join(ollama_dir, "models", "models", "blobs")
missing = []
corrupted = []
for b in blobs:
    if not re.match(r"^sha256-[a-f0-9]{64}$", b):
        sys.stderr.write(f"error: invalid blob digest format: {b}\n")
        sys.exit(1)
    bp = os.path.join(blobs_dir, b)
    if not os.path.isfile(bp):
        missing.append(b)
    else:
        act_sz = os.path.getsize(bp)
        exp_sz = expected_sizes.get(b)
        if exp_sz is not None and act_sz != exp_sz:
            corrupted.append((b, exp_sz, act_sz))

if missing:
    sys.stderr.write(f"error: model '{model_name}' has {len(missing)} missing blob(s) on disk\n")
    sys.exit(1)

if corrupted:
    sys.stderr.write(f"error: model '{model_name}' has {len(corrupted)} corrupted or size-mismatched blob(s) on disk\n")
    for b, exp, act in corrupted:
        sys.stderr.write(f"  - blob {b}: expected {exp} bytes, got {act} bytes\n")
    sys.exit(1)

def atomic_update_json(filepath, updater):
    if not os.path.isfile(filepath):
        return False
    dir_name = os.path.dirname(filepath)
    base_name = os.path.basename(filepath)
    tmp_path = os.path.join(dir_name, f".{base_name}.tmp.{os.getpid()}")
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        updater(data)
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write("\n")
        os.replace(tmp_path, filepath)
        return True
    except Exception as e:
        sys.stderr.write(f"error: failed to update {filepath}: {e}\n")
        return False
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass

models_json = os.path.join(project_dir, "configs", "models.json")
docker_json = os.path.join(project_dir, "configs", "teellm-docker.json")
prod_json = os.path.join(project_dir, "configs", "teellm-production.json")

def update_models(d):
    d["activeModel"] = model_name

def update_cfg(d):
    d.setdefault("backend", {})["defaultModel"] = model_name

targets = [
    (models_json, "activeModel", update_models),
    (docker_json, "backend.defaultModel", update_cfg),
    (prod_json, "backend.defaultModel", update_cfg),
]

updated = []
for filepath, key_desc, updater in targets:
    rel_path = os.path.relpath(filepath, project_dir)
    if os.path.isfile(filepath):
        if atomic_update_json(filepath, updater):
            updated.append((rel_path, key_desc))
        else:
            sys.stderr.write(f"warning: failed to update {rel_path}\n")
    else:
        sys.stderr.write(f"warning: {rel_path} not found\n")

if not updated:
    sys.stderr.write("error: no configuration files were updated\n")
    sys.exit(1)

for rel_path, key_desc in updated:
    print(f"UPDATED:{rel_path}:{key_desc}")
PY
      ) || switch_rc=$?

      if [[ $switch_rc -ne 0 ]]; then
        err "failed to switch active model to '$model_arg'"
        exit $switch_rc
      fi

      info "Active model successfully switched to: ${BOLD}$model_arg${NC}"
      while IFS=: read -r tag file key; do
        if [[ "$tag" == "UPDATED" ]]; then
          detail "$file -> $key: $model_arg"
        fi
      done <<< "$switch_output"
      echo ""
      echo -e "${BOLD}Next steps to deploy with ${model_arg}:${NC}"
      echo "  Deploy to local Docker:      ./deploy-llm.sh docker start"
      echo "  Deploy to remote Kubernetes: ./deploy-llm.sh remote start"
      ;;
    *)
      err "unknown models subcommand: $subcmd"
      show_models_usage >&2
      exit 1
      ;;
  esac
}

# ── CLI Usage and Options Parsing ─────────────────────────────

usage() {
  cat <<EOF
Usage: $(basename "$0") [docker|remote-docker|remote] [start|stop|probe] [options]
       $(basename "$0") models [list|info|switch] [args]

Deploy and manage standalone TEE-LLM inference service and offline Ollama runtime.

Model Management Commands:
  models list                  List available models and active selection.
  models info <model>          Display detailed profile and blob readiness for a model.
  models switch <model>        Verify and switch active model across configurations.

Targets:
  docker       Deploy to a local Docker container (default, container: $LOCAL_DOCKER_CONTAINER).
  remote-docker
               Deploy to a Docker container on the remote host over SSH
               (default container: $REMOTE_DOCKER_CONTAINER on ${REMOTE_USER}@${REMOTE_HOST}).
  remote       Deploy to remote Kubernetes Pod / host via SSH and kubectl.

Actions:
  start        Build binary, incrementally sync model & runtime, start daemons, and verify (default).
  stop         Stop target services (teellm-service, ollama, llama-server).
  probe        Probe target TEE-LLM HTTPS endpoint for RFC 8998 TEE-TLS 1.3 readiness.

Options:
  --model <name> (or --model=<name>)
      Specify target LLM model name (default: qwen2.5-coder:3b).
  --ollama-dir <path> (or --ollama-dir=<path>)
      Specify local directory containing offline Ollama package and models.
  --container <name> (or --container=<name>)
      Specify target local Docker container name (docker mode).
  --remote-container <name> (or --remote-container=<name>)
      Specify target Docker container name on the remote host (remote-docker mode).
  --port <port> (or --port=<port>)
      Specify TEE-LLM service listening port (default: $TEELLM_PORT).
  --config <path> (or --config=<path>)
      Specify path to alternate service JSON configuration template.
  -h, --help, help
      Display this help documentation.

Environment overrides:
  LOCAL_DOCKER_CONTAINER=${LOCAL_DOCKER_CONTAINER}
      Local Docker container name.
  REMOTE_DOCKER_CONTAINER=${REMOTE_DOCKER_CONTAINER}
      Docker container name on the remote host (remote-docker mode).
  TEELLM_PORT=${TEELLM_PORT}
      TEE-LLM service listening port.
  OLLAMA_LOCAL_DIR=${OLLAMA_LOCAL_DIR:-}
      Path to offline Ollama and model weights bundle.
  OLLAMA_MODEL=${OLLAMA_MODEL:-}
      Default model override for inference.
  CON_WORKDIR=${CON_WORKDIR}
      Working directory inside target container.
  CONTAINER_OLLAMA_DIR=${CONTAINER_OLLAMA_DIR}
      Ollama deployment directory inside target container.
  TARGET_NAMESPACE=${TARGET_NAMESPACE}
      Remote Kubernetes namespace.
  TARGET_POD=${TARGET_POD}
      Remote Kubernetes target Pod name.
  REMOTE_HOST=${REMOTE_HOST}
      Remote SSH host IP or hostname.
  REMOTE_USER=${REMOTE_USER}
      Remote SSH login username.
  PASSWORD=<hidden>
      Remote SSH password override (or TARGET_PASSWORD).
  TEELLM_CONFIG_PATH=${TEELLM_CONFIG_PATH:-}
      Custom configuration JSON path.

Examples:
  $(basename "$0")
  $(basename "$0") models list
  $(basename "$0") models info qwen2.5-coder:3b
  $(basename "$0") models switch qwen2.5-coder:3b
  $(basename "$0") docker start
  $(basename "$0") docker start --model qwen2.5-coder:7b
  $(basename "$0") docker stop
  $(basename "$0") docker probe
  $(basename "$0") remote-docker start
  $(basename "$0") remote-docker start --model qwen2.5-coder:7b
  $(basename "$0") remote-docker start --remote-container taa-env-slim-v2
  $(basename "$0") remote-docker probe
  $(basename "$0") remote-docker stop
  $(basename "$0") remote start
  $(basename "$0") remote probe
  $(basename "$0") remote stop
EOF
}

DEPLOY_DOCKER=false
DEPLOY_REMOTE=false
REMOTE_CONTAINER_MODE=false
MODE=""
ACTION=""
CLI_MODEL=""
CLI_OLLAMA_DIR=""
CLI_CONTAINER=""
CLI_REMOTE_CONTAINER=""
CLI_PORT=""
CLI_CONFIG=""

while [[ $# -gt 0 ]]; do
  arg="$1"
  case "$arg" in
    models)
      TRAP_SUPPRESS_DEPLOYMENT_BANNER=true
      shift
      handle_models_command "$@"
      exit 0
      ;;
    docker)
      if [[ -n "$MODE" && "$MODE" != "docker" ]]; then
        err "cannot specify multiple targets ($MODE and docker)"
        usage >&2
        exit 1
      fi
      MODE="docker"
      ;;
    remote-docker)
      if [[ -n "$MODE" && "$MODE" != "remote-docker" ]]; then
        err "cannot specify multiple targets ($MODE and remote-docker)"
        usage >&2
        exit 1
      fi
      MODE="remote-docker"
      ;;
    remote)
      if [[ -n "$MODE" && "$MODE" != "remote" ]]; then
        err "cannot specify multiple targets ($MODE and remote)"
        usage >&2
        exit 1
      fi
      MODE="remote"
      ;;
    start)
      if [[ -n "$ACTION" && "$ACTION" != "start" ]]; then
        err "cannot specify multiple actions ($ACTION and start)"
        usage >&2
        exit 1
      fi
      ACTION="start"
      ;;
    stop)
      if [[ -n "$ACTION" && "$ACTION" != "stop" ]]; then
        err "cannot specify multiple actions ($ACTION and stop)"
        usage >&2
        exit 1
      fi
      ACTION="stop"
      ;;
    probe)
      if [[ -n "$ACTION" && "$ACTION" != "probe" ]]; then
        err "cannot specify multiple actions ($ACTION and probe)"
        usage >&2
        exit 1
      fi
      ACTION="probe"
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
    --ollama-dir=*)
      CLI_OLLAMA_DIR="${arg#*=}"
      ;;
    --ollama-dir)
      shift
      if [[ $# -eq 0 || "$1" == -* ]]; then
        err "--ollama-dir requires a directory path argument"
        usage >&2
        exit 1
      fi
      CLI_OLLAMA_DIR="$1"
      ;;
    --container=*)
      CLI_CONTAINER="${arg#*=}"
      ;;
    --container)
      shift
      if [[ $# -eq 0 || "$1" == -* ]]; then
        err "--container requires a container name argument"
        usage >&2
        exit 1
      fi
      CLI_CONTAINER="$1"
      ;;
    --remote-container=*)
      CLI_REMOTE_CONTAINER="${arg#*=}"
      ;;
    --remote-container)
      shift
      if [[ $# -eq 0 || "$1" == -* ]]; then
        err "--remote-container requires a container name argument"
        usage >&2
        exit 1
      fi
      CLI_REMOTE_CONTAINER="$1"
      ;;
    --port=*)
      CLI_PORT="${arg#*=}"
      ;;
    --port)
      shift
      if [[ $# -eq 0 || "$1" == -* ]]; then
        err "--port requires a port number argument"
        usage >&2
        exit 1
      fi
      CLI_PORT="$1"
      ;;
    --config=*)
      CLI_CONFIG="${arg#*=}"
      ;;
    --config)
      shift
      if [[ $# -eq 0 || "$1" == -* ]]; then
        err "--config requires a file path argument"
        usage >&2
        exit 1
      fi
      CLI_CONFIG="$1"
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

# The target keyword is stored as a single mode so that two targets can never be combined;
# the booleans below are what the rest of the script switches on.
MODE="${MODE:-docker}"
case "$MODE" in
  docker) DEPLOY_DOCKER=true ;;
  remote) DEPLOY_REMOTE=true ;;
  remote-docker) REMOTE_CONTAINER_MODE=true ;;
esac

ACTION="${ACTION:-start}"

if [[ -n "$CLI_CONTAINER" ]]; then
  LOCAL_DOCKER_CONTAINER="$CLI_CONTAINER"
fi
if [[ -n "$CLI_REMOTE_CONTAINER" ]]; then
  REMOTE_DOCKER_CONTAINER="$CLI_REMOTE_CONTAINER"
fi

# The container the deployment body operates on: whichever daemon the selected target owns.
if [[ "$REMOTE_CONTAINER_MODE" == true ]]; then
  TARGET_CONTAINER="$REMOTE_DOCKER_CONTAINER"
else
  TARGET_CONTAINER="$LOCAL_DOCKER_CONTAINER"
fi

if [[ -n "$CLI_PORT" ]]; then
  TEELLM_PORT="$CLI_PORT"
fi
if [[ -n "$CLI_CONFIG" ]]; then
  TEELLM_CONFIG_PATH="$CLI_CONFIG"
fi

cd "$PROJECT_DIR"

# ── Probe Action Handler ──────────────────────────────────────

if [[ "$ACTION" == "probe" ]]; then
  banner "Probing TEE-LLM Service" "Endpoint: https://127.0.0.1:${TEELLM_PORT}"
  if [[ "$DEPLOY_REMOTE" != true ]]; then
    probe_where="the local docker daemon"
    if [[ "$REMOTE_CONTAINER_MODE" == true ]]; then
      probe_where="${REMOTE_USER}@${REMOTE_HOST}"
    fi
    step "probing teellm-service in container ($TARGET_CONTAINER on $probe_where)"
    if ! dk ps --format '{{.Names}}' | grep -Eq "^${TARGET_CONTAINER}\$"; then
      err "docker container '$TARGET_CONTAINER' is not running"
      exit 1
    fi
    if dk exec -i "$TARGET_CONTAINER" "$CON_WORKDIR/teellm-service" -probe "https://127.0.0.1:${TEELLM_PORT}"; then
      info "probe check successful: teellm-service is healthy on https://127.0.0.1:${TEELLM_PORT}"
      exit 0
    else
      err "probe check failed on https://127.0.0.1:${TEELLM_PORT}"
      exit 1
    fi
  else
    step "probing teellm-service in remote pod ($TARGET_POD)"
    ensure_remote_ssh
    if remote_ssh "$(container_exec) \"$CON_WORKDIR/teellm-service\" -probe \"https://127.0.0.1:${TEELLM_PORT}\""; then
      info "remote probe check successful: teellm-service is healthy on https://127.0.0.1:${TEELLM_PORT}"
      exit 0
    else
      err "remote probe check failed on https://127.0.0.1:${TEELLM_PORT}"
      exit 1
    fi
  fi
fi

# ── Stop Action Handler ───────────────────────────────────────

if [[ "$ACTION" == "stop" ]]; then
  banner "Stopping TEE-LLM Services"
  if [[ "$DEPLOY_REMOTE" != true ]]; then
    step "stopping teellm-service and ollama in container ($TARGET_CONTAINER)"
    if dk ps --format '{{.Names}}' | grep -Eq "^${TARGET_CONTAINER}\$"; then
      dk exec -i "$TARGET_CONTAINER" sh -lc "touch '$CON_WORKDIR/manual-teellm'; pkill -f '[s]tart-teellm\.sh' >/dev/null 2>&1 || true; pkill -x teellm-service >/dev/null 2>&1 || true; killall teellm-service >/dev/null 2>&1 || true; pkill -x ollama >/dev/null 2>&1 || true; killall ollama >/dev/null 2>&1 || true; pkill -x llama-server >/dev/null 2>&1 || true; killall llama-server >/dev/null 2>&1 || true" 2>/dev/null || true
      for _ in {1..20}; do
        if ! dk exec -i "$TARGET_CONTAINER" sh -lc "pgrep -f '[s]tart-teellm\.sh' >/dev/null 2>&1 || pgrep -x teellm-service >/dev/null 2>&1 || pgrep -x ollama >/dev/null 2>&1"; then
          break
        fi
        sleep 0.2
      done
    fi
    info "teellm-service, ollama, and llama-server stopped cleanly in $TARGET_CONTAINER"
    exit 0
  else
    step "stopping teellm-service and ollama in remote pod ($TARGET_POD)"
    ensure_remote_ssh
    remote_ssh "$(container_exec) sh -lc 'pkill -x teellm-service >/dev/null 2>&1 || true; killall teellm-service >/dev/null 2>&1 || true; pkill -x ollama >/dev/null 2>&1 || true; killall ollama >/dev/null 2>&1 || true; pkill -x llama-server >/dev/null 2>&1 || true; killall llama-server >/dev/null 2>&1 || true'" 2>/dev/null || true
    info "teellm-service, ollama, and llama-server stopped cleanly in remote pod $TARGET_POD"
    exit 0
  fi
fi

# ── Deployment Logic (start) ──────────────────────────────────

OLLAMA_LOCAL_DIR="$(resolve_ollama_local_dir)"
OLLAMA_MODEL="$(resolve_target_model)"

require_dir "ollama offline package" "$OLLAMA_LOCAL_DIR"
require_file "ollama executable" "$OLLAMA_LOCAL_DIR/ollama"
require_file "start-ollama.sh script" "$OLLAMA_LOCAL_DIR/start-ollama.sh"
require_dir "ollama models directory" "$OLLAMA_LOCAL_DIR/models/models"
require_dir "ollama lib directory" "$OLLAMA_LOCAL_DIR/lib/ollama"
verify_ollama_binary "$OLLAMA_LOCAL_DIR/ollama"

# Read model metadata
model_meta="$(resolve_ollama_model_artifacts "$OLLAMA_LOCAL_DIR" "$OLLAMA_MODEL" "json")"
model_mb="$(python3 -c 'import sys, json; print(json.loads(sys.argv[1])["weight_mb"])' "$model_meta" 2>/dev/null || echo "unknown")"

# Certificates resolution
cert_pair=($(resolve_certificates))
LOCAL_HRK_CERT="${cert_pair[0]:-}"
LOCAL_HSK_CERT="${cert_pair[1]:-}"

# Build teellm-service locally
build_local_binary() {
  step "building teellm-service from ./teellm/cmd/teellm-service"
  ensure_go_compiler
  require_file "teellm supervisor script missing" "$TEELLM_DIR/deploy/start.sh"
  mkdir -p "$TEELLM_DIR/bin"
  # The teellm module is a sibling of this script in the go.work workspace, so the package
  # path resolves from the repository root exactly like ./tools/platform-mock does in deploy.sh.
  spin_task "compiling teellm-service binary" go build -o "$TEELLM_DIR/bin/teellm-service" ./teellm/cmd/teellm-service
  require_file "build verification failed (teellm-service binary missing)" "$TEELLM_DIR/bin/teellm-service"
  info "teellm-service binary built: $TEELLM_DIR/bin/teellm-service"
}

# ── Container Deployment Mode (local docker or remote docker over SSH) ────────

deploy_container() {
  if [[ "$REMOTE_CONTAINER_MODE" == true ]]; then
    banner "Deploying TEE-LLM Service (Remote Docker)" \
      "Host: ${REMOTE_USER}@${REMOTE_HOST} | Container: $TARGET_CONTAINER | Model: $OLLAMA_MODEL (${model_mb}MB)"
    step "verifying remote host connectivity"
    check_remote_connectivity
  else
    banner "Deploying TEE-LLM Service (Docker)" \
      "Container: $TARGET_CONTAINER | Model: $OLLAMA_MODEL (${model_mb}MB)"
    require_command docker
  fi

  dk info >/dev/null 2>&1 || {
    err "docker daemon is not running or not accessible"
    if [[ "$REMOTE_CONTAINER_MODE" == true ]]; then
      detail "Check that the docker daemon on ${REMOTE_USER}@${REMOTE_HOST} is up and that ${REMOTE_USER} may use it."
    fi
    exit 1
  }

  ensure_target_container
  build_local_binary

  step "checking attestation prerequisites inside container"
  if ! dk exec -i "$TARGET_CONTAINER" sh -lc 'test -e /dev/csv-guest' 2>/dev/null; then
    warn "/dev/csv-guest not found in container (mock attestation provider fallback active)"
  else
    info "Hygon CSV hardware attestation device /dev/csv-guest detected"
  fi

  # Incremental sync of Ollama package and model
  # An image that shipped the bundle under its older name keeps that runtime on disk; move it
  # into place instead of streaming several GB of identical libraries again. The
  # is-not-a-symlink guard skips containers that carry an alias left behind by an earlier
  # revision of this script.
  if [[ "$CONTAINER_LEGACY_OLLAMA_DIR" != "$CONTAINER_OLLAMA_DIR" ]]; then
    if dk exec -i "$TARGET_CONTAINER" sh -lc "test -d '$CONTAINER_LEGACY_OLLAMA_DIR/lib/ollama' && ! test -L '$CONTAINER_LEGACY_OLLAMA_DIR' && ! test -d '$CONTAINER_OLLAMA_DIR/lib/ollama'" >/dev/null 2>&1; then
      step "migrating the existing ollama runtime from $CONTAINER_LEGACY_OLLAMA_DIR"
      dk exec -i "$TARGET_CONTAINER" sh -lc "mkdir -p '$CON_WORKDIR' && if [ ! -d '$CONTAINER_OLLAMA_DIR' ]; then mv '$CONTAINER_LEGACY_OLLAMA_DIR' '$CONTAINER_OLLAMA_DIR'; elif [ ! -d '$CONTAINER_OLLAMA_DIR/lib' ]; then cp -r -n '$CONTAINER_LEGACY_OLLAMA_DIR/lib' '$CONTAINER_OLLAMA_DIR/'; fi"
      info "existing ollama runtime reused from $CONTAINER_LEGACY_OLLAMA_DIR"
    fi
  fi

  step "checking ollama package and model weights inside container"
  dk exec -i "$TARGET_CONTAINER" mkdir -p "$CONTAINER_OLLAMA_DIR" "$CON_WORKDIR/certs" "$CON_WORKDIR/configs"

  local check_script has_base_runtime=false has_lib=false has_model=false
  check_script="$(resolve_ollama_model_artifacts "$OLLAMA_LOCAL_DIR" "$OLLAMA_MODEL" "check_model_sh" "$CONTAINER_OLLAMA_DIR")"

  if dk exec -i "$TARGET_CONTAINER" sh -lc "test -f '$CONTAINER_OLLAMA_DIR/ollama' && test -f '$CONTAINER_OLLAMA_DIR/start-ollama.sh' && test -f '$CONTAINER_OLLAMA_DIR/lib/ollama/libllama-server-impl.so'"; then
    has_base_runtime=true
  fi
  if dk exec -i "$TARGET_CONTAINER" sh -lc "test -f '$CONTAINER_OLLAMA_DIR/lib/ollama/libllama-server-impl.so'"; then
    has_lib=true
  fi
  if dk exec -i "$TARGET_CONTAINER" sh -lc "$check_script" >/dev/null 2>&1; then
    has_model=true
  fi

  if [[ "$FORCE_QWEN_COPY" == false && "$has_base_runtime" == true && "$has_model" == true ]]; then
    info "ollama runtime and target model '$OLLAMA_MODEL' (${model_mb}MB) already present in container"
  elif [[ "$FORCE_QWEN_COPY" == false && "$has_base_runtime" == true && "$has_model" == false ]]; then
    step "incrementally copying model '$OLLAMA_MODEL' (${model_mb}MB) into container"
    local qwen_filelist
    qwen_filelist="$(mktemp /tmp/teellm_qwen_files.XXXXXX)"
    TEMP_FILELIST="$qwen_filelist"
    resolve_ollama_model_artifacts "$OLLAMA_LOCAL_DIR" "$OLLAMA_MODEL" "model_only" > "$qwen_filelist"
    spin_task "transferring model weights (${model_mb}MB) into container" \
      stream_files_into_container "$OLLAMA_LOCAL_DIR" "$qwen_filelist" "$CONTAINER_OLLAMA_DIR"
    rm -f "$qwen_filelist"
    TEMP_FILELIST=""
    info "incremental model transfer completed"
  else
    step "copying ollama runtime and model '$OLLAMA_MODEL' (${model_mb}MB) into container"
    local qwen_filelist
    qwen_filelist="$(mktemp /tmp/teellm_qwen_files.XXXXXX)"
    TEMP_FILELIST="$qwen_filelist"

    if [[ "$FORCE_QWEN_COPY" == true ]]; then
      dk exec -i "$TARGET_CONTAINER" rm -rf "$CONTAINER_OLLAMA_DIR"
      dk exec -i "$TARGET_CONTAINER" mkdir -p "$CONTAINER_OLLAMA_DIR"
      resolve_ollama_model_artifacts "$OLLAMA_LOCAL_DIR" "$OLLAMA_MODEL" "full" > "$qwen_filelist"
    elif [[ "$has_lib" == true ]]; then
      info "reusing existing lib directory in container; syncing runtime scripts and model"
      {
        echo "ollama"
        echo "start-ollama.sh"
        for opt in "models/cache" "models/models/cache" "models/models/id_ed25519" "models/models/id_ed25519.pub"; do
          [[ -e "$OLLAMA_LOCAL_DIR/$opt" ]] && echo "$opt"
        done
        resolve_ollama_model_artifacts "$OLLAMA_LOCAL_DIR" "$OLLAMA_MODEL" "model_only"
      } > "$qwen_filelist"
    else
      resolve_ollama_model_artifacts "$OLLAMA_LOCAL_DIR" "$OLLAMA_MODEL" "full" > "$qwen_filelist"
    fi

    spin_task "transferring ollama bundle into container" \
      stream_files_into_container "$OLLAMA_LOCAL_DIR" "$qwen_filelist" "$CONTAINER_OLLAMA_DIR"
    rm -f "$qwen_filelist"
    TEMP_FILELIST=""
    info "ollama package transfer completed"
  fi

  dk exec -i "$TARGET_CONTAINER" sh -lc "chmod +x '$CONTAINER_OLLAMA_DIR/ollama' '$CONTAINER_OLLAMA_DIR/start-ollama.sh' '$CONTAINER_OLLAMA_DIR/lib/ollama/llama-'* 2>/dev/null || true"

  # Restore the soname symlinks llama-server needs; the bundle ships versioned files only.
  local soname_links
  soname_links="$(dk exec -i "$TARGET_CONTAINER" sh -lc "$(ollama_soname_fix_script)" sh "$CONTAINER_OLLAMA_DIR/lib/ollama" 2>/dev/null || echo 0)"
  if [[ "${soname_links:-0}" != "0" ]]; then
    info "restored $soname_links ollama soname symlink(s) in $CONTAINER_OLLAMA_DIR/lib/ollama"
  fi

  # Start Ollama daemon
  step "checking ollama daemon status inside container"
  local ollama_already_running=false ollama_tags=""
  # A daemon answering on the port is only reusable if it serves the model this deployment
  # installs. A container that shipped the older layout keeps its own daemon running from
  # $CONTAINER_LEGACY_OLLAMA_DIR, pointed at that directory's model set, so it would answer the
  # port while being unable to serve the deployed model. Asking /api/tags which models the
  # running daemon actually has tells the two apart, whichever directory it was started from.
  ollama_tags="$(dk exec -i "$TARGET_CONTAINER" curl -fsS "http://$OLLAMA_HOST/api/tags" 2>/dev/null || true)"
  if grep -q "\"$OLLAMA_MODEL\"" <<<"$ollama_tags"; then
    ollama_already_running=true
    info "ollama daemon is already active on http://$OLLAMA_HOST with model '$OLLAMA_MODEL'"
  elif [[ -n "$ollama_tags" ]]; then
    warn "replacing the ollama daemon already listening on $OLLAMA_HOST: it does not serve '$OLLAMA_MODEL'"
    step "stopping the stale ollama daemon inside container"
    dk exec -i "$TARGET_CONTAINER" sh -lc "pkill -x ollama >/dev/null 2>&1 || true; killall ollama >/dev/null 2>&1 || true; pkill -x llama-server >/dev/null 2>&1 || true; killall llama-server >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
    for _ in {1..20}; do
      if ! dk exec -i "$TARGET_CONTAINER" sh -lc "pgrep -x ollama >/dev/null 2>&1" >/dev/null 2>&1; then
        break
      fi
      sleep 0.5
    done
    info "stale ollama daemon stopped"
  fi

  if [[ "$ollama_already_running" == false ]]; then
    step "starting ollama daemon inside container"
    dk exec -d "$TARGET_CONTAINER" sh -lc "cd '$CONTAINER_OLLAMA_DIR' && exec env OLLAMA_HOST='$OLLAMA_HOST' OLLAMA_MODELS='$CONTAINER_OLLAMA_DIR/models/models' OLLAMA_LIBRARY_PATH='$CONTAINER_OLLAMA_DIR/lib/ollama' ./start-ollama.sh > '$OLLAMA_LOG_FILE' 2>&1"

    step "waiting for ollama service to become ready"
    local ollama_ready=false
    local wait_start_ts
    wait_start_ts=$(date +%s)
    cursor_hide
    local spin_len=${#SPIN_FRAMES[@]}
    local i=0
    for ((attempt=1; attempt<=OLLAMA_READY_TIMEOUT/OLLAMA_READY_INTERVAL; attempt++)); do
      if dk exec -i "$TARGET_CONTAINER" curl -fsS "http://$OLLAMA_HOST/api/tags" >/dev/null 2>&1; then
        ollama_ready=true
        break
      fi
      if [[ "$IS_TTY" == true ]]; then
        local now
        now=$(date +%s)
        local elapsed=$((now - wait_start_ts))
        local frame="${SPIN_FRAMES[$i]}"
        printf "\r   ${CYAN}%s${NC} waiting for ollama daemon ${DIM}(%ds / %ds)...${NC}" "$frame" "$elapsed" "$OLLAMA_READY_TIMEOUT"
        i=$(( (i + 1) % spin_len ))
      fi
      sleep "$OLLAMA_READY_INTERVAL"
    done
    cursor_show
    printf "\r\033[K"
    if [[ "$ollama_ready" != true ]]; then
      err "ollama daemon did not become ready within ${OLLAMA_READY_TIMEOUT}s"
      dk exec -i "$TARGET_CONTAINER" tail -n 50 "$OLLAMA_LOG_FILE" || true
      exit 1
    fi
    info "ollama daemon ready and responding on http://$OLLAMA_HOST"
  fi

  # Deploy certificates if available locally
  step "configuring attestation certificates"
  if [[ -n "$LOCAL_HRK_CERT" && -n "$LOCAL_HSK_CERT" ]]; then
    ctr_cp_in "$LOCAL_HRK_CERT" "$CON_WORKDIR/certs/hrk.cert" >/dev/null
    ctr_cp_in "$LOCAL_HSK_CERT" "$CON_WORKDIR/certs/hsk_cek.cert" >/dev/null
    info "certificates deployed: $CON_WORKDIR/certs/hrk.cert and hsk_cek.cert"
  else
    if dk exec -i "$TARGET_CONTAINER" sh -lc "test -f '$CON_WORKDIR/certs/hrk.cert' && test -f '$CON_WORKDIR/certs/hsk_cek.cert'"; then
      info "using existing certificates inside container ($CON_WORKDIR/certs)"
    else
      warn "attestation certificates not found locally or in container; fallback mock will be used"
    fi
  fi

  # Prepare & Copy teellm-docker.json
  step "preparing and deploying teellm configuration"
  local cfg_template="${TEELLM_CONFIG_PATH:-$TEELLM_DIR/configs/teellm-docker.json}"
  local tmp_cfg
  tmp_cfg="$(mktemp /tmp/teellm_cfg.XXXXXX)"
  TEMP_CONFIG_FILE="$tmp_cfg"
  prepare_config "$cfg_template" "$tmp_cfg" "$OLLAMA_MODEL" "$TEELLM_PORT" "$CON_WORKDIR/certs/hrk.cert" "$CON_WORKDIR/certs/hsk_cek.cert"
  ctr_cp_in "$tmp_cfg" "$CON_WORKDIR/configs/teellm-docker.json" "teellm-docker.json"
  ctr_cp_in "$tmp_cfg" "$CON_WORKDIR/teellm-docker.json" "teellm-docker.json" 2>/dev/null || true
  if [[ -f "$TEELLM_DIR/configs/models.json" ]]; then
    ctr_cp_in "$TEELLM_DIR/configs/models.json" "$CON_WORKDIR/configs/models.json" >/dev/null 2>&1 || true
  fi
  rm -f "$tmp_cfg"
  TEMP_CONFIG_FILE=""
  info "configuration deployed to $TARGET_CONTAINER:$CON_WORKDIR/configs/teellm-docker.json"

  # Copy teellm-service binary and supervisor script
  step "copying teellm-service binary and supervisor script into container"
  ctr_cp_in "$TEELLM_DIR/bin/teellm-service" "$CON_WORKDIR/teellm-service"
  ctr_cp_in "$TEELLM_DIR/deploy/start.sh" "$CON_WORKDIR/start-teellm.sh"
  dk exec -i "$TARGET_CONTAINER" sh -lc "chmod +x '$CON_WORKDIR/teellm-service' '$CON_WORKDIR/start-teellm.sh'"
  info "binary and supervisor deployed to $TARGET_CONTAINER:$CON_WORKDIR"

  # Stop old teellm-service and daemon wrapper
  step "stopping previous teellm-service and daemon wrapper inside container"
  dk exec -i "$TARGET_CONTAINER" sh -lc "touch '$CON_WORKDIR/manual-teellm'; pkill -f '[s]tart-teellm\.sh' >/dev/null 2>&1 || true; pkill -x teellm-service >/dev/null 2>&1 || true; killall teellm-service >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
  local teellm_stopped=false
  for _ in {1..30}; do
    if ! dk exec -i "$TARGET_CONTAINER" sh -lc "pgrep -f '[s]tart-teellm\.sh' >/dev/null 2>&1 || pgrep -x teellm-service >/dev/null 2>&1"; then
      teellm_stopped=true
      break
    fi
    sleep 0.2
  done
  if [[ "$teellm_stopped" != true ]]; then
    warn "teellm-service or start-teellm.sh did not terminate gracefully; force-killing"
    dk exec -i "$TARGET_CONTAINER" sh -lc "pkill -9 -f '[s]tart-teellm\.sh' >/dev/null 2>&1 || true; pkill -9 -x teellm-service >/dev/null 2>&1 || true; killall -9 teellm-service >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
    sleep 0.5
  fi
  info "stopped previous teellm-service and daemon instances"

  # Start teellm supervisor inside container
  step "starting teellm supervisor inside container on port :${TEELLM_PORT}"
  dk exec -i "$TARGET_CONTAINER" sh -lc "rm -f '$CON_WORKDIR/manual-teellm'"
  dk exec -d "$TARGET_CONTAINER" sh -lc "cd '$CON_WORKDIR' && nohup bash ./start-teellm.sh >/dev/null 2>&1 &"

  # Probe TEE-LLM readiness
  step "probing teellm-service readiness via TEE-TLS 1.3"
  local teellm_ready=false
  local wait_start_ts
  wait_start_ts=$(date +%s)
  cursor_hide
  local spin_len=${#SPIN_FRAMES[@]}
  local i=0
  for ((attempt=1; attempt<=30; attempt++)); do
    if dk exec -i "$TARGET_CONTAINER" "$CON_WORKDIR/teellm-service" -probe "https://127.0.0.1:${TEELLM_PORT}" >/dev/null 2>&1; then
      teellm_ready=true
      break
    fi
    if [[ "$IS_TTY" == true ]]; then
      local now
      now=$(date +%s)
      local elapsed=$((now - wait_start_ts))
      local frame="${SPIN_FRAMES[$i]}"
      printf "\r   ${CYAN}%s${NC} probing teellm-service readiness ${DIM}(%ds / 30s)...${NC}" "$frame" "$elapsed"
      i=$(( (i + 1) % spin_len ))
    fi
    sleep 1
  done
  cursor_show
  printf "\r\033[K"
  if [[ "$teellm_ready" != true ]]; then
    err "teellm-service did not become ready on https://127.0.0.1:${TEELLM_PORT}"
    echo -e "   ${YELLOW}↳${NC} teellm-service log (${TEELLM_LOG_FILE}):"
    dk exec -i "$TARGET_CONTAINER" sh -lc "tail -n 60 '$TEELLM_LOG_FILE' 2>/dev/null || true"
    exit 1
  fi
  local total_elapsed=$(( $(date +%s) - wait_start_ts ))
  info "teellm-service ready and verified via TEE-TLS 1.3: https://127.0.0.1:${TEELLM_PORT} ${DIM}(took ${total_elapsed}s)${NC}"

  if [[ "$REMOTE_CONTAINER_MODE" == true ]]; then
    banner "Deploy Complete (Remote Docker)" "TEE-LLM service running and verified healthy in ${TARGET_CONTAINER}"
    print_container_summary "${REMOTE_USER}@${REMOTE_HOST} docker daemon"
  else
    banner "Deploy Complete (Docker)" "TEE-LLM service running and verified healthy"
    print_container_summary "local docker daemon"
  fi
}

# ── Remote Deployment Mode ───────────────────────�──────────────

sync_ollama_to_remote() {
  step "syncing ollama package to remote host (${REMOTE_USER}@${REMOTE_HOST})"
  remote_ssh "mkdir -p '$REMOTE_OLLAMA_DIR'"

  if [[ "$OLLAMA_PRUNE_SYNC" == true ]]; then
    info "pruning sync for model '$OLLAMA_MODEL' (${model_mb}MB) to remote host"

    # Reuse existing remote library if available to save bandwidth
    if remote_ssh "test -d '$REMOTE_DIR/ollama-qwen2.5-coder-0.5b/lib/ollama' && ! test -d '$REMOTE_OLLAMA_DIR/lib/ollama'"; then
      info "reusing existing lib on remote host from ollama-qwen2.5-coder-0.5b"
      remote_ssh "mkdir -p '$REMOTE_OLLAMA_DIR/lib' && cp -r -n '$REMOTE_DIR/ollama-qwen2.5-coder-0.5b/lib/ollama' '$REMOTE_OLLAMA_DIR/lib/'"
    fi

    local list_tmp
    list_tmp="$(mktemp /tmp/ollama_files.XXXXXX)"
    TEMP_FILELIST="$list_tmp"
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
    TEMP_FILELIST=""
  else
    if command -v rsync >/dev/null 2>&1 && remote_ssh "command -v rsync >/dev/null 2>&1"; then
      sshpass -p "$PASSWORD" rsync -a -r --exclude='*cuda*' --delete --partial --info=progress2 \
        -e "ssh -q -o LogLevel=ERROR -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$HOME/.ssh/known_hosts" \
        "$OLLAMA_LOCAL_DIR/" \
        "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_OLLAMA_DIR/"
    else
      warn "rsync not available; falling back to scp -r transfer"
      remote_ssh "rm -rf '$REMOTE_OLLAMA_DIR.new' && mkdir -p '$REMOTE_DIR'"
      sshpass -p "$PASSWORD" scp -r "${SSH_OPTS[@]}" "$OLLAMA_LOCAL_DIR" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_OLLAMA_DIR.new"
      remote_ssh "rm -rf '$REMOTE_OLLAMA_DIR' && mv '$REMOTE_OLLAMA_DIR.new' '$REMOTE_OLLAMA_DIR'"
    fi
  fi

  if ! remote_ssh "test -f '$REMOTE_OLLAMA_DIR/ollama' && test -f '$REMOTE_OLLAMA_DIR/start-ollama.sh' && test -d '$REMOTE_OLLAMA_DIR/models/models' && test -f '$REMOTE_OLLAMA_DIR/lib/ollama/libllama-server-impl.so'"; then
    err "remote ollama package verification failed: missing components in $REMOTE_OLLAMA_DIR"
    exit 1
  fi
  remote_ssh "chmod +x '$REMOTE_OLLAMA_DIR/ollama' '$REMOTE_OLLAMA_DIR/start-ollama.sh' '$REMOTE_OLLAMA_DIR/lib/ollama/llama-'* 2>/dev/null || true"
  info "ollama package verified on remote host ($REMOTE_OLLAMA_DIR)"
}

copy_ollama_to_remote_pod() {
  step "checking ollama package inside remote pod ($TARGET_POD)"
  remote_ssh "$(container_exec) sh -lc 'command -v tar >/dev/null 2>&1 || { echo kubectl exec requires tar inside container; exit 1; }'"
  remote_ssh "command -v tar >/dev/null 2>&1 || { echo remote tar is required; exit 1; }"

  # Ollama used to live under this name. A pod deployed before the rename still has it as a real
  # directory, so move it into place instead of streaming several GB again. The is-not-a-symlink
  # guard skips pods that carry an alias left behind by an older revision of this script.
  local legacy_container_path="$CONTAINER_LEGACY_OLLAMA_DIR"
  if [[ "$CONTAINER_OLLAMA_DIR" != "$legacy_container_path" ]]; then
    if remote_ssh "$(container_exec) sh -lc 'test -d \"$legacy_container_path/lib/ollama\" && ! test -L \"$legacy_container_path\" && ! test -d \"$CONTAINER_OLLAMA_DIR/lib/ollama\"'" >/dev/null 2>&1; then
      info "migrating existing ollama runtime from $legacy_container_path to $CONTAINER_OLLAMA_DIR"
      remote_ssh "$(container_exec) sh -lc 'mkdir -p \"$CON_WORKDIR\" && if [ ! -d \"$CONTAINER_OLLAMA_DIR\" ]; then mv \"$legacy_container_path\" \"$CONTAINER_OLLAMA_DIR\"; elif [ ! -d \"$CONTAINER_OLLAMA_DIR/lib\" ]; then cp -r -n \"$legacy_container_path/lib\" \"$CONTAINER_OLLAMA_DIR/\"; fi'"
    fi
  fi

  local check_script has_base_runtime=false has_lib=false has_model=false
  check_script="$(resolve_ollama_model_artifacts "$OLLAMA_LOCAL_DIR" "$OLLAMA_MODEL" "check_model_sh" "$CONTAINER_OLLAMA_DIR")"

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
    info "ollama runtime and model '$OLLAMA_MODEL' (${model_mb}MB) already present in remote pod"
  elif [[ "$FORCE_QWEN_COPY" == false && "$has_base_runtime" == true && "$has_model" == false ]]; then
    step "streaming model '$OLLAMA_MODEL' (${model_mb}MB) into remote pod"
    remote_ssh "$(container_exec) sh -lc 'mkdir -p \"$CONTAINER_OLLAMA_DIR\"'"
    local file_list
    file_list="$(resolve_ollama_model_artifacts "$OLLAMA_LOCAL_DIR" "$OLLAMA_MODEL" "model_only")"
    remote_ssh "set -o pipefail; tar -b 1024 -C '$REMOTE_OLLAMA_DIR' -cf - -T - | $(container_exec_i) tar -xf - -C '$CONTAINER_OLLAMA_DIR'" <<< "$file_list" || {
      err "failed to stream ollama model into remote pod"
      exit 1
    }
    info "incremental model stream transfer completed"
  else
    step "streaming pruned ollama runtime and model '$OLLAMA_MODEL' (${model_mb}MB) into remote pod"
    remote_ssh "$(container_exec) sh -lc 'mkdir -p \"$CONTAINER_OLLAMA_DIR\"'"
    local file_list
    if [[ "$FORCE_QWEN_COPY" == false && "$has_lib" == true ]]; then
      info "reusing existing lib in pod; streaming binaries and model"
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
      err "failed to stream ollama package into remote pod"
      exit 1
    }
    info "ollama package stream transfer completed"
  fi

  remote_ssh "$(container_exec) sh -lc 'chmod +x \"$CONTAINER_OLLAMA_DIR/ollama\" \"$CONTAINER_OLLAMA_DIR/start-ollama.sh\" \"$CONTAINER_OLLAMA_DIR/lib/ollama/llama-\"* 2>/dev/null || true'"

  # Restore the soname symlinks llama-server needs; the bundle ships versioned files only.
  local remote_soname_links
  remote_soname_links="$(remote_ssh "$(container_exec) sh -lc '$(ollama_soname_fix_script)' sh '$CONTAINER_OLLAMA_DIR/lib/ollama'" 2>/dev/null || echo 0)"
  if [[ "${remote_soname_links:-0}" != "0" ]]; then
    info "restored $remote_soname_links ollama soname symlink(s) in $CONTAINER_OLLAMA_DIR/lib/ollama"
  fi

  info "ollama runtime and model '$OLLAMA_MODEL' verified inside remote pod"
}

deploy_remote() {
  banner "Deploying TEE-LLM Service (Remote)" "Host: ${REMOTE_USER}@${REMOTE_HOST} | Pod: $TARGET_POD | Model: $OLLAMA_MODEL"

  step "verifying remote host and target pod connectivity"
  check_remote_connectivity
  check_remote_pod

  build_local_binary

  step "stopping old daemons inside remote pod"
  remote_ssh "$(container_exec) sh -lc 'killall ollama >/dev/null 2>&1 || true; pkill -x ollama >/dev/null 2>&1 || true; killall llama-server >/dev/null 2>&1 || true; pkill -x llama-server >/dev/null 2>&1 || true; killall teellm-service >/dev/null 2>&1 || true; pkill -x teellm-service >/dev/null 2>&1 || true'"

  sync_ollama_to_remote
  copy_ollama_to_remote_pod

  # Start Ollama daemon in remote pod
  step "starting ollama daemon inside remote pod"
  remote_ssh "$(container_exec) sh -lc 'cd \"$CONTAINER_OLLAMA_DIR\" && exec env OLLAMA_HOST=\"$OLLAMA_HOST\" OLLAMA_MODELS=\"$CONTAINER_OLLAMA_DIR/models/models\" OLLAMA_LIBRARY_PATH=\"$CONTAINER_OLLAMA_DIR/lib/ollama\" nohup ./start-ollama.sh > \"$OLLAMA_LOG_FILE\" 2>&1 &'"

  step "waiting for remote ollama service to become ready"
  local ollama_ready=false
  local wait_start_ts
  wait_start_ts=$(date +%s)
  cursor_hide
  local spin_len=${#SPIN_FRAMES[@]}
  local i=0
  for ((attempt=1; attempt<=OLLAMA_READY_TIMEOUT/OLLAMA_READY_INTERVAL; attempt++)); do
    if remote_ssh "$(container_exec) curl -fsS 'http://$OLLAMA_HOST/api/tags' >/dev/null 2>&1"; then
      ollama_ready=true
      break
    fi
    if [[ "$IS_TTY" == true ]]; then
      local now
      now=$(date +%s)
      local elapsed=$((now - wait_start_ts))
      local frame="${SPIN_FRAMES[$i]}"
      printf "\r   ${CYAN}%s${NC} waiting for remote ollama daemon ${DIM}(%ds / %ds)...${NC}" "$frame" "$elapsed" "$OLLAMA_READY_TIMEOUT"
      i=$(( (i + 1) % spin_len ))
    fi
    sleep "$OLLAMA_READY_INTERVAL"
  done
  cursor_show
  printf "\r\033[K"
  if [[ "$ollama_ready" != true ]]; then
    err "remote ollama daemon did not become ready within ${OLLAMA_READY_TIMEOUT}s"
    remote_ssh "$(container_exec) tail -n 50 '$OLLAMA_LOG_FILE' || true"
    exit 1
  fi
  info "remote ollama daemon ready and responding on http://$OLLAMA_HOST"

  # Deploy certificates and binary to remote host then into pod
  step "preparing and uploading configuration and binary"
  local cfg_template="${TEELLM_CONFIG_PATH:-$TEELLM_DIR/configs/teellm-production.json}"
  local tmp_cfg
  tmp_cfg="$(mktemp /tmp/teellm_cfg.XXXXXX)"
  TEMP_CONFIG_FILE="$tmp_cfg"
  prepare_config "$cfg_template" "$tmp_cfg" "$OLLAMA_MODEL" "$TEELLM_PORT" "$CON_WORKDIR/certs/hrk.cert" "$CON_WORKDIR/certs/hsk_cek.cert"

  remote_ssh "mkdir -p '$REMOTE_DIR/configs' '$REMOTE_DIR/certs'"
  sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$TEELLM_DIR/bin/teellm-service" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/teellm-service.new"
  sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$tmp_cfg" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/configs/teellm-production.json"
  if [[ -f "$TEELLM_DIR/configs/models.json" ]]; then
    sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$TEELLM_DIR/configs/models.json" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/configs/models.json"
  fi
  rm -f "$tmp_cfg"
  TEMP_CONFIG_FILE=""

  if [[ -n "$LOCAL_HRK_CERT" && -n "$LOCAL_HSK_CERT" ]]; then
    sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$LOCAL_HRK_CERT" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/certs/hrk.cert"
    sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$LOCAL_HSK_CERT" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/certs/hsk_cek.cert"
  fi

  remote_ssh "mv '$REMOTE_DIR/teellm-service.new' '$REMOTE_DIR/teellm-service' && chmod +x '$REMOTE_DIR/teellm-service'"

  # Copy into remote pod
  step "installing binary, certificates and configuration into remote pod"
  remote_ssh "$(container_exec) sh -lc 'mkdir -p \"$CON_WORKDIR/certs\" \"$CON_WORKDIR/configs\"'"
  remote_ssh "$(container_cp "$REMOTE_DIR/teellm-service" "$CON_WORKDIR/teellm-service")"
  remote_ssh "$(container_cp "$REMOTE_DIR/configs/teellm-production.json" "$CON_WORKDIR/configs/teellm-production.json")"
  if [[ -f "$TEELLM_DIR/configs/models.json" ]]; then
    remote_ssh "$(container_cp "$REMOTE_DIR/configs/models.json" "$CON_WORKDIR/configs/models.json")"
  fi
  remote_ssh "$(container_exec) sh -lc 'chmod +x \"$CON_WORKDIR/teellm-service\"'"
  if [[ -n "$LOCAL_HRK_CERT" && -n "$LOCAL_HSK_CERT" ]]; then
    remote_ssh "$(container_cp "$REMOTE_DIR/certs/hrk.cert" "$CON_WORKDIR/certs/hrk.cert")"
    remote_ssh "$(container_cp "$REMOTE_DIR/certs/hsk_cek.cert" "$CON_WORKDIR/certs/hsk_cek.cert")"
  fi

  # Start teellm-service inside remote pod
  step "starting teellm-service daemon inside remote pod"
  remote_ssh "$(container_exec) sh -lc 'cd \"$CON_WORKDIR\" && exec nohup \"$CON_WORKDIR/teellm-service\" -config \"$CON_WORKDIR/configs/teellm-production.json\" -model \"$OLLAMA_MODEL\" > \"$TEELLM_LOG_FILE\" 2>&1 &'"

  # Probe remote service
  step "probing remote teellm-service readiness via TEE-TLS 1.3"
  local teellm_ready=false
  local wait_start_ts
  wait_start_ts=$(date +%s)
  cursor_hide
  local spin_len=${#SPIN_FRAMES[@]}
  local i=0
  for ((attempt=1; attempt<=30; attempt++)); do
    if remote_ssh "$(container_exec) \"$CON_WORKDIR/teellm-service\" -probe \"https://127.0.0.1:${TEELLM_PORT}\"" >/dev/null 2>&1; then
      teellm_ready=true
      break
    fi
    if [[ "$IS_TTY" == true ]]; then
      local now
      now=$(date +%s)
      local elapsed=$((now - wait_start_ts))
      local frame="${SPIN_FRAMES[$i]}"
      printf "\r   ${CYAN}%s${NC} probing remote teellm-service readiness ${DIM}(%ds / 30s)...${NC}" "$frame" "$elapsed"
      i=$(( (i + 1) % spin_len ))
    fi
    sleep 1
  done
  cursor_show
  printf "\r\033[K"
  if [[ "$teellm_ready" != true ]]; then
    err "remote teellm-service did not become ready on https://127.0.0.1:${TEELLM_PORT}"
    remote_ssh "$(container_exec) \"$CON_WORKDIR/teellm-service\" -probe \"https://127.0.0.1:${TEELLM_PORT}\" || true"
    remote_ssh "$(container_exec) tail -n 60 '$TEELLM_LOG_FILE' || true"
    exit 1
  fi
  local total_elapsed=$(( $(date +%s) - wait_start_ts ))
  info "remote teellm-service ready and verified via TEE-TLS 1.3: https://127.0.0.1:${TEELLM_PORT} ${DIM}(took ${total_elapsed}s)${NC}"

  banner "Deploy Complete (Remote)" "TEE-LLM remote service running and verified healthy"
  echo -e "  ${BOLD}${CYAN}● TEE-LLM Inference Service${NC}  ${DIM}(RFC 8998 ShangMi TEE-TLS 1.3)${NC}"
  echo -e "    ${MUTED}↳ Target Pod :${NC} ${TARGET_POD} (${TARGET_NAMESPACE})"
  echo -e "    ${MUTED}↳ Remote Host:${NC} ${REMOTE_USER}@${REMOTE_HOST}"
  echo -e "    ${MUTED}↳ Port       :${NC} ${TEELLM_PORT}"
  echo -e "    ${MUTED}↳ Config     :${NC} ${CON_WORKDIR}/configs/teellm-production.json"
  echo -e "    ${MUTED}↳ Log file   :${NC} ${TEELLM_LOG_FILE}"
  echo ""
  echo -e "  ${BOLD}${CYAN}● Ollama / Qwen Engine${NC}  ${DIM}(In-Pod Engine)${NC}"
  echo -e "    ${MUTED}↳ Endpoint   :${NC} ${BOLD}http://${OLLAMA_HOST}${NC}"
  echo -e "    ${MUTED}↳ Model      :${NC} ${PURPLE}${OLLAMA_MODEL}${NC}"
  echo -e "    ${MUTED}↳ Path       :${NC} ${CONTAINER_OLLAMA_DIR}"
  echo -e "    ${MUTED}↳ Log file   :${NC} ${OLLAMA_LOG_FILE}"
  echo ""
}

# ── Main Entrypoint ───────────────────────────────────────────

if [[ "$DEPLOY_REMOTE" == true ]]; then
  deploy_remote
else
  deploy_container
fi
