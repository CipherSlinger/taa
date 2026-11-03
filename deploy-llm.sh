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
TEMP_POD_MANIFEST=""
TEMP_BUILDER_CONTAINER=""
TRAP_SUPPRESS_DEPLOYMENT_BANNER=false
STEP=0

cursor_hide() { [[ "$IS_TTY" == true ]] && printf "\033[?25l" 2>/dev/null || true; }
cursor_show() { [[ "$IS_TTY" == true ]] && printf "\033[?25h" 2>/dev/null || true; }

handle_err() {
  LAST_ERR_LINE="${1:-unknown}"
  LAST_ERR_CMD="${2:-unknown}"
}
trap 'handle_err $LINENO "$BASH_COMMAND"' ERR

# Removes the image-builder container unless the operator asked to keep it. Registered here rather
# than as a local exit trap because the deployment already owns the EXIT trap, and a second one
# would replace the error banner.
cleanup_builder_container() {
  [[ -n "${TEMP_BUILDER_CONTAINER:-}" ]] || return 0
  if [[ "${TEELLM_IMAGE_KEEP_BUILDER:-false}" == true ]]; then
    return 0
  fi
  docker rm -f "$TEMP_BUILDER_CONTAINER" >/dev/null 2>&1 || true
  TEMP_BUILDER_CONTAINER=""
}

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
  if [[ -n "${TEMP_POD_MANIFEST:-}" && -f "$TEMP_POD_MANIFEST" ]]; then
    rm -f "$TEMP_POD_MANIFEST" 2>/dev/null || true
  fi
  cleanup_builder_container || true

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

# Paths inside the TEE-LLM Pod. The image carries no TAA payload, so the service tree lives under
# /opt/teellm: /root/taa belongs to the TAA images and must not appear in an inference image.
CON_WORKDIR="${CON_WORKDIR:-/opt/teellm}"
CONTAINER_OLLAMA_DIR="${CONTAINER_OLLAMA_DIR:-/opt/teellm/ollama}"
# Older image revisions ship the same ollama bundle under this name. It carries the identical
# runtime (only the model set differs), so a container that still has it can be migrated into
# $CONTAINER_OLLAMA_DIR instead of streaming the runtime in again.
CONTAINER_LEGACY_OLLAMA_DIR="${CONTAINER_LEGACY_OLLAMA_DIR:-$CON_WORKDIR/ollama-qwen2.5-coder-0.5b}"

# TEE-LLM and Ollama ports & endpoints
TEELLM_PORT="${TEELLM_PORT:-8443}"
# Platform the instance registers with, heartbeats to and pushes logs to. Empty
# disables all outbound reporting.
TEELLM_PLATFORM_ADDR="${TEELLM_PLATFORM_ADDR:-http://172.16.10.181:18081}"
TEELLM_LOG_FILE="${TEELLM_LOG_FILE:-$CON_WORKDIR/teellm-service.log}"
OLLAMA_HOST="${OLLAMA_HOST:-127.0.0.1:11434}"
# The supervisor starts ollama and redirects its output here; the readiness failure below dumps it.
OLLAMA_LOG_FILE="${OLLAMA_LOG_FILE:-$CON_WORKDIR/ollama.log}"
OLLAMA_READY_TIMEOUT="${OLLAMA_READY_TIMEOUT:-120}"
OLLAMA_READY_INTERVAL="${OLLAMA_READY_INTERVAL:-2}"
FORCE_QWEN_COPY="${FORCE_QWEN_COPY:-false}"
OLLAMA_PRUNE_SYNC="${OLLAMA_PRUNE_SYNC:-true}"

# Kubernetes & Remote settings
TARGET_NAMESPACE="${TARGET_NAMESPACE:-osr}"
# Whether the caller named a Pod. Captured before the default below, so that --create-pod can tell
# "the operator asked for this Pod" from "the script filled in a default" and refuse the pairing
# instead of quietly deploying a TEE-LLM Pod they did not ask for.
TARGET_POD_WAS_SET="${TARGET_POD+set}"
TARGET_POD="${TARGET_POD:-taa-env-slim-v2-20260916-b2038037072e1052-54f554445c-n2pnv}"
REMOTE_HOST="${REMOTE_HOST:-172.16.10.178}"
REMOTE_USER="${REMOTE_USER:-root}"
PASSWORD="${TARGET_PASSWORD:-${PASSWORD:-Osrd@2026}}"
# Host-side staging directory. Kept out of /root/taa, which is the TAA deployment's tree.
REMOTE_DIR="${REMOTE_DIR:-/root/teellm}"
OLLAMA_DIR_NAME="$(basename "$CONTAINER_OLLAMA_DIR")"
REMOTE_OLLAMA_DIR="${REMOTE_OLLAMA_DIR:-$REMOTE_DIR/$OLLAMA_DIR_NAME}"
K_NS="${TARGET_NAMESPACE:+-n $TARGET_NAMESPACE}"

# ── Dedicated TEE-LLM Pod ─────────────────────────────────────
# The TEE-LLM service needs /dev/csv-guest to produce a real CSV attestation; a plain docker
# container has no such device, so teellm-service falls back to a mock evidence provider that
# signs its own report. TAA verifies only the report's PEK signature and skips the certificate
# chain, so it cannot tell that mock report from hardware at the handshake -- which is why the
# deployment itself refuses to run without the device. A kata-qemu-csv2 Pod has it, because its
# guest init creates it -- which is the whole reason this Pod exists, and why --create-pod
# deploys into it rather than into the TAA Pod that TARGET_POD defaults to (that Pod has the
# device too, but it is not where teellm-service should run, and aiming the deployment at it
# would make every later gate pass while the service never reaches the Pod the endpoint points
# at).
TEELLM_POD_NAME="${TEELLM_POD_NAME:-taa-teellm}"
# The image this script builds from the working tree carries the service, the supervisor and the
# ollama runtime, so a fresh guest serves without any host-side copy.
#
# Its tag is the date it was built on, so the same-day default is only a guess: build on the 27th
# and deploy on the 28th and today's tag names an image nobody pushed. Left alone, that guess is
# the one the guest's CDH tries to pull, and the Pod stops in ImagePullBackOff after the guest has
# already booted. resolve_teellm_pod_image() therefore replaces it with the newest teellm tag the
# registry actually has, and refuses rather than falling back to a tag it cannot see.
TEELLM_IMAGE_REGISTRY="${TEELLM_IMAGE_REGISTRY:-172.16.10.178:31313}"
TEELLM_IMAGE_REPO="${TEELLM_IMAGE_REPO:-teellm}"
# Source image for the Pod image and the archive it can be loaded from when it is not local. The
# TAA payload under /root/taa is stripped before the teellm payload is added (build path below).
TEELLM_IMAGE_BASE="${TEELLM_IMAGE_BASE:-taa-env:slim-v2}"
TEELLM_IMAGE_BASE_ARCHIVE="${TEELLM_IMAGE_BASE_ARCHIVE:-$PROJECT_DIR/deploy/base/taa-env-slim-v2.tar.gz}"
# Keep the builder container after the image is committed, for inspecting a payload that failed to
# build. The container is removed on success by default.
TEELLM_IMAGE_KEEP_BUILDER="${TEELLM_IMAGE_KEEP_BUILDER:-false}"
# Captured before the default below, so resolution can tell "the operator named an image" from
# "the script guessed one from today's date". Only a guess is replaced by a tag the registry
# actually has; an explicit name is the operator's decision, and a registry whose tag listing is
# slow, filtered or 401-guarded is no reason to override it.
TEELLM_POD_IMAGE_WAS_SET="${TEELLM_POD_IMAGE+set}"
TEELLM_POD_IMAGE="${TEELLM_POD_IMAGE:-$TEELLM_IMAGE_REGISTRY/$TEELLM_IMAGE_REPO:$(date +%Y%m%d)}"
TEELLM_POD_NODE="${TEELLM_POD_NODE:-hygon-master}"
TEELLM_POD_RUNTIME_CLASS="${TEELLM_POD_RUNTIME_CLASS:-kata-qemu-csv2}"
# Kata sizes the guest as default_memory + limits.memory and default_vcpus + limits.cpu, and
# encrypted memory is resident from boot, so these two numbers are a permanent host cost.
TEELLM_POD_CPU="${TEELLM_POD_CPU:-8}"
# 16Gi, not the 8Gi the TAA Pod gets away with: this container also has to hold a whole model.
# At 8Gi the first deployment of this feature came up, reported the hardware evidence provider,
# and then had llama-server SIGKILLed while loading qwen2.5-coder:7b -- the container's cgroup
# hit its ceiling (memory.events oom_kill=128, the model's page cache and the 4.5GB of tensor
# buffers together exceeding 8Gi) and teellm-service answered 503 until the deploy gave up. The
# TAA Pod never showed this because TAA's LLM calls never got past the handshake to request an
# inference, so its own ollama was never asked to load anything. Sizing has to cover the model,
# not just the service.
TEELLM_POD_MEMORY="${TEELLM_POD_MEMORY:-16Gi}"
# 1800s rather than the 180s a plain Pod needs: a fresh CSV2 Pod boots its guest first and pulls
# this image inside it, through the in-guest CDH. The image is several GB, and the guest pull has
# been measured at 5 to 20 minutes on this host, so a shorter window turns a healthy first creation
# into a timeout.
TEELLM_POD_READY_TIMEOUT="${TEELLM_POD_READY_TIMEOUT:-1800}"
# Whether a Pod that has to be created is first built from this working tree. On, the deployment
# recompiles teellm-service, bakes it plus the ollama runtime and the model into an image, pushes
# that image and creates the Pod from it, so a Pod never runs a binary older than the tree being
# deployed. Off, it falls back to the previous behaviour of picking the newest date tag the
# registry already lists. An explicitly named TEELLM_POD_IMAGE skips the build either way: an
# operator who names an image is making a decision, not guessing one.
TEELLM_BUILD_POD_IMAGE="${TEELLM_BUILD_POD_IMAGE:-true}"
TEELLM_POD_PULL_POLICY="${TEELLM_POD_PULL_POLICY:-IfNotPresent}"
# Uncompressed size of the Pod image, in GiB. Empty probes the image locally, then on the remote
# host, and warns before falling back to a measured constant. Only the memory guard reads it.
TEELLM_POD_IMAGE_SIZE_GIB="${TEELLM_POD_IMAGE_SIZE_GIB:-}"
# Escape hatch for the memory guard, matching --force in the reference create script. Two gates
# read it: the guest-overlay budget and the host's available memory.
TEELLM_POD_FORCE_MEMORY="${TEELLM_POD_FORCE_MEMORY:-false}"
# Whether pod-down counts the host's kata sandboxes after deleting. A leaked qemu keeps its whole
# -m resident, and encrypted memory is not reclaimable, so the count is the only thing that shows it.
TEELLM_POD_ORPHAN_CHECK="${TEELLM_POD_ORPHAN_CHECK:-true}"
# Interactive confirmation before a creation, which is a confidential VM of host-resident memory.
# Non-interactive runs proceed without it: --create-pod is already the deliberate act.
TEELLM_POD_ASSUME_YES="${TEELLM_POD_ASSUME_YES:-false}"
# Reads the kata default_memory that sizes the guest on top of limits.memory.
KATA_TOML="${KATA_TOML:-/opt/kata/share/defaults/kata-containers/configuration-qemu-csv2.toml}"
TEELLM_POD_TEMPLATE="${TEELLM_POD_TEMPLATE:-$PROJECT_DIR/deploy/manifest/k8s/teellm-pod.yaml.tmpl}"
# The script that becomes the Pod's PID 1 and owns teellm-service and ollama. It is installed into
# the Pod by the deployment, so it is versioned here rather than baked into the image.
TEELLM_SUPERVISOR_SCRIPT="${TEELLM_SUPERVISOR_SCRIPT:-$PROJECT_DIR/deploy/teellm-supervisor.sh}"
# Seconds to wait for the container command to start the supervisor before starting it from here.
# A Pod created before the supervisor existed has `sleep infinity` as PID 1, so nothing inside
# will ever run the script and the fallback is the only way to migrate it without recreating it.
TEELLM_SUPERVISOR_START_WAIT="${TEELLM_SUPERVISOR_START_WAIT:-5}"
# Optional escape hatch for hosts with no CoCo Pod to copy the annotation from; leave empty to
# derive it (see derive_cc_init_data).
TEELLM_POD_CC_INIT_DATA="${TEELLM_POD_CC_INIT_DATA:-}"
TEELLM_POD_IP=""
CREATE_POD=false
TEMP_POD_MANIFEST=""
# Set once the local teellm-service binary has been rebuilt in this run. Creating a Pod builds the
# binary to bake into the image, and the deployment installs the same file into the Pod afterwards;
# without this flag that would be a second `go build` of identical sources.
LOCAL_BINARY_BUILT=false

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
  ensure_remote_ssh
  if ! sshpass -p "$PASSWORD" ssh "${SSH_OPTS[@]}" -o ConnectTimeout=5 "${REMOTE_USER}@${REMOTE_HOST}" "true" 2>/dev/null; then
    err "cannot connect to remote host ${REMOTE_USER}@${REMOTE_HOST} via SSH (timeout or authentication failed)"
    detail "Please verify network connectivity, REMOTE_HOST ($REMOTE_HOST), or password credentials."
    exit 1
  fi
  info "remote host SSH connection verified: ${REMOTE_USER}@${REMOTE_HOST}"
}

check_remote_pod() {
  if ! remote_ssh "kubectl $K_NS get pod '$TARGET_POD' >/dev/null 2>&1"; then
    err "target pod '$TARGET_POD' not found in namespace '${TARGET_NAMESPACE:-default}' on remote host"
    detail "Please check TARGET_POD or run 'kubectl get pods -n ${TARGET_NAMESPACE:-default}' on remote host."
    exit 1
  fi
  info "remote target pod verified: ${TARGET_POD} (namespace: ${TARGET_NAMESPACE:-default})"
}

# Replaces the date-guessed TEE-LLM image with the newest one the registry actually lists.
#
# The image tag is the build date, so "today" is a guess that is only
# right on the day of the build. Deployed a day later it names a tag nobody pushed, and the
# failure is expensive and late: the Pod is applied, its guest boots, the in-guest CDH pulls, and
# the Pod ends up in ImagePullBackOff after the confidential VM is already resident. Asking the
# registry which teellm tags exist turns that guess into a fact.
#
# Only a guessed image is resolved. An explicit TEELLM_POD_IMAGE is used as given, and a registry
# whose listing cannot be read falls back to the guess with a warning rather than failing: the
# listing is a convenience, while a registry that answers 401 or is unreachable from the deploy
# host says nothing about whether the guest's CDH can pull the tag.
resolve_teellm_pod_image() {
  if [[ -n "$TEELLM_POD_IMAGE_WAS_SET" ]]; then
    return 0
  fi

  local listing tags newest
  listing="$(remote_ssh "curl -sk --max-time 10 'https://$TEELLM_IMAGE_REGISTRY/v2/$TEELLM_IMAGE_REPO/tags/list'" 2>/dev/null || true)"
  # One line per tag, date tags only: the repository root also answers with other names, and a
  # tag this script cannot compare by date is not a candidate.
  tags="$(grep -o '"[0-9]\{8\}"' <<<"$listing" | tr -d '"' | sort -r || true)"
  if [[ -z "$tags" ]]; then
    warn "could not list tags of $TEELLM_IMAGE_REGISTRY/$TEELLM_IMAGE_REPO; keeping $(date +%Y%m%d)"
    detail "Set TEELLM_POD_IMAGE explicitly if today's tag is not the one in the registry."
    return 0
  fi

  newest="${tags%%$'\n'*}"
  if [[ "$newest" == "$(date +%Y%m%d)" ]]; then
    info "TEE-LLM image: $TEELLM_POD_IMAGE (built today)"
  else
    local previous="$TEELLM_POD_IMAGE"
    TEELLM_POD_IMAGE="$TEELLM_IMAGE_REGISTRY/$TEELLM_IMAGE_REPO:$newest"
    info "TEE-LLM image: $TEELLM_POD_IMAGE (newest in the registry)"
    detail "today's date tag is not there; $previous would fail the guest's image pull"
  fi
}

# ── Dedicated TEE-LLM Pod lifecycle ───────────────────────────

# Converts a Kubernetes memory quantity to MiB. Returns 1 for a form this script does not parse, so
# the caller can tell "zero" from "unreadable".
quantity_to_mib() {
  local v="$1"
  case "$v" in
    *Ki) echo $(( ${v%Ki} / 1024 )) ;;
    *Mi) echo $(( ${v%Mi} )) ;;
    *Gi) echo $(( ${v%Gi} * 1024 )) ;;
    *Ti) echo $(( ${v%Ti} * 1024 * 1024 )) ;;
    *K)  echo $(( ${v%K} / 1024 )) ;;
    *M)  echo $(( ${v%M} * 1000000 / 1048576 )) ;;
    *G)  echo $(( ${v%G} * 1000000000 / 1048576 )) ;;
    ''|*[!0-9]*) return 1 ;;
    *)   echo $(( v / 1048576 )) ;;
  esac
}

# The memory the kata runtime adds to limits.memory to size the guest. Read from the runtime's own
# configuration; 2048 is the shipped default and is what this host's configuration-qemu-csv2.toml
# carries, so an unreadable file does not change the arithmetic.
kata_default_memory_mib() {
  local v
  v="$(remote_ssh "sed -n 's/^default_memory *= *//p' '$KATA_TOML' 2>/dev/null | head -1" || true)"
  v="${v//$'\r'/}"
  v="${v//$'\n'/}"
  if [[ ! "$v" =~ ^[0-9]+$ ]]; then
    v=2048
  fi
  printf '%s' "$v"
}

# Builds the image the new Pod will run from this working tree and pushes it to the registry the
# guest pulls from. Without this the creation path only names an existing tag, so a Pod runs
# whatever was pushed last -- silently older than the tree being deployed, and there is nothing in
# the Pod to show it.
#
# Why the payload is baked in rather than copied at deploy time: the Pod runs on a Kata CSV2 guest
# whose container rootfs upperdir is a tmpfs inside the guest. Anything copied in afterwards lives
# in guest RAM and dies with the sandbox, so a host reboot would leave a confidential VM that
# listens on nothing. Baking the service, the supervisor and the model into the image is what makes
# a freshly booted guest serve without a host-side step.
#
# The tag is the build date, so a rebuild replaces the same name. The pull policy is therefore set
# to Always on this path: on a fresh guest there is no cache to consult, but saying Always removes
# the question, where IfNotPresent leaves the guest free to take a copy of an image that was
# replaced underneath its name.
#
# The registry is asked for the tag's current config digest before anything is exported. That
# digest is the image ID Docker reports locally, so an identical build -- the common case when a
# deployment is retried -- skips the multi-GB archive, the upload and the push entirely.
build_teellm_pod_image() {
  local date_tag local_image registry_image archive base_image clean_base
  date_tag="$(date +%Y%m%d)"
  local_image="$TEELLM_IMAGE_REPO:$date_tag"
  registry_image="$TEELLM_IMAGE_REGISTRY/$TEELLM_IMAGE_REPO:$date_tag"
  archive="$PROJECT_DIR/deploy/out/$TEELLM_IMAGE_REPO-$date_tag.tar.gz"
  base_image="$TEELLM_IMAGE_BASE"
  clean_base="teellm-base:$date_tag"

  step "building the TEE-LLM Pod image from this working tree ($local_image)"
  detail "the ollama runtime and the model are streamed into the image and pushed; this takes tens of minutes"

  # First, and unconditionally: the image has to carry this tree's binary, and an existing file says
  # nothing about whether it matches these sources. The flag below keeps the deployment's own
  # install step from compiling the identical sources a second time.
  build_local_binary

  require_command docker
  if ! docker info >/dev/null 2>&1; then
    err "the docker daemon is not reachable, so the TEE-LLM Pod image cannot be built"
    detail "Start docker, or set TEELLM_POD_IMAGE to a prebuilt image."
    exit 1
  fi

  local model_repo model_tag manifest_rel
  [[ "$OLLAMA_MODEL" == *:* ]] || {
    err "OLLAMA_MODEL must be <family>:<tag>, got '$OLLAMA_MODEL'"
    exit 1
  }
  model_repo="${OLLAMA_MODEL%%:*}"
  model_tag="${OLLAMA_MODEL#*:}"
  manifest_rel="models/models/manifests/registry.ollama.ai/library/$model_repo/$model_tag"
  require_file "teellm-service binary" "$TEELLM_DIR/bin/teellm-service"
  require_file "TEE-LLM supervisor" "$TEELLM_SUPERVISOR_SCRIPT"
  require_file "TEE-LLM service config" "$TEELLM_DIR/configs/teellm-production.json"
  require_file "TEE-LLM model index" "$TEELLM_DIR/configs/models.json"
  require_file "ollama binary" "$OLLAMA_LOCAL_DIR/ollama"
  require_file "ollama launcher" "$OLLAMA_LOCAL_DIR/start-ollama.sh"
  require_file "ollama manifest for $OLLAMA_MODEL" "$OLLAMA_LOCAL_DIR/$manifest_rel"
  require_dir "ollama library" "$OLLAMA_LOCAL_DIR/lib/ollama"

  if ! docker image inspect "$base_image" >/dev/null 2>&1; then
    require_file "TEE-LLM base image archive" "$TEELLM_IMAGE_BASE_ARCHIVE"
    step "loading the base image from $(basename "$TEELLM_IMAGE_BASE_ARCHIVE")"
    docker load -i "$TEELLM_IMAGE_BASE_ARCHIVE" >/dev/null
    docker image inspect "$base_image" >/dev/null 2>&1 || {
      err "base image '$base_image' is not in $TEELLM_IMAGE_BASE_ARCHIVE"
      exit 1
    }
  fi
  info "source image ready: $base_image"

  # The TAA images carry /root/taa (the taa binary and its autostart wrapper); an inference image
  # must contain neither. An empty build context keeps docker from packing the multi-GB archives
  # that sit in deploy/ into the build.
  if ! docker image inspect "$clean_base" >/dev/null 2>&1; then
    step "building the TAA-free base image: $clean_base"
    local clean_ctx
    clean_ctx="$(mktemp -d /tmp/teellm-clean-base.XXXXXX)"
    docker build -q -t "$clean_base" -f - "$clean_ctx" >/dev/null <<EOF
FROM $base_image
USER root
RUN rm -rf /root/taa
EOF
    rm -rf "$clean_ctx"
  fi
  base_image="$clean_base"
  if ! docker run --rm --entrypoint sh "$base_image" -c 'test ! -e /root/taa' >/dev/null 2>&1; then
    err "base image '$base_image' still contains /root/taa"
    detail "Remove the cached image (docker rmi $base_image) and re-run, or point TEELLM_IMAGE_BASE at another source image."
    exit 1
  fi
  info "base image ready (no /root/taa): $base_image"

  # Only what the deployed model needs: the accelerator runtimes are irrelevant on CPU and would
  # add ~4.3GB, and every model but the selected one is dead weight in the guest's tmpfs.
  step "resolving the ollama payload for '$OLLAMA_MODEL'"
  local model_blobs
  model_blobs="$(python3 - "$OLLAMA_LOCAL_DIR/$manifest_rel" <<'PY'
import json, sys
manifest = json.load(open(sys.argv[1]))
for item in [manifest["config"]] + manifest["layers"]:
    digest = item["digest"].split(":", 1)[1]
    print("models/models/blobs/sha256-" + digest)
PY
)"
  [[ -n "$model_blobs" ]] || {
    err "could not resolve the blobs of $OLLAMA_MODEL from $OLLAMA_LOCAL_DIR/$manifest_rel"
    exit 1
  }

  local file_list payload_bytes payload_mb
  file_list="$(mktemp /tmp/teellm-image-files.XXXXXX)"
  {
    echo "ollama"
    echo "start-ollama.sh"
    # Files and the bundle's own symlinks, one directory level only: the accelerator runtimes
    # (cuda_v12, cuda_v13, mlx_cuda_v13, vulkan) and the headers are directories and are skipped
    # on purpose.
    ( cd "$OLLAMA_LOCAL_DIR" && find lib/ollama -maxdepth 1 \( -type f -o -type l \) ! -name '*cuda*' )
    for optional in models/cache models/id_ed25519 models/id_ed25519.pub \
                    models/models/cache models/models/id_ed25519 models/models/id_ed25519.pub; do
      [[ -e "$OLLAMA_LOCAL_DIR/$optional" ]] && echo "$optional"
    done
    echo "$manifest_rel"
    printf '%s\n' "$model_blobs"
  } > "$file_list"
  payload_bytes="$(cd "$OLLAMA_LOCAL_DIR" && xargs -d '\n' -a "$file_list" stat -c %s 2>/dev/null | awk '{s+=$1} END {print s+0}')"
  payload_mb="$(awk -v b="$payload_bytes" 'BEGIN {printf "%.0f", b/1048576}')"
  info "payload: $(wc -l < "$file_list") files, ${payload_mb}MB"

  # The builder container is removed on every exit path by cleanup_display unless the operator
  # asked to keep it; TEELLM_IMAGE_KEEP_BUILDER is what makes a failed build inspectable.
  local builder_container="taa-teellm-builder-$$"
  step "starting the builder container"
  docker rm -f "$builder_container" >/dev/null 2>&1 || true
  docker run -d --name "$builder_container" --user root --entrypoint bash "$base_image" -c 'sleep infinity' >/dev/null
  TEMP_BUILDER_CONTAINER="$builder_container"
  # /opt/teellm, not $CON_WORKDIR: this is the path baked into the image, and the Pod manifest and
  # the supervisor both name it literally.
  docker exec -i "$builder_container" sh -c 'mkdir -p /opt/teellm/configs /opt/teellm/ollama'

  step "copying teellm-service, supervisor and configs"
  docker cp "$TEELLM_DIR/bin/teellm-service" "$builder_container:/opt/teellm/teellm-service"
  docker cp "$TEELLM_SUPERVISOR_SCRIPT" "$builder_container:/opt/teellm/teellm-supervisor.sh"
  docker cp "$TEELLM_DIR/configs/teellm-production.json" "$builder_container:/opt/teellm/configs/teellm-production.json"
  docker cp "$TEELLM_DIR/configs/models.json" "$builder_container:/opt/teellm/configs/models.json"

  step "streaming the ollama runtime and model into the image (${payload_mb}MB)"
  tar -C "$OLLAMA_LOCAL_DIR" -cf - -T "$file_list" |
    docker exec -i "$builder_container" tar -xf - -C /opt/teellm/ollama
  rm -f "$file_list"

  step "finishing the payload inside the image"
  # llama-server links against the soname forms of its libraries and carries RUNPATH=$ORIGIN, while
  # the bundle ships versioned files only; without these links it exits 127 and ollama answers 500.
  docker exec -i -e MODEL="$OLLAMA_MODEL" "$builder_container" sh -c '
set -e
d=/opt/teellm/ollama/lib/ollama
chmod +x /opt/teellm/teellm-service /opt/teellm/teellm-supervisor.sh \
         /opt/teellm/ollama/ollama /opt/teellm/ollama/start-ollama.sh "$d"/llama-* 2>/dev/null || true
n=0
for f in "$d"/lib*.so.*; do
  [ -e "$f" ] || continue
  [ -L "$f" ] && continue
  b=${f##*/}; stem=${b%%.so.*}; rest=${b#*.so.}
  [ "$rest" = "$b" ] && continue
  s="$stem.so.${rest%%.*}"
  if [ ! -e "$d/$s" ]; then ln -sf "$b" "$d/$s"; n=$((n+1)); fi
done
echo "soname links created: $n"
printf %s "$MODEL" > /opt/teellm/.teellm-model
printf "model file: "; cat /opt/teellm/.teellm-model; echo
'

  step "verifying the payload inside the image"
  docker exec -i -e MODEL="$OLLAMA_MODEL" "$builder_container" sh -c '
set -e
for p in /opt/teellm/teellm-service /opt/teellm/teellm-supervisor.sh \
         /opt/teellm/configs/teellm-production.json /opt/teellm/configs/models.json \
         /opt/teellm/ollama/ollama /opt/teellm/ollama/start-ollama.sh \
         /opt/teellm/ollama/lib/ollama/libllama-server-impl.so \
         /opt/teellm/ollama/lib/ollama/libllama-common.so.0 \
         /opt/teellm/ollama/lib/ollama/libggml.so.0; do
  test -s "$p" || { echo "missing: $p" >&2; exit 1; }
done
[ "$(cat /opt/teellm/.teellm-model)" = "$MODEL" ] || { echo "wrong .teellm-model" >&2; exit 1; }
/opt/teellm/ollama/ollama --version
du -sh /opt/teellm/ollama /opt/teellm/teellm-service
'

  step "committing the image: $local_image"
  docker commit \
    -c 'ENTRYPOINT ["bash", "/opt/teellm/teellm-supervisor.sh"]' \
    -c 'CMD []' \
    -c 'USER root' \
    -c 'WORKDIR /opt/teellm' \
    -c 'EXPOSE 8443' \
    -m "TEE-LLM image: base $base_image + teellm-service + ollama $OLLAMA_MODEL at $(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "$builder_container" "$local_image" >/dev/null
  cleanup_builder_container
  local image_bytes
  image_bytes="$(docker image inspect --format '{{.Size}}' "$local_image")"
  info "image committed: $local_image ($(awk -v b="$image_bytes" 'BEGIN {printf "%.0f", b/1048576}')MB uncompressed)"

  # The memory guard downstream sizes the guest against the image, so give it the real figure
  # rather than making it guess: the registry name is not what is local, and the operator may not
  # have set TEELLM_POD_IMAGE_SIZE_GIB.
  if [[ -z "$TEELLM_POD_IMAGE_SIZE_GIB" ]]; then
    TEELLM_POD_IMAGE_SIZE_GIB="$(awk -v b="$image_bytes" 'BEGIN {printf "%.2f", b/1073741824}')"
  fi

  local local_id remote_config
  local_id="$(docker image inspect --format '{{.Id}}' "$local_image" 2>/dev/null || true)"
  if [[ -z "$local_id" ]]; then
    err "the built image '$local_image' is missing"
    exit 1
  fi

  # The config digest in a schema2 manifest is the image ID Docker reports locally, so the two
  # together answer "does the registry already hold exactly this build?" -- the question that
  # decides whether anything has to leave this host at all.
  remote_config="$(remote_ssh "curl -sk --max-time 10 -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' 'https://$TEELLM_IMAGE_REGISTRY/v2/$TEELLM_IMAGE_REPO/manifests/$date_tag'" 2>/dev/null |
    grep -o 'sha256:[0-9a-f]\{64\}' | head -n 1 || true)"
  if [[ -n "$remote_config" && "$remote_config" == "$local_id" ]]; then
    info "the registry already holds this build; nothing uploaded: $registry_image"
    TEELLM_POD_IMAGE="$registry_image"
    TEELLM_POD_PULL_POLICY="Always"
    return 0
  fi

  step "exporting the image archive: $archive"
  mkdir -p "$(dirname "$archive")"
  local tmp_archive="${archive}.tmp.$$"
  if command -v pigz >/dev/null 2>&1; then
    docker save "$local_image" | pigz -c > "$tmp_archive"
  else
    docker save "$local_image" | gzip -c > "$tmp_archive"
  fi
  mv -f "$tmp_archive" "$archive"
  info "archive saved: $archive ($(du -h "$archive" | cut -f1))"

  step "uploading the image to ${REMOTE_USER}@${REMOTE_HOST} and updating $registry_image"
  local remote_archive="/tmp/$(basename "$archive")"
  sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$archive" "${REMOTE_USER}@${REMOTE_HOST}:$remote_archive"
  if ! remote_ssh bash -s -- "$remote_archive" "$local_image" "$registry_image" "$TEELLM_IMAGE_REGISTRY" "$TEELLM_IMAGE_REPO" "$date_tag" <<'REMOTE_PUSH'
set -euo pipefail
archive="$1"; local_image="$2"; registry_image="$3"
registry="$4"; repo="$5"; tag="$6"
trap 'rm -f "$archive"' EXIT

docker load -i "$archive" >/dev/null
docker tag "$local_image" "$registry_image"

manifest_url="https://$registry/v2/$repo/manifests/$tag"
accept="Accept: application/vnd.docker.distribution.manifest.v2+json"
# Best effort: a registry with deletion disabled answers 405, and the push below still replaces
# the tag atomically.
old_digest="$(curl -skI --max-time 10 -H "$accept" "$manifest_url" 2>/dev/null |
  awk 'tolower($1) == "docker-content-digest:" {print $2}' | tr -d '\r' | tail -n 1 || true)"
if [ -n "$old_digest" ]; then
  curl -sk -X DELETE --max-time 15 "$registry/v2/$repo/manifests/$old_digest" >/dev/null 2>&1 || true
fi
docker push "$registry_image" >/dev/null
REMOTE_PUSH
  then
    err "failed to upload or push the TEE-LLM Pod image to $registry_image"
    detail "Check that ${REMOTE_HOST} can push to $TEELLM_IMAGE_REGISTRY, or set TEELLM_POD_IMAGE to a prebuilt image."
    exit 1
  fi
  rm -f "$archive"

  TEELLM_POD_IMAGE="$registry_image"
  TEELLM_POD_PULL_POLICY="Always"
  info "TEE-LLM Pod image built and pushed: $TEELLM_POD_IMAGE"
}

# Sizes the guest before anything is created. A kata CSV2 guest gets default_memory + limits.memory
# of encrypted memory that is resident on the host from boot and cannot be reclaimed, and the
# container's / is an overlayfs whose layers live on a tmpfs capped at half the guest's visible
# memory. An image bigger than that cap dies with ENOSPC after the VM has already been booted; a
# VM bigger than the host's free memory takes the host down with it. Both are arithmetic, so both
# are checked here rather than discovered from an event twenty minutes later.
check_pod_memory_budget() {
  local mem_mib
  mem_mib="$(quantity_to_mib "$TEELLM_POD_MEMORY")" || {
    err "cannot read TEELLM_POD_MEMORY='$TEELLM_POD_MEMORY' as a Kubernetes memory quantity"
    exit 1
  }

  local image_mib=""
  if [[ -n "$TEELLM_POD_IMAGE_SIZE_GIB" ]]; then
    image_mib="$(awk -v g="$TEELLM_POD_IMAGE_SIZE_GIB" 'BEGIN { printf "%d", g * 1024 }')"
    info "Pod image size: ${TEELLM_POD_IMAGE_SIZE_GIB}GiB (TEELLM_POD_IMAGE_SIZE_GIB)"
  elif docker image inspect "$TEELLM_POD_IMAGE" >/dev/null 2>&1; then
    image_mib=$(( $(docker image inspect -f '{{.Size}}' "$TEELLM_POD_IMAGE") / 1048576 ))
    info "Pod image size: ${image_mib}MiB uncompressed (local docker)"
  elif remote_ssh "docker image inspect '$TEELLM_POD_IMAGE' >/dev/null 2>&1" >/dev/null 2>&1; then
    image_mib="$(remote_ssh "docker image inspect -f '{{.Size}}' '$TEELLM_POD_IMAGE'" 2>/dev/null | awk '{ printf "%d", $1 / 1048576 }')"
    info "Pod image size: ${image_mib}MiB uncompressed (remote docker)"
  else
    image_mib=6247
    warn "could not measure $TEELLM_POD_IMAGE; assuming 6.10GiB, the size teellm images measure"
    detail "Set TEELLM_POD_IMAGE_SIZE_GIB to size the Pod against the real figure."
  fi

  local default_mib unpacked_mib vm_mib visible_mib run_mib need_mib bare_gib min_gib
  default_mib="$(kata_default_memory_mib)"
  # Measured on this host: the container rootfs occupies about 1.04x the image's uncompressed size.
  unpacked_mib=$(( image_mib * 104 / 100 ))
  vm_mib=$(( default_mib + mem_mib ))
  # About 1500MiB is lost to the guest kernel and ACPI tables, so this is what the guest sees.
  visible_mib=$(( vm_mib - 1500 ))
  run_mib=$(( visible_mib / 2 ))
  need_mib=$(( unpacked_mib * 115 / 100 + 256 ))
  bare_gib=$(( (unpacked_mib * 2 + 1500 - default_mib + 1023) / 1024 ))
  min_gib=$(( (need_mib * 2 + 1500 - default_mib + 1023) / 1024 ))

  step "sizing the TEE-LLM Pod (kata confidential VM)"
  detail "container limits.memory: ${mem_mib}MiB ($TEELLM_POD_MEMORY)"
  detail "kata default_memory: ${default_mib}MiB ($KATA_TOML)"
  detail "guest VM memory: ${vm_mib}MiB, resident on the host and not reclaimable"
  detail "guest visible memory: ${visible_mib}MiB; the rootfs overlay is capped at half of it: ${run_mib}MiB"
  detail "image unpacked: ${unpacked_mib}MiB; with a 15% writable margin: ${need_mib}MiB"

  if [[ "$run_mib" -lt "$unpacked_mib" ]]; then
    err "the Pod cannot start: the guest overlay cap is ${run_mib}MiB and the image alone needs ${unpacked_mib}MiB"
    detail "The guest fills its tmpfs and the container dies with ENOSPC after the VM has booted."
    detail "Raise TEELLM_POD_MEMORY to at least ${bare_gib}Gi (floor), preferably ${min_gib}Gi or more."
    exit 1
  fi
  if [[ "$run_mib" -lt "$need_mib" ]]; then
    if [[ "$TEELLM_POD_FORCE_MEMORY" != true ]]; then
      err "the Pod's memory is too tight: only $(( run_mib - unpacked_mib ))MiB would be left for the writable layer"
      detail "Raise TEELLM_POD_MEMORY to at least ${min_gib}Gi, or set TEELLM_POD_FORCE_MEMORY=true to proceed."
      exit 1
    fi
    warn "proceeding with a tight overlay budget ($(( run_mib - unpacked_mib ))MiB writable), forced"
  fi

  local avail_mib
  avail_mib="$(remote_ssh "free -m" 2>/dev/null | awk 'NR==2 { print $7 }' || true)"
  avail_mib="${avail_mib//$'\r'/}"
  avail_mib="${avail_mib//$'\n'/}"
  if [[ ! "$avail_mib" =~ ^[0-9]+$ ]] || [[ "$avail_mib" -eq 0 ]]; then
    warn "could not read the host's available memory; skipping the host memory check"
    return 0
  fi
  if [[ "$vm_mib" -gt "$avail_mib" ]]; then
    if [[ "$TEELLM_POD_FORCE_MEMORY" != true ]]; then
      err "the host has ${avail_mib}MiB available and this confidential VM needs ${vm_mib}MiB"
      detail "CSV2 memory is resident from boot and is not reclaimed, so starting it would exhaust the host."
      detail "Free a kata environment, or set TEELLM_POD_FORCE_MEMORY=true to accept the risk."
      exit 1
    fi
    warn "VM ${vm_mib}MiB exceeds the host's ${avail_mib}MiB available; continuing because TEELLM_POD_FORCE_MEMORY=true"
  elif [[ "$vm_mib" -gt $(( avail_mib * 8 / 10 )) ]]; then
    warn "the VM takes $(( vm_mib * 100 / avail_mib ))% of the host's ${avail_mib}MiB available"
  else
    info "host memory fits: VM ${vm_mib}MiB of ${avail_mib}MiB available"
  fi
}

# Reads the cc_init_data annotation off a CoCo Pod that already runs on the remote host. The
# guest's CDH needs it to trust the local registry's self-signed certificate when it pulls the
# image -- the host's own trust does not carry into the guest -- and a Pod without it stops in
# StartError. Only this value is borrowed from another Pod; the other two annotations the manifest
# carries are fixed strings the template sets itself (see teellm-pod.yaml.tmpl). Prints the bare
# value; the caller substitutes it into the manifest.
derive_cc_init_data() {
  if [[ -n "$TEELLM_POD_CC_INIT_DATA" ]]; then
    printf '%s' "$TEELLM_POD_CC_INIT_DATA"
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
    err "no Pod on ${REMOTE_USER}@${REMOTE_HOST} carries the cc_init_data annotation"
    detail "Without it the guest's CDH cannot pull the image and the new Pod stops in StartError."
    detail "Bring up any CoCo Pod once (deploy-taa-vm.sh up) or pass TEELLM_POD_CC_INIT_DATA=<base64>."
    exit 1
  fi
  printf '%s' "$derived"
}

# Prints the target Pod's IP, or nothing when it has none yet.
teellm_pod_ip() {
  local ip
  ip="$(remote_ssh "kubectl $K_NS get pod '$TARGET_POD' -o jsonpath='{.status.podIP}' 2>/dev/null" || true)"
  ip="${ip//$'\r'/}"
  ip="${ip//$'\n'/}"
  printf '%s' "$ip"
}

# A creation is a whole confidential VM of host-resident encrypted memory, so it is confirmed when
# someone is there to answer. A non-interactive run -- deploy.sh, a CI job -- proceeds: --create-pod
# is already the deliberate act, and a prompt with no one at stdin would block forever.
confirm_pod_creation() {
  if [[ "$TEELLM_POD_ASSUME_YES" == true ]] || [[ ! -t 0 ]]; then
    return 0
  fi
  echo ""
  echo "    About to create: ${TARGET_NAMESPACE}/${TARGET_POD}"
  echo "      image    $TEELLM_POD_IMAGE"
  echo "      cpu      $TEELLM_POD_CPU"
  echo "      memory   $TEELLM_POD_MEMORY (the VM is larger and resident on the host)"
  echo ""
  local answer=""
  read -r -p "    Continue? [y/N] " answer || true
  if [[ ! "$answer" =~ ^[Yy]$ ]]; then
    info "cancelled; nothing was created"
    exit 0
  fi
}

# Waits for a freshly created Pod to become Ready, polling the way the reference create script does
# rather than through `kubectl wait`. `kubectl wait` cannot stop early: an ImagePullBackOff or a
# CrashLoopBackOff is already decided, but it keeps the whole timeout and then reports only that it
# timed out. Polling shows the phase transitions and names the reason the Pod stopped.
wait_for_teellm_pod() {
  local deadline last="" phase ready reason
  deadline=$(( $(date +%s) + TEELLM_POD_READY_TIMEOUT ))
  while [[ "$(date +%s)" -lt "$deadline" ]]; do
    phase="$(remote_ssh "kubectl $K_NS get pod '$TARGET_POD' -o jsonpath='{.status.phase}' 2>/dev/null" || true)"
    ready="$(remote_ssh "kubectl $K_NS get pod '$TARGET_POD' -o jsonpath='{.status.containerStatuses[0].ready}' 2>/dev/null" || true)"
    phase="${phase//$'\r'/}"
    phase="${phase//$'\n'/}"
    ready="${ready//$'\r'/}"
    ready="${ready//$'\n'/}"
    if [[ "$phase/$ready" != "$last" ]]; then
      printf "     %s  %s%s\n" "$(date '+%H:%M:%S')" "${phase:-?}" "${ready:+  ready=$ready}"
      last="$phase/$ready"
    fi
    if [[ "$ready" == "true" ]]; then
      return 0
    fi
    if [[ "$phase" == "Failed" ]]; then
      return 1
    fi
    reason="$(remote_ssh "kubectl $K_NS get pod '$TARGET_POD' -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}' 2>/dev/null" || true)"
    reason="${reason//$'\r'/}"
    reason="${reason//$'\n'/}"
    case "$reason" in
      ErrImagePull|ImagePullBackOff|InvalidImageName|CreateContainerConfigError|CrashLoopBackOff)
        err "the container is stuck in $reason"
        return 1
        ;;
    esac
    sleep 5
  done
  return 1
}

# The host-resident size of the Pod's confidential VM: kata adds its default_memory to the
# container's limit. Prints nothing when the Pod or its limit cannot be read.
pod_vm_memory_mib() {
  local limits default_mib limits_mib
  limits="$(remote_ssh "kubectl $K_NS get pod '$TARGET_POD' -o jsonpath='{.spec.containers[0].resources.limits.memory}' 2>/dev/null" || true)"
  limits="${limits//$'\r'/}"
  limits="${limits//$'\n'/}"
  [[ -n "$limits" ]] || return 1
  limits_mib="$(quantity_to_mib "$limits")" || return 1
  default_mib="$(kata_default_memory_mib)"
  echo $(( limits_mib + default_mib ))
}

# Counts the host's kata sandboxes after a delete. Removing a Pod normally takes its sandbox and
# its qemu with it, but this host has leaked both -- containerd restarted inside a VM's boot window,
# and a RunPodSandbox retry left its qemu behind -- and a leaked qemu keeps its whole -m resident.
# Three counts have to agree: the kata Pods the cluster knows, the sandbox directories, the qemus.
check_kata_orphans() {
  if [[ "$TEELLM_POD_ORPHAN_CHECK" != true ]]; then
    return 0
  fi
  step "checking for leftover kata sandboxes (three counts must agree)"
  local report kata_pods sbs qemus
  report="$(remote_ssh 'bash -s' <<'REMOTE_ORPHANS'
set -u
kata_pods=$(kubectl get pods -A -o jsonpath='{range .items[*]}{.spec.runtimeClassName}{"\n"}{end}' 2>/dev/null | grep -c '^kata' || true)
sbs=$(ls -1 /run/vc/sbs 2>/dev/null | grep -c . || true)
qemus=$(pgrep -c -f '[q]emu-system' 2>/dev/null || true)
printf 'kata_pods=%s\nsbs=%s\nqemus=%s\n' "${kata_pods:-0}" "${sbs:-0}" "${qemus:-0}"
if [ "${kata_pods:-0}" != "${sbs:-0}" ] || [ "${sbs:-0}" != "${qemus:-0}" ]; then
  echo "ORPHANS"
  pgrep -a -f '[q]emu-system' 2>/dev/null | while read -r pid rest; do
    rss=$(awk '/VmRSS/{printf "%.1f GiB", $2/1048576}' "/proc/$pid/status" 2>/dev/null)
    m=$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null | grep -o '\-m [0-9]*' | head -1)
    echo "  pid=$pid  RSS=${rss:-?}  ${m}  $(echo "$rest" | cut -c1-60)"
  done
fi
REMOTE_ORPHANS
)"
  report="${report//$'\r'/}"
  kata_pods="$(sed -n 's/^kata_pods=//p' <<<"$report")"
  sbs="$(sed -n 's/^sbs=//p' <<<"$report")"
  qemus="$(sed -n 's/^qemus=//p' <<<"$report")"
  detail "kata Pods: ${kata_pods:-?}   /run/vc/sbs: ${sbs:-?}   qemu-system: ${qemus:-?}"
  if grep -q '^ORPHANS$' <<<"$report"; then
    warn "the counts disagree: a sandbox outlived its Pod and its memory has not come back"
    while IFS= read -r line; do
      detail "$line"
    done < <(sed -n '/^ORPHANS$/,$p' <<<"$report" | tail -n +2)
    detail "Do not kill qemu directly: the sandbox directory and the shim record would survive it."
    detail "  1) sudo crictl pods | grep -i <sandbox prefix>   # confirm nothing still needs it"
    detail "  2) sudo crictl stopsandbox <sandbox-id>"
    detail "  3) sudo crictl rmp <sandbox-id>"
    detail "  4) re-run $(basename "$0") pod-down to recheck"
  else
    info "no leftover sandboxes"
  fi
}

# Makes sure the dedicated TEE-LLM Pod exists, is Ready and can really produce a CSV attestation,
# then records its IP in TEELLM_POD_IP.
pod_up() {
  require_file "TEE-LLM Pod template" "$TEELLM_POD_TEMPLATE"
  step "checking the dedicated TEE-LLM Pod ($TARGET_POD in $TARGET_NAMESPACE)"

  if remote_ssh "kubectl $K_NS get pod '$TARGET_POD' >/dev/null 2>&1"; then
    # An existing Pod is never re-applied and never recreated. Its annotations and resource
    # limits are immutable, so an apply fails; and "delete then apply" would build a second
    # confidential VM, throw away the guest's writable layer (the ollama bundle and the model
    # live there) and change the Pod IP that TAA's endpoint points at.
    if ! remote_ssh "kubectl $K_NS wait --for=condition=Ready --timeout=5s pod/'$TARGET_POD' >/dev/null 2>&1"; then
      err "Pod '$TARGET_POD' exists but is not Ready"
      remote_ssh "kubectl $K_NS get pod '$TARGET_POD' -o wide" || true
      remote_ssh "kubectl $K_NS describe pod '$TARGET_POD' | tail -n 30" || true
      detail "Recreating it would not help: the guest's writable layer holds the ollama runtime and"
      detail "the model, and a new Pod would also change the IP. Delete it by hand only if it is wedged."
      exit 1
    fi
    info "reusing the running TEE-LLM Pod (nothing applied)"
  else
    # The image is chosen only on this path: an existing Pod's image cannot change, so building or
    # resolving one there would be work whose result nothing acts on.
    if [[ -n "$TEELLM_POD_IMAGE_WAS_SET" ]]; then
      info "TEE-LLM image: $TEELLM_POD_IMAGE (named explicitly; nothing built or resolved)"
    elif [[ "$TEELLM_BUILD_POD_IMAGE" == true ]]; then
      build_teellm_pod_image
    else
      resolve_teellm_pod_image
    fi

    # Before the manifest is rendered and long before anything is applied: both a guest that cannot
    # hold its own rootfs and a VM larger than the host can hold are known here, not from an event.
    check_pod_memory_budget

    local cc_init_data
    cc_init_data="$(derive_cc_init_data)"
    TEMP_POD_MANIFEST="$(mktemp /tmp/teellm-pod.XXXXXX.yaml)"
    # The placeholders are substituted with | as the delimiter because the injected base64 value
    # contains / and + but never |. Values are quoted in the template, so an unquoted-looking
    # value cannot leak into YAML either.
    sed -e "s|__POD_NAME__|$TARGET_POD|g" \
        -e "s|__NAMESPACE__|$TARGET_NAMESPACE|g" \
        -e "s|__NODE_NAME__|$TEELLM_POD_NODE|g" \
        -e "s|__IMAGE__|$TEELLM_POD_IMAGE|g" \
        -e "s|__PULL_POLICY__|$TEELLM_POD_PULL_POLICY|g" \
        -e "s|__RUNTIME_CLASS__|$TEELLM_POD_RUNTIME_CLASS|g" \
        -e "s|__CPU__|$TEELLM_POD_CPU|g" \
        -e "s|__MEMORY__|$TEELLM_POD_MEMORY|g" \
        -e "s|__MODEL__|$OLLAMA_MODEL|g" \
        -e "s|__CC_INIT_DATA__|$cc_init_data|g" \
        "$TEELLM_POD_TEMPLATE" > "$TEMP_POD_MANIFEST"
    confirm_pod_creation
    step "creating the TEE-LLM Pod (runtimeClassName: $TEELLM_POD_RUNTIME_CLASS, node: $TEELLM_POD_NODE)"
    remote_ssh "kubectl $K_NS apply -f -" < "$TEMP_POD_MANIFEST"
    rm -f "$TEMP_POD_MANIFEST"
    TEMP_POD_MANIFEST=""
    info "submitted; the guest boots before it can pull the image, so a first creation takes minutes"
    if ! wait_for_teellm_pod; then
      err "TEE-LLM Pod '$TARGET_POD' did not become Ready within ${TEELLM_POD_READY_TIMEOUT}s"
      remote_ssh "kubectl $K_NS describe pod '$TARGET_POD' | sed -n '/Events:/,\$p' | tail -n 20" || true
      detail "The Pod is left in place for inspection: kubectl $K_NS describe pod '$TARGET_POD'"
      detail "Container logs: kubectl $K_NS logs '$TARGET_POD'"
      detail "Delete and recreate: $(basename "$0") pod-down"
      exit 1
    fi
    info "TEE-LLM Pod created and Ready"
  fi

  # The device is the point of this Pod. Its absence is silent: teellm-service merely logs a
  # warning, switches to mock evidence and still answers the readiness probe -- which cannot
  # catch this, because that probe's client skips attestation verification. Check the device
  # rather than the RuntimeClass name, since the name alone does not prove which guest booted.
  if ! remote_ssh "$(container_exec) test -e /dev/csv-guest"; then
    err "Pod '$TARGET_POD' has no /dev/csv-guest, so it cannot produce a real CSV attestation"
    detail "teellm-service would fall back to mock evidence, which TAA cannot tell apart from"
    detail "hardware now that the certificate chain is skipped. Expected runtimeClassName $TEELLM_POD_RUNTIME_CLASS."
    detail "Pod left running for inspection: kubectl $K_NS exec '$TARGET_POD' -- ls -l /dev/csv*"
    exit 1
  fi

  TEELLM_POD_IP="$(teellm_pod_ip)"
  if [[ -z "$TEELLM_POD_IP" ]]; then
    err "Pod '$TARGET_POD' is Ready but reports no Pod IP"
    exit 1
  fi
  info "TEE-LLM Pod ready with a real CSV device: $TARGET_POD at $TEELLM_POD_IP"
}

# Deletes the dedicated TEE-LLM Pod. Destructive by design: the guest's writable layer -- the
# ollama runtime and the model copied into it -- goes with it, so the next start has to deploy
# them again.
pod_down() {
  step "deleting the TEE-LLM Pod ($TARGET_POD in $TARGET_NAMESPACE)"
  if ! remote_ssh "kubectl $K_NS get pod '$TARGET_POD' >/dev/null 2>&1"; then
    info "TEE-LLM Pod '$TARGET_POD' does not exist"
    # Still checked: a sandbox can outlive its Pod, and then nothing else would ever report it.
    check_kata_orphans
    return 0
  fi

  local vm_mib=""
  vm_mib="$(pod_vm_memory_mib 2>/dev/null || true)"

  # A grace period rather than --wait: the deletion is polled below so the wait and the fallback
  # measure the same thing, and a guest that ignores the signal is visible rather than hidden.
  remote_ssh "kubectl $K_NS delete pod '$TARGET_POD' --grace-period=30 --ignore-not-found --wait=false" || true
  local gone=false
  local _i
  for _i in $(seq 1 36); do
    if ! remote_ssh "kubectl $K_NS get pod '$TARGET_POD' >/dev/null 2>&1"; then
      gone=true
      break
    fi
    sleep 5
  done
  # A VM-backed Pod whose guest is wedged will not answer a graceful delete; fall back to force so
  # a broken Pod cannot block the teardown. Its memory is host-resident, so leaving it costs GiB.
  if [[ "$gone" != true ]]; then
    warn "Pod '$TARGET_POD' did not exit within 180s; forcing deletion"
    remote_ssh "kubectl $K_NS delete pod '$TARGET_POD' --force --grace-period=0" || true
    for _i in $(seq 1 12); do
      if ! remote_ssh "kubectl $K_NS get pod '$TARGET_POD' >/dev/null 2>&1"; then
        gone=true
        break
      fi
      sleep 5
    done
  fi
  if [[ "$gone" != true ]]; then
    err "Pod '$TARGET_POD' is still present after a forced delete"
    exit 1
  fi
  info "TEE-LLM Pod '$TARGET_POD' deleted"
  if [[ "$vm_mib" =~ ^[0-9]+$ ]] && [[ "$vm_mib" -gt 0 ]]; then
    info "about $(( vm_mib / 1024 ))GiB of host memory comes back once the sandbox is collected"
  fi
  check_kata_orphans
}

# The Pod supervisor owns teellm-service and ollama, so the deployment cannot simply kill them:
# it pauses the supervisor first, and resumes it only after every new file is in place. A
# supervisor left running during the stream would restart a daemon on a half-written binary.
pod_supervisor_pause() {
  remote_ssh "$(container_exec) sh -lc 'touch \"$CON_WORKDIR/.teellm-supervisor-pause\"'"
}

# Lifting the pause is also when an installed supervisor script takes effect: the restart request
# makes the running copy re-exec the file the deployment just moved into place. The request is
# made unconditionally. Whether the Pod came from pod_up or was named by a bare TARGET_POD run,
# and whether the container command or the fallback started the supervisor, the copy in memory may
# predate the installed file -- a conditional request once left a stale supervisor running after
# its replacement had been installed, and the fix it carried never took effect. Re-execing a copy
# that already runs the current file costs one restart of the daemons, before they are up.
pod_supervisor_resume() {
  remote_ssh "$(container_exec) sh -lc 'touch \"$CON_WORKDIR/.teellm-supervisor-restart\"; rm -f \"$CON_WORKDIR/.teellm-supervisor-pause\"'"
}

# A Pod created with this template runs the supervisor itself as soon as the file is installed.
# A Pod created before the supervisor existed still has `sleep infinity` as PID 1 and no process
# that would ever exec the script, so after a short grace period the deployment starts it
# detached. The supervisor is a flock singleton, so a race between the two cannot yield two copies.
# On such a Pod the copy is not PID 1: a restart of the container loses it until the next
# deployment. Recreating the Pod is what makes supervision container-durable.
ensure_pod_supervisor_running() {
  local attempt
  for ((attempt = 1; attempt <= TEELLM_SUPERVISOR_START_WAIT; attempt++)); do
    if remote_ssh "$(container_exec) sh -lc 'p=\"$CON_WORKDIR/.teellm-supervisor.pid\"; pid=\$(cat \"\$p\" 2>/dev/null); [ -n \"\$pid\" ] && kill -0 \"\$pid\" 2>/dev/null'" >/dev/null 2>&1; then
      info "Pod supervisor is already running"
      return 0
    fi
    sleep 1
  done
  step "starting the Pod supervisor (this Pod has no process that would exec it)"
  remote_ssh "$(container_exec) sh -lc 'cd \"$CON_WORKDIR\" && nohup ./teellm-supervisor.sh >> \"$CON_WORKDIR/teellm-service.log\" 2>&1 &'"
}

# Stops the three daemons the supervisor owns inside the Pod. Both the 'stop' action and the start
# path's "stopping old daemons" step need the whole list, so it lives here and is written once.
# 'killall' and 'pkill -x' are both tried: a busybox userland has only the former. A miss is not an
# error -- the daemon may simply not be running -- hence the trailing || true on every clause.
# Callers pause the supervisor first; without that it would restart them within its delay.
stop_pod_daemons() {
  remote_ssh "$(container_exec) sh -lc 'pkill -x teellm-service >/dev/null 2>&1 || true; killall teellm-service >/dev/null 2>&1 || true; pkill -x ollama >/dev/null 2>&1 || true; killall ollama >/dev/null 2>&1 || true; pkill -x llama-server >/dev/null 2>&1 || true; killall llama-server >/dev/null 2>&1 || true'"
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
  local cfg_file="${TEELLM_CONFIG_PATH:-$TEELLM_DIR/configs/teellm-production.json}"
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

prepare_config() {
  local template="$1"
  local output_file="$2"
  local model="$3"
  local port="$4"
  local platform_addr="${5:-}"

  require_file "teellm config template" "$template"
  require_command python3

  python3 - "$template" "$output_file" "$model" "$port" "$platform_addr" <<'PY'
import json, sys

template_path, output_path, model, port, platform_addr = sys.argv[1:6]
with open(template_path, "r", encoding="utf-8") as f:
    cfg = json.load(f)

if model:
    cfg.setdefault("backend", {})["defaultModel"] = model
if port:
    cfg.setdefault("server", {})["addr"] = f":{port}"
if platform_addr:
    cfg.setdefault("platform", {})["addr"] = platform_addr

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
      echo "  Deploy: ./deploy-llm.sh --create-pod start"
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
Usage: $(basename "$0") [start|stop|probe|pod-down] [options]
       $(basename "$0") models [list|info|switch] [args]

Deploy and manage the standalone TEE-LLM inference service and its offline Ollama runtime in a
Kata CSV2 Kubernetes Pod.

Model Management Commands:
  models list                  List available models and active selection.
  models info <model>          Display detailed profile and blob readiness for a model.
  models switch <model>        Verify and switch active model across configurations.

Actions:
  start        Build binary, incrementally sync model & runtime, hand the daemons to the Pod
               supervisor, and verify (default).
  stop         Pause the Pod supervisor and stop its services (teellm-service, ollama, llama-server).
  probe        Probe the TEE-LLM HTTPS endpoint for RFC 8998 TEE-TLS 1.3 readiness.
  pod-down     Delete the dedicated TEE-LLM Pod (see --create-pod), then check the host for
               kata sandboxes left behind by it.

Options:
  --model <name> (or --model=<name>)
      Specify target LLM model name (default: qwen2.5-coder:3b).
  --ollama-dir <path> (or --ollama-dir=<path>)
      Specify local directory containing offline Ollama package and models.
  --create-pod
      Deploy into a dedicated Kata CSV2 Pod named by TEELLM_POD_NAME, creating it if it is absent,
      instead of into TARGET_POD. The Pod exists to give teellm-service a real /dev/csv-guest:
      without that device it serves mock evidence, and TAA cannot tell that evidence apart from
      hardware at the handshake. Creating the Pod builds teellm-service from this working tree,
      bakes it plus the ollama runtime and model into an image, pushes that image and runs the Pod
      from it, so the Pod never runs a binary older than the tree being deployed. That build takes
      tens of minutes. The registry is asked for the config digest currently under the tag first:
      when it already holds this exact build, nothing is exported or uploaded. An existing Pod is
      reused and never re-created -- a second Pod would be a second confidential VM, and the image
      cannot change under a running one.
      If TARGET_POD is set explicitly it must equal TEELLM_POD_NAME, or the run is refused.
  --port <port> (or --port=<port>)
      Specify TEE-LLM service listening port (default: $TEELLM_PORT).
  --config <path> (or --config=<path>)
      Specify path to alternate service JSON configuration template.
  --pod <name> (or --pod=<name>, pod=<name>)
      Deploy into the existing Pod named <name>; same as setting TARGET_POD, and it wins over the
      variable. Nothing about the Pod's lifecycle is touched unless --create-pod is also given,
      and then <name> must equal TEELLM_POD_NAME.
  -h, --help, help
      Display this help documentation.

Environment overrides:
  TEELLM_PORT=${TEELLM_PORT}
      TEE-LLM service listening port.
  TEELLM_PLATFORM_ADDR=${TEELLM_PLATFORM_ADDR}
      Platform this instance registers with. Empty disables reporting.
  OLLAMA_LOCAL_DIR=${OLLAMA_LOCAL_DIR:-}
      Path to offline Ollama and model weights bundle.
  OLLAMA_MODEL=${OLLAMA_MODEL:-}
      Default model override for inference.
  CON_WORKDIR=${CON_WORKDIR}
      Working directory inside the TEE-LLM Pod.
  CONTAINER_OLLAMA_DIR=${CONTAINER_OLLAMA_DIR}
      Ollama deployment directory inside the TEE-LLM Pod.
  TARGET_NAMESPACE=${TARGET_NAMESPACE}
      Remote Kubernetes namespace (the TEE-LLM Pod's namespace too).
  TARGET_POD=${TARGET_POD}
      Remote Kubernetes target Pod name.
  TEELLM_POD_NAME=${TEELLM_POD_NAME}
      Name of the dedicated TEE-LLM Pod (--create-pod, pod-down).
  TEELLM_POD_IMAGE=${TEELLM_POD_IMAGE}
      Image for the dedicated TEE-LLM Pod. Set explicitly, it is used as given and nothing is
      built or resolved. Left unset with TEELLM_BUILD_POD_IMAGE=true (the default), the Pod image
      is built from this working tree, pushed as
      $TEELLM_IMAGE_REGISTRY/$TEELLM_IMAGE_REPO:<today> and used. Left unset with the build
      disabled, it is today's date tag replaced by the newest date tag the registry lists.
  TEELLM_BUILD_POD_IMAGE=${TEELLM_BUILD_POD_IMAGE}
      Whether a Pod that has to be created is built from this working tree first (see above).
  TEELLM_POD_PULL_POLICY=${TEELLM_POD_PULL_POLICY}
      imagePullPolicy for the Pod; forced to Always when this run built the image, because the
      tag is a same-day one that a rebuild replaces in place.
  TEELLM_IMAGE_REGISTRY / TEELLM_IMAGE_REPO
      Registry the built image is pushed to, and the repository name inside it.
  TEELLM_IMAGE_BASE=${TEELLM_IMAGE_BASE}
  TEELLM_IMAGE_BASE_ARCHIVE=${TEELLM_IMAGE_BASE_ARCHIVE}
      Source image for the built Pod image, and the archive it is loaded from when it is not
      already local. The TAA payload under /root/taa is stripped before the teellm payload is
      added.
  TEELLM_IMAGE_KEEP_BUILDER=${TEELLM_IMAGE_KEEP_BUILDER}
      Keep the builder container after the image is committed, for inspecting a payload that
      failed to build. Removed on success by default.
  TEELLM_POD_NODE=${TEELLM_POD_NODE}
      Node the dedicated TEE-LLM Pod is pinned to.
  TEELLM_POD_RUNTIME_CLASS=${TEELLM_POD_RUNTIME_CLASS}
      RuntimeClass of the dedicated TEE-LLM Pod. It has to be a CSV2 class, because only such a
      guest creates /dev/csv-guest.
  TEELLM_POD_CPU=${TEELLM_POD_CPU} / TEELLM_POD_MEMORY=${TEELLM_POD_MEMORY}
      Container CPU / memory for the dedicated TEE-LLM Pod. Kata sizes the guest from these
      limits (guest RAM = the kata default_memory + TEELLM_POD_MEMORY, vCPUs = default_vcpus +
      TEELLM_POD_CPU) and CSV2 encrypted memory is resident from boot, so the memory figure is a
      permanent cost on the host rather than a ceiling. It has to fit the served model as well as
      teellm-service: 8Gi OOM-killed llama-server while it loaded a 7B model.
  TEELLM_POD_IMAGE_SIZE_GIB / TEELLM_POD_FORCE_MEMORY
      Size the Pod is checked against, and the escape hatch for that check. Before creating
      anything the deployment verifies that the image fits the guest's overlayfs (whose cap is
      half the guest's visible memory) and that the whole VM fits the host's free memory; it
      stops instead of booting a VM that will die with ENOSPC or exhaust the host.
  TEELLM_POD_READY_TIMEOUT=${TEELLM_POD_READY_TIMEOUT}
      Seconds to wait for a freshly created TEE-LLM Pod to become Ready. Long by default: the
      guest boots before it can pull the image, through its own CDH.
  TEELLM_POD_ASSUME_YES=${TEELLM_POD_ASSUME_YES}
      Skip the interactive confirmation before creating the Pod (also skipped when stdin is not
      a terminal, so scripted runs never block).
  TEELLM_POD_ORPHAN_CHECK=${TEELLM_POD_ORPHAN_CHECK}
      After pod-down, compare the host's kata Pod count, its /run/vc/sbs directories and its
      qemu-system processes. Any disagreement means a sandbox outlived its Pod and its memory
      has not been returned.
  TEELLM_POD_CC_INIT_DATA=<base64>
      cc_init_data annotation for the new Pod. Left empty it is read from a CoCo Pod that already
      runs on the remote host; without it the guest cannot pull the image. Only this value is
      borrowed from another Pod: the runtime-handler and kernel_params annotations the manifest
      carries are fixed in the template.
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
  $(basename "$0") --create-pod start
  $(basename "$0") --create-pod start --model qwen2.5-coder:7b
  $(basename "$0") start
  $(basename "$0") --pod taa-teellm start
  $(basename "$0") pod=taa-teellm start
  $(basename "$0") probe
  $(basename "$0") stop
  $(basename "$0") pod-down

Point TAA at the Pod afterwards: the deployment prints
  LLM_IP=https://<pod-ip>:${TEELLM_PORT}
which deploy.sh writes into TAA's llm.endpoint. Use the Pod IP, not a Service name: a kata guest
cannot resolve cluster DNS.
EOF
}

ACTION=""
CLI_MODEL=""
CLI_OLLAMA_DIR=""
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
    pod-down)
      if [[ -n "$ACTION" && "$ACTION" != "pod-down" ]]; then
        err "cannot specify multiple actions ($ACTION and pod-down)"
        usage >&2
        exit 1
      fi
      ACTION="pod-down"
      ;;
    --create-pod)
      CREATE_POD=true
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
    # Names the Pod to install into. Setting TARGET_POD_WAS_SET is what keeps --create-pod honest:
    # the check that refuses a mis-aimed dedicated-Pod command keys off "the operator named a Pod".
    --pod=*|pod=*)
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

if [[ "$CREATE_POD" == true || "$ACTION" == "pod-down" ]]; then
  # An explicitly named Pod wins the argument: overriding it would aim the deployment at a Pod
  # the operator named, which is exactly the silent mis-target these paths have to prevent.
  if [[ "$TARGET_POD_WAS_SET" == "set" && "$TARGET_POD" != "$TEELLM_POD_NAME" ]]; then
    err "this command addresses the TEE-LLM Pod '$TEELLM_POD_NAME', but TARGET_POD names '$TARGET_POD'"
    detail "Unset TARGET_POD, or set TEELLM_POD_NAME=$TARGET_POD to treat that Pod as the TEE-LLM Pod."
    exit 1
  fi
  # Unconditional, default or not: TARGET_POD defaults to a TAA environment Pod, which has
  # /dev/csv-guest as well, so a mis-aimed deployment passes every gate below while teellm-service
  # ends up in a Pod that the printed endpoint does not point at -- and pod-down would delete TAA
  # itself.
  TARGET_POD="$TEELLM_POD_NAME"
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
  step "probing teellm-service in remote pod ($TARGET_POD)"
  if remote_ssh "$(container_exec) \"$CON_WORKDIR/teellm-service\" -probe \"https://127.0.0.1:${TEELLM_PORT}\""; then
    info "remote probe check successful: teellm-service is healthy on https://127.0.0.1:${TEELLM_PORT}"
    exit 0
  else
    err "remote probe check failed on https://127.0.0.1:${TEELLM_PORT}"
    exit 1
  fi
fi

# ── Stop Action Handler ───────────────────────────────────────

if [[ "$ACTION" == "stop" ]]; then
  banner "Stopping TEE-LLM Services"
  step "pausing the Pod supervisor in remote pod ($TARGET_POD)"
  pod_supervisor_pause 2>/dev/null || true
  step "stopping teellm-service, ollama, and llama-server in remote pod ($TARGET_POD)"
  stop_pod_daemons 2>/dev/null || true
  info "teellm-service, ollama, and llama-server stopped cleanly in remote pod $TARGET_POD"
  exit 0
fi

# ── Dedicated Pod Teardown Handler ────────────────────────────
# Handled before the start path's preflight, which insists on the local offline ollama bundle --
# a teardown must not depend on the machine that deployed the bundle still having it.

if [[ "$ACTION" == "pod-down" ]]; then
  banner "Deleting the TEE-LLM Pod" "Pod: $TARGET_POD (namespace: ${TARGET_NAMESPACE:-default})"
  pod_down
  echo ""
  warn "The guest's writable layer went with the Pod, so the ollama runtime and the model are gone."
  detail "The next '--create-pod start' deploys them again."
  echo ""
  exit 0
fi

# ── Deployment Logic (start) ──────────────────────────────────

OLLAMA_LOCAL_DIR="$(resolve_ollama_local_dir)"
OLLAMA_MODEL="$(resolve_target_model)"

require_dir "ollama offline package" "$OLLAMA_LOCAL_DIR"
require_file "ollama executable" "$OLLAMA_LOCAL_DIR/ollama"
require_file "start-ollama.sh script" "$OLLAMA_LOCAL_DIR/start-ollama.sh"
require_file "TEE-LLM Pod supervisor script" "$TEELLM_SUPERVISOR_SCRIPT"
require_dir "ollama models directory" "$OLLAMA_LOCAL_DIR/models/models"
require_dir "ollama lib directory" "$OLLAMA_LOCAL_DIR/lib/ollama"
verify_ollama_binary "$OLLAMA_LOCAL_DIR/ollama"

# Read model metadata
model_meta="$(resolve_ollama_model_artifacts "$OLLAMA_LOCAL_DIR" "$OLLAMA_MODEL" "json")"
model_mb="$(python3 -c 'import sys, json; print(json.loads(sys.argv[1])["weight_mb"])' "$model_meta" 2>/dev/null || echo "unknown")"

# Build teellm-service locally
build_local_binary() {
  # Once per run: a Pod creation builds the binary to bake into the image, and the deployment then
  # installs that same file into the Pod. Compiling again would only re-derive identical bytes.
  if [[ "$LOCAL_BINARY_BUILT" == true ]]; then
    info "teellm-service was already rebuilt in this run: $TEELLM_DIR/bin/teellm-service"
    return 0
  fi
  step "building teellm-service from ./teellm/cmd/teellm-service"
  ensure_go_compiler
  require_file "teellm supervisor script missing" "$TEELLM_DIR/deploy/start.sh"
  mkdir -p "$TEELLM_DIR/bin"
  # The teellm module is a sibling of this script in the go.work workspace, so the package
  # path resolves from the repository root exactly like ./tools/platform-mock does in deploy.sh.
  spin_task "compiling teellm-service binary" go build -o "$TEELLM_DIR/bin/teellm-service" ./teellm/cmd/teellm-service
  require_file "build verification failed (teellm-service binary missing)" "$TEELLM_DIR/bin/teellm-service"
  LOCAL_BINARY_BUILT=true
  info "teellm-service binary built: $TEELLM_DIR/bin/teellm-service"
}

# ── TEE-LLM Pod Deployment ────────────────────────────────────

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

# A TEE-LLM image can carry the ollama runtime and the model (build_teellm_pod_image), which is what
# lets a freshly booted guest serve without the deployment copying anything in. When the Pod
# already has both, streaming several GB from the packaging host to the remote host and then into
# the Pod is pure overhead, so the Pod is probed first and the host sync is skipped. The probes are
# the same ones copy_ollama_to_remote_pod uses to decide whether it has anything left to copy.
sync_ollama_to_remote_if_missing() {
  # A forced copy is an explicit request to restage the bundle, so the probe is not consulted.
  if [[ "$FORCE_QWEN_COPY" == true ]]; then
    sync_ollama_to_remote
    return 0
  fi
  local check_script
  check_script="$(resolve_ollama_model_artifacts "$OLLAMA_LOCAL_DIR" "$OLLAMA_MODEL" "check_model_sh" "$CONTAINER_OLLAMA_DIR")"
  if remote_ssh "$(container_exec) sh -lc 'test -f \"$CONTAINER_OLLAMA_DIR/ollama\" && test -f \"$CONTAINER_OLLAMA_DIR/start-ollama.sh\" && test -f \"$CONTAINER_OLLAMA_DIR/lib/ollama/libllama-server-impl.so\"'" >/dev/null 2>&1 \
     && remote_ssh "$(container_exec) sh -lc '$check_script'" >/dev/null 2>&1; then
    info "ollama runtime and model '$OLLAMA_MODEL' are already inside the Pod; skipping the host sync"
    return 0
  fi
  sync_ollama_to_remote
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

deploy_teellm() {
  banner "Deploying TEE-LLM Service" "Host: ${REMOTE_USER}@${REMOTE_HOST} | Pod: $TARGET_POD | Model: $OLLAMA_MODEL"

  step "verifying remote host and target pod connectivity"
  check_remote_connectivity
  # Before check_remote_pod, which demands that the Pod exists: on this path the script is what
  # brings it into existence.
  if [[ "$CREATE_POD" == true ]]; then
    pod_up
  fi
  check_remote_pod
  if [[ -z "$TEELLM_POD_IP" ]]; then
    TEELLM_POD_IP="$(teellm_pod_ip)"
  fi

  build_local_binary

  # Before anything is killed or written. The supervisor restarts whatever it finds missing, so a
  # daemon left running during the stream could execute a half-copied runtime.
  step "pausing the Pod supervisor inside remote pod"
  pod_supervisor_pause

  step "stopping old daemons inside remote pod"
  stop_pod_daemons

  sync_ollama_to_remote_if_missing
  copy_ollama_to_remote_pod

  # Deploy the binary and configuration to the remote host, then into the Pod
  step "preparing and uploading configuration and binary"
  local cfg_template="${TEELLM_CONFIG_PATH:-$TEELLM_DIR/configs/teellm-production.json}"
  local tmp_cfg
  tmp_cfg="$(mktemp /tmp/teellm_cfg.XXXXXX)"
  TEMP_CONFIG_FILE="$tmp_cfg"
  prepare_config "$cfg_template" "$tmp_cfg" "$OLLAMA_MODEL" "$TEELLM_PORT" "$TEELLM_PLATFORM_ADDR"

  remote_ssh "mkdir -p '$REMOTE_DIR/configs'"
  sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$TEELLM_DIR/bin/teellm-service" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/teellm-service.new"
  sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$TEELLM_SUPERVISOR_SCRIPT" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/teellm-supervisor.sh"
  sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$tmp_cfg" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/configs/teellm-production.json"
  if [[ -f "$TEELLM_DIR/configs/models.json" ]]; then
    sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$TEELLM_DIR/configs/models.json" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/configs/models.json"
  fi
  rm -f "$tmp_cfg"
  TEMP_CONFIG_FILE=""

  remote_ssh "mv '$REMOTE_DIR/teellm-service.new' '$REMOTE_DIR/teellm-service' && chmod +x '$REMOTE_DIR/teellm-service'"

  # Copy into remote pod
  step "installing binary and configuration into remote pod"
  remote_ssh "$(container_exec) sh -lc 'mkdir -p \"$CON_WORKDIR/configs\"'"
  remote_ssh "$(container_cp "$REMOTE_DIR/teellm-service" "$CON_WORKDIR/teellm-service")"
  remote_ssh "$(container_cp "$REMOTE_DIR/configs/teellm-production.json" "$CON_WORKDIR/configs/teellm-production.json")"
  if [[ -f "$TEELLM_DIR/configs/models.json" ]]; then
    remote_ssh "$(container_cp "$REMOTE_DIR/configs/models.json" "$CON_WORKDIR/configs/models.json")"
  fi
  remote_ssh "$(container_exec) sh -lc 'chmod +x \"$CON_WORKDIR/teellm-service\"'"

  # The supervisor is the Pod's PID 1 and the only thing that starts or restarts a daemon. It is
  # moved into place rather than written in place: `mv` swaps the inode, while overwriting a
  # running script fails with ETXTBSY. A running copy re-execs the new file on resume.
  remote_ssh "$(container_cp "$REMOTE_DIR/teellm-supervisor.sh" "$CON_WORKDIR/.teellm-supervisor.sh.new")"
  remote_ssh "$(container_exec) sh -lc 'chmod +x \"$CON_WORKDIR/.teellm-supervisor.sh.new\" && mv \"$CON_WORKDIR/.teellm-supervisor.sh.new\" \"$CON_WORKDIR/teellm-supervisor.sh\"'"

  # Written every deployment: a reused Pod keeps the env it was created with, so this file is what
  # carries a `models switch` into a Pod that is not recreated.
  remote_ssh "$(container_exec) sh -lc 'printf %s \"$OLLAMA_MODEL\" > \"$CON_WORKDIR/.teellm-model\"'"

  # Migrates a Pod that predates the supervisor; a no-op on one that already runs it.
  step "ensuring the Pod supervisor is running"
  ensure_pod_supervisor_running

  # Hand the daemons back. On a reused Pod this also re-execs the supervisor that was just
  # installed, so a supervisor change takes effect without recreating the CSV2 guest.
  step "resuming the Pod supervisor inside remote pod"
  pod_supervisor_resume

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

  # Probe remote service. The supervisor starts it once ollama answers; there is no separate start
  # step here, and adding one would race the supervisor for the port.
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

  # The probe above cannot vouch for the attestation: its client is built with
  # InsecureSkipAttestationVerify set (see runProbe in teellm/cmd/teellm-service), so it passes
  # just as well against a mock report. Which provider the server picked is only in its log, and
  # a mock provider is the failure this gate exists to catch: TAA verifies only the report's PEK
  # signature, which the mock authority also produces validly, and with measurement unset nothing
  # downstream rejects it.
  if [[ "$CREATE_POD" == true ]]; then
    step "confirming the service serves hardware evidence, not mock evidence"
    local provider_log
    provider_log="$(remote_ssh "$(container_exec) tail -n 200 '$TEELLM_LOG_FILE'" || true)"
    if ! grep -q "using Hygon hardware evidence provider" <<<"$provider_log"; then
      err "teellm-service in '$TARGET_POD' did not report the Hygon hardware evidence provider"
      remote_ssh "$(container_exec) tail -n 30 '$TEELLM_LOG_FILE'" || true
      detail "TAA cannot distinguish a mock report from hardware at the handshake, so this"
      detail "deployment would serve non-attested evidence. Check that the Pod still has /dev/csv-guest."
      exit 1
    fi
    if grep -q "falling back to mock attestation provider" <<<"$provider_log"; then
      err "teellm-service in '$TARGET_POD' fell back to the mock attestation provider"
      remote_ssh "$(container_exec) tail -n 30 '$TEELLM_LOG_FILE'" || true
      exit 1
    fi
    info "service is serving Hygon hardware evidence (/dev/csv-guest present)"
  fi

  banner "Deploy Complete (TEE-LLM Pod)" "TEE-LLM service running and verified healthy"
  echo -e "  ${BOLD}${CYAN}● TEE-LLM Inference Service${NC}  ${DIM}(RFC 8998 ShangMi TEE-TLS 1.3)${NC}"
  echo -e "    ${MUTED}↳ Target Pod :${NC} ${TARGET_POD} (${TARGET_NAMESPACE})"
  echo -e "    ${MUTED}↳ Pod IP     :${NC} ${TEELLM_POD_IP:-unknown}"
  echo -e "    ${MUTED}↳ Remote Host:${NC} ${REMOTE_USER}@${REMOTE_HOST}"
  echo -e "    ${MUTED}↳ Port       :${NC} ${TEELLM_PORT}"
  echo -e "    ${MUTED}↳ Config     :${NC} ${CON_WORKDIR}/configs/teellm-production.json"
  echo -e "    ${MUTED}↳ Supervisor :${NC} ${CON_WORKDIR}/teellm-supervisor.sh (restarts teellm-service and ollama)"
  echo -e "    ${MUTED}↳ Log file   :${NC} ${TEELLM_LOG_FILE}"
  if [[ -n "$TEELLM_POD_IP" ]]; then
    # The Pod IP, not a Service name: a kata guest cannot resolve cluster DNS, so TAA has to be
    # pointed at the address itself. This is also the only knob that changes TAA's llm.endpoint
    # on the remote path -- deploy.sh always writes it from LLM_IP.
    echo -e "    ${MUTED}↳ For TAA    :${NC} LLM_IP=https://${TEELLM_POD_IP}:${TEELLM_PORT}"
  fi
  echo ""
  echo -e "  ${BOLD}${CYAN}● Ollama / Qwen Engine${NC}  ${DIM}(In-Pod Engine)${NC}"
  echo -e "    ${MUTED}↳ Endpoint   :${NC} ${BOLD}http://${OLLAMA_HOST}${NC}"
  echo -e "    ${MUTED}↳ Model      :${NC} ${PURPLE}${OLLAMA_MODEL}${NC}"
  echo -e "    ${MUTED}↳ Path       :${NC} ${CONTAINER_OLLAMA_DIR}"
  echo -e "    ${MUTED}↳ Log file   :${NC} ${OLLAMA_LOG_FILE}"
  echo ""
}

# ── Main Entrypoint ───────────────────────────────────────────

deploy_teellm
