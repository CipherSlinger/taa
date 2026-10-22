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
  if [[ -n "${TEMP_POD_MANIFEST:-}" && -f "$TEMP_POD_MANIFEST" ]]; then
    rm -f "$TEMP_POD_MANIFEST" 2>/dev/null || true
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
# container has no such device, so teellm-service falls back to a mock evidence provider whose HRK
# changes on every start, and TAA rejects the handshake with "untrusted HRK certificate". A
# kata-qemu-csv2 Pod has the device, because its guest init creates it -- which is the whole
# reason this Pod exists, and why --create-pod deploys into it rather than into the TAA Pod that
# TARGET_POD defaults to (that Pod has the device too, but it is not where teellm-service should
# run, and aiming the deployment at it would make every later gate pass while the service never
# reaches the Pod the endpoint points at).
TEELLM_POD_NAME="${TEELLM_POD_NAME:-taa-teellm}"
# The image built by build-teellm-image.sh carries the service, the supervisor, the certificates
# and the ollama runtime, so a fresh guest serves without any host-side copy.
TEELLM_IMAGE_DATE="${TEELLM_IMAGE_DATE:-$(date +%Y%m%d)}"
TEELLM_POD_IMAGE="${TEELLM_POD_IMAGE:-172.16.10.178:31313/teellm:teellm-$TEELLM_IMAGE_DATE}"
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
# 600s rather than the 180s a plain Pod needs: a fresh CSV2 Pod boots its guest first and pulls
# this image inside it, through the in-guest CDH.
TEELLM_POD_READY_TIMEOUT="${TEELLM_POD_READY_TIMEOUT:-600}"
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

# ── Dedicated TEE-LLM Pod lifecycle ───────────────────────────

# Reads the cc_init_data annotation off a CoCo Pod that already runs on the remote host. The
# guest's CDH needs it to trust the local registry's self-signed certificate when it pulls the
# image -- the host's own trust does not carry into the guest -- and a Pod without it stops in
# StartError. Only that one annotation is ever copied: the runtime-handler key would hijack the
# runtime, and an empty hypervisor kernel_params value would erase the rdinit= that boots TAA's
# guest. Prints the bare value; the caller substitutes it into the manifest.
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
        -e "s|__RUNTIME_CLASS__|$TEELLM_POD_RUNTIME_CLASS|g" \
        -e "s|__CPU__|$TEELLM_POD_CPU|g" \
        -e "s|__MEMORY__|$TEELLM_POD_MEMORY|g" \
        -e "s|__MODEL__|$OLLAMA_MODEL|g" \
        -e "s|__CC_INIT_DATA__|$cc_init_data|g" \
        "$TEELLM_POD_TEMPLATE" > "$TEMP_POD_MANIFEST"
    step "creating the TEE-LLM Pod (runtimeClassName: $TEELLM_POD_RUNTIME_CLASS, node: $TEELLM_POD_NODE)"
    remote_ssh "kubectl $K_NS apply -f -" < "$TEMP_POD_MANIFEST"
    rm -f "$TEMP_POD_MANIFEST"
    TEMP_POD_MANIFEST=""
    # Long, because the guest boots before it can pull the image. Dumping the events first keeps a
    # timeout diagnosable, which a bare "timed out" is not.
    if ! remote_ssh "kubectl $K_NS wait --for=condition=Ready --timeout=${TEELLM_POD_READY_TIMEOUT}s pod/'$TARGET_POD'"; then
      err "TEE-LLM Pod '$TARGET_POD' did not become Ready within ${TEELLM_POD_READY_TIMEOUT}s"
      remote_ssh "kubectl $K_NS describe pod '$TARGET_POD' | tail -n 40" || true
      detail "The Pod is left in place for inspection: kubectl $K_NS describe pod '$TARGET_POD'"
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
    detail "teellm-service would fall back to mock evidence and TAA would reject every handshake"
    detail "with 'untrusted HRK certificate'. Expected runtimeClassName $TEELLM_POD_RUNTIME_CLASS."
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
    return 0
  fi
  remote_ssh "kubectl $K_NS delete pod '$TARGET_POD' --ignore-not-found --wait=true --timeout=90s" || true
  # A VM-backed Pod whose guest is wedged will not answer a graceful delete; fall back to force so
  # a broken Pod cannot block the teardown. Its memory is host-resident, so leaving it costs GiB.
  if remote_ssh "kubectl $K_NS get pod '$TARGET_POD' >/dev/null 2>&1"; then
    warn "Pod '$TARGET_POD' did not exit within 90s; forcing deletion"
    remote_ssh "kubectl $K_NS delete pod '$TARGET_POD' --force --grace-period=0" || true
  fi
  if remote_ssh "kubectl $K_NS get pod '$TARGET_POD' >/dev/null 2>&1"; then
    err "Pod '$TARGET_POD' is still present after a forced delete"
    exit 1
  fi
  info "TEE-LLM Pod '$TARGET_POD' deleted"
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
  pod-down     Delete the dedicated TEE-LLM Pod (see --create-pod).

Options:
  --model <name> (or --model=<name>)
      Specify target LLM model name (default: qwen2.5-coder:3b).
  --ollama-dir <path> (or --ollama-dir=<path>)
      Specify local directory containing offline Ollama package and models.
  --create-pod
      Deploy into a dedicated Kata CSV2 Pod named by TEELLM_POD_NAME, creating it if it is absent,
      instead of into TARGET_POD. The Pod exists to give teellm-service a real /dev/csv-guest:
      without that device it serves mock evidence, and TAA rejects every handshake with
      "untrusted HRK certificate". An existing Pod is reused and never re-created -- a second Pod
      would be a second confidential VM.
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
      Image for the dedicated TEE-LLM Pod; it must carry ollama, tar/curl and python3.
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
  TEELLM_POD_READY_TIMEOUT=${TEELLM_POD_READY_TIMEOUT}
      Seconds to wait for a freshly created TEE-LLM Pod to become Ready. Long by default: the
      guest boots before it can pull the image, through its own CDH.
  TEELLM_POD_CC_INIT_DATA=<base64>
      cc_init_data annotation for the new Pod. Left empty it is read from a CoCo Pod that already
      runs on the remote host; without it the guest cannot pull the image. Exactly this one
      annotation is ever copied -- the runtime-handler key would hijack the runtime, and an empty
      hypervisor kernel_params value would erase the rdinit= that boots the guest.
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

# A TEE-LLM image can carry the ollama runtime and the model (build-teellm-image.sh), which is what
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

  # Deploy certificates and binary to remote host then into pod
  step "preparing and uploading configuration and binary"
  local cfg_template="${TEELLM_CONFIG_PATH:-$TEELLM_DIR/configs/teellm-production.json}"
  local tmp_cfg
  tmp_cfg="$(mktemp /tmp/teellm_cfg.XXXXXX)"
  TEMP_CONFIG_FILE="$tmp_cfg"
  prepare_config "$cfg_template" "$tmp_cfg" "$OLLAMA_MODEL" "$TEELLM_PORT" "$CON_WORKDIR/certs/hrk.cert" "$CON_WORKDIR/certs/hsk_cek.cert"

  remote_ssh "mkdir -p '$REMOTE_DIR/configs' '$REMOTE_DIR/certs'"
  sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$TEELLM_DIR/bin/teellm-service" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/teellm-service.new"
  sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$TEELLM_SUPERVISOR_SCRIPT" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/teellm-supervisor.sh"
  sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$tmp_cfg" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/configs/teellm-production.json"
  if [[ -f "$TEELLM_DIR/configs/models.json" ]]; then
    sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$TEELLM_DIR/configs/models.json" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/configs/models.json"
  fi
  rm -f "$tmp_cfg"
  TEMP_CONFIG_FILE=""

  if [[ -n "$LOCAL_HRK_CERT" && -n "$LOCAL_HSK_CERT" ]]; then
    sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$LOCAL_HRK_CERT" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/certs/hrk.cert"
    sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$LOCAL_HSK_CERT" "${REMOTE_USER}@${REMOTE_HOST}:$REMOTE_DIR/certs/hsk_cek.cert"
  elif [[ "$CREATE_POD" == true ]]; then
    # Fatal on this path only. The certificates are what binds the report's SM3 public key to the
    # trust anchor, so serving without them fails every handshake -- and a deployment that reports
    # success while doing that is worse than one that refuses to run.
    err "no Hygon attestation certificates found, and the TEE-LLM Pod cannot serve without them"
    detail "Expected $PROJECT_DIR/deploy/certs/hrk.cert and hsk_cek.cert (ATT_HRK_SOURCE / ATT_HSK_SOURCE override the location)."
    exit 1
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
  # just as well against a mock report. Which provider the server picked is only in its log, and a
  # mock provider is exactly the failure that reaches production as "untrusted HRK certificate".
  if [[ "$CREATE_POD" == true ]]; then
    step "confirming the service serves hardware evidence, not mock evidence"
    local provider_log
    provider_log="$(remote_ssh "$(container_exec) tail -n 200 '$TEELLM_LOG_FILE'" || true)"
    if ! grep -q "using Hygon hardware evidence provider" <<<"$provider_log"; then
      err "teellm-service in '$TARGET_POD' did not report the Hygon hardware evidence provider"
      remote_ssh "$(container_exec) tail -n 30 '$TEELLM_LOG_FILE'" || true
      detail "TAA will reject a mock report with 'untrusted HRK certificate', so this deployment"
      detail "would fail code audit. Check that the Pod still has /dev/csv-guest."
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
