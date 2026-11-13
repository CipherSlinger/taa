#!/usr/bin/env bash
#
# deploy-platform-mock.sh - build, run and inspect the platform mock.
#
# This is the single place that owns the platform-mock lifecycle. The deployment
# scripts (deploy.sh, deploy-fhe.sh) do not start the mock: they only point TAA at
# a platform, so the build flags, readiness probe and pid handling live here alone.
#
# Usage:
#   ./deploy-platform-mock.sh start|stop|restart|status [options]
#
# The mock runs on the remote host: the binary is built here, uploaded over SSH
# and started detached there. Without --taa-target the mock runs in multi-instance
# mode: each TAA instance derives its own target from its registration, using
# --taa-port (default 6001).
set -Eeuo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Defaults ────────────────────────────────────────────────────────────────
BINARY_PATH="${PLATFORM_MOCK_BINARY_PATH:-${MOCK_BINARY_PATH:-$PROJECT_DIR/bin/platform-mock}}"
BINARY_NAME="${PLATFORM_MOCK_BINARY_NAME:-platform-mock}"
# 18081, not 18080: on the shared hosts 18080 is where the real control plane
# listens (ccs-node-agent), and the mock exists to stand in for it, not to
# contend with it. `deploy.sh` still defaults to 18080 because that is the real
# platform; point it here with MOCK_PORT=18081 when debugging against the mock.
PORT="${MOCK_PORT:-18081}"
ADDR="${PLATFORM_ADDR:-}"
STATE_DIR="${PLATFORM_MOCK_STATE_DIR-__unset__}"
UPLOAD_DIR="${PLATFORM_MOCK_UPLOAD_DIR-__unset__}"
LOG_FILE="${PLATFORM_MOCK_LOG_FILE-__unset__}"
PID_FILE="${PLATFORM_MOCK_PID_FILE-__unset__}"
TAA_TARGET="${PLATFORM_MOCK_TAA_TARGET:-}"
TAA_POD=""
TAA_NS=""
TAA_PORT=""
LLM_TARGET="${PLATFORM_MOCK_LLM_TARGET:-}"
LLM_POD=""
LLM_NS=""
LLM_PORT=""
# Host port the TEE-LLM Pod publishes its plaintext platform listener on (`deploy-llm.sh`,
# TEELLM_POD_ATTESTATION_HOST_PORT). The mock polls the host address by default because it
# outlives the Pod: a Pod IP changes on every recreation, so a mock that discovered one would
# keep calling an address nothing answers until its next rediscovery. Pass --llm-pod to go back
# to kubectl discovery, or --llm-target to name any other base URL.
LLM_HOST_PORT="${PLATFORM_MOCK_LLM_HOST_PORT:-16001}"
SM2_ID="${PLATFORM_SM2_ID:-}"
PLATFORM_KEY_FILE="${PLATFORM_KEY_FILE:-}"
# TEE-LLM console account and secure listener. Empty means the binary's own
# defaults: admin / teellm@2026, and a TLS endpoint derived from the LLM target
# host on port 18443.
CONSOLE_USER="${CONSOLE_USER:-}"
CONSOLE_PASSWORD="${CONSOLE_PASSWORD:-}"
TEE_TLS_ENDPOINT="${TEELLM_TLS_ENDPOINT:-}"
READY_TIMEOUT="${PLATFORM_READY_TIMEOUT:-${READY_TIMEOUT:-60}}"
READY_INTERVAL="${PLATFORM_READY_INTERVAL:-${READY_INTERVAL:-2}}"

REMOTE_HOST="${REMOTE_HOST:-}"
REMOTE_USER="${REMOTE_USER:-root}"
REMOTE_DIR="${REMOTE_DIR:-/root/taa}"
REMOTE_BINARY=""
REMOTE_SSH_PORT=""
REMOTE_PASSWORD="${REMOTE_PASSWORD:-}"
# The environment spelling this replaced. Refused after parsing rather than ignored, so a stale
# invocation cannot silently authenticate with a different password than it passed.
TARGET_PASSWORD_ENV_WAS_SET="${TARGET_PASSWORD+set}"
SSH_EXTRA_OPTS=()

ALLOW_EMPTY_ATTESTATION=0
SKIP_BUILD=0
DRY_RUN="${DRY_RUN:-0}"
REUSE_IF_RUNNING=0
RESET_REGISTER=0

ACTION=""

# ── Logging ─────────────────────────────────────────────────────────────────
log()  { printf '[platform-mock] %s\n' "$*"; }
warn() { printf '[platform-mock] WARNING: %s\n' "$*" >&2; }
die()  { printf '[platform-mock] ERROR: %s\n' "$*" >&2; exit 1; }

is_dry_run() { [ "$DRY_RUN" = "1" ]; }

shell_quote() {
  local out="" arg q
  for arg in "$@"; do
    printf -v q '%q' "$arg"
    out+="$q "
  done
  printf '%s' "${out% }"
}

usage() {
  cat <<'EOF'
Usage: deploy-platform-mock.sh <start|stop|restart|status> [options]

Builds the platform mock from ./tools/platform-mock/cmd/platform-mock and manages
one instance on the remote host (the binary is uploaded over SSH). Local mode has
been removed.

Common options:
  --binary PATH              Local build output (default: bin/platform-mock)
  --binary-name NAME         Binary name used for pkill and the remote install
  --addr ADDR                Listen address (default: 0.0.0.0:<port>)
  --port N                   Listen/probe port (default: 18081)
  --state-dir DIR            Persisted state directory (empty = omit the flag)
  --upload-dir DIR           Uploaded-files directory (empty = omit the flag)
  --log-file PATH            Log file (default: <remote-dir>/platform-mock.log)
  --pid-file PATH            PID file (default: <remote-dir>/platform-mock.pid)
  --taa-target URL           Single-instance fixed TAA address; omit to derive
                             each instance's address from its registration
  --pod NAME                 TAA Pod for kubectl auto-discovery
  --namespace NS             Namespace for --pod (omit = search all namespaces)
  --taa-port PORT            Port used for discovery and for per-instance target derivation
  --llm-target URL           TEE-LLM base URL; the platform polls it, so no
                             registration address is needed
                             (default http://<--host>:<LLM_HOST_PORT>)
  --llm-pod NAME             TEE-LLM Pod for kubectl auto-discovery instead of
                             the host address (default taa-teellm)
  --llm-ns NS                Namespace for --llm-pod (omit = search all namespaces)
  --llm-port PORT            TEE-LLM plaintext platform port (default 6001);
                             giving any of --llm-pod/--llm-ns/--llm-port
                             switches the mock back to kubectl discovery
  --sm2-id ID                SM2 ID_A passed to the mock
  --platform-key-file PATH   Platform SM2 key file passed to the mock
  --console-user NAME        TEE-LLM console login (default admin)
  --console-password PASS    TEE-LLM console password (default teellm@2026)
  --tee-tls-endpoint H:P     TEE-LLM TEE-TLS listener used by the console
                             (default <llm-target host>:18443)
  --allow-empty-attestation  Skip attestation validation (non-TEE testing)
  --reuse                    On start, reuse an instance already answering
  --reset-register           POST /api/register/reset once the instance is ready
  --skip-build               Use the binary already at --binary
  --ready-timeout SECONDS    Readiness timeout (default: 60)
  --ready-interval SECONDS   Readiness poll interval (default: 2)
  --dry-run                  Print what would run, execute nothing
  -h, --help                 Show this help

SSH options:
  --host HOST                SSH host (also REMOTE_HOST)
  --user USER                SSH user (default: root)
  --remote-password PASSWORD SSH password via sshpass (also REMOTE_PASSWORD)
  --remote-dir DIR           Remote working directory (default: /root/taa)
  --remote-binary PATH       Remote binary path (default: <remote-dir>/<binary-name>)
  --ssh-port N               SSH port
  --ssh-opt OPTION           Extra ssh option, repeatable

Defaults: no --state-dir/--upload-dir (the binary's own defaults apply),
log <remote-dir>/platform-mock.log, pid <remote-dir>/platform-mock.pid.
EOF
}

need_value() {
  [ $# -ge 2 ] || die "$1 requires a value"
}

parse_args() {
  [ $# -ge 1 ] || { usage >&2; exit 2; }
  case "$1" in
    -h|--help) usage; exit 0 ;;
    local|local-docker)
      die "local mode has been removed; the mock runs on the remote host (use --host/REMOTE_HOST)"
      ;;
  esac
  ACTION="$1"
  shift
  case "$ACTION" in
    start|stop|restart|status) ;;
    *) die "unknown action '$ACTION' (expected start, stop, restart or status)" ;;
  esac

  while [ $# -gt 0 ]; do
    case "$1" in
      --binary) need_value "$@"; BINARY_PATH="$2"; shift 2 ;;
      --binary-name) need_value "$@"; BINARY_NAME="$2"; shift 2 ;;
      --addr) need_value "$@"; ADDR="$2"; shift 2 ;;
      --port) need_value "$@"; PORT="$2"; shift 2 ;;
      --state-dir) need_value "$@"; STATE_DIR="$2"; shift 2 ;;
      --upload-dir) need_value "$@"; UPLOAD_DIR="$2"; shift 2 ;;
      --log-file) need_value "$@"; LOG_FILE="$2"; shift 2 ;;
      --pid-file) need_value "$@"; PID_FILE="$2"; shift 2 ;;
      --taa-target) need_value "$@"; TAA_TARGET="$2"; shift 2 ;;
      --pod) need_value "$@"; TAA_POD="$2"; shift 2 ;;
      --llm-target) need_value "$@"; LLM_TARGET="$2"; shift 2 ;;
      --llm-pod) need_value "$@"; LLM_POD="$2"; shift 2 ;;
      --llm-ns) need_value "$@"; LLM_NS="$2"; shift 2 ;;
      --llm-port) need_value "$@"; LLM_PORT="$2"; shift 2 ;;
      --namespace) need_value "$@"; TAA_NS="$2"; shift 2 ;;
      --taa-port) need_value "$@"; TAA_PORT="$2"; shift 2 ;;
      --sm2-id) need_value "$@"; SM2_ID="$2"; shift 2 ;;
      --platform-key-file) need_value "$@"; PLATFORM_KEY_FILE="$2"; shift 2 ;;
      --console-user) need_value "$@"; CONSOLE_USER="$2"; shift 2 ;;
      --console-password) need_value "$@"; CONSOLE_PASSWORD="$2"; shift 2 ;;
      --tee-tls-endpoint) need_value "$@"; TEE_TLS_ENDPOINT="$2"; shift 2 ;;
      --allow-empty-attestation) ALLOW_EMPTY_ATTESTATION=1; shift ;;
      --reuse) REUSE_IF_RUNNING=1; shift ;;
      --reset-register) RESET_REGISTER=1; shift ;;
      --skip-build) SKIP_BUILD=1; shift ;;
      --ready-timeout) need_value "$@"; READY_TIMEOUT="$2"; shift 2 ;;
      --ready-interval) need_value "$@"; READY_INTERVAL="$2"; shift 2 ;;
      --dry-run) DRY_RUN=1; shift ;;
      --host) need_value "$@"; REMOTE_HOST="$2"; shift 2 ;;
      --user) need_value "$@"; REMOTE_USER="$2"; shift 2 ;;
      --remote-password) need_value "$@"; REMOTE_PASSWORD="$2"; shift 2 ;;
      --remote-dir) need_value "$@"; REMOTE_DIR="$2"; shift 2 ;;
      --remote-binary) need_value "$@"; REMOTE_BINARY="$2"; shift 2 ;;
      --ssh-port) need_value "$@"; REMOTE_SSH_PORT="$2"; shift 2 ;;
      --ssh-opt) need_value "$@"; SSH_EXTRA_OPTS+=("$2"); shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown option '$1' (see --help)" ;;
    esac
  done
}

resolve_defaults() {
  if [ -n "$TARGET_PASSWORD_ENV_WAS_SET" ]; then
    die "TARGET_PASSWORD is no longer supported; pass --remote-password <password> instead"
  fi
  [ -n "$ADDR" ] || ADDR="0.0.0.0:${PORT}"
  PROBE_PORT="${ADDR##*:}"
  case "$PROBE_PORT" in
    ''|*[!0-9]*) PROBE_PORT="$PORT" ;;
  esac
  PROBE_BASE="http://127.0.0.1:${PROBE_PORT}"
  PROBE_URL="${PROBE_BASE}/api/register/status"

  [ "$STATE_DIR" = "__unset__" ] && STATE_DIR=""
  [ "$UPLOAD_DIR" = "__unset__" ] && UPLOAD_DIR=""
  [ "$LOG_FILE" = "__unset__" ] && LOG_FILE="$REMOTE_DIR/platform-mock.log"
  [ "$PID_FILE" = "__unset__" ] && PID_FILE="$REMOTE_DIR/platform-mock.pid"
  [ -n "$REMOTE_HOST" ] || die "--host or REMOTE_HOST is required"
  [ -n "$REMOTE_BINARY" ] || REMOTE_BINARY="$REMOTE_DIR/$BINARY_NAME"
  return 0
}

# ── SSH ─────────────────────────────────────────────────────────────────────
setup_ssh() {
  local -a common=(-q -o LogLevel=ERROR -o StrictHostKeyChecking=accept-new \
    -o "UserKnownHostsFile=$HOME/.ssh/known_hosts")
  [ -n "$REMOTE_SSH_PORT" ] && common+=(-p "$REMOTE_SSH_PORT")
  local -a extra=()
  local opt
  for opt in "${SSH_EXTRA_OPTS[@]}"; do
    extra+=(-o "$opt")
  done
  local -a prefix=()
  if [ -n "$REMOTE_PASSWORD" ]; then
    command -v sshpass >/dev/null 2>&1 \
      || die "sshpass is required when --remote-password is set; install it or use key authentication"
    prefix=(sshpass -p "$REMOTE_PASSWORD")
  fi
  SSH_CMD=("${prefix[@]}" ssh "${common[@]}" "${extra[@]}")
  SCP_CMD=("${prefix[@]}" scp -q "${common[@]}" "${extra[@]}")
  REMOTE_TARGET="${REMOTE_USER}@${REMOTE_HOST}"
}

remote_sh() {
  local script="$1"
  "${SSH_CMD[@]}" "$REMOTE_TARGET" "$script"
}

# ── Probe helpers ───────────────────────────────────────────────────────────
http_ready_remote() {
  remote_sh "curl -fsS -o /dev/null $(shell_quote "$PROBE_URL") 2>/dev/null || wget -q -O /dev/null $(shell_quote "$PROBE_URL") 2>/dev/null"
}

http_ready() {
  http_ready_remote
}

wait_ready() {
  if is_dry_run; then return 0; fi
  local elapsed=0
  while [ "$elapsed" -lt "$READY_TIMEOUT" ]; do
    if http_ready; then return 0; fi
    sleep "$READY_INTERVAL"
    elapsed=$((elapsed + READY_INTERVAL))
  done
  return 1
}

reset_register() {
  [ "$RESET_REGISTER" = "1" ] || return 0
  local url="${PROBE_BASE}/api/register/reset"
  if is_dry_run; then
    log "would POST $url"
    return 0
  fi
  remote_sh "curl -fsS -o /dev/null -X POST $(shell_quote "$url")" \
    || die "could not clear the register state on $url"
  log "register state cleared on $PROBE_BASE"
}

# ── Build ───────────────────────────────────────────────────────────────────
build_binary() {
  if [ "$SKIP_BUILD" = "1" ]; then
    if is_dry_run; then
      log "would use the existing binary at $BINARY_PATH"
      return 0
    fi
    [ -f "$BINARY_PATH" ] || die "--skip-build was given but $BINARY_PATH does not exist"
    return 0
  fi

  if is_dry_run; then
    log "would build $BINARY_PATH (CGO_ENABLED=0 GOOS=linux go build -o $BINARY_PATH ./tools/platform-mock/cmd/platform-mock)"
    return 0
  fi

  command -v go >/dev/null 2>&1 || die "the go compiler is required to build platform-mock"
  mkdir -p "$(dirname "$BINARY_PATH")"
  log "building $BINARY_PATH for linux (CGO disabled)"
  ( cd "$PROJECT_DIR" && CGO_ENABLED=0 GOOS=linux go build -o "$BINARY_PATH" ./tools/platform-mock/cmd/platform-mock )
  [ -f "$BINARY_PATH" ] || die "go build reported success but $BINARY_PATH is not there"
}

# ── Mock arguments ──────────────────────────────────────────────────────────
build_mock_args() {
  MOCK_ARGS=(-addr "$ADDR")
  [ -n "$STATE_DIR" ] && MOCK_ARGS+=(-state-dir "$STATE_DIR")
  [ -n "$UPLOAD_DIR" ] && MOCK_ARGS+=(-upload-dir "$UPLOAD_DIR")
  if [ -n "$TAA_TARGET" ]; then
    MOCK_ARGS+=(-taa-target "$TAA_TARGET")
  else
    [ -n "$TAA_POD" ] && MOCK_ARGS+=(-taa-pod "$TAA_POD")
    [ -n "$TAA_NS" ] && MOCK_ARGS+=(-taa-ns "$TAA_NS")
    [ -n "$TAA_PORT" ] && MOCK_ARGS+=(-taa-port "$TAA_PORT")
  fi
  LLM_TARGET_EFFECTIVE=""
  if [ -n "$LLM_TARGET" ]; then
    LLM_TARGET_EFFECTIVE="$LLM_TARGET"
    MOCK_ARGS+=(-llm-target "$LLM_TARGET")
  elif [ -n "$LLM_POD$LLM_NS$LLM_PORT" ]; then
    # Any discovery flag opts back into kubectl. LLM_PORT is included so that
    # `--llm-port` alone keeps meaning "the default Pod, another port" rather
    # than being silently ignored in favour of the host address.
    [ -n "$LLM_POD" ] && MOCK_ARGS+=(-llm-pod "$LLM_POD")
    [ -n "$LLM_NS" ] && MOCK_ARGS+=(-llm-ns "$LLM_NS")
    [ -n "$LLM_PORT" ] && MOCK_ARGS+=(-llm-port "$LLM_PORT")
  else
    # The host address, not the Pod IP: deploy-llm.sh publishes the listener on
    # the node precisely so it has an address that survives recreating the Pod.
    LLM_TARGET_EFFECTIVE="http://${REMOTE_HOST}:${LLM_HOST_PORT}"
    MOCK_ARGS+=(-llm-target "$LLM_TARGET_EFFECTIVE")
  fi
  [ "$ALLOW_EMPTY_ATTESTATION" = "1" ] && MOCK_ARGS+=(-allow-empty-attestation)
  [ -n "$SM2_ID" ] && MOCK_ARGS+=(-sm2-id "$SM2_ID")
  [ -n "$PLATFORM_KEY_FILE" ] && MOCK_ARGS+=(-platform-key-file "$PLATFORM_KEY_FILE")

  # The console reads these from the environment, and passing them this way
  # keeps the password out of the process arguments on the remote host.
  REMOTE_ENV_PREFIX=""
  [ -n "$CONSOLE_USER" ] && REMOTE_ENV_PREFIX+="CONSOLE_USER=$(shell_quote "$CONSOLE_USER") "
  [ -n "$CONSOLE_PASSWORD" ] && REMOTE_ENV_PREFIX+="CONSOLE_PASSWORD=$(shell_quote "$CONSOLE_PASSWORD") "
  [ -n "$TEE_TLS_ENDPOINT" ] && REMOTE_ENV_PREFIX+="TEELLM_TLS_ENDPOINT=$(shell_quote "$TEE_TLS_ENDPOINT") "
  return 0
}

# ── Remote lifecycle ────────────────────────────────────────────────────────
stop_remote() {
  if is_dry_run; then
    log "would stop $BINARY_NAME on $REMOTE_TARGET (pid file $PID_FILE)"
    return 0
  fi
  remote_sh "if [ -f $(shell_quote "$PID_FILE") ]; then p=\$(cat $(shell_quote "$PID_FILE") 2>/dev/null || true); if [ -n \"\$p\" ]; then kill \"\$p\" 2>/dev/null || true; sleep 1; kill -9 \"\$p\" 2>/dev/null || true; fi; rm -f $(shell_quote "$PID_FILE"); fi; pkill -x $(shell_quote "$BINARY_NAME") >/dev/null 2>&1 || true"
}

upload_remote() {
  if is_dry_run; then
    log "would upload $BINARY_PATH to $REMOTE_TARGET:$REMOTE_BINARY"
    return 0
  fi
  [ -f "$BINARY_PATH" ] || die "cannot upload $BINARY_PATH: no such file"
  local tmp="${REMOTE_BINARY}.new"
  remote_sh "mkdir -p $(shell_quote "$(dirname "$REMOTE_BINARY")") $(shell_quote "$(dirname "$LOG_FILE")")" \
    || die "could not create the remote directories for $REMOTE_BINARY"
  "${SCP_CMD[@]}" "$BINARY_PATH" "$REMOTE_TARGET:$tmp" \
    || die "failed to copy $BINARY_PATH to $REMOTE_TARGET:$tmp"
  remote_sh "chmod 755 $(shell_quote "$tmp") && mv -f $(shell_quote "$tmp") $(shell_quote "$REMOTE_BINARY")" \
    || die "failed to place $REMOTE_BINARY on $REMOTE_TARGET"
  log "uploaded $BINARY_PATH -> $REMOTE_TARGET:$REMOTE_BINARY"
}

start_remote() {
  build_mock_args
  if [ -n "$LLM_TARGET_EFFECTIVE" ]; then
    log "TEE-LLM target: $LLM_TARGET_EFFECTIVE (host address; pass --llm-pod for kubectl discovery)"
  else
    log "TEE-LLM target: kubectl discovery from the Pod name (--llm-pod/--llm-ns/--llm-port)"
  fi
  log "console: user ${CONSOLE_USER:-admin}; TEE-TLS endpoint ${TEE_TLS_ENDPOINT:-(derived from the LLM target host on port 18443)}"
  if is_dry_run; then
    log "would start ${REMOTE_ENV_PREFIX}$REMOTE_BINARY on $REMOTE_TARGET with ${MOCK_ARGS[*]} (log $LOG_FILE)"
    return 0
  fi
  remote_sh "mkdir -p $(shell_quote "$REMOTE_DIR")" || die "could not create $REMOTE_DIR on $REMOTE_TARGET"
  stop_remote
  upload_remote
  log "starting platform-mock on $REMOTE_TARGET ($ADDR)"
  remote_sh "nohup ${REMOTE_ENV_PREFIX}$(shell_quote "$REMOTE_BINARY") $(shell_quote "${MOCK_ARGS[@]}") > $(shell_quote "$LOG_FILE") 2>&1 < /dev/null & echo \$! > $(shell_quote "$PID_FILE")" \
    || die "failed to start $REMOTE_BINARY on $REMOTE_TARGET"
  if ! wait_ready; then
    remote_sh "tail -n 40 $(shell_quote "$LOG_FILE")" >&2 || true
    die "platform-mock did not answer $PROBE_URL on $REMOTE_TARGET within ${READY_TIMEOUT}s (log $LOG_FILE)"
  fi
  log "platform-mock is answering on $REMOTE_TARGET ($PROBE_BASE, pid $PID_FILE)"
}

status_remote() {
  local running=0
  if remote_sh "if [ -f $(shell_quote "$PID_FILE") ]; then p=\$(cat $(shell_quote "$PID_FILE") 2>/dev/null || true); [ -n \"\$p\" ] && kill -0 \"\$p\" 2>/dev/null && echo \"pid \$p\"; fi; pgrep -x $(shell_quote "$BINARY_NAME") >/dev/null 2>&1" 2>/dev/null; then
    log "running on $REMOTE_TARGET (pid file $PID_FILE, log $LOG_FILE)"
    running=1
  else
    log "not running on $REMOTE_TARGET (pid file $PID_FILE)"
  fi
  if http_ready_remote; then
    log "status endpoint ready on $REMOTE_TARGET: $PROBE_BASE"
    return 0
  fi
  log "status endpoint not answering on $REMOTE_TARGET: $PROBE_BASE"
  [ "$running" = "1" ] && return 0
  return 1
}

# ── Dispatch ────────────────────────────────────────────────────────────────
main() {
  if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
  fi
  parse_args "$@"
  resolve_defaults
  setup_ssh

  case "$ACTION" in
    start)
      if [ "$REUSE_IF_RUNNING" = "1" ] && ! is_dry_run && http_ready; then
        warn "something already answers on $PROBE_BASE; reusing it instead of starting a second platform-mock. This run cannot confirm how it was started (for example whether -allow-empty-attestation was set), and --reset-register affects whatever else is using it."
        reset_register
        return 0
      fi
      build_binary
      start_remote
      reset_register
      ;;
    stop)
      stop_remote
      log "platform-mock stopped"
      ;;
    restart)
      stop_remote
      build_binary
      start_remote
      reset_register
      ;;
    status)
      status_remote
      ;;
  esac
}

main "$@"
