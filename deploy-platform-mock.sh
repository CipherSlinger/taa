#!/usr/bin/env bash
#
# deploy-platform-mock.sh - build, run and inspect the platform mock.
#
# This is the single place that owns the platform-mock lifecycle. deploy.sh and
# deploy-fhe.sh call it instead of carrying their own copies, so the build flags,
# readiness probe and pid handling cannot drift between the two entry points.
#
# Usage:
#   ./deploy-platform-mock.sh local  start|stop|restart|status [options]
#   ./deploy-platform-mock.sh remote start|stop|restart|status [options]
#
# Local mode runs the binary on this host. Remote mode uploads it over SSH and
# starts it detached there. TAA-specific coupling stays in the caller: deploy.sh
# still discovers the TAA Pod IP and passes it as --taa-target.
set -Eeuo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Defaults ────────────────────────────────────────────────────────────────
BINARY_PATH="${PLATFORM_MOCK_BINARY_PATH:-${MOCK_BINARY_PATH:-$PROJECT_DIR/bin/platform-mock}}"
BINARY_NAME="${PLATFORM_MOCK_BINARY_NAME:-platform-mock}"
PORT="${PLATFORM_PORT:-${LOCAL_PLATFORM_PORT:-18080}}"
ADDR="${PLATFORM_ADDR:-${LOCAL_PLATFORM_BIND:-}}"
STATE_DIR="${PLATFORM_MOCK_STATE_DIR-__unset__}"
UPLOAD_DIR="${PLATFORM_MOCK_UPLOAD_DIR-__unset__}"
LOG_FILE="${PLATFORM_MOCK_LOG_FILE-__unset__}"
PID_FILE="${PLATFORM_MOCK_PID_FILE-__unset__}"
TAA_TARGET="${PLATFORM_MOCK_TAA_TARGET:-${LOCAL_TAA_URL:-}}"
TAA_POD=""
TAA_NS=""
TAA_PORT=""
SM2_ID="${PLATFORM_SM2_ID:-}"
PLATFORM_KEY_FILE="${PLATFORM_KEY_FILE:-}"
READY_TIMEOUT="${PLATFORM_READY_TIMEOUT:-${READY_TIMEOUT:-60}}"
READY_INTERVAL="${PLATFORM_READY_INTERVAL:-${READY_INTERVAL:-2}}"

REMOTE_HOST="${REMOTE_HOST:-}"
REMOTE_USER="${REMOTE_USER:-root}"
REMOTE_DIR="${REMOTE_DIR:-/root/taa}"
REMOTE_BINARY=""
REMOTE_SSH_PORT=""
PASSWORD="${TARGET_PASSWORD:-${PASSWORD:-}}"
SSH_EXTRA_OPTS=()

ALLOW_EMPTY_ATTESTATION=0
SKIP_BUILD=0
STATIC_BUILD=0
DRY_RUN="${DRY_RUN:-0}"
REUSE_IF_RUNNING=0
RESET_REGISTER=0

TARGET=""
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
Usage: deploy-platform-mock.sh <local|remote> <start|stop|restart|status> [options]

Builds the platform mock from ./tools/platform-mock/cmd/platform-mock and manages
one instance. Local mode runs it on this host; remote mode uploads it over SSH.

Common options:
  --binary PATH              Local build output (default: bin/platform-mock)
  --binary-name NAME         Binary name used for pkill and the remote install
  --addr ADDR                Listen address (default: 0.0.0.0:<port>)
  --port N                   Listen/probe port (default: 18080)
  --state-dir DIR            Persisted state directory (empty = omit the flag)
  --upload-dir DIR           Uploaded-files directory (empty = omit the flag)
  --log-file PATH            Log file (local default: .local/logs/platform-mock.log)
  --pid-file PATH            PID file (local default: .local/run/platform-mock.pid)
  --taa-target URL           Single-instance fixed TAA address; omit to derive
                             each instance's address from its registration
  --taa-pod NAME             TAA Pod for kubectl auto-discovery
  --taa-ns NS                Namespace for --taa-pod
  --taa-port PORT            Port used for discovery and for per-instance target derivation
  --sm2-id ID                SM2 ID_A passed to the mock
  --platform-key-file PATH   Platform SM2 key file passed to the mock
  --allow-empty-attestation  Skip attestation validation (non-TEE testing)
  --reuse                    On start, reuse an instance already answering
  --reset-register           POST /api/register/reset once the instance is ready
  --skip-build               Use the binary already at --binary
  --static                   Force CGO_ENABLED=0 GOOS=linux (remote mode does this anyway)
  --ready-timeout SECONDS    Readiness timeout (default: 60)
  --ready-interval SECONDS   Readiness poll interval (default: 2)
  --dry-run                  Print what would run, execute nothing
  -h, --help                 Show this help

Remote options:
  --host HOST                SSH host (also REMOTE_HOST)
  --user USER                SSH user (default: root)
  --password PASSWORD        SSH password via sshpass (also TARGET_PASSWORD)
  --remote-dir DIR           Remote working directory (default: /root/taa)
  --remote-binary PATH       Remote binary path (default: <remote-dir>/<binary-name>)
  --ssh-port N               SSH port
  --ssh-opt OPTION           Extra ssh option, repeatable

Local defaults: state .local/platform-mock, uploads .local/upload.
Remote defaults: no --state-dir/--upload-dir (the binary's own defaults apply),
log <remote-dir>/platform-mock.log, pid <remote-dir>/platform-mock.pid.
EOF
}

need_value() {
  [ $# -ge 2 ] || die "$1 requires a value"
}

parse_args() {
  [ $# -ge 2 ] || { usage >&2; exit 2; }
  TARGET="$1"
  ACTION="$2"
  shift 2
  case "$TARGET" in
    local|remote) ;;
    *) die "unknown target '$TARGET' (expected local or remote)" ;;
  esac
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
      --taa-pod) need_value "$@"; TAA_POD="$2"; shift 2 ;;
      --taa-ns) need_value "$@"; TAA_NS="$2"; shift 2 ;;
      --taa-port) need_value "$@"; TAA_PORT="$2"; shift 2 ;;
      --sm2-id) need_value "$@"; SM2_ID="$2"; shift 2 ;;
      --platform-key-file) need_value "$@"; PLATFORM_KEY_FILE="$2"; shift 2 ;;
      --allow-empty-attestation) ALLOW_EMPTY_ATTESTATION=1; shift ;;
      --reuse) REUSE_IF_RUNNING=1; shift ;;
      --reset-register) RESET_REGISTER=1; shift ;;
      --skip-build) SKIP_BUILD=1; shift ;;
      --static) STATIC_BUILD=1; shift ;;
      --ready-timeout) need_value "$@"; READY_TIMEOUT="$2"; shift 2 ;;
      --ready-interval) need_value "$@"; READY_INTERVAL="$2"; shift 2 ;;
      --dry-run) DRY_RUN=1; shift ;;
      --host) need_value "$@"; REMOTE_HOST="$2"; shift 2 ;;
      --user) need_value "$@"; REMOTE_USER="$2"; shift 2 ;;
      --password) need_value "$@"; PASSWORD="$2"; shift 2 ;;
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
  [ -n "$ADDR" ] || ADDR="0.0.0.0:${PORT}"
  PROBE_PORT="${ADDR##*:}"
  case "$PROBE_PORT" in
    ''|*[!0-9]*) PROBE_PORT="$PORT" ;;
  esac
  PROBE_BASE="http://127.0.0.1:${PROBE_PORT}"
  PROBE_URL="${PROBE_BASE}/api/register/status"

  if [ "$TARGET" = "local" ]; then
    [ "$STATE_DIR" = "__unset__" ] && STATE_DIR="$PROJECT_DIR/.local/platform-mock"
    [ "$UPLOAD_DIR" = "__unset__" ] && UPLOAD_DIR="$PROJECT_DIR/.local/upload"
    [ "$LOG_FILE" = "__unset__" ] && LOG_FILE="$PROJECT_DIR/.local/logs/platform-mock.log"
    [ "$PID_FILE" = "__unset__" ] && PID_FILE="$PROJECT_DIR/.local/run/platform-mock.pid"
  else
    [ "$STATE_DIR" = "__unset__" ] && STATE_DIR=""
    [ "$UPLOAD_DIR" = "__unset__" ] && UPLOAD_DIR=""
    [ "$LOG_FILE" = "__unset__" ] && LOG_FILE="$REMOTE_DIR/platform-mock.log"
    [ "$PID_FILE" = "__unset__" ] && PID_FILE="$REMOTE_DIR/platform-mock.pid"
    [ -n "$REMOTE_HOST" ] || die "remote mode requires --host or REMOTE_HOST"
    [ -n "$REMOTE_BINARY" ] || REMOTE_BINARY="$REMOTE_DIR/$BINARY_NAME"
  fi
  return 0
}

# ── SSH ─────────────────────────────────────────────────────────────────────
setup_ssh() {
  [ "$TARGET" = "remote" ] || return 0
  local -a common=(-q -o LogLevel=ERROR -o StrictHostKeyChecking=accept-new \
    -o "UserKnownHostsFile=$HOME/.ssh/known_hosts")
  [ -n "$REMOTE_SSH_PORT" ] && common+=(-p "$REMOTE_SSH_PORT")
  local -a extra=()
  local opt
  for opt in "${SSH_EXTRA_OPTS[@]}"; do
    extra+=(-o "$opt")
  done
  local -a prefix=()
  if [ -n "$PASSWORD" ]; then
    command -v sshpass >/dev/null 2>&1 \
      || die "sshpass is required when --password is set; install it or use key authentication"
    prefix=(sshpass -p "$PASSWORD")
  fi
  SSH_CMD=("${prefix[@]}" ssh "${common[@]}" "${extra[@]}")
  SCP_CMD=("${prefix[@]}" scp -q "${common[@]}" "${extra[@]}")
  REMOTE_TARGET="${REMOTE_USER}@${REMOTE_HOST}"
}

remote_sh() {
  local script="$1"
  "${SSH_CMD[@]}" "$REMOTE_TARGET" "$script"
}

remote_capture() {
  local script="$1"
  "${SSH_CMD[@]}" "$REMOTE_TARGET" "$script"
}

# ── Probe helpers ───────────────────────────────────────────────────────────
http_ready_local() {
  curl -fsS -o /dev/null "$PROBE_URL" 2>/dev/null \
    || wget -q -O /dev/null "$PROBE_URL" 2>/dev/null
}

http_ready_remote() {
  remote_sh "curl -fsS -o /dev/null $(shell_quote "$PROBE_URL") 2>/dev/null || wget -q -O /dev/null $(shell_quote "$PROBE_URL") 2>/dev/null"
}

http_ready() {
  if [ "$TARGET" = "local" ]; then
    http_ready_local
  else
    http_ready_remote
  fi
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
  if [ "$TARGET" = "local" ]; then
    curl -fsS -o /dev/null -X POST "$url" \
      || wget -q -O /dev/null --post-data='' "$url" \
      || die "could not clear the register state on $url"
  else
    remote_sh "curl -fsS -o /dev/null -X POST $(shell_quote "$url")" \
      || die "could not clear the register state on $url"
  fi
  log "register state cleared on $PROBE_BASE"
}

# ── Build ───────────────────────────────────────────────────────────────────
build_binary() {
  local static_build="$STATIC_BUILD"
  [ "$TARGET" = "remote" ] && static_build=1

  if [ "$SKIP_BUILD" = "1" ]; then
    if is_dry_run; then
      log "would use the existing binary at $BINARY_PATH"
      return 0
    fi
    [ -f "$BINARY_PATH" ] || die "--skip-build was given but $BINARY_PATH does not exist"
    return 0
  fi

  if is_dry_run; then
    if [ "$static_build" = "1" ]; then
      log "would build $BINARY_PATH (CGO_ENABLED=0 GOOS=linux go build -o $BINARY_PATH ./tools/platform-mock/cmd/platform-mock)"
    else
      log "would build $BINARY_PATH (go build -o $BINARY_PATH ./tools/platform-mock/cmd/platform-mock)"
    fi
    return 0
  fi

  command -v go >/dev/null 2>&1 || die "the go compiler is required to build platform-mock"
  mkdir -p "$(dirname "$BINARY_PATH")"
  if [ "$static_build" = "1" ]; then
    log "building $BINARY_PATH for linux (CGO disabled)"
    ( cd "$PROJECT_DIR" && CGO_ENABLED=0 GOOS=linux go build -o "$BINARY_PATH" ./tools/platform-mock/cmd/platform-mock )
  else
    log "building $BINARY_PATH"
    ( cd "$PROJECT_DIR" && go build -o "$BINARY_PATH" ./tools/platform-mock/cmd/platform-mock )
  fi
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
  [ "$ALLOW_EMPTY_ATTESTATION" = "1" ] && MOCK_ARGS+=(-allow-empty-attestation)
  [ -n "$SM2_ID" ] && MOCK_ARGS+=(-sm2-id "$SM2_ID")
  [ -n "$PLATFORM_KEY_FILE" ] && MOCK_ARGS+=(-platform-key-file "$PLATFORM_KEY_FILE")
  return 0
}

# ── Local lifecycle ─────────────────────────────────────────────────────────
stop_local() {
  if is_dry_run; then
    log "would stop the local platform-mock (pid file $PID_FILE)"
    return 0
  fi
  if [ -f "$PID_FILE" ]; then
    local pid
    pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      local i
      for i in $(seq 1 50); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
      done
      kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$PID_FILE"
  fi
  # pkill -f would match this script itself, whose argv carries --binary PATH.
  pkill -x "$BINARY_NAME" >/dev/null 2>&1 || true
}

start_local() {
  if is_dry_run; then
    log "would start $BINARY_PATH on $ADDR (log $LOG_FILE, pid $PID_FILE)"
    return 0
  fi
  [ -n "$STATE_DIR" ] && mkdir -p "$STATE_DIR"
  [ -n "$UPLOAD_DIR" ] && mkdir -p "$UPLOAD_DIR"
  mkdir -p "$(dirname "$LOG_FILE")" "$(dirname "$PID_FILE")"
  stop_local
  build_mock_args
  log "starting platform-mock on $ADDR"
  nohup "$BINARY_PATH" "${MOCK_ARGS[@]}" >"$LOG_FILE" 2>&1 </dev/null &
  printf '%s\n' "$!" >"$PID_FILE"
  sleep 0.2
  if ! kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    [ -f "$LOG_FILE" ] && tail -n 20 "$LOG_FILE" >&2 || true
    die "platform-mock exited immediately after start (log $LOG_FILE)"
  fi
  if ! wait_ready; then
    [ -f "$LOG_FILE" ] && tail -n 40 "$LOG_FILE" >&2 || true
    die "platform-mock did not answer $PROBE_URL within ${READY_TIMEOUT}s (log $LOG_FILE)"
  fi
  log "platform-mock is answering on $PROBE_BASE"
}

status_local() {
  local running=0
  if [ -f "$PID_FILE" ]; then
    local pid
    pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      log "running (pid $pid, log $LOG_FILE)"
      running=1
    else
      log "not running (stale pid file $PID_FILE)"
    fi
  else
    log "not running (no pid file $PID_FILE)"
  fi
  if http_ready_local; then
    log "status endpoint ready: $PROBE_URL"
    return 0
  fi
  log "status endpoint not answering: $PROBE_URL"
  [ "$running" = "1" ] && return 0
  return 1
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
  if is_dry_run; then
    log "would start $REMOTE_BINARY on $REMOTE_TARGET with ${MOCK_ARGS[*]} (log $LOG_FILE)"
    return 0
  fi
  remote_sh "mkdir -p $(shell_quote "$REMOTE_DIR")" || die "could not create $REMOTE_DIR on $REMOTE_TARGET"
  stop_remote
  upload_remote
  log "starting platform-mock on $REMOTE_TARGET ($ADDR)"
  remote_sh "nohup $(shell_quote "$REMOTE_BINARY") $(shell_quote "${MOCK_ARGS[@]}") > $(shell_quote "$LOG_FILE") 2>&1 < /dev/null & echo \$! > $(shell_quote "$PID_FILE")" \
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
      if [ "$TARGET" = "local" ]; then
        start_local
      else
        start_remote
      fi
      reset_register
      ;;
    stop)
      if [ "$TARGET" = "local" ]; then
        stop_local
      else
        stop_remote
      fi
      log "platform-mock stopped"
      ;;
    restart)
      if [ "$TARGET" = "local" ]; then
        stop_local
      else
        stop_remote
      fi
      build_binary
      if [ "$TARGET" = "local" ]; then
        start_local
      else
        start_remote
      fi
      reset_register
      ;;
    status)
      if [ "$TARGET" = "local" ]; then
        status_local
      else
        status_remote
      fi
      ;;
  esac
}

main "$@"
