#!/usr/bin/env bash
# Deploy the FHE side on a GPU host. The handoff bundle ships one self-contained
# image that already contains redis, api_server, worker, the FHE runtime and the
# CUDA runtime libraries. This script starts one container from that image and
# puts TAA and its supervisor inside the same container: TAA reaches the FHE API
# at 127.0.0.1:58996 and the FHE callback reaches TAA at 127.0.0.1:6001, both
# over container loopback, so 58996 is never published on the host and a
# leftover compose stack cannot collide with it. Only TAA's own port is
# published, because the platform (or platform-mock) drives TAA over the host.
#
# `taa save` packages TAA into the image instead of deploying: it builds
# taa-fhe:<date> from the handoff image, exports the archive, uploads it and
# loads it on the remote host.
#
# -E (errtrace) is what makes the ERR trap below reach the run/render functions
# and the few subshells: without it bash does not inherit the ERR trap into a
# function, and every external command here runs inside one.
set -Eeuo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── FHE side ─────────────────────────────────────────────────────────────────
HANDOFF_DIR="${HANDOFF_DIR:-$PROJECT_DIR/latti-fhe-handoff}"
FHE_IMAGE="${FHE_IMAGE:-latti/latti-server-node:latest}"
# The archive the bundle ships. It is both the default for FHE_IMAGE_ARCHIVE and
# the file the bundle's own SHA256SUMS entry covers.
BUNDLE_IMAGE_ARCHIVE="$HANDOFF_DIR/image/latti-server-latest.tar.gz"
FHE_IMAGE_ARCHIVE="${FHE_IMAGE_ARCHIVE:-$BUNDLE_IMAGE_ARCHIVE}"
# Expected digest for an archive the bundle does not ship; empty means the
# operator vouched for neither and the verification step says so.
FHE_IMAGE_ARCHIVE_SHA256="${FHE_IMAGE_ARCHIVE_SHA256:-}"
# The bundle ships resnet20 (12 MB) and retina (444 MB); resnet20 is the model
# the delivery measured end to end.
FHE_MODEL_ID="${FHE_MODEL_ID:-resnet20}"
FHE_MODELS_SRC="${FHE_MODELS_SRC:-$HANDOFF_DIR/data/models}"
# Container-internal API port. API_HOST_PORT is kept as a compatibility alias
# from the version that published this port on the host; nothing publishes it
# now.
FHE_API_PORT="${FHE_API_PORT:-${API_HOST_PORT:-58996}}"
# Container-internal FHE data root. The FHE entrypoint reads CONTAINER_DATA_DIR
# (default /data) and renders model_registry.dir = $CONTAINER_DATA_DIR/models,
# keys_dir = $CONTAINER_DATA_DIR/keys. TAA writes the models, eval-key cache and
# results into the same tree, so both sides must use this one path; when they
# diverge the FHE registry scans an empty models directory and task creation
# fails with "Model ... not found". The value is also passed to the container as
# CONTAINER_DATA_DIR so the two cannot drift.
FHE_CONTAINER_DATA_DIR="${FHE_CONTAINER_DATA_DIR:-/data}"
FHE_ACTIVATE_TIMEOUT="${FHE_ACTIVATE_TIMEOUT:-300}"

# ── TAA side ─────────────────────────────────────────────────────────────────
# TAA_IMAGE defaults to the handoff image: a deploy run injects TAA into it at
# start time. A `taa save` run tags its packaged result taa-fhe:<date>, and
# `TAA_IMAGE=taa-fhe:<date> ./deploy-fhe.sh taa` then runs that image instead.
TAA_IMAGE="${TAA_IMAGE:-$FHE_IMAGE}"
TAA_CONTAINER_NAME="${TAA_CONTAINER_NAME:-taa-fhe}"
TAA_DOCKER_NETWORK="${TAA_DOCKER_NETWORK:-bridge}"
TAA_CONTAINER_WORKDIR="${TAA_CONTAINER_WORKDIR:-/root/taa}"
TAA_CONFIG_FILE="taa-config.json"
BINARY_NAME="${BINARY_NAME:-taa}"
TAA_LOG_FILE="${TAA_LOG_FILE:-$TAA_CONTAINER_WORKDIR/taa.log}"
# The supervisor's command line as a pgrep/pkill pattern, bracketed in the first
# letter and in the dot so it matches start.sh without matching the shell that
# carries the pattern.
SUPERVISOR_PATTERN='[s]tart[.]sh'
# Must match server.addr in $TAA_FHE_CONFIG. This is the one port published on
# the host: the platform reaches TAA through it. TAA_PUBLISH_ADDR narrows the
# bind (127.0.0.1 is enough for a host-local platform-mock); an empty value
# disables publishing, and then the platform has to reach the container IP.
TAA_PORT="${TAA_PORT:-6001}"
TAA_PUBLISH_ADDR="${TAA_PUBLISH_ADDR:-0.0.0.0}"
case "$TAA_PUBLISH_ADDR" in
  ""|0.0.0.0|127.0.0.1) TAA_PROBE_HOST=127.0.0.1 ;;
  *) TAA_PROBE_HOST="$TAA_PUBLISH_ADDR" ;;
esac
# An explicitly empty TAA_GPUS omits --gpus.
TAA_GPUS="${TAA_GPUS-all}"
TAA_RESTART_POLICY="${TAA_RESTART_POLICY:-unless-stopped}"
TAA_ENTRYPOINT_SOURCE="${TAA_ENTRYPOINT_SOURCE:-$PROJECT_DIR/deploy/taa-fhe-entrypoint.sh}"
TAA_ENTRYPOINT_CONTAINER="/opt/taa-entrypoint.sh"
TAA_READY_TIMEOUT="${TAA_READY_TIMEOUT:-120}"
TAA_READY_INTERVAL="${TAA_READY_INTERVAL:-2}"
FHE_READY_TIMEOUT="${FHE_READY_TIMEOUT:-180}"

# ── Where the deployment happens ─────────────────────────────────────────────
REMOTE_HOST="${REMOTE_HOST:-172.16.10.178}"
REMOTE_USER="${REMOTE_USER:-root}"
PASSWORD="${TARGET_PASSWORD:-Osrd@2026}"
REMOTE_DIR="${REMOTE_DIR:-/root/taa-fhe}"
REMOTE_TARGET="${REMOTE_TARGET:-${REMOTE_USER}@${REMOTE_HOST}}"

# Two host directories that decide the binds. They are named here as well as in
# the path block below so --help can print them before anything is resolved.
HOST_DATA_DIR="${HOST_DATA_DIR:-/opt/fhe-data}"
HOST_TAA_STATE_DIR="${HOST_TAA_STATE_DIR:-/opt/taa-state}"
# Redis persistence. The image's entrypoint keeps it in /data/redis, which on a
# host that still runs the old compose stack is the same directory that stack's
# newer redis writes (RDB v12, unreadable by the image's redis 7.0) - the
# container then dies on boot. Giving this container its own directory is what
# keeps the two from sharing state at all.
HOST_FHE_REDIS_DIR="${HOST_FHE_REDIS_DIR:-$HOST_DATA_DIR/redis-unified}"

# ── Platform side ────────────────────────────────────────────────────────────
# platform-mock stands in for the control plane. 18081, not deploy.sh's 18080:
# on the shared FHE host 18080 is held by ccs-node-agent.
PLATFORM_PORT="${PLATFORM_PORT:-18081}"
PLATFORM_ADDR="${PLATFORM_ADDR:-0.0.0.0:$PLATFORM_PORT}"
PLATFORM_MOCK_BINARY_NAME="${PLATFORM_MOCK_BINARY_NAME:-platform-mock}"
PLATFORM_MOCK_BINARY_PATH="${PLATFORM_MOCK_BINARY_PATH:-$PROJECT_DIR/bin/$PLATFORM_MOCK_BINARY_NAME}"
PLATFORM_MOCK_STATE_DIR="${PLATFORM_MOCK_STATE_DIR:-$REMOTE_DIR/platform-mock-state}"
PLATFORM_MOCK_UPLOAD_DIR="${PLATFORM_MOCK_UPLOAD_DIR:-$REMOTE_DIR/platform-mock-files}"
PLATFORM_READY_TIMEOUT="${PLATFORM_READY_TIMEOUT:-30}"
DEPLOY_PLATFORM_MOCK=1

TAA_BINARY_PATH="${TAA_BINARY_PATH:-$PROJECT_DIR/bin/taa}"
BUILD_BINARIES=1

# The identity the TAA container is given with -e. On a type=fhe instance these
# win over the config file (internal/config, applyFHEIdentityOverride).
PLATFORM_IP="${PLATFORM_IP:-}"
DOCKER_ID="${DOCKER_ID:-}"

# ── Packaging the taa-fhe image (taa save) ───────────────────────────────────
SAVE_DATE_TAG="$(date +%Y%m%d)"
TAA_FHE_SAVE_IMAGE="${TAA_FHE_SAVE_IMAGE:-taa-fhe:${SAVE_DATE_TAG}}"
TAA_FHE_SAVE_ARCHIVE="${TAA_FHE_SAVE_ARCHIVE:-$PROJECT_DIR/deploy/taa-fhe-${SAVE_DATE_TAG}.tar.gz}"
SAVE_ACTION=0
SAVE_BUILDER_CONTAINER=""

DRY_RUN="${DRY_RUN:-0}"

# ── Logging and failure reporting ────────────────────────────────────────────
STEP=0
log()  { printf '[deploy-fhe] %s\n' "$*"; }
warn() { printf '[deploy-fhe] WARNING: %s\n' "$*" >&2; }
step() { STEP=$((STEP + 1)); printf '\n[deploy-fhe] === %s) %s ===\n' "$STEP" "$*"; }

# A failed run leaves the container running on purpose: a re-run must be able to
# reuse it, and tearing down the FHE side because the last step failed would be
# worse than leaving it. The contract is only that no exit path is silent about
# what it left.
TAA_CONTAINER_TOUCHED=0
REPORTING=0

report_left_running() {
  [ "$REPORTING" = 0 ] || return 0
  REPORTING=1
  printf '\n[deploy-fhe] state left on the host (%s):\n' "$1" >&2
  if [ "$TAA_CONTAINER_TOUCHED" = 1 ]; then
    printf '[deploy-fhe]   container %s runs the FHE entrypoint and the TAA supervisor\n' "$TAA_CONTAINER_NAME" >&2
    printf '[deploy-fhe]     logs : docker logs --tail 100 %s\n' "$TAA_CONTAINER_NAME" >&2
    printf '[deploy-fhe]     taa  : docker exec %s tail -n 60 %s\n' "$TAA_CONTAINER_NAME" "$TAA_LOG_FILE" >&2
    printf '[deploy-fhe]     stop : docker rm -f %s\n' "$TAA_CONTAINER_NAME" >&2
  else
    printf '[deploy-fhe]   nothing this run started is still running.\n' >&2
  fi
  printf '[deploy-fhe] this script stops none of it; run the stop commands yourself.\n' >&2
}

die() { printf '[deploy-fhe] ERROR: %s\n' "$*" >&2; report_left_running "the run failed"; exit 1; }

on_error() {
  local rc="$1"
  trap - ERR
  # With -E the trap is inherited by subshells too; let the parent report once.
  if [ "$BASHPID" != "$$" ]; then
    exit "$rc"
  fi
  report_left_running "step ${STEP} failed (exit ${rc})"
  exit "$rc"
}
on_signal() {
  local sig="${1:-INT}" num
  trap - INT TERM
  report_left_running "interrupted"
  num="$(kill -l "$sig" 2>/dev/null)" || num=2
  exit $((128 + num))
}
trap 'on_error $?' ERR
trap 'on_signal INT' INT
trap 'on_signal TERM' TERM

TAA_RENDER_TMPDIR=""
cleanup_render_out() {
  [ -n "${TAA_RENDER_TMPDIR:-}" ] || return 0
  rm -rf "$TAA_RENDER_TMPDIR"
  TAA_RENDER_TMPDIR=""
}
cleanup_save_builder() {
  [ -n "${SAVE_BUILDER_CONTAINER:-}" ] || return 0
  local name="$SAVE_BUILDER_CONTAINER"
  SAVE_BUILDER_CONTAINER=""
  is_dry_run && return 0
  docker rm -f "$name" >/dev/null 2>&1 || true
}
trap 'cleanup_render_out; cleanup_save_builder' EXIT

is_dry_run() { [ "$DRY_RUN" = "1" ]; }

# ── Host helpers ─────────────────────────────────────────────────────────────
# Every host-side command goes through one of these, so "which machine runs
# this" is decided in a handful of functions instead of at every call site.
run() {
  if is_dry_run; then
    if [ -n "$REMOTE_TARGET" ]; then
      printf '[deploy-fhe] would run on %s: %s\n' "$REMOTE_TARGET" "$*"
    else
      printf '[deploy-fhe] would run: %s\n' "$*"
    fi
    return 0
  fi
  ssh_host "$@"
}

run_local() {
  if is_dry_run; then
    printf '[deploy-fhe] would run: %s\n' "$*"
    return 0
  fi
  "$@"
}

SSH_COMMON_OPTS=(
  -q
  -o LogLevel=ERROR
  -o StrictHostKeyChecking=accept-new
  -o UserKnownHostsFile="$HOME/.ssh/known_hosts"
)
SSH_OPTS=(-n "${SSH_COMMON_OPTS[@]}")

shell_quote() {
  local out="" arg q
  for arg in "$@"; do
    printf -v q '%q' "$arg"
    out+="$q "
  done
  printf '%s' "${out% }"
}

setup_remote_ssh() {
  [ -n "$REMOTE_TARGET" ] || return 0
  local -a prefix=()
  if [ -n "$PASSWORD" ]; then
    command -v sshpass >/dev/null 2>&1 \
      || die "sshpass is required to reach $REMOTE_TARGET with TARGET_PASSWORD set; install it, or clear TARGET_PASSWORD to use key authentication"
    prefix=(sshpass -p "$PASSWORD")
  fi
  require_command scp
  require_command rsync
  REMOTE_SSH=("${prefix[@]}" ssh "${SSH_OPTS[@]}")
  REMOTE_SCP=("${prefix[@]}" scp -q "${SSH_COMMON_OPTS[@]}")
  RSYNC_SSH=""
  [ -n "$PASSWORD" ] && RSYNC_SSH="sshpass -p $(shell_quote "$PASSWORD") "
  RSYNC_SSH+="ssh $(shell_quote -o LogLevel=ERROR -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$HOME/.ssh/known_hosts")"
}

ssh_host() {
  if [ -z "$REMOTE_TARGET" ]; then
    "$@"
  else
    "${REMOTE_SSH[@]}" "$REMOTE_TARGET" "$(shell_quote "$@")"
  fi
}

host_sh() {
  local script="$1"
  if is_dry_run; then
    if [ -n "$REMOTE_TARGET" ]; then
      printf '[deploy-fhe] would run on %s: %s\n' "$REMOTE_TARGET" "$script"
    else
      printf '[deploy-fhe] would run: %s\n' "$script"
    fi
    return 0
  fi
  if [ -z "$REMOTE_TARGET" ]; then
    bash -c "$script"
  else
    "${REMOTE_SSH[@]}" "$REMOTE_TARGET" "$script"
  fi
}

host_capture() {
  local script="$1"
  if is_dry_run && [ -n "$REMOTE_TARGET" ]; then
    printf '[deploy-fhe] dry-run: not reading %s from %s\n' "$script" "$REMOTE_TARGET" >&2
    return 0
  fi
  if [ -z "$REMOTE_TARGET" ]; then
    bash -c "$script"
  else
    "${REMOTE_SSH[@]}" "$REMOTE_TARGET" "$script"
  fi
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "command '$1' is required but not installed or not in PATH"
}

require_host_command() {
  local name="$1"
  host_sh "command -v $(shell_quote "$name") >/dev/null 2>&1" \
    || die "command '$name' is required on ${REMOTE_TARGET:-this host} but is not installed or not in PATH there"
}

same_path() {
  local a b
  a="$(realpath -m -- "$1")" || return 1
  b="$(realpath -m -- "$2")" || return 1
  [ "$a" = "$b" ]
}

paths_overlap() {
  local a b
  a="$(realpath -m -- "$1")" || return 1
  b="$(realpath -m -- "$2")" || return 1
  if [ "$a" = "/" ] || [ "$b" = "/" ] || [ "$a" = "$b" ]; then
    return 0
  fi
  case "$a/" in "$b"/*) return 0 ;; esac
  case "$b/" in "$a"/*) return 0 ;; esac
  return 1
}

build_binary() {
  local out="$1" pkg="$2"
  if is_dry_run; then
    log "would build $out (CGO_ENABLED=0 GOOS=linux go build -o $out $pkg)"
    return 0
  fi
  require_command go
  log "building $out"
  ( cd "$PROJECT_DIR" && CGO_ENABLED=0 GOOS=linux go build -o "$out" "$pkg" ) \
    || die "go build failed for $pkg"
  [ -f "$out" ] || die "go build reported success but $out is not there"
}

host_detach() {
  local logfile="$1" pidfile="$2"
  shift 2
  if is_dry_run; then
    printf '[deploy-fhe] would start on %s: %s > %s 2>&1 & (detached)\n' \
      "${REMOTE_TARGET:-this host}" "$(shell_quote "$@")" "$logfile"
    return 0
  fi
  if [ -z "$REMOTE_TARGET" ]; then
    nohup "$@" >"$logfile" 2>&1 </dev/null &
    printf '%s\n' "$!" >"$pidfile"
  else
    "${REMOTE_SSH[@]}" "$REMOTE_TARGET" \
      "nohup $(shell_quote "$@") > $(shell_quote "$logfile") 2>&1 < /dev/null & echo \$! > $(shell_quote "$pidfile")" >/dev/null \
      || die "failed to start $(shell_quote "$@") on $REMOTE_TARGET"
  fi
  log "started '$1' on ${REMOTE_TARGET:-this host} (log $logfile)"
}

upload_file() {
  local src="$1" dest="$2" mode="${3:-}"
  [ -n "$REMOTE_TARGET" ] || return 0
  if is_dry_run; then
    printf '[deploy-fhe] would copy %s -> %s:%s (mode %s)\n' "$src" "$REMOTE_TARGET" "$dest" "${mode:-644}"
    return 0
  fi
  [ -f "$src" ] || die "cannot upload $src: no such file"
  local tmp="${dest}.new"
  host_sh "mkdir -p $(shell_quote "$(dirname "$dest")")" \
    || die "cannot create $(dirname "$dest") on $REMOTE_TARGET"
  "${REMOTE_SCP[@]}" "$src" "$REMOTE_TARGET:$tmp" \
    || die "failed to copy $src to $REMOTE_TARGET:$tmp"
  host_sh "chmod ${mode:-644} $(shell_quote "$tmp") && mv -f $(shell_quote "$tmp") $(shell_quote "$dest")" \
    || die "failed to place $dest on $REMOTE_TARGET"
  log "uploaded $src -> $REMOTE_TARGET:$dest"
}

# Copies the model tree without --delete: an operator's extra models and the
# eval-key cache beside them must survive a re-run.
upload_models() {
  local src="$1" dest="$2"
  if same_path "$src" "$dest"; then
    log "models are already in place at $dest"
    return 0
  fi
  if is_dry_run; then
    printf '[deploy-fhe] would rsync -a %s/ -> %s:%s/\n' "$src" "${REMOTE_TARGET:-this host}" "$dest"
    return 0
  fi
  [ -d "$src" ] || die "model directory not found: $src"
  if [ -z "$REMOTE_TARGET" ]; then
    mkdir -p "$dest" || die "cannot create $dest"
    cp -a "$src/." "$dest/" || die "failed to copy models to $dest"
  else
    host_sh "mkdir -p $(shell_quote "$dest")" || die "cannot create $dest on $REMOTE_TARGET"
    rsync -a -e "$RSYNC_SSH" "$src/" "$REMOTE_TARGET:$dest/" \
      || die "failed to upload models to $REMOTE_TARGET:$dest"
  fi
  log "staged models $src/ -> $dest/"
}

upload_archive() {
  local src="$1" dest="$2"
  [ -n "$REMOTE_TARGET" ] || return 0
  if is_dry_run; then
    printf '[deploy-fhe] would rsync %s -> %s:%s\n' "$src" "$REMOTE_TARGET" "$dest"
    return 0
  fi
  [ -f "$src" ] || die "cannot upload $src: no such file"
  host_sh "mkdir -p $(shell_quote "$(dirname "$dest")")" \
    || die "cannot create $(dirname "$dest") on $REMOTE_TARGET"
  rsync -a --partial --inplace -e "$RSYNC_SSH" "$src" "$REMOTE_TARGET:$dest" \
    || die "failed to upload $src to $REMOTE_TARGET:$dest"
  log "uploaded $src -> $REMOTE_TARGET:$dest"
}

verify_one() {
  local rel="$1" file="${2:-$HANDOFF_DIR/$1}" expected="${3:-}" want got
  if is_dry_run; then
    if [ -n "$expected" ]; then
      log "would verify $rel against the expected digest"
    else
      log "would verify $rel against SHA256SUMS"
    fi
    return 0
  fi
  if [ -n "$expected" ]; then
    want="$expected"
  else
    [ -f "$HANDOFF_DIR/SHA256SUMS" ] || die "no SHA256SUMS in $HANDOFF_DIR"
    want="$(awk -v f="$rel" '$2 == f || $2 == "*"f {print $1}' "$HANDOFF_DIR/SHA256SUMS")"
    [ -n "$want" ] || die "SHA256SUMS has no entry for $rel"
  fi
  [ -f "$file" ] || die "missing artifact: $file"
  got="$(sha256sum "$file" | awk '{print $1}')"
  [ "$got" = "$want" ] || die "checksum mismatch for $rel ($file): got $got want $want"
  log "verified $rel"
}

usage() {
  cat <<EOF
Usage: $(basename "$0") [taa|platform-mock] [save] [options]

Deploy the unified FHE + TAA node. One container is started from the handoff
image (latti/latti-server-node:latest), which already contains redis, the FHE
api, the worker and the runtime; TAA and its supervisor are copied into that
same container. TAA talks to the FHE API at 127.0.0.1:58996 inside the
container, so 58996 is never published on the host; only TAA's port (6001) is,
because the platform drives TAA over the host. The deployment host is
${REMOTE_USER}@${REMOTE_HOST} by default.

Arguments:
  taa
      Deploy the unified container: prepare/load the image, stage the models,
      create the container, inject TAA, wait for both health endpoints and
      activate the model. platform-mock is assumed to be running already;
      set PLATFORM_IP if it is not on this host.
  platform-mock
      Deploy only platform-mock: build and upload its binary, start it if
      nothing answers on PLATFORM_PORT, and clear its register state.
  (no argument)
      Deploy platform-mock and the unified container.

  save
      Package instead of deploy, and only with the taa argument: build
      TAA into the handoff image (TAA binary, deploy/start.sh, the rendered
      config and the combined entrypoint), tag the result
      TAA_FHE_SAVE_IMAGE (taa-fhe:<date>), export it to
      TAA_FHE_SAVE_ARCHIVE, then upload and docker-load it on the default
      remote target. Nothing is started. Run the result with
      TAA_IMAGE=taa-fhe:<date> ./deploy-fhe.sh taa.

Options:
  -n, --dry-run         Print the commands and execute nothing.
  --remote              Deploy to ${REMOTE_USER}@${REMOTE_HOST} (default).
  --local               Deploy on the machine running this script.
  --no-platform-mock    Do not build, upload or start platform-mock, and do not
                        check the registration at the end.
  --skip-build          Use the binaries already at TAA_BINARY_PATH /
                        PLATFORM_MOCK_BINARY_PATH.
  -h, --help            Show this help.

Environment:
  HANDOFF_DIR=${HANDOFF_DIR}
      Delivery bundle: image/latti-server-latest.tar.gz and data/models/.
  FHE_IMAGE=${FHE_IMAGE}
      Image the handoff archive is loaded as.
  FHE_IMAGE_ARCHIVE=${FHE_IMAGE_ARCHIVE}
      Archive loaded by docker load. The bundle's own archive is verified
      against SHA256SUMS; a custom archive is verified against
      FHE_IMAGE_ARCHIVE_SHA256, or warned about when that is unset.
  FHE_MODEL_ID=${FHE_MODEL_ID}
      Model activated after the FHE API answers; its directory must exist at
      HOST_DATA_DIR/models/<model_id>/server.
  FHE_API_PORT=${FHE_API_PORT}
      Container-internal FHE API port. Never published. API_HOST_PORT is a
      deprecated alias.
  TAA_IMAGE=${TAA_IMAGE}
      Image the unified container runs. Defaults to FHE_IMAGE (runtime
      injection); set it to taa-fhe:<date> to run a saved image.
  TAA_CONTAINER_NAME=${TAA_CONTAINER_NAME}
  TAA_DOCKER_NETWORK=${TAA_DOCKER_NETWORK}
      Must not be host: 58996 has to stay inside the container.
  TAA_PORT=${TAA_PORT}
      TAA listening port; must match server.addr in the template.
  TAA_PUBLISH_ADDR=${TAA_PUBLISH_ADDR}
      Host address TAA_PORT is published on. Empty disables publishing.
  TAA_GPUS=${TAA_GPUS}
      Passed to --gpus (default all); empty omits the flag.
  TAA_RESTART_POLICY=${TAA_RESTART_POLICY}
  PLATFORM_IP=${PLATFORM_IP}
      Injected into the container (it wins over the config on type=fhe).
      Defaulted to the docker network gateway on this host, because
      127.0.0.1 inside the container is the container itself.
  PLATFORM_PORT=${PLATFORM_PORT}
      Port platform-mock listens on.
  HOST_DATA_DIR=${HOST_DATA_DIR}
      Host directory mounted at FHE_CONTAINER_DATA_DIR. It holds the model
      tree, per-user eval contexts, tasks and results.
  FHE_CONTAINER_DATA_DIR=${FHE_CONTAINER_DATA_DIR}
      Container-internal FHE data root. The FHE entrypoint derives
      models/keys/tasks/results from it, and TAA's rendered config now uses
      the same path, so one bind serves both. Passed to the container as
      CONTAINER_DATA_DIR.
  HOST_TAA_STATE_DIR=${HOST_TAA_STATE_DIR}
      TAA's SM2 key pair and sealed state, on a bind of its own so the FHE
      side cannot read it.
  HOST_FHE_REDIS_DIR=${HOST_FHE_REDIS_DIR}
      Redis persistence, mounted at /data/redis. Kept apart from the
      directory a leftover compose stack's redis writes, whose RDB the
      image's older redis cannot read.
  REMOTE_HOST=${REMOTE_HOST}, REMOTE_USER=${REMOTE_USER}
      Remote target; TARGET_PASSWORD is the ssh password (empty means key or
      agent authentication). REMOTE_DIR=${REMOTE_DIR} holds uploaded files.
EOF
}

# ── Arguments ────────────────────────────────────────────────────────────────
DEPLOY_MODE="all"

while [ $# -gt 0 ]; do
  case "$1" in
    fhe)
      printf '[deploy-fhe] ERROR: the fhe mode was removed: the FHE services now run inside the taa container\n' >&2
      exit 1
      ;;
    taa|platform-mock)
      if [ "$DEPLOY_MODE" != "all" ] && [ "$DEPLOY_MODE" != "$1" ]; then
        printf '[deploy-fhe] ERROR: choose one of taa or platform-mock\n' >&2
        usage >&2
        exit 1
      fi
      DEPLOY_MODE="$1"
      ;;
    save)
      if [ "$SAVE_ACTION" = 1 ]; then
        printf '[deploy-fhe] ERROR: save was given twice\n' >&2
        usage >&2
        exit 1
      fi
      SAVE_ACTION=1
      ;;
    -n|--dry-run) DRY_RUN=1 ;;
    --remote) REMOTE_TARGET="${REMOTE_USER}@${REMOTE_HOST}" ;;
    --local) REMOTE_TARGET="" ;;
    --no-platform-mock) DEPLOY_PLATFORM_MOCK=0 ;;
    --skip-build) BUILD_BINARIES=0 ;;
    -h|--help|help) usage; exit 0 ;;
    *) printf '[deploy-fhe] ERROR: unknown argument: %s\n' "$1" >&2; usage >&2; exit 1 ;;
  esac
  shift
done

DEPLOY_TAA=1
DEPLOY_MOCK=1
case "$DEPLOY_MODE" in
  taa) DEPLOY_MOCK=0 ;;
  platform-mock) DEPLOY_TAA=0 ;;
esac
if [ "$DEPLOY_MODE" = "platform-mock" ] && [ "$DEPLOY_PLATFORM_MOCK" != 1 ]; then
  printf '[deploy-fhe] ERROR: the platform-mock argument deploys platform-mock, but --no-platform-mock was given\n' >&2
  usage >&2
  exit 1
fi
if [ "$SAVE_ACTION" = 1 ] && [ "$DEPLOY_MODE" != "taa" ]; then
  printf '[deploy-fhe] ERROR: save is only valid with the taa argument: deploy-fhe.sh taa save\n' >&2
  usage >&2
  exit 1
fi
# A save run starts nothing, so it builds and deploys no mock.
if [ "$SAVE_ACTION" = 1 ]; then
  DEPLOY_MOCK=0
fi

setup_remote_ssh

# ── Paths this run uses ──────────────────────────────────────────────────────
HOST_DATA_DIR="${HOST_DATA_DIR:-/opt/fhe-data}"
HOST_TAA_STATE_DIR="${HOST_TAA_STATE_DIR:-/opt/taa-state}"
TAA_FHE_CONFIG="${TAA_FHE_CONFIG:-$PROJECT_DIR/configs/taa-fhe.json}"
STAGED_MODELS_DIR="$HOST_DATA_DIR/models"
TAA_RENDERED_CONFIG="${TAA_RENDERED_CONFIG:-$HOST_DATA_DIR/taa-fhe.rendered.json}"
TAA_CONTAINER_CONFIG_PATH="${TAA_CONTAINER_CONFIG_PATH:-$TAA_CONTAINER_WORKDIR/$TAA_CONFIG_FILE}"
TAA_RENDER_OUT="$TAA_RENDERED_CONFIG"
if [ "$DEPLOY_TAA" = 1 ] && [ -n "$REMOTE_TARGET" ] && ! is_dry_run && [ "$SAVE_ACTION" != 1 ]; then
  TAA_RENDER_TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/deploy-fhe-render.XXXXXX")" \
    || die "cannot create a temporary directory for the rendered config"
  TAA_RENDER_OUT="$TAA_RENDER_TMPDIR/taa-fhe.rendered.json"
fi

HOST_START_SH="$PROJECT_DIR/deploy/start.sh"
HOST_TAA_BINARY_PATH="$TAA_BINARY_PATH"
HOST_PLATFORM_MOCK_BINARY_PATH="$PLATFORM_MOCK_BINARY_PATH"
HOST_ENTRYPOINT_PATH="$TAA_ENTRYPOINT_SOURCE"
HOST_FHE_IMAGE_ARCHIVE="$FHE_IMAGE_ARCHIVE"
if [ -n "$REMOTE_TARGET" ]; then
  HOST_START_SH="$REMOTE_DIR/deploy/start.sh"
  HOST_TAA_BINARY_PATH="$REMOTE_DIR/bin/$BINARY_NAME"
  HOST_PLATFORM_MOCK_BINARY_PATH="$REMOTE_DIR/bin/$PLATFORM_MOCK_BINARY_NAME"
  HOST_ENTRYPOINT_PATH="$REMOTE_DIR/deploy/$(basename "$TAA_ENTRYPOINT_SOURCE")"
  HOST_FHE_IMAGE_ARCHIVE="$REMOTE_DIR/image/$(basename "$FHE_IMAGE_ARCHIVE")"
fi

# ── Guards on the operator-invented paths ────────────────────────────────────
# These refuse in --dry-run too: they are configuration mistakes, and a dry run
# is where a mistake this cheap to check should be caught.
case "$HOST_DATA_DIR" in
  ""|/) die "HOST_DATA_DIR='$HOST_DATA_DIR' is not a usable directory" ;;
esac
case "$HOST_TAA_STATE_DIR" in
  ""|/) die "HOST_TAA_STATE_DIR='$HOST_TAA_STATE_DIR' is not a usable directory" ;;
esac
case "$FHE_CONTAINER_DATA_DIR" in
  ""|/) die "FHE_CONTAINER_DATA_DIR='$FHE_CONTAINER_DATA_DIR' is not a usable directory" ;;
  /*) ;;
  *) die "FHE_CONTAINER_DATA_DIR='$FHE_CONTAINER_DATA_DIR' is a container path and must be absolute" ;;
esac
if paths_overlap "$HOST_TAA_STATE_DIR" "$HOST_DATA_DIR"; then
  die "HOST_TAA_STATE_DIR=$HOST_TAA_STATE_DIR and HOST_DATA_DIR=$HOST_DATA_DIR overlap; the FHE entrypoint reads HOST_DATA_DIR as $FHE_CONTAINER_DATA_DIR, so TAA's SM2 key pair and sealed state would be readable from the FHE side, which is what the separate state bind exists to prevent"
fi
if paths_overlap "$FHE_MODELS_SRC" "$STAGED_MODELS_DIR" && ! same_path "$FHE_MODELS_SRC" "$STAGED_MODELS_DIR"; then
  die "$STAGED_MODELS_DIR and the bundle models $FHE_MODELS_SRC overlap (one contains the other); the model copy would recurse into itself"
fi
if [ "$TAA_DOCKER_NETWORK" = "host" ]; then
  die "TAA_DOCKER_NETWORK=host is refused: 58996 has to stay inside the container, and host networking would publish it on the host"
fi
case "$TAA_PORT" in
  ''|*[!0-9]*) die "TAA_PORT='$TAA_PORT' is not a number" ;;
esac
if [ "$TAA_CONTAINER_WORKDIR" != "/root/taa" ]; then
  die "TAA_CONTAINER_WORKDIR=$TAA_CONTAINER_WORKDIR, but deploy/start.sh runs taa in /root/taa and taa reads ./$TAA_CONFIG_FILE from its working directory"
fi
if [ "$TAA_CONTAINER_CONFIG_PATH" != "$TAA_CONTAINER_WORKDIR/$TAA_CONFIG_FILE" ]; then
  die "TAA_CONTAINER_CONFIG_PATH=$TAA_CONTAINER_CONFIG_PATH, but deploy/start.sh runs taa with no --config, so taa reads $TAA_CONTAINER_WORKDIR/$TAA_CONFIG_FILE"
fi
if ! is_dry_run; then
  [ -f "$TAA_ENTRYPOINT_SOURCE" ] || die "combined entrypoint not found: $TAA_ENTRYPOINT_SOURCE"
  [ -f "$PROJECT_DIR/deploy/start.sh" ] || die "TAA supervisor script missing: $PROJECT_DIR/deploy/start.sh"
  bash -n "$TAA_ENTRYPOINT_SOURCE" || die "syntax error in $TAA_ENTRYPOINT_SOURCE"
  bash -n "$PROJECT_DIR/deploy/start.sh" || die "syntax error in $PROJECT_DIR/deploy/start.sh"
fi
TAA_ENTRYPOINT_SHA256="$(sha256sum "$TAA_ENTRYPOINT_SOURCE" 2>/dev/null | awk '{print $1}')"
[ -n "$TAA_ENTRYPOINT_SHA256" ] || TAA_ENTRYPOINT_SHA256="<unset>"

# ── Rendering ────────────────────────────────────────────────────────────────
render_taa_config() {
  local upload="${1:-1}"
  [ -f "$TAA_FHE_CONFIG" ] || die "TAA config template not found: $TAA_FHE_CONFIG"
  command -v jq >/dev/null 2>&1 || die "command 'jq' is required but not installed or not in PATH"
  local rendered_dir
  rendered_dir="$(dirname "$TAA_RENDER_OUT")"
  [ -d "$rendered_dir" ] || die "cannot write $TAA_RENDER_OUT: $rendered_dir does not exist"
  jq \
      --arg endpoint "http://127.0.0.1:${FHE_API_PORT}" \
      --arg data "$FHE_CONTAINER_DATA_DIR" \
      --arg state "$HOST_TAA_STATE_DIR" \
      '.fhe.endpoint = $endpoint | .fhe.dataDir = $data
       | .fhe.keyCacheDir = ($data + "/taa-fhe-keys")
       | .storage.result  = ($data + "/taa-results")
       | .storage.keys    = ($state + "/keys")' \
      "$TAA_FHE_CONFIG" > "$TAA_RENDER_OUT" \
    || die "failed to render $TAA_FHE_CONFIG -> $TAA_RENDER_OUT"
  chmod 600 "$TAA_RENDER_OUT"
  log "rendered $TAA_FHE_CONFIG -> $TAA_RENDER_OUT"
  if [ -n "$REMOTE_TARGET" ] && [ "$upload" = 1 ]; then
    upload_file "$TAA_RENDER_OUT" "$TAA_RENDERED_CONFIG" 600
  fi

  local addr
  addr="$(jq -r '.server.addr' "$TAA_RENDER_OUT")"
  [ "$addr" = ":$TAA_PORT" ] \
    || die "server.addr in the rendered config is '$addr' but TAA_PORT is ':$TAA_PORT'"

  # TAA's stateful paths have to land inside the bind that carries them.
  local state_pair state_key state_bind state_path
  for state_pair in \
    ".fhe.keyCacheDir|$FHE_CONTAINER_DATA_DIR" \
    ".storage.result|$FHE_CONTAINER_DATA_DIR" \
    ".storage.keys|$HOST_TAA_STATE_DIR"; do
    state_key="${state_pair%%|*}"
    state_bind="${state_pair#*|}"
    state_path="$(jq -r "$state_key" "$TAA_RENDER_OUT")"
    case "$state_path" in
      "$state_bind"/*) ;;
      *) die "the rendered config sets $state_key to '$state_path', outside the bind '$state_bind' that carries it" ;;
    esac
  done

  # PLATFORM_IP is injected at run time, but leaving it to the template on a
  # bridge network points TAA at itself.
  if [ "$TAA_DOCKER_NETWORK" != "host" ]; then
    local effective_platform="${PLATFORM_IP:-$(jq -r '.platform.ip // empty' "$TAA_RENDER_OUT")}"
    case "$effective_platform" in
      127.0.0.1:*|localhost:*)
        if [ "$SAVE_ACTION" = 1 ]; then
          warn "the baked config points at platform.ip=$effective_platform, which is the container itself on network $TAA_DOCKER_NETWORK; a standalone run needs -e PLATFORM_IP"
        else
          die "platform ip '$effective_platform' is container loopback on network $TAA_DOCKER_NETWORK; set PLATFORM_IP to the bridge gateway or a reachable platform"
        fi
        ;;
    esac
  fi
}

# ── Probes ───────────────────────────────────────────────────────────────────
container_running() {
  host_sh "docker inspect --format '{{.State.Running}}' $(shell_quote "$TAA_CONTAINER_NAME") 2>/dev/null | grep -qx true"
}

fail_if_container_stopped() {
  if ! container_running; then
    host_sh "docker logs --tail 200 $(shell_quote "$TAA_CONTAINER_NAME") 2>&1" || true
    die "container $TAA_CONTAINER_NAME is not running"
  fi
}

# The image has no curl, so in-container probes use python3.
wait_for_fhe_health() {
  local deadline=$((SECONDS + FHE_READY_TIMEOUT))
  while [ "$SECONDS" -lt "$deadline" ]; do
    fail_if_container_stopped
    if run docker exec "$TAA_CONTAINER_NAME" python3 -c \
        'import sys,urllib.request; urllib.request.urlopen("http://127.0.0.1:"+sys.argv[1]+"/api/v1/health", timeout=5).read(1)' \
        "$FHE_API_PORT" >/dev/null 2>&1; then
      return 0
    fi
    sleep "$TAA_READY_INTERVAL"
  done
  return 1
}

wait_for_taa() {
  local deadline=$((SECONDS + TAA_READY_TIMEOUT))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if host_sh "curl -fsS -o /dev/null -X POST 'http://${TAA_PROBE_HOST}:${TAA_PORT}/v1/taa/health'" 2>/dev/null; then
      return 0
    fi
    sleep "$TAA_READY_INTERVAL"
  done
  return 1
}

platform_register_state() {
  host_capture "curl -fsS 'http://127.0.0.1:${PLATFORM_PORT}/api/register/status'" 2>/dev/null || true
}

wait_for_platform_mock() {
  local deadline=$((SECONDS + PLATFORM_READY_TIMEOUT))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if host_sh "curl -fsS -o /dev/null 'http://127.0.0.1:${PLATFORM_PORT}/api/register/status'" 2>/dev/null; then
      return 0
    fi
    sleep "$TAA_READY_INTERVAL"
  done
  return 1
}

# ── The unified container ────────────────────────────────────────────────────
CONTAINER_STATE=""

create_or_reuse_container() {
  # One bind carries the whole shared tree: the FHE side reads it as its data
  # root and TAA's rendered config uses the same container path for models,
  # the eval-key cache and results. HOST_DATA_DIR stays a host-side name only.
  local -a binds=("$HOST_DATA_DIR:$FHE_CONTAINER_DATA_DIR")
  binds+=("$HOST_FHE_REDIS_DIR:$FHE_CONTAINER_DATA_DIR/redis")
  binds+=("$HOST_TAA_STATE_DIR:$HOST_TAA_STATE_DIR")

  local -a required_envs=("TAA_ENTRYPOINT_SHA256=$TAA_ENTRYPOINT_SHA256" "CONTAINER_DATA_DIR=$FHE_CONTAINER_DATA_DIR")
  [ -z "$PLATFORM_IP" ] || required_envs+=("PLATFORM_IP=$PLATFORM_IP")
  [ -z "$DOCKER_ID" ] || required_envs+=("DOCKER_ID=$DOCKER_ID")

  local -a create_args=(--name "$TAA_CONTAINER_NAME" --network "$TAA_DOCKER_NETWORK")
  create_args+=(--restart "$TAA_RESTART_POLICY")
  [ -z "$TAA_GPUS" ] || create_args+=(--gpus "$TAA_GPUS")
  create_args+=(-p "$TAA_PUBLISH_ADDR:$TAA_PORT:$TAA_PORT")
  create_args+=(--entrypoint "$TAA_ENTRYPOINT_CONTAINER")
  local item
  for item in "${binds[@]}"; do create_args+=(-v "$item"); done
  for item in "${required_envs[@]}"; do create_args+=(-e "$item"); done
  create_args+=("$TAA_IMAGE")

  if is_dry_run; then
    log "dry-run: would reuse $TAA_CONTAINER_NAME only when image, binds, environment, network, entrypoint, published port, restart policy and GPU request all match; otherwise it would create:"
    run docker create "${create_args[@]}"
    CONTAINER_STATE=new
    return 0
  fi

  if host_sh "docker ps -a --format '{{.Names}}' | grep -Fxq $(shell_quote "$TAA_CONTAINER_NAME")"; then
    local current target_id reasons="" reason
    current="$(host_capture "docker inspect $(shell_quote "$TAA_CONTAINER_NAME")" 2>/dev/null || true)"
    target_id="$(host_capture "docker image inspect --format '{{.Id}}' $(shell_quote "$TAA_IMAGE")" 2>/dev/null || true)"
    if [ -z "$current" ]; then
      reasons="cannot inspect the existing container"
    else
      local cur_image cur_id net ep policy publish_all
      cur_image="$(printf '%s' "$current" | jq -r '.[0].Config.Image // empty' 2>/dev/null || true)"
      cur_id="$(printf '%s' "$current" | jq -r '.[0].Image // empty' 2>/dev/null || true)"
      if [ "$cur_image" != "$TAA_IMAGE" ] && { [ -z "$target_id" ] || [ "$cur_id" != "$target_id" ]; }; then
        reasons+="image=${cur_image:-unknown} "
      fi
      net="$(printf '%s' "$current" | jq -r '.[0].HostConfig.NetworkMode // empty' 2>/dev/null || true)"
      [ "$net" = "$TAA_DOCKER_NETWORK" ] || reasons+="network=${net:-unknown} "
      ep="$(printf '%s' "$current" | jq -r '(.[0].Config.Entrypoint // []) | join(" ")' 2>/dev/null || true)"
      [ "$ep" = "$TAA_ENTRYPOINT_CONTAINER" ] || reasons+="entrypoint=${ep:-unknown} "
      policy="$(printf '%s' "$current" | jq -r '.[0].HostConfig.RestartPolicy.Name // empty' 2>/dev/null || true)"
      [ "$policy" = "$TAA_RESTART_POLICY" ] || reasons+="restart=${policy:-none} "
      publish_all="$(printf '%s' "$current" | jq -r '.[0].HostConfig.PublishAllPorts // false' 2>/dev/null || true)"
      [ "$publish_all" = "false" ] || reasons+="publish-all=${publish_all} "
      for reason in "${binds[@]}"; do
        printf '%s' "$current" | jq -e --arg b "$reason" '(.[0].HostConfig.Binds // []) | index($b) != null' >/dev/null 2>&1 \
          || reasons+="bind=$reason "
      done
      for reason in "${required_envs[@]}"; do
        printf '%s' "$current" | jq -e --arg e "$reason" '(.[0].Config.Env // []) | index($e) != null' >/dev/null 2>&1 \
          || reasons+="env=$reason "
      done
      if ! printf '%s' "$current" | jq -e --arg ip "$TAA_PUBLISH_ADDR" --arg port "$TAA_PORT" '
          (.[0].HostConfig.PortBindings // {}) as $pb
          | ((($pb[$port + "/tcp"] // []) | length) == 1
             and $pb[$port + "/tcp"][0].HostIp == $ip
             and $pb[$port + "/tcp"][0].HostPort == $port)
            and (($pb["58996/tcp"] // null) == null)' >/dev/null 2>&1; then
        reasons+="published-port "
      fi
      if [ -n "$TAA_GPUS" ]; then
        printf '%s' "$current" | jq -e '((.[0].HostConfig.DeviceRequests // []) | length) > 0' >/dev/null 2>&1 \
          || reasons+="gpus "
      fi
    fi

    if [ -n "$reasons" ]; then
      warn "container $TAA_CONTAINER_NAME does not match this run ($reasons); recreating"
      run docker rm -f "$TAA_CONTAINER_NAME"
    else
      if host_sh "docker ps --format '{{.Names}}' | grep -Fxq $(shell_quote "$TAA_CONTAINER_NAME")"; then
        CONTAINER_STATE=running
        log "reusing running container $TAA_CONTAINER_NAME"
      else
        CONTAINER_STATE=stopped
        log "reusing stopped container $TAA_CONTAINER_NAME"
      fi
      return 0
    fi
  fi

  log "creating container $TAA_CONTAINER_NAME (image $TAA_IMAGE, network $TAA_DOCKER_NETWORK, published $TAA_PORT)"
  run docker create "${create_args[@]}"
  CONTAINER_STATE=new
}

install_taa_files() {
  local state="$1"
  if [ "$state" = "running" ]; then
    # The wrapper owns start.sh; killing both makes it restart the supervisor
    # after its 10s delay, and the copies below fit well inside that window.
    # .new + mv keeps a running taa from seeing a half-written binary
    # (docker cp directly onto a running executable fails with ETXTBSY).
    run docker exec -i "$TAA_CONTAINER_NAME" sh -lc "touch '$TAA_CONTAINER_WORKDIR/manual'"
    run docker exec -i "$TAA_CONTAINER_NAME" \
      sh -lc "pkill -f '$SUPERVISOR_PATTERN' >/dev/null 2>&1 || true; pkill -x '$BINARY_NAME' >/dev/null 2>&1 || true"
    if ! is_dry_run; then
      local waited=0
      while [ "$waited" -lt 25 ]; do
        host_sh "docker exec -i '$TAA_CONTAINER_NAME' sh -lc \"pgrep -f '$SUPERVISOR_PATTERN' >/dev/null 2>&1\"" || break
        waited=$((waited + 1))
        sleep 0.2
      done
    fi
    run docker cp "$HOST_START_SH" "$TAA_CONTAINER_NAME:$TAA_CONTAINER_WORKDIR/start.sh.new"
    run docker cp "$HOST_TAA_BINARY_PATH" "$TAA_CONTAINER_NAME:$TAA_CONTAINER_WORKDIR/$BINARY_NAME.new"
    run docker cp "$TAA_RENDERED_CONFIG" "$TAA_CONTAINER_NAME:$TAA_CONTAINER_CONFIG_PATH.new"
    run docker exec -i "$TAA_CONTAINER_NAME" sh -lc \
      "mv -f '$TAA_CONTAINER_WORKDIR/start.sh.new' '$TAA_CONTAINER_WORKDIR/start.sh' \
       && mv -f '$TAA_CONTAINER_WORKDIR/$BINARY_NAME.new' '$TAA_CONTAINER_WORKDIR/$BINARY_NAME' \
       && mv -f '$TAA_CONTAINER_CONFIG_PATH.new' '$TAA_CONTAINER_CONFIG_PATH' \
       && chown root:root '$TAA_CONTAINER_WORKDIR/start.sh' '$TAA_CONTAINER_WORKDIR/$BINARY_NAME' '$TAA_CONTAINER_CONFIG_PATH' \
       && chmod +x '$TAA_CONTAINER_WORKDIR/start.sh' '$TAA_CONTAINER_WORKDIR/$BINARY_NAME' \
       && chmod 600 '$TAA_CONTAINER_CONFIG_PATH' \
       && rm -f '$TAA_CONTAINER_WORKDIR/manual'"
    log "refreshed TAA files in the running container; the supervisor restarts taa by itself"
    return 0
  fi

  # A new or stopped container starts without /root/taa: the FHE image does not
  # carry the TAA workdir, and docker cp cannot create a missing parent. The
  # wrapper copes with that (it logs the missing start.sh and retries every
  # 10s), so the container is started first and the workdir is created from
  # inside it. Docker cp then copies over the start.sh that is not there yet,
  # so there is no running binary to collide with.
  run docker cp "$HOST_ENTRYPOINT_PATH" "$TAA_CONTAINER_NAME:$TAA_ENTRYPOINT_CONTAINER"
  run docker start "$TAA_CONTAINER_NAME"
  run docker exec -i "$TAA_CONTAINER_NAME" sh -lc "mkdir -p '$TAA_CONTAINER_WORKDIR'"
  run docker cp "$HOST_START_SH" "$TAA_CONTAINER_NAME:$TAA_CONTAINER_WORKDIR/start.sh"
  run docker cp "$HOST_TAA_BINARY_PATH" "$TAA_CONTAINER_NAME:$TAA_CONTAINER_WORKDIR/$BINARY_NAME"
  run docker cp "$TAA_RENDERED_CONFIG" "$TAA_CONTAINER_NAME:$TAA_CONTAINER_CONFIG_PATH"
  if ! is_dry_run; then
    host_sh "docker exec -i '$TAA_CONTAINER_NAME' sh -lc \"chown root:root '$TAA_ENTRYPOINT_CONTAINER' '$TAA_CONTAINER_WORKDIR/start.sh' '$TAA_CONTAINER_WORKDIR/$BINARY_NAME' '$TAA_CONTAINER_CONFIG_PATH' && chmod +x '$TAA_ENTRYPOINT_CONTAINER' '$TAA_CONTAINER_WORKDIR/start.sh' '$TAA_CONTAINER_WORKDIR/$BINARY_NAME' && chmod 600 '$TAA_CONTAINER_CONFIG_PATH' && rm -f '$TAA_CONTAINER_WORKDIR/manual'\"" \
      || die "container $TAA_CONTAINER_NAME started but the TAA files are not in place (see docker logs $TAA_CONTAINER_NAME)"
  fi
}

# ── Save path ────────────────────────────────────────────────────────────────
if [ "$SAVE_ACTION" = 1 ]; then
step "packaging the taa-fhe image locally ($TAA_FHE_SAVE_IMAGE)"
if [ "$BUILD_BINARIES" = 1 ]; then
  build_binary "$TAA_BINARY_PATH" ./cmd/taa
else
  log "--skip-build: packaging the binary already at $TAA_BINARY_PATH"
  if ! is_dry_run && [ ! -f "$TAA_BINARY_PATH" ]; then
    die "--skip-build was given but $TAA_BINARY_PATH does not exist"
  fi
fi
if ! is_dry_run; then
  docker info >/dev/null 2>&1 || die "docker daemon is not running or accessible on this machine"
  if ! docker image inspect "$FHE_IMAGE" >/dev/null 2>&1; then
    [ -f "$FHE_IMAGE_ARCHIVE" ] \
      || die "base image $FHE_IMAGE is not present and no archive was found at $FHE_IMAGE_ARCHIVE"
    if same_path "$FHE_IMAGE_ARCHIVE" "$BUNDLE_IMAGE_ARCHIVE"; then
      verify_one image/latti-server-latest.tar.gz "$FHE_IMAGE_ARCHIVE"
    elif [ -n "$FHE_IMAGE_ARCHIVE_SHA256" ]; then
      verify_one image/latti-server-latest.tar.gz "$FHE_IMAGE_ARCHIVE" "$FHE_IMAGE_ARCHIVE_SHA256"
    else
      warn "FHE_IMAGE_ARCHIVE=$FHE_IMAGE_ARCHIVE is not the archive this bundle ships, so it is NOT covered by SHA256SUMS; set FHE_IMAGE_ARCHIVE_SHA256 to have it verified"
    fi
    log "loading base image $FHE_IMAGE from $FHE_IMAGE_ARCHIVE"
    docker load -i "$FHE_IMAGE_ARCHIVE" || die "failed to load $FHE_IMAGE_ARCHIVE"
  fi
  if [ -z "${TAA_RENDER_TMPDIR:-}" ]; then
    TAA_RENDER_TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/deploy-fhe-save.XXXXXX")" \
      || die "cannot create a temporary directory for the rendered config"
  fi
  TAA_RENDER_OUT="$TAA_RENDER_TMPDIR/$TAA_CONFIG_FILE"
  render_taa_config 0
else
  log "would ensure $FHE_IMAGE is present locally, loading $FHE_IMAGE_ARCHIVE if needed"
  log "would render $TAA_FHE_CONFIG -> $TAA_CONTAINER_WORKDIR/$TAA_CONFIG_FILE and bake it into the image"
fi

builder="taa-fhe-builder-$$"
SAVE_BUILDER_CONTAINER="$builder"
run_local docker run -d --name "$builder" --entrypoint tail "$FHE_IMAGE" -f /dev/null
run_local docker exec -i "$builder" sh -lc "mkdir -p '$TAA_CONTAINER_WORKDIR'"
run_local docker cp "$PROJECT_DIR/deploy/start.sh" "$builder:$TAA_CONTAINER_WORKDIR/start.sh"
run_local docker cp "$TAA_ENTRYPOINT_SOURCE" "$builder:$TAA_ENTRYPOINT_CONTAINER"
run_local docker cp "$TAA_BINARY_PATH" "$builder:$TAA_CONTAINER_WORKDIR/$BINARY_NAME"
if is_dry_run; then
  printf '[deploy-fhe] would copy the rendered config -> %s:%s/%s (mode 600)\n' \
    "$builder" "$TAA_CONTAINER_WORKDIR" "$TAA_CONFIG_FILE"
else
  run_local docker cp "$TAA_RENDER_OUT" "$builder:$TAA_CONTAINER_WORKDIR/$TAA_CONFIG_FILE"
fi
run_local docker exec -i "$builder" sh -lc \
  "chown root:root '$TAA_ENTRYPOINT_CONTAINER' '$TAA_CONTAINER_WORKDIR/start.sh' '$TAA_CONTAINER_WORKDIR/$BINARY_NAME' '$TAA_CONTAINER_WORKDIR/$TAA_CONFIG_FILE' \
   && chmod +x '$TAA_ENTRYPOINT_CONTAINER' '$TAA_CONTAINER_WORKDIR/start.sh' '$TAA_CONTAINER_WORKDIR/$BINARY_NAME' \
   && chmod 600 '$TAA_CONTAINER_WORKDIR/$TAA_CONFIG_FILE'"
# /opt/entrypoint.sh is the FHE side the combined entrypoint starts; a base
# image without it would commit an image that cannot boot.
run_local docker exec -i "$builder" sh -lc "test -x /opt/entrypoint.sh" \
  || die "$FHE_IMAGE does not contain /opt/entrypoint.sh"
run_local docker exec -i "$builder" sh -lc \
  "rm -f '$TAA_CONTAINER_WORKDIR/manual' '$TAA_CONTAINER_WORKDIR/manual-teellm' '$TAA_CONTAINER_WORKDIR/taa.log' '$TAA_CONTAINER_WORKDIR/.start.lock'"
run_local docker commit \
  -c 'ENTRYPOINT ["/opt/taa-entrypoint.sh"]' \
  -c 'CMD []' \
  -c 'WORKDIR /root/taa' \
  -c 'EXPOSE 58996 6001' \
  -m "taa-fhe image packaged from $FHE_IMAGE at $(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  "$builder" "$TAA_FHE_SAVE_IMAGE"
run_local docker rm -f "$builder"
SAVE_BUILDER_CONTAINER=""

if ! is_dry_run; then
  committed="$(docker image inspect --format '{{.Config.Entrypoint}} {{.Config.WorkingDir}} {{json .Config.ExposedPorts}}' "$TAA_FHE_SAVE_IMAGE" 2>/dev/null || true)"
  log "packaged image: $committed"
fi

step "saving the image archive to $TAA_FHE_SAVE_ARCHIVE"
if ! is_dry_run; then
  mkdir -p "$(dirname "$TAA_FHE_SAVE_ARCHIVE")"
fi
compressor="gzip"
if ! is_dry_run && command -v pigz >/dev/null 2>&1; then
  compressor="pigz"
fi
save_tmp="${TAA_FHE_SAVE_ARCHIVE}.tmp.$$"
if is_dry_run; then
  log "would run: bash -c set -euo pipefail; docker save $TAA_FHE_SAVE_IMAGE | $compressor -c > $save_tmp && mv -f $save_tmp $TAA_FHE_SAVE_ARCHIVE"
else
  bash -c "set -euo pipefail; docker save $(shell_quote "$TAA_FHE_SAVE_IMAGE") | $compressor -c > $(shell_quote "$save_tmp") && mv -f $(shell_quote "$save_tmp") $(shell_quote "$TAA_FHE_SAVE_ARCHIVE")" \
    || die "failed to export $TAA_FHE_SAVE_IMAGE to $TAA_FHE_SAVE_ARCHIVE"
  [ -f "$TAA_FHE_SAVE_ARCHIVE" ] || die "docker save reported success but $TAA_FHE_SAVE_ARCHIVE is not there"
fi

if [ -n "$REMOTE_TARGET" ]; then
  step "uploading the archive to $REMOTE_TARGET"
  host_archive="$REMOTE_DIR/$(basename "$TAA_FHE_SAVE_ARCHIVE")"
  upload_archive "$TAA_FHE_SAVE_ARCHIVE" "$host_archive"

  step "loading $TAA_FHE_SAVE_IMAGE on $REMOTE_TARGET"
  run docker load -i "$host_archive"
  if ! is_dry_run; then
    host_sh "docker image inspect $(shell_quote "$TAA_FHE_SAVE_IMAGE") >/dev/null 2>&1" \
      || die "docker load finished but $TAA_FHE_SAVE_IMAGE is not present on $REMOTE_TARGET"
    log "image $TAA_FHE_SAVE_IMAGE is present on $REMOTE_TARGET"
    log "archive $host_archive kept on $REMOTE_TARGET"
  fi
else
  log "local run: $TAA_FHE_SAVE_IMAGE was committed into this docker daemon; nothing to upload or load"
fi

if is_dry_run; then
  log "would leave $TAA_FHE_SAVE_ARCHIVE for delivery; nothing is deployed by this run"
else
  archive_size=$(stat -c %s "$TAA_FHE_SAVE_ARCHIVE" 2>/dev/null || echo 0)
  archive_mb=$(awk -v b="$archive_size" 'BEGIN { printf "%.1f", b / 1048576 }')
  printf '\n[deploy-fhe] taa-fhe image packaged\n'
  log "image      : $TAA_FHE_SAVE_IMAGE (base $FHE_IMAGE)"
  log "contents   : $TAA_CONTAINER_WORKDIR/{$BINARY_NAME,start.sh,$TAA_CONFIG_FILE} + $TAA_ENTRYPOINT_CONTAINER"
  log "archive    : $TAA_FHE_SAVE_ARCHIVE (${archive_mb}MB)"
  if [ -n "$REMOTE_TARGET" ]; then
    log "loaded on  : $REMOTE_TARGET"
    log "remote copy: $REMOTE_DIR/$(basename "$TAA_FHE_SAVE_ARCHIVE") (kept)"
  fi
  log "deploy with: TAA_IMAGE=$TAA_FHE_SAVE_IMAGE ./deploy-fhe.sh taa"
  log "standalone : docker run -d --gpus all -p $TAA_PORT:$TAA_PORT"
  log "             -v $HOST_DATA_DIR:$FHE_CONTAINER_DATA_DIR -v $HOST_FHE_REDIS_DIR:$FHE_CONTAINER_DATA_DIR/redis -v $HOST_TAA_STATE_DIR:$HOST_TAA_STATE_DIR"
  log "             -e CONTAINER_DATA_DIR=$FHE_CONTAINER_DATA_DIR -e PLATFORM_IP=<bridge-gateway>:$PLATFORM_PORT $TAA_FHE_SAVE_IMAGE"
fi
exit 0
fi

# ── Preflight ────────────────────────────────────────────────────────────────
if is_dry_run; then
  log "dry-run: nothing will be executed; the tool preflight is skipped"
else
  for cmd in jq sha256sum awk realpath; do
    require_command "$cmd"
  done
  if [ -n "$REMOTE_TARGET" ]; then
    for cmd in docker curl rsync; do
      require_host_command "$cmd"
    done
  else
    for cmd in docker curl; do
      require_command "$cmd"
    done
  fi
  if [ "$DEPLOY_TAA" = 1 ]; then
    [ -f "$TAA_FHE_CONFIG" ] || die "TAA config template not found: $TAA_FHE_CONFIG"
  fi
fi

if [ "$DEPLOY_TAA" = 1 ]; then
  # The GPU is what the FHE worker needs. Reported rather than refused: this
  # script cannot know what else the card is for.
  gpu_report="$(host_capture 'nvidia-smi --query-gpu=name,compute_cap,memory.total,memory.used --format=csv,noheader' 2>/dev/null || true)"
  if [ -n "$gpu_report" ]; then
    while IFS= read -r gpu_line; do
      [ -n "$gpu_line" ] && log "GPU on ${REMOTE_TARGET:-this host}: $gpu_line"
    done <<<"$gpu_report"
  elif ! is_dry_run; then
    warn "nvidia-smi reported no GPU on ${REMOTE_TARGET:-this host}; the FHE worker needs a CUDA device"
  fi

  # A leftover compose stack may still own the host's 58996/58998 and the GPU's
  # memory. This run does not publish 58996, so it can coexist, but the
  # operator should know it is there.
  if ! is_dry_run; then
    legacy="$(host_capture "docker ps --format '{{.Names}}' | grep -E '^fhe-(api|worker|redis)' || true" 2>/dev/null || true)"
    if [ -n "$legacy" ]; then
      warn "leftover compose containers are running: $(printf '%s' "$legacy" | tr '\n' ' '); this run leaves them alone, but they may hold GPU memory and host ports 58996/58998"
    fi
    # 6001 is the one port this run publishes; a listener that is not our
    # container would make docker create fail later, so name it now.
    conflict="$(host_capture "docker ps --format '{{.Names}} {{.Ports}}' | grep -F ':$TAA_PORT->' | grep -Fv $(shell_quote "$TAA_CONTAINER_NAME") || true" 2>/dev/null || true)"
    if [ -n "$conflict" ]; then
      die "host port $TAA_PORT is already published by another container: $(printf '%s' "$conflict" | tr '\n' ' '); stop it first (or set TAA_PORT with a matching server.addr)"
    fi
  fi
fi

# ── Build ────────────────────────────────────────────────────────────────────
if [ "$DEPLOY_TAA" = 1 ] || { [ "$DEPLOY_MOCK" = 1 ] && [ "$DEPLOY_PLATFORM_MOCK" = 1 ]; }; then
step "building the binaries this run deploys"
if [ "$BUILD_BINARIES" != 1 ]; then
  log "--skip-build: using the binaries already at the paths this run deploys"
  if ! is_dry_run; then
    if [ "$DEPLOY_TAA" = 1 ]; then
      [ -f "$TAA_BINARY_PATH" ] || die "--skip-build was given but $TAA_BINARY_PATH does not exist"
    fi
    if [ "$DEPLOY_MOCK" = 1 ] && [ "$DEPLOY_PLATFORM_MOCK" = 1 ]; then
      [ -f "$PLATFORM_MOCK_BINARY_PATH" ] || die "--skip-build was given but $PLATFORM_MOCK_BINARY_PATH does not exist"
    fi
  fi
else
  if [ "$DEPLOY_TAA" = 1 ]; then
    build_binary "$TAA_BINARY_PATH" ./cmd/taa
  fi
  if [ "$DEPLOY_MOCK" = 1 ] && [ "$DEPLOY_PLATFORM_MOCK" = 1 ]; then
    build_binary "$PLATFORM_MOCK_BINARY_PATH" ./tools/platform-mock/cmd/platform-mock
  fi
fi
fi

# ── Upload ───────────────────────────────────────────────────────────────────
if [ "$DEPLOY_TAA" = 1 ] || { [ "$DEPLOY_MOCK" = 1 ] && [ "$DEPLOY_PLATFORM_MOCK" = 1 ]; }; then
step "uploading this run's inputs to ${REMOTE_TARGET:-this host}"
if [ "$DEPLOY_TAA" = 1 ]; then
  upload_models "$FHE_MODELS_SRC" "$STAGED_MODELS_DIR"
  upload_file "$PROJECT_DIR/deploy/start.sh" "$HOST_START_SH" 755
  upload_file "$TAA_BINARY_PATH" "$HOST_TAA_BINARY_PATH" 755
  upload_file "$TAA_ENTRYPOINT_SOURCE" "$HOST_ENTRYPOINT_PATH" 755
fi
if [ "$DEPLOY_MOCK" = 1 ] && [ "$DEPLOY_PLATFORM_MOCK" = 1 ]; then
  upload_file "$PLATFORM_MOCK_BINARY_PATH" "$HOST_PLATFORM_MOCK_BINARY_PATH" 755
fi
fi

# ── Image ────────────────────────────────────────────────────────────────────
if [ "$DEPLOY_TAA" = 1 ]; then
step "preparing the unified image $TAA_IMAGE"
if is_dry_run; then
  if [ "$TAA_IMAGE" = "$FHE_IMAGE" ]; then
    log "would check for $FHE_IMAGE on the deployment host; if absent, verify $FHE_IMAGE_ARCHIVE, upload it to $HOST_FHE_IMAGE_ARCHIVE and docker load it"
  else
    log "would check that $TAA_IMAGE is already present on the deployment host (a taa save run loads it)"
  fi
elif host_sh "docker image inspect $(shell_quote "$TAA_IMAGE") >/dev/null 2>&1"; then
  log "image $TAA_IMAGE is present"
elif [ "$TAA_IMAGE" = "$FHE_IMAGE" ]; then
  if same_path "$FHE_IMAGE_ARCHIVE" "$BUNDLE_IMAGE_ARCHIVE"; then
    verify_one image/latti-server-latest.tar.gz "$FHE_IMAGE_ARCHIVE"
  elif [ -n "$FHE_IMAGE_ARCHIVE_SHA256" ]; then
    verify_one image/latti-server-latest.tar.gz "$FHE_IMAGE_ARCHIVE" "$FHE_IMAGE_ARCHIVE_SHA256"
  else
    warn "FHE_IMAGE_ARCHIVE=$FHE_IMAGE_ARCHIVE is not the archive this bundle ships, so it is NOT covered by SHA256SUMS; set FHE_IMAGE_ARCHIVE_SHA256 to have it verified"
  fi
  upload_archive "$FHE_IMAGE_ARCHIVE" "$HOST_FHE_IMAGE_ARCHIVE"
  run docker load -i "$HOST_FHE_IMAGE_ARCHIVE"
  host_sh "docker image inspect $(shell_quote "$FHE_IMAGE") >/dev/null 2>&1" \
    || die "docker load finished but $FHE_IMAGE is not present on ${REMOTE_TARGET:-this host}"
  log "image $FHE_IMAGE is present"
else
  die "image $TAA_IMAGE is not present on ${REMOTE_TARGET:-this host}; run './deploy-fhe.sh taa save' first, or point TAA_IMAGE at an image that is loaded"
fi
fi

# ── Platform address ─────────────────────────────────────────────────────────
if [ "$DEPLOY_TAA" = 1 ]; then
step "resolving the platform address"
if [ -n "$PLATFORM_IP" ]; then
  log "PLATFORM_IP=$PLATFORM_IP (explicit)"
elif is_dry_run; then
  PLATFORM_IP="<bridge-gateway>:$PLATFORM_PORT"
  log "dry-run: the real run would read the gateway of docker network $TAA_DOCKER_NETWORK and set PLATFORM_IP=<gateway>:$PLATFORM_PORT"
else
  gateway="$(host_capture "docker network inspect $(shell_quote "$TAA_DOCKER_NETWORK") --format '{{(index .IPAM.Config 0).Gateway}}'" 2>/dev/null || true)"
  [ -n "$gateway" ] && [ "$gateway" != "<no value>" ] \
    || die "cannot read the gateway of docker network $TAA_DOCKER_NETWORK; set PLATFORM_IP explicitly"
  PLATFORM_IP="$gateway:$PLATFORM_PORT"
  log "PLATFORM_IP defaulted to $PLATFORM_IP (the gateway of network $TAA_DOCKER_NETWORK)"
fi
case "$PLATFORM_IP" in
  127.0.0.1:*|localhost:*)
    die "PLATFORM_IP=$PLATFORM_IP is the container itself on network $TAA_DOCKER_NETWORK; use the bridge gateway or a reachable platform address"
    ;;
esac
fi

# ── FHE data tree and rendered config ────────────────────────────────────────
if [ "$DEPLOY_TAA" = 1 ]; then
step "staging the FHE data tree and the TAA config"
run mkdir -p "$HOST_DATA_DIR" "$HOST_DATA_DIR/models" "$HOST_DATA_DIR/keys" \
  "$HOST_DATA_DIR/tasks" "$HOST_DATA_DIR/results" "$HOST_DATA_DIR/logs" \
  "$HOST_FHE_REDIS_DIR" "$HOST_TAA_STATE_DIR"
run chmod 755 "$HOST_DATA_DIR" "$HOST_DATA_DIR/models" "$HOST_DATA_DIR/keys" \
  "$HOST_DATA_DIR/tasks" "$HOST_DATA_DIR/results" "$HOST_DATA_DIR/logs"
if is_dry_run; then
  log "would render $TAA_FHE_CONFIG -> $TAA_RENDERED_CONFIG (endpoint, dataDir, keyCacheDir, storage.result, storage.keys)"
else
  host_sh "test -d $(shell_quote "$STAGED_MODELS_DIR/$FHE_MODEL_ID/server")" \
    || die "model $FHE_MODEL_ID is not staged at $STAGED_MODELS_DIR/$FHE_MODEL_ID/server; the handoff bundle carries it under data/models/"
  render_taa_config
fi
fi

# ── platform-mock ────────────────────────────────────────────────────────────
if [ "$DEPLOY_MOCK" = 1 ]; then
step "starting platform-mock on $PLATFORM_ADDR"
if [ "$DEPLOY_PLATFORM_MOCK" != 1 ]; then
  log "--no-platform-mock: nothing started here; TAA registers with PLATFORM_IP=${PLATFORM_IP:-<unset>}"
else
  if is_dry_run; then
    log "would probe http://127.0.0.1:$PLATFORM_PORT/api/register/status, start $HOST_PLATFORM_MOCK_BINARY_PATH if nothing answers, clear its register state, and give TAA PLATFORM_IP=${PLATFORM_IP:-<unset>}"
  else
    if host_sh "curl -fsS -o /dev/null 'http://127.0.0.1:${PLATFORM_PORT}/api/register/status'"; then
      warn "something already answers on 127.0.0.1:$PLATFORM_PORT; reusing it instead of starting a second platform-mock. This run cannot confirm it was started with -allow-empty-attestation, and clearing its register state below affects whatever else is using it."
    else
      host_detach "$REMOTE_DIR/platform-mock.log" "$REMOTE_DIR/platform-mock.pid" \
        "$HOST_PLATFORM_MOCK_BINARY_PATH" \
        -addr "$PLATFORM_ADDR" \
        -state-dir "$PLATFORM_MOCK_STATE_DIR" \
        -upload-dir "$PLATFORM_MOCK_UPLOAD_DIR" \
        -taa-target "http://${TAA_PROBE_HOST}:${TAA_PORT}" \
        -allow-empty-attestation
      wait_for_platform_mock \
        || die "platform-mock did not answer on 127.0.0.1:$PLATFORM_PORT within ${PLATFORM_READY_TIMEOUT}s (log $REMOTE_DIR/platform-mock.log)"
      log "platform-mock is answering on 127.0.0.1:$PLATFORM_PORT (state $PLATFORM_MOCK_STATE_DIR)"
    fi
    host_sh "curl -fsS -o /dev/null -X POST 'http://127.0.0.1:${PLATFORM_PORT}/api/register/reset'" \
      || die "could not clear the register state on http://127.0.0.1:${PLATFORM_PORT}"
  fi
fi
fi

# ── Container ────────────────────────────────────────────────────────────────
if [ "$DEPLOY_TAA" = 1 ]; then
step "creating or reusing $TAA_CONTAINER_NAME"
create_or_reuse_container
TAA_CONTAINER_TOUCHED=1
install_taa_files "$CONTAINER_STATE"

step "waiting for the FHE API inside $TAA_CONTAINER_NAME"
if is_dry_run; then
  log "would wait up to ${FHE_READY_TIMEOUT}s for GET http://127.0.0.1:$FHE_API_PORT/api/v1/health via docker exec python3"
else
  if ! wait_for_fhe_health; then
    host_sh "docker logs --tail 200 $(shell_quote "$TAA_CONTAINER_NAME") 2>&1" || true
    die "the FHE API did not answer /api/v1/health inside $TAA_CONTAINER_NAME within ${FHE_READY_TIMEOUT}s"
  fi
  log "FHE API is ready"
fi

step "activating model $FHE_MODEL_ID"
if is_dry_run; then
  log "would POST http://127.0.0.1:$FHE_API_PORT/api/v1/models/activate?model_id=$FHE_MODEL_ID via docker exec python3"
else
  run docker exec "$TAA_CONTAINER_NAME" python3 -c '
import sys, urllib.parse, urllib.request
url = "http://127.0.0.1:%s/api/v1/models/activate?model_id=%s" % (sys.argv[1], urllib.parse.quote(sys.argv[2]))
urllib.request.urlopen(urllib.request.Request(url, data=b"", method="POST"), timeout=float(sys.argv[3])).read()
' "$FHE_API_PORT" "$FHE_MODEL_ID" "$FHE_ACTIVATE_TIMEOUT" \
    || die "model activation failed for $FHE_MODEL_ID (expected $STAGED_MODELS_DIR/$FHE_MODEL_ID/server)"
  log "model $FHE_MODEL_ID activated"
fi

step "verifying the published ports"
if is_dry_run; then
  log "would require docker port $TAA_CONTAINER_NAME to show $TAA_PORT/tcp and not 58996/tcp"
else
  port_out="$(host_capture "docker port $(shell_quote "$TAA_CONTAINER_NAME")" 2>/dev/null || true)"
  case "$port_out" in
    *"$TAA_PORT/tcp"*) ;;
    *) die "container $TAA_CONTAINER_NAME does not publish $TAA_PORT/tcp (docker port: ${port_out:-empty})" ;;
  esac
  case "$port_out" in
    *"58996/tcp"*) die "container $TAA_CONTAINER_NAME publishes 58996/tcp, which must stay container-internal" ;;
  esac
  log "published ports: $(printf '%s' "$port_out" | tr '\n' ' ')"
fi

step "waiting for TAA to answer on ${TAA_PROBE_HOST}:$TAA_PORT"
if is_dry_run; then
  log "would wait up to ${TAA_READY_TIMEOUT}s for POST http://${TAA_PROBE_HOST}:${TAA_PORT}/v1/taa/health"
else
  if ! wait_for_taa; then
    host_sh "docker exec -i '$TAA_CONTAINER_NAME' sh -lc \"tail -n 60 '$TAA_LOG_FILE' 2>/dev/null || true\"" || true
    die "TAA did not answer POST http://${TAA_PROBE_HOST}:${TAA_PORT}/v1/taa/health within ${TAA_READY_TIMEOUT}s"
  fi
  log "TAA fhe instance is ready"
fi
fi

# ── Registration gate ────────────────────────────────────────────────────────
if [ "$DEPLOY_TAA" = 1 ]; then
step "verifying the platform recorded this instance's registration"
if is_dry_run; then
  if [ "$DEPLOY_PLATFORM_MOCK" != 1 ]; then
    log "--no-platform-mock: nothing to ask"
  elif [ "$DEPLOY_MOCK" = 1 ]; then
    log "would read http://127.0.0.1:$PLATFORM_PORT/api/register/status and require the dockerId this run's identity resolves to"
  else
    log "would read http://127.0.0.1:$PLATFORM_PORT/api/register/status only if something answers there"
  fi
elif [ "$DEPLOY_PLATFORM_MOCK" != 1 ]; then
  log "--no-platform-mock: nothing to ask; this run does not start the platform"
elif [ "$DEPLOY_MOCK" != 1 ] \
  && ! host_sh "curl -fsS -o /dev/null 'http://127.0.0.1:${PLATFORM_PORT}/api/register/status'"; then
  warn "taa-only run: nothing answers on 127.0.0.1:$PLATFORM_PORT, so the registration was not checked; deploy platform-mock (./deploy-fhe.sh platform-mock) or point PLATFORM_IP at a live platform"
else
  if [ -n "$DOCKER_ID" ]; then
    expected_docker_id="$DOCKER_ID"
    expected_source="DOCKER_ID, injected into the container by this run"
  else
    expected_docker_id="$(jq -r '.platform.dockerID // empty' "$TAA_RENDER_OUT" 2>/dev/null || true)"
    expected_source="platform.dockerID in $TAA_FHE_CONFIG, since this run injected none"
  fi
  register_state="$(platform_register_state)"
  registered_id="$(printf '%s' "$register_state" | jq -r '.result.dockerId // empty' 2>/dev/null || true)"
  registered_ok="$(printf '%s' "$register_state" | jq -r '.result.accepted // false' 2>/dev/null || true)"
  if [ -z "$registered_id" ] && [ "$registered_ok" != "true" ]; then
    die "platform-mock on 127.0.0.1:$PLATFORM_PORT recorded no registration at all (expected dockerId '$expected_docker_id' from $expected_source). TAA is up, but the platform never heard from it -- see docker logs $TAA_CONTAINER_NAME and /root/taa/taa.log"
  fi
  if [ "$registered_ok" != "true" ]; then
    die "platform-mock recorded dockerId '$registered_id' and REJECTED it: $(printf '%s' "$register_state" | jq -r '.result.message // "no message"' 2>/dev/null || true)"
  fi
  if [ "$registered_id" != "$expected_docker_id" ]; then
    die "platform-mock recorded dockerId '$registered_id', but this run's identity resolves to '$expected_docker_id' (from $expected_source)"
  fi
  log "registration confirmed: dockerId=$registered_id accepted=true"
  log "platform status: http://127.0.0.1:$PLATFORM_PORT/api/register/status"
fi
fi

# ── Summary ──────────────────────────────────────────────────────────────────
if [ "$DEPLOY_TAA" = 1 ] && ! is_dry_run; then
  printf '\n[deploy-fhe] unified FHE + TAA node deployed\n'
  log "container      : $TAA_CONTAINER_NAME (image $TAA_IMAGE, network $TAA_DOCKER_NETWORK)"
  log "FHE API        : http://127.0.0.1:$FHE_API_PORT (container-internal, not published; model $FHE_MODEL_ID activated)"
  log "TAA            : http://${TAA_PROBE_HOST}:${TAA_PORT}/v1/taa/health (published)"
  log "FHE data dir   : $HOST_DATA_DIR (mounted at $FHE_CONTAINER_DATA_DIR, shared with TAA's rendered paths)"
  log "TAA state dir  : $HOST_TAA_STATE_DIR (SM2 key pair and sealed state; on a bind of its own)"
  log "platform       : PLATFORM_IP=$PLATFORM_IP"
  log "logs           : docker logs -f $TAA_CONTAINER_NAME"
  log "taa log        : docker exec $TAA_CONTAINER_NAME tail -f $TAA_LOG_FILE"
  log "stop           : docker rm -f $TAA_CONTAINER_NAME"
fi
if [ "$DEPLOY_MOCK" = 1 ] && [ "$DEPLOY_TAA" = 0 ] && ! is_dry_run; then
  printf '\n[deploy-fhe] platform-mock deployed\n'
  log "platform-mock  : http://127.0.0.1:${PLATFORM_PORT} (state $PLATFORM_MOCK_STATE_DIR)"
  log "platform log   : $REMOTE_DIR/platform-mock.log"
fi

if is_dry_run; then
  log "dry-run complete: nothing was executed"
fi
