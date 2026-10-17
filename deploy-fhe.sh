#!/usr/bin/env bash
# Deploy the FHE side on a GPU host: import the image, stage the runtime and the
# models into the shared directory, start the api/worker/redis stack, then start
# this host's TAA instance with server.type=fhe, under the same supervisor
# deploy.sh installs.
#
# This script owns the FHE side; deploy.sh owns the TAA image itself.
# -E (errtrace) is what makes the ERR trap below reach the run/run_in/render
# functions and the few subshells: without it bash does not inherit the ERR trap
# into a function, and every external command here runs inside one, so the trap
# never fired and every failure exited silently.
set -Eeuo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── FHE side ─────────────────────────────────────────────────────────────────
# The handoff bundle is the delivery directory produced by the FHE team. Its
# internal layout (image/, third_party/, data/models/, deploy/docker/) is what
# every path below assumes.
HANDOFF_DIR="${HANDOFF_DIR:-$PROJECT_DIR/latti-fhe-handoff}"
FHE_IMAGE="${FHE_IMAGE:-latti/latti-server:latest}"
# The archive the bundle ships, named once: it is both the default for
# FHE_IMAGE_ARCHIVE and the file the bundle's own SHA256SUMS entry covers, and the
# verification step below has to tell the two apart without them drifting.
BUNDLE_IMAGE_ARCHIVE="$HANDOFF_DIR/image/latti-server-latest.tar.gz"
FHE_IMAGE_ARCHIVE="${FHE_IMAGE_ARCHIVE:-$BUNDLE_IMAGE_ARCHIVE}"
# Expected digest for an archive the bundle does not ship; empty means the
# operator vouched for neither and the verification step says so.
FHE_IMAGE_ARCHIVE_SHA256="${FHE_IMAGE_ARCHIVE_SHA256:-}"
FHE_MODEL_ID="${FHE_MODEL_ID:-cifar10}"

# ── TAA side ─────────────────────────────────────────────────────────────────
# Names mirror deploy.sh's docker target so the two scripts describe the same
# container and the same working directory inside it.
TAA_IMAGE="${TAA_IMAGE:-taa-env:slim-v2}"
TAA_CONTAINER_NAME="${TAA_CONTAINER_NAME:-taa-fhe}"
TAA_DOCKER_NETWORK="${TAA_DOCKER_NETWORK:-host}"
TAA_CONTAINER_WORKDIR="${TAA_CONTAINER_WORKDIR:-/root/taa}"
# taa resolves an unset --config from config.DefaultFileName, which is
# "taa-config.json" relative to its own working directory, and deploy/start.sh
# starts it with no --config at all.
TAA_CONFIG_FILE="taa-config.json"
BINARY_NAME="${BINARY_NAME:-taa}"
TAA_LOG_FILE="${TAA_LOG_FILE:-$TAA_CONTAINER_WORKDIR/taa.log}"
# The supervisor's command line as a pgrep/pkill pattern, bracketed in the first
# letter and in the dot so that it matches start.sh without matching the shell that
# carries the pattern. Written without a backslash on purpose: under --remote the
# string crosses two more shells, and '[.]' is one literal character there where '\\.'
# depends on every layer agreeing about backslashes.
SUPERVISOR_PATTERN='[s]tart[.]sh'
# Must match server.addr in $TAA_FHE_CONFIG; the readiness probe below, and the
# URL the FHE containers call back on, both use it.
TAA_PORT="${TAA_PORT:-6001}"
TAA_READY_TIMEOUT="${TAA_READY_TIMEOUT:-120}"
TAA_READY_INTERVAL="${TAA_READY_INTERVAL:-2}"
# Seconds to wait for the FHE api to answer after `up -d` returns; see wait_for_fhe_stack.
FHE_READY_TIMEOUT="${FHE_READY_TIMEOUT:-120}"

# ── Where the deployment happens ─────────────────────────────────────────────
# Remote is the default: this script runs on an operator workstation while the
# FHE worker needs a CUDA host, so there is nothing useful to deploy locally on
# the machine that launches it. REMOTE_TARGET defaults to
# $REMOTE_USER@$REMOTE_HOST, and every host-side command below becomes one ssh
# invocation. `--local` empties it and turns the same commands into plain local
# ones; the distinction lives only in ssh_host/run/run_in/host_sh below, which
# is what keeps the rest of the script from having to care.
#
# These names are deploy.sh's, deliberately: an operator already exporting
# REMOTE_HOST/TARGET_PASSWORD for the TAA side does not restate them here.
REMOTE_HOST="${REMOTE_HOST:-172.16.10.178}"
REMOTE_USER="${REMOTE_USER:-root}"
PASSWORD="${TARGET_PASSWORD:-Osrd@2026}"
REMOTE_DIR="${REMOTE_DIR:-/root/taa-fhe}"
REMOTE_TARGET="${REMOTE_TARGET:-${REMOTE_USER}@${REMOTE_HOST}}"
# Where the bundle is copied to on the remote host. Derived here rather than
# after the upload so the guard below can refuse a target that would collide
# with a directory the upload's --delete is about to write into.
REMOTE_HANDOFF_DIR="${REMOTE_HANDOFF_DIR:-$REMOTE_DIR/latti-fhe-handoff}"

# ── Platform side ────────────────────────────────────────────────────────────
# platform-mock stands in for the control plane, so a full chain (TAA registers,
# the platform drives tasks, results come back) can be run without one. 18081,
# not deploy.sh's 18080: on the shared FHE host 18080 is held by ccs-node-agent.
PLATFORM_PORT="${PLATFORM_PORT:-18081}"
PLATFORM_ADDR="${PLATFORM_ADDR:-0.0.0.0:$PLATFORM_PORT}"
PLATFORM_MOCK_BINARY_NAME="${PLATFORM_MOCK_BINARY_NAME:-platform-mock}"
PLATFORM_MOCK_BINARY_PATH="${PLATFORM_MOCK_BINARY_PATH:-$PROJECT_DIR/bin/$PLATFORM_MOCK_BINARY_NAME}"
PLATFORM_MOCK_STATE_DIR="${PLATFORM_MOCK_STATE_DIR:-$REMOTE_DIR/platform-mock-state}"
PLATFORM_MOCK_UPLOAD_DIR="${PLATFORM_MOCK_UPLOAD_DIR:-$REMOTE_DIR/platform-mock-files}"
PLATFORM_READY_TIMEOUT="${PLATFORM_READY_TIMEOUT:-30}"
DEPLOY_PLATFORM_MOCK=1
# TAA's own binary: built here and pushed into the container, so a deployment
# runs the commit it was launched from rather than whatever the base image
# happens to carry. The container's copy is not installed otherwise -- nothing
# else in this script writes one.
TAA_BINARY_PATH="${TAA_BINARY_PATH:-$PROJECT_DIR/bin/taa}"
BUILD_BINARIES=1

# ── Packaging the taa-fhe image (taa save) ───────────────────────────────────
# A save run builds no deployment: it bakes the TAA binary and its supervisor
# into $TAA_IMAGE, tags the result here and exports it as an archive beside the
# base-image archives deploy.sh writes. The tag carries the date for the same
# reason deploy.sh's does -- an archive is a snapshot, and rebuilding must not
# silently replace the one an earlier delivery was made from. The config is
# deliberately not baked in: it carries the callback token and this deployment's
# paths, and deploy-fhe.sh taa copies the rendered one in at start time.
SAVE_DATE_TAG="$(date +%Y%m%d)"
TAA_FHE_SAVE_IMAGE="${TAA_FHE_SAVE_IMAGE:-taa-fhe:${SAVE_DATE_TAG}}"
TAA_FHE_SAVE_ARCHIVE="${TAA_FHE_SAVE_ARCHIVE:-$PROJECT_DIR/deploy/taa-fhe-${SAVE_DATE_TAG}.tar.gz}"
# The archive a save run imports when the base image is not in the local daemon.
# Same default and purpose as deploy.sh's LOCAL_DOCKER_IMAGE_ARCHIVE: a machine
# that only received the delivery files can still package without pulling.
TAA_BASE_IMAGE_ARCHIVE="${TAA_BASE_IMAGE_ARCHIVE:-$PROJECT_DIR/deploy/taa-env-slim-v2.tar.gz}"
SAVE_ACTION=0
SAVE_BUILDER_CONTAINER=""

# The identity the TAA container is given with -e. On a type=fhe instance these
# win over the config file (internal/config, applyFHEIdentityOverride), so they
# are the channel a deployment uses to say where this instance registers.
#
# PLATFORM_IP is defaulted only when this run starts the mock itself, because
# only then does the script know where the mock is; DOCKER_ID is never
# defaulted, so the template's platform block stays the fallback it is meant to
# be. Both are left to the template when unset, which is a working default
# rather than a half-configured instance.
PLATFORM_IP="${PLATFORM_IP:-}"
DOCKER_ID="${DOCKER_ID:-}"

DRY_RUN="${DRY_RUN:-0}"

STEP=0
log()  { printf '[deploy-fhe] %s\n' "$*"; }
warn() { printf '[deploy-fhe] WARNING: %s\n' "$*" >&2; }
die()  { printf '[deploy-fhe] ERROR: %s\n' "$*" >&2; report_left_running "the run failed"; exit 1; }
step() { STEP=$((STEP + 1)); printf '\n[deploy-fhe] === %s) %s ===\n' "$STEP" "$*"; }

# ── What a failure leaves behind ─────────────────────────────────────────────
# The steps below start things that outlive this script, and nothing here tears
# anything down on the way out: a run may be deliberately re-running against a
# stack that must stay up. The contract is therefore only that no exit path is
# silent about the state it leaves, so die() and the traps name what is still
# running and the exact command that stops it.
FHE_STACK_TOUCHED=0
TAA_CONTAINER_TOUCHED=0
TAA_SUPERVISOR_STARTED=0
REPORTING=0

report_left_running() {
  # Re-entrancy guard: the reporter runs from a signal/ERR trap as well as from
  # die(), and a printf failing inside it must not re-enter itself.
  [ "$REPORTING" = 0 ] || return 0
  REPORTING=1
  local node_dir="${NODE_DOCKER_DIR:-$HANDOFF_DIR/deploy/docker}"
  printf '\n[deploy-fhe] state left on the host (%s):\n' "$1" >&2
  if [ "$FHE_STACK_TOUCHED$TAA_CONTAINER_TOUCHED" = "00" ]; then
    printf '[deploy-fhe]   nothing this run started is still running.\n' >&2
    return 0
  fi
  if [ "$FHE_STACK_TOUCHED" = 1 ]; then
    printf '[deploy-fhe]   FHE stack : the stack step ran run-node.sh up -d; if the containers are up, they were left running\n' >&2
    printf '[deploy-fhe]               look : (cd %s && ./scripts/run-node.sh ps)\n' "$node_dir" >&2
    printf '[deploy-fhe]               stop : (cd %s && ./scripts/run-node.sh down)\n' "$node_dir" >&2
  else
    printf '[deploy-fhe]   FHE stack : not started by this run\n' >&2
  fi
  if [ "$TAA_CONTAINER_TOUCHED" = 1 ]; then
    if [ "$TAA_SUPERVISOR_STARTED" = 1 ]; then
      printf '[deploy-fhe]   TAA       : container %s runs the start.sh supervisor, which restarts taa every 10s\n' "$TAA_CONTAINER_NAME" >&2
    else
      printf '[deploy-fhe]   TAA       : container %s exists, with no supervisor started in it\n' "$TAA_CONTAINER_NAME" >&2
    fi
    printf '[deploy-fhe]               stop : docker rm -f %s\n' "$TAA_CONTAINER_NAME" >&2
  else
    printf '[deploy-fhe]   TAA       : no container was created by this run\n' >&2
  fi
  printf '[deploy-fhe] this script stops none of it; run the stop commands yourself to remove it.\n' >&2
}

on_error() {
  local rc="$1"
  trap - ERR
  # With -E the trap is inherited by subshells too, and a subshell's REPORTING is
  # its own copy: reporting there would leave the parent's REPORTING at 0 and the
  # parent would report the same failure a second time (run_in's `( cd ... && ... )`
  # fails exactly once but is entered twice). The subshell leaves the report to the
  # parent, which sees the subshell's status through `set -e`.
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
  # 130 is the SIGINT convention (128 + 2); TERM is 143, so the signal's own
  # number decides the status instead of reusing INT's for both.
  num="$(kill -l "$sig" 2>/dev/null)" || num=2
  exit $((128 + num))
}
# Without these, a `die` after step 4 or a Ctrl-C during `docker load` leaves the
# host in a state only the operator's memory knows about.
trap 'on_error $?' ERR
trap 'on_signal INT' INT
trap 'on_signal TERM' TERM

# The rendered config carries the callback token, and a --remote run writes it to a
# private directory here before uploading it. No exit path may leave that behind, so
# the cleanup hangs off EXIT, which every path above ends in -- including the ones
# that exit through die(), a signal, or set -e.
TAA_RENDER_TMPDIR=""
cleanup_render_out() {
  [ -n "${TAA_RENDER_TMPDIR:-}" ] || return 0
  rm -rf "$TAA_RENDER_TMPDIR"
  TAA_RENDER_TMPDIR=""
}
# The save path assembles its image in a throwaway container on this machine.
# Removing it from a trap rather than at the end of the happy path is what keeps
# a failed commit or an interrupted save from leaving a multi-gigabyte container
# behind. An empty name means the run never got that far.
cleanup_save_builder() {
  [ -n "${SAVE_BUILDER_CONTAINER:-}" ] || return 0
  local name="$SAVE_BUILDER_CONTAINER"
  SAVE_BUILDER_CONTAINER=""
  is_dry_run && return 0
  docker rm -f "$name" >/dev/null 2>&1 || true
}
trap 'cleanup_render_out; cleanup_save_builder' EXIT

is_dry_run() { [ "$DRY_RUN" = "1" ]; }

# Every external command goes through run/run_in so that DRY_RUN=1 prints the
# plan instead of touching the host.
run() {
  if is_dry_run; then
    # $* rather than the shell_quote form that actually goes over the wire: this line
    # is read by an operator, and every %q escape of a space or a quote costs more than
    # the fidelity is worth. An argument carrying a space is the one case where the two
    # disagree, and it disagrees in the harmless direction -- the real command quotes.
    if [ -n "$REMOTE_TARGET" ]; then
      printf '[deploy-fhe] would run on %s: %s\n' "$REMOTE_TARGET" "$*"
    else
      printf '[deploy-fhe] would run: %s\n' "$*"
    fi
    return 0
  fi
  ssh_host "$@"
}

# Same, for the one command that has to execute in another directory (rsync and
# compose both resolve paths relative to their own working directory).
run_in() {
  local dir="$1"
  shift
  if is_dry_run; then
    if [ -n "$REMOTE_TARGET" ]; then
      printf '[deploy-fhe] would run on %s: (cd %s && %s)\n' "$REMOTE_TARGET" "$dir" "$*"
    else
      printf '[deploy-fhe] would run: (cd %s && %s)\n' "$dir" "$*"
    fi
    return 0
  fi
  if [ -z "$REMOTE_TARGET" ]; then
    ( cd "$dir" && "$@" )
    return
  fi
  # One ssh, and the remote login shell does the cd: ssh already runs its command
  # through that shell, so a second sh -lc would only add a quoting layer.
  local cmd
  printf -v cmd 'cd %q && %s' "$dir" "$(shell_quote "$@")"
  "${REMOTE_SSH[@]}" "$REMOTE_TARGET" "$cmd"
}

# One command on the machine running this script, through the same dry-run
# printer the host helpers use. The save action builds its image here rather
# than where it is deployed, so it must not go through run/run_in.
run_local() {
  if is_dry_run; then
    printf '[deploy-fhe] would run: %s\n' "$*"
    return 0
  fi
  "$@"
}

# ── The two hosts ────────────────────────────────────────────────────────────
# Everything that has to happen on the deployment host goes through one of these, so
# "which machine runs this" is decided in a handful of functions instead of at thirty
# call sites: ssh_host/run/run_in for an argv, host_sh/host_capture for a shell string
# or a value, host_detach for something that outlives the ssh, and upload_file/
# upload_tree for the files themselves. Everything else in this script is either local
# by nature (jq, go build, the bundle's own checksums) or says in a comment why.
#
# The one-shot commands get ssh -n (stdin from /dev/null): nothing here streams input
# to the remote, and without it the first ssh in a loop would swallow the rest of this
# script's stdin. See SSH_COMMON_OPTS for why the uploads must not get it.
# Options every ssh/scp to the deployment host shares. -n is deliberately not one
# of them: it belongs to the one-shot commands below (without it the first ssh in
# a loop swallows the rest of this script's stdin), and it must not reach the
# uploads -- rsync's transport *is* the ssh child's own stdin and stdout, and
# ssh -n redirects that from /dev/null, so the transfer would move nothing.
SSH_COMMON_OPTS=(
  -q
  -o LogLevel=ERROR
  -o StrictHostKeyChecking=accept-new
  -o UserKnownHostsFile="$HOME/.ssh/known_hosts"
)
SSH_OPTS=(-n "${SSH_COMMON_OPTS[@]}")

# Renders an argv as one line the remote login shell re-parses into the same
# words. %q is what keeps a path with a space, a quote or a $ in it intact
# across the trip; the login shell on the hosts this targets is bash.
shell_quote() {
  local out="" arg q
  for arg in "$@"; do
    printf -v q '%q' "$arg"
    out+="$q "
  done
  printf '%s' "${out% }"
}

# sshpass only when a password is set, so key or agent authentication works by
# clearing TARGET_PASSWORD rather than being second-class. scp and rsync need the
# same wrapper, so the three invocations are built here rather than at each call.
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
  # -q: scp's progress meter is one line per file rewritten in place, and the files
  # it carries here are small; the 300 MiB bundle goes over rsync instead.
  REMOTE_SCP=("${prefix[@]}" scp -q "${SSH_COMMON_OPTS[@]}")
  # The transport rsync is given with -e, which it splits and runs as a shell
  # command rather than reading as an argv -- hence its own rendering of the same
  # options. -q and the log-level option are dropped here: rsync wants ssh's own
  # diagnostics on a transfer that fails, and SSH_COMMON_OPTS' -q would silence them.
  RSYNC_SSH=""
  [ -n "$PASSWORD" ] && RSYNC_SSH="sshpass -p $(shell_quote "$PASSWORD") "
  RSYNC_SSH+="ssh $(shell_quote -o LogLevel=ERROR -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$HOME/.ssh/known_hosts")"
}

# One command on the deployment host, argv and all.
ssh_host() {
  if [ -z "$REMOTE_TARGET" ]; then
    "$@"
  else
    "${REMOTE_SSH[@]}" "$REMOTE_TARGET" "$(shell_quote "$@")"
  fi
}

# For the commands that are a pipeline or a shell builtin rather than an argv --
# `docker ps | grep -Fxq`, `[ -w path ]`, a pgrep inside the container. They run
# under bash -c locally so the caller writes one form for both hosts, and the
# exit status comes back through ssh, which is what makes `if host_sh ...` work.
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

# run_node runs a run-node.sh subcommand with the stack-shaping values handed to it
# on the command line instead of by inheritance.
#
# The exports above are what point the stack at the tree this script stages, and they
# are enough while this script and the stack share one environment. A --remote run is
# the case where they do not: every host-side command goes over ssh, ssh carries no
# environment, and run-node.sh then falls back to the bundle's own env/node.local.env
# -- absolute paths belonging to the machine the bundle was assembled on. The stack
# comes up healthy against a tree TAA never writes to and activation still succeeds,
# because the bundle carries the same model, so the only symptom is tasks that never
# finish. Naming the values here is the form that survives the hop, and it is
# equivalent to the export it replaces because run-node.sh restores every name it
# finds already set.
run_node() {
  local assignments="" name
  # Only the names this run decided. run-node.sh's restore rule is `[[ -v $name ]]`,
  # so assigning an empty value wins over the env file exactly as a good one does --
  # and NODE_IP_OVERRIDE is deliberately unset rather than emptied when this run
  # could not derive an address.
  for name in HOST_DATA_DIR HOST_RUNTIME_DIR HOST_REDIS_DIR API_HOST_PORT NODE_ID_OVERRIDE NODE_IP_OVERRIDE; do
    if [ -n "${!name:-}" ]; then
      assignments+="$(printf '%q ' "$name=${!name}")"
    fi
  done
  local args="" arg
  for arg in "$@"; do
    args+="$(printf ' %q' "$arg")"
  done
  host_sh "cd $(printf %q "$NODE_DOCKER_DIR") && env ${assignments}./scripts/run-node.sh$args"
}

# host_sh for a value rather than a status. A remote --dry-run reads nothing and
# says so: a dry run has to stay runnable without reaching the host at all, and
# every caller below treats an empty answer as "this run could not derive one"
# rather than as a value. The local dry run keeps reading, as it always has.
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
  local name="$1"
  command -v "$name" >/dev/null 2>&1 || die "command '$name' is required but not installed or not in PATH"
}

# Builds one binary on the machine running this script. Deliberately not one of the
# host helpers: a --remote run builds here and uploads, so what reaches the container
# is the commit this script was launched from rather than whatever the deployment host
# has checked out. CGO_ENABLED=0 and GOOS=linux to match the images it lands in.
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

# What require_command is for the deployment host: the same check, run there. Every
# name checked this way is one a host-side command below invokes (docker, curl,
# rsync), so checking it here rather than on the machine running this script is the
# difference between a preflight and a guess.
require_host_command() {
  local name="$1"
  host_sh "command -v $(shell_quote "$name") >/dev/null 2>&1" \
    || die "command '$name' is required on ${REMOTE_TARGET:-this host} but is not installed or not in PATH there"
}

# Starts a command on the deployment host that has to outlive the shell that starts
# it. The three redirections are what let ssh return rather than hold the channel
# open for as long as the process lives: ssh waits for every writer of its stdout
# and stderr to exit, and a daemon that keeps them keeps ssh with it.
host_detach() {
  local log="$1" pidfile="$2"
  shift 2
  if is_dry_run; then
    printf '[deploy-fhe] would start on %s: %s > %s 2>&1 & (detached)\n' \
      "${REMOTE_TARGET:-this host}" "$(shell_quote "$@")" "$log"
    return 0
  fi
  if [ -z "$REMOTE_TARGET" ]; then
    nohup "$@" >"$log" 2>&1 </dev/null &
    printf '%s\n' "$!" >"$pidfile"
  else
    "${REMOTE_SSH[@]}" "$REMOTE_TARGET" \
      "nohup $(shell_quote "$@") > $(shell_quote "$log") 2>&1 < /dev/null & echo \$! > $(shell_quote "$pidfile")" >/dev/null \
      || die "failed to start $(shell_quote "$@") on $REMOTE_TARGET"
  fi
  log "started '$1' on ${REMOTE_TARGET:-this host} (pid $(host_capture "cat $(shell_quote "$pidfile")" 2>/dev/null || true), log $log)"
}

# Copies one file to a path on the deployment host. Writes a .new beside the
# destination and renames onto it, so a reader on that host -- the FHE stack, or TAA
# reading its rendered config -- never catches a half-written file. $3 is the mode,
# defaulting to what scp would have left.
upload_file() {
  local src="$1" dest="$2" mode="${3:-}"
  [ -n "$REMOTE_TARGET" ] || return 0
  # The existence check comes after the dry-run return on purpose: a dry run has to
  # stay runnable on a host where nothing has been built or unpacked yet -- it is what
  # an operator runs to see what a deployment would do -- so it prints the copy it
  # would make instead of refusing over a file the real run would have produced.
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

# The same for a whole tree, which is what the handoff bundle is. --delete is here
# for the reason the staging step keeps it: a re-upload has to match the bundle that
# was delivered rather than accumulate files from an older handoff, and a stale
# third_party tree is a silently wrong deployment. The guard on REMOTE_HANDOFF_DIR
# below is what keeps that from being destructive.
upload_tree() {
  local src="$1" dest="$2"
  [ -n "$REMOTE_TARGET" ] || return 0
  if is_dry_run; then
    printf '[deploy-fhe] would rsync -a --delete %s/ -> %s:%s/\n' "$src" "$REMOTE_TARGET" "$dest"
    return 0
  fi
  [ -d "$src" ] || die "cannot upload $src: no such directory"
  host_sh "mkdir -p $(shell_quote "$dest")" || die "cannot create $dest on $REMOTE_TARGET"
  rsync -a --delete -e "$RSYNC_SSH" "$src/" "$REMOTE_TARGET:$dest/" \
    || die "failed to upload $src to $REMOTE_TARGET:$dest"
  log "uploaded $src/ -> $REMOTE_TARGET:$dest/"
}

# Copies an image archive to the deployment host. Deliberately not upload_file:
# that one writes a .new beside the destination and renames, which is right for a
# small file a reader may catch mid-write and wrong for an archive of tens of
# gigabytes -- it needs the space twice. rsync's --partial/--inplace let a
# transfer that failed resume instead of starting over, and nothing on the host
# reads the archive until `docker load` runs below.
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

usage() {
  cat <<EOF
Usage: $(basename "$0") [fhe|taa|platform-mock] [save] [options]

Deploy the FHE side on a GPU host: import the Latti server image from the handoff
bundle, stage the FHE runtime and models, start the api/worker/redis stack, then
start that host's TAA instance with server.type=fhe under the deploy/start.sh
supervisor. The deployment host is \${REMOTE_USER}@\${REMOTE_HOST} by default --
this script runs on an operator workstation, and the FHE worker needs the CUDA
host. platform-mock is deployed there too by the bare form, which is what makes an
end-to-end registration test possible.

Arguments:
  fhe
      Deploy only the three FHE services (fhe-api, fhe-worker, fhe-redis):
      verify and load the server image, stage the runtime and models, start
      the stack, wait for its health endpoint and activate the model. TAA,
      platform-mock and the binaries they need are not built, uploaded or
      started.
  taa
      Deploy only the TAA instance: build and upload the TAA binary and its
      supervisor, render the config, create the container and start it, then
      wait for its health endpoint. The FHE stack and platform-mock are
      assumed to be running already; model activation is not repeated, and
      the registration check runs only when something answers on
      PLATFORM_PORT.
  platform-mock
      Deploy only platform-mock: build and upload its binary, start it if
      nothing answers on PLATFORM_PORT, and clear its register state. No FHE
      image, runtime, model or TAA container is touched.
  (no argument)
      Deploy the FHE stack, platform-mock and TAA, in that order. This is the
      original behaviour.

  fhe, taa and platform-mock are mutually exclusive; passing two is refused.

  save
      Package instead of deploy, and only with the taa argument: build the TAA
      binary, bake it, its supervisor and the rendered config into the base
      image (TAA_IMAGE), tag the result TAA_FHE_SAVE_IMAGE and export it as a
      gzipped archive at TAA_FHE_SAVE_ARCHIVE, which defaults to
      deploy/taa-fhe-<date>.tar.gz. The image is assembled and saved on this
      machine, so the archive lands in the local deploy/ directory. On the
      default remote target the archive is then uploaded and loaded into the
      host's docker daemon automatically; the uploaded copy is kept at
      REMOTE_DIR so a later reload or deployment does not upload it again.
      Nothing is started. The config is rendered from TAA_FHE_CONFIG with the
      callback URL/token and the data/state paths below, then placed at
      \$TAA_CONTAINER_WORKDIR/$TAA_CONFIG_FILE, so the image boots without the
      taa argument's copy step; a taa run still renders and copies its own
      config over it. The image therefore carries TAA_CALLBACK_TOKEN.

Options:
  -n, --dry-run
      Print the commands that would run and execute nothing. Needs no GPU, no
      FHE stack and no Docker. With the default remote target it prints the ssh
      command lines and still connects to nothing.
  --remote
      Deploy to \${REMOTE_USER}@\${REMOTE_HOST}. This is the default, and the
      flag is accepted for explicitness; REMOTE_HOST, REMOTE_USER,
      TARGET_PASSWORD, REMOTE_DIR and REMOTE_HANDOFF_DIR override the target,
      and the first three are the names deploy.sh uses for the same host.
  --local
      Deploy on the machine running this script instead. Needs a CUDA GPU and
      a writable HOST_DATA_DIR/HOST_TAA_STATE_DIR there.
  --no-platform-mock
      Do not build, upload or start platform-mock, and do not check the
      registration at the end. Then nothing here answers at PLATFORM_IP, so set
      PLATFORM_IP (or rely on the template's platform block) to point TAA at a
      platform that is already running. Not valid with the platform-mock
      argument.
  --skip-build
      Do not run 'go build' for the TAA binary or platform-mock; use what is
      already at TAA_BINARY_PATH / PLATFORM_MOCK_BINARY_PATH, which then have to
      exist.
  -h, --help
      Display this help documentation.

Environment:
  REMOTE_HOST=${REMOTE_HOST}, REMOTE_USER=${REMOTE_USER}
      Host and user --remote targets. TARGET_PASSWORD is the ssh password (empty
      means key or agent authentication); REMOTE_DIR=\${REMOTE_DIR} is where this
      run keeps the uploaded bundle, the binaries and platform-mock's state, and
      REMOTE_HANDOFF_DIR=\${REMOTE_HANDOFF_DIR} is the uploaded bundle itself.
  PLATFORM_IP=${PLATFORM_IP}
      Passed to the TAA container as PLATFORM_IP, which on a type=fhe instance
      wins over the config file's platform block. Defaulted to
      127.0.0.1:\${PLATFORM_PORT} when this run starts platform-mock itself, since
      only then is the address known; left unset otherwise, so the template's
      platform.ip decides.
  DOCKER_ID=${DOCKER_ID}
      Passed the same way. Never defaulted: the template's platform.dockerID is
      the fallback, and registration refuses an empty dockerId outright. The last
      step of a run requires the platform to have recorded this value, from
      whichever of the two sources applies.
  PLATFORM_PORT=${PLATFORM_PORT}
      Port platform-mock listens on (PLATFORM_ADDR=\${PLATFORM_ADDR}). Not
      deploy.sh's 18080 -- on the shared FHE host that port is already taken.
  PLATFORM_MOCK_BINARY_PATH=${PLATFORM_MOCK_BINARY_PATH}
      platform-mock binary. Built here unless --skip-build, uploaded to
      \${REMOTE_DIR}/bin/ on a remote run.
  PLATFORM_MOCK_STATE_DIR=${PLATFORM_MOCK_STATE_DIR}
      Register/report state platform-mock persists. This run clears the register
      state before TAA starts, so the registration it checks at the end is one
      TAA actually made.
  PLATFORM_MOCK_UPLOAD_DIR=${PLATFORM_MOCK_UPLOAD_DIR}
      Directory platform-mock stores uploads in, served at /files/.
  PLATFORM_READY_TIMEOUT=${PLATFORM_READY_TIMEOUT}
      Seconds to wait for platform-mock to answer after this run starts it.
  TAA_BINARY_PATH=${TAA_BINARY_PATH}
      TAA binary. Built here unless --skip-build, copied into the container at
      \$TAA_CONTAINER_WORKDIR/$BINARY_NAME on every run: nothing else installs one,
      so without it the image's own binary would serve.
  HANDOFF_DIR=${HANDOFF_DIR}
      Delivery bundle (image/, third_party/, data/, deploy/docker/). On a remote
      run this script's copy is verified here and uploaded; the deployment host
      then reads the copy under REMOTE_HANDOFF_DIR.
  HOST_DATA_DIR=${HOST_DATA_DIR:-}
      Shared directory the FHE stack mounts as /data and TAA reads as fhe.dataDir.
      The script exports it (and HOST_RUNTIME_DIR, HOST_REDIS_DIR, API_HOST_PORT
      below) before starting the stack, and run-node.sh keeps an exported value
      over the one in env/node.local.env -- so the stack uses this path whatever
      the env file says, and the stack and TAA share one directory by
      construction rather than by hand-alignment.
  HOST_TAA_STATE_DIR=${HOST_TAA_STATE_DIR:-/opt/taa-state}
      Directory TAA's own instance state lives in, mounted at itself as a second
      bind; the config's storage.keys is the keys/ directory inside it, so the SM2
      key pair and state.sealed land here. Deliberately not inside HOST_DATA_DIR:
      that tree is what the FHE stack mounts as /data, and these are TAA's identity
      rather than anything the service is meant to read. It has to be persistent for
      the same reason the derived paths do - the container is recreated whenever the
      image or either bind changes - and losing it is the quietest of the three,
      because the config still validates: state.sealed holds the imported-model
      checksum, so a fresh directory makes the instance reject every data import
      with "no model imported yet" while the model package sits untouched on the
      data bind.
  HOST_RUNTIME_DIR=${HOST_RUNTIME_DIR:-}
      Where the FHE runtime from the bundle is staged; mounted read-only by the
      stack. Defaults to \${REMOTE_DIR}/latti-runtime on the default remote run
      (a directory of its own, because the upload is an rsync --delete into
      REMOTE_HANDOFF_DIR), and to the local bundle's third_party/latti-ai-runtime
      under --local. 'rsync -a --delete' targets it, so it must not be the data
      directory, must not contain it and must not be inside it -- nor may it
      contain or be inside HOST_TAA_STATE_DIR: the run refuses otherwise, before
      anything is deleted.
  HOST_REDIS_DIR=${HOST_REDIS_DIR:-${HOST_DATA_DIR:-/opt/fhe-data}/redis}
      Redis AOF directory the stack mounts as /data in fhe-redis. Defaults to a
      directory inside HOST_DATA_DIR; set it to keep an AOF that already exists
      elsewhere.
  TAA_FHE_CONFIG=${TAA_FHE_CONFIG:-}
      TAA configuration template rendered with the callback URL/token below and
      the data/state paths. Defaults to $PROJECT_DIR/configs/taa-fhe.json; an
      override is used as given. A save run bakes the rendered result into the
      image, so the template is an input to both the taa and the save path.
  TAA_CALLBACK_BASE_URL=${TAA_CALLBACK_BASE_URL:-}
      Base URL of this TAA instance as the FHE containers reach it. Defaults to
      http://\${REMOTE_HOST}:\${TAA_PORT} on the default remote run; a local run
      has to set it. Required by the save path too, because the config baked
      into the image carries it. Set it to 'auto' to have TAA derive the address
      at startup (server.addr port plus the address this instance resolves
      itself to); that is the value that survives a Pod being recreated with a
      new Pod IP.
  TAA_CALLBACK_TOKEN=${TAA_CALLBACK_TOKEN:-}
      Shared secret the FHE service presents on the callback endpoint. A default
      is set in this script so the plain invocation is complete; set it in the
      environment to use another one. An empty value is refused, because an
      unauthenticated callback endpoint is open to every local process.
  API_HOST_PORT=${API_HOST_PORT:-58996}
      Host port the FHE api service publishes. Exported to the stack like the
      directory variables above.
  NODE_LOCAL_ENV_FILE=${NODE_LOCAL_ENV_FILE:-}
      env file run-node.sh reads instead of \$NODE_DOCKER_DIR/env/node.local.env.
      Both the stack and the report below use this one when it is set.
  NODE_ID_OVERRIDE=${NODE_ID_OVERRIDE:-}
      Node id the FHE stack registers under; defaults to this host's short
      hostname. run-node.sh keeps an exported value over the one in the env file
      above, so this script, not that file, decides it.
  NODE_IP_OVERRIDE=${NODE_IP_OVERRIDE:-}
      Address the stack advertises, which NODE_API_URL is built from; defaults to
      the first address 'hostname -I' reports. Same override rule: the bundle's
      env file names another machine, and without the exported value the stack
      would register as that host.
  FHE_IMAGE=${FHE_IMAGE}
      Image tag the handoff archive is loaded as.
  FHE_IMAGE_ARCHIVE=${FHE_IMAGE_ARCHIVE}
      Archive loaded by 'docker load'. Defaults to the archive the bundle ships,
      which is verified against the bundle's SHA256SUMS first. An archive the
      bundle does not ship is not covered by those manifests: give its digest
      below, or the run warns that it is loading this one unverified.
  FHE_IMAGE_ARCHIVE_SHA256=${FHE_IMAGE_ARCHIVE_SHA256}
      Expected sha256 of FHE_IMAGE_ARCHIVE. Set it when FHE_IMAGE_ARCHIVE names a
      self-built or pulled image, and the archive is verified against this digest
      the way the bundle's own archive is verified against SHA256SUMS. A mismatch
      fails the run in both cases.
  FHE_MODEL_ID=${FHE_MODEL_ID}
      Model activated on the stack before a task can run.
  TAA_IMAGE=${TAA_IMAGE}
      TAA image started on this host (deploy.sh builds it). A taa save run bakes
      the binary and supervisor into this image to produce its archive.
  TAA_FHE_SAVE_IMAGE=${TAA_FHE_SAVE_IMAGE}
      Tag given to the image a taa save run packages (date-stamped by default).
  TAA_FHE_SAVE_ARCHIVE=${TAA_FHE_SAVE_ARCHIVE}
      Archive a taa save run writes, in the project's deploy/ directory by
      default. It is written here, then uploaded and loaded on the deployment
      host.
  TAA_BASE_IMAGE_ARCHIVE=${TAA_BASE_IMAGE_ARCHIVE}
      Archive a taa save run imports when TAA_IMAGE is not in the local docker
      daemon.
  TAA_CONTAINER_NAME=${TAA_CONTAINER_NAME}
      TAA container name.
  TAA_CONTAINER_WORKDIR=${TAA_CONTAINER_WORKDIR}
      Working directory inside the TAA container. deploy/start.sh owns /root/taa:
      it cds there, runs ./taa there and logs to /root/taa/taa.log, so this must
      stay /root/taa. The rendered config is placed at
      \$TAA_CONTAINER_WORKDIR/$TAA_CONFIG_FILE, the path taa reads by default.
  TAA_CONTAINER_CONFIG_PATH=${TAA_CONTAINER_CONFIG_PATH:-}
      Path inside the container the rendered config is copied to. Changing it
      stops the supervisor from seeing the rendered config.
  TAA_RENDERED_CONFIG=${TAA_RENDERED_CONFIG:-}
      Host-side path the rendered config is written to before it is copied in.
  TAA_LOG_FILE=${TAA_LOG_FILE}
      Log the TAA supervisor writes, inside the container.
  TAA_DOCKER_NETWORK=${TAA_DOCKER_NETWORK}
      Docker network for the TAA container. It must stay host: the rendered
      fhe.endpoint is http://127.0.0.1:${API_HOST_PORT:-58996} and the FHE callback
      arrives on the host address.
  TAA_PORT=${TAA_PORT}
      TAA listening port; must match server.addr in \$TAA_FHE_CONFIG.
  TAA_READY_TIMEOUT=${TAA_READY_TIMEOUT}
      Seconds to wait for TAA to answer its health endpoint.
  FHE_READY_TIMEOUT=${FHE_READY_TIMEOUT}
      Seconds to wait for the FHE api to answer /api/v1/health after the stack step
      starts it. 'run-node.sh up -d' returns when the containers have started, not
      when the application inside has bound its port, so this probe has to wait.
  TAA_READY_INTERVAL=${TAA_READY_INTERVAL}
      Seconds between two attempts of any of the waits above.
  DRY_RUN=${DRY_RUN}
      Same as --dry-run. A dry run prints <unset> for the required inputs above
      that are not set, instead of refusing the way a real run does.
EOF
}

# What this run deploys. The bare invocation keeps the original behaviour: the
# FHE stack, platform-mock, then the TAA instance on top of them. A positional
# `fhe`, `taa` or `platform-mock` narrows the run to one component; they are
# mutually exclusive because passing two would not name a single component.
DEPLOY_MODE="all"

while [ $# -gt 0 ]; do
  case "$1" in
    fhe|taa|platform-mock)
      if [ "$DEPLOY_MODE" != "all" ] && [ "$DEPLOY_MODE" != "$1" ]; then
        printf '[deploy-fhe] ERROR: choose one of fhe, taa or platform-mock\n' >&2
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

DEPLOY_FHE_STACK=1
DEPLOY_TAA=1
DEPLOY_MOCK=1
case "$DEPLOY_MODE" in
  fhe) DEPLOY_TAA=0; DEPLOY_MOCK=0 ;;
  taa) DEPLOY_FHE_STACK=0; DEPLOY_MOCK=0 ;;
  platform-mock) DEPLOY_FHE_STACK=0; DEPLOY_TAA=0 ;;
esac
# --no-platform-mock removes the one thing the platform-mock argument exists to
# deploy, so the two together describe no run at all rather than a smaller one.
# In the bare form the flag stays valid: it narrows the run to the FHE stack and
# TAA, which is what it always meant.
if [ "$DEPLOY_MODE" = "platform-mock" ] && [ "$DEPLOY_PLATFORM_MOCK" != 1 ]; then
  printf '[deploy-fhe] ERROR: the platform-mock argument deploys platform-mock, but --no-platform-mock was given\n' >&2
  usage >&2
  exit 1
fi
# save packages the TAA side into an image and starts nothing. It is meaningful
# only with the taa argument: the fhe and platform-mock arguments name components
# that have no image of their own here, and the bare form describes a deployment
# rather than a package.
if [ "$SAVE_ACTION" = 1 ] && [ "$DEPLOY_MODE" != "taa" ]; then
  printf '[deploy-fhe] ERROR: save is only valid with the taa argument: deploy-fhe.sh taa save\n' >&2
  usage >&2
  exit 1
fi

setup_remote_ssh

# ── Required inputs ──────────────────────────────────────────────────────────
# Checked before anything runs, and before anything is staged: a run that cannot
# finish should fail here rather than halfway through an rsync --delete. Neither
# value has a safe default -- a stack pointed at the wrong runtime, or a callback
# endpoint with no token, is worse than a refused run -- so the real run refuses
# without them. A dry run has nothing to protect, so it prints a visible
# placeholder instead: that keeps `DRY_RUN=1 ./deploy-fhe.sh` runnable on a host
# that has never deployed this stack.
require_input() {
  local name="$1" message="$2"
  [ -n "${!name:-}" ] && return 0
  if is_dry_run; then
    warn "$name is unset; this dry run prints <unset> where its value belongs"
    printf -v "$name" '%s' '<unset>'
    return 0
  fi
  die "$message"
}

HOST_DATA_DIR="${HOST_DATA_DIR:-/opt/fhe-data}"
# Not exported, unlike the four at the end of this block: the bundle's run-node.sh has
# no name for this directory and nothing in the stack reads it. TAA reaches it through
# the rendered config's storage.keys, and through the second bind start_taa_container
# adds.
HOST_TAA_STATE_DIR="${HOST_TAA_STATE_DIR:-/opt/taa-state}"
# Defaults for the three inputs that used to be required. They are named in the
# environment they describe: on a remote run the runtime directory is the uploaded
# bundle's copy on that host, and the callback URL is the deployment host's address
# as the FHE containers reach it. An explicit environment value still wins, and a
# local run (--local) falls back to the bundle beside this script.
if [ -n "$REMOTE_TARGET" ]; then
  # A sibling of the uploaded bundle, not a directory inside it: the upload is
  # 'rsync -a --delete' into REMOTE_HANDOFF_DIR, so the runtime has to be staged
  # out of it before the stack mounts it.
  HOST_RUNTIME_DIR="${HOST_RUNTIME_DIR:-$REMOTE_DIR/latti-runtime}"
  TAA_CALLBACK_BASE_URL="${TAA_CALLBACK_BASE_URL:-http://${REMOTE_HOST}:${TAA_PORT}}"
else
  HOST_RUNTIME_DIR="${HOST_RUNTIME_DIR:-$HANDOFF_DIR/third_party/latti-ai-runtime}"
fi
# Shared secret the FHE service presents on the callback endpoint. It is set here
# so the default invocation (`./deploy-fhe.sh`) is complete; override it from the
# environment to use a different one. This file is the only place it is stored.
TAA_CALLBACK_TOKEN="${TAA_CALLBACK_TOKEN:-8a9711dfcb0b55a296d9db255dba7dc47be23ca06deeff58}"
# The runtime directory is only consumed by the staging step, and the callback
# URL only by the rendered config, so each is required only when the side that
# reads it is part of this run.
if [ "$DEPLOY_FHE_STACK" = 1 ]; then
  require_input HOST_RUNTIME_DIR 'HOST_RUNTIME_DIR must point at third_party/latti-ai-runtime'
fi
TAA_FHE_CONFIG="${TAA_FHE_CONFIG:-$PROJECT_DIR/configs/taa-fhe.json}"
# Both paths that produce a runnable TAA need the address the FHE containers call
# back on: the deploy path writes it into the config it installs at start time,
# and the save path bakes the same rendered config into the image. The template
# and the token are checked by render_taa_config itself. 'auto' is a valid value:
# TAA then derives the address from server.addr and its own host name at startup.
if [ "$DEPLOY_TAA" = 1 ]; then
  require_input TAA_CALLBACK_BASE_URL 'TAA_CALLBACK_BASE_URL must be reachable from the FHE containers, or set to auto'
fi
API_HOST_PORT="${API_HOST_PORT:-58996}"
HOST_REDIS_DIR="${HOST_REDIS_DIR:-$HOST_DATA_DIR/redis}"

# Each of these is one value written twice: here, and in the bundle's
# env/node.local.env. run-node.sh sources that file and then restores the value of
# every name it saw already set in the environment (`[[ -v $name ]]` in
# load_local_env_defaults), so exporting them is what makes the stack read the tree
# this script stages. Without the export the bundle's own absolute paths -- under
# the FHE team's home directory, on a machine that is not this one -- decide where
# the stack looks while TAA reads $HOST_DATA_DIR: the stack still comes up healthy
# (the bundle carries the same model), activation still succeeds, and every task
# then hangs until taskTimeoutMs.
#
# The export decides that only while this script and the stack share one
# environment. On a --remote run every host-side command goes over ssh, and ssh
# carries no environment, so the export reaches nothing: the failure it was written
# to prevent is the one a live remote run produced, and it looked exactly as
# described above. run_node below passes the same values on the command line, which
# does survive the hop, and is what the stack step uses.
export HOST_DATA_DIR HOST_RUNTIME_DIR HOST_REDIS_DIR API_HOST_PORT

# ── The bundle as the deployment host sees it ────────────────────────────────
# On a --remote run there are two copies of the handoff bundle: the one this script
# holds, which is what gets verified here (verify_one hashes it, and SHA256SUMS is
# beside it) and uploaded, and the one the deployment host reads, which is what
# `docker load` and the staging rsync consume. Every host-side path below is named
# from HOST_HANDOFF_DIR rather than from HANDOFF_DIR, so the guards that reason about
# them reason about the paths that are really used.
if [ -n "$REMOTE_TARGET" ]; then
  HOST_HANDOFF_DIR="$REMOTE_HANDOFF_DIR"
else
  HOST_HANDOFF_DIR="$HANDOFF_DIR"
fi

NODE_DOCKER_DIR="$HOST_HANDOFF_DIR/deploy/docker"
# NODE_ENV_FILE is the path run-node.sh resolves on the host; NODE_ENV_FILE_LOCAL is
# the copy of that same file beside this script. The upload copies the bundle
# verbatim, so the two carry the same content, and it is the local one the report
# below can actually open. NODE_LOCAL_ENV_FILE overrides the first and, being a path
# on the host, leaves the report reading nothing -- which it says, rather than
# reporting the file as carrying no value.
NODE_ENV_FILE="${NODE_LOCAL_ENV_FILE:-$NODE_DOCKER_DIR/env/node.local.env}"
NODE_ENV_FILE_LOCAL="$HANDOFF_DIR/deploy/docker/env/node.local.env"

# Same problem, two names nobody had checked. NODE_ID_OVERRIDE and
# NODE_IP_OVERRIDE are on run-node.sh's restore list and env/node.local.env sets
# both -- NODE_ID_OVERRIDE=local and NODE_IP_OVERRIDE=172.16.10.178, the FHE
# team's machine -- so without an exported value the file's win, and the stack
# registers itself as another team's node with NODE_API_URL pointing at that
# host's address. The values exported here are the ones run-node.sh would have
# derived on its own (hostname -s, and the first address hostname -I reports), so
# this run decides the identity; an operator who wants a specific one sets these
# in this script's environment and the export passes it through. The report below
# names the divergence when the env file disagrees.
#
# Both are read from the deployment host rather than the one this script runs on
# (host_capture), because that is the machine run-node.sh derives them on: on a
# remote run the identity has to be the remote host's or the stack registers as
# the wrong node -- and under `--remote -n` it is read from neither, which leaves
# the env file's value in force and is reported as such.
NODE_ID_OVERRIDE="${NODE_ID_OVERRIDE:-$(host_capture 'hostname -s' 2>/dev/null || true)}"
# A derivation that yields nothing has to export nothing. run-node.sh's restore
# rule is `[[ -v $name ]]`, so a set-but-empty exported value wins over the env
# file's exactly as a good one does: exporting an empty NODE_IP_OVERRIDE is what
# turned NODE_API_URL into "http://:58996". Unset instead, which leaves the env
# file's value in force -- the honest outcome of "this run could not derive one".
if [ -z "$NODE_ID_OVERRIDE" ]; then
  warn "'hostname -s' reported no name, so NODE_ID_OVERRIDE is not exported and $NODE_ENV_FILE decides it"
  unset NODE_ID_OVERRIDE
fi
# The address needs more than "not empty". 'hostname -I' lists every address the
# host has in no documented order, and its first field is regularly an IPv6
# address or the docker0 bridge (172.17.0.0/16) -- neither of which the platform
# can reach at NODE_API_URL, so taking the first unconditionally advertises an
# address that never answers. A candidate therefore has to look like an IPv4
# dotted quad, a non-bridge candidate is preferred over a bridge one, and what was
# chosen and what was passed over are both named below.
if [ -z "${NODE_IP_OVERRIDE:-}" ]; then
  NODE_IP_OVERRIDE=""
  node_ip_all="$(host_capture 'hostname -I' 2>/dev/null || true)"
  node_ip_skipped=""
  node_ip_bridge=""
  for node_ip in $node_ip_all; do
    if ! printf '%s' "$node_ip" \
         | grep -Eq '^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'; then
      node_ip_skipped="${node_ip_skipped:+$node_ip_skipped }$node_ip (not an IPv4 dotted quad)"
      continue
    fi
    case "$node_ip" in
      172.17.*)
        node_ip_bridge="${node_ip_bridge:-$node_ip}"
        node_ip_skipped="${node_ip_skipped:+$node_ip_skipped }$node_ip (Docker bridge)"
        continue
        ;;
    esac
    NODE_IP_OVERRIDE="$node_ip"
    break
  done
  # A host whose only IPv4 address is the bridge is still better identified by
  # that than by the env file's address, which names a different machine.
  if [ -z "$NODE_IP_OVERRIDE" ]; then
    NODE_IP_OVERRIDE="$node_ip_bridge"
  fi
  if [ -z "$NODE_IP_OVERRIDE" ]; then
    warn "'hostname -I' reported no usable IPv4 address (${node_ip_all:-no output}), so NODE_IP_OVERRIDE is not exported and $NODE_ENV_FILE decides it"
    unset NODE_IP_OVERRIDE
  elif [ "$NODE_IP_OVERRIDE" = "$node_ip_bridge" ]; then
    warn "NODE_IP_OVERRIDE=$NODE_IP_OVERRIDE, but every IPv4 address 'hostname -I' reported (${node_ip_all:-no output}) is a Docker bridge, which the platform cannot reach; set NODE_IP_OVERRIDE to the address it should use"
  elif [ -n "$node_ip_skipped" ]; then
    warn "NODE_IP_OVERRIDE=$NODE_IP_OVERRIDE, chosen from 'hostname -I' (${node_ip_all:-no output}); passed over $node_ip_skipped"
  fi
fi
export NODE_ID_OVERRIDE NODE_IP_OVERRIDE

# The rendered config is written here on the host, to a mode-600 file that the
# data directory's owner can inspect, and then copied into the container at the
# path taa reads by default (TAA_CONTAINER_CONFIG_PATH). It used to be consumed in
# place through the HOST_DATA_DIR bind mount; that stops working the moment TAA
# has to run under start.sh, which passes no --config.
TAA_RENDERED_CONFIG="${TAA_RENDERED_CONFIG:-$HOST_DATA_DIR/taa-fhe.rendered.json}"
TAA_CONTAINER_CONFIG_PATH="${TAA_CONTAINER_CONFIG_PATH:-$TAA_CONTAINER_WORKDIR/$TAA_CONFIG_FILE}"
# Where jq writes, which is not always where the deployment host wants it. jq runs
# here in both modes -- it holds the callback token in its environment, and this is
# the side that can create the file 0600 from the start -- so a remote run renders
# into a private temporary directory (mktemp -d is 0700, and the EXIT trap above
# removes it) and uploads the result, while TAA_RENDERED_CONFIG stays what it always
# was: the path on the deployment host the config is deployed to. Everything that
# reads the rendered bytes -- the two guards in render_taa_config -- reads the local
# copy either way; only where it lives during the run differs.
TAA_RENDER_OUT="$TAA_RENDERED_CONFIG"
if [ -n "$REMOTE_TARGET" ] && ! is_dry_run; then
  TAA_RENDER_TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/deploy-fhe-render.XXXXXX")" \
    || die "cannot create a temporary directory for the rendered config"
  TAA_RENDER_OUT="$TAA_RENDER_TMPDIR/taa-fhe.rendered.json"
fi

# ── Read-only helpers ────────────────────────────────────────────────────────

# Reads a plain NAME=/absolute/path assignment out of a bundle env file. The file
# has no expansion, so it never needs to be sourced.
read_env_path() {
  local env_file="$1" key="$2"
  awk -F= -v key="$key" '
    $1 == key {
      sub(/^[^=]*=/, "")
      sub(/[ \t]+#.*$/, "")
      gsub(/^[ \t]+|[ \t\r]+$/, "")
      gsub(/^"|"$/, "")
      print
      exit
    }' "$env_file"
}

# True when both arguments name the same path, symlinks and trailing slashes
# included. -m so it also answers for paths that do not exist yet, which is what
# makes the guards below usable in --dry-run.
same_path() {
  local a b
  a="$(realpath -m -- "$1")" || return 1
  b="$(realpath -m -- "$2")" || return 1
  [ "$a" = "$b" ]
}

# True when either path is the other, contains the other, or is contained by it.
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

# The one-way form of paths_overlap: true when $1 is $2 or contains it. For the guards
# where the direction is the whole question -- 'rsync --delete' writes into the first
# path, so a second path inside it is destroyed while a second path containing it is
# merely adjacent.
path_contains() {
  local outer inner
  outer="$(realpath -m -- "$1")" || return 1
  inner="$(realpath -m -- "$2")" || return 1
  if [ "$outer" = "/" ] || [ "$outer" = "$inner" ]; then
    return 0
  fi
  case "$inner/" in "$outer"/*) return 0 ;; esac
  return 1
}

# ── The files this run puts on the deployment host ───────────────────────────
# Four paths, each named once for the host that reads it: the image archive docker
# load reads, the supervisor docker cp copies in, and the two binaries. Locally each
# is the operator-facing path unchanged; under --remote each is the copy the upload
# phase places under REMOTE_DIR, because every command that touches them runs there.
#
# An archive the bundle ships keeps its place inside the uploaded tree -- the upload
# carries it, so the host's copy is the one to load. An archive the operator pointed
# at from elsewhere is used as given and is *not* uploaded: there is no rule for where
# it would go, and inventing one would put a second copy of a multi-gigabyte image on
# a host that already has one. The warning is what keeps that from being a surprise.
if same_path "$FHE_IMAGE_ARCHIVE" "$BUNDLE_IMAGE_ARCHIVE"; then
  HOST_FHE_IMAGE_ARCHIVE="$HOST_HANDOFF_DIR/image/latti-server-latest.tar.gz"
else
  HOST_FHE_IMAGE_ARCHIVE="$FHE_IMAGE_ARCHIVE"
  if [ -n "$REMOTE_TARGET" ]; then
    warn "--remote uploads $HANDOFF_DIR and nothing else, so FHE_IMAGE_ARCHIVE=$FHE_IMAGE_ARCHIVE is read on $REMOTE_TARGET exactly as written; it has to exist there"
  fi
fi
HOST_START_SH="$PROJECT_DIR/deploy/start.sh"
HOST_TAA_BINARY_PATH="$TAA_BINARY_PATH"
HOST_PLATFORM_MOCK_BINARY_PATH="$PLATFORM_MOCK_BINARY_PATH"
if [ -n "$REMOTE_TARGET" ]; then
  HOST_START_SH="$REMOTE_DIR/deploy/start.sh"
  HOST_TAA_BINARY_PATH="$REMOTE_DIR/bin/$BINARY_NAME"
  HOST_PLATFORM_MOCK_BINARY_PATH="$REMOTE_DIR/bin/$PLATFORM_MOCK_BINARY_NAME"
fi

# Reports the values the FHE stack will actually run with, and says so when the
# bundle's env file disagrees with this run. It is a report, not a warning: the
# export above makes the exported value win in run-node.sh, so a mismatch in the
# env file cannot reach the deployment and a WARNING on the default configuration
# would be noise rather than a signal. It runs in --dry-run too, because a dry run
# is exactly where an operator should learn which tree the stack will use.
report_stack_binding() {
  local name want got
  # The file this reads is the local copy of the one the stack reads (see
  # NODE_ENV_FILE_LOCAL above); the messages below name the host-side path, because
  # that is the file the value they report actually comes from. An override that
  # names a path only the host has leaves nothing to read here, and then the report
  # compares against no file at all -- said first, so the "(no NAME in ...)" lines
  # below are not read as "the env file carries nothing".
  local env_src="$NODE_ENV_FILE_LOCAL"
  [ -z "${NODE_LOCAL_ENV_FILE:-}" ] || env_src="$NODE_LOCAL_ENV_FILE"
  if [ ! -r "$env_src" ]; then
    warn "cannot read $env_src from here, so this report compares against no env file; the stack on ${REMOTE_TARGET:-this host} reads ${NODE_ENV_FILE}"
  fi
  for name in HOST_DATA_DIR HOST_RUNTIME_DIR HOST_REDIS_DIR API_HOST_PORT; do
    want="${!name}"
    got=""
    if [ -r "$env_src" ]; then
      got="$(read_env_path "$env_src" "$name")"
    fi
    if [ -z "$got" ]; then
      log "$name=$want (no $name in $NODE_ENV_FILE)"
    elif [ "$got" = "$want" ]; then
      log "$name=$want (the value $NODE_ENV_FILE carries)"
    else
      log "$name=$want -- $NODE_ENV_FILE carries $got, which this run overrides: the exported value wins in run-node.sh, so the stack uses $want, not $got"
    fi
  done
  # The same report for the node identity, which is the pair that used to be a
  # silent override rather than a reported one. Unlike the four above, a value the
  # env file carries here is worth a WARNING: the bundle's 172.16.10.178 is not
  # this host, and an operator reading the banner should see that this run did not
  # adopt it. A name the derivation above could not produce is not exported at
  # all, and then the env file's value is what runs -- said here rather than in
  # the branch below, which would otherwise report an override that never happened.
  for name in NODE_ID_OVERRIDE NODE_IP_OVERRIDE; do
    want="${!name:-}"
    got=""
    if [ -r "$env_src" ]; then
      got="$(read_env_path "$env_src" "$name")"
    fi
    if [ -z "$want" ]; then
      log "$name is not exported by this run ($NODE_ENV_FILE carries ${got:-none}), so the env file decides it"
    elif [ -n "$got" ] && [ "$got" != "$want" ]; then
      warn "$NODE_ENV_FILE carries $name=$got, which this run overrides with $name='$want'; run-node.sh keeps the exported value, so the stack registers as ${want:-the host default}, not $got"
    else
      log "$name=${want} (the value $NODE_ENV_FILE carries: ${got:-none})"
    fi
  done
  # FHE_IMAGE cannot be pinned the same way, and that is a property of run-node.sh
  # rather than an oversight here: load_local_env_defaults restores only the names
  # on its own list, and LATTI_SERVER_IMAGE is not one of them, so the env file
  # overwrites whatever this script exports and compose runs the env file's tag.
  # Only a run that loads a different image than the env file names is affected.
  got="$(read_env_path "$NODE_ENV_FILE" LATTI_SERVER_IMAGE 2>/dev/null || true)"
  if [ -n "$got" ] && [ "$got" != "$FHE_IMAGE" ]; then
    warn "$NODE_ENV_FILE sets LATTI_SERVER_IMAGE=$got but this run loads $FHE_IMAGE; run-node.sh does not let the environment override LATTI_SERVER_IMAGE, so the stack will run $got"
  fi
}

# The bundle's SHA256SUMS lists client/latti-client-wasm-0.1.0.zip while the
# shipped file is latti-wasm-0.1.1.zip, so an unconditional `sha256sum -c`
# always fails. Verify the two artifacts that matter, by their real names.
#
# $1 is the name SHA256SUMS uses; $2, when given, is the file to hash, so a
# caller whose artifact path is overridable can make the checksum cover the file
# that is actually consumed instead of the one it defaulted to; $3, when given, is
# a digest the caller vouches for, and it is matched instead of the SHA256SUMS
# entry -- for an artifact the bundle's manifests do not cover.
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

wait_for_taa() {
  local deadline=$((SECONDS + TAA_READY_TIMEOUT))
  while [ "$SECONDS" -lt "$deadline" ]; do
    # host_sh: the probe has to run where taa listens. On a remote run 127.0.0.1
    # is the remote host, which is the point -- probing from here would answer
    # for whichever taa happens to run on this machine.
    if host_sh "curl -fsS -o /dev/null -X POST 'http://127.0.0.1:${TAA_PORT}/v1/taa/health'" 2>/dev/null; then
      return 0
    fi
    sleep "$TAA_READY_INTERVAL"
  done
  return 1
}

# The FHE api needs the same wait for the same reason, and it is the one step of this
# script that a live run caught out: `run-node.sh up -d` is `docker compose up -d`, which
# returns when the containers have *started*, not when the application inside has bound
# its port. Probing once in that window gets a connection reset -- measured at ~7s on the
# first real run -- and reports a healthy stack as a broken one.
wait_for_fhe_stack() {
  local deadline=$((SECONDS + FHE_READY_TIMEOUT))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if host_sh "curl -fsS -o /dev/null 'http://127.0.0.1:${API_HOST_PORT}/api/v1/health'" 2>/dev/null; then
      return 0
    fi
    sleep "$TAA_READY_INTERVAL"
  done
  return 1
}

# What the mock recorded for the last registration attempt, as the JSON it answered
# with, and nothing at all when it never received one. Read as the last gate of a run:
# a TAA that answers /v1/taa/health proves it started, not that the platform ever heard
# from it, and a failed registration is only a warning at startup (internal/app/taa) --
# so the two are checked separately. The whole state is returned rather than just the
# dockerId because a rejected registration stores the dockerId too (with accepted
# false), and reading the id alone would pass on exactly the failure this gate exists
# to catch.
platform_register_state() {
  host_capture "curl -fsS 'http://127.0.0.1:${PLATFORM_PORT}/api/register/status'" 2>/dev/null || true
}

# The mock answering is not the same as the mock that answers being ours: on a re-run
# the previous run's process is still listening, and a second one would fail to bind
# and exit. So the port is probed first and an answer is reported as "already there"
# rather than as this run's doing.
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

render_taa_config() {
  # The save path renders on the packaging machine and bakes the result straight
  # into the image, so it must not upload the copy it just made to the deployment
  # host; pass 0 to skip that hop.
  local upload="${1:-1}"
  [ -f "$TAA_FHE_CONFIG" ] || die "TAA config template not found: $TAA_FHE_CONFIG"
  command -v jq >/dev/null 2>&1 || die "command 'jq' is required but not installed or not in PATH"
  # The two ways the pipeline below fails are not the same failure, so the
  # destination is checked first and named separately: a missing directory is a
  # mkdir problem, and reporting it as "failed to render with jq" sends the operator
  # to the template. Under --remote this is the local staging file -- the upload
  # after the render creates the directory on the deployment host itself.
  local rendered_dir
  rendered_dir="$(dirname "$TAA_RENDER_OUT")"
  [ -d "$rendered_dir" ] || die "cannot write $TAA_RENDER_OUT: $rendered_dir does not exist"
  # Two things happen here that the shell has to do rather than jq: the callback
  # token reaches jq through its environment, never through argv (--arg token would
  # publish the secret in /proc/<pid>/cmdline to every local user for as long as jq
  # lives), and umask 077 creates the file 0600 from the start instead of leaving it
  # at the caller's umask until the chmod below runs. $ENV needs jq 1.5 or newer.
  #
  # storage.keys is the one path taken from a second variable, because it is the one
  # that does not belong on the data bind: see the loop at the end of this function.
  ( umask 077; TAA_CALLBACK_TOKEN="$TAA_CALLBACK_TOKEN" jq \
      --arg url "$TAA_CALLBACK_BASE_URL" \
      --arg endpoint "http://127.0.0.1:${API_HOST_PORT}" \
      --arg data "$HOST_DATA_DIR" \
      --arg state "$HOST_TAA_STATE_DIR" \
      '.fhe.callbackBaseUrl = $url | .fhe.callbackToken = $ENV.TAA_CALLBACK_TOKEN
       | .fhe.endpoint = $endpoint | .fhe.dataDir = $data
       | .fhe.keyCacheDir = ($data + "/taa-fhe-keys")
       | .storage.result  = ($data + "/taa-results")
       | .storage.keys    = ($state + "/keys")' \
      "$TAA_FHE_CONFIG" > "$TAA_RENDER_OUT" ) \
    || die "failed to render $TAA_FHE_CONFIG -> $TAA_RENDER_OUT (jq rejected the template, or the redirect could not create that file)"
  # The file carries the callback token. The redirect above already created it 0600;
  # this is for the case where it already existed with a wider mode.
  chmod 600 "$TAA_RENDER_OUT"
  log "rendered $TAA_FHE_CONFIG -> $TAA_RENDER_OUT"
  # The second hop, on a remote run: docker cp below reads the config from the
  # deployment host, so it has to be there before that step. Mode 600 all the way --
  # the file carries the callback token.
  if [ -n "$REMOTE_TARGET" ] && [ "$upload" = 1 ]; then
    upload_file "$TAA_RENDER_OUT" "$TAA_RENDERED_CONFIG" 600
  fi

  # The readiness probe and the callback URL both assume TAA listens on
  # TAA_PORT; a template that says otherwise would be polled at the wrong port.
  local addr
  addr="$(jq -r '.server.addr' "$TAA_RENDER_OUT")"
  [ "$addr" = ":$TAA_PORT" ] \
    || die "server.addr in the rendered config is '$addr' but TAA_PORT is ':$TAA_PORT'"

  # Three of TAA's stateful paths have to land inside the bind that carries them - the
  # container gets two, and start_taa_container recreates it whenever either changes -
  # or they live in the writable layer and die with the container:
  #
  #   - fhe.keyCacheDir holds the eval keys, re-downloaded 3.1 GiB at a time against
  #     a cache the design deliberately never evicts;
  #   - storage.result holds each finished task's result directory and the
  #     import-index.json beside them, which is the record export resolves a result
  #     through, so losing it answers 404 for work already reported as succeeded;
  #   - storage.keys holds the TAA SM2 key pair and state.sealed, the sealed instance
  #     state. ModelChecksum lives in there, and the FHE task path refuses an import
  #     while it is empty, so an instance that loses this directory forgets its model
  #     was ever imported and rejects every data import as "no model imported yet" -
  #     while the model package sits untouched on the bind.
  #
  # The filter above is what delivers that, by assigning each path from the variable
  # whose bind carries it. This loop asserts it rather than checking it: with those
  # lines intact it cannot fire. It is here for the edit that removes or weakens them,
  # which is invisible while both variables keep their defaults - the template's
  # literals happen to agree with them - and wrong the moment either does not. Contrast
  # the addr check above, which reads a field the filter never writes and so can catch
  # the template itself.
  #
  # storage.keys is checked against the second bind rather than the first, and that is
  # the whole reason this loops over pairs: asserting it against $HOST_DATA_DIR would
  # both reject the correct render and accept one that put TAA's SM2 key pair inside
  # the tree the FHE stack mounts as /data.
  local state_pair state_key state_bind state_path
  for state_pair in \
    ".fhe.keyCacheDir|$HOST_DATA_DIR" \
    ".storage.result|$HOST_DATA_DIR" \
    ".storage.keys|$HOST_TAA_STATE_DIR"; do
    state_key="${state_pair%%|*}"
    state_bind="${state_pair#*|}"
    state_path="$(jq -r "$state_key" "$TAA_RENDER_OUT")"
    case "$state_path" in
      "$state_bind"/*) ;;
      *) die "the rendered config sets $state_key to '$state_path', outside the bind '$state_bind' that has to carry it: recreating the container would destroy it" ;;
    esac
  done
}

# Mirrors deploy.sh's container handling: reuse a container that already runs the
# expected image *and* carries both binds this run needs, recreate one that does not.
start_taa_container() {
  local -a args=(-d --name "$TAA_CONTAINER_NAME" --network "$TAA_DOCKER_NETWORK")
  # Two binds, and the second is the reason there are two: the first is the tree the
  # FHE stack shares as /data, the second carries TAA's own state - the keys directory
  # the rendered config names, holding the SM2 key pair and state.sealed - and is
  # deliberately not inside the first. Mounting both at themselves keeps each path
  # spelled the same way on the host and in the container, which is what lets the
  # rendered config's absolute paths mean anything.
  args+=(-v "$HOST_DATA_DIR:$HOST_DATA_DIR")
  args+=(-v "$HOST_TAA_STATE_DIR:$HOST_TAA_STATE_DIR")
  # The instance's identity, in the one channel internal/config lets win over the
  # config file on a type=fhe instance. Both are optional: an unset value is left to
  # the template's platform block, which is a working default rather than a
  # half-configured instance -- and the recreate check below is what stops a container
  # that a previous run created without them from continuing without them.
  local -a required_envs=()
  if [ -n "$PLATFORM_IP" ]; then
    args+=(-e "PLATFORM_IP=$PLATFORM_IP")
    required_envs+=("PLATFORM_IP=$PLATFORM_IP")
  fi
  if [ -n "$DOCKER_ID" ]; then
    args+=(-e "DOCKER_ID=$DOCKER_ID")
    required_envs+=("DOCKER_ID=$DOCKER_ID")
  fi
  args+=(--entrypoint tail "$TAA_IMAGE" -f /dev/null)

  if is_dry_run; then
    # A dry run executes nothing -- in particular it does not call docker, which is
    # what lets it run on a host with no daemon -- so it cannot know whether the
    # container already exists. Print the decision the real run would make instead
    # of the create branch as though it were certain.
    log "dry-run: the real run would reuse $TAA_CONTAINER_NAME if it already exists with image $TAA_IMAGE, the binds $HOST_DATA_DIR:$HOST_DATA_DIR and $HOST_TAA_STATE_DIR:$HOST_TAA_STATE_DIR and the environment ${required_envs[*]:-this run sets none}, and would otherwise create it:"
    run docker run "${args[@]}"
    return 0
  fi

  # -F: docker allows '.' in container names, and `grep -E "^taa.fhe\$"` also matches
  # an unrelated "taaXfhe". That match would make this block skip creating the
  # container and report it as already running, and every later docker exec would
  # fail against a container this deployment does not own.
  if host_sh "docker ps -a --format '{{.Names}}' | grep -Fxq $(shell_quote "$TAA_CONTAINER_NAME")"; then
    local current_image current_id target_id image_mismatch=false bind_mismatch=false env_mismatch=false
    local required_bind required_env current_binds current_env missing_binds="" missing_env=""
    current_image="$(host_capture "docker inspect --format '{{.Config.Image}}' $(shell_quote "$TAA_CONTAINER_NAME")" 2>/dev/null || true)"
    current_id="$(host_capture "docker inspect --format '{{.Image}}' $(shell_quote "$TAA_CONTAINER_NAME")" 2>/dev/null || true)"
    target_id="$(host_capture "docker image inspect --format '{{.Id}}' $(shell_quote "$TAA_IMAGE")" 2>/dev/null || true)"
    if [ -n "$current_image" ] && [ "$current_image" != "$TAA_IMAGE" ]; then
      image_mismatch=true
    elif [ -n "$current_id" ] && [ -n "$target_id" ] && [ "$current_id" != "$target_id" ]; then
      image_mismatch=true
    fi
    # Both binds are as much a part of the container's identity as its image, for this
    # script: the config copied in below sets fhe.dataDir to $HOST_DATA_DIR and
    # storage.keys to $HOST_TAA_STATE_DIR/keys, and the only thing that makes each path
    # the same directory on both sides is its bind. Comparing the image alone let a
    # re-run with a different HOST_DATA_DIR reuse the old container and then push a
    # config for the new directory into it; taa's os.MkdirAll then created that path in
    # the container's own writable layer, where no host directory backs it, and the run
    # printed its success banner. The same mistake on the second bind is quieter and
    # worse: taa would mint a fresh SM2 key pair and a fresh state.sealed in the
    # writable layer, report itself healthy, and then refuse every data import as "no
    # model imported yet", because the ModelChecksum it sealed is in the directory on
    # the host that nothing mounted -- while this run reported success. A bind that
    # cannot be read is treated as a mismatch: the failure this guards is silent, so
    # the unconfirmed case has to take the loud branch.
    current_binds="$(host_capture "docker inspect --format '{{json .HostConfig.Binds}}' $(shell_quote "$TAA_CONTAINER_NAME")" 2>/dev/null || true)"
    for required_bind in "$HOST_DATA_DIR:$HOST_DATA_DIR" "$HOST_TAA_STATE_DIR:$HOST_TAA_STATE_DIR"; do
      if ! printf '%s' "$current_binds" \
           | jq -e --arg b "$required_bind" 'type == "array" and index($b) != null' >/dev/null 2>&1; then
        bind_mismatch=true
        missing_binds="${missing_binds:+$missing_binds, }$required_bind"
      fi
    done
    # And the environment, for the same reason and with a quieter failure. A container
    # built before this run had PLATFORM_IP/DOCKER_ID -- or one built by a run whose
    # values differed -- is reused by the image and bind checks above, and then the
    # identity never reaches the process inside it: internal/config falls back to the
    # template, the instance registers under the wrong dockerId or cannot register at
    # all, and the only symptom is a platform that never hears from a node this run
    # reported as deployed. Only the variables this run means to set are compared, so
    # a run that sets neither behaves exactly as it did before.
    current_env="$(host_capture "docker inspect --format '{{json .Config.Env}}' $(shell_quote "$TAA_CONTAINER_NAME")" 2>/dev/null || true)"
    # ${arr[@]+"${arr[@]}"} rather than "${arr[@]}": under set -u an empty array is an
    # unbound variable before bash 4.4, and this list is empty whenever the run sets
    # neither variable -- the case that has to keep working unchanged.
    for required_env in ${required_envs[@]+"${required_envs[@]}"}; do
      if ! printf '%s' "$current_env" \
           | jq -e --arg e "$required_env" 'type == "array" and index($e) != null' >/dev/null 2>&1; then
        env_mismatch=true
        missing_env="${missing_env:+$missing_env, }$required_env"
      fi
    done
    if [ "$image_mismatch" = true ] || [ "$bind_mismatch" = true ] || [ "$env_mismatch" = true ]; then
      if [ "$image_mismatch" = true ]; then
        warn "container $TAA_CONTAINER_NAME runs $current_image, expected $TAA_IMAGE; recreating"
      fi
      if [ "$bind_mismatch" = true ]; then
        warn "container $TAA_CONTAINER_NAME does not carry every bind this run needs: missing $missing_binds (its binds: ${current_binds:-unreadable}); recreating so taa reads the directories this run configured"
      fi
      if [ "$env_mismatch" = true ]; then
        warn "container $TAA_CONTAINER_NAME does not carry every environment variable this run sets: missing $missing_env (its environment: ${current_env:-unreadable}); recreating so the instance registers as this run intends"
      fi
      run docker rm -f "$TAA_CONTAINER_NAME"
    fi
  fi

  if host_sh "docker ps --format '{{.Names}}' | grep -Fxq $(shell_quote "$TAA_CONTAINER_NAME")"; then
    log "container $TAA_CONTAINER_NAME is already running"
    return 0
  fi
  if host_sh "docker ps -a --format '{{.Names}}' | grep -Fxq $(shell_quote "$TAA_CONTAINER_NAME")"; then
    log "starting stopped container $TAA_CONTAINER_NAME"
    run docker start "$TAA_CONTAINER_NAME"
    return 0
  fi
  log "creating container $TAA_CONTAINER_NAME (image $TAA_IMAGE, network $TAA_DOCKER_NETWORK)"
  run docker run "${args[@]}"
}

# ── Guards on the operator-invented paths ────────────────────────────────────
# All of them are configuration mistakes rather than missing inputs, so unlike
# require_input they refuse in --dry-run too: a dry run is where a path this cheap
# to check and this expensive to survive should be caught.
#
# The bundle trees the staging step reads from are defined here so every guard runs
# before the run has done anything at all -- including `docker load`, which mutates
# the daemon's image store. Both are named from HOST_HANDOFF_DIR, the copy on the
# machine that runs the staging: on a --remote run the source of the rsync is the
# uploaded tree, not the one this script is holding.
RUNTIME_SRC="$HOST_HANDOFF_DIR/third_party/latti-ai-runtime"
MODELS_SRC="$HOST_HANDOFF_DIR/data/models"
# $HOST_DATA_DIR/models is the one the staging step copies into; naming it once keeps
# the guard and the copy below on the same path.
STAGED_MODELS_DIR="$HOST_DATA_DIR/models"

if paths_overlap "$HOST_RUNTIME_DIR" "$HOST_DATA_DIR"; then
  die "HOST_RUNTIME_DIR=$HOST_RUNTIME_DIR and HOST_DATA_DIR=$HOST_DATA_DIR overlap (one is the other, or one contains the other); 'rsync -a --delete' in the staging step targets HOST_RUNTIME_DIR, so this would delete the eval-key cache and the task state before only models/ is put back"
fi
# Every tree the staging step must not consume, checked against the destination it
# deletes into. The check that used to stand in for this was equality-only, which
# HOST_RUNTIME_DIR set to the source's *parent* walks straight through: the files
# being read are the files being deleted, and all rsync reports is "file has
# vanished" (exit 24). paths_overlap is nesting-aware and symmetric, so the two
# spellings of the mistake -- one containing the other -- are both caught. Equality
# with RUNTIME_SRC is the one legitimate overlap ("already staged in place") and is
# excluded, exactly as it is in the copy below.
if paths_overlap "$RUNTIME_SRC" "$HOST_RUNTIME_DIR" && ! same_path "$RUNTIME_SRC" "$HOST_RUNTIME_DIR"; then
  die "HOST_RUNTIME_DIR=$HOST_RUNTIME_DIR and the bundle runtime $RUNTIME_SRC overlap (one contains the other); 'rsync -a --delete' targets HOST_RUNTIME_DIR, so staging would delete the source it is reading from"
fi
if paths_overlap "$MODELS_SRC" "$HOST_RUNTIME_DIR"; then
  die "HOST_RUNTIME_DIR=$HOST_RUNTIME_DIR and the bundle models $MODELS_SRC overlap (one contains the other); 'rsync -a --delete' targets HOST_RUNTIME_DIR, so staging would delete the models the next step copies from"
fi
# HOST_REDIS_DIR may live outside HOST_DATA_DIR, and then the guard above does not
# reach it: the redis AOF is still a tree the rsync must not delete.
if paths_overlap "$HOST_REDIS_DIR" "$HOST_RUNTIME_DIR"; then
  die "HOST_RUNTIME_DIR=$HOST_RUNTIME_DIR and HOST_REDIS_DIR=$HOST_REDIS_DIR overlap (one contains the other); 'rsync -a --delete' targets HOST_RUNTIME_DIR, so staging would delete the redis AOF"
fi
# TAA's own state directory holds the keys directory TAA identifies itself through -
# the SM2 key pair, and state.sealed beside it. It gets a bind of its own precisely so
# those stay out of the tree the FHE stack reads, and that only holds while it stays
# outside both trees that stack mounts: HOST_DATA_DIR (as /data in api and worker, and
# the tree the whole FHE contract is built on) and HOST_REDIS_DIR (as /data in
# fhe-redis). Nesting counts - a bind of $HOST_DATA_DIR/keys is still a directory under
# /data - and the 0700 taa enforces on the keys directory does not cover this either:
# that mode keeps out a non-root container user, not a root one.
if paths_overlap "$HOST_TAA_STATE_DIR" "$HOST_DATA_DIR"; then
  die "HOST_TAA_STATE_DIR=$HOST_TAA_STATE_DIR and HOST_DATA_DIR=$HOST_DATA_DIR overlap (one is the other, or one contains the other); the FHE stack mounts HOST_DATA_DIR as /data, so TAA's SM2 key pair and sealed instance state would be readable from inside the FHE containers, which is what the second bind exists to prevent"
fi
# HOST_REDIS_DIR may live outside HOST_DATA_DIR, and then the guard just above does
# not reach it: the redis container mounts that directory as /data, so the key pair
# is reachable from there instead.
if paths_overlap "$HOST_TAA_STATE_DIR" "$HOST_REDIS_DIR"; then
  die "HOST_TAA_STATE_DIR=$HOST_TAA_STATE_DIR and HOST_REDIS_DIR=$HOST_REDIS_DIR overlap (one contains the other); the FHE stack mounts HOST_REDIS_DIR as /data in fhe-redis, so TAA's SM2 key pair and sealed instance state would be readable from inside that container"
fi
# And the rsync above, from the other side: it targets HOST_RUNTIME_DIR with --delete,
# so a state directory inside it would be deleted on every re-stage, taking the SM2 key
# pair and the sealed state with it.
if paths_overlap "$HOST_TAA_STATE_DIR" "$HOST_RUNTIME_DIR"; then
  die "HOST_TAA_STATE_DIR=$HOST_TAA_STATE_DIR and HOST_RUNTIME_DIR=$HOST_RUNTIME_DIR overlap (one contains the other); 'rsync -a --delete' targets HOST_RUNTIME_DIR, so staging would delete TAA's SM2 key pair and sealed instance state"
fi
# And the copy itself: 'cp -a $MODELS_SRC/. $STAGED_MODELS_DIR/' recurses when the
# source is inside the destination or the other way round. Equality is the bundle's
# own data directory being used in place, which the copy skips.
if paths_overlap "$MODELS_SRC" "$STAGED_MODELS_DIR" && ! same_path "$MODELS_SRC" "$STAGED_MODELS_DIR"; then
  die "$STAGED_MODELS_DIR and the bundle models $MODELS_SRC overlap (one contains the other); 'cp -a' would copy a tree into itself"
fi
# deploy/start.sh is the supervisor this script now runs TAA under, and it owns
# /root/taa: it cds there, runs ./taa there -- which is how taa finds
# ./taa-config.json -- and logs to /root/taa/taa.log. A different workdir would
# place the rendered config where the supervisor never looks, and taa would come up
# on the config baked into the image while this script reported success.
if [ "$TAA_CONTAINER_WORKDIR" != "/root/taa" ]; then
  die "TAA_CONTAINER_WORKDIR=$TAA_CONTAINER_WORKDIR, but deploy/start.sh runs taa in /root/taa and taa reads ./taa-config.json from its working directory; the rendered config would never be read"
fi
# TAA_CONTAINER_CONFIG_PATH decides the same thing from the other end, so it gets
# the same treatment rather than being left as a knob that silently stops the
# supervisor from seeing the rendered config.
if [ "$TAA_CONTAINER_CONFIG_PATH" != "$TAA_CONTAINER_WORKDIR/$TAA_CONFIG_FILE" ]; then
  die "TAA_CONTAINER_CONFIG_PATH=$TAA_CONTAINER_CONFIG_PATH, but deploy/start.sh runs taa with no --config, so taa reads $TAA_CONTAINER_WORKDIR/$TAA_CONFIG_FILE; the rendered config would never be read"
fi
# And the one path only a --remote run has: where the upload writes the bundle. It is
# 'rsync -a --delete', so a destination that is one of the trees this deployment has
# to keep -- or that contains one -- would delete state instead of refreshing a
# bundle. REMOTE_DIR itself is not refused in general; it is caught here exactly
# because the binaries and the supervisor live under it.
if [ -n "$REMOTE_TARGET" ]; then
  case "$REMOTE_HANDOFF_DIR" in
    ""|/) die "REMOTE_HANDOFF_DIR='$REMOTE_HANDOFF_DIR' is not a directory the bundle may be uploaded into: the upload runs 'rsync -a --delete' there" ;;
  esac
  remote_keep_paths=("$HOST_DATA_DIR" "$HOST_RUNTIME_DIR" "$HOST_TAA_STATE_DIR" "$HOST_REDIS_DIR" "$HOST_TAA_BINARY_PATH" "$HOST_START_SH")
  if [ "$DEPLOY_PLATFORM_MOCK" = 1 ]; then
    remote_keep_paths+=("$PLATFORM_MOCK_STATE_DIR" "$PLATFORM_MOCK_UPLOAD_DIR")
  fi
  # The image archive is on the list only when it is not the bundle's own. The one the
  # bundle ships lives inside the uploaded tree by design -- the upload is what puts it
  # there, and the run loads it from there -- so holding the destination away from it
  # would refuse every default run.
  if ! same_path "$FHE_IMAGE_ARCHIVE" "$BUNDLE_IMAGE_ARCHIVE"; then
    remote_keep_paths+=("$HOST_FHE_IMAGE_ARCHIVE")
  fi
  for remote_keep in "${remote_keep_paths[@]}"; do
    if path_contains "$REMOTE_HANDOFF_DIR" "$remote_keep"; then
      die "REMOTE_HANDOFF_DIR=$REMOTE_HANDOFF_DIR contains $remote_keep, which has to survive this run; the upload's 'rsync -a --delete' would delete it (set REMOTE_HANDOFF_DIR to a directory of its own)"
    fi
  done
fi

# ── Steps ────────────────────────────────────────────────────────────────────

if is_dry_run; then
  log "dry-run: nothing will be executed; the tool preflight is skipped"
else
  # Split by the machine that runs each command, not by what it does. jq, sha256sum,
  # awk and realpath are this script's own: it renders the config, verifies the bundle
  # and compares paths here, and the deployment host needs none of them. docker, curl
  # and rsync are the host's -- every use below goes through run/run_in/host_sh -- and
  # realpath is here for the path guards above, which answer "no overlap" when it is
  # missing, so it is checked like the rest.
  for cmd in jq sha256sum awk realpath; do
    require_command "$cmd"
  done
  for cmd in docker curl rsync; do
    require_host_command "$cmd"
  done
  # The save action assembles and exports the image on this machine, so docker
  # has to be here as well; the host check above still covers the `docker load`
  # it runs afterwards by default.
  if [ "$SAVE_ACTION" = 1 ]; then
    require_command docker
  fi
  # Checked here rather than in the last step so a missing template cannot fail after
  # the FHE stack is already up. Both belong to the TAA side, so a run that deploys
  # only the FHE stack does not need them.
  if [ "$DEPLOY_TAA" = 1 ]; then
    if [ "$SAVE_ACTION" != 1 ]; then
      [ -f "$TAA_FHE_CONFIG" ] || die "TAA config template not found: $TAA_FHE_CONFIG"
    fi
    # The supervisor is installed into the container, not taken from the image: a base
    # image that never carried one would otherwise leave taa unsupervised. A save run
    # bakes this same file in, so it needs it just as much as a deploy does.
    [ -f "$PROJECT_DIR/deploy/start.sh" ] || die "TAA supervisor script missing: $PROJECT_DIR/deploy/start.sh"
  fi
  if [ "$DEPLOY_FHE_STACK" = 1 ]; then
    # The GPU is the one thing about the deployment host that can be wrong without any
    # command failing. The FHE worker's runtime is built for Ada (CUDA arch 89, per the
    # bundle's build-info/manifest.json), needs roughly 45 GiB of free card memory to
    # start, and is a Hygon DCU's non-starter because it is CUDA. Reported rather than
    # refused -- this script cannot know what else the card is for -- and reported here,
    # before 300 MiB is uploaded, so the operator sees it before the wait.
    gpu_report="$(host_capture 'nvidia-smi --query-gpu=name,compute_cap,memory.total,memory.used --format=csv,noheader' 2>/dev/null || true)"
    if [ -n "$gpu_report" ]; then
      while IFS= read -r gpu_line; do
        [ -n "$gpu_line" ] && log "GPU on ${REMOTE_TARGET:-this host}: $gpu_line"
      done <<<"$gpu_report"
    else
      warn "nvidia-smi reported no GPU on ${REMOTE_TARGET:-this host}; the FHE worker needs a CUDA device, and the bundled runtime is built for compute capability 8.9 (Ada)"
    fi
  fi
fi
if [ "$DEPLOY_FHE_STACK" = 1 ]; then
  report_stack_binding
fi

if [ "$DEPLOY_FHE_STACK" = 1 ]; then
step "verifying the bundle artifacts this deployment consumes"
# Before the load below, not after: an archive that verifies is imported into the
# daemon, and until it verifies nothing of it should be. FHE_IMAGE_ARCHIVE is
# overridable, so the checksum is taken over the file that gets loaded: verifying
# the default while loading an override verifies nothing about what runs.
#
# Which digest it can be taken against depends on which archive it is. The
# bundle's own archive is covered by the SHA256SUMS the bundle ships, and that
# check stays exactly as it was. An archive the bundle does not ship -- a
# self-built or pulled image, which is what the override is for -- is not in those
# manifests, and holding it to another archive's digest rejects it for merely
# differing. So it is verified against FHE_IMAGE_ARCHIVE_SHA256 when the operator
# supplies one, and otherwise loaded unverified with a warning that names the
# check that did not happen: a silent skip is what this whole step exists to
# prevent.
if same_path "$FHE_IMAGE_ARCHIVE" "$BUNDLE_IMAGE_ARCHIVE"; then
  verify_one image/latti-server-latest.tar.gz "$FHE_IMAGE_ARCHIVE"
elif [ -n "$FHE_IMAGE_ARCHIVE_SHA256" ]; then
  verify_one image/latti-server-latest.tar.gz "$FHE_IMAGE_ARCHIVE" "$FHE_IMAGE_ARCHIVE_SHA256"
else
  warn "FHE_IMAGE_ARCHIVE=$FHE_IMAGE_ARCHIVE is not the archive this bundle ships ($BUNDLE_IMAGE_ARCHIVE), so it is NOT covered by $HANDOFF_DIR/SHA256SUMS; set FHE_IMAGE_ARCHIVE_SHA256=<sha256> to have it verified"
  if ! is_dry_run; then
    [ -f "$FHE_IMAGE_ARCHIVE" ] || die "missing artifact: $FHE_IMAGE_ARCHIVE"
  fi
fi
# This one covers third_party/latti-ai-runtime.tar.gz, while the staging step
# rsyncs third_party/latti-ai-runtime/ -- the unpacked directory beside it, which
# SHA256SUMS carries no checksum for. Unpacking the verified tarball here would be
# the way to bind them, and it is not worth what it costs: the bundle's own env
# names that directory, the delivery ships them as one tree, and an empty or
# missing directory is already refused below. It stays a gap by choice.
verify_one third_party/latti-ai-runtime.tar.gz
fi

if [ "$DEPLOY_TAA" = 1 ] || [ "$DEPLOY_MOCK" = 1 ]; then
step "building the binaries this run deploys"
# Each binary is built only for the side that runs it: a taa-only run does not
# build platform-mock, and a platform-mock-only run does not build TAA. Both are
# built on this machine and pushed, so a deployment runs the commit it was
# launched from: the TAA binary is copied into the container below, and
# platform-mock is the control-plane stand-in the last gate reads. --skip-build
# keeps whatever is already at the paths below, for a run that has just built
# them, and is then held to those files actually existing.
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
else
  log "fhe-only run: nothing is built here; the FHE stack runs the image the bundle ships"
fi

if [ "$SAVE_ACTION" = 1 ]; then
  log "save run: the binary and supervisor are packaged here; the only thing uploaded is the finished archive, in the save step below"
else
step "uploading this run's inputs to ${REMOTE_TARGET:-this host}"
# Everything the host-side commands read has to be there first: the bundle, which
# `docker load` and the staging rsync read from; the supervisor, which docker cp
# copies into the container; and the two binaries. The rendered config is the one
# exception -- it does not exist yet, and the step that renders it uploads it. A run
# that deploys one side uploads only that side's inputs.
if [ -z "$REMOTE_TARGET" ]; then
  log "local run: the bundle is read where it is, and the binaries the step above wrote are where the commands below look for them"
else
  if [ "$DEPLOY_FHE_STACK" = 1 ]; then
    log "uploading $HANDOFF_DIR to $REMOTE_TARGET:$REMOTE_HANDOFF_DIR; this is the long part of a remote run"
    upload_tree "$HANDOFF_DIR" "$REMOTE_HANDOFF_DIR"
  fi
  if [ "$DEPLOY_TAA" = 1 ]; then
    upload_file "$PROJECT_DIR/deploy/start.sh" "$HOST_START_SH" 755
    upload_file "$TAA_BINARY_PATH" "$HOST_TAA_BINARY_PATH" 755
  fi
  if [ "$DEPLOY_MOCK" = 1 ] && [ "$DEPLOY_PLATFORM_MOCK" = 1 ]; then
    upload_file "$PLATFORM_MOCK_BINARY_PATH" "$HOST_PLATFORM_MOCK_BINARY_PATH" 755
  fi
fi
fi

if [ "$SAVE_ACTION" = 1 ]; then
step "packaging the taa-fhe image locally ($TAA_FHE_SAVE_IMAGE)"
# The image is assembled and exported on this machine, then shipped: docker and
# the base image are here, and the archive belongs in deploy/ beside the
# base-image archives. It carries the binary from the build step, the supervisor
# start.sh runs from, and the rendered config at the path taa reads by default.
# Baking the config is what makes the image bootable on its own -- a k8s pod or a
# bare docker run starts it without the deploy path's copy step. A deploy-fhe.sh
# taa run still renders and copies its own config every time, so the baked one is
# a fallback there rather than the one that decides. It carries the callback
# token, so the image itself is as sensitive as that token.
#
# The entrypoint is installed for the same reason deploy.sh installs it on its
# save path: without one, whatever the base image carried decides how the
# container starts. The deploy path overrides it with `--entrypoint tail` and
# starts start.sh itself, so the two do not disagree.
if ! is_dry_run; then
  docker info >/dev/null 2>&1 || die "docker daemon is not running or accessible on this machine"
  # A machine that has only the delivery files can still package: the base
  # image archive deploy.sh writes is the same fallback its own save path uses.
  if ! docker image inspect "$TAA_IMAGE" >/dev/null 2>&1; then
    [ -f "$TAA_BASE_IMAGE_ARCHIVE" ] \
      || die "base image $TAA_IMAGE is not present and no archive was found at $TAA_BASE_IMAGE_ARCHIVE"
    log "loading base image $TAA_IMAGE from $TAA_BASE_IMAGE_ARCHIVE"
    docker load -i "$TAA_BASE_IMAGE_ARCHIVE" || die "failed to load $TAA_BASE_IMAGE_ARCHIVE"
  fi
  # Render before the builder exists, so a template jq rejects fails the run
  # without leaving a container behind. A --remote run already created
  # TAA_RENDER_TMPDIR at startup; a --local save has none, so create one. The
  # EXIT trap removes it either way, keeping a file that carries the callback
  # token from surviving the run.
  if [ -z "${TAA_RENDER_TMPDIR:-}" ]; then
    TAA_RENDER_TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/deploy-fhe-save.XXXXXX")" \
      || die "cannot create a temporary directory for the rendered config"
  fi
  TAA_RENDER_OUT="$TAA_RENDER_TMPDIR/$TAA_CONFIG_FILE"
  # 0: the config is baked into the image here, so there is no deployment host
  # to upload it to on this path.
  render_taa_config 0
else
  log "would render $TAA_FHE_CONFIG -> $TAA_CONTAINER_WORKDIR/$TAA_CONFIG_FILE (callback $TAA_CALLBACK_BASE_URL) and bake it into the image"
fi
builder="taa-fhe-builder-$$"
SAVE_BUILDER_CONTAINER="$builder"
run_local docker run -d --name "$builder" --entrypoint tail "$TAA_IMAGE" -f /dev/null
run_local docker exec -i "$builder" sh -lc "mkdir -p '$TAA_CONTAINER_WORKDIR'"
run_local docker cp "$PROJECT_DIR/deploy/start.sh" "$builder:$TAA_CONTAINER_WORKDIR/start.sh"
run_local docker cp "$TAA_BINARY_PATH" "$builder:$TAA_CONTAINER_WORKDIR/$BINARY_NAME"
if ! is_dry_run; then
  run_local docker cp "$TAA_RENDER_OUT" "$builder:$TAA_CONTAINER_WORKDIR/$TAA_CONFIG_FILE"
fi
run_local docker exec -i "$builder" sh -lc "chmod +x '$TAA_CONTAINER_WORKDIR/start.sh' '$TAA_CONTAINER_WORKDIR/$BINARY_NAME' && chmod 600 '$TAA_CONTAINER_WORKDIR/$TAA_CONFIG_FILE'"
# start.sh treats a `manual` marker in the workdir as "do not start taa" and
# appends to taa.log. Either one surviving in the base image would make a freshly
# packaged node look deployed while taa never runs, or present a previous
# deployment's log as though it belonged to this image. Both are build residue,
# not content.
run_local docker exec -i "$builder" sh -lc "rm -f '$TAA_CONTAINER_WORKDIR/manual' '$TAA_CONTAINER_WORKDIR/manual-teellm' '$TAA_CONTAINER_WORKDIR/taa.log'"
run_local docker commit \
  -c 'ENTRYPOINT ["bash", "/root/taa/start.sh"]' \
  -c 'CMD []' \
  -c 'WORKDIR /root/taa' \
  -c 'EXPOSE 6001' \
  -m "taa-fhe image packaged from $TAA_IMAGE at $(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  "$builder" "$TAA_FHE_SAVE_IMAGE"
run_local docker rm -f "$builder"
SAVE_BUILDER_CONTAINER=""

step "saving the image archive to $TAA_FHE_SAVE_ARCHIVE"
# The temporary name is what keeps a half-written archive from looking like a
# package. pigz when this machine has it: the base image alone is tens of
# gigabytes, and the difference is minutes rather than seconds.
if ! is_dry_run; then
  mkdir -p "$(dirname "$TAA_FHE_SAVE_ARCHIVE")"
fi
compressor="gzip"
if ! is_dry_run && command -v pigz >/dev/null 2>&1; then
  compressor="pigz"
fi
save_tmp="${TAA_FHE_SAVE_ARCHIVE}.tmp.$$"
# pipefail matters here: without it a failing `docker save` leaves pigz/gzip
# compressing an empty stream, exiting 0, and the `mv` below would publish a
# truncated archive under the real name.
if is_dry_run; then
  log "would run: bash -lc set -euo pipefail; docker save $TAA_FHE_SAVE_IMAGE | $compressor -c > $save_tmp && mv -f $save_tmp $TAA_FHE_SAVE_ARCHIVE"
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
  # The host copy is kept: it is the delivered archive on the remote side, so a
  # re-load or a later deployment does not need to upload tens of gigabytes
  # again. It is left where it was uploaded, at $host_archive.
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
  log "image      : $TAA_FHE_SAVE_IMAGE"
  log "base image : $TAA_IMAGE"
  log "contents   : $TAA_CONTAINER_WORKDIR/$BINARY_NAME, start.sh and $TAA_CONFIG_FILE baked in"
  log "archive    : $TAA_FHE_SAVE_ARCHIVE (${archive_mb}MB)"
  if [ -n "$REMOTE_TARGET" ]; then
    log "loaded on  : $REMOTE_TARGET"
    log "remote copy: $REMOTE_DIR/$(basename "$TAA_FHE_SAVE_ARCHIVE") (kept)"
  fi
  log "deploy with: TAA_IMAGE=$TAA_FHE_SAVE_IMAGE ./deploy-fhe.sh taa"
  log "config     : $TAA_CONTAINER_WORKDIR/$TAA_CONFIG_FILE baked in (rendered from $(basename "$TAA_FHE_CONFIG"))"
  log "             a deploy-fhe.sh taa run renders and copies its own config over it"
fi
exit 0
fi

if [ "$DEPLOY_FHE_STACK" = 1 ]; then
step "importing $FHE_IMAGE from the handoff bundle"
run docker load -i "$HOST_FHE_IMAGE_ARCHIVE"
if is_dry_run; then
  log "would assert image $FHE_IMAGE is present"
else
  host_sh "docker image inspect $(shell_quote "$FHE_IMAGE") >/dev/null 2>&1" \
    || die "image $FHE_IMAGE not found after loading $HOST_FHE_IMAGE_ARCHIVE"
  log "image $FHE_IMAGE is present"
fi

step "staging the FHE runtime and models"
# HOST_DATA_DIR may legitimately be the bundle's own data directory (that is the
# path the bundle's env/node.local.env names), and then the copy below would have
# source == destination: GNU cp fails with "'...' and '...' are the same file",
# exit 1, and `set -e` kills the run after this step has created the data
# subdirectories but before any model is in place -- a half-staged node. The rsync
# is a silent no-op in the same situation, so it is skipped here too rather than
# left to look like work.
if same_path "$RUNTIME_SRC" "$HOST_RUNTIME_DIR"; then
  log "runtime already in place: $HOST_RUNTIME_DIR is the bundle's own third_party/latti-ai-runtime"
else
  # --delete is kept deliberately: it is what makes a re-staged runtime match the
  # bundle instead of accumulating shared objects from an older handoff, and a stale
  # .so is a silently wrong deployment. The overlap guards above are what make it
  # safe, and the checks below close the one way it still destroys something: an
  # empty or missing source would empty the destination. They are skipped in
  # --dry-run, which deletes nothing and has to stay runnable on a host the bundle
  # is not unpacked on.
  if ! is_dry_run; then
    host_sh "test -d $(shell_quote "$RUNTIME_SRC")" || die "runtime source not found: $RUNTIME_SRC"
    # `ls` failing is not the same as `ls` succeeding with nothing to say: a
    # directory this user cannot read reports the same empty string as an empty one,
    # and calling that "the source is empty" hides the permission problem behind a
    # diagnosis that would send the operator looking at the bundle instead.
    src_entries="$(host_capture "ls -A $(shell_quote "$RUNTIME_SRC")" 2>/dev/null)" \
      || die "runtime source is not readable: $RUNTIME_SRC"
    [ -n "$src_entries" ] || die "runtime source is empty: $RUNTIME_SRC (rsync -a --delete would empty $HOST_RUNTIME_DIR)"
  fi
  run mkdir -p "$HOST_RUNTIME_DIR"
  run rsync -a --delete "$RUNTIME_SRC/" "$HOST_RUNTIME_DIR/"
fi
run mkdir -p "$HOST_DATA_DIR"/{models,keys,tasks,results} "$HOST_REDIS_DIR"
if same_path "$MODELS_SRC" "$STAGED_MODELS_DIR"; then
  log "models already in place: $STAGED_MODELS_DIR is the bundle's own data/models"
else
  # The destination is created just above; the source is not checked anywhere else,
  # and a missing one is a bundle that was never unpacked rather than an empty
  # delivery, so it says which of the two it is instead of leaving `cp` to print its
  # own error. Skipped in --dry-run for the same reason the runtime checks are.
  if ! is_dry_run; then
    host_sh "test -d $(shell_quote "$MODELS_SRC")" || die "models source not found: $MODELS_SRC"
  fi
  run cp -a "$MODELS_SRC/." "$STAGED_MODELS_DIR/"
fi
# After the copy, not before it: `cp -a` gives models/ the source directory's mode,
# and on a bundle whose models are not group- or world-traversable that would be the
# last word on the mode and put the directory back out of the containers' reach.
#
# These are the directories the api, worker and redis containers enter through a bind
# mount, and they run as a uid other than this script's, so every one of them has to
# stay traversable. mkdir cannot be relied on for that: its mode argument is masked
# by the caller's umask, and it is ignored entirely for a directory that already
# exists -- which is every one of these on a second run. Under `umask 077` all five
# were left 0700, and the service could not enter them at all. The mode is therefore
# set explicitly, on every run, and separately from the mkdir. It is the mode a
# default umask already produced, so nothing that works today changes; only the
# restrictive-umask case does.
run chmod 755 "$HOST_DATA_DIR" "$HOST_DATA_DIR"/{models,keys,tasks,results} "$HOST_REDIS_DIR"
fi

if [ "$DEPLOY_MOCK" = 1 ]; then
step "starting platform-mock on $PLATFORM_ADDR"
# In the bare form this runs before the FHE stack, and well before TAA: TAA
# registers within a few seconds of
# coming up, and a mock that is not listening yet turns that registration into the
# background retry loop it is designed to be -- which is exactly what this hunk of the
# run exists to observe, so it must not be the thing that is being observed.
#
# -allow-empty-attestation is not optional. A type=fhe instance writes an empty
# attestation by design (internal/app/taa), and the mock rejects a registration
# carrying one unless that flag is set -- so a run without it reports a TAA that came
# up healthy and a platform that never heard from it, with nothing naming the flag.
if [ "$DEPLOY_PLATFORM_MOCK" != 1 ]; then
  log "--no-platform-mock: nothing started here; TAA registers with PLATFORM_IP=${PLATFORM_IP:-<unset: platform.ip in the template decides>}"
else
  # The one place PLATFORM_IP gets a default, because this is the one place the mock's
  # address is known to this script. TAA runs on the host network (TAA_DOCKER_NETWORK),
  # so 127.0.0.1 means the host from inside its container as well. Computed outside the
  # dry-run branch below on purpose: the TAA container's environment is settled in a
  # later step, and a plan that left out an -e the real run would add is a plan that
  # does not describe the run.
  PLATFORM_IP="${PLATFORM_IP:-127.0.0.1:$PLATFORM_PORT}"
  if is_dry_run; then
    log "would probe http://127.0.0.1:$PLATFORM_PORT/api/register/status, start $HOST_PLATFORM_MOCK_BINARY_PATH if nothing answers, clear its register state, and give TAA PLATFORM_IP=$PLATFORM_IP"
  else
    if host_sh "curl -fsS -o /dev/null 'http://127.0.0.1:${PLATFORM_PORT}/api/register/status'"; then
      warn "something already answers on 127.0.0.1:$PLATFORM_PORT; reusing it instead of starting a second platform-mock. This run cannot see how that process was started, so -allow-empty-attestation is not confirmed, and clearing its register state below affects whatever else is using it."
    else
      host_detach "$REMOTE_DIR/platform-mock.log" "$REMOTE_DIR/platform-mock.pid" \
        "$HOST_PLATFORM_MOCK_BINARY_PATH" \
        -addr "$PLATFORM_ADDR" \
        -state-dir "$PLATFORM_MOCK_STATE_DIR" \
        -upload-dir "$PLATFORM_MOCK_UPLOAD_DIR" \
        -taa-target "http://127.0.0.1:$TAA_PORT" \
        -allow-empty-attestation
      wait_for_platform_mock \
        || die "platform-mock did not answer on 127.0.0.1:$PLATFORM_PORT within ${PLATFORM_READY_TIMEOUT}s (log $REMOTE_DIR/platform-mock.log)"
      log "platform-mock is answering on 127.0.0.1:$PLATFORM_PORT (state $PLATFORM_MOCK_STATE_DIR)"
    fi
    # The mock keeps its register state in a file that outlives this run, and the gate
    # at the end reads it. Clearing it here is what makes that gate a statement about
    # *this* run: otherwise a registration recorded on a previous run satisfies it
    # while the TAA started below never reached the platform at all.
    run curl -fsS -o /dev/null -X POST "http://127.0.0.1:${PLATFORM_PORT}/api/register/reset" \
      || die "could not clear the register state on http://127.0.0.1:${PLATFORM_PORT}"
  fi
fi
fi

if [ "$DEPLOY_FHE_STACK" = 1 ]; then
step "starting the FHE node stack (api + worker + redis)"
# run_node, not run_in: the values that point the stack at the tree staged in the
# previous step have to travel on the command line to reach a remote host at all.
FHE_STACK_TOUCHED=1
run_node up -d

step "preflight: the FHE stack is serving on 127.0.0.1:$API_HOST_PORT"
if is_dry_run; then
  log "would wait up to ${FHE_READY_TIMEOUT}s for GET http://127.0.0.1:${API_HOST_PORT}/api/v1/health"
else
  wait_for_fhe_stack || {
    # What the stack step left, so a stack that never comes up is diagnosable from
    # this output rather than from a second run: compose's own state, and the api
    # container's log, which is where a failed model load reports itself.
    host_sh "docker ps -a --filter 'name=fhe-' --format '{{.Names}}  {{.Status}}'" || true
    die "FHE stack did not answer GET http://127.0.0.1:${API_HOST_PORT}/api/v1/health within ${FHE_READY_TIMEOUT}s (logs: cd $NODE_DOCKER_DIR && ./scripts/run-node.sh logs --tail=50)"
  }
fi
if is_dry_run; then
  log "would check on ${REMOTE_TARGET:-this host}: test -w $HOST_DATA_DIR"
else
  host_sh "test -w $(shell_quote "$HOST_DATA_DIR")" || die "$HOST_DATA_DIR is not writable"
fi
# A model must activate before a task can run. The bundled cifar10 model is the
# one the delivery bundle measured against.
run curl -fsS -o /dev/null -X POST \
  "http://127.0.0.1:${API_HOST_PORT}/api/v1/models/activate?model_id=${FHE_MODEL_ID}" \
  || die "model activation failed"
fi

if [ "$DEPLOY_TAA" = 1 ]; then
step "starting the TAA fhe instance"
# A taa-only run never runs the staging step, which is what normally creates
# HOST_DATA_DIR -- and the rendered config is written under it. Creating it here is
# also what a TAA container needs: it bind-mounts this directory.
run mkdir -p "$HOST_DATA_DIR"
if is_dry_run; then
  log "would render $TAA_FHE_CONFIG -> $TAA_RENDERED_CONFIG (callbackBaseUrl, callbackToken, endpoint, dataDir, keyCacheDir, storage.result, storage.keys)"
else
  render_taa_config
fi
if [ "$TAA_DOCKER_NETWORK" != "host" ]; then
  warn "TAA_DOCKER_NETWORK=$TAA_DOCKER_NETWORK, but fhe.endpoint is http://127.0.0.1:${API_HOST_PORT}: inside a non-host network 127.0.0.1 is the TAA container itself"
  # The same mistake on the other address this run hands the container, and quieter:
  # the registration that follows would go to whatever answers on that port inside the
  # container's own network, or to nothing, and the platform would simply never hear
  # from this node.
  if [ -n "$PLATFORM_IP" ]; then
    case "$PLATFORM_IP" in
      127.0.0.1:*|localhost:*) warn "PLATFORM_IP=$PLATFORM_IP, but TAA_DOCKER_NETWORK=$TAA_DOCKER_NETWORK: inside a non-host network that address is the TAA container itself, not the platform, so the registration will not reach it" ;;
    esac
  fi
fi
start_taa_container
TAA_CONTAINER_TOUCHED=1

# TAA runs under deploy/start.sh, the same supervisor deploy.sh installs. Its
# container's PID 1 is `tail -f /dev/null`, which never exits, so without the
# supervisor a taa that dies after this script exits -- panic, OOM, a corrupt eval
# key -- stays dead and unlogged while the node keeps looking deployed, where
# deploy.sh's readiness gate would otherwise keep being retried.
#
# Every command from here to the nohup below acts inside the container the step
# just settled on. A dry run never creates one, so it names that rather than
# printing the copies as if they ran against something.
if is_dry_run; then
  log "dry-run: the copies and execs below target the container the step above would leave ($TAA_CONTAINER_NAME); nothing is copied here, since the rendered config is not written either"
fi
run docker exec -i "$TAA_CONTAINER_NAME" sh -lc "mkdir -p '$TAA_CONTAINER_WORKDIR'"
run docker cp "$HOST_START_SH" "$TAA_CONTAINER_NAME:$TAA_CONTAINER_WORKDIR/start.sh"
run docker exec -i "$TAA_CONTAINER_NAME" sh -lc "chmod +x '$TAA_CONTAINER_WORKDIR/start.sh'"
# The binary, from the build step, over whatever the base image carries. start.sh runs
# ./taa from the workdir, so this is the file that decides which commit a deployment
# runs; without it the run would report success while the image's own binary served.
# The path is inside the workdir rather than on either bind, so it is the container's
# writable layer and is refreshed on every run -- recreated containers included.
run docker cp "$HOST_TAA_BINARY_PATH" "$TAA_CONTAINER_NAME:$TAA_CONTAINER_WORKDIR/$BINARY_NAME"
run docker exec -i "$TAA_CONTAINER_NAME" sh -lc "chmod +x '$TAA_CONTAINER_WORKDIR/$BINARY_NAME'"
# Copied rather than rendered through the data-directory mount: start.sh runs ./taa
# with no --config, so the config has to be at the path taa reads by default.
run docker cp "$TAA_RENDERED_CONFIG" "$TAA_CONTAINER_NAME:$TAA_CONTAINER_CONFIG_PATH"

# Whatever a previous run left has to be gone first: start.sh holds a singleton
# flock, so a surviving supervisor would make this one exit at once and the
# readiness wait below would then time out against a taa nobody started.
run docker exec -i "$TAA_CONTAINER_NAME" sh -lc "touch '$TAA_CONTAINER_WORKDIR/manual'"
run docker exec -i "$TAA_CONTAINER_NAME" \
  sh -lc "pkill -f '$SUPERVISOR_PATTERN' >/dev/null 2>&1 || true; pkill -x '$BINARY_NAME' >/dev/null 2>&1 || true"
if is_dry_run; then
  log "would wait for any previous start.sh in $TAA_CONTAINER_NAME to exit, then start ./start.sh under nohup"
else
  waited=0
  while [ "$waited" -lt 25 ]; do
    host_sh "docker exec -i '$TAA_CONTAINER_NAME' sh -lc \"pgrep -f '$SUPERVISOR_PATTERN' >/dev/null 2>&1\"" || break
    waited=$((waited + 1))
    sleep 0.2
  done
  # pgrep -f matches the command line, which a zombie no longer has, so a stopped
  # supervisor is really stopped here and this cannot wedge on a defunct process.
  # Each turn is one round trip under --remote, which is why the loop is bounded by a
  # count of turns rather than by seconds.
  if host_sh "docker exec -i '$TAA_CONTAINER_NAME' sh -lc \"pgrep -f '$SUPERVISOR_PATTERN' >/dev/null 2>&1\""; then
    warn "a previous start.sh supervisor is still running in $TAA_CONTAINER_NAME; force-killing it"
    run docker exec -i "$TAA_CONTAINER_NAME" \
      sh -lc "pkill -9 -f '$SUPERVISOR_PATTERN' >/dev/null 2>&1 || true; pkill -9 -x '$BINARY_NAME' >/dev/null 2>&1 || true"
  fi
fi
run docker exec -i "$TAA_CONTAINER_NAME" sh -lc "rm -f '$TAA_CONTAINER_WORKDIR/manual'"
run docker exec -d "$TAA_CONTAINER_NAME" \
  sh -lc "cd '$TAA_CONTAINER_WORKDIR' && nohup bash ./start.sh >/dev/null 2>&1 &"
TAA_SUPERVISOR_STARTED=1

step "waiting for TAA to answer on 127.0.0.1:$TAA_PORT"
if is_dry_run; then
  log "would wait up to ${TAA_READY_TIMEOUT}s for POST http://127.0.0.1:${TAA_PORT}/v1/taa/health"
else
  if ! wait_for_taa; then
    log "taa log ($TAA_LOG_FILE):"
    host_sh "docker exec -i '$TAA_CONTAINER_NAME' sh -lc \"tail -n 60 '$TAA_LOG_FILE' 2>/dev/null || true\"" || true
    die "TAA did not answer POST http://127.0.0.1:${TAA_PORT}/v1/taa/health within ${TAA_READY_TIMEOUT}s"
  fi
  log "TAA fhe instance is ready"
  if [ "$DEPLOY_FHE_STACK" = 1 ]; then
    printf '\n[deploy-fhe] deployment complete\n'
    log "FHE stack      : http://127.0.0.1:${API_HOST_PORT}/api/v1 (model ${FHE_MODEL_ID} activated)"
  else
    printf '\n[deploy-fhe] TAA instance deployed\n'
    log "FHE stack      : http://127.0.0.1:${API_HOST_PORT}/api/v1 (not touched by this run; model activation was not repeated)"
    log "platform-mock  : not touched by this run; TAA registers with PLATFORM_IP=${PLATFORM_IP:-<unset: platform.ip in the rendered config decides>}"
  fi
  log "FHE data dir   : $HOST_DATA_DIR"
  log "FHE runtime    : $HOST_RUNTIME_DIR"
  log "FHE redis dir  : $HOST_REDIS_DIR"
  log "TAA state dir  : $HOST_TAA_STATE_DIR (SM2 key pair and sealed instance state; it is on a bind of its own, so it is the one directory here the FHE containers cannot read)"
  # The readiness probe above proves something answers on $TAA_PORT and nothing
  # more -- any other listener on the host satisfies it -- and `docker exec -d`
  # returning 0 means only that docker delivered the command. So the supervisor is
  # reported as what it was observed to be, with the bracket keeping pgrep from
  # matching the shell that carries the pattern.
  if host_sh "docker exec -i '$TAA_CONTAINER_NAME' sh -lc \"pgrep -f '$SUPERVISOR_PATTERN' >/dev/null 2>&1\""; then
    log "TAA instance   : http://127.0.0.1:${TAA_PORT}/v1/taa/health (container $TAA_CONTAINER_NAME)"
    log "TAA supervisor : deploy/start.sh observed running in $TAA_CONTAINER_NAME; it restarts taa every 10s (log $TAA_LOG_FILE)"
  else
    log "TAA instance   : http://127.0.0.1:${TAA_PORT}/v1/taa/health (container $TAA_CONTAINER_NAME)"
    warn "no running start.sh supervisor observed in $TAA_CONTAINER_NAME: something answers on 127.0.0.1:$TAA_PORT, but nothing will restart taa if it exits (log $TAA_LOG_FILE, stop with docker rm -f $TAA_CONTAINER_NAME)"
  fi
  log "TAA config     : $TAA_RENDERED_CONFIG -> $TAA_CONTAINER_NAME:$TAA_CONTAINER_CONFIG_PATH"
  log "Callback URL   : $TAA_CALLBACK_BASE_URL"
  log "stop the stack : (cd $NODE_DOCKER_DIR && ./scripts/run-node.sh down)"
  log "stop TAA       : docker rm -f $TAA_CONTAINER_NAME"
fi

step "verifying the platform recorded this instance's registration"
# The one check that says the identity this run injected took effect. Everything above
# can pass while the platform never hears from the node: an empty attestation against a
# mock started without -allow-empty-attestation, a dockerId the platform refuses, a
# PLATFORM_IP that reaches nothing -- each of those is a WARNING in TAA's own log and a
# background retry, so "TAA is up" and "the platform knows about it" are two different
# statements and only this one is about the deployment being usable.
if is_dry_run; then
  if [ "$DEPLOY_PLATFORM_MOCK" != 1 ]; then
    log "--no-platform-mock: nothing to ask; this run does not start the platform, so it has no endpoint whose answer it could hold to"
  elif [ "$DEPLOY_MOCK" = 1 ]; then
    log "would read on ${REMOTE_TARGET:-this host}: http://127.0.0.1:$PLATFORM_PORT/api/register/status, and require the dockerId it recorded to be the one this run's identity resolves to"
  else
    log "would read on ${REMOTE_TARGET:-this host}: http://127.0.0.1:$PLATFORM_PORT/api/register/status only if something answers there; a taa-only run does not deploy the mock and does not require one"
  fi
elif [ "$DEPLOY_PLATFORM_MOCK" != 1 ]; then
  log "--no-platform-mock: nothing to ask; this run did not start the platform, so it has no endpoint whose answer it could hold to"
elif [ "$DEPLOY_MOCK" != 1 ] \
  && ! host_sh "curl -fsS -o /dev/null 'http://127.0.0.1:${PLATFORM_PORT}/api/register/status'"; then
  # A taa-only run deploys neither the mock nor the FHE stack, so there may be no
  # platform to ask at the one address this script knows. The registration is still
  # worth checking when a mock from an earlier run is listening; refusing the whole
  # deployment over a platform this run never claimed to start is not.
  warn "taa-only run: nothing answers on 127.0.0.1:$PLATFORM_PORT, so the registration was not checked; deploy platform-mock (./deploy-fhe.sh platform-mock) or point PLATFORM_IP at a live platform to have it verified"
else
  # Which dockerId should have arrived is what this run decided, and saying which of
  # the two sources it came from is half the value of the check: the injected
  # environment wins over the file on a type=fhe instance, and with nothing injected the
  # template's platform block is what the instance reads.
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
    die "platform-mock on 127.0.0.1:$PLATFORM_PORT recorded no registration at all (expected dockerId '$expected_docker_id' from $expected_source). TAA is up, but the platform never heard from it -- the registration warning in the taa log names why (docker exec $TAA_CONTAINER_NAME tail -n 60 $TAA_LOG_FILE)"
  fi
  if [ "$registered_ok" != "true" ]; then
    die "platform-mock recorded dockerId '$registered_id' and REJECTED it: $(printf '%s' "$register_state" | jq -r '.result.message // "no message"' 2>/dev/null || true)"
  fi
  if [ "$registered_id" != "$expected_docker_id" ]; then
    die "platform-mock recorded dockerId '$registered_id', but this run's identity resolves to '$expected_docker_id' (from $expected_source); the instance registered under another identity, which is what a container reused with a stale environment looks like"
  fi
  log "registration confirmed: platform-mock recorded dockerId=$registered_id accepted=true (expected '$expected_docker_id' from $expected_source)"
  log "platform status: http://127.0.0.1:$PLATFORM_PORT/api/register/status"
fi
fi

# An fhe-only run has no TAA step to print a summary, so it gets its own here. Same
# directories a full run reports, minus the TAA ones this run did not deploy.
if [ "$DEPLOY_FHE_STACK" = 1 ] && [ "$DEPLOY_TAA" = 0 ] && ! is_dry_run; then
  printf '\n[deploy-fhe] FHE stack deployed\n'
  log "FHE stack      : http://127.0.0.1:${API_HOST_PORT}/api/v1 (model ${FHE_MODEL_ID} activated)"
  log "FHE data dir   : $HOST_DATA_DIR"
  log "FHE runtime    : $HOST_RUNTIME_DIR"
  log "FHE redis dir  : $HOST_REDIS_DIR"
  log "stop the stack : (cd $NODE_DOCKER_DIR && ./scripts/run-node.sh down)"
fi

# A platform-mock-only run likewise has no TAA step to print a summary.
if [ "$DEPLOY_MOCK" = 1 ] && [ "$DEPLOY_TAA" = 0 ] && ! is_dry_run; then
  printf '\n[deploy-fhe] platform-mock deployed\n'
  log "platform-mock  : http://127.0.0.1:${PLATFORM_PORT} (state $PLATFORM_MOCK_STATE_DIR)"
  log "platform log   : $REMOTE_DIR/platform-mock.log"
fi

# Last line of the script on purpose: a dry run prints this once, after the last step,
# so its position is what says the plan above is the whole plan.
if is_dry_run; then
  log "dry-run complete: nothing was executed"
fi
