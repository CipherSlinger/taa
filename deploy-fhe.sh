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
FHE_IMAGE_ARCHIVE="${FHE_IMAGE_ARCHIVE:-$HANDOFF_DIR/image/latti-server-latest.tar.gz}"
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
# Must match server.addr in $TAA_FHE_CONFIG; the readiness probe below, and the
# URL the FHE containers call back on, both use it.
TAA_PORT="${TAA_PORT:-6001}"
TAA_READY_TIMEOUT="${TAA_READY_TIMEOUT:-120}"
TAA_READY_INTERVAL="${TAA_READY_INTERVAL:-2}"

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

is_dry_run() { [ "$DRY_RUN" = "1" ]; }

# Every external command goes through run/run_in so that DRY_RUN=1 prints the
# plan instead of touching the host.
run() {
  if is_dry_run; then printf '[deploy-fhe] would run: %s\n' "$*"; return 0; fi
  "$@"
}

# Same, for the one command that has to execute in another directory (rsync and
# compose both resolve paths relative to their own working directory).
run_in() {
  local dir="$1"
  shift
  if is_dry_run; then printf '[deploy-fhe] would run: (cd %s && %s)\n' "$dir" "$*"; return 0; fi
  ( cd "$dir" && "$@" )
}

require_command() {
  local name="$1"
  command -v "$name" >/dev/null 2>&1 || die "command '$name' is required but not installed or not in PATH"
}

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Deploy the FHE side on a GPU host: import the Latti server image from the handoff
bundle, stage the FHE runtime and models, start the api/worker/redis stack, then
start this host's TAA instance with server.type=fhe under the deploy/start.sh
supervisor.

Options:
  -n, --dry-run
      Print the commands that would run and execute nothing. Needs no GPU, no
      FHE stack and no Docker.
  -h, --help
      Display this help documentation.

Environment:
  HANDOFF_DIR=${HANDOFF_DIR}
      Delivery bundle (image/, third_party/, data/, deploy/docker/).
  HOST_DATA_DIR=${HOST_DATA_DIR:-}
      Shared directory the FHE stack mounts as /data and TAA reads as fhe.dataDir.
      The script exports it (and HOST_RUNTIME_DIR, HOST_REDIS_DIR, API_HOST_PORT
      below) before starting the stack, and run-node.sh keeps an exported value
      over the one in env/node.local.env -- so the stack uses this path whatever
      the env file says, and the stack and TAA share one directory by
      construction rather than by hand-alignment.
  HOST_RUNTIME_DIR=${HOST_RUNTIME_DIR:-}
      Where the FHE runtime from the bundle is staged; mounted read-only by the
      stack. 'rsync -a --delete' targets it, so it must not be the data
      directory, must not contain it and must not be inside it: the run refuses
      otherwise, before anything is deleted.
  HOST_REDIS_DIR=${HOST_REDIS_DIR:-$HOST_DATA_DIR/redis}
      Redis AOF directory the stack mounts as /data in fhe-redis. Defaults to a
      directory inside HOST_DATA_DIR; set it to keep an AOF that already exists
      elsewhere.
  TAA_FHE_CONFIG=${TAA_FHE_CONFIG:-}
      TAA configuration template rendered with the callback URL/token below.
      Defaults to $PROJECT_DIR/configs/taa-fhe.json; an override is used as given.
  TAA_CALLBACK_BASE_URL=${TAA_CALLBACK_BASE_URL:-}
      Base URL of this TAA instance as the FHE containers reach it.
  TAA_CALLBACK_TOKEN=${TAA_CALLBACK_TOKEN:-}
      Shared secret the FHE service presents on the callback endpoint. Required:
      an unauthenticated callback endpoint is open to every local process.
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
      Archive verified and then loaded by 'docker load'.
  FHE_MODEL_ID=${FHE_MODEL_ID}
      Model activated on the stack before a task can run.
  TAA_IMAGE=${TAA_IMAGE}
      TAA image started on this host (deploy.sh builds it).
  TAA_CONTAINER_NAME=${TAA_CONTAINER_NAME}
      TAA container name.
  TAA_CONTAINER_WORKDIR=${TAA_CONTAINER_WORKDIR}
      Working directory inside the TAA container. deploy/start.sh owns /root/taa:
      it cds there, runs ./taa there and logs to /root/taa/taa.log, so this must
      stay /root/taa. The rendered config is placed at
      \$TAA_CONTAINER_WORKDIR/$TAA_CONFIG_FILE, the path taa reads by default.
  TAA_CONTAINER_CONFIG_PATH=${TAA_CONTAINER_CONFIG_PATH}
      Path inside the container the rendered config is copied to. Changing it
      stops the supervisor from seeing the rendered config.
  TAA_RENDERED_CONFIG=${TAA_RENDERED_CONFIG}
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
  DRY_RUN=${DRY_RUN}
      Same as --dry-run. A dry run prints <unset> for the required inputs above
      that are not set, instead of refusing the way a real run does.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    -n|--dry-run) DRY_RUN=1 ;;
    -h|--help|help) usage; exit 0 ;;
    *) printf '[deploy-fhe] ERROR: unknown argument: %s\n' "$1" >&2; usage >&2; exit 1 ;;
  esac
  shift
done

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
require_input HOST_RUNTIME_DIR 'HOST_RUNTIME_DIR must point at third_party/latti-ai-runtime'
TAA_FHE_CONFIG="${TAA_FHE_CONFIG:-$PROJECT_DIR/configs/taa-fhe.json}"
require_input TAA_CALLBACK_BASE_URL 'TAA_CALLBACK_BASE_URL must be reachable from the FHE containers'
require_input TAA_CALLBACK_TOKEN 'TAA_CALLBACK_TOKEN must be set; an unauthenticated callback endpoint is open to every local process'
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
export HOST_DATA_DIR HOST_RUNTIME_DIR HOST_REDIS_DIR API_HOST_PORT

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
NODE_ID_OVERRIDE="${NODE_ID_OVERRIDE:-$(hostname -s 2>/dev/null || true)}"
NODE_IP_OVERRIDE="${NODE_IP_OVERRIDE:-$(hostname -I 2>/dev/null | awk '{print $1}' || true)}"
export NODE_ID_OVERRIDE NODE_IP_OVERRIDE

NODE_DOCKER_DIR="$HANDOFF_DIR/deploy/docker"
# Resolved exactly the way run-node.sh resolves it, so the report below reads the
# file the stack is going to read and not just the one next to it.
NODE_ENV_FILE="${NODE_LOCAL_ENV_FILE:-$NODE_DOCKER_DIR/env/node.local.env}"
# The rendered config is written here on the host, to a mode-600 file that the
# data directory's owner can inspect, and then copied into the container at the
# path taa reads by default (TAA_CONTAINER_CONFIG_PATH). It used to be consumed in
# place through the HOST_DATA_DIR bind mount; that stops working the moment TAA
# has to run under start.sh, which passes no --config.
TAA_RENDERED_CONFIG="${TAA_RENDERED_CONFIG:-$HOST_DATA_DIR/taa-fhe.rendered.json}"
TAA_CONTAINER_CONFIG_PATH="${TAA_CONTAINER_CONFIG_PATH:-$TAA_CONTAINER_WORKDIR/$TAA_CONFIG_FILE}"

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

# Reports the values the FHE stack will actually run with, and says so when the
# bundle's env file disagrees with this run. It is a report, not a warning: the
# export above makes the exported value win in run-node.sh, so a mismatch in the
# env file cannot reach the deployment and a WARNING on the default configuration
# would be noise rather than a signal. It runs in --dry-run too, because a dry run
# is exactly where an operator should learn which tree the stack will use.
report_stack_binding() {
  local name want got
  for name in HOST_DATA_DIR HOST_RUNTIME_DIR HOST_REDIS_DIR API_HOST_PORT; do
    want="${!name}"
    got=""
    if [ -f "$NODE_ENV_FILE" ]; then
      got="$(read_env_path "$NODE_ENV_FILE" "$name")"
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
  # adopt it.
  for name in NODE_ID_OVERRIDE NODE_IP_OVERRIDE; do
    want="${!name}"
    got=""
    if [ -f "$NODE_ENV_FILE" ]; then
      got="$(read_env_path "$NODE_ENV_FILE" "$name")"
    fi
    if [ -n "$got" ] && [ "$got" != "$want" ]; then
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
# that is actually consumed instead of the one it defaulted to.
verify_one() {
  local rel="$1" file="${2:-$HANDOFF_DIR/$1}" want got
  if is_dry_run; then
    log "would verify $rel against SHA256SUMS"
    return 0
  fi
  [ -f "$HANDOFF_DIR/SHA256SUMS" ] || die "no SHA256SUMS in $HANDOFF_DIR"
  [ -f "$file" ] || die "missing artifact: $file"
  want="$(awk -v f="$rel" '$2 == f || $2 == "*"f {print $1}' "$HANDOFF_DIR/SHA256SUMS")"
  [ -n "$want" ] || die "SHA256SUMS has no entry for $rel"
  got="$(sha256sum "$file" | awk '{print $1}')"
  [ "$got" = "$want" ] || die "checksum mismatch for $rel ($file): got $got want $want"
  log "verified $rel"
}

wait_for_taa() {
  local deadline=$((SECONDS + TAA_READY_TIMEOUT))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if curl -fsS -o /dev/null -X POST "http://127.0.0.1:${TAA_PORT}/v1/taa/health" 2>/dev/null; then
      return 0
    fi
    sleep "$TAA_READY_INTERVAL"
  done
  return 1
}

render_taa_config() {
  [ -f "$TAA_FHE_CONFIG" ] || die "TAA config template not found: $TAA_FHE_CONFIG"
  command -v jq >/dev/null 2>&1 || die "command 'jq' is required but not installed or not in PATH"
  # The two ways the pipeline below fails are not the same failure, so the
  # destination is checked first and named separately: "$TAA_RENDERED_CONFIG's
  # directory is missing" is a cp/mkdir problem, and reporting it as "failed to
  # render with jq" sends the operator to the template.
  local rendered_dir
  rendered_dir="$(dirname "$TAA_RENDERED_CONFIG")"
  [ -d "$rendered_dir" ] || die "cannot write $TAA_RENDERED_CONFIG: $rendered_dir does not exist"
  # Two things happen here that the shell has to do rather than jq: the callback
  # token reaches jq through its environment, never through argv (--arg token would
  # publish the secret in /proc/<pid>/cmdline to every local user for as long as jq
  # lives), and umask 077 creates the file 0600 from the start instead of leaving it
  # at the caller's umask until the chmod below runs. $ENV needs jq 1.5 or newer.
  ( umask 077; TAA_CALLBACK_TOKEN="$TAA_CALLBACK_TOKEN" jq \
      --arg url "$TAA_CALLBACK_BASE_URL" \
      --arg endpoint "http://127.0.0.1:${API_HOST_PORT}" \
      --arg data "$HOST_DATA_DIR" \
      '.fhe.callbackBaseUrl = $url | .fhe.callbackToken = $ENV.TAA_CALLBACK_TOKEN
       | .fhe.endpoint = $endpoint | .fhe.dataDir = $data' \
      "$TAA_FHE_CONFIG" > "$TAA_RENDERED_CONFIG" ) \
    || die "failed to render $TAA_FHE_CONFIG -> $TAA_RENDERED_CONFIG (jq rejected the template, or the redirect could not create that file)"
  # The file carries the callback token. The redirect above already created it 0600;
  # this is for the case where it already existed with a wider mode.
  chmod 600 "$TAA_RENDERED_CONFIG"
  log "rendered $TAA_FHE_CONFIG -> $TAA_RENDERED_CONFIG"

  # The readiness probe and the callback URL both assume TAA listens on
  # TAA_PORT; a template that says otherwise would be polled at the wrong port.
  local addr
  addr="$(jq -r '.server.addr' "$TAA_RENDERED_CONFIG")"
  [ "$addr" = ":$TAA_PORT" ] \
    || die "server.addr in the rendered config is '$addr' but TAA_PORT is ':$TAA_PORT'"
}

# Mirrors deploy.sh's container handling: reuse a container that already runs the
# expected image *and* carries the bind this run needs, recreate one that does not.
start_taa_container() {
  local -a args=(-d --name "$TAA_CONTAINER_NAME" --network "$TAA_DOCKER_NETWORK")
  args+=(-v "$HOST_DATA_DIR:$HOST_DATA_DIR")
  args+=(--entrypoint tail "$TAA_IMAGE" -f /dev/null)

  if is_dry_run; then
    # A dry run executes nothing -- in particular it does not call docker, which is
    # what lets it run on a host with no daemon -- so it cannot know whether the
    # container already exists. Print the decision the real run would make instead
    # of the create branch as though it were certain.
    log "dry-run: the real run would reuse $TAA_CONTAINER_NAME if it already exists with image $TAA_IMAGE and the bind $HOST_DATA_DIR:$HOST_DATA_DIR, and would otherwise create it:"
    run docker run "${args[@]}"
    return 0
  fi

  # -F: docker allows '.' in container names, and `grep -E "^taa.fhe\$"` also matches
  # an unrelated "taaXfhe". That match would make this block skip creating the
  # container and report it as already running, and every later docker exec would
  # fail against a container this deployment does not own.
  if docker ps -a --format '{{.Names}}' | grep -Fxq "$TAA_CONTAINER_NAME"; then
    local current_image current_id target_id image_mismatch=false bind_mismatch=false
    local required_bind current_binds
    current_image="$(docker inspect --format '{{.Config.Image}}' "$TAA_CONTAINER_NAME" 2>/dev/null || true)"
    current_id="$(docker inspect --format '{{.Image}}' "$TAA_CONTAINER_NAME" 2>/dev/null || true)"
    target_id="$(docker image inspect --format '{{.Id}}' "$TAA_IMAGE" 2>/dev/null || true)"
    if [ -n "$current_image" ] && [ "$current_image" != "$TAA_IMAGE" ]; then
      image_mismatch=true
    elif [ -n "$current_id" ] && [ -n "$target_id" ] && [ "$current_id" != "$target_id" ]; then
      image_mismatch=true
    fi
    # The bind is as much a part of the container's identity as its image, for this
    # script: the config copied in below sets fhe.dataDir to $HOST_DATA_DIR, and the
    # only thing that makes that path the same directory on both sides is this
    # bind. Comparing the image alone let a re-run with a different HOST_DATA_DIR
    # reuse the old container and then push a config for the new directory into it;
    # taa's os.MkdirAll then created that path in the container's own writable
    # layer, where no host directory backs it, and the run printed its success
    # banner. A bind that cannot be read is treated as a mismatch: the failure this
    # guards is silent, so the unconfirmed case has to take the loud branch.
    required_bind="$HOST_DATA_DIR:$HOST_DATA_DIR"
    current_binds="$(docker inspect --format '{{json .HostConfig.Binds}}' "$TAA_CONTAINER_NAME" 2>/dev/null || true)"
    if ! printf '%s' "$current_binds" \
         | jq -e --arg b "$required_bind" 'type == "array" and index($b) != null' >/dev/null 2>&1; then
      bind_mismatch=true
    fi
    if [ "$image_mismatch" = true ] || [ "$bind_mismatch" = true ]; then
      if [ "$image_mismatch" = true ]; then
        warn "container $TAA_CONTAINER_NAME runs $current_image, expected $TAA_IMAGE; recreating"
      fi
      if [ "$bind_mismatch" = true ]; then
        warn "container $TAA_CONTAINER_NAME does not carry the bind $required_bind (its binds: ${current_binds:-unreadable}); recreating so taa sees the data directory this run configured"
      fi
      run docker rm -f "$TAA_CONTAINER_NAME"
    fi
  fi

  if docker ps --format '{{.Names}}' | grep -Fxq "$TAA_CONTAINER_NAME"; then
    log "container $TAA_CONTAINER_NAME is already running"
    return 0
  fi
  if docker ps -a --format '{{.Names}}' | grep -Fxq "$TAA_CONTAINER_NAME"; then
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
# the daemon's image store.
RUNTIME_SRC="$HANDOFF_DIR/third_party/latti-ai-runtime"
MODELS_SRC="$HANDOFF_DIR/data/models"
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

# ── Steps ────────────────────────────────────────────────────────────────────

if is_dry_run; then
  log "dry-run: nothing will be executed; the tool preflight is skipped"
else
  # realpath is here for the path guards above, which answer "no overlap" when it
  # is missing -- that is the silent direction, so it is checked like the rest.
  for cmd in docker jq rsync sha256sum curl awk realpath; do
    require_command "$cmd"
  done
  # Checked here rather than in the last step so a missing template cannot fail after
  # the FHE stack is already up.
  [ -f "$TAA_FHE_CONFIG" ] || die "TAA config template not found: $TAA_FHE_CONFIG"
  # The supervisor is installed into the container, not taken from the image: a base
  # image that never carried one would otherwise leave taa unsupervised.
  [ -f "$PROJECT_DIR/deploy/start.sh" ] || die "TAA supervisor script missing: $PROJECT_DIR/deploy/start.sh"
fi
report_stack_binding

step "verifying the bundle artifacts this deployment consumes"
# Before the load below, not after: an archive that verifies is imported into the
# daemon, and until it verifies nothing of it should be. FHE_IMAGE_ARCHIVE is
# overridable, so the checksum is taken over the file that gets loaded: verifying
# the default while loading an override verifies nothing about what runs.
verify_one image/latti-server-latest.tar.gz "$FHE_IMAGE_ARCHIVE"
# This one covers third_party/latti-ai-runtime.tar.gz, while the staging step
# rsyncs third_party/latti-ai-runtime/ -- the unpacked directory beside it, which
# SHA256SUMS carries no checksum for. Unpacking the verified tarball here would be
# the way to bind them, and it is not worth what it costs: the bundle's own env
# names that directory, the delivery ships them as one tree, and an empty or
# missing directory is already refused below. It stays a gap by choice.
verify_one third_party/latti-ai-runtime.tar.gz

step "importing $FHE_IMAGE from the handoff bundle"
run docker load -i "$FHE_IMAGE_ARCHIVE"
if is_dry_run; then
  log "would assert image $FHE_IMAGE is present"
else
  docker image inspect "$FHE_IMAGE" >/dev/null 2>&1 \
    || die "image $FHE_IMAGE not found after loading $FHE_IMAGE_ARCHIVE"
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
    [ -d "$RUNTIME_SRC" ] || die "runtime source not found: $RUNTIME_SRC"
    # `ls` failing is not the same as `ls` succeeding with nothing to say: a
    # directory this user cannot read reports the same empty string as an empty one,
    # and calling that "the source is empty" hides the permission problem behind a
    # diagnosis that would send the operator looking at the bundle instead.
    src_entries="$(ls -A "$RUNTIME_SRC" 2>/dev/null)" \
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
    [ -d "$MODELS_SRC" ] || die "models source not found: $MODELS_SRC"
  fi
  run cp -a "$MODELS_SRC/." "$STAGED_MODELS_DIR/"
fi

step "starting the FHE node stack (api + worker + redis)"
# HOST_DATA_DIR / HOST_RUNTIME_DIR / HOST_REDIS_DIR / API_HOST_PORT are exported
# above, which is what points the stack at the tree staged in the previous step.
FHE_STACK_TOUCHED=1
run_in "$NODE_DOCKER_DIR" ./scripts/run-node.sh up -d

step "preflight: the FHE stack is serving on 127.0.0.1:$API_HOST_PORT"
run curl -fsS -o /dev/null "http://127.0.0.1:${API_HOST_PORT}/api/v1/health" \
  || die "FHE health check failed"
if is_dry_run; then
  log "would check: test -w $HOST_DATA_DIR"
else
  [ -w "$HOST_DATA_DIR" ] || die "$HOST_DATA_DIR is not writable"
fi
# A model must activate before a task can run. The bundled cifar10 model is the
# one the delivery bundle measured against.
run curl -fsS -o /dev/null -X POST \
  "http://127.0.0.1:${API_HOST_PORT}/api/v1/models/activate?model_id=${FHE_MODEL_ID}" \
  || die "model activation failed"

step "starting the TAA fhe instance"
if is_dry_run; then
  log "would render $TAA_FHE_CONFIG -> $TAA_RENDERED_CONFIG (callbackBaseUrl, callbackToken, endpoint, dataDir)"
else
  render_taa_config
fi
if [ "$TAA_DOCKER_NETWORK" != "host" ]; then
  warn "TAA_DOCKER_NETWORK=$TAA_DOCKER_NETWORK, but fhe.endpoint is http://127.0.0.1:${API_HOST_PORT}: inside a non-host network 127.0.0.1 is the TAA container itself"
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
run docker cp "$PROJECT_DIR/deploy/start.sh" "$TAA_CONTAINER_NAME:$TAA_CONTAINER_WORKDIR/start.sh"
run docker exec -i "$TAA_CONTAINER_NAME" sh -lc "chmod +x '$TAA_CONTAINER_WORKDIR/start.sh'"
# Copied rather than rendered through the data-directory mount: start.sh runs ./taa
# with no --config, so the config has to be at the path taa reads by default.
run docker cp "$TAA_RENDERED_CONFIG" "$TAA_CONTAINER_NAME:$TAA_CONTAINER_CONFIG_PATH"

# Whatever a previous run left has to be gone first: start.sh holds a singleton
# flock, so a surviving supervisor would make this one exit at once and the
# readiness wait below would then time out against a taa nobody started.
run docker exec -i "$TAA_CONTAINER_NAME" sh -lc "touch '$TAA_CONTAINER_WORKDIR/manual'"
run docker exec -i "$TAA_CONTAINER_NAME" \
  sh -lc "pkill -f '[s]tart\.sh' >/dev/null 2>&1 || true; pkill -x '$BINARY_NAME' >/dev/null 2>&1 || true"
if is_dry_run; then
  log "would wait for any previous start.sh in $TAA_CONTAINER_NAME to exit, then start ./start.sh under nohup"
else
  waited=0
  while [ "$waited" -lt 25 ]; do
    docker exec -i "$TAA_CONTAINER_NAME" sh -lc "pgrep -f '[s]tart\.sh' >/dev/null 2>&1" || break
    waited=$((waited + 1))
    sleep 0.2
  done
  # pgrep -f matches the command line, which a zombie no longer has, so a stopped
  # supervisor is really stopped here and this cannot wedge on a defunct process.
  if docker exec -i "$TAA_CONTAINER_NAME" sh -lc "pgrep -f '[s]tart\.sh' >/dev/null 2>&1"; then
    warn "a previous start.sh supervisor is still running in $TAA_CONTAINER_NAME; force-killing it"
    run docker exec -i "$TAA_CONTAINER_NAME" \
      sh -lc "pkill -9 -f '[s]tart\.sh' >/dev/null 2>&1 || true; pkill -9 -x '$BINARY_NAME' >/dev/null 2>&1 || true"
  fi
fi
run docker exec -i "$TAA_CONTAINER_NAME" sh -lc "rm -f '$TAA_CONTAINER_WORKDIR/manual'"
run docker exec -d "$TAA_CONTAINER_NAME" \
  sh -lc "cd '$TAA_CONTAINER_WORKDIR' && nohup bash ./start.sh >/dev/null 2>&1 &"
TAA_SUPERVISOR_STARTED=1

step "waiting for TAA to answer on 127.0.0.1:$TAA_PORT"
if is_dry_run; then
  log "would wait up to ${TAA_READY_TIMEOUT}s for POST http://127.0.0.1:${TAA_PORT}/v1/taa/health"
  log "dry-run complete: nothing was executed"
else
  if ! wait_for_taa; then
    log "taa log ($TAA_LOG_FILE):"
    docker exec -i "$TAA_CONTAINER_NAME" sh -lc "tail -n 60 '$TAA_LOG_FILE' 2>/dev/null || true"
    die "TAA did not answer POST http://127.0.0.1:${TAA_PORT}/v1/taa/health within ${TAA_READY_TIMEOUT}s"
  fi
  log "TAA fhe instance is ready"
  printf '\n[deploy-fhe] deployment complete\n'
  log "FHE stack      : http://127.0.0.1:${API_HOST_PORT}/api/v1 (model ${FHE_MODEL_ID} activated)"
  log "FHE data dir   : $HOST_DATA_DIR"
  log "FHE runtime    : $HOST_RUNTIME_DIR"
  log "FHE redis dir  : $HOST_REDIS_DIR"
  # The readiness probe above proves something answers on $TAA_PORT and nothing
  # more -- any other listener on the host satisfies it -- and `docker exec -d`
  # returning 0 means only that docker delivered the command. So the supervisor is
  # reported as what it was observed to be, with the bracket keeping pgrep from
  # matching the shell that carries the pattern.
  if docker exec -i "$TAA_CONTAINER_NAME" sh -lc "pgrep -f '[s]tart\.sh' >/dev/null 2>&1"; then
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
