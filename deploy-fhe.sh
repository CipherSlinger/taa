#!/usr/bin/env bash
# Deploy the FHE side on a GPU host: import the image, stage the runtime and the
# models into the shared directory, start the api/worker/redis stack, then start
# this host's TAA instance with server.type=fhe.
#
# This script owns the FHE side; deploy.sh owns the TAA image itself.
set -euo pipefail

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
die()  { printf '[deploy-fhe] ERROR: %s\n' "$*" >&2; exit 1; }
step() { STEP=$((STEP + 1)); printf '\n[deploy-fhe] === %s) %s ===\n' "$STEP" "$*"; }

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
start this host's TAA instance with server.type=fhe.

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
      It must be the same path env/node.local.env gives run-node.sh, or the stack
      serves one directory while TAA reads another.
  HOST_RUNTIME_DIR=${HOST_RUNTIME_DIR:-}
      Where the FHE runtime from the bundle is staged; mounted read-only by the
      stack. Same caveat as HOST_DATA_DIR.
  TAA_FHE_CONFIG=${TAA_FHE_CONFIG:-}
      TAA configuration template rendered with the callback URL/token below.
      Defaults to $PROJECT_DIR/configs/taa-fhe.json; an override is used as given.
  TAA_CALLBACK_BASE_URL=${TAA_CALLBACK_BASE_URL:-}
      Base URL of this TAA instance as the FHE containers reach it.
  TAA_CALLBACK_TOKEN=${TAA_CALLBACK_TOKEN:-}
      Shared secret the FHE service presents on the callback endpoint. Required:
      an unauthenticated callback endpoint is open to every local process.
  API_HOST_PORT=${API_HOST_PORT:-58996}
      Host port the FHE api service publishes.
  FHE_IMAGE=${FHE_IMAGE}
      Image tag the handoff archive is loaded as.
  FHE_IMAGE_ARCHIVE=${FHE_IMAGE_ARCHIVE}
      Archive loaded by 'docker load'.
  FHE_MODEL_ID=${FHE_MODEL_ID}
      Model activated on the stack before a task can run.
  TAA_IMAGE=${TAA_IMAGE}
      TAA image started on this host (deploy.sh builds it).
  TAA_CONTAINER_NAME=${TAA_CONTAINER_NAME}
      TAA container name.
  TAA_CONTAINER_WORKDIR=${TAA_CONTAINER_WORKDIR}
      Working directory inside the TAA container; 'manual' and the log live here.
  TAA_LOG_FILE=${TAA_LOG_FILE}
      Log the TAA instance is started with, inside the container.
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

NODE_DOCKER_DIR="$HANDOFF_DIR/deploy/docker"
NODE_ENV_FILE="$NODE_DOCKER_DIR/env/node.local.env"
# The rendered config lands inside HOST_DATA_DIR, which is bind-mounted at the
# identical path, so the container reads the very same file with no extra mount.
TAA_RENDERED_CONFIG="${TAA_RENDERED_CONFIG:-$HOST_DATA_DIR/taa-fhe.rendered.json}"
TAA_CONTAINER_CONFIG_PATH="${TAA_CONTAINER_CONFIG_PATH:-$TAA_RENDERED_CONFIG}"

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

# run-node.sh takes HOST_DATA_DIR / HOST_RUNTIME_DIR from env/node.local.env, and
# this script deliberately does not export either one over it (see the note in
# usage). Two sources of truth for the same two paths is the one mistake that
# produces a stack that looks healthy while TAA reads an empty directory, so it
# is worth a warning.
warn_on_env_file_mismatch() {
  [ -f "$NODE_ENV_FILE" ] || return 0
  local name want got
  for name in HOST_DATA_DIR HOST_RUNTIME_DIR; do
    want="${!name}"
    got="$(read_env_path "$NODE_ENV_FILE" "$name")"
    [ -n "$got" ] || continue
    if [ "$got" != "$want" ]; then
      warn "$NODE_ENV_FILE sets $name=$got but this run uses $name=$want; the FHE stack and TAA must share one directory"
    fi
  done
}

# The bundle's SHA256SUMS lists client/latti-client-wasm-0.1.0.zip while the
# shipped file is latti-wasm-0.1.1.zip, so an unconditional `sha256sum -c`
# always fails. Verify the two artifacts that matter, by their real names.
verify_one() {
  local rel="$1" want got
  if is_dry_run; then
    log "would verify $rel against SHA256SUMS"
    return 0
  fi
  [ -f "$HANDOFF_DIR/SHA256SUMS" ] || die "no SHA256SUMS in $HANDOFF_DIR"
  [ -f "$HANDOFF_DIR/$rel" ] || die "missing artifact: $HANDOFF_DIR/$rel"
  want="$(awk -v f="$rel" '$2 == f || $2 == "*"f {print $1}' "$HANDOFF_DIR/SHA256SUMS")"
  [ -n "$want" ] || die "SHA256SUMS has no entry for $rel"
  got="$(sha256sum "$HANDOFF_DIR/$rel" | awk '{print $1}')"
  [ "$got" = "$want" ] || die "checksum mismatch for $rel: got $got want $want"
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
  jq --arg url "$TAA_CALLBACK_BASE_URL" --arg token "$TAA_CALLBACK_TOKEN" \
     --arg endpoint "http://127.0.0.1:${API_HOST_PORT}" --arg data "$HOST_DATA_DIR" \
     '.fhe.callbackBaseUrl = $url | .fhe.callbackToken = $token
      | .fhe.endpoint = $endpoint | .fhe.dataDir = $data' \
     "$TAA_FHE_CONFIG" > "$TAA_RENDERED_CONFIG" \
    || die "failed to render $TAA_FHE_CONFIG with jq"
  # The file carries the callback token.
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
# expected image, recreate one that does not.
start_taa_container() {
  local -a args=(-d --name "$TAA_CONTAINER_NAME" --network "$TAA_DOCKER_NETWORK")
  args+=(-v "$HOST_DATA_DIR:$HOST_DATA_DIR")
  args+=(--entrypoint tail "$TAA_IMAGE" -f /dev/null)

  if is_dry_run; then
    run docker run "${args[@]}"
    return 0
  fi

  if docker ps -a --format '{{.Names}}' | grep -Eq "^${TAA_CONTAINER_NAME}\$"; then
    local current_image current_id target_id image_mismatch=false
    current_image="$(docker inspect --format '{{.Config.Image}}' "$TAA_CONTAINER_NAME" 2>/dev/null || true)"
    current_id="$(docker inspect --format '{{.Image}}' "$TAA_CONTAINER_NAME" 2>/dev/null || true)"
    target_id="$(docker image inspect --format '{{.Id}}' "$TAA_IMAGE" 2>/dev/null || true)"
    if [ -n "$current_image" ] && [ "$current_image" != "$TAA_IMAGE" ]; then
      image_mismatch=true
    elif [ -n "$current_id" ] && [ -n "$target_id" ] && [ "$current_id" != "$target_id" ]; then
      image_mismatch=true
    fi
    if [ "$image_mismatch" = true ]; then
      warn "container $TAA_CONTAINER_NAME runs $current_image, expected $TAA_IMAGE; recreating"
      run docker rm -f "$TAA_CONTAINER_NAME"
    fi
  fi

  if docker ps --format '{{.Names}}' | grep -Eq "^${TAA_CONTAINER_NAME}\$"; then
    log "container $TAA_CONTAINER_NAME is already running"
    return 0
  fi
  if docker ps -a --format '{{.Names}}' | grep -Eq "^${TAA_CONTAINER_NAME}\$"; then
    log "starting stopped container $TAA_CONTAINER_NAME"
    run docker start "$TAA_CONTAINER_NAME"
    return 0
  fi
  log "creating container $TAA_CONTAINER_NAME (image $TAA_IMAGE, network $TAA_DOCKER_NETWORK)"
  run docker run "${args[@]}"
}

# ── Steps ────────────────────────────────────────────────────────────────────

if is_dry_run; then
  log "dry-run: nothing will be executed; the tool preflight is skipped"
else
  for cmd in docker jq rsync sha256sum curl awk; do
    require_command "$cmd"
  done
  # Checked here rather than in step 6 so a missing template cannot fail after the
  # FHE stack is already up.
  [ -f "$TAA_FHE_CONFIG" ] || die "TAA config template not found: $TAA_FHE_CONFIG"
  warn_on_env_file_mismatch
fi

step "importing $FHE_IMAGE from the handoff bundle"
run docker load -i "$FHE_IMAGE_ARCHIVE"
if is_dry_run; then
  log "would assert image $FHE_IMAGE is present"
else
  docker image inspect "$FHE_IMAGE" >/dev/null 2>&1 \
    || die "image $FHE_IMAGE not found after loading $FHE_IMAGE_ARCHIVE"
  log "image $FHE_IMAGE is present"
fi

step "verifying the bundle artifacts this deployment consumes"
verify_one image/latti-server-latest.tar.gz
verify_one third_party/latti-ai-runtime.tar.gz

step "staging the FHE runtime and models"
run mkdir -p "$HOST_RUNTIME_DIR"
run rsync -a --delete "$HANDOFF_DIR/third_party/latti-ai-runtime/" "$HOST_RUNTIME_DIR/"
run mkdir -p "$HOST_DATA_DIR"/{models,keys,tasks,results}
run cp -a "$HANDOFF_DIR/data/models/." "$HOST_DATA_DIR/models/"

step "starting the FHE node stack (api + worker + redis)"
# HOST_DATA_DIR / HOST_RUNTIME_DIR come from env/node.local.env here; this script
# does not export them over it, so warn_on_env_file_mismatch is the only guard
# that the stack and TAA are pointed at the same directories.
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
# Keeps the image's built-in start.sh from autostarting a second taa and racing
# this instance for :$TAA_PORT (the same marker deploy.sh touches).
run docker exec -i "$TAA_CONTAINER_NAME" \
  sh -lc "mkdir -p '$TAA_CONTAINER_WORKDIR' && touch '$TAA_CONTAINER_WORKDIR/manual'"
run docker exec -i "$TAA_CONTAINER_NAME" \
  sh -lc "pkill -x '$BINARY_NAME' >/dev/null 2>&1 || true"
run docker exec -d "$TAA_CONTAINER_NAME" \
  sh -lc "cd '$TAA_CONTAINER_WORKDIR' && nohup ./$BINARY_NAME --config '$TAA_CONTAINER_CONFIG_PATH' >> '$TAA_LOG_FILE' 2>&1 < /dev/null &"

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
  log "TAA instance   : http://127.0.0.1:${TAA_PORT}/v1/taa/health (container $TAA_CONTAINER_NAME)"
  log "FHE data dir   : $HOST_DATA_DIR"
  log "FHE runtime    : $HOST_RUNTIME_DIR"
  log "TAA config     : $TAA_RENDERED_CONFIG (in container: $TAA_CONTAINER_CONFIG_PATH)"
  log "Callback URL   : $TAA_CALLBACK_BASE_URL"
fi
