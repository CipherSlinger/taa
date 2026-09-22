#!/usr/bin/env bash
# Package a deployable TAA + TEE-LLM image from the local development container.
#
# Deploys both components into the container, guarantees exactly one supervisor pair
# with both daemons autostarting, applies production hygiene, then commits and exports
# a date+time stamped image archive.
#
# Usage: ./deploy-docker.sh [options]
set -euo pipefail

# ── Colors & logging ─────────────────────────────────────────
if [[ -t 1 ]]; then
  RED='\033[38;5;203m'; GREEN='\033[38;5;48m'; YELLOW='\033[38;5;215m'
  CYAN='\033[38;5;45m'; PURPLE='\033[38;5;141m'; BOLD='\033[1m'
  DIM='\033[2m'; MUTED='\033[38;5;244m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; CYAN=''; PURPLE=''; BOLD=''; DIM=''; MUTED=''; NC=''
fi

STEP=0
banner() {
  echo ""
  echo -e "${CYAN}╭──────────────────────────────────────────────────────────────────╮${NC}"
  echo -e "${CYAN}│${NC}  ${BOLD}$1${NC}"
  [[ -n "${2:-}" ]] && echo -e "${CYAN}│${NC}  ${DIM}$2${NC}"
  echo -e "${CYAN}╰──────────────────────────────────────────────────────────────────╯${NC}"
}
step()   { STEP=$((STEP + 1)); printf "  ${PURPLE}◆${NC} ${CYAN}[%02d]${NC} ${BOLD}%s${NC}\n" "$STEP" "$1"; }
info()   { printf "   ${GREEN}✓${NC} %s\n" "$1"; }
warn()   { printf "   ${YELLOW}⚠${NC} %s\n" "$1"; }
err()    { printf "   ${RED}✗${NC} %s\n" "$1" >&2; }
detail() { printf "     ${MUTED}↳ %s${NC}\n" "$1"; }

die() { err "$1"; exit 1; }

# ── Configuration (override via environment or CLI flags) ────
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Model to bake into both taa-config.json and teellm-docker.json.
LLM_MODEL="${LLM_MODEL:-qwen2.5-coder:3b}"
# Local development container that gets packaged.
CONTAINER_NAME="${CONTAINER_NAME:-taa-env-slim-v2}"
# Base image and the tag/archive naming scheme.
BASE_IMAGE="${BASE_IMAGE:-taa-env:slim-v2}"
IMAGE_REPO="${IMAGE_REPO:-taa-env}"
IMAGE_TAG_PREFIX="${IMAGE_TAG_PREFIX:-slim-v2}"
OUTPUT_DIR="${OUTPUT_DIR:-$PROJECT_DIR/deploy}"
# Date + time stamp so multiple packages on the same day stay distinguishable.
TAG_STAMP="${TAG_STAMP:-$(date +%Y%m%d-%H%M)}"
IMAGE_TAG="${IMAGE_TAG:-${IMAGE_REPO}:${IMAGE_TAG_PREFIX}-${TAG_STAMP}}"
ARCHIVE_PATH="${ARCHIVE_PATH:-${OUTPUT_DIR%/}/taa-env-${IMAGE_TAG_PREFIX}-${TAG_STAMP}.tar.gz}"

# TEE-LLM config template. The default keeps the known-good permissive attestation,
# which works without Hygon CSV hardware. Point this at
# teellm/configs/teellm-production.json to package strict attestation instead.
TEELLM_CONFIG_TEMPLATE="${TEELLM_CONFIG_TEMPLATE:-$PROJECT_DIR/teellm/configs/teellm-docker.json}"

# Production hygiene switches.
INCLUDE_PLATFORM="${INCLUDE_PLATFORM:-false}"
CLEAN_RUNTIME="${CLEAN_RUNTIME:-true}"
RESET_CONTAINER="${RESET_CONTAINER:-false}"

CONTAINER_WORKDIR="${CONTAINER_WORKDIR:-/root/taa}"
TAA_PORT="${TAA_PORT:-6001}"
TEELLM_PORT="${TEELLM_PORT:-8443}"
READY_TIMEOUT="${READY_TIMEOUT:-120}"
READY_INTERVAL="${READY_INTERVAL:-2}"

# Ollama runtime settings. Mirrors teellm/deploy.sh so the warm-up step below targets
# the same daemon, model store, and log file that teellm-service will use.
CONTAINER_OLLAMA_DIR="${CONTAINER_OLLAMA_DIR:-$CONTAINER_WORKDIR/ollama}"
OLLAMA_HOST="${OLLAMA_HOST:-127.0.0.1:11434}"
OLLAMA_LOG_FILE="${OLLAMA_LOG_FILE:-/tmp/ollama.log}"
OLLAMA_READY_TIMEOUT="${OLLAMA_READY_TIMEOUT:-120}"
OLLAMA_READY_INTERVAL="${OLLAMA_READY_INTERVAL:-2}"
# Cold weights are large; loading them can take far longer than a probe timeout.
WARMUP_TIMEOUT="${WARMUP_TIMEOUT:-300}"
# How long ollama keeps the warmed weights resident: must outlive the whole packaging run.
MODEL_KEEP_ALIVE="${MODEL_KEEP_ALIVE:-30m}"

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Deploy TAA and TEE-LLM into the local container, then export a date+time stamped
image archive containing both, with both daemons autostarting.

Options:
  --model <name>       LLM model to deploy and freeze into the image (default: $LLM_MODEL)
  --container <name>   Target local container (default: $CONTAINER_NAME)
  --tag <tag>          Override the committed image tag (default: $IMAGE_TAG)
  --archive <path>     Override the exported archive path (default: $ARCHIVE_PATH)
  --keep-platform      Keep the platform block in taa-config.json (test image, not production)
  --no-clean           Skip runtime trace cleanup (logs, results, keys, pause flags)
  --reset-container    Recreate the container from the base image before deploying.
                       Discards the deployed ollama runtime and weights; teellm/deploy.sh
                       re-syncs them from teellm/models/ollama, which is slow.
  -h, --help           Show this help

Environment overrides:
  LLM_MODEL, CONTAINER_NAME, BASE_IMAGE, IMAGE_TAG, ARCHIVE_PATH, OUTPUT_DIR,
  IMAGE_REPO, IMAGE_TAG_PREFIX, TAG_STAMP, TEELLM_CONFIG_TEMPLATE,
  INCLUDE_PLATFORM, CLEAN_RUNTIME, RESET_CONTAINER, READY_TIMEOUT,
  CONTAINER_OLLAMA_DIR, OLLAMA_HOST, OLLAMA_READY_TIMEOUT, WARMUP_TIMEOUT,
  MODEL_KEEP_ALIVE

Examples:
  $(basename "$0")
  $(basename "$0") --model qwen2.5-coder:7b
  $(basename "$0") --model qwen2.5-coder:3b --tag taa-env:slim-v2-release-1
  TEELLM_CONFIG_TEMPLATE=teellm/configs/teellm-production.json $(basename "$0")
EOF
}

while [[ $# -gt 0 ]]; do
  arg="$1"
  case "$arg" in
    --model=*)     LLM_MODEL="${arg#*=}" ;;
    --model)
      shift; [[ $# -eq 0 || "$1" == -* ]] && die "--model requires a model name"
      LLM_MODEL="$1" ;;
    --container=*) CONTAINER_NAME="${arg#*=}" ;;
    --container)
      shift; [[ $# -eq 0 || "$1" == -* ]] && die "--container requires a container name"
      CONTAINER_NAME="$1" ;;
    --tag=*)       IMAGE_TAG="${arg#*=}" ;;
    --tag)
      shift; [[ $# -eq 0 || "$1" == -* ]] && die "--tag requires a tag"
      IMAGE_TAG="$1" ;;
    --archive=*)   ARCHIVE_PATH="${arg#*=}" ;;
    --archive)
      shift; [[ $# -eq 0 || "$1" == -* ]] && die "--archive requires a path"
      ARCHIVE_PATH="$1" ;;
    --keep-platform)   INCLUDE_PLATFORM=true ;;
    --no-clean)        CLEAN_RUNTIME=false ;;
    --reset-container) RESET_CONTAINER=true ;;
    -h|--help|help)    usage; exit 0 ;;
    *) err "unknown argument: $arg"; usage >&2; exit 1 ;;
  esac
  shift
done

# ── Preflight ────────────────────────────────────────────────
banner "Packaging TAA + TEE-LLM Docker Image" "Model: $LLM_MODEL | Container: $CONTAINER_NAME"

step "preflight checks"
require_command() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }
require_command docker
docker info >/dev/null 2>&1 || die "docker daemon is not running or accessible"

[[ -f "$PROJECT_DIR/deploy.sh" ]] || die "deploy.sh not found in $PROJECT_DIR"
[[ -x "$PROJECT_DIR/teellm/deploy.sh" ]] || die "teellm/deploy.sh not found or not executable"
[[ -f "$PROJECT_DIR/deploy/start.sh" ]] || die "deploy/start.sh not found"
[[ -f "$TEELLM_CONFIG_TEMPLATE" ]] || die "teellm config template not found: $TEELLM_CONFIG_TEMPLATE"

# The packaged image only autostarts both daemons if the TAA supervisor launches the
# TEE-LLM one. Fail loudly rather than shipping an image that FATAL-loops on :8443.
# Match an uncommented launch line only: a commented-out invocation would otherwise
# satisfy this check while shipping an image whose TEE-LLM never autostarts.
if ! grep -Eq '^[^#]*start-teellm\.sh' "$PROJECT_DIR/deploy/start.sh"; then
  die "deploy/start.sh does not launch start-teellm.sh; TAA would fail-closed on :${TEELLM_PORT}"
fi
info "preflight passed (docker, scripts, dual-autostart supervisor)"

container_running() { docker ps --format '{{.Names}}' | grep -Eq "^${CONTAINER_NAME}\$"; }

if [[ "$RESET_CONTAINER" == true ]]; then
  step "recreating container from base image: $BASE_IMAGE"
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  # Reproduce the development container's run configuration: host networking (so the
  # in-container daemons share the host's ports) and an idle entrypoint that does not
  # autostart anything, since deploy.sh installs and supervises the daemons itself.
  docker run -d --name "$CONTAINER_NAME" --network host \
    -e DEBIAN_FRONTEND=noninteractive -e PYTHONUNBUFFERED=1 \
    --entrypoint tail "$BASE_IMAGE" -f /dev/null >/dev/null
  info "container $CONTAINER_NAME recreated from $BASE_IMAGE"
fi

# ── 1. Warm the model before any readiness probe ─────────────
# teellm-service answers /healthz with a real one-token generation, so the very first
# probe pays the cold weight load (seconds to minutes). `teellm-service -probe` allows
# only 5s and cancels its request on timeout, which aborts the load inside ollama --
# so the 30 retries in teellm/deploy.sh can never converge and its readiness gate fails
# on a container whose ollama was recently restarted. Load the weights here instead,
# and hold them resident for the rest of the run.
#
# Must mirror the options teellm-service's own health check sends (ollama_backend.go,
# HandleHealthCheck): ollama reloads a runner whose options differ, so if that payload ever
# gains options this warm-up stops preventing the cold load and the livelock described above
# comes back.
warm_payload="{\"model\":\"${LLM_MODEL}\",\"prompt\":\"ping\",\"stream\":false,\"keep_alive\":\"${MODEL_KEEP_ALIVE}\",\"options\":{\"num_predict\":1}}"

# Load the weights into ollama and hold them resident. Non-zero if the model is absent.
warm_model() {
  docker exec -i "$CONTAINER_NAME" curl -fsS -m "$WARMUP_TIMEOUT" -X POST \
    "http://${OLLAMA_HOST}/api/generate" -H 'Content-Type: application/json' \
    -d "$warm_payload" >/dev/null 2>&1
}

# Poll ollama's cheap catalog endpoint until the daemon answers at all. The deadline is
# wall-clock, so OLLAMA_READY_TIMEOUT means what it says instead of being multiplied by
# the probe time on top of the interval.
wait_for_ollama() {
  local deadline=$(( SECONDS + OLLAMA_READY_TIMEOUT ))
  while (( SECONDS < deadline )); do
    if docker exec -i "$CONTAINER_NAME" curl -fsS -m 5 "http://${OLLAMA_HOST}/api/tags" >/dev/null 2>&1; then
      return 0
    fi
    sleep "$OLLAMA_READY_INTERVAL"
  done
  return 1
}

step "warming model $LLM_MODEL in ollama"
container_running || die "container $CONTAINER_NAME is not running"

if docker exec -i "$CONTAINER_NAME" curl -fsS -m 5 "http://${OLLAMA_HOST}/api/tags" >/dev/null 2>&1; then
  info "ollama daemon already running on http://${OLLAMA_HOST}"
else
  info "ollama daemon not running; starting it as teellm/deploy.sh would"
  docker exec -d "$CONTAINER_NAME" sh -lc "cd '$CONTAINER_OLLAMA_DIR' && exec env OLLAMA_HOST='$OLLAMA_HOST' OLLAMA_MODELS='$CONTAINER_OLLAMA_DIR/models/models' OLLAMA_LIBRARY_PATH='$CONTAINER_OLLAMA_DIR/lib/ollama' ./start-ollama.sh > '$OLLAMA_LOG_FILE' 2>&1"
  if ! wait_for_ollama; then
    err "ollama daemon did not become ready within ${OLLAMA_READY_TIMEOUT}s"
    docker exec -i "$CONTAINER_NAME" sh -lc "tail -n 30 '$OLLAMA_LOG_FILE' 2>/dev/null || true"
    exit 1
  fi
  info "ollama daemon ready on http://${OLLAMA_HOST}"
fi

if warm_model; then
  info "model $LLM_MODEL loaded and held resident for ${MODEL_KEEP_ALIVE}"
else
  warn "model warm-up failed (missing weights?); teellm/deploy.sh will report the cause"
fi

# ── 2. TEE-LLM first: TAA's fail-closed probe needs :8443 already up ──
step "deploying TEE-LLM (model: $LLM_MODEL)"
info "running: (cd teellm && ./deploy.sh docker --model $LLM_MODEL --container $CONTAINER_NAME --config $TEELLM_CONFIG_TEMPLATE)"
( cd "$PROJECT_DIR/teellm" && ./deploy.sh docker --model "$LLM_MODEL" --container "$CONTAINER_NAME" \
    --config "$TEELLM_CONFIG_TEMPLATE" )
info "TEE-LLM deployed"

# ── 3. TAA ───────────────────────────────────────────────────
step "deploying TAA (model: $LLM_MODEL)"
info "running: ./deploy.sh docker taa --model $LLM_MODEL"
( cd "$PROJECT_DIR" && ./deploy.sh docker taa --model "$LLM_MODEL" )
info "TAA deployed"

# ── 4. Consolidate supervisors ───────────────────────────────
# Step 3 started `start.sh`, which also launches `start-teellm.sh`, racing the
# supervisor step 2 already started. Collapse everything down to one supervisor pair.
step "consolidating supervisors into a single autostart pair"
container_running || die "container $CONTAINER_NAME is not running"

# Everything the two deploy scripts may leave running: their supervisors and those
# supervisors' daemons. The bracket in `[s]tart` keeps pkill/pgrep from matching the
# shell that is running the pattern itself.
SUPERVISOR_PATTERN='[s]tart\.sh|[s]tart-teellm\.sh'
DAEMON_PATTERN='taa|teellm-service|ollama|llama-server'

# $1: signal number, or empty for the default SIGTERM. The dash is required -- `pkill 9 -f x`
# would parse 9 as a pattern, not as a signal.
kill_services() {
  local flag="${1:+-$1}"
  docker exec -i "$CONTAINER_NAME" sh -lc "
    pkill $flag -f '$SUPERVISOR_PATTERN' >/dev/null 2>&1 || true
    pkill $flag -x '$DAEMON_PATTERN'    >/dev/null 2>&1 || true
  " >/dev/null 2>&1 || true
}

services_alive() {
  docker exec -i "$CONTAINER_NAME" sh -lc \
    "pgrep -f '$SUPERVISOR_PATTERN' >/dev/null 2>&1 || pgrep -x '$DAEMON_PATTERN' >/dev/null 2>&1"
}

docker exec -i "$CONTAINER_NAME" sh -lc \
  "touch '$CONTAINER_WORKDIR/manual' '$CONTAINER_WORKDIR/manual-teellm'" >/dev/null 2>&1 || true
kill_services

stopped=false
for _ in {1..40}; do
  if ! services_alive; then
    stopped=true; break
  fi
  sleep 0.5
done
if [[ "$stopped" != true ]]; then
  warn "services did not terminate gracefully; force-killing"
  kill_services 9
  sleep 1
fi
info "all previous supervisors and daemons stopped"

docker exec -i "$CONTAINER_NAME" sh -lc "rm -f '$CONTAINER_WORKDIR/manual' '$CONTAINER_WORKDIR/manual-teellm'"
docker exec -d "$CONTAINER_NAME" sh -lc "cd '$CONTAINER_WORKDIR' && nohup bash ./start.sh >/dev/null 2>&1 &"
info "single start.sh supervisor launched (brings up TAA and TEE-LLM)"

# Killing ollama above dropped the warmed weights, so they must be loaded again before
# the 5s probe below runs -- otherwise the probe timeout aborts the load and livelocks
# exactly as described in step 1.
step "re-warming model after the supervisor restart"
if ! wait_for_ollama; then
  warn "ollama did not come back within ${OLLAMA_READY_TIMEOUT}s; probing anyway"
elif warm_model; then
  info "model $LLM_MODEL resident again"
else
  warn "model re-warm failed; probing anyway"
fi

step "waiting for both daemons to become ready"
teellm_ready=false
taa_ready=false
# Wall-clock deadline: every iteration also pays for a probe (the teellm one is capped at
# 5s inside teellm-service), so counting iterations would overshoot READY_TIMEOUT badly.
ready_deadline=$(( SECONDS + READY_TIMEOUT ))
while (( SECONDS < ready_deadline )); do
  if [[ "$teellm_ready" != true ]] && \
     docker exec -i "$CONTAINER_NAME" "$CONTAINER_WORKDIR/teellm-service" -probe "https://127.0.0.1:${TEELLM_PORT}" >/dev/null 2>&1; then
    teellm_ready=true
    info "teellm-service ready via TEE-TLS 1.3: https://127.0.0.1:${TEELLM_PORT}"
  fi
  if [[ "$taa_ready" != true ]] && \
     docker exec -i "$CONTAINER_NAME" curl -fsS -m 5 -X POST "http://127.0.0.1:${TAA_PORT}/v1/taa/health" >/dev/null 2>&1; then
    taa_ready=true
    info "taa ready: http://127.0.0.1:${TAA_PORT}/v1/taa/health"
  fi
  [[ "$teellm_ready" == true && "$taa_ready" == true ]] && break
  sleep "$READY_INTERVAL"
done

if [[ "$teellm_ready" != true || "$taa_ready" != true ]]; then
  err "readiness failed (teellm=$teellm_ready taa=$taa_ready): refusing to package a broken image"
  echo -e "   ${YELLOW}↳${NC} $CONTAINER_WORKDIR/teellm-service.log (tail):"
  docker exec -i "$CONTAINER_NAME" sh -lc "tail -n 30 '$CONTAINER_WORKDIR/teellm-service.log' 2>/dev/null || true"
  echo -e "   ${YELLOW}↳${NC} $CONTAINER_WORKDIR/taa.log (tail):"
  docker exec -i "$CONTAINER_NAME" sh -lc "tail -n 30 '$CONTAINER_WORKDIR/taa.log' 2>/dev/null || true"
  echo -e "   ${YELLOW}↳${NC} $OLLAMA_LOG_FILE (tail):"
  docker exec -i "$CONTAINER_NAME" sh -lc "tail -n 20 '$OLLAMA_LOG_FILE' 2>/dev/null || true"
  exit 1
fi

# ── 5. Production hygiene ────────────────────────────────────
step "applying production configuration"
if [[ "$INCLUDE_PLATFORM" == true ]]; then
  warn "keeping platform block: resulting image is a local test image, not production"
else
  docker exec -i "$CONTAINER_NAME" python3 - "$CONTAINER_WORKDIR/taa-config.json" <<'PY'
import json, sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    cfg = json.load(f)
cfg.pop("platform", None)
for key in ("platformIP", "dockerID", "contract"):
    cfg.pop(key, None)
with open(path, "w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)
    f.write("\n")
PY
  info "platform block removed: identity is injected via PLATFORM_IP/DOCKER_ID/CONTRACT"
fi

# teellm/deploy.sh copies the model catalog verbatim and never updates activeModel, so
# keep it consistent with the model actually frozen into backend.defaultModel.
docker exec -i "$CONTAINER_NAME" python3 - "$CONTAINER_WORKDIR/configs/models.json" "$LLM_MODEL" <<'PY'
import json, sys
path, model = sys.argv[1], sys.argv[2]
try:
    with open(path, "r", encoding="utf-8") as f:
        catalog = json.load(f)
except FileNotFoundError:
    sys.exit(0)
if catalog.get("activeModel") != model:
    catalog["activeModel"] = model
    with open(path, "w", encoding="utf-8") as f:
        json.dump(catalog, f, indent=2, ensure_ascii=False)
        f.write("\n")
PY
info "model catalog activeModel set to $LLM_MODEL"

step "container cleanup"
if [[ "$CLEAN_RUNTIME" == true ]]; then
  docker exec -i "$CONTAINER_NAME" bash -c "
    set -u
    rm -f '$CONTAINER_WORKDIR'/*.log
    rm -f '$CONTAINER_WORKDIR/attestation.report' '$CONTAINER_WORKDIR/nonce.bin'
    rm -f '$CONTAINER_WORKDIR/manual' '$CONTAINER_WORKDIR/manual-teellm'
    rm -rf '$CONTAINER_WORKDIR/results'/* '$CONTAINER_WORKDIR/data'/* \
           '$CONTAINER_WORKDIR/models'/* '$CONTAINER_WORKDIR/keys'/* 2>/dev/null || true
    rm -rf /tmp/* 2>/dev/null || true
    rm -f /root/.bash_history 2>/dev/null || true
  " >/dev/null 2>&1 || true
  info "logs, results, data, model scratch, keys and pause flags cleared"
else
  warn "runtime cleanup skipped (--no-clean): image may carry test traces"
fi

docker exec -i "$CONTAINER_NAME" bash -c "
  set -u
  mkdir -p '$CONTAINER_WORKDIR'/models '$CONTAINER_WORKDIR'/data '$CONTAINER_WORKDIR'/results \
           '$CONTAINER_WORKDIR'/keys '$CONTAINER_WORKDIR'/certs '$CONTAINER_WORKDIR'/configs
  mkdir -p /opt/taa/keys /opt/taa/input /opt/taa/output/result /opt/taa/output/log \
           /opt/taa/output/progress /opt/taa/checkpoint
  chmod 700 '$CONTAINER_WORKDIR/keys' /opt/taa/keys
" >/dev/null 2>&1 || true
info "runtime directories recreated with 700 permissions on keys dirs"

# ── 6. Commit ────────────────────────────────────────────────
step "committing container to image: $IMAGE_TAG"
docker stop "$CONTAINER_NAME" >/dev/null
commit_msg="Packaged from ${CONTAINER_NAME} with model ${LLM_MODEL} at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
if ! docker commit \
  -c 'ENTRYPOINT ["bash", "/root/taa/start.sh"]' \
  -c 'CMD []' \
  -c 'WORKDIR /root/taa' \
  -c 'EXPOSE 6001' \
  -c 'EXPOSE 8443' \
  -m "$commit_msg" \
  "$CONTAINER_NAME" "$IMAGE_TAG" >/dev/null; then
  docker start "$CONTAINER_NAME" >/dev/null 2>&1 || true
  die "docker commit failed"
fi
# One inspect for both fields; a failing substitution still aborts under `set -e`.
inspect_out=$(docker image inspect --format '{{.Id}} {{.Size}}' "$IMAGE_TAG")
image_id="${inspect_out%% *}"    # sha256:<hex>
image_id="${image_id#sha256:}"
image_id="${image_id:0:12}"
image_size="${inspect_out##* }"
image_size_mb=$(awk -v b="$image_size" 'BEGIN { printf "%.2f", b / 1048576 }')
info "image committed: $IMAGE_TAG (id: $image_id, size: ${image_size_mb}MB)"

# ── 7. Export ────────────────────────────────────────────────
step "exporting image archive: $ARCHIVE_PATH"
mkdir -p "$(dirname "$ARCHIVE_PATH")"
TMP_ARCHIVE="${ARCHIVE_PATH}.tmp.$$"
trap 'rm -f "${TMP_ARCHIVE:-}"' EXIT
compressor="gzip"
command -v pigz >/dev/null 2>&1 && compressor="pigz"

# `compressor` already holds the command name, so the two paths differ only by whether it
# is piped at all -- and only the piped one is actually compressed.
if [[ "$ARCHIVE_PATH" == *.tar.gz || "$ARCHIVE_PATH" == *.tgz ]]; then
  docker save "$IMAGE_TAG" | "$compressor" -c > "$TMP_ARCHIVE"
  note="compressed with $compressor"
else
  docker save -o "$TMP_ARCHIVE" "$IMAGE_TAG"
  note="uncompressed (docker save -o)"
fi
mv -f "$TMP_ARCHIVE" "$ARCHIVE_PATH"
TMP_ARCHIVE=""
archive_size="$(du -h "$ARCHIVE_PATH" | cut -f1)"
info "archive exported, $note: $ARCHIVE_PATH ($archive_size)"

# ── 8. Restore dev container ─────────────────────────────────
# `docker stop` in step 6 killed every daemon the deploys had started. The container's
# own entrypoint is an idle `tail -f /dev/null`, so `docker start` alone would hand back
# a development environment with no taa and no teellm-service.
step "restarting development container"
docker start "$CONTAINER_NAME" >/dev/null
docker exec -d "$CONTAINER_NAME" sh -lc "cd '$CONTAINER_WORKDIR' && nohup bash ./start.sh >/dev/null 2>&1 &"
info "container $CONTAINER_NAME restarted with the supervisor relaunched"

attestation_mode="$(docker exec -i "$CONTAINER_NAME" python3 -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["attestation"]["mode"])' \
  "$CONTAINER_WORKDIR/configs/teellm-docker.json" 2>/dev/null || echo "unknown")"

banner "Package Complete" "Both daemons autostart in the exported image"
echo -e "  ${BOLD}${CYAN}● Image${NC}"
echo -e "    ${MUTED}↳ Tag        :${NC} ${BOLD}${IMAGE_TAG}${NC}"
echo -e "    ${MUTED}↳ Image ID   :${NC} ${image_id}"
echo -e "    ${MUTED}↳ Size       :${NC} ${image_size_mb}MB"
echo -e "    ${MUTED}↳ Archive    :${NC} ${BOLD}${ARCHIVE_PATH}${NC} (${archive_size})"
echo ""
echo -e "  ${BOLD}${CYAN}● Contents${NC}"
echo -e "    ${MUTED}↳ Model      :${NC} ${PURPLE}${LLM_MODEL}${NC}"
echo -e "    ${MUTED}↳ Autostart  :${NC} start.sh (taa :${TAA_PORT}) + start-teellm.sh (teellm :${TEELLM_PORT})"
echo -e "    ${MUTED}↳ Attestation:${NC} ${attestation_mode}"
echo -e "    ${MUTED}↳ Platform   :${NC} $([[ "$INCLUDE_PLATFORM" == true ]] && echo "embedded (test image)" || echo "injected via PLATFORM_IP/DOCKER_ID/CONTRACT")"
echo ""
echo -e "  ${MUTED}Load on a target host:  docker load -i $(basename "$ARCHIVE_PATH")${NC}"
echo ""
