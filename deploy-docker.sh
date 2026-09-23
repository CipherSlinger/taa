#!/usr/bin/env bash
# Package a deployable TAA + TEE-LLM image from the local development container.
#
# Deploys both components into the container, verifies the flock singleton guard leaves
# exactly one supervisor pair with both daemons autostarting, applies production hygiene,
# then commits and exports a date+time stamped image archive.
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

# Tier 1 static scan engine baked into the image: regex or semgrep. The default stays the
# regex baseline, so packaging without an explicit choice does not move the engine
# production runs; semgrep is opt-in here until the holdout evidence passes under the
# assist policy.
SCAN_ENGINE="${SCAN_ENGINE:-regex}"
# Rules the semgrep engine loads. Closed over all three rule directories so an image can
# be re-pointed at another language without repackaging.
SEMGREP_RULES_SOURCE="${SEMGREP_RULES_SOURCE:-$PROJECT_DIR/models/audit/semgrep/rules}"
# Where the adapter reads its rules once the image runs. Deliberately not under models/ or
# /tmp, both of which the cleanup step empties: a rules file that disappears between the
# deploy and the commit produces an image whose every model import fails closed.
CONTAINER_SEMGREP_DIR="${CONTAINER_SEMGREP_DIR:-/opt/taa/semgrep}"
# Pinned so the image carries a CLI version that was measured rather than whatever pip
# resolved on packaging day. The resolved dependency tree is recorded next to it.
SEMGREP_VERSION="${SEMGREP_VERSION:-1.177.0}"
# The template deploy.sh turns into the container's taa-config.json. Passed through
# explicitly rather than exported, so it reaches only the one invocation that needs it.
TAA_TEMPLATE="${TAA_DOCKER_CONFIG_TEMPLATE:-$PROJECT_DIR/configs/taa-docker.json}"

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
# How long ollama keeps the warmed weights resident: must outlive the whole packaging run,
# since step 1 is the only place that loads them.
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
  --scan-engine <e>    Tier 1 static engine baked into the image: regex (default) or semgrep
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
  MODEL_KEEP_ALIVE, SCAN_ENGINE, SEMGREP_RULES_SOURCE, CONTAINER_SEMGREP_DIR,
  SEMGREP_VERSION

Examples:
  $(basename "$0")
  $(basename "$0") --model qwen2.5-coder:7b
  $(basename "$0") --model qwen2.5-coder:3b --tag taa-env:slim-v2-release-1
  $(basename "$0") --scan-engine semgrep
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
    --scan-engine=*)   SCAN_ENGINE="${arg#*=}" ;;
    --scan-engine)
      shift; [[ $# -eq 0 || "$1" == -* ]] && die "--scan-engine requires an engine name"
      SCAN_ENGINE="$1" ;;
    -h|--help|help)    usage; exit 0 ;;
    *) err "unknown argument: $arg"; usage >&2; exit 1 ;;
  esac
  shift
done

# Rejected here, where the operator sees it, and not left to the daemon: an unrecognized
# name is refused by the config loader at container start, which in the packaged image is
# after the daemons are down. Same whitelist as internal/config's staticEngines.
case "$SCAN_ENGINE" in
  regex|semgrep) ;;
  *) die "--scan-engine must be regex or semgrep, got: $SCAN_ENGINE" ;;
esac

# ── Preflight ────────────────────────────────────────────────
banner "Packaging TAA + TEE-LLM Docker Image" "Model: $LLM_MODEL | Container: $CONTAINER_NAME | Tier 1 engine: $SCAN_ENGINE"

step "preflight checks"
require_command() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }
require_command docker
# The engine reaches the daemon through a config template derived on the host, because
# write_taa_config copies the security block verbatim and a config patched into the
# container afterwards would need a second daemon restart to take effect.
require_command python3
docker info >/dev/null 2>&1 || die "docker daemon is not running or accessible"

[[ -f "$PROJECT_DIR/deploy.sh" ]] || die "deploy.sh not found in $PROJECT_DIR"
[[ -x "$PROJECT_DIR/teellm/deploy.sh" ]] || die "teellm/deploy.sh not found or not executable"
[[ -f "$PROJECT_DIR/deploy/start.sh" ]] || die "deploy/start.sh not found"
[[ -f "$TEELLM_CONFIG_TEMPLATE" ]] || die "teellm config template not found: $TEELLM_CONFIG_TEMPLATE"
[[ -f "$TAA_TEMPLATE" ]] || die "taa config template not found: $TAA_TEMPLATE"

# Checked before any container work, so a bad rules path costs nothing but this line. The
# engine is resolved from the config at startup and every scan then reads the rules, so a
# missing directory is not a degraded scan: it fails every import and has the model code
# deleted, indistinguishable from the scanner doing its job.
if [[ "$SCAN_ENGINE" == "semgrep" ]]; then
  [[ -d "$SEMGREP_RULES_SOURCE" ]] || die "semgrep rules not found: $SEMGREP_RULES_SOURCE"
  [[ -f "$SEMGREP_RULES_SOURCE/python/rules.yaml" ]] || die "semgrep python rules not found: $SEMGREP_RULES_SOURCE/python/rules.yaml"
fi

# One trap for every temporary path this run creates. Step 8 installs the archive path
# into TMP_ARCHIVE long after this point, which is why the expansion is deferred.
TMP_ARCHIVE=""
TMP_TAA_TEMPLATE=""
TMP_PIP_LOG=""
trap 'rm -f "${TMP_ARCHIVE:-}" "${TMP_TAA_TEMPLATE:-}" "${TMP_PIP_LOG:-}"' EXIT

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

# ── 3. Tier 1 static scan engine ─────────────────────────────
# Everything the semgrep arm needs is put in place before TAA is deployed, so the daemon
# boots once with the engine already resolved from its config. Nothing here is at risk
# from step 6's cleanup: site-packages and /opt/taa/semgrep are outside the paths it
# empties, and the rules deliberately do not live under models/ or /tmp.
if [[ "$SCAN_ENGINE" == "semgrep" ]]; then
  step "installing semgrep $SEMGREP_VERSION (Tier 1 engine)"
  container_running || die "container $CONTAINER_NAME is not running"

  # --break-system-packages: the base image's python is externally managed and ships no
  # ensurepip, so a venv cannot bootstrap itself here -- and a venv would additionally
  # have to be re-entered by the daemon, which shells out to `semgrep` from PATH.
  TMP_PIP_LOG="$(mktemp)"
  if ! docker exec -i "$CONTAINER_NAME" pip3 install --quiet --no-cache-dir \
       --break-system-packages "semgrep==${SEMGREP_VERSION}" >"$TMP_PIP_LOG" 2>&1; then
    tail -n 15 "$TMP_PIP_LOG" >&2
    die "pip3 install semgrep==${SEMGREP_VERSION} failed in $CONTAINER_NAME"
  fi

  # Read back from the CLI rather than trusting the pin: an existing install that pip
  # declined to change is the one way this step can succeed without the engine arriving.
  installed_version="$(docker exec -i "$CONTAINER_NAME" semgrep --version 2>/dev/null | tail -n 1 | tr -d '\r')"
  [[ "$installed_version" == "$SEMGREP_VERSION" ]] || \
    die "semgrep in $CONTAINER_NAME reports version '$installed_version', expected $SEMGREP_VERSION"
  info "semgrep $installed_version installed"

  step "installing semgrep rules into $CONTAINER_SEMGREP_DIR"
  # Remove first: `docker cp` of a directory into an existing one nests it instead of
  # replacing it, which would leave a previous run's rules reachable at a second path.
  docker exec -i "$CONTAINER_NAME" bash -c \
    "rm -rf '$CONTAINER_SEMGREP_DIR/rules' && mkdir -p '$CONTAINER_SEMGREP_DIR'"
  docker cp "$SEMGREP_RULES_SOURCE" "$CONTAINER_NAME:$CONTAINER_SEMGREP_DIR/rules" >/dev/null

  # The python rules are the file the adapter is pointed at; the other languages are
  # carried so the path can be re-pointed without repackaging.
  container_rules="$CONTAINER_SEMGREP_DIR/rules/python/rules.yaml"
  docker exec -i "$CONTAINER_NAME" bash -c "test -f '$container_rules'" >/dev/null 2>&1 || \
    die "rules did not land in the container: $container_rules"
  info "rules installed: $container_rules"

  # The version and the rule digests are what tie this image to the scans the holdout
  # evidence was gathered with. The freeze file is the tree that actually ran: pinning
  # semgrep does not pin what it pulls in.
  docker exec -i "$CONTAINER_NAME" bash -c "
    set -eu
    cd '$CONTAINER_SEMGREP_DIR'
    {
      printf 'engine semgrep\nversion %s\n' '$installed_version'
      find rules -type f -name '*.yaml' -exec sha256sum {} + | LC_ALL=C sort -k2
    } > MANIFEST
    pip3 freeze > pip-freeze.txt
  " >/dev/null
  info "recorded $CONTAINER_SEMGREP_DIR/MANIFEST and pip-freeze.txt"

  step "deriving the TAA config template for the semgrep engine"
  # Derived on the host and handed to deploy.sh as its template: write_taa_config copies
  # the security block verbatim, and a config patched into the container after the daemon
  # started would need a second restart to be read. The tracked templates keep no engine
  # key, so the engine production runs is not moved by packaging.
  TMP_TAA_TEMPLATE="$(mktemp)"
  python3 - "$TAA_TEMPLATE" "$TMP_TAA_TEMPLATE" "$container_rules" <<'PY'
import json, sys
src, dst, rules = sys.argv[1:4]
with open(src, "r", encoding="utf-8") as f:
    cfg = json.load(f)
security = cfg.setdefault("security", {})
security["codeScanEngine"] = "semgrep"
security["semgrepRulesPath"] = rules
with open(dst, "w", encoding="utf-8") as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
    f.write("\n")
PY
  TAA_TEMPLATE="$TMP_TAA_TEMPLATE"
  info "derived template sets codeScanEngine=semgrep and semgrepRulesPath=$container_rules"
fi

# ── 4. TAA ───────────────────────────────────────────────────
step "deploying TAA (model: $LLM_MODEL)"
info "running: ./deploy.sh docker taa --model $LLM_MODEL"
( cd "$PROJECT_DIR" && TAA_DOCKER_CONFIG_TEMPLATE="$TAA_TEMPLATE" ./deploy.sh docker taa --model "$LLM_MODEL" )
info "TAA deployed"

# ── 5. Verify the supervisor partition ───────────────────────
# Neither deploy script touches the other's supervisor: step 2 left one start-teellm.sh,
# step 4 stopped the old start.sh and left a fresh one, and the flock guard in both
# wrappers refuses the duplicate that step 4's start.sh tries to launch. There is nothing
# left to consolidate -- but the guarantee still has to be checked, because a container
# carrying a pre-guard ./start.sh would end up with two supervisors respawning each
# other's daemons. Nothing is killed here, so the warmed weights from step 1 stay resident
# and teellm-service's 5s probe below does not have to pay for a cold load.
step "verifying exactly one supervisor pair"
container_running || die "container $CONTAINER_NAME is not running"

# The bracket keeps pgrep from matching the shell running the pattern itself. `-f` matches
# the full command line, which is empty for a zombie, so an unreaped child cannot be
# counted as a live duplicate.
supervisor_count() {
  docker exec -i "$CONTAINER_NAME" sh -lc "pgrep -f '$1' 2>/dev/null | wc -l"
}

taa_supervisors="$(supervisor_count '[s]tart\.sh')"
teellm_supervisors="$(supervisor_count '[s]tart-teellm\.sh')"
if (( taa_supervisors != 1 || teellm_supervisors != 1 )); then
  err "expected one start.sh and one start-teellm.sh supervisor, found $taa_supervisors and $teellm_supervisors"
  docker exec -i "$CONTAINER_NAME" sh -lc "ps -eo pid,ppid,stat,args | grep -E '[s]tart(-teellm)?\.sh' || true"
  exit 1
fi
info "one start.sh supervisor and one start-teellm.sh supervisor"

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

# ── 6. Production hygiene ────────────────────────────────────
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

# ── 7. Commit ────────────────────────────────────────────────
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

# ── 8. Export ────────────────────────────────────────────────
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

# ── 9. Restore dev container ─────────────────────────────────
# `docker stop` in step 7 killed every daemon the deploys had started. The container's
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
