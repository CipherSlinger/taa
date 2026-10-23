#!/usr/bin/env bash
set -euo pipefail

# Builds the dedicated TEE-LLM image: a TAA-free base plus teellm-service, the Pod supervisor,
# the attestation certificates and the ollama runtime with one model baked in.
#
# Why this exists: the TEE-LLM Pod runs on a Kata CSV2 guest whose container rootfs upperdir is a
# tmpfs inside the guest. Anything deploy-llm.sh copies in at deploy time -- the service binary,
# the supervisor, the multi-GB model -- lives in guest RAM and dies with the sandbox, so a host
# reboot leaves a confidential VM that listens on nothing. Baking the payload into the image makes
# a freshly booted guest serve without any host-side step.
#
# The base image is derived from a TAA image, but /root/taa (the TAA binary and its autostart
# wrapper) is removed first: an inference image has no reason to carry an unrelated service, and
# its payload lives under /opt/teellm. deploy.sh's strip_teellm_from_image keeps the payload out of
# the TAA images, so this stays a second image built from the same source.
#
# Usage:
#   ./build-teellm-image.sh [--push] [--keep] [-h|--help]
#
#   --push   Also ship the archive to the remote host, load it there and push it to the local
#            registry so the guest's CDH can pull it (REMOTE_HOST / REMOTE_USER / TARGET_PASSWORD).
#   --keep   Keep the builder container around for inspection (it is removed on success by default).

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEELLM_DIR="${TEELLM_DIR:-$PROJECT_DIR/teellm}"
OLLAMA_LOCAL_DIR="${OLLAMA_LOCAL_DIR:-$TEELLM_DIR/models/ollama}"
OLLAMA_MODEL="${OLLAMA_MODEL:-qwen2.5-coder:7b}"
DATE_TAG="${DATE_TAG:-$(date +%Y%m%d)}"
# Source image (still carries TAA) and the TAA-free base derived from it.
BASE_IMAGE="${BASE_IMAGE:-taa-env:slim-v2}"
BASE_ARCHIVE="${BASE_ARCHIVE:-$PROJECT_DIR/deploy/base/taa-env-slim-v2.tar.gz}"
CLEAN_BASE_IMAGE="${CLEAN_BASE_IMAGE:-teellm-base:$DATE_TAG}"
# Every path inside the image lives here; nothing under /root/taa is used or created.
IMAGE_WORKDIR="${IMAGE_WORKDIR:-/opt/teellm}"
TARGET_IMAGE="${TARGET_IMAGE:-teellm:teellm-$DATE_TAG}"
TARGET_ARCHIVE="${TARGET_ARCHIVE:-$PROJECT_DIR/deploy/out/teellm-image-$DATE_TAG.tar.gz}"
REGISTRY_IMAGE="${REGISTRY_IMAGE:-172.16.10.178:31313/teellm:teellm-$DATE_TAG}"
BUILDER_CONTAINER="${BUILDER_CONTAINER:-taa-teellm-builder-$$}"

REMOTE_HOST="${REMOTE_HOST:-172.16.10.178}"
REMOTE_USER="${REMOTE_USER:-root}"
PASSWORD="${TARGET_PASSWORD:-Osrd@2026}"
SSH_OPTS=(-q -o LogLevel=ERROR -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$HOME/.ssh/known_hosts")

PUSH=false
KEEP_BUILDER=false

# ── Terminal output ──────────────────────────────────────────
if [[ -t 1 ]]; then
  RED='\033[38;5;203m'; GREEN='\033[38;5;48m'; YELLOW='\033[38;5;215m'
  CYAN='\033[38;5;45m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; DIM=''; NC=''
fi

info() { echo -e "  ${GREEN}✓${NC} $*"; }
step() { echo -e "  ${CYAN}◆${NC} ${BOLD}$*${NC}"; }
warn() { echo -e "  ${YELLOW}!${NC} $*" >&2; }
err()  { echo -e "  ${RED}✗${NC} ${BOLD}$*${NC}" >&2; }
detail() { echo -e "    ${DIM}↳ $*${NC}" >&2; }

usage() {
  sed -n '4,21p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --push) PUSH=true ;;
    --keep) KEEP_BUILDER=true ;;
    -h|--help|help) usage ;;
    *) err "unknown argument: $1"; detail "Try --help."; exit 1 ;;
  esac
  shift
done

cleanup() {
  [[ "$KEEP_BUILDER" == true ]] || docker rm -f "$BUILDER_CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

die() { err "$*"; exit 1; }
require_file() { [[ -s "$1" ]] || die "missing required file: $1"; }

# ── Preflight ────────────────────────────────────────────────
step "checking the build environment"
command -v docker >/dev/null 2>&1 || die "docker is required"
docker info >/dev/null 2>&1 || die "docker daemon is not running or accessible"

[[ "$OLLAMA_MODEL" == *:* ]] || die "OLLAMA_MODEL must be <family>:<tag>, got '$OLLAMA_MODEL'"
model_repo="${OLLAMA_MODEL%%:*}"
model_tag="${OLLAMA_MODEL#*:}"
manifest_rel="models/models/manifests/registry.ollama.ai/library/$model_repo/$model_tag"

if [[ ! -s "$TEELLM_DIR/bin/teellm-service" ]]; then
  step "teellm-service binary is missing; building it"
  command -v go >/dev/null 2>&1 || die "go is required to build teellm-service"
  ( cd "$PROJECT_DIR" && CGO_ENABLED=0 GOOS=linux go build -o "$TEELLM_DIR/bin/teellm-service" ./teellm/cmd/teellm-service )
fi
require_file "$TEELLM_DIR/bin/teellm-service"
require_file "$PROJECT_DIR/deploy/teellm-supervisor.sh"
require_file "$TEELLM_DIR/configs/teellm-production.json"
require_file "$TEELLM_DIR/configs/models.json"
require_file "$PROJECT_DIR/deploy/certs/hrk.cert"
require_file "$PROJECT_DIR/deploy/certs/hsk_cek.cert"
require_file "$OLLAMA_LOCAL_DIR/ollama"
require_file "$OLLAMA_LOCAL_DIR/start-ollama.sh"
require_file "$OLLAMA_LOCAL_DIR/$manifest_rel"
[[ -d "$OLLAMA_LOCAL_DIR/lib/ollama" ]] || die "missing ollama library directory: $OLLAMA_LOCAL_DIR/lib/ollama"

if ! docker image inspect "$BASE_IMAGE" >/dev/null 2>&1; then
  require_file "$BASE_ARCHIVE"
  step "loading base image from $(basename "$BASE_ARCHIVE")"
  docker load -i "$BASE_ARCHIVE" >/dev/null
  docker image inspect "$BASE_IMAGE" >/dev/null 2>&1 || die "base image '$BASE_IMAGE' is not in $BASE_ARCHIVE"
fi
info "source image ready: $BASE_IMAGE"

# Strip the TAA payload before anything teellm is added. The TAA images carry /root/taa with the
# taa binary and an autostart wrapper; the inference image must contain neither. An empty build
# context keeps docker from packing the multi-GB archives that sit in deploy/.
if ! docker image inspect "$CLEAN_BASE_IMAGE" >/dev/null 2>&1; then
  step "building the TAA-free base image: $CLEAN_BASE_IMAGE"
  clean_ctx="$(mktemp -d /tmp/teellm-clean-base.XXXXXX)"
  docker build -q -t "$CLEAN_BASE_IMAGE" -f - "$clean_ctx" >/dev/null <<EOF
FROM $BASE_IMAGE
USER root
RUN rm -rf /root/taa
EOF
  rm -rf "$clean_ctx"
fi
BASE_IMAGE="$CLEAN_BASE_IMAGE"
if docker run --rm --entrypoint sh "$BASE_IMAGE" -c 'test ! -e /root/taa' >/dev/null 2>&1; then
  info "base image ready (no /root/taa): $BASE_IMAGE"
else
  die "base image '$BASE_IMAGE' still contains /root/taa"
fi
info "model: $OLLAMA_MODEL ($manifest_rel)"

# ── Payload list ─────────────────────────────────────────────
# Only what the deployed model needs: the CUDA/MLX/Vulkan runtimes are CPU-irrelevant here and
# would add ~4.3 GB, and every model but the selected one is dead weight in the guest's tmpfs.
step "resolving the ollama payload for '$OLLAMA_MODEL'"
model_blobs="$(python3 - "$OLLAMA_LOCAL_DIR/$manifest_rel" <<'PY'
import json, sys
manifest = json.load(open(sys.argv[1]))
for item in [manifest["config"]] + manifest["layers"]:
    digest = item["digest"].split(":", 1)[1]
    print("models/models/blobs/sha256-" + digest)
PY
)"
[[ -n "$model_blobs" ]] || die "could not resolve the blobs of $OLLAMA_MODEL"

file_list="$(mktemp /tmp/teellm-image-files.XXXXXX)"
trap 'rm -f "$file_list"; cleanup' EXIT
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

# ── Build ────────────────────────────────────────────────────
step "starting the builder container"
docker rm -f "$BUILDER_CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$BUILDER_CONTAINER" --user root --entrypoint bash "$BASE_IMAGE" -c 'sleep infinity' >/dev/null
docker exec -i "$BUILDER_CONTAINER" sh -c 'mkdir -p /opt/teellm/configs /opt/teellm/certs /opt/teellm/ollama'

step "copying teellm-service, supervisor, configs and certificates"
docker cp "$TEELLM_DIR/bin/teellm-service"            "$BUILDER_CONTAINER:/opt/teellm/teellm-service"
docker cp "$PROJECT_DIR/deploy/teellm-supervisor.sh"  "$BUILDER_CONTAINER:/opt/teellm/teellm-supervisor.sh"
docker cp "$TEELLM_DIR/configs/teellm-production.json" "$BUILDER_CONTAINER:/opt/teellm/configs/teellm-production.json"
docker cp "$TEELLM_DIR/configs/models.json"           "$BUILDER_CONTAINER:/opt/teellm/configs/models.json"
docker cp "$PROJECT_DIR/deploy/certs/hrk.cert"        "$BUILDER_CONTAINER:/opt/teellm/certs/hrk.cert"
docker cp "$PROJECT_DIR/deploy/certs/hsk_cek.cert"    "$BUILDER_CONTAINER:/opt/teellm/certs/hsk_cek.cert"

step "streaming the ollama runtime and model into the image (${payload_mb}MB)"
tar -C "$OLLAMA_LOCAL_DIR" -cf - -T "$file_list" | docker exec -i "$BUILDER_CONTAINER" tar -xf - -C /opt/teellm/ollama

step "finishing the payload inside the image"
# llama-server links against the soname forms of its libraries and carries RUNPATH=$ORIGIN, while
# the bundle ships versioned files only; without these links it exits 127 and ollama answers 500.
docker exec -i -e MODEL="$OLLAMA_MODEL" "$BUILDER_CONTAINER" sh -c '
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
docker exec -i -e MODEL="$OLLAMA_MODEL" "$BUILDER_CONTAINER" sh -c '
set -e
for p in /opt/teellm/teellm-service /opt/teellm/teellm-supervisor.sh \
         /opt/teellm/configs/teellm-production.json /opt/teellm/configs/models.json \
         /opt/teellm/certs/hrk.cert /opt/teellm/certs/hsk_cek.cert \
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

step "committing the image: $TARGET_IMAGE"
docker commit \
  -c 'ENTRYPOINT ["bash", "/opt/teellm/teellm-supervisor.sh"]' \
  -c 'CMD []' \
  -c 'USER root' \
  -c 'WORKDIR /opt/teellm' \
  -c 'EXPOSE 8443' \
  -m "TEE-LLM image: base $BASE_IMAGE + teellm-service + ollama $OLLAMA_MODEL at $(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  "$BUILDER_CONTAINER" "$TARGET_IMAGE" >/dev/null
image_size_mb="$(docker image inspect --format '{{.Size}}' "$TARGET_IMAGE" | awk '{printf "%.0f", $1/1048576}')"
info "image committed: $TARGET_IMAGE (${image_size_mb}MB uncompressed)"

step "exporting the image archive: $TARGET_ARCHIVE"
mkdir -p "$(dirname "$TARGET_ARCHIVE")"
tmp_archive="${TARGET_ARCHIVE}.tmp.$$"
if command -v pigz >/dev/null 2>&1; then
  docker save "$TARGET_IMAGE" | pigz -c > "$tmp_archive"
else
  docker save "$TARGET_IMAGE" | gzip -c > "$tmp_archive"
fi
mv -f "$tmp_archive" "$TARGET_ARCHIVE"
info "archive saved: $TARGET_ARCHIVE ($(du -h "$TARGET_ARCHIVE" | cut -f1))"

# ── Optional push ────────────────────────────────────────────
if [[ "$PUSH" == true ]]; then
  step "pushing to the remote registry: $REGISTRY_IMAGE"
  command -v sshpass >/dev/null 2>&1 || die "sshpass is required for --push"
  remote_archive="/tmp/$(basename "$TARGET_ARCHIVE")"
  sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$TARGET_ARCHIVE" "${REMOTE_USER}@${REMOTE_HOST}:$remote_archive"
  sshpass -p "$PASSWORD" ssh "${SSH_OPTS[@]}" "${REMOTE_USER}@${REMOTE_HOST}" "
    set -e
    docker load -i '$remote_archive' >/dev/null
    docker tag '$TARGET_IMAGE' '$REGISTRY_IMAGE'
    docker push '$REGISTRY_IMAGE' >/dev/null
    rm -f '$remote_archive'
  "
  info "pushed: $REGISTRY_IMAGE"
fi

# ── Summary ──────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}${CYAN}● TEE-LLM Image${NC}"
echo -e "    ↳ Base     : $BASE_IMAGE"
echo -e "    ↳ Tag      : $TARGET_IMAGE"
echo -e "    ↳ Model    : $OLLAMA_MODEL"
echo -e "    ↳ Archive  : $TARGET_ARCHIVE"
if [[ "$PUSH" == true ]]; then
  echo -e "    ↳ Registry : $REGISTRY_IMAGE"
  echo ""
  echo -e "  Deploy with:"
  echo -e "    TEELLM_POD_IMAGE=$REGISTRY_IMAGE ./deploy-llm.sh --create-pod --pod taa-teellm start"
else
  echo ""
  echo -e "  Push to the guest-reachable registry, then deploy with:"
  echo -e "    docker tag $TARGET_IMAGE $REGISTRY_IMAGE && docker push $REGISTRY_IMAGE"
  echo -e "    TEELLM_POD_IMAGE=$REGISTRY_IMAGE ./deploy-llm.sh --create-pod --pod taa-teellm start"
  echo -e "  ${DIM}(or re-run with --push to do the first two steps over SSH)${NC}"
fi
echo ""
