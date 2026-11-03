#!/usr/bin/env bash
# Deploy the data-analysis role of TAA.
#
# The role itself is selected by CONTRACT_TYPE=3 (or by the rendered
# server.type), and the loader derives what the role cannot do - no code audit,
# no binary channel, no result check, no LLM, the rule-carrying scan engine -
# from that selection alone. What this script adds is the deployment shape the
# data-analysis tasks need: the jupyter base image, and a data landing directory
# inside that image's home.
#
# One thing follows from the base image and is rendered into a copy of the
# shared configs/taa-production.json: the data lands under
# /home/jovyan/systemAuthData, where the jupyter runtime reads it, instead of
# the shared template's /root/taa/data.
#
# The code audit block is left exactly as the shared template has it. The role
# (server.type=data-anaylsis, or CONTRACT_TYPE=3) disables the whole audit at
# startup - switches, LLM and a rule-carrying engine - so the template's semgrep
# selection never reaches a scan on this instance. What must not happen is the
# packaging path reading that text at face value and installing a semgrep
# payload this image has no use for, so engine provisioning is skipped
# explicitly below.
#
# The state sealing key source is not rendered: TAA detects /dev/csv-guest at
# startup and uses the CSV hardware key inside a guest, the SM2 derivation
# everywhere else. The remote and save paths therefore behave exactly as the
# docker path does here.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_TEMPLATE="$PROJECT_DIR/configs/taa-production.json"
BASE_IMAGE="${DATAANALYSIS_IMAGE:-jupyter-nologin-full:v2.2}"
BASE_ARCHIVE="${DATAANALYSIS_IMAGE_ARCHIVE:-$PROJECT_DIR/deploy/base/jupyter-nologin-full-v2.2.tar.gz}"
LOCAL_CONTAINER="${DATAANALYSIS_CONTAINER:-taa-dataanaylsis}"
RENDERED_TEMPLATE="$PROJECT_DIR/.local/run/taa-dataanaylsis.json"

die() { printf '[deploy-dataanaylsis] ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '[deploy-dataanaylsis] %s\n' "$*"; }

[ -f "$CONFIG_TEMPLATE" ] || die "config template not found: $CONFIG_TEMPLATE"
command -v python3 >/dev/null 2>&1 \
  || die "python3 is required to render the config template"

mkdir -p "$(dirname "$RENDERED_TEMPLATE")"
python3 - "$CONFIG_TEMPLATE" "$RENDERED_TEMPLATE" <<'PY'
import json
import sys

src, dst = sys.argv[1], sys.argv[2]
with open(src, encoding="utf-8") as f:
    cfg = json.load(f)

cfg.setdefault("server", {})["type"] = "data-anaylsis"
cfg.setdefault("storage", {})["data"] = "/home/jovyan/systemAuthData"

with open(dst, "w", encoding="utf-8") as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
    f.write("\n")
PY

export TAA_PRODUCTION_CONFIG_TEMPLATE="$RENDERED_TEMPLATE"
export TAA_DOCKER_CONFIG_TEMPLATE="$RENDERED_TEMPLATE"
export BASE_DOCKER_IMAGE="$BASE_IMAGE"
export BASE_DOCKER_IMAGE_ARCHIVE="$BASE_ARCHIVE"
export LOCAL_DOCKER_IMAGE="$BASE_IMAGE"
export LOCAL_DOCKER_IMAGE_ARCHIVE="$BASE_ARCHIVE"
export LOCAL_DOCKER_CONTAINER="$LOCAL_CONTAINER"
# The rendered template still selects semgrep, so deploy.sh would otherwise install the payload
# into the image (save) or the pod (remote). The role disables the engine at startup, and this
# base image ships neither the payload nor a use for it.
export TAA_SCAN_ENGINE_PROVISION=skip
# No gateway is deployed behind this instance, and the role disables the LLM; an
# endpoint injected by the environment would only be a leftover from the audit
# flavour.
unset LLM_IP TAA_LLM_ENDPOINT

# deploy.sh derives its save defaults from the taa-env image (including the
# archive basename), so a save run gets both names here unless the caller
# already chose them. -o/--archive and --image/--tag are deploy.sh's own.
args=("$@")
want_save=false
has_image=false
has_archive=false
for arg in "${args[@]}"; do
  case "$arg" in
    save) want_save=true ;;
    --image|--image=*|--tag|--tag=*) has_image=true ;;
    --archive|--archive=*|--output|--output=*|-o) has_archive=true ;;
  esac
done

if [[ "$want_save" == true ]]; then
  date_tag="$(date +%Y%m%d)"
  [[ "$has_image" == true ]] || args+=(--image "taa-dataanaylsis:$date_tag")
  [[ "$has_archive" == true ]] || args+=(--archive "$PROJECT_DIR/deploy/out/taa-dataanaylsis-$date_tag.tar.gz")
fi

log "config: $CONFIG_TEMPLATE rendered with server.type=data-anaylsis, data under /home/jovyan/systemAuthData"
log "base image: $BASE_IMAGE"
exec "$PROJECT_DIR/deploy.sh" "${args[@]}"
