#!/usr/bin/env bash
# Deploy the data-analysis role of TAA.
#
# The role is injected into the Pod as CONTRACT_TYPE=3 and is not written into the config: TAA
# derives everything the role changes from that one value - the code audit, the binary channel,
# the result check, the LLM and the rule-carrying scan engine are switched off, and the data lands
# under /home/jovyan/systemAuthData, where the jupyter runtime reads it, instead of the shared
# template's /root/taa/data. The shared configs/taa-production.json is therefore used unmodified,
# and the same image can be deployed as another role by injecting another value.
#
# What this script adds is the deployment shape the data-analysis tasks need: the jupyter base
# image, the role, and the packed image names.
#
# The state sealing key source is not rendered: TAA detects /dev/csv-guest at startup and uses the
# CSV hardware key inside a guest, the SM2 derivation everywhere else. Remote deployment and image
# packaging therefore behave the same way for this role.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_IMAGE="${DATAANALYSIS_IMAGE:-jupyter-nologin-full:v2.2}"
BASE_ARCHIVE="${DATAANALYSIS_IMAGE_ARCHIVE:-$PROJECT_DIR/deploy/base/jupyter-nologin-full-v2.2.tar.gz}"

log() { printf '[deploy-dataanaylsis] %s\n' "$*"; }

export BASE_DOCKER_IMAGE="$BASE_IMAGE"
export BASE_DOCKER_IMAGE_ARCHIVE="$BASE_ARCHIVE"
# 3 is data analysis in TAA's CONTRACT_TYPE mapping; the Pod carries it and the daemon resolves the
# role from it before it reads the config.
export TAA_POD_CONTRACT_TYPE=3
# The shared template still selects semgrep, so deploy.sh would otherwise install the payload into
# the image (save) or the pod (remote). The role disables the engine at startup, and this base
# image ships neither the payload nor a use for it.
export TAA_SCAN_ENGINE_PROVISION=skip
# No gateway is deployed behind this instance, and the role disables the LLM; an
# endpoint injected by the environment would only be a leftover from the audit
# flavour.
unset LLM_IP TAA_LLM_ENDPOINT

# deploy.sh derives its save defaults from the taa-env image (including the
# archive basename), so a save run gets both names here unless the caller
# already chose them. --archive and --image are deploy.sh's own.
args=("$@")
want_save=false
has_image=false
has_archive=false
for arg in "${args[@]}"; do
  case "$arg" in
    save) want_save=true ;;
    --image|--image=*) has_image=true ;;
    --archive|--archive=*) has_archive=true ;;
  esac
done

if [[ "$want_save" == true ]]; then
  date_tag="$(date +%Y%m%d)"
  [[ "$has_image" == true ]] || args+=(--image "taa-dataanaylsis:$date_tag")
  [[ "$has_archive" == true ]] || args+=(--archive "$PROJECT_DIR/deploy/out/taa-dataanaylsis-$date_tag.tar.gz")
fi

log "role: CONTRACT_TYPE=3 (data-anaylsis), data under /home/jovyan/systemAuthData"
log "base image: $BASE_IMAGE"
exec "$PROJECT_DIR/deploy.sh" "${args[@]}"
