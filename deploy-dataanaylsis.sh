#!/usr/bin/env bash
# Deploy the data-analysis flavour of TAA.
#
# The instance loads configs/taa-dataanaylsis.json: server.type=data-anaylsis,
# with the code audit and the LLM both switched off. That is what decides what
# this deployment may ship, so unlike deploy.sh this script never provisions the
# semgrep payload and never deploys -- or points TAA at -- a TEE-LLM gateway.
# Everything else (docker/remote modes, platform-mock, start/stop/save) stays
# deploy.sh's job: the arguments are forwarded to it with the environment
# overrides below, so the two deployments cannot drift apart.
#
# The base image is jupyter-nologin-full, the runtime the data-analysis tasks
# execute in; deploy.sh's taa-env:slim-v2 is not used here.
#
# docker mode runs outside the CSV guest, so it renders a copy of the template
# with storage.stateSealingKeySource=sm2: the shipped template asks for the CSV
# hardware key, which exists only inside the guest, and TAA would exit at
# startup without it. The remote and save paths keep the template as shipped.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_TEMPLATE="$PROJECT_DIR/configs/taa-dataanaylsis.json"
BASE_IMAGE="${DATAANALYSIS_IMAGE:-jupyter-nologin-full:v2.2}"
BASE_ARCHIVE="${DATAANALYSIS_IMAGE_ARCHIVE:-$PROJECT_DIR/deploy/base/jupyter-nologin-full-v2.2.tar.gz}"
LOCAL_CONTAINER="${DATAANALYSIS_CONTAINER:-taa-dataanaylsis}"

die() { printf '[deploy-dataanaylsis] ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '[deploy-dataanaylsis] %s\n' "$*"; }

[ -f "$CONFIG_TEMPLATE" ] || die "config template not found: $CONFIG_TEMPLATE"
command -v python3 >/dev/null 2>&1 \
  || die "python3 is required to validate and render the config template"

# One check, one purpose: the payload this script deploys carries no semgrep
# engine and no LLM. A template edit that turns either back on would quietly
# reintroduce a dependency this deployment does not ship, so refuse here instead
# of discovering it inside a container that cannot start.
python3 - "$CONFIG_TEMPLATE" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    cfg = json.load(f)

problems = []
if (cfg.get("server") or {}).get("type") != "data-anaylsis":
    problems.append('server.type is %r, want "data-anaylsis"'
                    % (cfg.get("server") or {}).get("type"))

audit = cfg.get("codeAudit") or {}
# The loader defaults both switches to true, so an absent key is an enabled one.
if audit.get("enabled", True):
    problems.append("codeAudit.enabled is not false")
if (audit.get("codeScan") or {}).get("engine") == "semgrep":
    problems.append("codeAudit.codeScan.engine is semgrep")
if (audit.get("llm") or {}).get("enabled", True):
    problems.append("codeAudit.llm.enabled is not false")

if problems:
    sys.stderr.write("[deploy-dataanaylsis] ERROR: %s would ship semgrep or the LLM:\n" % path)
    for problem in problems:
        sys.stderr.write("  - %s\n" % problem)
    sys.exit(1)
PY

# The docker-mode template lives beside deploy.sh's other run artefacts. TAA is
# not inside the CSV guest here, so the sealing key comes from SM2 instead of
# the hardware.
DOCKER_TEMPLATE="$PROJECT_DIR/.local/run/taa-dataanaylsis-docker.json"
mkdir -p "$(dirname "$DOCKER_TEMPLATE")"
python3 - "$CONFIG_TEMPLATE" "$DOCKER_TEMPLATE" <<'PY'
import json
import sys

src, dst = sys.argv[1], sys.argv[2]
with open(src, encoding="utf-8") as f:
    cfg = json.load(f)
cfg.setdefault("storage", {})["stateSealingKeySource"] = "sm2"
with open(dst, "w", encoding="utf-8") as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
    f.write("\n")
PY

export TAA_PRODUCTION_CONFIG_TEMPLATE="$CONFIG_TEMPLATE"
export TAA_DOCKER_CONFIG_TEMPLATE="$DOCKER_TEMPLATE"
export BASE_DOCKER_IMAGE="$BASE_IMAGE"
export BASE_DOCKER_IMAGE_ARCHIVE="$BASE_ARCHIVE"
export LOCAL_DOCKER_IMAGE="$BASE_IMAGE"
export LOCAL_DOCKER_IMAGE_ARCHIVE="$BASE_ARCHIVE"
export LOCAL_DOCKER_CONTAINER="$LOCAL_CONTAINER"
# No gateway is deployed behind this instance, and llm.enabled=false is what
# makes that binding; an endpoint injected by the environment would only be a
# leftover from the audit flavour.
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

log "config: $CONFIG_TEMPLATE (server.type=data-anaylsis, no semgrep, no LLM)"
log "base image: $BASE_IMAGE"
exec "$PROJECT_DIR/deploy.sh" "${args[@]}"
