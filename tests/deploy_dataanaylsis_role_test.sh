#!/usr/bin/env bash
# Verifies what deploy-dataanaylsis.sh hands to deploy.sh, without building, connecting or
# rendering anything: the role is injected as CONTRACT_TYPE=3, the shared config template is used
# unmodified (no rendered copy), the semgrep payload stays out, and save keeps its own image and
# archive names.
#
# The script under test execs "$PROJECT_DIR/deploy.sh", so a stub in the same throwaway directory
# stands in for the real deployment and records the environment it received.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

cp "$ROOT_DIR/deploy-dataanaylsis.sh" "$TMP_DIR/deploy-dataanaylsis.sh"
chmod +x "$TMP_DIR/deploy-dataanaylsis.sh"

cat > "$TMP_DIR/deploy.sh" <<'STUB'
#!/usr/bin/env bash
printf 'ARG=%s\n' "$@"
printf 'CONTRACT_TYPE=%s\n' "${TAA_POD_CONTRACT_TYPE:-<unset>}"
printf 'BASE_IMAGE=%s\n' "${BASE_DOCKER_IMAGE:-<unset>}"
printf 'BASE_ARCHIVE=%s\n' "${BASE_DOCKER_IMAGE_ARCHIVE:-<unset>}"
printf 'SCAN_PROVISION=%s\n' "${TAA_SCAN_ENGINE_PROVISION:-<unset>}"
printf 'CONFIG_TEMPLATE=%s\n' "${TAA_PRODUCTION_CONFIG_TEMPLATE:-<unset>}"
printf 'LLM_IP=%s\n' "${LLM_IP:-<unset>}"
printf 'LLM_ENDPOINT=%s\n' "${TAA_LLM_ENDPOINT:-<unset>}"
STUB
chmod +x "$TMP_DIR/deploy.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }

# Even when the caller exports an LLM endpoint, the role has no gateway behind it and the script
# drops it rather than letting a leftover from the audit flavour reach the deployment.
out="$(env LLM_IP=10.0.0.9 TAA_LLM_ENDPOINT=https://10.0.0.9:8443 \
  "$TMP_DIR/deploy-dataanaylsis.sh" 2>&1)"

grep -qx 'CONTRACT_TYPE=3' <<<"$out" \
  || fail "the role is not injected as CONTRACT_TYPE=3"
grep -qx 'BASE_IMAGE=jupyter-nologin-full:v2.2' <<<"$out" \
  || fail "the jupyter base image is not selected"
grep -qx 'SCAN_PROVISION=skip' <<<"$out" \
  || fail "the semgrep payload is no longer skipped"
grep -qx 'CONFIG_TEMPLATE=<unset>' <<<"$out" \
  || fail "the script still renders a config copy instead of using the shared template"
grep -qx 'LLM_IP=<unset>' <<<"$out" || fail "LLM_IP was not dropped"
grep -qx 'LLM_ENDPOINT=<unset>' <<<"$out" || fail "TAA_LLM_ENDPOINT was not dropped"

# save keeps the data-analysis image and archive names, derived from the caller's date.
date_tag="$(date +%Y%m%d)"
out="$("$TMP_DIR/deploy-dataanaylsis.sh" save 2>&1)"
grep -qx "ARG=--image" <<<"$out" || fail "save did not pass --image"
grep -qx "ARG=taa-dataanaylsis:$date_tag" <<<"$out" \
  || fail "save no longer defaults to the data-analysis image name"
grep -qx "ARG=--archive" <<<"$out" || fail "save did not pass --archive"
grep -q "ARG=.*/deploy/out/taa-dataanaylsis-$date_tag.tar.gz$" <<<"$out" \
  || fail "save no longer defaults to the data-analysis archive name"

echo "PASS: deploy-dataanaylsis.sh injects CONTRACT_TYPE=3, keeps the shared config unrendered and preserves the save names"
