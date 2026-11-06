#!/usr/bin/env bash
# Verifies what deploy-dataanaylsis.sh hands to deploy.sh, without building, connecting or
# rendering anything: the role is injected as CONTRACT_TYPE=3, the shared config template is used
# unmodified (no rendered copy), the semgrep payload stays out, and the role owns its image
# repository and Pod name so it cannot build over the tee role's image or contend for its Pod.
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
printf 'IMAGE_REPO=%s\n' "${TAA_POD_IMAGE_REPO:-<unset>}"
printf 'POD_NAME=%s\n' "${TAA_POD_NAME:-<unset>}"
printf 'SUPERVISOR=%s\n' "${TAA_SUPERVISOR_SOURCE:-<unset>}"
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

# The role owns both names: a shared repository would let the two roles overwrite each other's
# image under one same-day tag, and a shared Pod name would make one role's Pod block the other's.
grep -qx 'IMAGE_REPO=taa-dataanaylsis' <<<"$out" \
  || fail "the role does not own its image repository"
grep -qx 'POD_NAME=taa-dataanaylsis' <<<"$out" \
  || fail "the role does not own its Pod name"

# jupyter and TAA share the container, so this role's entrypoint is the combined
# supervisor, installed under the same name and path every role uses.
grep -q '^SUPERVISOR=.*/deploy/dataanaylsis/taa-supervisor\.sh$' <<<"$out" \
  || fail "the role does not select the combined jupyter + TAA supervisor"

# An operator's own names win over both defaults.
out="$(env TAA_POD_IMAGE_REPO=custom-repo TAA_POD_NAME=custom-pod \
  "$TMP_DIR/deploy-dataanaylsis.sh" 2>&1)"
grep -qx 'IMAGE_REPO=custom-repo' <<<"$out" || fail "an explicit image repository was overridden"
grep -qx 'POD_NAME=custom-pod' <<<"$out" || fail "an explicit Pod name was overridden"

# save needs no extra arguments: deploy.sh derives both names from the repository, so a save run
# and a create run land on the same image and archive.
out="$("$TMP_DIR/deploy-dataanaylsis.sh" save 2>&1)"
grep -qx 'IMAGE_REPO=taa-dataanaylsis' <<<"$out" \
  || fail "save no longer selects the data-analysis image repository"
grep -qx 'ARG=save' <<<"$out" || fail "save was not passed through"
if grep -q '^ARG=--image' <<<"$out" || grep -q '^ARG=--archive' <<<"$out"; then
  fail "save still overrides the names deploy.sh now derives from the repository"
fi

echo "PASS: deploy-dataanaylsis.sh injects CONTRACT_TYPE=3, keeps the shared config unrendered, and owns its image repository and Pod name"
