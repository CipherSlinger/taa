#!/usr/bin/env bash
# Verifies that the local deployment modes are gone and fail loudly instead of falling through
# to a deployment: `deploy.sh` no longer has a `docker` target (nor its `local` aliases), and
# `deploy-platform-mock.sh` no longer has a `local` target. Every check here stops in argument
# parsing, so the test never reaches SSH, docker or kubectl.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY="$ROOT_DIR/deploy.sh"
MOCK_DEPLOY="$ROOT_DIR/deploy-platform-mock.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }

# run_capture OUT_VAR <command...>: runs the command, storing combined output in OUT_VAR and
# returning its exit status without tripping `set -e`.
run_capture() {
  local __var="$1"
  shift
  local __out rc=0
  __out="$("$@" 2>&1)" || rc=$?
  printf -v "$__var" '%s' "$__out"
  return "$rc"
}

for mode in docker local local-docker; do
  rc=0
  run_capture out "$DEPLOY" "$mode" || rc=$?
  [[ "$rc" -ne 0 ]] || fail "deploy.sh $mode exited 0; the removed mode still deploys"
  grep -q "the '$mode' mode has been removed" <<<"$out" \
    || fail "deploy.sh $mode did not explain that the mode is gone"
done

rc=0
run_capture out "$DEPLOY" --container taa-env || rc=$?
[[ "$rc" -ne 0 ]] || fail "deploy.sh still accepts --container"
grep -q 'unknown argument: --container' <<<"$out" \
  || fail "deploy.sh --container did not fail on the removed option"

run_capture help "$DEPLOY" --help
grep -q -- '--container' <<<"$help" && fail "deploy.sh --help still documents --container"
grep -q 'LOCAL_DOCKER_\|TAA_DOCKER_CONFIG_TEMPLATE' <<<"$help" \
  && fail "deploy.sh --help still documents the removed docker overrides"
grep -q 'ONLY valid in docker mode' <<<"$help" \
  && fail "deploy.sh --help still ties save to docker mode"
grep -q 'save ' <<<"$help" || fail "deploy.sh --help no longer documents save"

rc=0
run_capture out "$MOCK_DEPLOY" local start || rc=$?
[[ "$rc" -ne 0 ]] || fail "deploy-platform-mock.sh local start exited 0"
grep -q 'local mode has been removed' <<<"$out" \
  || fail "deploy-platform-mock.sh local start did not explain that the mode is gone"

echo "PASS: removed deployment modes fail with an explanatory error"
