#!/usr/bin/env bash
# Verifies that the local deployment modes are gone and fail loudly instead of falling through
# to a deployment: `deploy.sh` no longer has a `docker` target (nor its `local` aliases), and
# `deploy-platform-mock.sh` no longer has a `local` target. It also verifies that the target Pod
# and namespace have exactly one spelling each -- `--pod` and `--namespace` -- and that the
# environment variables and positional `name=value` forms they replaced are refused.
# Every check here stops in argument parsing, so the test never reaches SSH, docker or kubectl.
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

for cmd in "$DEPLOY remote taa" "$MOCK_DEPLOY remote start"; do
  rc=0
  run_capture out $cmd || rc=$?
  [[ "$rc" -ne 0 ]] || fail "${cmd#$ROOT_DIR/} exited 0; the removed 'remote' word still deploys"
done
grep -q "unknown argument: remote" <<<"$("$DEPLOY" remote taa 2>&1 || true)" \
  || fail "deploy.sh remote did not fail as an unknown argument"
grep -q "unknown action 'remote'" <<<"$("$MOCK_DEPLOY" remote start 2>&1 || true)" \
  || fail "deploy-platform-mock.sh remote did not fail as an unknown action"

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

# The target Pod and namespace are command-line options: --pod and --namespace. The environment
# variables and positional name=value forms they replaced are refused before the run reaches
# anything, so a stale invocation cannot quietly deploy to the default Pod or namespace.
expect_refused() {
  local description="$1" expected="$2"
  shift 2
  local rc=0
  run_capture out env "$@" || rc=$?
  [[ "$rc" -ne 0 ]] || fail "$description exited 0"
  grep -q -- "$expected" <<<"$out" || fail "$description did not explain the removal"
}

expect_refused "deploy.sh TARGET_POD" "TARGET_POD is no longer supported" \
  TARGET_POD=stale "$DEPLOY" taa start
expect_refused "deploy.sh TARGET_NAMESPACE" "TARGET_NAMESPACE is no longer supported" \
  TARGET_NAMESPACE=stale "$DEPLOY" taa start
expect_refused "deploy-llm.sh TARGET_POD" "TARGET_POD is no longer supported" \
  TARGET_POD=stale "$ROOT_DIR/deploy-llm.sh" stop
expect_refused "deploy-llm.sh TARGET_NAMESPACE" "TARGET_NAMESPACE is no longer supported" \
  TARGET_NAMESPACE=stale "$ROOT_DIR/deploy-llm.sh" stop
expect_refused "deploy-fhe.sh TARGET_POD" "TARGET_POD is no longer supported" \
  TARGET_POD=stale "$ROOT_DIR/deploy-fhe.sh" taa
expect_refused "deploy-fhe.sh POD_NAMESPACE" "namespace environment variables are no longer supported" \
  POD_NAMESPACE=stale "$ROOT_DIR/deploy-fhe.sh" taa
expect_refused "deploy.sh pod=..." "unknown argument: pod=stale" \
  "$DEPLOY" taa start pod=stale
expect_refused "deploy-llm.sh pod=..." "unknown argument: pod=stale" \
  "$ROOT_DIR/deploy-llm.sh" pod=stale start
expect_refused "deploy-fhe.sh namespace=..." "unknown argument: namespace=stale" \
  "$ROOT_DIR/deploy-fhe.sh" namespace=stale --pod stale

for script in "$DEPLOY" "$ROOT_DIR/deploy-llm.sh" "$ROOT_DIR/deploy-fhe.sh"; do
  run_capture help "$script" --help
  grep -q -- '--pod <name>' <<<"$help" \
    || fail "$(basename "$script") --help does not document --pod <name>"
  grep -q -- '--namespace <ns>' <<<"$help" \
    || fail "$(basename "$script") --help does not document --namespace <ns>"
  grep -qE 'TARGET_POD|TARGET_NAMESPACE|POD_NAMESPACE' <<<"$help" \
    && fail "$(basename "$script") --help still documents a removed namespace/Pod variable"
done

echo "PASS: removed deployment modes, the 'remote' word and the old Pod/namespace spellings fail with an explanatory error"
