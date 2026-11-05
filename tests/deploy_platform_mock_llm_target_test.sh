#!/usr/bin/env bash
# Verifies which TEE-LLM address deploy-platform-mock.sh hands the mock.
#
# The mock polls the TEE-LLM instance for liveness, logs and its attestation report, and the
# console's TEE-LLM card displays the address it polls. That address used to come from kubectl
# Pod-IP discovery, which points at an IP that changes on every recreation of the Pod. The
# deployment now defaults to the host address the Pod publishes (`6001 → 16001`, see
# deploy-llm.sh), so the panel shows an address that survives a rebuild and no kubectl runs on
# this path at all. Discovery must stay reachable as an explicit opt-in, and an explicit
# `--llm-target` must always win.
#
# Every case runs with --dry-run and --skip-build: the script prints the argv it would start the
# mock with and touches neither the network nor the compiler.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/deploy-platform-mock.sh"

fail() {
  echo "FAIL: $1" >&2
  echo "$output" >&2
  exit 1
}

# argv is the exact argument vector the script says it would start the mock with; output is only
# used for the human-readable summary lines. Matching against argv matters because the summary
# line itself names --llm-pod while describing the opt-in.
run_dry() {
  output="$(DRY_RUN=1 "$SCRIPT" start --host 10.0.0.9 --skip-build "$@" 2>&1)" || true
  argv="$(sed -n 's/^\[platform-mock\] would start .* with \(.*\) (log .*/\1/p' <<<"$output")"
  [ -n "$argv" ] || fail "the dry run did not print the mock's argv"
}

# ── 1. Default: the host address and its published port ──────────────────────
run_dry
grep -q -- '-llm-target http://10.0.0.9:16001' <<<"$argv" \
  || fail "the mock is not started against the host address and its published port"
grep -q 'TEE-LLM target: http://10.0.0.9:16001' <<<"$output" \
  || fail "the start log does not name the TEE-LLM target"
if grep -q -- '-llm-pod' <<<"$argv"; then
  fail "Pod-IP discovery is still used by default"
fi

# ── 2. The host port is configurable ─────────────────────────────────────────
output="$(DRY_RUN=1 PLATFORM_MOCK_LLM_HOST_PORT=17001 \
  "$SCRIPT" start --host 10.0.0.9 --skip-build 2>&1)" || true
argv="$(sed -n 's/^\[platform-mock\] would start .* with \(.*\) (log .*/\1/p' <<<"$output")"
grep -q -- '-llm-target http://10.0.0.9:17001' <<<"$argv" \
  || fail "PLATFORM_MOCK_LLM_HOST_PORT did not reach the mock"

# ── 3. An explicit target wins over both defaults ────────────────────────────
run_dry --llm-target http://1.2.3.4:6001
grep -q -- '-llm-target http://1.2.3.4:6001' <<<"$argv" \
  || fail "--llm-target was replaced by the host address"
grep -q 'TEE-LLM target: http://1.2.3.4:6001' <<<"$output" \
  || fail "the start log names a target other than the one passed"

# ── 4. Any discovery flag opts back into kubectl ──────────────────────────────
# --llm-port alone has to count: it means "the default Pod, another port", not "ignore it and
# call the host address".
for flag in "--llm-pod taa-teellm" "--llm-ns osr" "--llm-port 6001"; do
  # shellcheck disable=SC2086
  run_dry $flag
  if grep -q -- '-llm-target' <<<"$argv"; then
    fail "$flag still produced a fixed host target"
  fi
  grep -q 'kubectl discovery' <<<"$output" \
    || fail "$flag did not switch the mock back to kubectl discovery"
done

echo "PASS: deploy-platform-mock targets the TEE-LLM host address by default and keeps Pod discovery as an opt-in"
