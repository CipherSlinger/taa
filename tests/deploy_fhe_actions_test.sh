#!/usr/bin/env bash
# Verifies deploy-fhe.sh's action vocabulary and its two targets, without touching the host:
# create is the default and the only action that creates a Pod, --pod adopts an existing Pod
# (create and delete refuse it), start is the other end of stop, and the docker container is
# selected explicitly with --target container. Every check runs in --dry-run, so nothing is
# built, pushed, started or removed and no SSH connection is made.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY="$ROOT_DIR/deploy-fhe.sh"

# create refuses to render a manifest without these; a dry run still checks them, because a
# missing platform address or public key is a configuration mistake worth catching there.
CREATE_ENV=(PLATFORM_IP=172.16.10.178:18081 PLATFORM_PUBLIC_KEY=04deadbeef)

fail() { echo "FAIL: $*" >&2; exit 1; }

run_capture() {
  local __var="$1"
  shift
  local __out rc=0
  __out="$("$@" 2>&1)" || rc=$?
  printf -v "$__var" '%s' "$__out"
  return "$rc"
}

# ── create is the default, and the only action that creates a Pod ─────────────
run_capture out env "${CREATE_ENV[@]}" "$DEPLOY" -n
grep -q 'this deployment owns osr/taa-fhe' <<<"$out" \
  || fail "the default action did not target the Pod this deployment owns"
grep -q 'creating the Pod osr/taa-fhe' <<<"$out" \
  || fail "the default action is no longer create"
grep -q 'verifying the Pod carries this run' <<<"$out" \
  || fail "create no longer verifies what the Pod carries"

# ── start and stop are the two ends of one switch and copy nothing ────────────
run_capture out "$DEPLOY" -n start
grep -q 'rm.*/root/taa/manual' <<<"$out" \
  || fail "start does not resume the supervisor"
grep -qE 'building the binaries|would run on .*docker (build|commit)' <<<"$out" \
  && fail "start built something instead of only starting the service"
grep -q 'creating the Pod' <<<"$out" && fail "start created a Pod"

run_capture out "$DEPLOY" -n stop
grep -q 'touch.*/root/taa/manual' <<<"$out" \
  || fail "stop does not pause the supervisor"
grep -qE 'building the binaries|would run on .*docker (build|commit)' <<<"$out" \
  && fail "stop built something instead of only stopping the service"
grep -q 'deleting the Pod this deployment created' <<<"$out" && fail "stop deleted the Pod"

# ── --pod adopts an existing Pod; create and delete refuse it ─────────────────
rc=0
run_capture out env "${CREATE_ENV[@]}" "$DEPLOY" -n create --pod taa-env-slim-v2 || rc=$?
[[ "$rc" -ne 0 ]] || fail "create accepted --pod"
grep -q 'update --pod taa-env-slim-v2' <<<"$out" \
  || fail "create --pod did not point at update as the way in"

rc=0
run_capture out "$DEPLOY" -n delete --pod taa-env-slim-v2 || rc=$?
[[ "$rc" -ne 0 ]] || fail "delete accepted --pod"
grep -q 'delete only removes the Pod this deployment created' <<<"$out" \
  || fail "delete --pod did not explain why it refuses"

rc=0
run_capture out "$DEPLOY" -n --target container --pod taa-env-slim-v2 || rc=$?
[[ "$rc" -ne 0 ]] || fail "--target container accepted --pod"
grep -q 'which --target container cannot deploy into' <<<"$out" \
  || fail "--target container --pod did not explain the conflict"

rc=0
run_capture out "$DEPLOY" -n save --pod taa-env-slim-v2 || rc=$?
[[ "$rc" -ne 0 ]] || fail "save accepted --pod"

# ── the docker container is a target of its own ───────────────────────────────
run_capture out env "${CREATE_ENV[@]}" "$DEPLOY" -n --target container
grep -q 'docker create --name' <<<"$out" || fail "--target container did not take the container path"
grep -qE 'kubectl|creating the Pod' <<<"$out" \
  && fail "--target container still touched the cluster"

rc=0
run_capture out "$DEPLOY" -n --target local || rc=$?
[[ "$rc" -ne 0 ]] || fail "an unknown --target value was accepted"

# ── the help matches what the script does ────────────────────────────────────
run_capture help "$DEPLOY" --help
for word in create update start stop probe delete save; do
  grep -qE "^  $word( |\$|\()" <<<"$help" \
    || fail "deploy-fhe.sh --help does not document the '$word' action"
done
grep -q -- '--target pod|container' <<<"$help" \
  || fail "deploy-fhe.sh --help does not document --target"
grep -q 'Usage: deploy-fhe.sh \[create|update|start|stop|probe|delete|save\]' <<<"$help" \
  || fail "deploy-fhe.sh --help does not lead with the action list"

# ── a Pod existence check must actually run the command it quotes ────────────
# A redirect written inside "$(shell_quote ...)" is applied to the local
# shell_quote call, not to the command handed to ssh: the remote command becomes
# empty, ssh exits 0, and every existence check answers "yes". That made create
# report an absent Pod as existing and then fail with "cannot read Pod".
if grep -qE 'host_sh "\$\(shell_quote [^)]*>/dev/null' "$DEPLOY"; then
  fail "a redirect sits inside the shell_quote substitution, so the remote Pod check would always succeed"
fi

# The manifest is piped into kubectl, so that one remote call has to keep stdin:
# REMOTE_SSH carries -n, and with it the manifest never leaves this host.
grep -q 'host_sh_stdin "$(shell_quote "${POD_KCTL\[@\]}" create -f -)"' "$DEPLOY" \
  || fail "the Pod manifest is no longer piped through host_sh_stdin"

echo "PASS: deploy-fhe.sh defaults to create, keeps start and stop a switch, refuses --pod on create/delete and offers the container path only through --target"
