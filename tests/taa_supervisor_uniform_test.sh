#!/usr/bin/env bash
# Every role installs exactly one autostart file, at the same path, under the same
# name: /root/taa/taa-supervisor.sh with `bash` as the image ENTRYPOINT. A role that
# needs a sidecar (jupyter for data analysis, /opt/entrypoint.sh for FHE) carries it
# in that file, so the deployment never has to know which role it is looking at.
#
# The TAA restart loop therefore exists three times. The block is delimited so this
# test can prove the copies have not drifted, and the process pattern a deploy uses to
# replace the file is checked to carry --taa-loop: without it, pkill would match PID 1
# (the entrypoint itself) and restart the container instead of the loop.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() { echo "FAIL: $*" >&2; exit 1; }

TEE="$ROOT_DIR/deploy/taa-supervisor.sh"
FHE="$ROOT_DIR/deploy/fhe/taa-supervisor.sh"
DATA="$ROOT_DIR/deploy/dataanaylsis/taa-supervisor.sh"

for f in "$TEE" "$FHE" "$DATA"; do
  [ -f "$f" ] || fail "missing role supervisor: $f"
  bash -n "$f" || fail "syntax error in $f"
done

extract_loop() {
  awk '/^# >>> TAA_LOOP/{on=1} on{print} /^# <<< TAA_LOOP/{exit}' "$1"
}

tee_loop="$(extract_loop "$TEE")"
[ -n "$tee_loop" ] || fail "$TEE has no TAA_LOOP block"
[ "$tee_loop" = "$(extract_loop "$FHE")" ] \
  || fail "the TAA loop in $FHE differs from $TEE"
[ "$tee_loop" = "$(extract_loop "$DATA")" ] \
  || fail "the TAA loop in $DATA differs from $TEE"

# deploy.sh installs the tee supervisor by default and the data-analysis wrapper
# overrides it; both must land on the one container path.
grep -q 'TAA_SUPERVISOR_SOURCE="${TAA_SUPERVISOR_SOURCE:-$PROJECT_DIR/deploy/taa-supervisor.sh}"' "$ROOT_DIR/deploy.sh" \
  || fail "deploy.sh no longer defaults to deploy/taa-supervisor.sh"
grep -q 'TAA_SUPERVISOR_CONTAINER="$TAA_WORKDIR/taa-supervisor.sh"' "$ROOT_DIR/deploy.sh" \
  || fail "deploy.sh no longer installs the supervisor at \$TAA_WORKDIR/taa-supervisor.sh"
grep -q 'deploy/dataanaylsis/taa-supervisor.sh' "$ROOT_DIR/deploy-dataanaylsis.sh" \
  || fail "deploy-dataanaylsis.sh does not select its combined supervisor"

# deploy-fhe.sh uses the same name and the same container path, and no longer
# installs a second, differently named entrypoint.
grep -q 'deploy/fhe/taa-supervisor.sh' "$ROOT_DIR/deploy-fhe.sh" \
  || fail "deploy-fhe.sh no longer packages deploy/fhe/taa-supervisor.sh"
grep -q 'TAA_ENTRYPOINT_CONTAINER="$TAA_WORKDIR/taa-supervisor.sh"' "$ROOT_DIR/deploy-fhe.sh" \
  || fail "deploy-fhe.sh does not install the entrypoint at \$TAA_WORKDIR/taa-supervisor.sh"
if grep -q 'taa-fhe-supervisor' "$ROOT_DIR/deploy-fhe.sh"; then
  fail "deploy-fhe.sh still refers to the old /opt/taa-fhe-supervisor.sh entrypoint"
fi

# Both combined supervisors keep the loop in a child selected by --taa-loop.
for f in "$FHE" "$DATA"; do
  grep -q '"\${1:-}" = "--taa-loop"' "$f" \
    || fail "$f has no --taa-loop branch"
  grep -q 'SELF=' "$f" || fail "$f cannot locate itself to start the loop"
done

# The data-analysis entrypoint starts jupyter with the home its config lives in and
# treats jupyter as the service: if it exits, TAA stops and the container exits.
grep -q 'start-notebook.py' "$DATA" || fail "$DATA does not start jupyter"
grep -q 'HOME="\$JUPYTER_HOME"' "$DATA" || fail "$DATA does not pin HOME for jupyter"
grep -q 'jupyter exited with status' "$DATA" || fail "$DATA does not act on jupyter's exit"
grep -q 'kill -TERM "\$taa_pid"' "$DATA" || fail "$DATA does not stop TAA when jupyter exits"

# The FHE entrypoint still owns the sidecar's liveness.
grep -q '/opt/entrypoint.sh' "$FHE" || fail "$FHE does not start the FHE entrypoint"
grep -q 'FHE entrypoint exited with status' "$FHE" || fail "$FHE does not act on the FHE side's exit"

# An update kills the loop, never PID 1.
grep -q "SUPERVISOR_PATTERN='\[t\]aa-supervisor\[\.\]sh --taa-loop'" "$ROOT_DIR/deploy-fhe.sh" \
  || fail "SUPERVISOR_PATTERN would match the entrypoint itself (PID 1)"

echo "PASS: every role installs one taa-supervisor.sh, the TAA loop is identical in all three, and updates signal only the --taa-loop child"
