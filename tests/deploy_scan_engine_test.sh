#!/usr/bin/env bash
# Verifies that a remote taa deploy provisions the code scan engine before it disturbs the
# running daemon. The engine is fail-closed: the kata pod image ships neither the semgrep CLI nor
# any rules, so an unprovisioned pod turns every deploy into a startup FATAL and a 10s restart
# loop that only shows up as a readiness timeout. The mock kubectl below keeps the pod's state in
# files, so the probe really changes its answer once an archive has been extracted.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

for tool in go python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "SKIP: $tool is required to run the deploy script"
    exit 0
  fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

MOCK_BIN="$TMP_DIR/bin"
MOCK_LOG="$TMP_DIR/commands.log"
MOCK_REMOTE_ROOT="$TMP_DIR/remote"
MOCK_STATE_DIR="$TMP_DIR/pod-state"
mkdir -p "$MOCK_BIN" "$MOCK_REMOTE_ROOT/root/taa" "$MOCK_STATE_DIR"
: > "$MOCK_LOG"
export MOCK_LOG MOCK_REMOTE_ROOT MOCK_STATE_DIR

# sshpass -p <password> <command...>
cat > "$MOCK_BIN/sshpass" <<'MOCK'
#!/usr/bin/env bash
if [[ "${1:-}" == "-p" ]]; then shift 2; fi
exec "$@"
MOCK

# ssh <options> user@host <command>: run the remote command locally, with paths under /root/taa
# redirected into the mock remote root so no root privileges are needed.
cat > "$MOCK_BIN/ssh" <<'MOCK'
#!/usr/bin/env bash
args=("$@"); i=0
while [[ $i -lt ${#args[@]} ]]; do
  case "${args[$i]}" in
    -o) i=$((i+2)); continue ;;
    -*) i=$((i+1)); continue ;;
    *) break ;;
  esac
done
host="${args[$i]}"; i=$((i+1))
cmd="${args[$i]}"
cmd="${cmd//\/root\/taa/$MOCK_REMOTE_ROOT\/root\/taa}"
echo "SSH[$host] $cmd" >> "$MOCK_LOG"
exec sh -c "$cmd"
MOCK

# scp <options> <src> user@host:<path>: copy into the mock remote root.
cat > "$MOCK_BIN/scp" <<'MOCK'
#!/usr/bin/env bash
args=("$@"); i=0
while [[ $i -lt ${#args[@]} ]]; do
  case "${args[$i]}" in
    -o) i=$((i+2)); continue ;;
    -*) i=$((i+1)); continue ;;
    *) break ;;
  esac
done
src="${args[$i]}"; dest="${args[$((i+1))]}"
path="${dest#*:}"
path="${path//\/root\/taa/$MOCK_REMOTE_ROOT\/root\/taa}"
echo "SCP[$src -> $path]" >> "$MOCK_LOG"
mkdir -p "$(dirname "$path")"
cp "$src" "$path"
MOCK

# kubectl, standing in for the cluster. The pod's contents are $MOCK_STATE_DIR: an extraction
# creates the corresponding file, which is what makes the engine probe answer differently on the
# next round. Streamed archives are drained so the writer never sees a broken pipe, and their
# byte count is logged -- a stream that carried nothing would otherwise look like a success.
cat > "$MOCK_BIN/kubectl" <<'MOCK'
#!/usr/bin/env bash
args=("$@"); i=0
while [[ $i -lt ${#args[@]} ]]; do
  case "${args[$i]}" in
    -n) i=$((i+2)); continue ;;
    *) break ;;
  esac
done
verb="${args[$i]}"
echo "KUBECTL $verb ${args[*]:$((i+1))}" >> "$MOCK_LOG"
case "$verb" in
  get) exit 0 ;;
  cp) exit 0 ;;
  exec)
    script="${args[${#args[@]}-1]}"
    case "$script" in
      *engine=*)
        e=no; r=no
        [[ -f "$MOCK_STATE_DIR/engine" ]] && e=yes
        [[ -f "$MOCK_STATE_DIR/rules" ]] && r=yes
        echo "engine=$e rules=$r"
        ;;
      *"tar -xzf"*)
        echo "STREAM bytes=$(cat | wc -c) :: $script" >> "$MOCK_LOG"
        case "$script" in
          *"-C /opt/taa/semgrep"*) touch "$MOCK_STATE_DIR/rules" ;;
          *) touch "$MOCK_STATE_DIR/engine" ;;
        esac
        ;;
      *"semgrep scan"*)
        # The remote script prints one line: "OK findings=<n> scanned=<n> version=<v>", or
        # "FAIL ..." with semgrep's own words when the engine cannot run. A pod whose semgrep
        # blocks or fails reports that here rather than hanging, so the mock can too.
        if [[ -f "$MOCK_STATE_DIR/verify_fails" ]]; then
          echo "FAIL rc=2 Failed to find semgrep-core in PATH or in the semgrep package version=unknown"
        else
          echo "OK findings=1 scanned=1 version=1.177.0"
        fi
        ;;
      *) ;;
    esac
    exit 0
    ;;
  *) exit 0 ;;
esac
MOCK

chmod +x "$MOCK_BIN"/*

# A stand-in for the payload archive on the remote host. Only its transfer is under test, so a few
# bytes are enough; the mock extracts nothing.
BUNDLE="$MOCK_REMOTE_ROOT/root/taa/semgrep-bundle.tar.gz"
printf 'not-a-real-payload\n' > "$BUNDLE"

# Runs one deploy and echoes its combined output. TAA_KEEP_MANUAL keeps the run out of the
# readiness wait, which is not what this test is about, and the run-time paths that would land in
# the shared checkout are redirected into the temporary directory.
run_deploy() {
  set +e
  output="$(PATH="$MOCK_BIN:$PATH" \
    TARGET_POD=mock-taa-pod \
    TAA_KEEP_MANUAL=true \
    TAA_BINARY_PATH="$TMP_DIR/bin/taa" \
    REMOTE_TAA_CONFIG_SOURCE="$TMP_DIR/remote-taa-config.json" \
    LOCAL_RUN_DIR="$TMP_DIR/run" \
    timeout 300 "$ROOT_DIR/deploy.sh" remote taa 2>&1)"
  status=$?
  set -e
}

fail() {
  echo "FAIL: $1" >&2
  echo "$output" >&2
  exit 1
}

# ── Scenario A: the pod is already provisioned ───────────────────────────────
touch "$MOCK_STATE_DIR/engine" "$MOCK_STATE_DIR/rules"
run_deploy
[[ $status -eq 0 ]] || fail "deploy exited $status with an already-provisioned pod"
grep -q "code scan engine already provisioned inside container" <<<"$output" \
  || fail "an already-provisioned engine was not detected"
# Provisioned is not verified: the check runs on every deploy, and this is the case that must not
# silently skip it, because a pod can hold an engine that cannot run.
grep -q "code scan engine ready inside container: semgrep 1.177.0" <<<"$output" \
  || fail "a redeploy onto a provisioned pod skipped the engine verification"
grep -q "STREAM" "$MOCK_LOG" && fail "an archive was streamed into a pod that already had the engine"
rm -f "$MOCK_STATE_DIR/engine" "$MOCK_STATE_DIR/rules"

# ── Scenario B: the pod has neither the engine nor the rules ─────────────────
: > "$MOCK_LOG"
run_deploy
[[ $status -eq 0 ]] || fail "deploy exited $status while provisioning a bare pod"

grep -q "STREAM bytes=[1-9][0-9]* :: tar -xzf - -C /$" "$MOCK_LOG" \
  || fail "the semgrep payload was not streamed into the container (or carried no bytes)"
grep -q "installing semgrep into the container from /root/taa/semgrep-bundle.tar.gz" <<<"$output" \
  || fail "the payload injection was not reported"
grep -q "STREAM bytes=[1-9][0-9]* :: mkdir -p /opt/taa/semgrep .* -C /opt/taa/semgrep$" "$MOCK_LOG" \
  || fail "the code scan rules were not streamed to the configured rules path"
grep -q "code scan engine ready inside container: semgrep 1.177.0 (rules: /opt/taa/semgrep/rules)" <<<"$output" \
  || fail "the provisioned engine was not verified against the rules path"

# The engine has to land before the rules: the verification scans with the CLI the payload brings,
# so a rules-first order would only be provable by accident on a slower host.
engine_line="$(grep -n 'STREAM.*-C /$' "$MOCK_LOG" | head -n 1 | cut -d: -f1)"
rules_line="$(grep -n 'STREAM.*-C /opt/taa/semgrep$' "$MOCK_LOG" | head -n 1 | cut -d: -f1)"
[[ -n "$engine_line" && -n "$rules_line" && "$engine_line" -lt "$rules_line" ]] \
  || fail "the rules were streamed before the engine payload (engine=$engine_line rules=$rules_line)"

# ── Scenario C: no payload anywhere ──────────────────────────────────────────
rm -f "$MOCK_STATE_DIR/engine" "$MOCK_STATE_DIR/rules" "$BUNDLE"
: > "$MOCK_LOG"
run_deploy
[[ $status -ne 0 ]] || fail "deploy succeeded without a semgrep payload to install"
grep -q "semgrep payload bundle not found" <<<"$output" \
  || fail "a missing payload did not fail with an actionable message"
grep -q "build-semgrep-payload-container.sh" <<<"$output" \
  || fail "the failure did not name the recipe that produces the payload"
grep -q "pausing old taa inside container" <<<"$output" \
  && fail "the deploy disturbed the running taa before it knew it could provision the engine"

# ── Scenario D: the payload installs but the engine cannot run ───────────────
# The failure this pins down is the one a network-isolated container produces: semgrep starts and
# then blocks on its own update check, so the check has to fail with an explanation rather than
# wait, and the daemon must not have been replaced by then.
rm -f "$MOCK_STATE_DIR/engine" "$MOCK_STATE_DIR/rules"
printf 'not-a-real-payload\n' > "$BUNDLE"
touch "$MOCK_STATE_DIR/verify_fails"
: > "$MOCK_LOG"
run_deploy
[[ $status -ne 0 ]] || fail "deploy succeeded although the engine could not be verified"
grep -q "code scan engine verification failed inside the container" <<<"$output" \
  || fail "a failing engine verification did not fail the deploy"
grep -q "Failed to find semgrep-core" <<<"$output" \
  || fail "semgrep's own output was discarded instead of being reported"
grep -q "offline and bounded" <<<"$output" \
  || fail "the verification failure did not explain the offline bound"
grep -q "pausing old taa inside container" <<<"$output" \
  && fail "the deploy replaced the running taa with an engine it could not verify"
rm -f "$MOCK_STATE_DIR/verify_fails"

echo "PASS: remote taa deploys provision the code scan engine before touching the running daemon"
