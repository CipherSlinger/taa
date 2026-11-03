#!/usr/bin/env bash
# Verifies the deployment-owned TAA Pod path: when TARGET_POD is unset, `deploy.sh remote taa`
# creates a Kata CSV2 Pod on the remote host, reuses it on later runs, and deletes it on stop.
# When TARGET_POD is set, the deployment never creates or deletes a Pod.
#
# The traps this test guards are not visible in a successful deployment, so each one gets a
# negative control:
#
#   * a second run must not create a second Pod -- a second confidential VM is tens of GiB of
#     host-resident encrypted memory, and recreating an existing Pod also throws away the guest's
#     writable layer;
#   * an explicitly named Pod that does not exist must fail rather than silently create one the
#     operator did not ask for;
#   * a Pod without /dev/csv-guest must fail the deploy, since TAA would then attest without a
#     hardware device and nothing in the flow would say so;
#   * stop must delete a Pod the deployment created, and must not delete an operator's Pod.
#
# The script runs from a throwaway repository root, which keeps the whole test independent of the
# real checkout, its build products and the semgrep payload.
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
export MOCK_LOG MOCK_REMOTE_ROOT MOCK_STATE_DIR
mkdir -p "$MOCK_BIN" "$MOCK_REMOTE_ROOT/root/taa" "$MOCK_STATE_DIR"
: > "$MOCK_LOG"

# ── Mocks ────────────────────────────────────────────────────────────────────

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

# kubectl, standing in for the cluster. The Pod lives in $MOCK_STATE_DIR: `create` makes it and
# keeps the manifest it was handed, which is how the test inspects what would have been submitted.
# The device node is a separate flag, so a Pod can exist and be Ready while lacking the one thing
# that makes it useful.
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
  get)
    if [[ "$*" == *"-A"* ]]; then echo "DERIVED_CC_INIT_DATA"; exit 0; fi
    [[ -f "$MOCK_STATE_DIR/pod" ]] && exit 0 || exit 1
    ;;
  wait)
    [[ -f "$MOCK_STATE_DIR/pod" ]] && exit 0 || exit 1
    ;;
  create)
    if [[ -f "$MOCK_STATE_DIR/pod" ]]; then
      echo "Error from server (AlreadyExists): pods \"${*##* }\"" >&2
      exit 1
    fi
    cat > "$MOCK_STATE_DIR/applied.yaml"
    echo "$(( $(cat "$MOCK_STATE_DIR/apply-count" 2>/dev/null || echo 0) + 1 ))" > "$MOCK_STATE_DIR/apply-count"
    touch "$MOCK_STATE_DIR/pod"
    exit 0
    ;;
  describe) exit 0 ;;
  delete)
    rm -f "$MOCK_STATE_DIR/pod"
    exit 0
    ;;
  cp) exit 0 ;;
  exec)
    # A Pod that is Pending or wedged cannot be exec'd into. stop must still delete the Pod.
    [[ -f "$MOCK_STATE_DIR/exec_fails" ]] && exit 1
    # Matched against the whole command, not its last word: `tail -n 200 <log>` ends in the log
    # path, and the readiness probe ends in its URL.
    case "$*" in
      *"/dev/csv-guest"*) [[ -f "$MOCK_STATE_DIR/csv_device" ]] && exit 0 || exit 1 ;;
      *"PLATFORM_IP"*"DOCKER_ID"*) exit 0 ;;
      *"pgrep -x taa"*) exit 1 ;;
      *"manual"*|*"pkill"*|*"chmod"*|*"ls -l"*) exit 0 ;;
      *"tail -n"*) echo "2026-11-03T10:00:00Z taa service listening on :6001"; exit 0 ;;
      *"/dev/tcp/"*) exit 0 ;;
      *) exit 0 ;;
    esac
    ;;
  *) exit 0 ;;
esac
MOCK

chmod +x "$MOCK_BIN"/*

# ── Throwaway repository root ────────────────────────────────────────────────

POD_NAME="taa-deploy"
DEFAULT_IMAGE="172.16.10.178:31313/taa-env:slim-v2"

REPO="$TMP_DIR/repo"
mkdir -p "$REPO/deploy/manifest/k8s" "$REPO/configs" "$REPO/cmd/taa"

cp "$ROOT_DIR/deploy.sh" "$REPO/deploy.sh"
cp "$ROOT_DIR/deploy/manifest/k8s/taa-pod.yaml.tmpl" "$REPO/deploy/manifest/k8s/"
cp "$ROOT_DIR/deploy/taa-supervisor.sh" "$REPO/deploy/taa-supervisor.sh"
cp "$ROOT_DIR/configs/taa-production.json" "$REPO/configs/taa-production.json"
chmod +x "$REPO/deploy.sh" "$REPO/deploy/taa-supervisor.sh"

# A stub daemon keeps the test independent of the real build graph.
printf 'module taa-fake\n\ngo 1.22\n' > "$REPO/go.mod"
printf 'package main\n\nfunc main() {}\n' > "$REPO/cmd/taa/main.go"

# ── Runner ───────────────────────────────────────────────────────────────────

output=""
status=0
RUN_ENV=()
run_deploy() {
  set +e
  # TAA_POD_IMAGE is pinned so the lifecycle cases do not build and push a production image;
  # the auto-build path is exercised against the real registry, not by this mock harness.
  output="$(PATH="$MOCK_BIN:$PATH" env -u TARGET_POD -u TAA_POD_NAME -u TAA_POD_IMAGE \
    TAA_POD_IMAGE="$DEFAULT_IMAGE" \
    "${RUN_ENV[@]}" \
    READY_TIMEOUT=2 \
    READY_INTERVAL=1 \
    TAA_POD_READY_TIMEOUT=5 \
    TAA_SCAN_ENGINE_PROVISION=skip \
    timeout 300 "$REPO/deploy.sh" "$@" 2>&1)"
  status=$?
  set -e
}

fail() {
  echo "FAIL: $1" >&2
  echo "$output" >&2
  exit 1
}

kubectl_lines() { grep -c '^KUBECTL ' "$MOCK_LOG" || true; }

# ── 1. First run: TARGET_POD unset, the Pod does not exist yet ──────────────

rm -f "$MOCK_STATE_DIR/applied.yaml" "$MOCK_STATE_DIR/apply-count"
touch "$MOCK_STATE_DIR/csv_device"

run_deploy taa start
[[ $status -eq 0 ]] || fail "taa start exited $status"

[[ "$(cat "$MOCK_STATE_DIR/apply-count" 2>/dev/null || echo 0)" == "1" ]] \
  || fail "the Pod was applied $(cat "$MOCK_STATE_DIR/apply-count" 2>/dev/null || echo 0) times, expected exactly one"

APPLIED="$MOCK_STATE_DIR/applied.yaml"
[[ -f "$APPLIED" ]] || fail "no manifest was submitted"
grep -q "^  name: $POD_NAME$" "$APPLIED" || fail "the manifest does not name the deployment-owned Pod"
grep -q "^  namespace: osr$" "$APPLIED" || fail "the manifest does not set the namespace"
grep -q "^  runtimeClassName: kata-qemu-csv2$" "$APPLIED" \
  || fail "the manifest does not use the CSV2 RuntimeClass that creates /dev/csv-guest"
grep -q "^  nodeName: hygon-master$" "$APPLIED" || fail "the manifest is not pinned to the node"
grep -q "^  restartPolicy: Always$" "$APPLIED" \
  || fail "the manifest does not keep the Pod restartable in place"
grep -q "^      image: $DEFAULT_IMAGE$" "$APPLIED" \
  || fail "the manifest does not use the default TAA image"
# An explicitly pinned image is not rebuilt, so it keeps the cheaper IfNotPresent policy.
grep -q "^      imagePullPolicy: IfNotPresent$" "$APPLIED" \
  || fail "a pinned image does not keep IfNotPresent"
# cc_init_data is required for the guest's CDH to pull the image; kernel_params must be non-empty
# so it is appended rather than erasing the guest's rdinit=; the runtime-handler key is never
# copied because it hijacks runtime selection away from runtimeClassName.
grep -q 'cc_init_data: DERIVED_CC_INIT_DATA$' "$APPLIED" \
  || fail "the cc_init_data annotation was not derived and injected"
grep -qE '^    io\.katacontainers\.config\.hypervisor\.kernel_params: "agent\.cdh_api_timeout=1200 agent\.image_pull_timeout=3600"$' "$APPLIED" \
  || fail "the non-empty cdh/image-pull kernel parameters are missing"
if grep -qE '^    io\.containerd\.cri\.runtime-handler:' "$APPLIED"; then
  fail "the manifest sets the runtime-handler annotation, which overrides runtimeClassName"
fi
annotation_keys="$(grep -cE '^    io\.' "$APPLIED")"
[[ "$annotation_keys" == "2" ]] || fail "expected exactly 2 annotation keys, found $annotation_keys"

# The device node is created inside the container, not by the guest.
grep -q "mknod /dev/csv-guest" "$APPLIED" || fail "the manifest does not create /dev/csv-guest"
grep -q "/sys/class/misc/csv-guest/dev" "$APPLIED" \
  || fail "the manifest does not read the csv-guest device numbers from sysfs"

# The remote config path strips the platform block, so identity has to arrive through the env or
# the deployment fails its own identity gate.
grep -q 'name: DOCKER_ID' "$APPLIED" || fail "the Pod environment does not carry DOCKER_ID"
grep -q "value: \"$POD_NAME\"" "$APPLIED" || fail "DOCKER_ID does not default to the Pod name"
grep -q 'name: PLATFORM_IP' "$APPLIED" || fail "the Pod environment does not carry PLATFORM_IP"
grep -q 'value: "172.16.10.178:18080"' "$APPLIED" || fail "PLATFORM_IP is not the configured platform address"
# Requests must equal limits: CSV2 memory is resident from boot, so an overcommit is a permanent
# host cost, not a burst.
cpu_limits="$(grep -cE '^          cpu: "' "$APPLIED")"
memory_limits="$(grep -cE '^          memory: "' "$APPLIED")"
[[ "$cpu_limits" == "2" && "$memory_limits" == "2" ]] \
  || fail "expected CPU and memory on both limits and requests"

grep -q "TAA Pod created and Ready: $POD_NAME" <<<"$output" \
  || fail "the Pod creation was not reported"
grep -q "taa service listening on" <<<"$output" \
  || fail "the deployment did not confirm the daemon's startup line"

# ── 2. Second run: the Pod exists and is reused ─────────────────────────────

run_deploy taa start
[[ $status -eq 0 ]] || fail "the second run exited $status"
[[ "$(cat "$MOCK_STATE_DIR/apply-count")" == "1" ]] \
  || fail "the second run applied the manifest again instead of reusing the Pod"
grep -q "remote target pod verified: $POD_NAME" <<<"$output" \
  || fail "the second run did not report the reused Pod"

# ── 3. Negative control: an explicitly named Pod that does not exist ────────

rm -f "$MOCK_STATE_DIR/pod" "$MOCK_STATE_DIR/apply-count"
before="$(wc -l < "$MOCK_LOG")"
set +e
output="$(PATH="$MOCK_BIN:$PATH" TARGET_POD=operator-pod \
  READY_TIMEOUT=2 READY_INTERVAL=1 TAA_SCAN_ENGINE_PROVISION=skip \
  timeout 300 "$REPO/deploy.sh" taa start 2>&1)"
status=$?
set -e
[[ $status -ne 0 ]] || fail "a missing explicitly named Pod was accepted"
grep -q "target pod 'operator-pod' not found" <<<"$output" || fail "the missing Pod was not named"
tail -n +"$((before + 1))" "$MOCK_LOG" > "$TMP_DIR/explicit-missing.log"
if grep -q "KUBECTL create" "$TMP_DIR/explicit-missing.log"; then
  fail "an explicit TARGET_POD still created a Pod instead of failing"
fi

# ── 4. Negative control: a Pod without /dev/csv-guest ───────────────────────

rm -f "$MOCK_STATE_DIR/pod" "$MOCK_STATE_DIR/apply-count" "$MOCK_STATE_DIR/csv_device"
run_deploy taa start
[[ $status -ne 0 ]] || fail "a Pod without /dev/csv-guest was accepted"
grep -q "/dev/csv-guest" <<<"$output" || fail "the missing device was not named in the error"
touch "$MOCK_STATE_DIR/csv_device"

# ── 5. stop deletes the deployment-owned Pod ────────────────────────────────

rm -f "$MOCK_STATE_DIR/pod" "$MOCK_STATE_DIR/apply-count"
run_deploy taa start
[[ $status -eq 0 ]] || fail "the setup run for stop exited $status"
before="$(wc -l < "$MOCK_LOG")"
run_deploy taa stop
[[ $status -eq 0 ]] || fail "stop exited $status"
[[ -f "$MOCK_STATE_DIR/pod" ]] && fail "the deployment-owned Pod survived stop"
tail -n +"$((before + 1))" "$MOCK_LOG" > "$TMP_DIR/stop.log"
grep -q "KUBECTL delete pod $POD_NAME" "$TMP_DIR/stop.log" \
  || fail "stop did not delete the deployment-owned Pod"
grep -q "TAA Pod '$POD_NAME' deleted" <<<"$output" || fail "the deletion was not reported"

# ── 6. stop leaves an explicitly named Pod in place ─────────────────────────

rm -f "$MOCK_STATE_DIR/pod" "$MOCK_STATE_DIR/apply-count"
run_deploy taa start
[[ $status -eq 0 ]] || fail "the setup run for the explicit stop exited $status"
before="$(wc -l < "$MOCK_LOG")"
set +e
output="$(PATH="$MOCK_BIN:$PATH" TARGET_POD="$POD_NAME" \
  READY_TIMEOUT=2 READY_INTERVAL=1 TAA_SCAN_ENGINE_PROVISION=skip \
  timeout 300 "$REPO/deploy.sh" taa stop 2>&1)"
status=$?
set -e
[[ $status -eq 0 ]] || fail "stop with an explicit TARGET_POD exited $status"
[[ -f "$MOCK_STATE_DIR/pod" ]] || fail "stop deleted an explicitly named Pod"
tail -n +"$((before + 1))" "$MOCK_LOG" > "$TMP_DIR/stop-explicit.log"
if grep -q "KUBECTL delete" "$TMP_DIR/stop-explicit.log"; then
  fail "stop deleted an explicitly named Pod"
fi

# ── 7. stop still deletes an owned Pod it cannot exec into ──────────────────
#
# A Pending or wedged Pod cannot be exec'd into, but its guest memory is host-resident: refusing
# to delete it because the kill failed would leave tens of GiB behind.

rm -f "$MOCK_STATE_DIR/pod" "$MOCK_STATE_DIR/apply-count" "$MOCK_STATE_DIR/exec_fails"
run_deploy taa start
[[ $status -eq 0 ]] || fail "the setup run for the wedged stop exited $status"
touch "$MOCK_STATE_DIR/exec_fails"
before="$(wc -l < "$MOCK_LOG")"
run_deploy taa stop
[[ $status -eq 0 ]] || fail "stop on a Pod it cannot exec into exited $status"
[[ -f "$MOCK_STATE_DIR/pod" ]] && fail "an owned Pod survived stop only because exec failed"
tail -n +"$((before + 1))" "$MOCK_LOG" > "$TMP_DIR/stop-wedged.log"
grep -q "KUBECTL delete pod $POD_NAME" "$TMP_DIR/stop-wedged.log" \
  || fail "stop did not delete an owned Pod it could not exec into"
rm -f "$MOCK_STATE_DIR/exec_fails"

echo "PASS: TAA Pod creation, reuse, device gate and stop-deletion behave as specified"
