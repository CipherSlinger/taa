#!/usr/bin/env bash
# Verifies the deployment-owned TAA Pod path: without --pod, `deploy.sh create` creates a Kata
# CSV2 Pod on the remote host, later runs reuse and verify it, and `delete` removes it. When --pod
# names a Pod, the deployment never creates or deletes a Pod.
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
#   * delete must remove a Pod the deployment created, and must refuse an operator's Pod;
#   * stop only stops the daemon and never removes the Pod.
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
# The rest is the command, exactly as ssh joins it: deploy.sh passes positional arguments
# (`bash -s -- <path>`) as separate argv entries, and dropping them would make those paths
# disappear only in the mock.
cmd="${args[*]:$i}"
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
    if [[ "$*" == *"-A"* ]]; then
      # A host with no CoCo Pod answers with nothing; the flag makes that state reachable while
      # the other cases keep the simpler "a Pod carries the annotation" behaviour.
      [[ -f "$MOCK_STATE_DIR/no_cc_init_data" ]] && exit 0
      echo "DERIVED_CC_INIT_DATA"; exit 0
    fi
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
      # /dev/tcp is bash-only and the image's /bin/sh is dash, where the same
      # probe fails however healthy the daemon is. Mirror that here so a probe
      # that regresses to sh cannot pass this suite.
      *"/dev/tcp/"*) case "$*" in *"bash -c"*) exit 0 ;; *) exit 1 ;; esac ;;
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
# A syntactically valid platform SM2 public key (04 || X || Y). The value is not used for crypto
# here; what is pinned is that it reaches the Pod environment, since TAA refuses to start without
# it and the remote config path has no platform block to carry it.
TEST_PLATFORM_KEY="04$(printf 'ab%.0s' {1..64})"
# The deployment reads the key off the host when it is not exported, so the fixture stands in for
# the platform-mock's state directory (its default state dir is the remote deployment directory).
printf '{\n  "privateKeyPem": "not-a-real-key",\n  "publicKeyHex": "%s"\n}\n' "$TEST_PLATFORM_KEY" \
  > "$MOCK_REMOTE_ROOT/root/taa/platform-key.json"

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
  # --image is pinned so the lifecycle cases do not build and push a production image;
  # the auto-build path is exercised against the real registry, not by this mock harness. The
  # platform key is deliberately not exported: it is read from the host, which is the path a real
  # operator takes, and every case here would otherwise stop proving that.
  output="$(PATH="$MOCK_BIN:$PATH" env -u TARGET_POD -u TAA_POD_NAME -u TAA_IMAGE \
    -u PLATFORM_PUBLIC_KEY -u TAA_POD_PLATFORM_PUBLIC_KEY -u TAA_POD_CC_INIT_DATA \
    "${RUN_ENV[@]}" \
    TAA_READY_TIMEOUT=2 \
    TAA_READY_INTERVAL=1 \
    TAA_POD_TAA_READY_TIMEOUT=5 \
    TAA_SCAN_ENGINE_PROVISION=skip \
    timeout 300 "$REPO/deploy.sh" --image "$DEFAULT_IMAGE" "$@" 2>&1)"
  status=$?
  set -e
}

fail() {
  echo "FAIL: $1" >&2
  echo "$output" >&2
  exit 1
}

kubectl_lines() { grep -c '^KUBECTL ' "$MOCK_LOG" || true; }

# ── 0. create and delete only ever act on the Pod this deployment owns ──────
#
# --pod says "use this Pod, do not touch its lifecycle", so pairing it with the two actions that
# change which Pods exist is refused before anything reaches the host.

for action in create delete; do
  set +e
  output="$(PATH="$MOCK_BIN:$PATH" timeout 60 "$REPO/deploy.sh" "$action" --pod operator-pod 2>&1)"
  status=$?
  set -e
  [[ $status -ne 0 ]] || fail "$action accepted --pod"
  grep -q "cannot be combined with --pod\|delete only removes the Pod this deployment created" \
    <<<"$output" || fail "$action --pod was refused without saying why"
done
[[ "$(kubectl_lines)" == "0" ]] || fail "a refused create/delete still reached the cluster"

# ── 1. First run: --pod not given, the Pod does not exist yet ────────────────
#
# No action argument: create is the default, so a bare invocation is the one-shot deployment.

rm -f "$MOCK_STATE_DIR/applied.yaml" "$MOCK_STATE_DIR/apply-count"
touch "$MOCK_STATE_DIR/csv_device"

run_deploy
[[ $status -eq 0 ]] || fail "the default action (create) exited $status"

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
grep -q 'name: PLATFORM_PUBLIC_KEY' "$APPLIED" \
  || fail "the Pod environment does not carry PLATFORM_PUBLIC_KEY"
grep -q "value: \"$TEST_PLATFORM_KEY\"" "$APPLIED" \
  || fail "the platform public key did not reach the Pod environment"
grep -q "platform public key read from" <<<"$output" \
  || fail "the platform public key was not read from the host when it was not exported"
# The role is part of the Pod environment, not the config: TAA resolves data analysis's landing
# directory and audit switches from it alone.
grep -q 'name: CONTRACT_TYPE' "$APPLIED" || fail "the Pod environment does not carry CONTRACT_TYPE"
grep -q 'value: "1"' "$APPLIED" || fail "CONTRACT_TYPE does not default to the tee role"
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

run_deploy create
[[ $status -eq 0 ]] || fail "the second run exited $status"
[[ "$(cat "$MOCK_STATE_DIR/apply-count")" == "1" ]] \
  || fail "the second run applied the manifest again instead of reusing the Pod"
grep -q "already exists; verifying it instead of creating a second one" <<<"$output" \
  || fail "the second run did not report the reused Pod"

# ── 2b. Reuse is refused when the existing Pod runs another role ────────────
#
# The role lives in the Pod environment, which cannot be changed in place. Reusing a tee Pod for a
# data-analysis deployment would install the right files into an instance that still audits like a
# tee, and with the role no longer rendered into the config nothing later in the flow would see it.

RUN_ENV=(TAA_POD_CONTRACT_TYPE=3)
run_deploy create
RUN_ENV=()
[[ $status -ne 0 ]] || fail "a role mismatch was accepted"
grep -q "runs the 'tee' role" <<<"$output" || fail "the role mismatch was not named"
[[ "$(cat "$MOCK_STATE_DIR/apply-count")" == "1" ]] \
  || fail "a role mismatch still applied a manifest"

# ── 3. Negative control: update never creates a Pod --pod names ─────────────

rm -f "$MOCK_STATE_DIR/pod" "$MOCK_STATE_DIR/apply-count"
before="$(wc -l < "$MOCK_LOG")"
set +e
output="$(PATH="$MOCK_BIN:$PATH" \
  TAA_READY_TIMEOUT=2 TAA_READY_INTERVAL=1 TAA_SCAN_ENGINE_PROVISION=skip \
  timeout 300 "$REPO/deploy.sh" update --pod operator-pod 2>&1)"
status=$?
set -e
[[ $status -ne 0 ]] || fail "a missing explicitly named Pod was accepted"
grep -q "TAA Pod 'operator-pod' does not exist" <<<"$output" || fail "the missing Pod was not named"
tail -n +"$((before + 1))" "$MOCK_LOG" > "$TMP_DIR/explicit-missing.log"
if grep -q "KUBECTL create" "$TMP_DIR/explicit-missing.log"; then
  fail "an explicit --pod still created a Pod instead of failing"
fi

# ── 4. Negative control: a Pod without /dev/csv-guest ───────────────────────

rm -f "$MOCK_STATE_DIR/pod" "$MOCK_STATE_DIR/apply-count" "$MOCK_STATE_DIR/csv_device"
run_deploy create
[[ $status -ne 0 ]] || fail "a Pod without /dev/csv-guest was accepted"
grep -q "/dev/csv-guest" <<<"$output" || fail "the missing device was not named in the error"
touch "$MOCK_STATE_DIR/csv_device"

# ── 5. delete removes the deployment-owned Pod ──────────────────────────────

rm -f "$MOCK_STATE_DIR/pod" "$MOCK_STATE_DIR/apply-count"
run_deploy create
[[ $status -eq 0 ]] || fail "the setup run for delete exited $status"
before="$(wc -l < "$MOCK_LOG")"
run_deploy delete
[[ $status -eq 0 ]] || fail "delete exited $status"
[[ -f "$MOCK_STATE_DIR/pod" ]] && fail "the deployment-owned Pod survived delete"
tail -n +"$((before + 1))" "$MOCK_LOG" > "$TMP_DIR/delete.log"
grep -q "KUBECTL delete pod $POD_NAME" "$TMP_DIR/delete.log" \
  || fail "delete did not remove the deployment-owned Pod"
grep -q "TAA Pod '$POD_NAME' deleted" <<<"$output" || fail "the deletion was not reported"

# ── 6. stop leaves the Pod in place; delete refuses an explicitly named Pod ──

rm -f "$MOCK_STATE_DIR/pod" "$MOCK_STATE_DIR/apply-count"
run_deploy create
[[ $status -eq 0 ]] || fail "the setup run for the explicit stop exited $status"
before="$(wc -l < "$MOCK_LOG")"
set +e
output="$(PATH="$MOCK_BIN:$PATH" \
  TAA_READY_TIMEOUT=2 TAA_READY_INTERVAL=1 TAA_SCAN_ENGINE_PROVISION=skip \
  timeout 300 "$REPO/deploy.sh" stop --pod "$POD_NAME" 2>&1)"
status=$?
set -e
[[ $status -eq 0 ]] || fail "stop with an explicit --pod exited $status"
[[ -f "$MOCK_STATE_DIR/pod" ]] || fail "stop removed the Pod instead of only stopping taa"
tail -n +"$((before + 1))" "$MOCK_LOG" > "$TMP_DIR/stop-explicit.log"
if grep -q "KUBECTL delete" "$TMP_DIR/stop-explicit.log"; then
  fail "stop deleted the Pod"
fi

set +e
output="$(PATH="$MOCK_BIN:$PATH" \
  TAA_READY_TIMEOUT=2 TAA_READY_INTERVAL=1 TAA_SCAN_ENGINE_PROVISION=skip \
  timeout 300 "$REPO/deploy.sh" delete --pod "$POD_NAME" 2>&1)"
status=$?
set -e
[[ $status -ne 0 ]] || fail "delete accepted an explicitly named Pod"
grep -q "delete only removes the Pod this deployment created" <<<"$output" \
  || fail "the refusal to delete an operator's Pod was not explained"
[[ -f "$MOCK_STATE_DIR/pod" ]] || fail "delete removed an explicitly named Pod"

# ── 7. delete still removes an owned Pod it cannot exec into ────────────────
#
# A Pending or wedged Pod cannot be exec'd into, but its guest memory is host-resident: refusing
# to delete it because the kill failed would leave tens of GiB behind.

rm -f "$MOCK_STATE_DIR/pod" "$MOCK_STATE_DIR/apply-count" "$MOCK_STATE_DIR/exec_fails"
run_deploy create
[[ $status -eq 0 ]] || fail "the setup run for the wedged delete exited $status"
touch "$MOCK_STATE_DIR/exec_fails"
before="$(wc -l < "$MOCK_LOG")"
run_deploy delete
[[ $status -eq 0 ]] || fail "delete on a Pod it cannot exec into exited $status"
[[ -f "$MOCK_STATE_DIR/pod" ]] && fail "an owned Pod survived delete only because exec failed"
tail -n +"$((before + 1))" "$MOCK_LOG" > "$TMP_DIR/delete-wedged.log"
grep -q "KUBECTL delete pod $POD_NAME" "$TMP_DIR/delete-wedged.log" \
  || fail "delete did not remove an owned Pod it could not exec into"
rm -f "$MOCK_STATE_DIR/exec_fails"

# ── 8. A new Pod is refused before creation without the platform key ─────────
#
# TAA seals every message it sends and exits at startup when the platform's SM2 key is missing,
# and the remote config path has no platform block to carry one. Creating the Pod anyway would
# spend a whole guest boot to reach a crash loop, so the gate has to fire before the manifest.
# Both sources are removed here: the exported variable and the host's key file.

KEY_FILE="$MOCK_REMOTE_ROOT/root/taa/platform-key.json"
mv "$KEY_FILE" "$TMP_DIR/platform-key.json"
rm -f "$MOCK_STATE_DIR/pod" "$MOCK_STATE_DIR/apply-count"
before="$(wc -l < "$MOCK_LOG")"
set +e
output="$(PATH="$MOCK_BIN:$PATH" env -u TARGET_POD -u TAA_POD_NAME -u TAA_IMAGE \
  -u PLATFORM_PUBLIC_KEY -u TAA_POD_PLATFORM_PUBLIC_KEY -u TAA_POD_CC_INIT_DATA \
  TAA_READY_TIMEOUT=2 TAA_READY_INTERVAL=1 TAA_POD_TAA_READY_TIMEOUT=5 \
  TAA_SCAN_ENGINE_PROVISION=skip \
  timeout 300 "$REPO/deploy.sh" --image "$DEFAULT_IMAGE" create 2>&1)"
status=$?
set -e
mv "$TMP_DIR/platform-key.json" "$KEY_FILE"
[[ $status -ne 0 ]] || fail "a new Pod was accepted without PLATFORM_PUBLIC_KEY"
grep -q "PLATFORM_PUBLIC_KEY is not set" <<<"$output" \
  || fail "the missing platform key was not named in the error"
grep -q "/root/taa/platform-key.json" <<<"$output" \
  || fail "the error did not say which key file was looked for"
tail -n +"$((before + 1))" "$MOCK_LOG" > "$TMP_DIR/missing-key.log"
if grep -q "KUBECTL create" "$TMP_DIR/missing-key.log"; then
  fail "a Pod was created without the platform public key"
fi
[[ -f "$MOCK_STATE_DIR/pod" ]] && fail "a Pod exists after the refused creation"

# ── 9. cc_init_data comes from the host's initdata file when nothing carries it ─
#
# The usual source is a running CoCo Pod, but requiring an unrelated Pod to exist just to create
# this one is not a dependency worth having: the vendor initdata file is the same input, and
# compressing it here is what the vendor's own Pod template does.

rm -f "$MOCK_STATE_DIR/pod" "$MOCK_STATE_DIR/apply-count"
touch "$MOCK_STATE_DIR/no_cc_init_data"
printf 'policy.rego = "package agent_policy"\n' > "$TMP_DIR/initdata.v1.toml"
set +e
output="$(PATH="$MOCK_BIN:$PATH" env -u TARGET_POD -u TAA_POD_NAME -u TAA_IMAGE \
  -u PLATFORM_PUBLIC_KEY -u TAA_POD_PLATFORM_PUBLIC_KEY -u TAA_POD_CC_INIT_DATA \
  TAA_POD_INITDATA_FILE="$TMP_DIR/initdata.v1.toml" \
  TAA_READY_TIMEOUT=2 TAA_READY_INTERVAL=1 TAA_POD_TAA_READY_TIMEOUT=5 \
  TAA_SCAN_ENGINE_PROVISION=skip \
  timeout 300 "$REPO/deploy.sh" --image "$DEFAULT_IMAGE" create 2>&1)"
status=$?
set -e
[[ $status -eq 0 ]] || fail "the deployment did not fall back to the initdata file (exit $status)"
expected_blob="$(gzip -c "$TMP_DIR/initdata.v1.toml" | base64 -w0)"
grep -q "cc_init_data: $expected_blob$" "$MOCK_STATE_DIR/applied.yaml" \
  || fail "the cc_init_data annotation was not rendered from the initdata file"
grep -q "cc_init_data rendered from" <<<"$output" \
  || fail "the fallback source was not reported"
rm -f "$MOCK_STATE_DIR/no_cc_init_data"

# ── 10. A malformed platform key is refused before creation ──────────────────
#
# A PEM block, a truncated hex string or a stray quote parses nowhere, and TAA would only say so
# after the guest had booted. The exported value wins over the key file, so the check has to run
# on it rather than trust that the file is the only source.

rm -f "$MOCK_STATE_DIR/pod" "$MOCK_STATE_DIR/apply-count"
before="$(wc -l < "$MOCK_LOG")"
set +e
output="$(PATH="$MOCK_BIN:$PATH" env -u TARGET_POD -u TAA_POD_NAME -u TAA_IMAGE \
  -u TAA_POD_PLATFORM_PUBLIC_KEY -u TAA_POD_CC_INIT_DATA \
  PLATFORM_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----" \
  TAA_READY_TIMEOUT=2 TAA_READY_INTERVAL=1 TAA_POD_TAA_READY_TIMEOUT=5 \
  TAA_SCAN_ENGINE_PROVISION=skip \
  timeout 300 "$REPO/deploy.sh" --image "$DEFAULT_IMAGE" create 2>&1)"
status=$?
set -e
[[ $status -ne 0 ]] || fail "a malformed platform key was accepted"
grep -q "not in the expected wire format" <<<"$output" \
  || fail "the malformed platform key was not named"
tail -n +"$((before + 1))" "$MOCK_LOG" > "$TMP_DIR/bad-key.log"
if grep -q "KUBECTL create" "$TMP_DIR/bad-key.log"; then
  fail "a Pod was created with a malformed platform key"
fi

echo "PASS: TAA Pod creation, reuse, device gate, stop and delete behave as specified"
