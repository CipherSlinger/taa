#!/usr/bin/env bash
# Verifies the dedicated TEE-LLM Pod path (--create-pod / pod-down).
#
# That Pod is what gives teellm-service a real /dev/csv-guest; without the device it serves mock
# evidence and TAA rejects every handshake. The traps this test guards are not visible in a
# successful deployment, so each one gets a negative control:
#
#   * the deployment must never aim at TARGET_POD's default, which is a *TAA* Pod that also has
#     /dev/csv-guest -- every gate would pass while the service landed in the wrong Pod;
#   * a second run must not create a second Pod (a second confidential VM is tens of GiB of
#     host-resident encrypted memory, and a new IP that TAA's endpoint no longer points at);
#   * a Pod without the device must fail the deploy, since the readiness probe cannot tell the
#     difference (its client skips attestation verification);
#   * a deployment with no attestation certificates must fail rather than serve nothing;
#   * an invocation with no action keyword must reach that same Pod path, since the target keyword
#     that used to say so is gone -- a bare run is now the only way to start a deployment.
#
# The script is run from a throwaway repository root, which is what makes the last case reachable
# and keeps the whole test independent of the teellm submodule and of the real ollama bundle.
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
MOCK_POD_IP="10.244.1.77"
export MOCK_LOG MOCK_REMOTE_ROOT MOCK_STATE_DIR MOCK_POD_IP
mkdir -p "$MOCK_BIN" "$MOCK_REMOTE_ROOT/root/teellm" "$MOCK_STATE_DIR"
: > "$MOCK_LOG"

# ── Mocks ────────────────────────────────────────────────────────────────────

# sshpass -p <password> <command...>
cat > "$MOCK_BIN/sshpass" <<'MOCK'
#!/usr/bin/env bash
if [[ "${1:-}" == "-p" ]]; then shift 2; fi
exec "$@"
MOCK

# ssh <options> user@host <command>: run the remote command locally, with paths under /root/teellm
# redirected into the mock remote root so no root privileges are needed. The rsync probe is
# answered "no" so the sync takes the plain tar path instead of driving a real rsync over the
# mock transport.
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
cmd="${cmd//\/root\/teellm/$MOCK_REMOTE_ROOT\/root\/teellm}"
echo "SSH[$host] $cmd" >> "$MOCK_LOG"
case "$cmd" in
  *"command -v rsync"*) exit 1 ;;
esac
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
path="${path//\/root\/teellm/$MOCK_REMOTE_ROOT\/root\/teellm}"
echo "SCP[$src -> $path]" >> "$MOCK_LOG"
mkdir -p "$(dirname "$path")"
cp "$src" "$path"
MOCK

# kubectl, standing in for the cluster. The Pod lives in $MOCK_STATE_DIR: `apply` creates it and
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
    if [[ "$*" == *"status.podIP"* ]]; then printf '%s' "$MOCK_POD_IP"; exit 0; fi
    [[ -f "$MOCK_STATE_DIR/pod" ]] && exit 0 || exit 1
    ;;
  wait)
    [[ -f "$MOCK_STATE_DIR/pod" ]] && exit 0 || exit 1
    ;;
  apply)
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
    # Matched against the whole command, not its last word: `tail -n 200 <log>` ends in the log
    # path, and the readiness probe ends in its URL.
    case "$*" in
      *".teellm-supervisor.pid"*) exit 1 ;;
      *"/dev/csv-guest"*) [[ -f "$MOCK_STATE_DIR/csv_device" ]] && exit 0 || exit 1 ;;
      *"tar -xf"*) cat >/dev/null; exit 0 ;;
      *"/api/tags"*) echo '{"models":[{"name":"qwen2.5-coder:0.5b"}]}'; exit 0 ;;
      *"-probe"*) exit 0 ;;
      *"tail -n"*) echo "2026-10-15T10:00:00Z using Hygon hardware evidence provider (hrk=/opt/teellm/certs/hrk.cert)"; exit 0 ;;
      *) exit 0 ;;
    esac
    ;;
  *) exit 0 ;;
esac
MOCK

chmod +x "$MOCK_BIN"/*

# ── Throwaway repository root ────────────────────────────────────────────────

COPY_POD_NAME="taa-teellm"
DEFAULT_POD_NAME="taa-env-slim-v2-20260916-b2038037072e1052-54f554445c-n2pnv"

REPO="$TMP_DIR/repo"
OLLAMA_DIR="$REPO/teellm/models/ollama"
mkdir -p "$REPO/deploy/manifest/k8s" "$REPO/deploy/certs" \
         "$REPO/teellm/deploy" "$REPO/teellm/configs" "$REPO/teellm/cmd/teellm-service" \
         "$OLLAMA_DIR/lib/ollama" \
         "$OLLAMA_DIR/models/models/blobs" \
         "$OLLAMA_DIR/models/models/manifests/registry.ollama.ai/library/qwen2.5-coder"

cp "$ROOT_DIR/deploy-llm.sh" "$REPO/deploy-llm.sh"
cp "$ROOT_DIR/deploy/manifest/k8s/teellm-pod.yaml.tmpl" "$REPO/deploy/manifest/k8s/"
cp "$ROOT_DIR/deploy/teellm-supervisor.sh" "$REPO/deploy/teellm-supervisor.sh"
chmod +x "$REPO/deploy/teellm-supervisor.sh"
printf 'hrk\n' > "$REPO/deploy/certs/hrk.cert"
printf 'hsk\n' > "$REPO/deploy/certs/hsk_cek.cert"

# The teellm module the deployment builds from. A stub keeps the test independent of the
# submodule, which the deploy script otherwise expects to be checked out next to itself.
printf 'module teellm-fake\n\ngo 1.22\n' > "$REPO/go.mod"
printf 'package main\n\nfunc main() {}\n' > "$REPO/teellm/cmd/teellm-service/main.go"
printf '#!/bin/sh\nexit 0\n' > "$REPO/teellm/deploy/start.sh"
cat > "$REPO/teellm/configs/teellm-production.json" <<'CFG'
{
  "server": { "addr": ":8443" },
  "backend": { "endpoint": "http://127.0.0.1:11434", "defaultModel": "qwen2.5-coder:0.5b" },
  "attestation": { "mode": "permissive" }
}
CFG

# A minimal but self-consistent offline bundle: the deploy script verifies the binary, the
# directories and the model manifest (digests and blob sizes included) before it transfers them.
cat > "$OLLAMA_DIR/ollama" <<'BIN'
#!/bin/sh
echo "ollama version is 0.5.0-fake"
exit 0
BIN
cat > "$OLLAMA_DIR/start-ollama.sh" <<'SH'
#!/bin/sh
exec "$(dirname "$0")/ollama" serve
SH
chmod +x "$OLLAMA_DIR/ollama" "$OLLAMA_DIR/start-ollama.sh"
: > "$OLLAMA_DIR/lib/ollama/libllama-server-impl.so"

CONFIG_DIGEST="$(printf 'a%.0s' {1..64})"
LAYER_DIGEST="$(printf 'b%.0s' {1..64})"
head -c 16 /dev/zero > "$OLLAMA_DIR/models/models/blobs/sha256-$CONFIG_DIGEST"
head -c 32 /dev/zero > "$OLLAMA_DIR/models/models/blobs/sha256-$LAYER_DIGEST"
cat > "$OLLAMA_DIR/models/models/manifests/registry.ollama.ai/library/qwen2.5-coder/0.5b" <<JSON
{
  "config": { "digest": "sha256:$CONFIG_DIGEST", "size": 16 },
  "layers": [ { "digest": "sha256:$LAYER_DIGEST", "size": 32 } ]
}
JSON

# ── Runner ───────────────────────────────────────────────────────────────────

output=""
status=0
run_deploy() {
  set +e
  output="$(PATH="$MOCK_BIN:$PATH" \
    OLLAMA_LOCAL_DIR="${RUN_OLLAMA_DIR:-$OLLAMA_DIR}" \
    OLLAMA_READY_TIMEOUT=2 \
    OLLAMA_READY_INTERVAL=1 \
    TEELLM_POD_READY_TIMEOUT=5 \
    TEELLM_SUPERVISOR_START_WAIT=1 \
    timeout 300 "$REPO/deploy-llm.sh" "$@" 2>&1)"
  status=$?
  set -e
}

fail() {
  echo "FAIL: $1" >&2
  echo "$output" >&2
  exit 1
}

kubectl_lines() { grep -c '^KUBECTL ' "$MOCK_LOG" || true; }

# ── 1. First run: the Pod does not exist yet ─────────────────────────────────

rm -f "$MOCK_STATE_DIR/applied.yaml" "$MOCK_STATE_DIR/apply-count"
touch "$MOCK_STATE_DIR/csv_device"

run_deploy --create-pod start --model qwen2.5-coder:0.5b
[[ $status -eq 0 ]] || fail "--create-pod start exited $status"

[[ "$(cat "$MOCK_STATE_DIR/apply-count" 2>/dev/null || echo 0)" == "1" ]] \
  || fail "the Pod was applied $(cat "$MOCK_STATE_DIR/apply-count" 2>/dev/null || echo 0) times, expected exactly one"

APPLIED="$MOCK_STATE_DIR/applied.yaml"
[[ -f "$APPLIED" ]] || fail "no manifest was submitted"
grep -q "^  name: $COPY_POD_NAME$" "$APPLIED" || fail "the manifest does not name the TEE-LLM Pod"
grep -q "^  namespace: osr$" "$APPLIED" || fail "the manifest does not set the namespace"
grep -q "^  runtimeClassName: kata-qemu-csv2$" "$APPLIED" \
  || fail "the manifest does not use the CSV2 RuntimeClass that creates /dev/csv-guest"
grep -q "^  nodeName: hygon-master$" "$APPLIED" || fail "the manifest is not pinned to the node"
grep -q "^  restartPolicy: Always$" "$APPLIED" \
  || fail "the manifest does not keep the Pod restartable in place"
grep -q 'cc_init_data: DERIVED_CC_INIT_DATA$' "$APPLIED" \
  || fail "the cc_init_data annotation was not derived and injected"
# The memory limit has to fit the model, not just teellm-service. 8Gi -- the figure the TAA Pod
# gets away with -- let the container cgroup OOM-kill llama-server while it loaded a 7B model, so
# the default is asserted to stay above it. requests must equal limits: CSV2 memory is resident
# from boot, so an overcommit here is a permanent host cost, not a burst.
memory_limits="$(grep -cE '^          memory: "' "$APPLIED")"
[[ "$memory_limits" == "2" ]] || fail "expected a memory figure on both limits and requests"
memory_gi="$(grep -oE '^          memory: "[0-9]+Gi"' "$APPLIED" | grep -oE '[0-9]+' | sort -u)"
[[ "$memory_gi" == "16" ]] \
  || fail "the TEE-LLM Pod memory default is $memory_gi Gi; a 7B model needs 16 (see the OOM note in deploy-llm.sh)"

# Exactly one annotation key, and it is the CoCo one. The runtime-handler key would hijack the
# runtime away from runtimeClassName, and an empty hypervisor kernel_params value would erase the
# rdinit= that boots TAA's guest.
annotation_keys="$(grep -cE '^    io\.' "$APPLIED")"
[[ "$annotation_keys" == "1" ]] || fail "expected exactly 1 annotation key, found $annotation_keys"
grep -qE '^    io\.katacontainers\.config\.runtime\.cc_init_data:' "$APPLIED" \
  || fail "the single annotation is not cc_init_data"

# The device node is created inside the container, not by the guest. A first version of this
# template assumed the RuntimeClass alone was enough, and the Pod came up Ready with an empty
# /dev -- every other gate would have passed while teellm-service served mock evidence.
grep -q "mknod /dev/csv-guest" "$APPLIED" || fail "the manifest does not create /dev/csv-guest"
grep -q "/sys/class/misc/csv-guest/dev" "$APPLIED" \
  || fail "the manifest does not read the csv-guest device numbers from sysfs"

# The container's PID 1 is the supervisor, not `sleep infinity`: restartPolicy only reacts to PID 1
# exiting, so an owned teellm-service and ollama is what keeps a dead daemon from staying dead.
grep -q "/opt/teellm/teellm-supervisor.sh" "$APPLIED" \
  || fail "the manifest does not hand PID 1 to the TEE-LLM supervisor"
grep -q "supervisor exited; restarting" "$APPLIED" \
  || fail "the manifest does not restart a supervisor that exits"
# The supervisor reads the model from the deployment; a Pod that already exists keeps its env.
grep -q "TEELLM_MODEL" "$APPLIED" || fail "the selected model is not in the Pod environment"
grep -q 'value: "qwen2.5-coder:0.5b"' "$APPLIED" \
  || fail "the Pod environment does not carry the selected model"

# The deployment must hand the daemons to the supervisor rather than start or stop them behind its
# back, and it must pause it before it writes over the live tree: a daemon starting mid-stream
# would execute a half-written binary.
grep -q "\.teellm-supervisor-pause" "$MOCK_LOG" \
  || fail "the deployment never paused the Pod supervisor"
grep -q "rm -f .*\.teellm-supervisor-pause" "$MOCK_LOG" \
  || fail "the deployment never resumed the Pod supervisor"
grep -q "teellm-supervisor.sh" "$MOCK_LOG" \
  || fail "the supervisor script was not installed into the Pod"
grep -q "\.teellm-model" "$MOCK_LOG" \
  || fail "the selected model was not written for the supervisor"
# A Pod created before the supervisor existed still runs `sleep infinity` as PID 1, so nothing in
# the container will ever exec the script; the deployment has to start it.
grep -qE "nohup \./teellm-supervisor\.sh" "$MOCK_LOG" \
  || fail "a Pod with no running supervisor was never given one"
if grep -qE 'nohup.*(start-ollama\.sh|teellm-service")' "$MOCK_LOG"; then
  fail "the deployment still starts daemons itself instead of leaving them to the supervisor"
fi
pause_line="$(grep -n "\.teellm-supervisor-pause" "$MOCK_LOG" | head -n1 | cut -d: -f1)"
live_write_line="$(grep -nE "KUBECTL cp|tar -xf" "$MOCK_LOG" | head -n1 | cut -d: -f1)"
[[ -n "$pause_line" && -n "$live_write_line" && "$pause_line" -lt "$live_write_line" ]] \
  || fail "the supervisor was not paused before the Pod's live tree was written to"
start_line="$(grep -nE "nohup \./teellm-supervisor\.sh" "$MOCK_LOG" | head -n1 | cut -d: -f1)"
resume_line="$(grep -n "rm -f .*\.teellm-supervisor-pause" "$MOCK_LOG" | head -n1 | cut -d: -f1)"
[[ -n "$start_line" && -n "$resume_line" && "$start_line" -lt "$resume_line" ]] \
  || fail "the supervisor was resumed before it was running"

# The deployment body must address the TEE-LLM Pod and nothing else. Aimed at the default TARGET_POD
# it would still pass every gate -- that Pod has /dev/csv-guest too -- and fail in production.
if grep -q "$DEFAULT_POD_NAME" "$MOCK_LOG"; then
  fail "a command was aimed at the default TARGET_POD ($DEFAULT_POD_NAME)"
fi
grep -q "$COPY_POD_NAME" "$MOCK_LOG" || fail "no command addressed the TEE-LLM Pod"

grep -q "reusing the running TEE-LLM Pod\|TEE-LLM Pod created and Ready" <<<"$output" \
  || fail "the Pod lifecycle steps are missing from the output"
grep -q "service is serving Hygon hardware evidence" <<<"$output" \
  || fail "the hardware evidence provider was not confirmed"
grep -q "TAA_LLM_ENDPOINT=https://$MOCK_POD_IP:8443" <<<"$output" \
  || fail "the summary does not hand over TAA_LLM_ENDPOINT"

# ── 2. Second run, with no action keyword: the Pod exists and is Ready ───────
# With the target keyword gone there is nothing left to name a target with, so the bare form has to
# reach the same Pod lifecycle as the explicit one rather than falling through to a no-op. Case 1
# already covered --create-pod start, so the reuse half is pinned down here in its bare form.

run_deploy --create-pod --model qwen2.5-coder:0.5b
[[ $status -eq 0 ]] || fail "the bare invocation (no action keyword) exited $status"
[[ "$(cat "$MOCK_STATE_DIR/apply-count")" == "1" ]] \
  || fail "the bare invocation applied the manifest again instead of reusing the Pod"
grep -q "reusing the running TEE-LLM Pod" <<<"$output" || fail "the bare invocation did not reuse the Pod"

# ── 2b. A bare TARGET_POD run re-execs the supervisor it just installed ──────
# `--create-pod` is not the only way in: a plain `TARGET_POD=... ./deploy-llm.sh` skips pod_up, so
# nothing marks the Pod as reused. If the restart request depended on that flag, the deployment
# would install a new supervisor script and leave the old copy running -- which is how a liveness
# fix silently failed to take effect once.

before="$(wc -l < "$MOCK_LOG")"
TARGET_POD="$COPY_POD_NAME" run_deploy
[[ $status -eq 0 ]] || fail "a bare TARGET_POD deployment exited $status"
tail -n +"$((before + 1))" "$MOCK_LOG" > "$TMP_DIR/bare.log"
grep -q "\.teellm-supervisor-restart" "$TMP_DIR/bare.log" \
  || fail "a bare TARGET_POD deployment did not ask the installed supervisor to re-exec"

# ── 3. Negative control: a Pod without /dev/csv-guest ────────────────────────

rm -f "$MOCK_STATE_DIR/csv_device"
run_deploy --create-pod start --model qwen2.5-coder:0.5b
[[ $status -ne 0 ]] || fail "a Pod without /dev/csv-guest was accepted"
grep -q "/dev/csv-guest" <<<"$output" || fail "the missing device was not named in the error"
touch "$MOCK_STATE_DIR/csv_device"

# ── 4. Negative control: --create-pod with a different explicit TARGET_POD ───

before="$(kubectl_lines)"
set +e
output="$(PATH="$MOCK_BIN:$PATH" TARGET_POD=some-other-pod \
  timeout 300 "$REPO/deploy-llm.sh" --create-pod start 2>&1)"
status=$?
set -e
[[ $status -ne 0 ]] || fail "--create-pod overrode an explicit TARGET_POD"
grep -q "addresses the TEE-LLM Pod" <<<"$output" || fail "the refusal does not explain the conflict"
[[ "$(kubectl_lines)" == "$before" ]] || fail "the refusal happened only after touching the cluster"

# ── 5. Negative control: no attestation certificates on the create path ──────

mv "$REPO/deploy/certs" "$TMP_DIR/certs-hidden"
run_deploy --create-pod start --model qwen2.5-coder:0.5b
[[ $status -ne 0 ]] || fail "a deployment without attestation certificates reported success"
grep -q "no Hygon attestation certificates found" <<<"$output" \
  || fail "the missing certificates were not named in the error"
mv "$TMP_DIR/certs-hidden" "$REPO/deploy/certs"

# ── 6. stop: the daemons are paused, not resurrected ─────────────────────────
# A supervisor that owns the daemons would restart them within the restart delay, so a stop that
# only killed processes would quietly do nothing.

before="$(wc -l < "$MOCK_LOG")"
run_deploy --create-pod stop
[[ $status -eq 0 ]] || fail "stop exited $status"
stop_log="$TMP_DIR/stop.log"
tail -n +"$((before + 1))" "$MOCK_LOG" > "$stop_log"
grep -q "\.teellm-supervisor-pause" "$stop_log" || fail "stop did not pause the supervisor"
grep -q "pkill -x teellm-service\|killall teellm-service" "$stop_log" \
  || fail "stop did not stop teellm-service"
stop_pause_line="$(grep -n "\.teellm-supervisor-pause" "$stop_log" | head -n1 | cut -d: -f1)"
stop_kill_line="$(grep -n "teellm-service" "$stop_log" | grep -v supervisor-pause | head -n1 | cut -d: -f1)"
[[ -n "$stop_pause_line" && -n "$stop_kill_line" && "$stop_pause_line" -lt "$stop_kill_line" ]] \
  || fail "stop killed the daemons before pausing the supervisor"

# ── 7. pod-down: the Pod is deleted, and nothing else is ─────────────────────

# Pointed at a bundle that does not exist: a teardown must not depend on the machine that deployed
# the bundle still having it, so this also pins down where the action is handled.
RUN_OLLAMA_DIR="$TMP_DIR/no-such-bundle"
run_deploy pod-down
[[ $status -eq 0 ]] || fail "pod-down exited $status"
[[ -f "$MOCK_STATE_DIR/pod" ]] && fail "the TEE-LLM Pod survived pod-down"
grep -q "TEE-LLM Pod '$COPY_POD_NAME' deleted" <<<"$output" || fail "pod-down did not report the deletion"
if grep -q "$DEFAULT_POD_NAME" "$MOCK_LOG"; then
  fail "pod-down was aimed at the default TARGET_POD ($DEFAULT_POD_NAME)"
fi

echo "PASS: the dedicated TEE-LLM Pod is created once, reused, gated on its CSV device, and is what the bare invocation deploys into"
