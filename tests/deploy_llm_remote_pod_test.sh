#!/usr/bin/env bash
# Verifies the dedicated TEE-LLM Pod path (create / delete).
#
# That Pod is what gives teellm-service a real /dev/csv-guest; without the device it serves mock
# evidence and TAA rejects every handshake. The traps this test guards are not visible in a
# successful deployment, so each one gets a negative control:
#
#   * the deployment must never aim at the default target Pod, which is a *TAA* Pod that also has
#     /dev/csv-guest -- every gate would pass while the service landed in the wrong Pod;
#   * a second run must not create a second Pod (a second confidential VM is tens of GiB of
#     host-resident encrypted memory, and a new IP that TAA's endpoint no longer points at);
#   * a Pod without the device must fail the deploy, since the readiness probe cannot tell the
#     difference (its client skips attestation verification);
#   * the rendered config must carry no Hygon certificate paths, and no certificate may be
#     copied to the remote host: TAA checks only the report's PEK signature, and the service
#     errors out if it is told to read a chain that is not there;
#   * an invocation with no action keyword must reach that same Pod path, since the target keyword
#     that used to say so is gone -- a bare run is now the only way to start a deployment;
#   * updating an existing Pod is the `update` action: it never creates or deletes one, and any
#     other spelling of the target Pod (the TARGET_POD environment variable, a positional
#     `pod=<name>`) is refused rather than quietly aiming the run somewhere else.
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
# ssh joins its command arguments into one remote command line; so does this mock, which matters
# for the image push (`bash -s -- <args>`) that reads its arguments from the joined form.
cmd="${args[*]:$i}"
cmd="${cmd//\/root\/teellm/$MOCK_REMOTE_ROOT\/root\/teellm}"
# The host's fallback copy of the cc_init_data value lives at /root/cc_init_data.txt; redirect it
# into the mock remote root so the fallback case reads a file this test owns.
cmd="${cmd//\/root\/cc_init_data.txt/$MOCK_REMOTE_ROOT\/root\/cc_init_data.txt}"
echo "SSH[$host] $cmd" >> "$MOCK_LOG"
case "$cmd" in
  *"command -v rsync"*) exit 1 ;;
esac
exec sh -c "$cmd"
MOCK

# curl, standing in for the local registry's tag listing. Only the teellm repository is answered;
# CURL_FAILS makes every request fail, which is how the deployment's fallback is checked. A
# manifest request answers with the config digest MOCK_REGISTRY_CONFIG names, and with nothing
# otherwise -- "this tag does not exist here" and "this tag holds a different build" are the same
# answer to the deployment, which then uploads.
cat > "$MOCK_BIN/curl" <<'MOCK'
#!/usr/bin/env bash
if [[ "${CURL_FAILS:-false}" == "true" ]]; then exit 7; fi
case "$*" in
  *"/v2/teellm/tags/list"*) printf '{"name":"teellm","tags":["20261025","20261026","latest"]}'; exit 0 ;;
  *"/v2/teellm/manifests/"*)
    if [[ -n "${MOCK_REGISTRY_CONFIG:-}" ]]; then
      printf '{"schemaVersion":2,"config":{"digest":"%s","size":1}}' "$MOCK_REGISTRY_CONFIG"
      exit 0
    fi
    exit 22
    ;;
esac
exit 22
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

# ss, standing in for the host's listener table. The remote commands run locally through the ssh
# mock, so without this the preflight would consult the test machine's real ports.
cat > "$MOCK_BIN/ss" <<'MOCK'
#!/usr/bin/env bash
# MOCK_HOST_PORT_BUSY answers as a host that already listens on the requested port. The port comes
# from the preflight's own PORT variable, so one flag can make either mapping busy.
if [[ -n "${MOCK_HOST_PORT_BUSY:-}" ]]; then
  echo "LISTEN 0 4096 0.0.0.0:${PORT:-18443} 0.0.0.0:*"
fi
exit 0
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
    # The creation preflight asks the cluster three things before it builds anything: that kubectl
    # reaches the API at all, that the namespace exists, and that the RuntimeClass does. All three
    # are answered yes here, because the cases under test are about what happens after them.
    if [[ "$*" == *"--raw /version"* ]]; then exit 0; fi
    if [[ "${args[$((i+1))]:-}" == "namespace" || "${args[$((i+1))]:-}" == "ns" ]]; then
      [[ -n "${MOCK_NO_NAMESPACE:-}" ]] && exit 1
      exit 0
    fi
    if [[ "${args[$((i+1))]:-}" == "runtimeclass" ]]; then exit 0; fi
    # The host port preflight asks every Pod what it publishes. MOCK_HOST_PORT_TAKEN_BY answers as
    # a cluster where that Pod already claims 18443.
    if [[ "$*" == *"hostPort"* ]]; then
      [[ -n "${MOCK_HOST_PORT_TAKEN_BY:-}" ]] && echo "$MOCK_HOST_PORT_TAKEN_BY ${PORT:-18443}"
      exit 0
    fi
    if [[ "$*" == *"-A"* ]]; then
      # MOCK_NO_CC_INIT_DATA stands for a host with no CoCo Pod at all: the annotation lookup
      # finds nothing, which is what makes the file fallback reachable.
      [[ -n "${MOCK_NO_CC_INIT_DATA:-}" ]] && exit 0
      echo "DERIVED_CC_INIT_DATA"; exit 0
    fi
    if [[ "$*" == *"status.podIP"* ]]; then printf '%s' "$MOCK_POD_IP"; exit 0; fi
    # The creation path polls the phase and the container's readiness rather than using
    # `kubectl wait`, and the teardown reads the memory limit to report what the host gets back.
    if [[ "$*" == *".status.phase"* ]]; then
      [[ -f "$MOCK_STATE_DIR/pod" ]] && { printf 'Running'; exit 0; } || exit 1
    fi
    if [[ "$*" == *"containerStatuses[0].ready"* ]]; then
      [[ -f "$MOCK_STATE_DIR/pod" ]] && { printf 'true'; exit 0; } || exit 1
    fi
    if [[ "$*" == *"limits.memory"* ]]; then
      [[ -f "$MOCK_STATE_DIR/pod" ]] && { printf '16Gi'; exit 0; } || exit 1
    fi
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
      *"tail -n"*) echo "2026-10-15T10:00:00Z using Hygon hardware evidence provider"; exit 0 ;;
      # The creation path verifies the payload the image carries. MOCK_POD_MISSING_BINARY stands
      # for an image built without the service, which is the case that must be reported rather
      # than patched with a copy.
      *"test -s /opt/teellm/teellm-service"*)
        [[ -n "${MOCK_POD_MISSING_BINARY:-}" ]] && exit 1
        exit 0 ;;
      *) exit 0 ;;
    esac
    ;;
  *) exit 0 ;;
esac
MOCK

# free, standing in for the remote host's memory. The ssh mock runs commands locally, so this is
# what the deployment's host-memory guard reads. MOCK_FREE_AVAIL_MIB sets the available column.
cat > "$MOCK_BIN/free" <<'MOCK'
#!/usr/bin/env bash
avail="${MOCK_FREE_AVAIL_MIB:-65536}"
printf '               total        used        free      shared  buff/cache   available\n'
printf 'Mem:           %d        %d        %d           0        %d        %s\n' 131072 32768 65536 32768 "$avail"
MOCK

# docker, standing in for the daemon the image build drives. The build itself is exercised against
# a real daemon in production; what this pins is the wiring around it -- that the binary exists
# before it is copied in, that the payload is committed under today's tag, that the archive is
# shipped and pushed when the registry does not already hold the build. A `teellm-base:` image is
# reported missing so the strip-TAA derivation runs, and every stdin-consuming step drains its
# input: a mock that exits without reading makes the writer on the other end of the pipe die of
# SIGPIPE, which `pipefail` turns into a failed deployment.
cat > "$MOCK_BIN/docker" <<'MOCK'
#!/usr/bin/env bash
echo "DOCKER $*" >> "$MOCK_LOG"
case "$1" in
  info) exit 0 ;;
  image)
    case "$*" in
      # The reuse gate asks the image for the fingerprint it recorded when it was committed. The
      # mock replays whatever the last case recorded, which is what a rerun over the same inputs
      # sees in production.
      *tee-llm.payload-fingerprint*)
        [[ -n "${MOCK_IMAGE_LABEL_FILE:-}" && -s "${MOCK_IMAGE_LABEL_FILE}" ]] && cat "$MOCK_IMAGE_LABEL_FILE"
        exit 0
        ;;
      # The derived base records the source image it was built from. An empty value means "no
      # label", which is what an image predating the label looks like.
      *tee-llm.base-source*)
        printf '%s\n' "${MOCK_BASE_SOURCE_LABEL:-}"
        exit 0
        ;;
      *teellm-base:*)
        case "$*" in
          *".Id"*|*".Size"*) ;;
          *) exit 1 ;;
        esac
        ;;
    esac
    case "$*" in
      *".Id"*) printf '%s\n' "${MOCK_IMAGE_ID:-sha256:1111111111111111111111111111111111111111111111111111111111111111}" ;;
      *".Size"*) printf '%s\n' "${MOCK_IMAGE_SIZE:-6550000000}" ;;
    esac
    exit 0
    ;;
  commit)
    for a in "$@"; do
      case "$a" in
        LABEL\ tee-llm.payload-fingerprint=*)
          [[ -n "${MOCK_COMMIT_LABEL_FILE:-}" ]] && printf '%s\n' "${a#*=}" > "$MOCK_COMMIT_LABEL_FILE"
          ;;
      esac
    done
    exit 0
    ;;
  build) cat >/dev/null; exit 0 ;;
  # A cross-tag reuse lookup answers with whatever MOCK_REUSE_IMAGE names; without it the lookup
  # finds nothing, which is what a host that has never built the image sees.
  images)
    [[ -n "${MOCK_REUSE_IMAGE:-}" ]] && printf '%s\n' "$MOCK_REUSE_IMAGE"
    exit 0
    ;;
  tag) exit 0 ;;
  cp)
    for a in "$@"; do
      case "$a" in
        */bin/teellm-service)
          if [ -s "$a" ]; then echo "DOCKER BINARY_PRESENT=yes" >> "$MOCK_LOG"
          else echo "DOCKER BINARY_PRESENT=no" >> "$MOCK_LOG"; fi
          ;;
      esac
    done
    exit 0
    ;;
  exec)
    case "$*" in
      *"tar -xf -"*) cat >/dev/null ;;
    esac
    exit 0
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
mkdir -p "$REPO/deploy/manifest/k8s" \
         "$REPO/teellm/deploy" "$REPO/teellm/configs" "$REPO/teellm/cmd/teellm-service" \
         "$OLLAMA_DIR/lib/ollama" \
         "$OLLAMA_DIR/models/models/blobs" \
         "$OLLAMA_DIR/models/models/manifests/registry.ollama.ai/library/qwen2.5-coder"

cp "$ROOT_DIR/deploy-llm.sh" "$REPO/deploy-llm.sh"
cp "$ROOT_DIR/deploy/manifest/k8s/teellm-pod.yaml.tmpl" "$REPO/deploy/manifest/k8s/"
cp "$ROOT_DIR/deploy/teellm-supervisor.sh" "$REPO/deploy/teellm-supervisor.sh"
chmod +x "$REPO/deploy/teellm-supervisor.sh"

# The model index the image payload step requires. The image build itself runs against the docker
# mock: what is under test here is the wiring around it, not the image's contents.
: > "$REPO/teellm/configs/models.json"

# The kata runtime configuration the memory guard reads default_memory from.
KATA_TOML_FILE="$TMP_DIR/kata-qemu-csv2.toml"
printf 'default_memory = 2048\ndefault_vcpus = 1\n' > "$KATA_TOML_FILE"

# The teellm module the deployment builds from. A stub keeps the test independent of the
# submodule, which the deploy script otherwise expects to be checked out next to itself.
printf 'module teellm-fake\n\ngo 1.22\n' > "$REPO/teellm/go.mod"
printf 'package main\n\nfunc main() {}\n' > "$REPO/teellm/cmd/teellm-service/main.go"
printf '#!/bin/sh\nexit 0\n' > "$REPO/teellm/deploy/start.sh"
cat > "$REPO/teellm/configs/teellm-production.json" <<'CFG'
{
  "server": { "addr": ":8443" },
  "backend": { "endpoint": "http://127.0.0.1:11434", "defaultModel": "qwen2.5-coder:0.5b" },
  "attestation": { "mode": "permissive" },
  "platform": { "addr": "http://172.16.10.181:18081", "dockerId": "taa-teellm" }
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
# A directory that the payload file list names directly. The real bundle has models/cache, and tar
# streams such an entry recursively, so the fingerprint has to cover what is inside it.
mkdir -p "$OLLAMA_DIR/models/cache"
printf 'cached' > "$OLLAMA_DIR/models/cache/partial"
cat > "$OLLAMA_DIR/models/models/manifests/registry.ollama.ai/library/qwen2.5-coder/0.5b" <<JSON
{
  "config": { "digest": "sha256:$CONFIG_DIGEST", "size": 16 },
  "layers": [ { "digest": "sha256:$LAYER_DIGEST", "size": 32 } ]
}
JSON

# ── Runner ───────────────────────────────────────────────────────────────────

output=""
status=0
# Extra VAR=value pairs for the next invocation, e.g. RUN_ENV=(CURL_FAILS=true). A name given here
# must not already be exported: an exported variable is inherited by every run, so the caller of
# this test setting CURL_FAILS would leak it into the cases that expect a working registry.
RUN_ENV=()
# Applied to every run, in front of RUN_ENV so a case can override any of them. The image size is
# pinned so the memory guard is arithmetic against a known figure rather than against whatever
# docker happens to have locally.
DEFAULT_ENV=(
  TEELLM_OLLAMA_READY_TIMEOUT=2
  OLLAMA_READY_INTERVAL=1
  TEELLM_POD_READY_TIMEOUT=5
  TEELLM_SUPERVISOR_START_WAIT=1
  TEELLM_POD_ASSUME_YES=true
  TEELLM_IMAGE_SIZE_GIB=6.10
  KATA_TOML="$KATA_TOML_FILE"
)
run_deploy() {
  set +e
  output="$(PATH="$MOCK_BIN:$PATH" env "${DEFAULT_ENV[@]}" "${RUN_ENV[@]}" \
    OLLAMA_LOCAL_DIR="${RUN_OLLAMA_DIR:-$OLLAMA_DIR}" \
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

run_deploy create --model qwen2.5-coder:0.5b
[[ $status -eq 0 ]] || fail "create exited $status"

[[ "$(cat "$MOCK_STATE_DIR/apply-count" 2>/dev/null || echo 0)" == "1" ]] \
  || fail "the Pod was applied $(cat "$MOCK_STATE_DIR/apply-count" 2>/dev/null || echo 0) times, expected exactly one"

# The Pod has to run an image built from this tree, not whatever tag was last pushed. Docker stands
# in for the real daemon, so these assertions are about the wiring: the image was committed once,
# under today's tag, only after the service binary had been rebuilt, and -- because the registry
# reported no manifest for that tag -- it was exported, shipped and pushed. The real build compiles
# nothing here, so a stale binary would otherwise be baked in silently.
TODAY_TAG="$(date +%Y%m%d)"
commit_calls="$(grep -c '^DOCKER commit ' "$MOCK_LOG" || true)"
[[ "$commit_calls" == "1" ]] || fail "the image was committed $commit_calls times, expected exactly one"
grep -qE "^DOCKER commit .* teellm:$TODAY_TAG\$" "$MOCK_LOG" \
  || fail "the image was not committed under the current build date"
grep -q '^DOCKER BINARY_PRESENT=yes$' "$MOCK_LOG" \
  || fail "teellm-service was not rebuilt before the image was committed"
# The cluster answers before the build starts: a missing namespace or RuntimeClass must not cost
# half an hour of image building first.
grep -q '^KUBECTL get --raw /version' "$MOCK_LOG" || fail "the preflight never probed the API server"
grep -q '^KUBECTL get runtimeclass ' "$MOCK_LOG" || fail "the preflight never checked the RuntimeClass"
grep -q 'MODEL=qwen2.5-coder:0.5b' "$MOCK_LOG" \
  || fail "the image was built for a different model than the deployment targets"
grep -q "^SCP\[.*deploy/out/teellm-$TODAY_TAG.tar.gz -> " "$MOCK_LOG" \
  || fail "the image archive was not shipped to the host that pushes"
grep -q "^DOCKER push 172.16.10.178:31313/teellm:$TODAY_TAG\$" "$MOCK_LOG" \
  || fail "the image was not pushed under the current build date"

APPLIED="$MOCK_STATE_DIR/applied.yaml"
[[ -f "$APPLIED" ]] || fail "no manifest was submitted"
grep -q "^  name: $COPY_POD_NAME$" "$APPLIED" || fail "the manifest does not name the TEE-LLM Pod"
grep -q "^  namespace: osr$" "$APPLIED" || fail "the manifest does not set the namespace"
grep -q "^  runtimeClassName: kata-qemu-csv2$" "$APPLIED" \
  || fail "the manifest does not use the CSV2 RuntimeClass that creates /dev/csv-guest"
grep -q "^  nodeName: hygon-master$" "$APPLIED" || fail "the manifest is not pinned to the node"
grep -q "^    katacontainers.io/kata-runtime: \"true\"$" "$APPLIED" \
  || fail "the manifest does not select a kata-capable node"
grep -q "^  restartPolicy: Always$" "$APPLIED" \
  || fail "the manifest does not keep the Pod restartable in place"
grep -q "^  terminationGracePeriodSeconds: 30$" "$APPLIED" \
  || fail "the manifest does not give the guest time to shut down"
grep -q 'cc_init_data: "DERIVED_CC_INIT_DATA"$' "$APPLIED" \
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
# Two vCPUs, the reference create script's figure: encrypted memory is resident, and a larger vCPU
# count is a further permanent claim on a host whose CPU requests are already nearly accounted for.
cpu_limits="$(grep -oE '^          cpu: "[0-9]+"' "$APPLIED" | grep -oE '[0-9]+' | sort -u)"
[[ "$cpu_limits" == "2" ]] || fail "the TEE-LLM Pod CPU default is $cpu_limits, expected 2"
# Both listeners are published on the node: the service's TLS port at the reference script's 18443,
# and the plaintext platform listener at 16001. The Pod IP changes on every recreation, so these
# mappings are the only addresses that survive one -- and 6001 is the one a plain HTTP client can
# use, since 8443 speaks RFC 8998 ShangMi TLS.
grep -q '^          containerPort: 8443$' "$APPLIED" \
  || fail "the manifest does not expose teellm-service's 8443"
grep -q '^          hostPort: 18443$' "$APPLIED" \
  || fail "the manifest does not publish the host port"
grep -q '^          containerPort: 6001$' "$APPLIED" \
  || fail "the manifest does not expose the plaintext platform listener on 6001"
grep -q '^          hostPort: 16001$' "$APPLIED" \
  || fail "the manifest does not publish the platform listener's host port"
# Logs from inside the guest are read next to the host's, so the container keeps the host's zone.
grep -q '^        - name: TZ$' "$APPLIED" || fail "the manifest does not set TZ"
grep -q '^          value: "Asia/Shanghai"$' "$APPLIED" || fail "TZ is not Asia/Shanghai"
# The overlay check only proves the image fits. What the service and the model have left over is a
# separate number, and it is the one that shows up as a cgroup OOM long after the Pod went Ready.
grep -qE 'business memory available: [0-9]+MiB \(cgroup limit 16384MiB, physical [0-9]+MiB\)' <<<"$output" \
  || fail "the deployment did not report the memory left for the service and the model"

# Three annotation keys, the set every kata-qemu-csv2 Pod on this host carries. runtime-handler has
# to name the same runtime class; kernel_params has to be non-empty and carry the two pull timeouts
# -- the image is pulled inside the guest by the CDH, where the defaults expire long before a
# multi-GB image arrives (the Pod sits in ContainerCreating and is then failed).
annotation_keys="$(grep -cE '^    io\.' "$APPLIED")"
[[ "$annotation_keys" == "3" ]] || fail "expected exactly 3 annotation keys, found $annotation_keys"
grep -qE '^    io\.containerd\.cri\.runtime-handler: kata-qemu-csv2$' "$APPLIED" \
  || fail "the runtime-handler annotation does not name the CSV2 runtime class"
grep -qE '^    io\.katacontainers\.config\.hypervisor\.kernel_params: "agent\.cdh_api_timeout=1200 agent\.image_pull_timeout=3600"$' "$APPLIED" \
  || fail "the kernel_params annotation is missing or not the measured pull timeouts"
grep -qE '^    io\.katacontainers\.config\.runtime\.cc_init_data: "[^"]+"$' "$APPLIED" \
  || fail "cc_init_data is missing or empty"

# The device node is created inside the container, not by the guest. A first version of this
# template assumed the RuntimeClass alone was enough, and the Pod came up Ready with an empty
# /dev -- every other gate would have passed while teellm-service served mock evidence.
grep -q "/proc/misc" "$APPLIED" || fail "the manifest does not read the device minor from /proc/misc"
grep -q "mknod -m 666 /dev/csv-guest" "$APPLIED" || fail "the manifest does not create /dev/csv-guest"

# The reference create script runs the container privileged as root; mknod on /dev needs
# CAP_MKNOD, and both the entrypoint and the supervisor expect root.
grep -q "^        privileged: true$" "$APPLIED" || fail "the container is not privileged"
grep -q "^        allowPrivilegeEscalation: true$" "$APPLIED" \
  || fail "the container forbids privilege escalation, which mknod needs"
grep -q "^        runAsUser: 0$" "$APPLIED" || fail "the container does not run as root"
grep -q "^        runAsNonRoot: false$" "$APPLIED" || fail "the container declares runAsNonRoot"
grep -q 'command: \["/bin/bash", "-c"\]' "$APPLIED" || fail "the start command is not bash -c"

# The container's PID 1 is the supervisor, not `sleep infinity` and not a restart loop: the
# reference create script execs it, so the container's lifetime is the supervisor's and
# restartPolicy is what brings the service back.
grep -q "exec /bin/bash /opt/teellm/teellm-supervisor.sh" "$APPLIED" \
  || fail "the manifest does not hand PID 1 to the TEE-LLM supervisor"
# The supervisor reads the model from the deployment; a Pod that already exists keeps its env.
grep -q "TEELLM_MODEL" "$APPLIED" || fail "the selected model is not in the Pod environment"
grep -q 'value: "qwen2.5-coder:0.5b"' "$APPLIED" \
  || fail "the Pod environment does not carry the selected model"

# A Pod created by this run takes everything from its image: the image was built from this tree
# moments earlier (or was named explicitly), so nothing may be installed into the Pod afterwards.
# A copy here would be a second, invisible definition of what the Pod runs, and it would keep a
# defective image working until the next Pod is created from it.
grep -q "the Pod image carries teellm-service" <<<"$output" \
  || fail "the creation did not verify the payload baked into the Pod image"
if grep -q "^KUBECTL cp " "$MOCK_LOG"; then
  fail "the creation copied files into the Pod instead of trusting its image"
fi
if grep -q "\.teellm-supervisor-pause" "$MOCK_LOG"; then
  fail "the creation paused the supervisor to install files, which it must not do"
fi
if grep -q "^SCP\[.*teellm-service" "$MOCK_LOG"; then
  fail "the creation uploaded a service binary for the Pod to install"
fi

# The deployment body must address the TEE-LLM Pod and nothing else. Aimed at the default target
# it would still pass every gate -- that Pod has /dev/csv-guest too -- and fail in production.
if grep -q "$DEFAULT_POD_NAME" "$MOCK_LOG"; then
  fail "a command was aimed at the default target Pod ($DEFAULT_POD_NAME)"
fi
grep -q "$COPY_POD_NAME" "$MOCK_LOG" || fail "no command addressed the TEE-LLM Pod"

grep -q "TEE-LLM Pod created and Ready" <<<"$output" \
  || fail "the Pod creation step is missing from the output"
grep -q "service is serving Hygon hardware evidence" <<<"$output" \
  || fail "the hardware evidence provider was not confirmed"
grep -q "LLM_IP=https://$MOCK_POD_IP:8443" <<<"$output" \
  || fail "the summary does not hand over LLM_IP"

# The Pod pulls the image this run just pushed, and it pulls it unconditionally: the tag is a
# build date, so a rebuild replaces it in place and a cached copy would defeat the build.
grep -q "^      image: 172.16.10.178:31313/teellm:$TODAY_TAG$" "$APPLIED" \
  || fail "the Pod image is not the one this run built"
grep -q "^      imagePullPolicy: Always$" "$APPLIED" \
  || fail "a freshly built image is not pulled unconditionally"

# ── 1b. With the build disabled, the newest registry tag is used ─────────────
# The tag is a build date, so today's date only names a real image on the day it was built. Left
# as a guess, a deployment the next day applies a Pod whose guest cannot pull, and the failure
# lands in ImagePullBackOff after a confidential VM has already booted. The registry's newest date
# tag has to win -- on the path that does not build one for itself.

rm -f "$MOCK_STATE_DIR/pod"
build_before="$(grep -c '^DOCKER commit ' "$MOCK_LOG" || true)"
RUN_ENV=(TEELLM_BUILD_POD_IMAGE=false)
run_deploy create --model qwen2.5-coder:0.5b
RUN_ENV=()
[[ $status -eq 0 ]] || fail "TEELLM_BUILD_POD_IMAGE=false exited $status"
[[ "$(grep -c '^DOCKER commit ' "$MOCK_LOG" || true)" == "$build_before" ]] \
  || fail "an image was built even though TEELLM_BUILD_POD_IMAGE=false"
grep -q "^      image: 172.16.10.178:31313/teellm:20261026$" "$APPLIED" \
  || fail "the Pod image is not the newest tag the registry lists"
if grep -q "teellm:$TODAY_TAG$" "$APPLIED"; then
  fail "the Pod image is still today's date tag, which the registry does not list"
fi
grep -q "^      imagePullPolicy: IfNotPresent$" "$APPLIED" \
  || fail "a pre-existing registry tag should not be forced to pull"

# ── 1c. The registry already holds this exact build ─────────────────────────
# Committing the image is how its ID is learned, so a build always happens; what must not happen is
# exporting several gigabytes, copying them to the host and pushing them again when the registry's
# manifest already points at those bytes. The mock answers the manifest query with the same digest
# Docker reports for the local image, and the archive/ship/push chain has to stay silent.

rm -f "$MOCK_STATE_DIR/pod"
scp_before="$(grep -c "^SCP\[.*teellm-$TODAY_TAG.tar.gz" "$MOCK_LOG" || true)"
push_before="$(grep -c '^DOCKER push ' "$MOCK_LOG" || true)"
RUN_ENV=(MOCK_REGISTRY_CONFIG=sha256:1111111111111111111111111111111111111111111111111111111111111111)
run_deploy create --model qwen2.5-coder:0.5b
RUN_ENV=()
[[ $status -eq 0 ]] || fail "the identical-build path exited $status"
grep -q "the registry already holds this build; nothing uploaded" <<<"$output" \
  || fail "the deployment did not notice the registry already holds this build"
[[ "$(grep -c "^SCP\[.*teellm-$TODAY_TAG.tar.gz" "$MOCK_LOG" || true)" == "$scp_before" ]] \
  || fail "the image archive was shipped even though the registry already holds this build"
[[ "$(grep -c '^DOCKER push ' "$MOCK_LOG" || true)" == "$push_before" ]] \
  || fail "the image was pushed even though the registry already holds this build"
grep -q "^      image: 172.16.10.178:31313/teellm:$TODAY_TAG$" "$APPLIED" \
  || fail "the Pod does not run the registry image the build produced"
grep -q "^      imagePullPolicy: Always$" "$APPLIED" \
  || fail "the freshly built tag is not pulled unconditionally"

# ── 2. Second run: the Pod exists, so the creation path refuses ───────────────
# create creates. Adopting an existing Pod would deploy into whatever image it happens to run,
# and replacing it would discard the guest's writable layer (the ollama runtime and the model) and
# change the IP TAA's endpoint points at, without the operator ever seeing the choice. The run says
# so and stops, before anything is built or applied.

apply_before="$(cat "$MOCK_STATE_DIR/apply-count")"
build_before="$(grep -c '^DOCKER commit ' "$MOCK_LOG" || true)"
run_deploy create --model qwen2.5-coder:0.5b
[[ $status -ne 0 ]] || fail "a second create run was accepted instead of refusing the existing Pod"
grep -q "already exists" <<<"$output" || fail "the refusal does not say the Pod already exists"
grep -q "delete" <<<"$output" || fail "the refusal does not tell the operator to delete the Pod first"
[[ "$(cat "$MOCK_STATE_DIR/apply-count")" == "$apply_before" ]] \
  || fail "the manifest was applied even though the Pod already exists"
[[ "$(grep -c '^DOCKER commit ' "$MOCK_LOG" || true)" == "$build_before" ]] \
  || fail "an image was built for a Pod that already exists"

# ── 2b. `update --pod` re-execs the supervisor it just installed ────────────
# `create` is not the only way in: `update` skips pod_up, so nothing marks the Pod as reused. If
# the restart request depended on that flag, the deployment would install a new supervisor script
# and leave the old copy running -- which is how a liveness fix silently failed to take effect once.

before="$(wc -l < "$MOCK_LOG")"
run_deploy update --pod "$COPY_POD_NAME"
[[ $status -eq 0 ]] || fail "an update of an existing Pod exited $status"
tail -n +"$((before + 1))" "$MOCK_LOG" > "$TMP_DIR/bare.log"
grep -q "\.teellm-supervisor-restart" "$TMP_DIR/bare.log" \
  || fail "a plain --pod deployment did not ask the installed supervisor to re-exec"

# A Pod this run did not create is the only case that still installs into it, and it still has to
# hand the daemons to the supervisor rather than start or stop them behind its back -- and pause it
# before writing over the live tree, so a daemon starting mid-stream cannot execute a half-written
# binary.
grep -q "\.teellm-supervisor-pause" "$TMP_DIR/bare.log" \
  || fail "an existing Pod was not paused before its live tree was written to"
grep -q "rm -f .*\.teellm-supervisor-pause" "$TMP_DIR/bare.log" \
  || fail "an existing Pod's supervisor was never resumed"
grep -q "teellm-supervisor.sh" "$TMP_DIR/bare.log" \
  || fail "the supervisor script was not installed into the Pod"
grep -q "\.teellm-model" "$TMP_DIR/bare.log" \
  || fail "the selected model was not written for the supervisor"
# A Pod created before the supervisor existed still runs `sleep infinity` as PID 1, so nothing in
# the container will ever exec the script; the deployment has to start it.
grep -qE "nohup \./teellm-supervisor\.sh" "$TMP_DIR/bare.log" \
  || fail "a Pod with no running supervisor was never given one"
if grep -qE 'nohup.*(start-ollama\.sh|teellm-service")' "$TMP_DIR/bare.log"; then
  fail "the deployment still starts daemons itself instead of leaving them to the supervisor"
fi
pause_line="$(grep -n "\.teellm-supervisor-pause" "$TMP_DIR/bare.log" | head -n1 | cut -d: -f1)"
# The image build also unpacks a tar, but into a throwaway builder container; only a write that
# goes through the remote host reaches the Pod's live tree, so those are what the order is about.
live_write_line="$(grep -nE "KUBECTL cp|SSH\[.*tar -xf" "$TMP_DIR/bare.log" | head -n1 | cut -d: -f1)"
[[ -n "$pause_line" && -n "$live_write_line" && "$pause_line" -lt "$live_write_line" ]] \
  || fail "the supervisor was not paused before the Pod's live tree was written to"
start_line="$(grep -nE "nohup \./teellm-supervisor\.sh" "$TMP_DIR/bare.log" | head -n1 | cut -d: -f1)"
resume_line="$(grep -n "rm -f .*\.teellm-supervisor-pause" "$TMP_DIR/bare.log" | head -n1 | cut -d: -f1)"
[[ -n "$start_line" && -n "$resume_line" && "$start_line" -lt "$resume_line" ]] \
  || fail "the supervisor was resumed before it was running"

# ── 3. Negative control: a Pod without /dev/csv-guest ────────────────────────
# A creation that goes through every earlier gate still has to be stopped by the device check,
# which is the only thing standing between a mock report and a deployment that claims attestation.

rm -f "$MOCK_STATE_DIR/pod" "$MOCK_STATE_DIR/csv_device"
run_deploy create --model qwen2.5-coder:0.5b
[[ $status -ne 0 ]] || fail "a Pod without /dev/csv-guest was accepted"
grep -q "/dev/csv-guest" <<<"$output" || fail "the missing device was not named in the error"
touch "$MOCK_STATE_DIR/csv_device"

# ── 3b. An explicit image is never second-guessed ────────────────────────────
# Resolution and building exist to pick an image, not to overrule an operator. A tag the listing
# does not show (a mirror, a manually pushed name) has to reach the manifest unchanged, and the
# deployment must not spend tens of minutes building an image nobody asked for.

rm -f "$MOCK_STATE_DIR/pod"
build_before="$(grep -c '^DOCKER commit ' "$MOCK_LOG" || true)"
RUN_ENV=(TEELLM_IMAGE="172.16.10.178:31313/teellm:pinned")
run_deploy create --model qwen2.5-coder:0.5b
RUN_ENV=()
[[ $status -eq 0 ]] || fail "an explicit TEELLM_IMAGE exited $status"
grep -q "^      image: 172.16.10.178:31313/teellm:pinned$" "$APPLIED" \
  || fail "an explicit TEELLM_IMAGE was replaced by a registry tag"
[[ "$(grep -c '^DOCKER commit ' "$MOCK_LOG" || true)" == "$build_before" ]] \
  || fail "an image was built despite an explicit TEELLM_IMAGE"
grep -q "^      imagePullPolicy: IfNotPresent$" "$APPLIED" \
  || fail "an explicit image was overridden to pull unconditionally"

# ── 3c. An unreadable registry listing falls back to the guessed tag ─────────
# The listing is a convenience on top of the guess. A registry that cannot be queried from the
# deploy host -- 401, unreachable, filtered -- says nothing about whether the guest's CDH can
# pull the tag, so the deployment proceeds and warns instead of failing.

rm -f "$MOCK_STATE_DIR/pod"
RUN_ENV=(CURL_FAILS=true TEELLM_BUILD_POD_IMAGE=false)
run_deploy create --model qwen2.5-coder:0.5b
RUN_ENV=()
[[ $status -eq 0 ]] || fail "an unreadable tag listing failed the deployment"
grep -q "^      image: 172.16.10.178:31313/teellm:$(date +%Y%m%d)$" "$APPLIED" \
  || fail "the guessed tag was not kept when the listing failed"
grep -q "could not list tags of" <<<"$output" || fail "the fallback was not reported"

# ── 3d. Negative control: the guest cannot hold the image ────────────────────
# A kata guest's rootfs is an overlayfs on a tmpfs capped at half of the guest's visible memory,
# so an image larger than that cap fails with ENOSPC -- after the confidential VM has been booted
# and its memory taken. The arithmetic is done before anything is applied.

rm -f "$MOCK_STATE_DIR/pod"
apply_before="$(cat "$MOCK_STATE_DIR/apply-count")"
RUN_ENV=(TEELLM_POD_MEMORY=8Gi)
run_deploy create --model qwen2.5-coder:0.5b
RUN_ENV=()
[[ $status -ne 0 ]] || fail "an 8Gi Pod was accepted although its overlay cannot hold the image"
grep -q "cannot start" <<<"$output" || fail "the memory refusal does not explain itself"
grep -qE "at least 1[0-9]Gi" <<<"$output" || fail "the refusal does not name the minimum memory"
[[ "$(cat "$MOCK_STATE_DIR/apply-count")" == "$apply_before" ]] \
  || fail "the Pod was applied despite failing the memory check"

# ── 3e. Negative control: the host cannot hold the VM ────────────────────────
# CSV2 memory is resident from boot and is never reclaimed, so a VM bigger than the host's free
# memory does not degrade gracefully -- it takes the host's other workloads with it.

rm -f "$MOCK_STATE_DIR/pod"
apply_before="$(cat "$MOCK_STATE_DIR/apply-count")"
RUN_ENV=(MOCK_FREE_AVAIL_MIB=4096)
run_deploy create --model qwen2.5-coder:0.5b
RUN_ENV=()
[[ $status -ne 0 ]] || fail "a VM larger than the host's available memory was accepted"
grep -q "available and this confidential VM needs" <<<"$output" \
  || fail "the host memory refusal does not explain itself"
[[ "$(cat "$MOCK_STATE_DIR/apply-count")" == "$apply_before" ]] \
  || fail "the Pod was applied despite failing the host memory check"

# ── 3f. Negative control: the host port is already listening ─────────────────
# A host port that something already holds makes the Pod unschedulable, and on a path that builds
# an image first the operator would learn that tens of minutes later. The check runs in the
# preflight, before any build, and refuses.

rm -f "$MOCK_STATE_DIR/pod"
apply_before="$(cat "$MOCK_STATE_DIR/apply-count")"
RUN_ENV=(MOCK_HOST_PORT_BUSY=yes)
run_deploy create --model qwen2.5-coder:0.5b
RUN_ENV=()
[[ $status -ne 0 ]] || fail "a taken host port was accepted"
grep -q "host port 18443 is already in use" <<<"$output" \
  || fail "the port refusal does not name the port"
grep -q "TEELLM_POD_HOST_PORT" <<<"$output" || fail "the port refusal does not name the override"
[[ "$(cat "$MOCK_STATE_DIR/apply-count")" == "$apply_before" ]] \
  || fail "the Pod was applied despite a taken host port"

# ── 3g. Another Pod's declaration is a warning, not a refusal ────────────────
# A declared hostPort on a Pod that is not running does not block scheduling, so the deployment
# proceeds and says what it found. Refusing here would make a stopped Pod of the same name a
# permanent obstacle to replacing it.

rm -f "$MOCK_STATE_DIR/pod"
RUN_ENV=(MOCK_HOST_PORT_TAKEN_BY="default/old-teellm")
run_deploy create --model qwen2.5-coder:0.5b
RUN_ENV=()
[[ $status -eq 0 ]] || fail "another Pod's hostPort declaration blocked the creation"
grep -q "declares host port 18443" <<<"$output" || fail "the declaration was not reported"
grep -q "default/old-teellm" <<<"$output" || fail "the declaration does not name the Pod"

# ── 3h. Setting a host port to 0 publishes only that one ────────────────────
# The escape hatch for a host that cannot spare a port. Kubernetes reads hostPort 0 as unset, so
# that listener falls back to the Pod IP; the other mapping is untouched.

rm -f "$MOCK_STATE_DIR/pod"
RUN_ENV=(TEELLM_POD_HOST_PORT=0)
run_deploy create --model qwen2.5-coder:0.5b
RUN_ENV=()
[[ $status -eq 0 ]] || fail "TEELLM_POD_HOST_PORT=0 exited $status"
grep -q '^          hostPort: 0$' "$APPLIED" || fail "TEELLM_POD_HOST_PORT=0 was not rendered"
grep -q "container port 8443 is not published" <<<"$output" || fail "the disabled port was not reported"
grep -q '^          hostPort: 16001$' "$APPLIED" \
  || fail "TEELLM_POD_HOST_PORT=0 also disabled the platform mapping"
rm -f "$MOCK_STATE_DIR/pod"

# ── 3i. TEELLM_POD_ATTESTATION_HOST_PORT=0 publishes the platform port nowhere ─
# The same escape hatch for the plaintext listener alone: the TLS mapping stays, and the platform
# keeps reaching 6001 at the Pod IP.

rm -f "$MOCK_STATE_DIR/pod"
RUN_ENV=(TEELLM_POD_ATTESTATION_HOST_PORT=0)
run_deploy create --model qwen2.5-coder:0.5b
RUN_ENV=()
[[ $status -eq 0 ]] || fail "TEELLM_POD_ATTESTATION_HOST_PORT=0 exited $status"
grep -q "container port 6001 is not published" <<<"$output" || fail "the disabled platform port was not reported"
grep -q '^          hostPort: 18443$' "$APPLIED" \
  || fail "TEELLM_POD_ATTESTATION_HOST_PORT=0 also disabled the TLS mapping"
[[ "$(grep -c '^          hostPort: 0$' "$APPLIED")" == "1" ]] \
  || fail "the disabled platform port was not rendered as hostPort 0"
rm -f "$MOCK_STATE_DIR/pod"

# ── 3j. Negative control: both container ports on one host port ──────────────
# One Pod cannot publish 8443 and 6001 on the same host port; Kubernetes rejects the manifest, and
# on this path that would happen after the image build. The collision is refused before anything.

rm -f "$MOCK_STATE_DIR/pod"
apply_before="$(cat "$MOCK_STATE_DIR/apply-count")"
RUN_ENV=(TEELLM_POD_ATTESTATION_HOST_PORT=18443)
run_deploy create --model qwen2.5-coder:0.5b
RUN_ENV=()
[[ $status -ne 0 ]] || fail "two container ports sharing one host port were accepted"
grep -q "cannot publish 8443 and 6001 on the same host port" <<<"$output" \
  || fail "the collision refusal does not explain itself"
[[ "$(cat "$MOCK_STATE_DIR/apply-count")" == "$apply_before" ]] \
  || fail "the Pod was applied despite the host port collision"
rm -f "$MOCK_STATE_DIR/pod"

# ── 3k. Negative control: the image is missing its payload ───────────────────
# Creation no longer installs anything, so an image that does not carry the service cannot be
# repaired by the deployment: it has to say which file is missing and stop, instead of copying a
# binary in and leaving a Pod whose contents no image describes.

apply_before="$(cat "$MOCK_STATE_DIR/apply-count")"
before="$(wc -l < "$MOCK_LOG")"
RUN_ENV=(MOCK_POD_MISSING_BINARY=yes)
run_deploy create --model qwen2.5-coder:0.5b
RUN_ENV=()
[[ $status -ne 0 ]] || fail "an image without teellm-service was accepted"
grep -q "does not carry the full TEE-LLM payload" <<<"$output" \
  || fail "the missing payload was not reported as such"
grep -q "missing: /opt/teellm/teellm-service" <<<"$output" \
  || fail "the missing file was not named"
grep -q "nothing was copied into the Pod" <<<"$output" \
  || fail "the refusal does not say that nothing was copied"
tail -n +"$((before + 1))" "$MOCK_LOG" > "$TMP_DIR/missing.log"
if grep -q "^KUBECTL cp " "$TMP_DIR/missing.log"; then
  fail "a defective image was patched with a copy instead of being reported"
fi
[[ "$(cat "$MOCK_STATE_DIR/apply-count")" == "$((apply_before + 1))" ]] \
  || fail "the defective Pod was not created before its payload was inspected"
rm -f "$MOCK_STATE_DIR/pod"

# Put a Pod back for the cases below: the two refusals above removed it to reach the creation path,
# and stop/delete need something to act on.
touch "$MOCK_STATE_DIR/pod"

# ── 4. Negative control: create with a different explicit --pod ───────

before="$(kubectl_lines)"
set +e
output="$(PATH="$MOCK_BIN:$PATH" \
  timeout 300 "$REPO/deploy-llm.sh" create --pod some-other-pod 2>&1)"
status=$?
set -e
[[ $status -ne 0 ]] || fail "create overrode an explicit --pod"
grep -q "addresses the TEE-LLM Pod" <<<"$output" || fail "the refusal does not explain the conflict"
[[ "$(kubectl_lines)" == "$before" ]] || fail "the refusal happened only after touching the cluster"

# ── 5. The rendered config and the transfers carry no certificates ───────────
# TAA verifies only the report's embedded PEK signature, so the service must not
# be told to read a vendor chain: a path left in the config makes the hardware
# provider fail the handshake when the file is absent, and a copy the peer never
# needs still has to be shipped.

REMOTE_CFG="$MOCK_REMOTE_ROOT/root/teellm/configs/teellm-production.json"
[[ -f "$REMOTE_CFG" ]] || fail "no rendered config reached the remote host"
if grep -qE '"(hrkCertPath|hskCekCertPath)"' "$REMOTE_CFG"; then
  fail "the rendered config still names Hygon certificate paths"
fi
if grep -q 'certs/' "$MOCK_LOG"; then
  fail "a Hygon certificate was still copied to the remote host or the Pod"
fi

# ── 5b. No platform block survives into the rendered config ──────────────────
# The platform calls TEE-LLM; the instance never reports out, so the rendered config must not
# carry a platform address even when the template it came from still has one (an image built
# before the direction changed ships exactly that).

has_platform_key() {
  python3 -c 'import json,sys; print("platform" in json.load(open(sys.argv[1])))' "$REMOTE_CFG"
}

run_deploy update
[[ $status -eq 0 ]] || fail "a deployment with a legacy platform block exited $status"
[[ "$(has_platform_key)" == "False" ]] \
  || fail "the rendered config still carries the template's platform block"

grep -q "platform reporting" <<<"$output" \
  && fail "the deployment still reports a platform address"

# ── 6. stop: the daemons are paused, not resurrected ─────────────────────────
# A supervisor that owns the daemons would restart them within the restart delay, so a stop that
# only killed processes would quietly do nothing.

before="$(wc -l < "$MOCK_LOG")"
run_deploy stop
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

# ── 6b. start: the other end of stop, and nothing beyond it ─────────────────
# start hands the daemons back to the supervisor already in the Pod. It must not build, sync or
# copy -- that is update's job, and a start that installed would need the offline ollama bundle on
# the machine, which a start-only workflow deliberately does not have.

before="$(wc -l < "$MOCK_LOG")"
build_before="$(grep -c '^DOCKER commit ' "$MOCK_LOG" || true)"
RUN_OLLAMA_DIR="$TMP_DIR/no-such-bundle"
run_deploy start
[[ $status -eq 0 ]] || fail "start exited $status"
start_log="$TMP_DIR/start.log"
tail -n +"$((before + 1))" "$MOCK_LOG" > "$start_log"
grep -q "rm -f .*\.teellm-supervisor-pause" "$start_log" \
  || fail "start did not resume the Pod supervisor"
[[ "$(grep -c '^DOCKER commit ' "$MOCK_LOG" || true)" == "$build_before" ]] \
  || fail "start built an image instead of only starting the services"
if grep -qE "KUBECTL cp|SSH\[.*tar -xf" "$start_log"; then
  fail "start copied files into the Pod instead of only resuming the supervisor"
fi

# A Pod that is not there is reported as that, and is not created: only create touches the Pod
# lifecycle.
rm -f "$MOCK_STATE_DIR/pod"
run_deploy start
[[ $status -ne 0 ]] || fail "start accepted a Pod that does not exist"
grep -q "TEE-LLM Pod '$COPY_POD_NAME' does not exist" <<<"$output" \
  || fail "start did not name the missing Pod"
[[ -f "$MOCK_STATE_DIR/pod" ]] && fail "start created the Pod"
touch "$MOCK_STATE_DIR/pod"
unset RUN_OLLAMA_DIR

# ── 7. delete: the Pod is deleted, and nothing else is ─────────────────────

# Pointed at a bundle that does not exist: a teardown must not depend on the machine that deployed
# the bundle still having it, so this also pins down where the action is handled.
RUN_OLLAMA_DIR="$TMP_DIR/no-such-bundle"
before="$(wc -l < "$MOCK_LOG")"
run_deploy delete
[[ $status -eq 0 ]] || fail "delete exited $status"
[[ -f "$MOCK_STATE_DIR/pod" ]] && fail "the TEE-LLM Pod survived delete"
grep -q "TEE-LLM Pod '$COPY_POD_NAME' deleted" <<<"$output" || fail "delete did not report the deletion"
if grep -q "$DEFAULT_POD_NAME" "$MOCK_LOG"; then
  fail "delete was aimed at the default target Pod ($DEFAULT_POD_NAME)"
fi
delete_log="$TMP_DIR/delete.log"
tail -n +"$((before + 1))" "$MOCK_LOG" > "$delete_log"
# The delete is submitted without waiting and then polled, the way the reference delete script does
# it: a kata guest needs its grace period, and a blocking kubectl wait would hide a guest that
# ignores the signal instead of letting the forced-delete fallback see it.
grep -q "delete pod $COPY_POD_NAME --grace-period=30 --ignore-not-found --wait=false" "$delete_log" \
  || fail "delete did not submit a grace-period delete that it then polls"
if grep -q "delete pod $COPY_POD_NAME .*--wait=true" "$delete_log"; then
  fail "delete still blocks inside kubectl wait instead of polling"
fi
# A sandbox can outlive its Pod and keep the whole VM resident, so the deletion is not the end of
# the teardown: the three counts are read on the remote host afterwards.
grep -q "checking for leftover kata sandboxes" <<<"$output" \
  || fail "delete did not check for leftover kata sandboxes"
grep -qE "kata Pods: [0-9?]+ +/run/vc/sbs: [0-9?]+ +qemu-system: [0-9?]+" <<<"$output" \
  || fail "the sandbox counts were not reported"

# Running it again is a no-op, not an error: the second run is also the only way to re-check the
# sandbox counts once someone has cleaned an orphan by hand.
run_deploy delete
[[ $status -eq 0 ]] || fail "delete on a Pod that is already gone exited $status"
grep -q "TEE-LLM Pod '$COPY_POD_NAME' does not exist" <<<"$output" \
  || fail "delete did not say the Pod was already gone"
grep -q "checking for leftover kata sandboxes" <<<"$output" \
  || fail "the already-gone path skipped the sandbox check"

# ── 8. Negative control: a missing namespace stops before the build ──────────
# The preflight is only worth its round trip if it runs first: a namespace typo has to cost a
# second, not the tens of minutes of compiling, committing and pushing an image that then cannot
# be applied anywhere.

unset RUN_OLLAMA_DIR
commit_before="$(grep -c '^DOCKER commit ' "$MOCK_LOG" || true)"
apply_before="$(cat "$MOCK_STATE_DIR/apply-count")"
RUN_ENV=(MOCK_NO_NAMESPACE=true)
run_deploy create --model qwen2.5-coder:0.5b
RUN_ENV=()
[[ $status -ne 0 ]] || fail "a missing namespace was accepted"
grep -q "namespace" <<<"$output" || fail "the missing namespace was not named in the error"
[[ "$(grep -c '^DOCKER commit ' "$MOCK_LOG" || true)" == "$commit_before" ]] \
  || fail "an image was built before the preflight had vetted the target namespace"
[[ "$(cat "$MOCK_STATE_DIR/apply-count")" == "$apply_before" ]] \
  || fail "the manifest was applied even though the target namespace does not exist"

# ── 9. No running CoCo Pod: cc_init_data comes from the host's file ──────────
# A freshly booted cluster has only runc system Pods, and the guest still needs the annotation to
# trust the local registry's certificate. The host keeps the same value in a file written when the
# CoCo runtime was set up, so creation reads it instead of failing and asking for an export.

mkdir -p "$MOCK_REMOTE_ROOT/root"
printf 'FILE_CC_INIT_DATA' > "$MOCK_REMOTE_ROOT/root/cc_init_data.txt"
RUN_ENV=(MOCK_NO_CC_INIT_DATA=true)
run_deploy create --model qwen2.5-coder:0.5b
RUN_ENV=()
[[ $status -eq 0 ]] || fail "create with no CoCo Pod running exited $status"
grep -q "cc_init_data read from /root/cc_init_data.txt" <<<"$output" \
  || fail "the deployment did not report reading cc_init_data from the host file"
grep -q 'cc_init_data: "FILE_CC_INIT_DATA"$' "$MOCK_STATE_DIR/applied.yaml" \
  || fail "the cc_init_data read from the file did not reach the manifest"

# ── 10. Unchanged inputs reuse the committed image ──────────────────────────
# The builder phase imports the ollama payload into a container and commits a multi-gigabyte
# layer, which is minutes of work. A rerun whose inputs are identical must not repeat it: the
# image records a fingerprint of everything the commit depends on, and the mock replays it on the
# next inspect. The negative control matters more than the positive one -- a fingerprint that
# misses an input would silently deploy the old image as the new tree.

LABEL_FILE="$TMP_DIR/image-fingerprint"
rm -f "$LABEL_FILE" "$MOCK_STATE_DIR/pod"
RUN_ENV=(MOCK_COMMIT_LABEL_FILE="$LABEL_FILE")
run_deploy create --model qwen2.5-coder:0.5b
RUN_ENV=()
[[ $status -eq 0 ]] || fail "the fingerprint-recording run exited $status"
[[ -s "$LABEL_FILE" ]] || fail "the committed image does not record a payload fingerprint"

commit_before="$(grep -c '^DOCKER commit ' "$MOCK_LOG" || true)"
rm -f "$MOCK_STATE_DIR/pod"
RUN_ENV=(MOCK_IMAGE_LABEL_FILE="$LABEL_FILE")
run_deploy create --model qwen2.5-coder:0.5b
RUN_ENV=()
[[ $status -eq 0 ]] || fail "the unchanged-input rerun exited $status"
grep -q "reusing the local image teellm:$TODAY_TAG" <<<"$output" \
  || fail "an unchanged tree was not recognized as already built"
if grep -q "streaming the ollama runtime" <<<"$output"; then
  fail "the payload was imported again even though nothing changed"
fi
[[ "$(grep -c '^DOCKER commit ' "$MOCK_LOG" || true)" == "$commit_before" ]] \
  || fail "the image was committed again even though nothing changed"

# A change inside a directory the payload list names is the input a per-file check is most likely
# to miss, and missing it would deploy the previous bundle as the new tree. The file lives under
# models/cache, which the list names as a directory; tar streams it recursively.
rm -f "$MOCK_STATE_DIR/pod"
printf 'more' >> "$OLLAMA_DIR/models/cache/partial"
RUN_ENV=(MOCK_IMAGE_LABEL_FILE="$LABEL_FILE")
run_deploy create --model qwen2.5-coder:0.5b
RUN_ENV=()
[[ $status -eq 0 ]] || fail "the changed-input run exited $status"
if grep -q "reusing the local image" <<<"$output"; then
  fail "a changed payload was reused as the previous image"
fi
[[ "$(grep -c '^DOCKER commit ' "$MOCK_LOG" || true)" == "$((commit_before + 1))" ]] \
  || fail "a changed payload did not cause a new commit"

# ── 11. Identical content under an earlier day's tag is reused ──────────────
# The tag is the build date, so the first deployment of a new day would otherwise re-import and
# re-commit an image the host already holds under a different name. The fingerprint is over the
# content, not over the tag, so a match under another tag is the same image.
commit_before="$(grep -c '^DOCKER commit ' "$MOCK_LOG" || true)"
rm -f "$MOCK_STATE_DIR/pod"
RUN_ENV=(MOCK_REUSE_IMAGE="teellm:20250101")
run_deploy create --model qwen2.5-coder:0.5b
RUN_ENV=()
[[ $status -eq 0 ]] || fail "the cross-tag reuse run exited $status"
grep -q "reusing teellm:20250101 as teellm:$TODAY_TAG" <<<"$output" \
  || fail "an identical image under an earlier day's tag was not reused"
grep -q "^DOCKER tag teellm:20250101 teellm:$TODAY_TAG" "$MOCK_LOG" \
  || fail "the reused image was not retagged to today's name"
[[ "$(grep -c '^DOCKER commit ' "$MOCK_LOG" || true)" == "$commit_before" ]] \
  || fail "the image was committed even though an identical one already existed"

# ── 12. A changed source image invalidates the cached stripped base ─────────
# The stripped base is cached under a date tag, so an unchanged existence test would keep serving
# a base derived from an older source for the rest of the day. The source image ID is recorded on
# the derived image; a mismatch rebuilds the derivation, a match skips it.
rm -f "$MOCK_STATE_DIR/pod"
RUN_ENV=(MOCK_IMAGE_LABEL_FILE="$LABEL_FILE" MOCK_BASE_SOURCE_LABEL="sha256:stale")
run_deploy create --model qwen2.5-coder:0.5b
RUN_ENV=()
[[ $status -eq 0 ]] || fail "the stale-base run exited $status"
grep -q "building the TAA-free base image" <<<"$output" \
  || fail "a derived base built from another source image was reused"

rm -f "$MOCK_STATE_DIR/pod"
RUN_ENV=(MOCK_IMAGE_LABEL_FILE="$LABEL_FILE" \
         MOCK_BASE_SOURCE_LABEL="sha256:1111111111111111111111111111111111111111111111111111111111111111")
run_deploy create --model qwen2.5-coder:0.5b
RUN_ENV=()
[[ $status -eq 0 ]] || fail "the current-base run exited $status"
if grep -q "building the TAA-free base image" <<<"$output"; then
  fail "the derived base was rebuilt even though it already came from this source image"
fi

# ── 13. Editing the build instructions invalidates the image ────────────────
# The copies, the soname-link fixup and the .teellm-model write run as shell text inside the
# build function, so editing them changes the image while leaving every file on disk untouched.
# Hashing that text is what stops such an edit from being deployed as the previous image.
FUNC_LABEL_FILE="$TMP_DIR/image-fingerprint-func"
rm -f "$FUNC_LABEL_FILE" "$MOCK_STATE_DIR/pod"
RUN_ENV=(MOCK_COMMIT_LABEL_FILE="$FUNC_LABEL_FILE")
run_deploy create --model qwen2.5-coder:0.5b
RUN_ENV=()
[[ $status -eq 0 ]] || fail "the instruction-fingerprint recording run exited $status"

commit_before="$(grep -c '^DOCKER commit ' "$MOCK_LOG" || true)"
rm -f "$MOCK_STATE_DIR/pod"
RUN_ENV=(MOCK_IMAGE_LABEL_FILE="$FUNC_LABEL_FILE")
run_deploy create --model qwen2.5-coder:0.5b
RUN_ENV=()
[[ $status -eq 0 ]] || fail "the unchanged-instructions run exited $status"
grep -q "reusing the local image" <<<"$output" \
  || fail "identical instructions were not recognized as already built"

cp "$REPO/deploy-llm.sh" "$TMP_DIR/deploy-llm.sh.pristine"
awk '{ print } /^build_teellm_pod_image\(\) \{$/ && !done { print "  : # test-only edit of the build instructions"; done = 1 }' \
  "$TMP_DIR/deploy-llm.sh.pristine" > "$REPO/deploy-llm.sh"
rm -f "$MOCK_STATE_DIR/pod"
RUN_ENV=(MOCK_IMAGE_LABEL_FILE="$FUNC_LABEL_FILE")
run_deploy create --model qwen2.5-coder:0.5b
RUN_ENV=()
[[ $status -eq 0 ]] || fail "the edited-instructions run exited $status"
if grep -q "reusing the local image" <<<"$output"; then
  fail "an image built by different instructions was reused"
fi
[[ "$(grep -c '^DOCKER commit ' "$MOCK_LOG" || true)" == "$((commit_before + 1))" ]] \
  || fail "editing the build instructions did not cause a new commit"
cp "$TMP_DIR/deploy-llm.sh.pristine" "$REPO/deploy-llm.sh"

# ── 14. update: only an existing Pod, and it never creates or deletes one ───
# update names its own target and refuses the cases that would take the Pod's lifecycle out of
# the operator's hands. The target Pod has exactly one spelling, --pod; the removed spellings are
# refused before anything touches the cluster, so a stale script cannot quietly deploy elsewhere.

apply_before="$(cat "$MOCK_STATE_DIR/apply-count")"
delete_before="$(grep -c '^KUBECTL delete ' "$MOCK_LOG" || true)"
run_deploy update
[[ $status -eq 0 ]] || fail "update on an existing Pod exited $status"
[[ "$(cat "$MOCK_STATE_DIR/apply-count")" == "$apply_before" ]] \
  || fail "update applied a manifest instead of updating the running Pod"
[[ "$(grep -c '^KUBECTL delete ' "$MOCK_LOG" || true)" == "$delete_before" ]] \
  || fail "update deleted something"
grep -q "updating it in place" <<<"$output" || fail "update did not report touching the existing Pod"
if grep -q "$DEFAULT_POD_NAME" "$MOCK_LOG"; then
  fail "update was aimed at the default target Pod ($DEFAULT_POD_NAME)"
fi

# A Pod that is not there is reported as that, and is not created: update's whole contract is that
# the Pod's lifecycle stays with create and delete.
rm -f "$MOCK_STATE_DIR/pod"
run_deploy update
[[ $status -ne 0 ]] || fail "update accepted a Pod that does not exist"
grep -q "TEE-LLM Pod '$COPY_POD_NAME' does not exist" <<<"$output" \
  || fail "update did not name the missing Pod"
grep -q -- "create" <<<"$output" \
  || fail "the missing-Pod refusal does not say how to create it"
[[ -f "$MOCK_STATE_DIR/pod" ]] && fail "update created the Pod"
[[ "$(cat "$MOCK_STATE_DIR/apply-count")" == "$apply_before" ]] \
  || fail "update applied a manifest for a Pod it then refused to create"

# The removed target-Pod spellings fail before they touch anything: --pod is the only one left,
# so a stale script must be told to change rather than silently fall back to the default Pod.
before="$(kubectl_lines)"
RUN_ENV=(TARGET_POD="$COPY_POD_NAME")
run_deploy start
RUN_ENV=()
[[ $status -ne 0 ]] || fail "the TARGET_POD environment variable was accepted"
grep -q "TARGET_POD is no longer supported" <<<"$output" \
  || fail "the refusal does not say the environment variable is retired"
grep -q -- "--pod <name>" <<<"$output" || fail "the refusal does not point at --pod"
[[ "$(kubectl_lines)" == "$before" ]] || fail "the refusal happened only after touching the cluster"

RUN_ENV=(TARGET_NAMESPACE=demo-ns)
run_deploy start
RUN_ENV=()
[[ $status -ne 0 ]] || fail "the TARGET_NAMESPACE environment variable was accepted"
grep -q "TARGET_NAMESPACE is no longer supported" <<<"$output" \
  || fail "the refusal does not say the namespace variable is retired"

run_deploy pod="$COPY_POD_NAME" start
[[ $status -ne 0 ]] || fail "the positional 'pod=<name>' spelling was accepted"
[[ "$(kubectl_lines)" == "$before" ]] || fail "a removed spelling reached the cluster"

# Creating and updating are different actions; asking for both is refused rather than resolved.
run_deploy create update
[[ $status -ne 0 ]] || fail "'create update' was accepted"
grep -q "cannot specify multiple actions (create and update)" <<<"$output" \
  || fail "the create/update conflict is not explained"

echo "PASS: the dedicated TEE-LLM Pod is created once, refused when it already exists, gated on its CSV device, is what the bare invocation deploys into, and is only ever updated by the update action"
