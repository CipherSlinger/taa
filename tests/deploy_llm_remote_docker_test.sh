#!/usr/bin/env bash
# Verifies the remote-docker target: the deployment body must reach the container through the
# remote host's docker daemon, never the local one, and must stage files on the host before
# docker cp (the daemon resolves both docker cp paths on its own host).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# The smallest model in the offline bundle keeps the exercised transfer cheap. Without it there
# is nothing to stream, so the transfer assertions would be vacuous.
MODEL="qwen2.5-coder:0.5b"
if [[ ! -f "$ROOT_DIR/teellm/models/ollama/models/models/manifests/registry.ollama.ai/library/qwen2.5-coder/0.5b" ]]; then
  echo "SKIP: offline bundle has no $MODEL to transfer"
  exit 0
fi

MOCK_BIN="$TMP_DIR/bin"
MOCK_LOG="$TMP_DIR/commands.log"
MOCK_REMOTE_ROOT="$TMP_DIR/remote"
mkdir -p "$MOCK_BIN" "$MOCK_REMOTE_ROOT"
: > "$MOCK_LOG"
export MOCK_LOG MOCK_REMOTE_ROOT

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

# docker, standing in for the remote host's daemon. The presence checks are answered so that the
# script takes the incremental model transfer path: the runtime is there, the model is not. The
# running daemon advertises a different model, which is the state a container that shipped the
# older layout is in, so the script has to replace it rather than reuse it.
cat > "$MOCK_BIN/docker" <<'MOCK'
#!/usr/bin/env bash
cmd="${1:-}"; shift || true
case "$cmd" in
  info) exit 0 ;;
  ps) echo "taa-env-slim-v2"; exit 0 ;;
  inspect) echo "taa-env:slim-v2 running 172.17.0.2"; exit 0 ;;
  start) exit 0 ;;
  cp)
    echo "DOCKER cp $*" >> "$MOCK_LOG"
    [[ -e "$1" ]] || { echo "docker cp source missing: $1" >&2; exit 1; }
    exit 0
    ;;
  exec)
    echo "DOCKER exec $*" >> "$MOCK_LOG"
    if [[ "$*" == *"tar -xf"* ]]; then cat >/dev/null; exit 0; fi
    if [[ "$*" == *"-probe"* ]]; then exit 0; fi
    if [[ "$*" == *"test -s"* ]]; then exit 1; fi
    if [[ "$*" == *"pgrep -x ollama"* ]]; then exit 1; fi   # the daemon dies when killed
    if [[ "$*" == *"/api/tags"* ]]; then echo '{"models":[{"name":"qwen2.5-coder:3b"}]}'; exit 0; fi
    exit 0
    ;;
  *) exit 0 ;;
esac
MOCK

# iptables, standing in for the remote host's firewall. The test may run as root, and the real
# command would then install a FORWARD rule on the machine running the tests.
cat > "$MOCK_BIN/iptables" <<'MOCK'
#!/usr/bin/env bash
echo "IPTABLES $*" >> "$MOCK_LOG"
case "${1:-}" in
  -C) exit 1 ;;   # the rule is not there yet, so the script has to add it
  -I) exit 0 ;;
  *) exit 0 ;;
esac
MOCK

chmod +x "$MOCK_BIN"/*

set +e
output="$(PATH="$MOCK_BIN:$PATH" \
  OLLAMA_READY_TIMEOUT=2 \
  OLLAMA_READY_INTERVAL=1 \
  timeout 900 "$ROOT_DIR/deploy-llm.sh" remote-docker start --model "$MODEL" 2>&1)"
status=$?
set -e

fail() {
  echo "FAIL: $1" >&2
  echo "$output" >&2
  exit 1
}

[[ $status -eq 0 ]] || fail "remote-docker start exited $status"

grep -q "SSH\[root@172.16.10.178\] docker 'exec' '-i' 'taa-env-slim-v2'" "$MOCK_LOG" \
  || fail "docker commands were not routed over the SSH hop"
grep -q "DOCKER exec -i taa-env-slim-v2 tar -xf -" "$MOCK_LOG" \
  || fail "ollama bundle was not streamed into the container"

# Staged on the host, then copied into the container from there.
grep -q "SCP\[.* -> $MOCK_REMOTE_ROOT/root/taa/stage/teellm-service\]" "$MOCK_LOG" \
  || fail "teellm-service binary was not staged on the remote host"
grep -q "DOCKER cp $MOCK_REMOTE_ROOT/root/taa/stage/teellm-service taa-env-slim-v2" "$MOCK_LOG" \
  || fail "staged teellm-service binary was not copied into the container"
grep -q "DOCKER cp $MOCK_REMOTE_ROOT/root/taa/stage/teellm-docker.json taa-env-slim-v2" "$MOCK_LOG" \
  || fail "staged configuration was not copied into the container"

# A daemon that cannot serve the deployed model must be replaced, not reused.
grep -q "replacing the ollama daemon already listening" <<<"$output" \
  || fail "a daemon serving another model set was reused instead of replaced"
grep -q "DOCKER exec.*pkill -x ollama" "$MOCK_LOG" \
  || fail "the stale ollama daemon was never stopped"

# A bridge-networked container is invisible to cluster pods unless the host forwards to it, and
# docker's own DOCKER chain drops exactly that traffic.
grep -q "IPTABLES -C FORWARD -s 10.244.0.0/16 -d 172.17.0.2/32 -p tcp --dport 8443 -j ACCEPT" "$MOCK_LOG" \
  || fail "the pod-to-gateway FORWARD rule was never checked"
grep -q "IPTABLES -I FORWARD 1 -s 10.244.0.0/16 -d 172.17.0.2/32 -p tcp --dport 8443 -j ACCEPT" "$MOCK_LOG" \
  || fail "pods were left unable to reach the gateway container"

# The summary has to hand over what a follow-up taa deployment needs.
grep -q "Container  : taa-env-slim-v2 (running)" <<<"$output" || fail "container name missing from the summary"
grep -q "Image      : taa-env:slim-v2" <<<"$output" || fail "container image missing from the summary"
grep -q "Container IP: 172.17.0.2" <<<"$output" || fail "container IP missing from the summary"
grep -q "Endpoint (inside the container)     : https://127.0.0.1:8443" <<<"$output" \
  || fail "in-container endpoint missing from the summary"
grep -q "Endpoint (host / other containers)  : https://172.17.0.2:8443" <<<"$output" \
  || fail "container-IP endpoint missing from the summary"
grep -q "TAA_LLM_ENDPOINT, taa elsewhere on the host: https://172.17.0.2:8443" <<<"$output" \
  || fail "TAA_LLM_ENDPOINT hint missing from the summary"

echo "PASS: remote-docker deploy reaches the remote container and prints its details"
