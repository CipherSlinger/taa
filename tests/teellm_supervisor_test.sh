#!/usr/bin/env bash
# Guards the TEE-LLM Pod supervisor (deploy/teellm-supervisor.sh).
#
# The Pod's PID 1 used to be `sleep infinity`, so teellm-service and ollama were unowned orphans:
# restartPolicy only reacts to PID 1 exiting, and the Pod template has no liveness probe, so a
# dead daemon stayed dead until someone re-ran the deployment. The supervisor is now what keeps
# them alive, which makes these behaviours load-bearing:
#
#   * teellm-service is restarted after it exits;
#   * ollama is restarted when it disappears, even while teellm-service keeps running;
#   * the pause file keeps both daemons down, so the deployment can stream a new binary and model
#     over the live tree without a half-written file being executed;
#   * the model named by the deployment is passed to teellm-service, so `models switch` survives
#     reusing an existing Pod;
#   * a restart request re-execs the supervisor, which is how an updated supervisor script takes
#     effect without recreating the Pod (and its CSV2 guest).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUPERVISOR="$ROOT_DIR/deploy/teellm-supervisor.sh"

for tool in timeout; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "SKIP: $tool is required to run the supervisor test"
    exit 0
  fi
done

TMP_DIR="$(mktemp -d)"
SUP_PID=""
cleanup() {
  if [[ -n "$SUP_PID" ]]; then
    kill "$SUP_PID" 2>/dev/null || true
    wait "$SUP_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

if [[ ! -x "$SUPERVISOR" ]]; then
  echo "FAIL: supervisor script missing or not executable: $SUPERVISOR" >&2
  exit 1
fi

# ── Fakes ────────────────────────────────────────────────────────────────────
# curl/pgrep answer from a marker file, so "ollama is up" is something the test controls, and
# start-ollama.sh creates the marker instead of binding a socket.

MOCK_BIN="$TMP_DIR/bin"
mkdir -p "$MOCK_BIN"
cat > "$MOCK_BIN/curl" <<'MOCK'
#!/bin/sh
[ -f "$OLLAMA_MARKER" ] && exit 0 || exit 1
MOCK
cat > "$MOCK_BIN/pgrep" <<'MOCK'
#!/bin/sh
[ -f "$OLLAMA_MARKER" ] && exit 0 || exit 1
MOCK
chmod +x "$MOCK_BIN"/*

fail() {
  echo "FAIL: $1" >&2
  if [[ -n "${WORK:-}" && -f "$WORK/teellm-service.log" ]]; then
    echo "--- supervisor log ---" >&2
    cat "$WORK/teellm-service.log" >&2
  fi
  exit 1
}

# Creates a throwaway /root/taa equivalent. $1 names the case; $2 is the fake service body.
new_work() {
  WORK="$TMP_DIR/work-$1"
  mkdir -p "$WORK/configs" "$WORK/ollama"
  printf '{}\n' > "$WORK/configs/teellm-production.json"
  cat > "$WORK/ollama/start-ollama.sh" <<SH
#!/bin/sh
touch "$WORK/ollama-up"
exit 0
SH
  chmod +x "$WORK/ollama/start-ollama.sh"
  cat > "$WORK/teellm-service" <<SH
#!/bin/sh
printf '%s\n' "\$*" >> "$WORK/service-args"
$2
SH
  chmod +x "$WORK/teellm-service"
  export OLLAMA_MARKER="$WORK/ollama-up"
}

start_supervisor() {
  TEELLM_WORKDIR="$WORK" \
  OLLAMA_DIR="$WORK/ollama" \
  TEELLM_SUPERVISOR_CHECK_INTERVAL=1 \
  TEELLM_SUPERVISOR_RESTART_DELAY=1 \
  TEELLM_SUPERVISOR_OLLAMA_WAIT=3 \
  PATH="$MOCK_BIN:$PATH" \
  OLLAMA_MARKER="$OLLAMA_MARKER" \
    timeout 20 "$SUPERVISOR" >> "$TMP_DIR/supervisor.out" 2>&1 &
  SUP_PID=$!
}

stop_supervisor() {
  if [[ -n "$SUP_PID" ]]; then
    kill "$SUP_PID" 2>/dev/null || true
    wait "$SUP_PID" 2>/dev/null || true
    SUP_PID=""
  fi
}

# wait_for <description> <file> [minimum line count]
wait_for_lines() {
  local what="$1" file="$2" want="${3:-1}" i
  for i in $(seq 1 100); do
    if [[ -f "$file" ]] && [[ "$(wc -l < "$file")" -ge "$want" ]]; then
      return 0
    fi
    sleep 0.1
  done
  fail "timed out waiting for $what ($file)"
}

# ── 1. teellm-service is restarted after it exits ────────────────────────────
# The old Pod left it dead, because nothing owned the process.

new_work restart-service 'exit 1'
start_supervisor
wait_for_lines "two teellm-service attempts" "$WORK/service-args" 2
stop_supervisor
grep -q "teellm-service exited with code 1" "$WORK/teellm-service.log" \
  || fail "the supervisor did not log the service exit"
grep -q -- "-config $WORK/configs/teellm-production.json" "$WORK/service-args" \
  || fail "teellm-service was not started with the production config"

# ── 2. ollama is restarted while teellm-service keeps running ────────────────
# The supervisor's own loop blocks on the service, so a check that only runs between service
# exits would leave a dead ollama in place for as long as the service lives.

new_work restart-ollama 'sleep 60'
start_supervisor
for _ in $(seq 1 100); do [[ -f "$OLLAMA_MARKER" ]] && break; sleep 0.1; done
[[ -f "$OLLAMA_MARKER" ]] || fail "the supervisor did not start ollama"
rm -f "$OLLAMA_MARKER"
for _ in $(seq 1 100); do [[ -f "$OLLAMA_MARKER" ]] && break; sleep 0.1; done
[[ -f "$OLLAMA_MARKER" ]] || fail "the supervisor did not restart ollama after it disappeared"
stop_supervisor

# ── 3. The pause file keeps both daemons down ────────────────────────────────
# The deployment streams binaries and models over the live tree; a daemon starting mid-stream
# executes a half-written file.

new_work pause 'exit 1'
touch "$WORK/.teellm-supervisor-pause"
start_supervisor
sleep 3
[[ ! -f "$WORK/service-args" ]] || fail "teellm-service was started while paused"
[[ ! -f "$OLLAMA_MARKER" ]] || fail "ollama was started while paused"
rm -f "$WORK/.teellm-supervisor-pause"
wait_for_lines "teellm-service after the pause was lifted" "$WORK/service-args" 1
stop_supervisor

# ── 4. The model is read from the deployment's selection file ────────────────
# A reused Pod keeps its env, so the model cannot live only in the template.

new_work model 'exit 1'
printf 'qwen2.5-coder:3b\n' > "$WORK/.teellm-model"
start_supervisor
wait_for_lines "teellm-service with a selected model" "$WORK/service-args" 1
stop_supervisor
grep -q -- "-model qwen2.5-coder:3b" "$WORK/service-args" \
  || fail "the selected model was not passed to teellm-service"

# ── 5. A restart request re-execs the supervisor ─────────────────────────────
# An updated supervisor script cannot replace a running one in place, and recreating the Pod
# would throw away the CSV2 guest's writable layer.

new_work reexec 'sleep 60'
start_supervisor
for _ in $(seq 1 100); do [[ -f "$WORK/service-args" ]] && break; sleep 0.1; done
touch "$WORK/.teellm-supervisor-restart"
for _ in $(seq 1 100); do
  [[ "$(grep -c "supervisor started" "$WORK/teellm-service.log" 2>/dev/null || echo 0)" -ge 2 ]] && break
  sleep 0.1
done
stop_supervisor
grep -q "restart requested" "$WORK/teellm-service.log" \
  || fail "the supervisor did not act on the restart request"
[[ "$(grep -c "supervisor started" "$WORK/teellm-service.log")" -ge 2 ]] \
  || fail "the supervisor did not re-exec itself after the restart request"

echo "PASS: the TEE-LLM Pod supervisor restarts both daemons, honours the pause file, passes the selected model, and re-execs on request"
