#!/bin/sh
# TEE-LLM Pod supervisor: owns teellm-service and ollama inside the Pod, and is PID 1.
#
# Why this exists: the Pod's container command used to end in `sleep infinity`, so both daemons
# were unowned orphans. `restartPolicy: Always` only reacts to PID 1 exiting and the Pod has no
# liveness probe, so a dead teellm-service or ollama stayed dead until someone re-ran the
# deployment -- and a restart of the container would have been the only alternative, reloading
# the model with it.
#
# The deployment drives this supervisor through files under the working directory, because a
# `kubectl exec` session cannot own a process that outlives it:
#
#   .teellm-supervisor-pause    both daemons stay down while it exists. The deployment sets it
#                               before it overwrites the binary or streams a model into the live
#                               tree, so nothing executes a half-written file.
#   .teellm-supervisor-restart  re-exec this script, so an updated copy takes effect without
#                               recreating the Pod (which would throw away the CSV2 guest's
#                               writable layer and the model in it).
#   .teellm-model               the model the deployment selected. A reused Pod keeps the env it
#                               was created with, so `--model` cannot live in the template alone.
#
# The Ollama check runs inside the teellm-service loop, not only between service restarts: the
# service can run for days, and a supervisor that only noticed a dead ollama on the next service
# exit would leave inference broken for exactly that long.
#
# Environment (all optional, defaults match the Pod):
#   TEELLM_WORKDIR                     /opt/teellm
#   OLLAMA_DIR                         $TEELLM_WORKDIR/ollama
#   OLLAMA_HOST                        127.0.0.1:11434
#   TEELLM_CONFIG                      $TEELLM_WORKDIR/configs/teellm-production.json
#   TEELLM_MODEL                       fallback model when .teellm-model is absent
#   TEELLM_SUPERVISOR_CHECK_INTERVAL   seconds between health checks (default 5)
#   TEELLM_SUPERVISOR_RESTART_DELAY    seconds before restarting a dead daemon (default 10)
#   TEELLM_SUPERVISOR_OLLAMA_WAIT      seconds to wait for ollama to answer (default 30)
set -u

WORKDIR="${TEELLM_WORKDIR:-/opt/teellm}"
OLLAMA_DIR="${OLLAMA_DIR:-$WORKDIR/ollama}"
OLLAMA_HOST="${OLLAMA_HOST:-127.0.0.1:11434}"
CONFIG="${TEELLM_CONFIG:-$WORKDIR/configs/teellm-production.json}"

MODEL_FILE="$WORKDIR/.teellm-model"
PAUSE_FILE="$WORKDIR/.teellm-supervisor-pause"
RESTART_FILE="$WORKDIR/.teellm-supervisor-restart"
PID_FILE="$WORKDIR/.teellm-supervisor.pid"
LOCK_FILE="$WORKDIR/.teellm-supervisor.lock"
LOG_FILE="$WORKDIR/teellm-service.log"
OLLAMA_LOG_FILE="$WORKDIR/ollama.log"

CHECK_INTERVAL="${TEELLM_SUPERVISOR_CHECK_INTERVAL:-5}"
RESTART_DELAY="${TEELLM_SUPERVISOR_RESTART_DELAY:-10}"
OLLAMA_WAIT="${TEELLM_SUPERVISOR_OLLAMA_WAIT:-30}"

TEELLM_CHILD=""
OLLAMA_MISSING_WARNED=""

cd "$WORKDIR" 2>/dev/null || {
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ): working directory $WORKDIR is not reachable" >&2
  exit 1
}

log() {
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ): $*" >> "$LOG_FILE"
}

# Singleton. Two ways in: the container command on a Pod created with this template, and the
# deployment's fallback on a Pod that predates the supervisor (its PID 1 is still `sleep infinity`,
# so nothing inside will ever exec the script). Both can race; the loser exits rather than fight
# for :8443. flock is kernel state released when the process dies, so a stale file can never wedge
# the Pod. The pid file below is not the lock -- it is how the deployment asks whether a copy is
# already running.
exec 9>"$LOCK_FILE"
if command -v flock >/dev/null 2>&1; then
  if ! flock -n 9; then
    log "another supervisor holds the lock; exiting"
    exit 0
  fi
fi
echo $$ > "$PID_FILE"

# Installed only after the lock is held, so a copy that loses the race cannot remove the winner's
# pid file.
cleanup() {
  rm -f "$PID_FILE"
  if [ -n "$TEELLM_CHILD" ]; then
    kill -TERM "$TEELLM_CHILD" 2>/dev/null || true
    wait "$TEELLM_CHILD" 2>/dev/null || true
  fi
  exit 0
}
trap cleanup SIGTERM SIGINT

# A process can hold the port while being unable to answer; treat either signal as alive. The
# process check also keeps a slow model load (which can outlast the wait below) from being read
# as a crash and duplicated: a second ollama would only fail to bind.
#
# The name check must ignore zombies. A killed process keeps its name until its parent reaps it,
# and `pgrep -x` matches it with exit 0; on a Pod whose PID 1 is `sleep infinity` nothing reaps,
# so a killed ollama would look alive for the container's whole lifetime. That is not theoretical:
# a deployment stopped the daemons, the killed ollama was reparented to PID 1 and stayed a
# zombie, this check reported it alive, no new ollama was started, and the deployment waited out
# its full readiness timeout with no backend at all.
process_is_live() {
  local state
  state="$(awk '{print $3}' "/proc/$1/stat" 2>/dev/null)"
  [ -n "$state" ] && [ "$state" != "Z" ]
}

ollama_alive() {
  if curl -fsS "http://$OLLAMA_HOST/api/tags" >/dev/null 2>&1; then
    return 0
  fi
  if command -v pgrep >/dev/null 2>&1; then
    local pid
    for pid in $(pgrep -x ollama 2>/dev/null); do
      process_is_live "$pid" && return 0
    done
  fi
  return 1
}

ensure_ollama() {
  # While paused the deployment may be streaming a new runtime over the live tree.
  [ -f "$PAUSE_FILE" ] && return 0
  ollama_alive && return 0
  if [ ! -x "$OLLAMA_DIR/start-ollama.sh" ]; then
    # Once per absence, not once per check: this runs every few seconds.
    if [ "$OLLAMA_MISSING_WARNED" != "1" ]; then
      log "warning: $OLLAMA_DIR/start-ollama.sh is missing or not executable; cannot start ollama"
      OLLAMA_MISSING_WARNED=1
    fi
    return 0
  fi
  OLLAMA_MISSING_WARNED=""

  log "ollama is not running; starting $OLLAMA_DIR/start-ollama.sh"
  # 9>&-: a child must not inherit the singleton lock, or killing the supervisor would leave the
  # lock held by an orphan and no future copy could start.
  ( cd "$OLLAMA_DIR" && OLLAMA_HOST="$OLLAMA_HOST" ./start-ollama.sh ) >> "$OLLAMA_LOG_FILE" 2>&1 9>&- &

  i=0
  while [ "$i" -lt "$OLLAMA_WAIT" ]; do
    if curl -fsS "http://$OLLAMA_HOST/api/tags" >/dev/null 2>&1; then
      log "ollama is ready"
      return 0
    fi
    sleep 1
    i=$((i + 1))
  done
  log "warning: ollama did not answer within ${OLLAMA_WAIT}s; leaving it to finish loading"
}

# The deployment writes the selection before lifting the pause, so a reused Pod follows
# `models switch` without being recreated.
current_model() {
  if [ -s "$MODEL_FILE" ]; then
    tr -d '\r\n' < "$MODEL_FILE"
  else
    printf '%s' "${TEELLM_MODEL:-}"
  fi
}

run_service() {
  local model
  model="$(current_model)"
  if [ -n "$model" ]; then
    log "starting teellm-service -config $CONFIG -model $model"
    "$WORKDIR/teellm-service" -config "$CONFIG" -model "$model" >> "$LOG_FILE" 2>&1 9>&- &
  else
    log "starting teellm-service -config $CONFIG"
    "$WORKDIR/teellm-service" -config "$CONFIG" >> "$LOG_FILE" 2>&1 9>&- &
  fi
  TEELLM_CHILD=$!

  while kill -0 "$TEELLM_CHILD" 2>/dev/null; do
    sleep "$CHECK_INTERVAL"
    if [ -f "$RESTART_FILE" ]; then
      log "restart requested; stopping teellm-service"
      kill -TERM "$TEELLM_CHILD" 2>/dev/null || true
      break
    fi
    ensure_ollama
  done

  wait "$TEELLM_CHILD" 2>/dev/null
  local rc=$?
  TEELLM_CHILD=""
  log "teellm-service exited with code $rc, restart in ${RESTART_DELAY}s"
}

log "supervisor started (workdir=$WORKDIR, pid=$$)"

while true; do
  if [ -f "$RESTART_FILE" ]; then
    rm -f "$RESTART_FILE"
    log "restart requested; re-exec $0"
    # The absolute path is what the Pod's container command uses, so this replaces PID 1 in
    # place and picks up the script the deployment just installed.
    exec "$0"
  fi

  if [ -f "$PAUSE_FILE" ]; then
    sleep "$CHECK_INTERVAL"
    continue
  fi

  ensure_ollama

  if [ ! -x "$WORKDIR/teellm-service" ]; then
    log "teellm-service is missing or not executable; retry in ${RESTART_DELAY}s"
    sleep "$RESTART_DELAY"
    continue
  fi
  if [ ! -f "$CONFIG" ]; then
    log "configuration $CONFIG is missing; retry in ${RESTART_DELAY}s"
    sleep "$RESTART_DELAY"
    continue
  fi

  run_service
  sleep "$RESTART_DELAY"
done
