#!/usr/bin/env bash
# Combined entrypoint for the unified FHE + TAA container.
#
# The handoff image's own /opt/entrypoint.sh starts redis, api_server and the
# worker, then waits on all of them and exits when any one dies. This wrapper
# starts that entrypoint unchanged and puts the TAA supervisor beside it, so one
# container serves both sides and they share a network namespace: TAA reaches
# the FHE API at 127.0.0.1:58996 and the FHE callback reaches TAA at
# 127.0.0.1:6001 without publishing either port.
#
# Liveness is decided by the FHE entrypoint. If redis, api_server or the worker
# exits, this wrapper stops TAA and exits with that status, which is what lets
# the container restart policy act. The TAA supervisor is restarted here only
# when it exits on its own.
set -uo pipefail

FHE_ENTRYPOINT="${FHE_ENTRYPOINT:-/opt/entrypoint.sh}"
TAA_WORKDIR="${TAA_WORKDIR:-/root/taa}"
TAA_RESTART_DELAY="${TAA_RESTART_DELAY:-10}"

fhe_pid=""
taa_pid=""
stopping=0

log() { printf '%s [taa-fhe] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }

stop_children() {
  [ "$stopping" = 1 ] && return 0
  stopping=1
  if [ -n "$taa_pid" ]; then kill -TERM "$taa_pid" 2>/dev/null || true; fi
  if [ -n "$fhe_pid" ]; then kill -TERM "$fhe_pid" 2>/dev/null || true; fi
}

on_term() {
  stop_children
  if [ -n "$fhe_pid" ]; then wait "$fhe_pid" 2>/dev/null || true; fi
  exit 0
}
trap on_term TERM INT

if [ ! -x "$FHE_ENTRYPOINT" ]; then
  log "missing or non-executable $FHE_ENTRYPOINT"
  exit 1
fi
"$FHE_ENTRYPOINT" &
fhe_pid=$!
log "FHE entrypoint started (pid $fhe_pid)"

# ./start.sh is the supervisor deploy.sh installs. It cds to the workdir, holds
# a singleton flock, runs ./taa and restarts it every 10 seconds. Running it
# through exec makes $! the supervisor itself, so the TERM below reaches it
# directly instead of a subshell that would leave it orphaned.
start_taa() {
  if [ -x "$TAA_WORKDIR/start.sh" ]; then
    ( cd "$TAA_WORKDIR" && exec ./start.sh ) &
    taa_pid=$!
    log "TAA supervisor started (pid $taa_pid)"
  else
    taa_pid=""
    log "$TAA_WORKDIR/start.sh is missing; retrying in ${TAA_RESTART_DELAY}s"
  fi
}
start_taa

while :; do
  if [ -n "$taa_pid" ]; then
    wait -n "$fhe_pid" "$taa_pid" 2>/dev/null || true
  else
    # Nothing to wait on yet. Blocking in `wait -n "$fhe_pid"` here would park
    # the loop until the FHE entrypoint dies and never retry a workdir that was
    # created after the container started (the deploy copies it in, the image
    # does not ship it), so tick instead.
    sleep 1 &
    wait $! 2>/dev/null || true
  fi

  if ! kill -0 "$fhe_pid" 2>/dev/null; then
    wait "$fhe_pid"
    rc=$?
    log "FHE entrypoint exited with status $rc; stopping TAA"
    stop_children
    if [ -n "$taa_pid" ]; then wait "$taa_pid" 2>/dev/null || true; fi
    exit "$rc"
  fi

  [ "$stopping" = 1 ] && continue

  if [ -z "$taa_pid" ] || ! kill -0 "$taa_pid" 2>/dev/null; then
    if [ -n "$taa_pid" ]; then
      wait "$taa_pid" 2>/dev/null || true
      log "TAA supervisor exited; restarting in ${TAA_RESTART_DELAY}s"
    else
      log "TAA supervisor is not running; retrying in ${TAA_RESTART_DELAY}s"
    fi
    taa_pid=""
    sleep "$TAA_RESTART_DELAY" &
    wait $! 2>/dev/null || true
    [ "$stopping" = 1 ] && continue
    start_taa
  fi
done
