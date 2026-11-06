#!/usr/bin/env bash
# Combined entrypoint for the unified FHE + TAA container, installed as
# /root/taa/taa-supervisor.sh (the same path every role uses).
#
# The handoff image's own /opt/entrypoint.sh starts redis, api_server and the
# worker, then waits on all of them and exits when any one dies. This entrypoint
# starts that script unchanged and puts the TAA restart loop beside it, so one
# container serves both sides and they share a network namespace: TAA reaches
# the FHE API at 127.0.0.1:58996 and the FHE callback reaches TAA at
# 127.0.0.1:6001 without publishing either port.
#
# The TAA loop runs as a child of this file (`bash <this file> --taa-loop`), not
# inline: deploy updates replace the file and signal the loop, and keeping the
# loop in a child means the update can kill and restart it without touching
# PID 1, which would restart the container and lose the guest's writable layer
# (and the FHE services) with it.
#
# Liveness is decided by the FHE entrypoint. If redis, api_server or the worker
# exits, this entrypoint stops TAA and exits with that status, which is what lets
# the container restart policy act. The TAA loop is restarted here only when it
# exits on its own.
set -uo pipefail

TAA_WORKDIR="${TAA_WORKDIR:-/root/taa}"
FHE_ENTRYPOINT="${FHE_ENTRYPOINT:-/opt/entrypoint.sh}"
TAA_RESTART_DELAY="${TAA_RESTART_DELAY:-10}"
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

# ── The TAA loop (child) ─────────────────────────────────────────────────────
# Selected by the parent below with --taa-loop. It is the same loop the tee role
# runs inline, so a role still has exactly one file to install.
if [ "${1:-}" = "--taa-loop" ]; then

# >>> TAA_LOOP -- keep byte-identical in deploy/taa-supervisor.sh,
# deploy/fhe/taa-supervisor.sh and deploy/dataanaylsis/taa-supervisor.sh: each role
# installs one self-contained file, so the loop cannot live in a shared file.
# tests/taa_supervisor_uniform_test.sh diffs this block across the three.
cd "$TAA_WORKDIR" || exit 1
LOG="$TAA_WORKDIR/taa.log"
LOCK="$TAA_WORKDIR/.taa-supervisor.lock"
TAAPID=""

cleanup() {
  if [ -n "$TAAPID" ]; then
    kill -TERM "$TAAPID" 2>/dev/null || true
  fi
  exit 0
}
trap cleanup SIGTERM SIGINT

# Singleton guard: only one supervisor may own taa. Two of them -- one started by
# each deploy script -- race for :6001 and interleave the same log file. flock is
# used instead of a pidfile because the lock is kernel state released when this
# process dies, so a stale lock can never wedge the container's ENTRYPOINT. Every
# child below closes the lock fd, so an orphaned daemon cannot keep the lock after
# the supervisor itself is gone.
exec 9>"$LOCK"
if command -v flock >/dev/null 2>&1; then
  flock -n 9
  lock_rc=$?
  if [ "$lock_rc" -eq 1 ]; then
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ): another taa-supervisor.sh already holds the singleton lock, exiting" >> "$LOG"
    exit 0
  elif [ "$lock_rc" -ne 0 ]; then
    # An unusable lock (e.g. flock rc=65, bad fd) must never be read as "someone else owns
    # it": that would let the container's ENTRYPOINT exit instantly and kill the container.
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ): warning: singleton lock unusable (flock rc=${lock_rc}), continuing unguarded" >> "$LOG"
  fi
else
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ): warning: flock not found, singleton guard disabled" >> "$LOG"
fi

[ -f get-attestation.bak ] && [ ! -f get-attestation ] && mv get-attestation.bak get-attestation
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ): taa autostart wrapper started" >> "$LOG"

while true; do
  if [ -f ./manual ]; then
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ): manual mode active, autostart paused" >> "$LOG"
    sleep 10
    continue
  fi
  if [ ! -x ./taa ]; then
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ): ./taa not found, retry in 30s" >> "$LOG"
    sleep 30
    continue
  fi
  ./taa >> "$LOG" 2>&1 9>&- &
  TAAPID=$!
  wait "$TAAPID"
  EXIT_CODE=$?
  TAAPID=""
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ): taa exited with code ${EXIT_CODE}, restart in 10s" >> "$LOG"
  sleep 10
done
# <<< TAA_LOOP

  exit 0
fi

# ── The combined entrypoint (PID 1) ─────────────────────────────────────────
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

# The child reads the same file this process is executing. Updates replace the
# file with mv, so this PID 1 keeps its inode and only the child is restarted.
start_taa() {
  bash "$SELF" --taa-loop &
  taa_pid=$!
  log "TAA loop started (pid $taa_pid)"
}
start_taa

while :; do
  wait -n "$fhe_pid" "$taa_pid" 2>/dev/null || true

  if ! kill -0 "$fhe_pid" 2>/dev/null; then
    wait "$fhe_pid"
    rc=$?
    log "FHE entrypoint exited with status $rc; stopping TAA"
    stop_children
    if [ -n "$taa_pid" ]; then wait "$taa_pid" 2>/dev/null || true; fi
    exit "$rc"
  fi

  [ "$stopping" = 1 ] && continue

  if ! kill -0 "$taa_pid" 2>/dev/null; then
    wait "$taa_pid" 2>/dev/null || true
    log "TAA loop exited; restarting in ${TAA_RESTART_DELAY}s"
    taa_pid=""
    sleep "$TAA_RESTART_DELAY" &
    wait $! 2>/dev/null || true
    [ "$stopping" = 1 ] && continue
    start_taa
  fi
done
