#!/usr/bin/env bash
# Combined entrypoint for the data-analysis container, installed as
# /root/taa/taa-supervisor.sh (the same path every role uses).
#
# This role runs on the jupyter base image (ENTRYPOINT `tini -g --`, CMD
# `start-notebook.py`), and its data lands under /home/jovyan/systemAuthData for
# the notebook runtime to read. Replacing that ENTRYPOINT with the plain TAA
# supervisor starts TAA but never jupyter, so this file starts both: the jupyter
# server as the sidecar and the TAA restart loop as a child.
#
# The TAA loop runs as a child of this file (`bash <this file> --taa-loop`), not
# inline: deploy updates replace the file and signal the loop, and keeping the
# loop in a child means the update can kill and restart it without touching
# PID 1, which would restart the container and lose the guest's writable layer.
#
# Liveness: jupyter is the service this container exists for. If it exits, TAA is
# stopped and the container exits with jupyter's status, so the restart policy
# acts on a container image whose notebooks are gone. The TAA loop is restarted
# here only when it exits on its own.
set -uo pipefail

TAA_WORKDIR="${TAA_WORKDIR:-/root/taa}"
JUPYTER_CMD="${JUPYTER_CMD:-start-notebook.py}"
# start-notebook.py execs start.sh, which starts jupyter as the user the container
# runs as. Jupyter only reads $HOME/.jupyter, and allow_root lives in
# /home/jovyan/.jupyter/jupyter_server_config.py: with any other HOME the server
# refuses to start as root. The image sets HOME=/home/jovyan already; setting it
# here keeps the entrypoint correct even if the Pod environment changes it.
JUPYTER_HOME="${JUPYTER_HOME:-/home/jovyan}"
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
jupyter_pid=""
taa_pid=""
stopping=0

log() { printf '%s [taa-analysis] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }

stop_children() {
  [ "$stopping" = 1 ] && return 0
  stopping=1
  if [ -n "$taa_pid" ]; then kill -TERM "$taa_pid" 2>/dev/null || true; fi
  if [ -n "$jupyter_pid" ]; then kill -TERM "$jupyter_pid" 2>/dev/null || true; fi
}

on_term() {
  stop_children
  if [ -n "$jupyter_pid" ]; then wait "$jupyter_pid" 2>/dev/null || true; fi
  exit 0
}
trap on_term TERM INT

if ! command -v "$JUPYTER_CMD" >/dev/null 2>&1; then
  log "$JUPYTER_CMD not found in PATH; this base image cannot serve notebooks"
  exit 1
fi
(
  cd "$JUPYTER_HOME" || exit 1
  exec env HOME="$JUPYTER_HOME" "$JUPYTER_CMD"
) &
jupyter_pid=$!
log "jupyter started (pid $jupyter_pid, home $JUPYTER_HOME)"

# The child reads the same file this process is executing. Updates replace the
# file with mv, so this PID 1 keeps its inode and only the child is restarted.
start_taa() {
  bash "$SELF" --taa-loop &
  taa_pid=$!
  log "TAA loop started (pid $taa_pid)"
}
start_taa

while :; do
  wait -n "$jupyter_pid" "$taa_pid" 2>/dev/null || true

  if ! kill -0 "$jupyter_pid" 2>/dev/null; then
    wait "$jupyter_pid"
    rc=$?
    log "jupyter exited with status $rc; stopping TAA"
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
