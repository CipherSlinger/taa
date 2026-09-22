#!/usr/bin/env bash
# TAA autostart wrapper: starts taa, keeps the container alive, retries on exit.
# Also brings up the TEE-LLM supervisor (ollama + teellm-service) when present,
# so the inference gateway is reachable for taa's fail-closed readiness probe.
# Manual mode: touch /root/taa/manual to pause taa autostart; rm it to resume.
#              touch /root/taa/manual-teellm to pause only the TEE-LLM side.
set -u
cd /root/taa || exit 1
LOG=/root/taa/taa.log
TEELLM_LOG=/root/taa/teellm-service.log
LOCK=/root/taa/.start.lock
TAAPID=""
TEEPID=""

cleanup() {
  if [ -n "$TAAPID" ]; then
    kill -TERM "$TAAPID" 2>/dev/null || true
  fi
  if [ -n "$TEEPID" ]; then
    kill -TERM "$TEEPID" 2>/dev/null || true
  fi
  exit 0
}
trap cleanup SIGTERM SIGINT

# Singleton guard: only one supervisor may own taa and the TEE-LLM wrapper. Two of them --
# one started by each deploy script -- race for :6001 and :8443 and interleave the same log
# files. flock is used instead of a pidfile because the lock is kernel state released when
# this process dies, so a stale lock can never wedge the container's ENTRYPOINT. Every child
# below closes the lock fd, so an orphaned daemon cannot keep the lock after the supervisor
# itself is gone.
exec 9>"$LOCK"
if command -v flock >/dev/null 2>&1; then
  flock -n 9
  lock_rc=$?
  if [ "$lock_rc" -eq 1 ]; then
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ): another start.sh already holds the singleton lock, exiting" >> "$LOG"
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

# Start the TEE-LLM supervisor before taa so it wins the startup race; taa's own
# retry loop tolerates the gateway not being ready on the very first probe.
if [ -x ./start-teellm.sh ]; then
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ): starting teellm autostart wrapper" >> "$LOG"
  nohup ./start-teellm.sh >> "$TEELLM_LOG" 2>&1 9>&- &
  TEEPID=$!
else
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ): ./start-teellm.sh not found, teellm autostart skipped" >> "$LOG"
fi

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
