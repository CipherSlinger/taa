#!/usr/bin/env bash
# TAA autostart wrapper: starts taa, keeps the container alive, retries on exit.
# Manual mode: touch /root/taa/manual to pause autostart; rm it to resume.
set -u
cd /root/taa || exit 1
LOG=/root/taa/taa.log
TAAPID=""

cleanup() {
  if [ -n "$TAAPID" ]; then
    kill -TERM "$TAAPID" 2>/dev/null || true
  fi
  exit 0
}
trap cleanup SIGTERM SIGINT

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
  ./taa >> "$LOG" 2>&1 &
  TAAPID=$!
  wait "$TAAPID"
  EXIT_CODE=$?
  TAAPID=""
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ): taa exited with code ${EXIT_CODE}, restart in 10s" >> "$LOG"
  sleep 10
done
