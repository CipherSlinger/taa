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

[ -f get-attestation.bak ] && [ ! -f get-attestation ] && mv get-attestation.bak get-attestation
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ): taa autostart wrapper started" >> "$LOG"

# Start the TEE-LLM supervisor before taa so it wins the startup race; taa's own
# retry loop tolerates the gateway not being ready on the very first probe.
if [ -x ./start-teellm.sh ]; then
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ): starting teellm autostart wrapper" >> "$LOG"
  nohup ./start-teellm.sh >> "$TEELLM_LOG" 2>&1 &
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
  ./taa >> "$LOG" 2>&1 &
  TAAPID=$!
  wait "$TAAPID"
  EXIT_CODE=$?
  TAAPID=""
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ): taa exited with code ${EXIT_CODE}, restart in 10s" >> "$LOG"
  sleep 10
done
