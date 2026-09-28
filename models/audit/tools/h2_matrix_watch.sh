#!/usr/bin/env bash
# Watch the H2.1 holdout matrix while it runs, from the host.
#
# Three things are watched, because they fail in different ways and two of them
# fail silently:
#
# 1. The driver log, for the terminal signals -- each run's exit code, the end of
#    the matrix, and the refusals the driver itself raises. A run that exits
#    non-zero stops the matrix (see h2_loaded_rounds.sh), so this is the coarse
#    "is it still making progress" channel.
#
# 2. The UNCERTAIN rate in the artifacts being written. This one matters more than
#    it looks, and it points the opposite way from what an earlier version of this
#    script claimed. An UNCERTAIN verdict on a HIGH or MEDIUM finding lifts the
#    sample's risk level to HIGH, and under the assist policy that blocks the
#    sample (code_security_analyzer.py:855-875). So a failed call is recorded as
#    MORE malicious than the truth, not less: in this corpus, which holds no
#    LOW-severity findings at all, it can only manufacture false positives and can
#    never hide a malicious sample. Counting UNCERTAIN verdicts as they are
#    produced is still the only signal that distinguishes "the LLM arbitrated and
#    found nothing" from "the LLM never answered".
#
# 3. The runner's liveness and the cgroup's memory. A request in flight when the
#    container OOM-kills llama-server gets a connection failure, not a timeout, and
#    the killed server cannot write its own 500 line -- so the artifact and the log
#    both stay quiet about it. The runner's ABSENCE is therefore its own alert, not
#    something to be inferred from a changed pid: between the kill and ollama
#    serve's respawn there is no pid to compare against. The respawn is reported
#    separately, because the first calls after it pay a ~29 s model load on top of
#    their decode and land close to the 60 s cap. The heartbeat reports the
#    cgroup's memory decomposed into anon and file rather than as current/max,
#    because `current` includes reclaimable page cache; the anon figure is the
#    one that means pressure.
#
# Emits a line only when something changes, so that silence means "unchanged", and
# a heartbeat every 30 polls so that silence cannot be confused with a dead watch.
#
# Run it on the HOST (it reaches into the container with docker exec), not inside.
set -uo pipefail

CONTAINER=${CONTAINER:-taa-env-slim-v2}
OUT=${OUT:-/root/taa/verify/h2-assist-unloaded}
LOG=${LOG:-$OUT-driver.log}
# The cgroup path is a *container* path, expanded here and sent in with the rest of
# the probe. It is a parameter only so the field-alignment test can point it at a
# fixture directory instead of depending on the host's cgroup layout.
CGROUP=${CGROUP:-/sys/fs/cgroup}
# Poll and heartbeat cadence are parameters for the same reason: a test that had to
# wait 30 minutes for the first heartbeat could not exist.
POLL_INTERVAL=${POLL_INTERVAL:-60}
HEARTBEAT_EVERY=${HEARTBEAT_EVERY:-30}

prev_unc=-1
prev_oom=-1
prev_pid=""
prev_present=-1

( docker exec "$CONTAINER" tail -F -n +1 "$LOG" 2>/dev/null \
  | grep --line-buffered -E "^[a-z]+ run [0-9]+: exit=|matrix done|refusing|could not warm|Traceback" ) &

poll=0
while true; do
  poll=$((poll + 1))
  # `tr` merges the readings onto one line. Without it the python count keeps its
  # trailing newline, `read` takes only the first line, and the oom/pid/run-count
  # fields come back empty -- which reads as "no OOM, no respawn" for the whole run.
  # That is the failure mode of a watch: it reports silence as health.
  read -r unc oom pid nrun anonm filem memc memmax < <(docker exec "$CONTAINER" sh -c "
    python3 -c \"
import glob, json
n = 0
for p in glob.glob('$OUT/*-run*/*/audit_report.json'):
    try:
        if json.load(open(p)).get('conclusion', {}).get('verdict') == 'UNCERTAIN':
            n += 1
    except Exception:
        pass
print(n)
\" 2>/dev/null || echo -1
    awk '/^oom_kill /{printf \"%s \", \$2}' $CGROUP/memory.events
    ps -eo pid,args | awk '/llama-server/ && !/awk/{printf \"%s \", \$1; found=1; exit} END{if (!found) printf \"none \"}'
    ls -d $OUT/*-run*/ 2>/dev/null | wc -l
    awk '/^anon /{printf \"%d \", \$2/1048576}' $CGROUP/memory.stat
    awk '/^file /{printf \"%d \", \$2/1048576}' $CGROUP/memory.stat
    awk '{printf \"%d \", \$1/1048576}' $CGROUP/memory.current
    awk '{printf \"%d \", \$1/1048576}' $CGROUP/memory.max
  " 2>/dev/null | tr '\n' ' ')

  # The pid field is always emitted, as the literal "none" when the runner is
  # absent. It was previously skipped when absent, which shifted every later
  # field one place left: the run count landed in `pid`, so `pid_now` was a
  # number, the GONE alert below never fired, and the watch reported an OOM
  # kill as health. A watch must not have a silent branch.
  pid_now="${pid:-}"
  [ "$pid_now" = "none" ] && pid_now=""

  if [ -z "${unc:-}" ]; then
    echo "ALERT $(date -u +%H:%M:%SZ) container unreachable"
  else
    if [ "$prev_unc" -ge 0 ] && [ "$unc" -gt "$prev_unc" ]; then
      echo "UNCERTAIN +$((unc - prev_unc)) (now $unc) $(date -u +%H:%M:%SZ) -- an LLM call did not arbitrate; on a HIGH/MEDIUM finding that blocks the sample (a false positive), it cannot hide one"
    fi
    prev_unc=$unc
    if [ "$prev_oom" -ge 0 ] && [ "${oom:-0}" != "$prev_oom" ]; then
      echo "ALERT $(date -u +%H:%M:%SZ) cgroup oom_kill $prev_oom -> $oom"
    fi
    prev_oom=${oom:-0}
    if [ -z "$pid_now" ]; then
      if [ "$prev_present" = "1" ]; then
        echo "ALERT $(date -u +%H:%M:%SZ) llama-server GONE (was $prev_pid): OOM kill or crash; every LLM call in this window fails"
      fi
      prev_present=0
    else
      if [ "$prev_present" = "1" ] && [ "$pid_now" != "$prev_pid" ]; then
        echo "ALERT $(date -u +%H:%M:%SZ) llama-server pid $prev_pid -> $pid_now: killed and respawned between polls"
      elif [ "$prev_present" = "0" ]; then
        echo "ALERT $(date -u +%H:%M:%SZ) llama-server respawned (now $pid_now): the first calls pay a model load"
      fi
      prev_present=1
      prev_pid="$pid_now"
    fi
  fi

  if [ $((poll % HEARTBEAT_EVERY)) -eq 0 ]; then
    # `current` alone invites a wrong reading: it is anon (real pressure) plus
    # file (reclaimable page cache), and a large file share is not proximity to
    # the limit. Reported decomposed so the anon figure is the one read.
    echo "HEARTBEAT $(date -u +%H:%M:%SZ) runs=$nrun uncertain_total=$prev_unc oom_kill=$prev_oom llama_pid=$prev_pid mem_anon=${anonm:-?}MiB mem_file=${filem:-?}MiB mem_current=${memc:-?}MiB mem_max=${memmax:-?}MiB"
  fi
  sleep "$POLL_INTERVAL"
done
