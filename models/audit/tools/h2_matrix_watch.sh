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
# 2. The failed-arbitration count in the artifacts being written. This one matters
#    more than it looks, and it points the opposite way from what an earlier version
#    of this script claimed. A failed call is recorded as MORE malicious than the
#    truth, not less: an UNCERTAIN verdict on a HIGH or MEDIUM finding lifts the
#    sample's risk level to HIGH, and under the assist policy that blocks the sample
#    (code_security_analyzer.py:855-875). In this corpus, which holds no LOW-severity
#    findings at all, that direction is the whole story: a failure can never hide a
#    malicious sample. What it does instead depends on the sample's true label --
#    a false positive on a benign sample, and a true positive on a malicious one
#    (both measured; plan sections 21 G and 28 B). The two move the criterion's
#    deltas in opposite directions, which is why the report has to split failure
#    counts by true label rather than report one total.
#
#    The field it reads is `statistics.uncertain`, not `conclusion.verdict`. That is
#    a correction: the verdict is what the failure was *lifted into*, so most failures
#    do not leave an UNCERTAIN verdict behind. Measured on the two complete runs,
#    `statistics.uncertain > 0` identifies exactly the samples whose llm_state is
#    llm_unavailable or parse_error -- 8 of 8 in regex-run1 and 6 of 6 in semgrep-run1,
#    identical by sample id -- while `conclusion.verdict == "UNCERTAIN"` finds only 1
#    and 2 of those same failures. Counting the verdict would therefore miss most of a
#    wave of failures, which is the one event this branch exists to make loud.
#
# 3. The runner's liveness and the cgroup's memory. A request in flight when the
#    container OOM-kills llama-server comes back as an HTTP Error 500, not a
#    connection failure and not a timeout: ollama itself survives and answers for
#    the dead runner. Measured 2026-09-28 (plan section 25), where the one oom_kill
#    and the one 500 across four rounds are the same event. That makes the three
#    failure modes separable after the fact -- timed out, HTTP 500, unparseable --
#    which is why the report has to carry the oom_kill count next to the failure
#    counts rather than a single "not arbitrated" total.
#
#    The runner's ABSENCE is its own signal, because between the kill and ollama
#    serve's respawn there is no pid to compare against -- but absence has two
#    causes and only one of them is a fault. ollama unloads an idle model when its
#    keep_alive window lapses, and stretches of samples that need no LLM call make
#    that routine here. The discriminator is the oom_kill counter this probe
#    already reads, so the branch below reports a kill and an unload separately
#    rather than calling both of them "OOM kill or crash". In both cases the next
#    call pays a model load on top of its decode and lands closer to the 60 s cap.
#    The heartbeat reports the cgroup's memory decomposed into anon and file
#    rather than as current/max, because `current` includes reclaimable page
#    cache; the anon figure is the one that means pressure.
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
prev_uncf=-1
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
  #
  # The python emits two fields (samples with a failed arbitration, and the failed
  # findings they contain) and its fallback substitutes two, so the alignment below
  # holds whether or not it succeeds. A one-field fallback would shift every later
  # field left, which is the bug this pair of counts must not reintroduce.
  read -r fsamp ffind oom pid nrun anonm filem memc memmax < <(docker exec "$CONTAINER" sh -c "
    python3 -c \"
import glob, json
samples = findings = 0
for p in glob.glob('$OUT/*-run*/*/audit_report.json'):
    try:
        u = json.load(open(p)).get('statistics', {}).get('uncertain', 0) or 0
    except Exception:
        continue
    if u:
        samples += 1
        findings += u
print(samples, findings)
\" 2>/dev/null || echo -1 -1
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

  if [ -z "${fsamp:-}" ]; then
    echo "ALERT $(date -u +%H:%M:%SZ) container unreachable"
  else
    if [ "$prev_unc" -ge 0 ] && [ "$fsamp" -gt "$prev_unc" ]; then
      echo "FAILED-ARBITRATION +$((fsamp - prev_unc)) sample(s) (now $fsamp samples / $ffind findings) $(date -u +%H:%M:%SZ) -- an LLM call did not arbitrate; that blocks the sample, so it is a false positive if the sample is benign and a true positive if it is malicious, and it can never hide a malicious one"
    fi
    prev_unc=$fsamp
    prev_uncf=$ffind
    # Whether the cgroup killed something in this poll. Computed before prev_oom is
    # advanced, because the liveness branch below needs the answer and prev_oom is
    # overwritten on the next line.
    oom_moved=0
    if [ "$prev_oom" -ge 0 ] && [ "${oom:-0}" != "$prev_oom" ]; then
      oom_moved=1
      echo "ALERT $(date -u +%H:%M:%SZ) cgroup oom_kill $prev_oom -> $oom"
    fi
    prev_oom=${oom:-0}
    if [ -z "$pid_now" ]; then
      if [ "$prev_present" = "1" ]; then
        # A missing runner is not by itself a kill. ollama unloads an idle model once
        # its keep_alive window lapses (five minutes by default), and this matrix has
        # long stretches of samples that need no LLM call at all, so an unload is a
        # routine event here rather than a fault. Measured on 2026-09-28: the runner
        # disappeared around 05:01:51 with oom_kill unchanged at 1, and the next call
        # reloaded it ("llama-server started in 5.79 seconds") and returned 200. Read
        # as a kill, that would have put an OOM in the report that never happened and,
        # worse, asserted that calls in the window had failed when the one that
        # followed it succeeded. The discriminator is the counter the watch already
        # reads, so the two cases are separated rather than guessed at.
        if [ "$oom_moved" = "1" ]; then
          echo "ALERT $(date -u +%H:%M:%SZ) llama-server GONE (was $prev_pid) after an OOM kill: the request in flight fails, and the rest resume on the respawn"
        else
          echo "INFO $(date -u +%H:%M:%SZ) llama-server unloaded while idle (was $prev_pid, oom_kill unchanged at ${oom:-0}): not a fault; the next call reloads it and pays the model load"
        fi
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
    # `all_runs` is in the label because these two counts span every run directory
    # under $OUT, not the run in flight. The alert above is a per-poll delta and is
    # unaffected; the heartbeat's totals are not per-run and must not be read as such.
    echo "HEARTBEAT $(date -u +%H:%M:%SZ) runs=$nrun failed_samples_all_runs=$prev_unc failed_findings_all_runs=$prev_uncf oom_kill=$prev_oom llama_pid=$prev_pid mem_anon=${anonm:-?}MiB mem_file=${filem:-?}MiB mem_current=${memc:-?}MiB mem_max=${memmax:-?}MiB"
  fi
  sleep "$POLL_INTERVAL"
done
