#!/usr/bin/env bash
# Same-container press test for the Tier 1 semgrep engine (stage G of
# .claude/specs/2026-09-23-semgrep-engine-integration-design.md).
#
# Run it *inside* the TAA container, where semgrep, its rules and the ollama runner all
# live. It puts the adapter's own scan under sustained load while probing the LLM the
# audit uses, so that "what does co-locating them cost" is answered by numbers rather
# than by the container still being up.
#
# Why the load is sustained: one scan of the 400-file audit-100 corpus finishes in about
# five seconds, so a probe loop that launches scans once measures an idle LLM from the
# second sample on. The loader relaunches rounds until the probes are done.
#
# Why every probe records llama_pid and llama_rss_kb: the failure this exists to catch
# is an LLM that has become unusable while the container is still up (RestartCount=0,
# StartedAt unchanged -- .claude/specs/2026-09-22-semgrep-engine-noninferiority-
# evidence-design.md:435). Container survival therefore proves nothing here; a changed
# runner pid or a collapsed RSS is the signal.
#
# Usage (inside the container):
#   ./semgrep_press_test.sh
# Environment:
#   LEVELS             concurrent scans per level (default "0 4 8 12")
#   PROBES_PER_LEVEL   probes per level (default 10)
#   PROBE_TIMEOUT      probe timeout, seconds (default 30, matches llm.requestTimeoutMs)
#   CORPUS             directory to scan (default: the staged audit-100 copy)
#   RULES              semgrep --config (default: the rules this image ships)
#   OUT                output directory (default /root/taa/verify/press)
set -uo pipefail

OLLAMA=${OLLAMA:-http://127.0.0.1:11434}
MODEL=${MODEL:-qwen2.5-coder:3b}
RULES=${RULES:-/opt/taa/semgrep/rules/python/rules.yaml}
CORPUS=${CORPUS:-/root/taa/verify/bench}
OUT=${OUT:-/root/taa/verify/press}
PROBE_TIMEOUT=${PROBE_TIMEOUT:-30}
PROBES_PER_LEVEL=${PROBES_PER_LEVEL:-10}
LEVELS=${LEVELS:-"0 4 8 12"}

mkdir -p "$OUT"

# Single instance. A second run appends into the same probe log, and every number below
# then describes a mixture of two loads rather than one.
if [[ -e "$OUT/.running" ]] && kill -0 "$(cat "$OUT/.running" 2>/dev/null)" 2>/dev/null; then
  echo "another press run is active (pid $(cat "$OUT/.running")); refusing to start" >&2
  exit 1
fi
echo $$ > "$OUT/.running"
trap 'rm -f "$OUT/.running"' EXIT

: > "$OUT/llm_probes.log"
: > "$OUT/rss.log"

# ── Per-probe observability ──────────────────────────────────
# An empty reading is normalised to "none"/"0" rather than left blank, so that a killed
# runner leaves `llama_pid=none` in the log instead of an ambiguous empty field.
llama_state() {
  local line pid rss
  line="$(ps -eo pid=,rss=,args= | awk '/llama-server/ && !/awk/ {print $1, $2; exit}')"
  pid="${line%% *}"; rss="${line##* }"
  printf '%s %s' "${pid:-none}" "${rss:-0}"
}

mem_avail_kb() {
  awk '/^MemAvailable:/ {print $2}' /proc/meminfo
}

# ── Probes ───────────────────────────────────────────────────
# Same model, same options and same keep_alive the daemon's audit uses, so a probe
# contends for exactly the resource the audit needs. The timeout matches production, so
# "ok" here means "this call would have succeeded in an audit".
llm_probe() {
  local level="$1" i start end code dur state scans line
  for i in $(seq 1 "$PROBES_PER_LEVEL"); do
    # pgrep -c prints 0 and exits 1 when nothing matches, so the count is captured and
    # defaulted rather than read from a fallback that would append a second line.
    scans=$(pgrep -fc "semgrep scan --config" 2>/dev/null)
    scans=${scans:-0}
    line="$(llama_state)"
    start=$(date +%s.%N)
    code=$(curl -s -o "$OUT/probe-$level-$i.json" -w '%{http_code}' -m "$PROBE_TIMEOUT" \
      -X POST "$OLLAMA/api/generate" -H 'Content-Type: application/json' \
      -d "{\"model\":\"$MODEL\",\"prompt\":\"Return the single word ok.\",\"stream\":false,\"keep_alive\":\"30m\",\"options\":{\"num_predict\":8,\"temperature\":0.1,\"seed\":42}}" 2>/dev/null)
    end=$(date +%s.%N)
    dur=$(awk -v a="$start" -v b="$end" 'BEGIN{printf "%.1f", b-a}')
    if [[ "$code" == "200" ]] && grep -q '"response"' "$OUT/probe-$level-$i.json" 2>/dev/null; then
      state=ok
    elif [[ -z "$code" || "$code" == "000" ]]; then
      state=timeout
    else
      state=http_$code
    fi
    printf 'level=%s probe=%d scans_active=%s state=%s http=%s seconds=%s llama_pid=%s llama_rss_kb=%s mem_avail_kb=%s\n' \
      "$level" "$i" "$scans" "$state" "${code:-none}" "$dur" \
      "${line%% *}" "${line##* }" "$(mem_avail_kb)" | tee -a "$OUT/llm_probes.log"
  done
}

# ── Sustained load ───────────────────────────────────────────
# The adapter's own argument vector, one process per concurrent scan, relaunched as soon
# as a round drains, so the load outlives a single round and covers every probe.
LOADER_PID=""
start_loader() {
  local level="$1"
  rm -f "$OUT/stop-$level"
  : > "$OUT/rounds-$level"
  (
    local round=0 i
    while [[ ! -f "$OUT/stop-$level" ]]; do
      round=$((round + 1))
      for i in $(seq 1 "$level"); do
        (
          semgrep scan --config "$RULES" --json --quiet --disable-version-check \
            --no-git-ignore --max-memory 1024 "$CORPUS" \
            > "$OUT/scan-$level-r$round-$i.json" 2> "$OUT/scan-$level-r$round-$i.err"
          echo "$?" > "$OUT/scan-$level-r$round-$i.exit"
        ) &
      done
      wait
      echo "$round" > "$OUT/rounds-$level"
    done
  ) &
  LOADER_PID=$!
}

stop_loader() {
  local level="$1"
  touch "$OUT/stop-$level"
  if [[ -n "$LOADER_PID" ]]; then
    for _ in $(seq 1 30); do
      kill -0 "$LOADER_PID" 2>/dev/null || break
      sleep 2
    done
    kill -TERM "$LOADER_PID" 2>/dev/null
    wait "$LOADER_PID" 2>/dev/null
  fi
  pkill -f "semgrep scan --config" >/dev/null 2>&1
  pkill -f semgrep-core >/dev/null 2>&1
  sleep 1
}

# Sampled every second while a level runs: the pressure the OOM killer acts on. This is
# what "memory flat across -j" does not cover, because that measurement held the scan
# count at one.
sample_rss() {
  while true; do
    printf '%s %s %s %s\n' "$(date -u +%H:%M:%S)" \
      "$(ps -eo rss=,args= | awk '/semgrep/ && !/awk/ {s += $1} END {printf "%d", s}')" \
      "$(ps -eo rss=,args= | awk '/ollama/ && !/awk/ {s += $1} END {printf "%d", s}')" \
      "$(mem_avail_kb)" >> "$OUT/rss.log"
    sleep 1
  done
}

echo "===== press test start: $(date -u +%Y-%m-%dT%H:%M:%SZ) ====="
echo "semgrep: $(semgrep --version 2>/dev/null | tail -1)"
echo "rules: $RULES"
echo "corpus: $CORPUS ($(find "$CORPUS" -name '*.py' | wc -l) files)"
echo "probes per level: $PROBES_PER_LEVEL, timeout: ${PROBE_TIMEOUT}s"

sample_rss &
RSS_PID=$!

for level in $LEVELS; do
  echo "----- level: $level concurrent scans -----"
  if [[ "$level" != "0" ]]; then
    start_loader "$level"
    sleep 5   # let the first round reach steady state before the probes
  fi

  llm_probe "$level"

  if [[ "$level" != "0" ]]; then
    stop_loader "$level"
    peak_scan=$(awk '{if ($2 > m) m = $2} END {print m+0}' "$OUT/rss.log")
    echo "level $level: rounds completed = $(cat "$OUT/rounds-$level" 2>/dev/null || echo 0), peak semgrep RSS = ${peak_scan} kB"
  fi

  ollama_procs=$(pgrep -fc 'ollama' 2>/dev/null)
  echo "ollama runner processes: ${ollama_procs:-0}"
done

kill "$RSS_PID" 2>/dev/null; wait "$RSS_PID" 2>/dev/null

echo "===== verdict inputs ====="
echo "--- probe outcomes, split by whether semgrep was running when the probe started ---"
awk '
  { for (i = 1; i <= NF; i++) { split($i, kv, "="); v[kv[1]] = kv[2] } }
  { key = (v["scans_active"] + 0 > 0 ? "loaded" : "idle") }
  { n[key]++; s[key] += v["seconds"]; if (v["seconds"] > max[key]) max[key] = v["seconds"]; st[key" "v["state"]]++ }
  END {
    for (k in n) printf "%s: n=%d mean=%.1fs max=%.1fs\n", k, n[k], s[k]/n[k], max[k]
    for (k in st) printf "  %s\n", k
  }' "$OUT/llm_probes.log"
echo "--- llama-server identity across probes (a second pid means it was killed and respawned) ---"
awk '{ for (i = 1; i <= NF; i++) { split($i, kv, "="); v[kv[1]] = kv[2] } ; print v["llama_pid"], v["llama_rss_kb"] }' \
  "$OUT/llm_probes.log" | uniq -c
echo "--- scan exits across every round ---"
for f in "$OUT"/scan-*.exit; do cat "$f"; done | sort | uniq -c
echo "--- scan errors (non-empty stderr means the scan itself failed) ---"
n_err=0
for f in "$OUT"/scan-*.err; do [[ -s "$f" ]] && { n_err=$((n_err + 1)); printf '%s: %s bytes\n' "$(basename "$f")" "$(wc -c < "$f")"; }; done
echo "non-empty stderr files: $n_err"
echo "--- findings per scan (from the JSON, not from a claim) ---"
python3 - "$OUT" <<'PY'
import glob, json, os, sys
out = sys.argv[1]
summary = {}
for path in sorted(glob.glob(os.path.join(out, "scan-*.json"))):
    try:
        d = json.load(open(path))
        key = (len(d.get("results", [])), len(d.get("errors", [])),
               len((d.get("paths") or {}).get("scanned", [])))
    except Exception as e:
        key = ("unreadable", str(e), 0)
    summary[key] = summary.get(key, 0) + 1
for key, n in sorted(summary.items(), key=lambda kv: -kv[1]):
    print("results=%s errors=%s scanned=%s -> %d scans" % (key[0], key[1], key[2], n))
PY
echo "===== press test end: $(date -u +%Y-%m-%dT%H:%M:%SZ) ====="
