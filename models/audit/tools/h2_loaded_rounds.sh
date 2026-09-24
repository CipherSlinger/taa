#!/usr/bin/env bash
# H2.1: the three paired rounds of the holdout judgement, under sustained Semgrep
# press load (spec 9.3 item 1: "scanning and the LLM loaded at the same time").
#
# Run it *inside* the TAA container, as root of the staged tree, because semgrep,
# the rules, the corpus and the ollama runner all live there.
#
# Two protocol facts are encoded here rather than left to the caller:
#
# 1. The six runs are emitted in the strict alternation regex1, semgrep1, regex2,
#    semgrep2, regex3, semgrep3 -- which is the order engine_compare_report.py
#    declares in RUN_ORDER. That order is deliberate: it makes a drift in the
#    machine over the session appear as a difference between run indices rather
#    than as a difference between engines. Batching all three regex runs and then
#    all three semgrep runs would fold that drift into the engine comparison.
#
# 2. The press load runs for the whole matrix, not for one press script lifetime.
#    A single press run steps its levels and exits inside about twenty minutes,
#    while the matrix takes hours, so a load that is not restarted would leave
#    most rounds measured on an idle machine -- the exact condition the serial
#    matrix already covered and this stage exists to go beyond.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)

CORPUS_ROOT=${CORPUS_ROOT:-models/audit/benchmarks/audit-holdout}
CORPUS_LIST=${CORPUS_LIST:-$CORPUS_ROOT/corpus-list.json}
RULES=${RULES:-models/audit/semgrep/rules/python/rules.yaml}
MODEL=${MODEL:-qwen2.5-coder:3b}
SEED=${SEED:-42}
POLICY=${POLICY:-assist}
OUT=${OUT:-/root/taa/verify/h2-assist}
PRESS_LEVELS=${PRESS_LEVELS:-"0 4 8 12"}
PRESS_PROBES=${PRESS_PROBES:-10}
LOAD=${LOAD:-1}

mkdir -p "$OUT"
STOP="$OUT/.stop-load"

# Single instance: two matrices appending into one base dir would produce a set
# of runs that describes a mixture of two loads rather than one.
if [[ -e "$OUT/.running" ]] && kill -0 "$(cat "$OUT/.running" 2>/dev/null)" 2>/dev/null; then
  echo "another matrix is active (pid $(cat "$OUT/.running")); refusing to start" >&2
  exit 1
fi
echo $$ > "$OUT/.running"
trap 'rm -f "$OUT/.running" "$STOP"' EXIT

run_press_forever() {
  rm -f "$STOP"
  local n=0
  while [[ ! -e "$STOP" ]]; do
    n=$((n + 1))
    echo "----- press pass $n -----"
    RULES="$RULES" LEVELS="$PRESS_LEVELS" PROBES_PER_LEVEL="$PRESS_PROBES" \
      OUT="$OUT/press" bash "$HERE/semgrep_press_test.sh" || true
  done
}

if [[ "$LOAD" == "1" ]]; then
  run_press_forever > "$OUT/press.log" 2>&1 &
  LOAD_PID=$!
  echo "press load started (pid $LOAD_PID); log $OUT/press.log"
  sleep 10
  # The load must be real before the first round is measured, not a process that
  # failed to start and left the matrix quietly unloaded.
  if ! kill -0 "$LOAD_PID" 2>/dev/null; then
    echo "press load died on startup; refusing to measure an unloaded matrix" >&2
    tail -20 "$OUT/press.log" >&2
    exit 1
  fi
  grep -q "press test start" "$OUT/press.log" || {
    echo "press load produced no start banner; refusing to continue" >&2
    tail -20 "$OUT/press.log" >&2
    exit 1
  }
fi

echo "===== H2.1 matrix start: $(date -u +%Y-%m-%dT%H:%M:%SZ) ====="
echo "policy=$POLICY model=$MODEL seed=$SEED rules=$RULES"
echo "corpus=$CORPUS_ROOT"
echo "samples=$(python3 -c "import json;print(len(json.load(open('$CORPUS_LIST'))['samples']))")"
echo "output=$OUT"

for entry in "regex 1" "semgrep 1" "regex 2" "semgrep 2" "regex 3" "semgrep 3"; do
  set -- $entry
  engine=$1; index=$2
  run_dir="$OUT/$engine-run$index"
  rm -rf "$run_dir"
  started=$(date +%s)
  echo "----- $engine run $index -----"
  python3 "$HERE/audit_benchmark_eval.py" \
    --benchmark-root "$CORPUS_ROOT" \
    --corpus-list "$CORPUS_LIST" \
    --manifest-out "$OUT/manifest-$engine-run$index.json" \
    --results-dir "$run_dir" \
    --engine "$engine" \
    --policy "$POLICY" \
    --llm-backend ollama \
    --llm-model "$MODEL" \
    --llm-seed "$SEED" \
    > "$OUT/$engine-run$index.log" 2>&1
  code=$?
  echo "$engine run $index: exit=$code seconds=$(( $(date +%s) - started ))"
  if [[ $code -ne 0 ]]; then
    # A run that did not finish is recorded as such and the matrix stops: the
    # pair it belongs to cannot be scored, and continuing would spend hours
    # producing a set of runs that cannot yield a verdict either way.
    echo "$engine run $index exited $code; stopping the matrix" >&2
    tail -30 "$OUT/$engine-run$index.log" >&2
    break
  fi
  python3 -c "
import json
try:
    c = json.load(open('$run_dir/confusion-matrix.json'))
    print('  tp=%(tp)s fp=%(fp)s tn=%(tn)s fn=%(fn)s' % c)
except Exception as e:
    print('  confusion matrix unreadable:', e)
"
done

if [[ "$LOAD" == "1" ]]; then
  touch "$STOP"
  wait "$LOAD_PID" 2>/dev/null
  echo "press load stopped"
fi

echo "===== H2.1 matrix done: $(date -u +%Y-%m-%dT%H:%M:%SZ) ====="
echo "run dirs:"; ls -d "$OUT"/*-run* 2>/dev/null
echo
echo "next: python3 $HERE/engine_compare_report.py --base-dir $OUT"
