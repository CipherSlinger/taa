#!/usr/bin/env bash
# Stage H (CPG multi-language integration) functional verification, run inside
# the container.
#
# Two phases:
#   1. a clean package produces no findings and passes, which is what keeps it
#      on the fast path - the graph pass is guarded by an empty finding list
#   2. a cross-service package takes the slow path and blocks. The report must
#      carry the whole boundary-crossing chain rather than one end of it, the
#      synthesized system-level finding must be present and attributed to the
#      graph engine, and the block must reach the platform as code=1 with the
#      model wiped
#
# Every verdict goes through check(), including the ones computed in Python:
# the Python step prints "ok|label|detail" lines and bash owns the verdict, so
# there is one place that decides pass or fail.
#
# The malicious package here is synthetic and self-authored. Nothing from the
# audit corpora is copied into it, and it is never imported, executed, or
# byte-compiled - TAA's own audit reads it, which is the thing under test.
set -uo pipefail

VERIFY=/root/taa/verify
TAA=http://127.0.0.1:6001/v1/taa/importModel
MOCK=http://127.0.0.1:18080
PORT=18099
LOG=/root/taa/taa.log
MODELS=/root/taa/models
FAILED=0

check() {
  local label="$1" ok="$2" detail="${3:-}"
  if [ "$ok" = "1" ]; then
    echo "  PASS  $label"
  else
    echo "  FAIL  $label  $detail"
    FAILED=1
  fi
}

# check_stream turns the ok|label|detail lines a Python step prints into check()
# calls. It reads from process substitution rather than a pipe: a pipeline would
# run the loop in a subshell and the FAILED it sets would not survive.
check_stream() {
  while IFS='|' read -r ok label detail; do
    [ -n "$label" ] && check "$label" "$ok" "$detail"
  done
}

log_from() { tail -c +"$1" "$LOG" 2>/dev/null; }

# wait_for <pattern> <log offset> follows the log from the offset rather than
# re-reading it on every poll, and gives up after five minutes.
#
# The lines are read one at a time instead of piped into grep -m1. Under
# pipefail the pipe form reports the opposite of the truth: grep exits the
# moment it matches, tail takes SIGPIPE, and the pipeline's status becomes
# tail's 141 even though the pattern was found.
#
# A timeout is a failure, not a note. The daemon logging the outcome is part of
# what this script asserts, and a wait that quietly gives up would let the
# checks that follow report on a run that never finished.
wait_for() {
  local pattern="$1" offset="$2" line
  while IFS= read -r line; do
    case "$line" in
      *"$pattern"*) return 0 ;;
    esac
  done < <(timeout 300 tail -c +"$offset" -f "$LOG" 2>/dev/null)
  echo "  !! timed out waiting for: $pattern"
  FAILED=1
  return 1
}

# audit_report <taskId> prints the JSON body of the audit report the platform
# received for that task, or nothing if it never arrived.
audit_report() {
  curl -fsS "$MOCK/api/reportAudit/status" 2>/dev/null | python3 -c '
import sys, json
d = json.load(sys.stdin)
for e in ((d.get("result") or {}).get("history") or []):
    if e.get("taskId") == sys.argv[1]:
        print(json.dumps({"code": e.get("code"), "msg": e.get("msg"),
                          "report": json.loads(e.get("report") or "{}")}))
        break' "$1"
}

# audit_code <taskId> reads the platform's code field out of the same report.
audit_code() {
  audit_report "$1" | python3 -c '
import sys, json
try:
    print(json.load(sys.stdin).get("code"))
except Exception:
    pass'
}

echo "===================== setup ====================="
rm -rf "$VERIFY/pkg-cpg-clean" "$VERIFY/pkg-cpg-cross"
mkdir -p "$VERIFY/pkg-cpg-clean"

# ---------------------------------------------------------------- clean ----
cat > "$VERIFY/pkg-cpg-clean/train.py" <<'PY'
import torch
import torch.nn as nn


class Net(nn.Module):
    def __init__(self):
        super().__init__()
        self.fc = nn.Linear(10, 2)

    def forward(self, x):
        return self.fc(x)
PY

# ---------------------------------------------------------- cross-service ----
# One value read in service_a and executed in service_b. Each file on its own
# is ordinary; the defect exists only in the join, which is what the graph
# layer is for and what neither Tier 1 engine can see.
mkdir -p "$VERIFY/pkg-cpg-cross/service_a" "$VERIFY/pkg-cpg-cross/service_b"
cat > "$VERIFY/pkg-cpg-cross/service_a/client.py" <<'PY'
import os

import requests


def send_telemetry():
    payload = os.environ["API_KEY"]
    requests.post("http://sidecar:8080/v1/telemetry", json=payload)
PY
cat > "$VERIFY/pkg-cpg-cross/service_b/server.py" <<'PY'
import os

from flask import Flask, request

app = Flask(__name__)


@app.post("/v1/telemetry")
def telemetry():
    data = request.get_json()
    os.system(data)
PY

python3 - <<'PY'
import os, zipfile
for name in ("pkg-cpg-clean", "pkg-cpg-cross"):
    src = os.path.join("/root/taa/verify", name)
    dst = src + ".zip"
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as z:
        for root, _, files in os.walk(src):
            for f in files:
                full = os.path.join(root, f)
                z.write(full, os.path.relpath(full, src))
    print("package %s: %d bytes" % (dst, os.path.getsize(dst)))
PY

pkill -f "http.server ${PORT}" >/dev/null 2>&1
(cd "$VERIFY" && nohup python3 -m http.server "$PORT" >/dev/null 2>&1 &)
for _ in $(seq 1 20); do
  curl -fsS -o /dev/null "http://127.0.0.1:${PORT}/pkg-cpg-clean.zip" && break
  sleep 0.5
done
echo "file server: $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:${PORT}/pkg-cpg-clean.zip)"

echo ""
echo "===================== 1. clean package: the fast path ====================="
curl -fsS -X POST "$MOCK/api/reportAudit/reset" >/dev/null 2>&1
curl -fsS -X POST "$MOCK/api/reportModelImport/reset" >/dev/null 2>&1
OFFSET=$(( $(wc -c < "$LOG") + 1 ))
curl -fsS -X POST "$TAA" -H 'Content-Type: application/json' \
  -d "{\"resourceUrl\":\"http://127.0.0.1:${PORT}/pkg-cpg-clean.zip\",\"requestId\":\"h-clean\",\"taskId\":\"h-task-clean\",\"runtimeConfig\":\"{\\\"commands\\\":[\\\"python3 train.py\\\"]}\"}" >/dev/null
wait_for "审计完成" "$OFFSET"
sleep 2
log_from "$OFFSET" | grep "审计完成" | sed 's/^/  log: /'

CLEAN_N=$(audit_report h-task-clean | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
except Exception:
    print(-1); raise SystemExit
r = d.get("report") or {}
print(sum(len(fr.get("findings") or []) for fr in r.get("file_reports") or []))')

check "clean package produced no findings (graph pass never entered)" \
      "$([ "$CLEAN_N" = "0" ] && echo 1 || echo 0)" "findings=$CLEAN_N"
check "clean package passed the gate" \
      "$([ "$(audit_code h-task-clean)" = "0" ] && echo 1 || echo 0)"

echo ""
echo "===================== 2. cross-service package: block ====================="
curl -fsS -X POST "$MOCK/api/reportAudit/reset" >/dev/null 2>&1
curl -fsS -X POST "$MOCK/api/reportModelImport/reset" >/dev/null 2>&1
OFFSET=$(( $(wc -c < "$LOG") + 1 ))
curl -fsS -X POST "$TAA" -H 'Content-Type: application/json' \
  -d "{\"resourceUrl\":\"http://127.0.0.1:${PORT}/pkg-cpg-cross.zip\",\"requestId\":\"h-cross\",\"taskId\":\"h-task-cross\",\"runtimeConfig\":\"{\\\"commands\\\":[\\\"python3 train.py\\\"]}\"}" >/dev/null
wait_for "模型安全审计未通过" "$OFFSET"
sleep 3
echo "  --- daemon log ---"
log_from "$OFFSET" | grep "审计\|清除模型状态" | sed 's/^/  /'

check_stream < <(audit_report h-task-cross | python3 -c '
import sys, json
d = json.load(sys.stdin)
rep = d.get("report") or {}
stats = (rep.get("conclusion") or {}).get("statistics") or {}
findings = [f for fr in rep.get("file_reports") or [] for f in (fr.get("findings") or [])]
synth = [f for f in findings if f.get("rule_id") == "taa-cross-service-rce"]
enriched = [f for f in findings if f.get("cpg_evidence")]

def check(label, ok, detail=""):
    print("%d|%s|%s" % (1 if ok else 0, label, "" if ok else detail))

check("the platform was told code=1", d.get("code") == 1, "code=%s" % d.get("code"))
check("the report marks the flow as crossing a service",
      (stats.get("microservice") or 0) > 0, "microservice=%s" % stats.get("microservice"))
check("the report marks the flow as crossing a file",
      (stats.get("cross_file") or 0) > 0, "cross_file=%s" % stats.get("cross_file"))
check("Tier 1 findings on the path carry the trajectory",
      len(enriched) > 0, "enriched=%d" % len(enriched))
check("exactly one system-level finding was synthesized",
      len(synth) == 1, "synthesized=%d" % len(synth))

if synth:
    s = synth[0]
    ev = s.get("cpg_evidence") or ""
    trace = s.get("taint_trace") or []
    edges = [t.get("edge_type") or t.get("type") for t in trace]
    check("the synthesized finding is attributed to the graph engine",
          s.get("engine") == "cpg", "engine=%s" % s.get("engine"))
    check("it is anchored at the sink, not at the source",
          "server.py" in (s.get("file") or ""), "file=%s" % s.get("file"))
    check("the trajectory names both services",
          "service_a" in ev and "service_b" in ev, "")
    check("the trajectory crosses the microservice boundary",
          any(e and "MICROSERVICE" in e for e in edges), "edges=%s" % edges)
    check("the trajectory ends at a command-execution sink",
          "CMD_001" in ev and "SINK" in ev, "")
    # stderr, so the evidence stays out of the check stream.
    print("  --- evidence as the model sees it ---", file=sys.stderr)
    for ln in ev.splitlines():
        print("  " + ln, file=sys.stderr)
    print("  --- llm verdict: %s" % s.get("llm_verdict"), file=sys.stderr)
')

echo "  --- model state after the block ---"
REMAIN=$(ls -A "$MODELS" 2>/dev/null | wc -l)
check "/root/taa/models was wiped" "$([ "$REMAIN" = "0" ] && echo 1 || echo 0)" "entries=$REMAIN"

echo ""
echo "===================== engine provenance ====================="
grep -o "engine=[a-z]*" "$LOG" | sort | uniq -c
pkill -f "http.server ${PORT}" >/dev/null 2>&1
echo "===================== $( [ "$FAILED" = "0" ] && echo 'ALL CHECKS PASSED' || echo 'FAILURES PRESENT' ) ====================="
exit "$FAILED"
