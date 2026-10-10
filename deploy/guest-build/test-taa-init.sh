#!/usr/bin/env bash
# Unit tests for the two pure helpers in taa-init.sh.
#
# The wrapper itself cannot be run here: it is PID 1 inside a CSV2 guest and
# needs /dev/console, a mounted /proc and a /dev it may mknod in. Its two
# decision helpers, however, are plain shell over files, and they are the parts
# that silently produce a wrong verdict -- a wrong csv-guest minor degrades
# attestation to an empty report, and a wrong wait verdict either blocks a
# healthy boot or lets a degraded one through. So they are tested with fixtures
# instead of left to the next hardware run.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TAA_INIT="$SCRIPT_DIR/taa-init.sh"

if [[ ! -r "$TAA_INIT" ]]; then
  echo "error: cannot read $TAA_INIT" >&2
  exit 1
fi

WORK_DIR="$(mktemp -d /tmp/taa-init-test.XXXXXX)"
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

failures=0

check() {
  local what="$1"
  local expected="$2"
  local actual="$3"
  if [[ "$actual" == "$expected" ]]; then
    printf 'ok   %s\n' "$what"
  else
    printf 'FAIL %s\n     expected: %s\n     actual:   %s\n' "$what" "$expected" "$actual" >&2
    failures=$((failures + 1))
  fi
}

# Source only the helper part of the wrapper. The marker is part of the contract:
# everything above it must stay side-effect free, or sourcing it would start
# TAA and exec kata-agent inside this test.
marker='# ===== main flow'
if ! grep -qF "$marker" "$TAA_INIT"; then
  echo "error: main-flow marker not found in $TAA_INIT" >&2
  exit 1
fi
# shellcheck disable=SC1090
. <(sed -n "1,\|$marker|p" "$TAA_INIT" | sed '$d')

echo "== resolve_csv_minor =="

misc="$WORK_DIR/misc"
printf '  1 ram0\n 14 netlink\n256 csv-guest\n' >"$misc"
missing_sysdev="$WORK_DIR/no-such-dev"
check "reads the minor from /proc/misc" "256" \
  "$(CSV_MISC_FILE="$misc" CSV_SYSDEV_FILE="$missing_sysdev" resolve_csv_minor)"

# Fallback source. This is the path that produced the working recipe on
# 2026-10-09; /proc/misc is preferred only because it was measured first.
sysdev="$WORK_DIR/sysdev"
printf '10:257\n' >"$sysdev"
no_csv_misc="$WORK_DIR/misc-without-csv"
printf '  1 ram0\n' >"$no_csv_misc"
check "falls back to /sys/class/misc/csv-guest/dev" "257" \
  "$(CSV_MISC_FILE="$no_csv_misc" CSV_SYSDEV_FILE="$sysdev" resolve_csv_minor)"

# Nothing readable: must print nothing and still succeed. Returning nonzero here
# would take down PID 1 under `set -u` semantics elsewhere in the wrapper.
set +e
out="$(CSV_MISC_FILE="$missing_sysdev" CSV_SYSDEV_FILE="$missing_sysdev" resolve_csv_minor)"
rc=$?
set -e
check "prints nothing when neither source exists" "" "$out"
check "still returns 0 when neither source exists" "0" "$rc"

# A device with a name that merely contains "csv-guest" must not match: the
# lookup is an exact field compare, not a substring one.
decoy="$WORK_DIR/misc-decoy"
printf '  7 not-csv-guest\n' >"$decoy"
check "does not match a name that merely contains csv-guest" "" \
  "$(CSV_MISC_FILE="$decoy" CSV_SYSDEV_FILE="$missing_sysdev" resolve_csv_minor)"

echo "== wait_for_attestation_verdict =="

ok_log="$WORK_DIR/ok.log"
printf 'starting\nattestation report verified successfully\n' >"$ok_log"
set +e
wait_for_attestation_verdict "$ok_log" 5
check "verified report -> 0" "0" "$?"

degraded_log="$WORK_DIR/degraded.log"
printf 'starting\nWARNING: continuing with empty report\n' >"$degraded_log"
wait_for_attestation_verdict "$degraded_log" 5
check "degraded report -> 1" "1" "$?"

# Neither line appears: the wait must expire (2) rather than report success.
# This is the case that would otherwise let a Pod reach Ready with an empty
# attestation report, which is exactly what the gate exists to prevent.
silent_log="$WORK_DIR/silent.log"
printf 'starting\n' >"$silent_log"
wait_for_attestation_verdict "$silent_log" 1
check "no verdict -> 2" "2" "$?"

# A missing log is the same class as a silent one.
wait_for_attestation_verdict "$WORK_DIR/does-not-exist.log" 1
check "missing log -> 2" "2" "$?"
set -e

echo
if [[ "$failures" -eq 0 ]]; then
  echo "all checks passed"
else
  echo "$failures check(s) failed" >&2
  exit 1
fi
