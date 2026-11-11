#!/usr/bin/env bash
# Unit tests for the pure helpers in taa-init.sh.
#
# The wrapper itself cannot be run here: it is PID 1 inside a CSV2 guest and
# needs /dev/console, a mounted /proc and a /dev it may mknod in. Its decision
# helpers, however, are plain shell over files, and they are the parts that
# silently produce a wrong verdict -- a wrong csv-guest minor degrades
# attestation to an empty report. So they are tested with fixtures instead of
# left to the next hardware run.
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

echo "== apply_cmdline_identity =="

# The kernel command line is host-provided input read by PID 1, so these tests
# are mostly about what must NOT happen: unknown keys ignored, no arbitrary name
# exported, and a missing /proc/cmdline not taking the boot down.

cmdline="$WORK_DIR/cmdline"
cat >"$cmdline" <<'EOF'
BOOT_IMAGE=/vmlinuz rdinit=/usr/local/bin/taa-init console=hvc0 taa.platform_ip=10.1.2.3:18080 taa.docker_id=fixture-docker-id taa.platform_public_key=04ab taa.llm_endpoint=https://10.1.2.3:8443
EOF

got="$(
  export CMDLINE_FILE="$cmdline"
  apply_cmdline_identity >/dev/null 2>&1
  printf '%s|%s|%s' "${PLATFORM_IP:-}" "${DOCKER_ID:-}" \
    "${PLATFORM_PUBLIC_KEY:-}"
)"
check "maps taa.* tokens onto the deployment names" \
  '10.1.2.3:18080|fixture-docker-id|04ab' "$got"

# The env file is the build-time fallback; the command line is the deployment's
# current identity and has to win.
got="$(
  PLATFORM_IP=10.0.0.9 DOCKER_ID=stale
  export CMDLINE_FILE="$cmdline"
  apply_cmdline_identity >/dev/null 2>&1
  printf '%s|%s' "$PLATFORM_IP" "$DOCKER_ID"
)"
check "overrides the baked env file" '10.1.2.3:18080|fixture-docker-id' "$got"

# Anything not on the allow-list stays out of the environment, including names
# that would let the host turn a token into a privileged setting (PATH) or into
# secret material (TAASECRETKEY is never carried at all).
leak_cmdline="$WORK_DIR/cmdline-leak"
cat >"$leak_cmdline" <<'EOF'
taa.path=/tmp/evil taa.TAASECRETKEY=secret taa.unknown_key=x taa.=empty
EOF
got="$(
  export CMDLINE_FILE="$leak_cmdline"
  apply_cmdline_identity >/dev/null 2>&1
  for name in TAASECRETKEY UNKNOWN_KEY; do
    if declare -p "$name" >/dev/null 2>&1; then printf '%s ' "$name"; fi
  done
  printf 'PATH=%s' "$PATH"
)"
check "refuses keys outside the allow-list" "PATH=$PATH" "$got"

# A non-taa token must not be re-exported under its own name.
got="$(
  export CMDLINE_FILE="$leak_cmdline"
  apply_cmdline_identity >/dev/null 2>&1
  declare -p taa.unknown_key >/dev/null 2>&1 && echo exported || echo absent
)"
check "does not export the raw token name" "absent" "$got"

# Duplicate keys are prevented at render time, but a hand-edited config could
# still carry two: the later one has to win, as it would for the kernel.
dup_cmdline="$WORK_DIR/cmdline-dup"
printf 'taa.platform_ip=1.1.1.1:1 taa.platform_ip=2.2.2.2:2\n' >"$dup_cmdline"
got="$(
  export CMDLINE_FILE="$dup_cmdline"
  apply_cmdline_identity >/dev/null 2>&1
  printf '%s' "$PLATFORM_IP"
)"
check "the last duplicate wins" "2.2.2.2:2" "$got"

# An unreadable command line must not abort: PID 1 has no supervisor to restart
# it, and the env file is still a usable identity.
set +e
( export CMDLINE_FILE="$WORK_DIR/does-not-exist"; apply_cmdline_identity ) >/dev/null 2>&1
rc=$?
set -e
check "missing CMDLINE_FILE still returns 0" "0" "$rc"

# taa.modules is the one identity key that is not a TAA setting: it names the
# drivers taa-init has to load before anything looks for the device.
modules_cmdline="$WORK_DIR/cmdline-modules"
printf 'taa.modules=hycu,hycu-sched\n' >"$modules_cmdline"
got="$(
  unset TAA_MODULES
  export CMDLINE_FILE="$modules_cmdline"
  apply_cmdline_identity >/dev/null 2>&1
  printf '%s' "${TAA_MODULES:-<unset>}"
)"
check "maps taa.modules onto TAA_MODULES" "hycu,hycu-sched" "$got"

echo "== load_kernel_modules =="

# A stub kmod records the argv it was called with; the real one only lives
# inside the DCU payload and cannot be run here.
stub_kmod="$WORK_DIR/kmod"
kmod_log="$WORK_DIR/kmod.log"
cat >"$stub_kmod" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"${KMOD_LOG:?}"
exit "${KMOD_STUB_RC:-0}"
EOF
chmod +x "$stub_kmod"

release="$(uname -r)"
modules_dir="$WORK_DIR/modules"
mkdir -p "$modules_dir/$release"
: >"$modules_dir/$release/modules.dep"

# Empty list: the function must not touch kmod at all. That is what every
# non-DCU role relies on, since their initrd ships no kmod binary.
rm -f "$kmod_log"
set +e
( unset TAA_MODULES
  KMOD_BIN="$stub_kmod" MODULES_DIR="$modules_dir" load_kernel_modules ) >/dev/null 2>&1
rc=$?
set -e
check "an empty module list is a no-op" "absent" \
  "$([[ -e "$kmod_log" ]] && echo present || echo absent)"
check "an empty module list still returns 0" "0" "$rc"

# Comma-separated, in order, one modprobe per name; an empty element between
# commas must not become an empty module name.
got="$(
  export KMOD_LOG="$kmod_log"
  KMOD_BIN="$stub_kmod" MODULES_DIR="$modules_dir" TAA_MODULES=hycu,,hycu-sched \
    load_kernel_modules >/dev/null 2>&1
  cat "$kmod_log"
)"
check "loads each named module in order" 'modprobe hycu
modprobe hycu-sched' "$got"

# modules.dep is shipped, so the normal path must not pay for a depmod.
rm -f "$kmod_log"
( export KMOD_LOG="$kmod_log"
  KMOD_BIN="$stub_kmod" MODULES_DIR="$modules_dir" TAA_MODULES=hycu \
    load_kernel_modules ) >/dev/null 2>&1
check "does not re-run depmod when modules.dep is present" "1" "$(wc -l <"$kmod_log")"

# Without it the kernel cannot resolve dependencies, so depmod runs first; it
# writes only into the initrd's ramfs and is cheap next to an unloadable module.
empty_modules="$WORK_DIR/modules-empty"
mkdir -p "$empty_modules"
rm -f "$kmod_log"
( export KMOD_LOG="$kmod_log"
  KMOD_BIN="$stub_kmod" MODULES_DIR="$empty_modules" TAA_MODULES=hycu \
    load_kernel_modules ) >/dev/null 2>&1
check "runs depmod before loading when modules.dep is missing" "depmod -b / $release" \
  "$(head -1 "$kmod_log")"

# PID 1 must not exit: a module that fails to load is logged, and the boot goes
# on. The task that needs the card fails later with an error naming it.
set +e
( export KMOD_LOG="$kmod_log"; export KMOD_STUB_RC=1
  KMOD_BIN="$stub_kmod" MODULES_DIR="$modules_dir" TAA_MODULES=hycu,hycu-sched \
    load_kernel_modules ) >/dev/null 2>&1
rc=$?
set -e
check "a failed modprobe is not fatal" "0" "$rc"

# A role whose initrd has no kmod (or a payload fetched without it) must warn
# and continue rather than abort.
set +e
( KMOD_BIN="$WORK_DIR/no-such-kmod" MODULES_DIR="$modules_dir" TAA_MODULES=hycu \
  load_kernel_modules ) >/dev/null 2>&1
rc=$?
set -e
check "a missing kmod is not fatal" "0" "$rc"

echo "== TAA restart supervision =="

# Nothing in the initrd restarts TAA, so these helpers are the only thing between
# a crash and a guest that is up but no longer serves /v1/taa/*. The backoff has
# to double on a quick crash and reset after a stable run, or a permanently
# broken config either spins or never gets a fast retry after a one-off exit.
check "keeps backing off while failures are quick" "20" \
  "$(TAA_RESTART_DELAY=5 TAA_RESTART_STABLE_SECONDS=60 restart_delay_after 20 5)"
check "resets the delay once a run was stable" "5" \
  "$(TAA_RESTART_DELAY=5 TAA_RESTART_STABLE_SECONDS=60 restart_delay_after 40 60)"
check "doubles the delay after a quick exit" "40" \
  "$(TAA_RESTART_MAX_DELAY=60 double_restart_delay 20)"
check "caps the delay at the maximum" "60" \
  "$(TAA_RESTART_MAX_DELAY=60 double_restart_delay 40)"

# The delay is compared as an integer, so a fractional or malformed uptime must
# not leak into the arithmetic (which would abort the supervisor under set -u).
uptime_ok="$WORK_DIR/uptime-ok"
printf '123.45 67.89\n' >"$uptime_ok"
check "truncates /proc/uptime to whole seconds" "123" \
  "$(UPTIME_FILE="$uptime_ok" uptime_seconds)"
uptime_bad="$WORK_DIR/uptime-bad"
printf 'not-a-number\n' >"$uptime_bad"
check "a malformed uptime reads as 0" "0" \
  "$(UPTIME_FILE="$uptime_bad" uptime_seconds)"
check "a missing uptime reads as 0" "0" \
  "$(UPTIME_FILE="$WORK_DIR/no-such-uptime" uptime_seconds)"

echo "== main flow invariants =="

# The PATH extension is a side effect on the environment, so it lives in the main
# flow and cannot be sourced and called here. It is still worth pinning: PID 1's
# default PATH has no /usr/local/bin, TAA resolves the semgrep CLI through PATH,
# and the only symptom of losing this line is a remote "executable file not found"
# on every audit -- after a build, a deploy and a boot. Order matters too: the
# export has to precede the TAA invocation below it.
path_line="$(grep -nF 'PATH="/usr/local/bin:$PATH"' "$TAA_INIT" | cut -d: -f1 | head -1)"
# The call site, not the definition inside supervise_taa: the ordering below is
# about the main flow starting TAA after its environment is in place.
taa_line="$(grep -nF 'supervise_taa &' "$TAA_INIT" | cut -d: -f1 | head -1)"
check "extends PATH before starting TAA" "yes" \
  "$([[ -n "$path_line" && -n "$taa_line" && "$path_line" -lt "$taa_line" ]] && echo yes || echo no)"

# The deployment marker tells TAA it runs from the initrd. It has to be exported
# before the TAA invocation, and it has to be the literal initrd value: TAA's
# mount-based inference exists so a forgotten export shows up as a warning, not
# so this script can stop declaring itself.
dep_line="$(grep -nF 'export TAA_DEPLOYMENT' "$TAA_INIT" | cut -d: -f1 | head -1)"
check "exports the deployment marker before starting TAA" "yes" \
  "$([[ -n "$dep_line" && -n "$taa_line" && "$dep_line" -lt "$taa_line" ]] && echo yes || echo no)"
check "declares the initrd shape rather than guessing" "yes" \
  "$(grep -qF 'TAA_DEPLOYMENT=initrd' "$TAA_INIT" && echo yes || echo no)"

# Module loading sits between the two edges that define it: after
# apply_cmdline_identity, because the list comes from the command line, and
# before TAA starts, because the device has to exist by the time anything opens
# it. Getting either edge wrong leaves the driver unloaded with no error.
identity_line="$(grep -n '^apply_cmdline_identity$' "$TAA_INIT" | cut -d: -f1 | head -1 || true)"
modules_line="$(grep -n '^load_kernel_modules$' "$TAA_INIT" | cut -d: -f1 | head -1 || true)"
check "loads modules after the command line is read" "yes" \
  "$([[ -n "$identity_line" && -n "$modules_line" && "$identity_line" -lt "$modules_line" ]] && echo yes || echo no)"
check "loads modules before TAA starts" "yes" \
  "$([[ -n "$modules_line" && -n "$taa_line" && "$modules_line" -lt "$taa_line" ]] && echo yes || echo no)"

# The supervisor itself must wait on each TAA process and pause between retries;
# without both it would either spawn unbounded processes or exit on the first
# crash. It has to be started in the background: PID 1 reaches the final exec,
# which would otherwise replace the loop.
supervisor_body="$(awk '/^supervise_taa\(\) \{/{f=1} f{print} f&&/^\}/{exit}' "$TAA_INIT")"
check "the supervisor waits for the TAA process to exit" "yes" \
  "$(grep -qF 'wait "$taa_pid"' <<<"$supervisor_body" && echo yes || echo no)"
check "the supervisor pauses before restarting" "yes" \
  "$(grep -qF 'sleep "$delay"' <<<"$supervisor_body" && echo yes || echo no)"
check "backgrounds the supervisor so PID 1 can exec" "yes" \
  "$(grep -qE '^[[:space:]]*supervise_taa &[[:space:]]*$' "$TAA_INIT" && echo yes || echo no)"

exec_line="$(grep -n '^exec /sbin/init' "$TAA_INIT" | cut -d: -f1 | head -1)"
check "starts the supervisor before exec'ing kata-agent" "yes" \
  "$([[ -n "$taa_line" && -n "$exec_line" && "$taa_line" -lt "$exec_line" ]] && echo yes || echo no)"
check "the final exec is still the last statement" "yes" \
  "$([[ -n "$exec_line" && "$(tail -n 1 "$TAA_INIT" | grep -c '^exec /sbin/init')" == "1" ]] && echo yes || echo no)"

echo
if [[ "$failures" -eq 0 ]]; then
  echo "all checks passed"
else
  echo "$failures check(s) failed" >&2
  exit 1
fi
