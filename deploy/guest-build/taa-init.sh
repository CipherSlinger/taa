#!/bin/sh
# taa-init -- first userspace process of the Kata CSV2 initrd, selected by the
# kernel parameter rdinit=.
#
# Why not a systemd unit: this initrd has no systemd. usr/sbin/init is kata-agent,
# and a unit file dropped in here would never be executed by anything.
# Why rdinit= and not init=: kernel_init() tries the ramdisk init first (rdinit=,
# default /init) and never looks at init= once that succeeds -- and the base
# initrd already has a root-level init -> /sbin/init. So init= is dead config.
#
# PID 1 rule: if PID 1 exits, the kernel panics with "Attempted to kill init" and
# the whole VM dies -- not a failed Pod, a failed VM. This script therefore does
# not use `set -e`: every step has to swallow its own failure (|| true) or handle
# it explicitly, and the only exit path allowed is the final exec.
set -u

CONSOLE=/dev/console
TAA_BIN=/usr/local/bin/taa
TAA_CONFIG=/etc/taa/taa-config.json
TAA_LOG=/tmp/taa.log
ENV_FILE=/etc/default/taa.env

# csv-guest is a misc device: major 10 is fixed, the minor is allocated
# dynamically by the kernel (measured 2026-10-09 as "256 csv-guest" in
# /proc/misc), so it must be read at runtime and never hardcoded.
# These two paths are overridable only so the helpers can be tested locally;
# production always uses the defaults.
CSV_MISC_FILE="${CSV_MISC_FILE:-/proc/misc}"
CSV_SYSDEV_FILE="${CSV_SYSDEV_FILE:-/sys/class/misc/csv-guest/dev}"
CSV_DEV=/dev/csv-guest
CSV_MAJOR=10

# The two log lines that carry TAA's attestation verdict
# (internal/app/taa/app.go:548 and :569).
ATTESTATION_OK_PATTERN="attestation report verified successfully"
ATTESTATION_DEGRADED_PATTERN="continuing with empty report"

log() { echo "taa-init: $*" >"$CONSOLE" 2>/dev/null || true; }

# Print the csv-guest minor, or nothing when neither source can be read.
# /proc/misc is preferred: that is the path used for the 2026-10-09 evidence.
resolve_csv_minor() {
  local minor=""
  local candidate name
  if [ -r "$CSV_MISC_FILE" ]; then
    while read -r candidate name; do
      if [ "$name" = "csv-guest" ]; then minor="$candidate"; break; fi
    done <"$CSV_MISC_FILE"
  fi
  if [ -z "$minor" ] && [ -r "$CSV_SYSDEV_FILE" ]; then
    IFS=: read -r _csv_major minor <"$CSV_SYSDEV_FILE" || true
  fi
  if [ -n "$minor" ]; then
    printf '%s\n' "$minor"
  fi
  return 0
}

# Wait for TAA to state its verdict in the log:
#   0 = self-verification passed   1 = degraded to an empty report   2 = timeout
# Why wait at all: on attestation failure TAA only writes a WARNING plus an empty
# report and keeps running (app.go:548), so "the process is alive" and "the Pod is
# Ready" are both worthless as evidence. This line is the only one that counts.
wait_for_attestation_verdict() {
  local log_file="$1"
  local max_wait="$2"
  local i=0
  while [ "$i" -lt "$max_wait" ]; do
    if [ -r "$log_file" ]; then
      if grep -q "$ATTESTATION_OK_PATTERN" "$log_file" 2>/dev/null; then return 0; fi
      if grep -q "$ATTESTATION_DEGRADED_PATTERN" "$log_file" 2>/dev/null; then return 1; fi
    fi
    sleep 1
    i=$((i + 1))
  done
  return 2
}

# ===== main flow (local tests source only the part above this line) =====

# Read the build-time /etc/default/taa.env. It carries TAA_ADDR, TAA_REQUIRED,
# TAA_REQUIRE_ATTESTATION, PLATFORM_IP and DOCKER_ID.
if [ -r "$ENV_FILE" ]; then
  . "$ENV_FILE"
fi

cd / || true

TAA_ADDR="${TAA_ADDR:-0.0.0.0:6001}"
TAA_REQUIRED="${TAA_REQUIRED:-1}"
TAA_REQUIRE_ATTESTATION="${TAA_REQUIRE_ATTESTATION:-1}"
ATTESTATION_TIMEOUT="${ATTESTATION_TIMEOUT:-60}"

# With TAA_REQUIRED=1, do not step aside for kata-agent: the Pod stays NotReady.
# That is deliberate fail-closed behaviour.
fail_taa_required() {
  log "$1"
  if [ "$TAA_REQUIRED" = "1" ]; then
    if [ -r "$TAA_LOG" ]; then
      cat "$TAA_LOG" >"$CONSOLE" 2>&1 || true
    fi
    log "TAA_REQUIRED=1; not starting kata-agent"
    while true; do sleep 3600; done
  fi
}

# 1) Mount /proc and /sys. This script runs before kata-agent, so both are still
#    empty (mounting them is init's job) and the minor lookup below needs them.
mkdir -p /proc /sys 2>/dev/null || true
mount -t proc  proc  /proc >/dev/null 2>&1 || true
mount -t sysfs sysfs /sys  >/dev/null 2>&1 || true

# 2) Create /dev/csv-guest. The driver is built in (CONFIG_CSV_GUEST=y) and has
#    already called misc_register(); only the node is missing, because this
#    guest's /dev is neither devtmpfs nor managed by udev.
if [ ! -e "$CSV_DEV" ]; then
  csv_minor="$(resolve_csv_minor)"
  if [ -n "$csv_minor" ]; then
    if mknod "$CSV_DEV" c "$CSV_MAJOR" "$csv_minor" 2>/dev/null; then
      chmod 600 "$CSV_DEV" 2>/dev/null || true
      log "created $CSV_DEV ($CSV_MAJOR, $csv_minor)"
    else
      log "WARNING: mknod $CSV_DEV c $CSV_MAJOR $csv_minor failed"
    fi
  else
    log "WARNING: csv-guest minor unreadable from $CSV_MISC_FILE and $CSV_SYSDEV_FILE; the csv-hw state sealing key is unavailable and attestation will degrade to an empty report"
  fi
fi

# 3) Start TAA. The gate is "config is readable" -- that file is a hard dependency
#    (TAA exits 1 without it). PLATFORM_IP/DOCKER_ID only affect registration,
#    and a failed registration is already just a warning (app.go:135).
#
#    PID 1 inherits the kernel's default PATH (/sbin:/usr/sbin:/bin:/usr/bin),
#    which does not include /usr/local/bin. TAA resolves the semgrep CLI through
#    PATH, so the engine would report "executable file not found" on every audit
#    while the binary sits right next to this script. Extend PATH here, where the
#    rest of the boot environment is already being set up.
PATH="/usr/local/bin:$PATH"
export PATH

TAA_PID=""
if [ -r "$TAA_CONFIG" ]; then
  "$TAA_BIN" -config "$TAA_CONFIG" -addr "$TAA_ADDR" >"$TAA_LOG" 2>&1 &
  TAA_PID="$!"
else
  fail_taa_required "missing $TAA_CONFIG; not starting TAA"
fi

# 4) Liveness probe. A live process is not a working service; this only proves it
#    did not exit immediately.
if [ -n "$TAA_PID" ]; then
  sleep 2
  kill -0 "$TAA_PID" >/dev/null 2>&1 || fail_taa_required "TAA exited immediately"
fi

# 5) Attestation gate. Neither step above shows that the report is real, so the
#    acceptance criterion is moved forward into the boot path.
if [ -n "$TAA_PID" ] && [ "$TAA_REQUIRE_ATTESTATION" = "1" ]; then
  wait_for_attestation_verdict "$TAA_LOG" "$ATTESTATION_TIMEOUT"
  case "$?" in
    0) log "attestation self-verification passed" ;;
    1) fail_taa_required "attestation degraded to an empty report (see log above)" ;;
    *) fail_taa_required "no attestation verdict in $TAA_LOG after ${ATTESTATION_TIMEOUT}s" ;;
  esac
fi

exec /sbin/init "$@"
