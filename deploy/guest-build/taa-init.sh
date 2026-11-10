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
# Overridable only so the helpers can be tested locally, like the two above.
CMDLINE_FILE="${CMDLINE_FILE:-/proc/cmdline}"
CSV_DEV=/dev/csv-guest
CSV_MAJOR=10

log() { echo "taa-init: $*" >"$CONSOLE" 2>/dev/null || true; }

# Deployment identity can also arrive on the kernel command line as
# `taa.<key>=<value>`. That is how a deployment changes its platform address,
# docker id, public key or LLM endpoint without rebuilding the measured initrd:
# the launcher renders the tokens into the Kata config's kernel_params, QEMU puts
# them on -append, and they are read from here.
#
# Only the names below are honoured. The command line is host-provided input, so
# exporting arbitrary names from it would let the host set anything at all.
cmdline_env_name() {
  case "$1" in
    platform_ip)         echo PLATFORM_IP ;;
    docker_id)           echo DOCKER_ID ;;
    platform_public_key) echo PLATFORM_PUBLIC_KEY ;;
    platform_sm2_id)     echo PLATFORM_SM2_ID ;;
    contract_id)         echo CONTRACT_ID ;;
    contract_type)       echo CONTRACT_TYPE ;;
    llm_endpoint)        echo TAA_LLM_ENDPOINT ;;
    addr)                echo TAA_ADDR ;;
    *) return 1 ;;
  esac
}

# Values override the build-time /etc/default/taa.env: the image may be older than
# the deployment it is used for. They are whitespace-free by construction -- the
# renderer refuses anything else -- so a plain word split is enough here.
apply_cmdline_identity() {
  [ -r "$CMDLINE_FILE" ] || return 0
  local token key value name applied=""
  for token in $(cat "$CMDLINE_FILE" 2>/dev/null); do
    case "$token" in
      taa.*=*) ;;
      *) continue ;;
    esac
    key="${token%%=*}"
    key="${key#taa.}"
    value="${token#*=}"
    name="$(cmdline_env_name "$key")" || continue
    export "$name=$value"
    applied="$applied $name"
  done
  if [ -n "$applied" ]; then
    log "identity from kernel cmdline:$applied"
  fi
  return 0
}

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

# ===== main flow (local tests source only the part above this line) =====

# Read the build-time /etc/default/taa.env. It carries the wrapper switch
# (TAA_ADDR) and the deployment identity TAA reads at startup (PLATFORM_IP,
# DOCKER_ID, PLATFORM_PUBLIC_KEY, PLATFORM_SM2_ID, CONTRACT_ID, CONTRACT_TYPE,
# TAA_LLM_ENDPOINT). This file is the guest's fallback environment; the same
# names can be overridden from the kernel command line (see
# apply_cmdline_identity below), which is what lets a deployment change its
# identity without rebuilding the image.
if [ -r "$ENV_FILE" ]; then
  . "$ENV_FILE"
fi

cd / || true

TAA_ADDR="${TAA_ADDR:-0.0.0.0:6001}"

# 1) Mount /proc and /sys. This script runs before kata-agent, so both are still
#    empty (mounting them is init's job) and the minor lookup below needs them.
mkdir -p /proc /sys 2>/dev/null || true
mount -t proc  proc  /proc >/dev/null 2>&1 || true
mount -t sysfs sysfs /sys  >/dev/null 2>&1 || true

# 1b) Identity from the kernel command line, overriding the env file read above.
#     Must run after /proc is mounted: /proc/cmdline is the only copy of it.
apply_cmdline_identity

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

# 3) Start TAA. A missing config is logged and the boot continues: TAA is the
#    daemon every later step talks to, but the VM itself has to come up, so
#    nothing here may hold kata-agent hostage. PLATFORM_IP/DOCKER_ID only affect
#    registration, and a failed registration is already just a warning
#    (app.go:135).
#
#    PID 1 inherits the kernel's default PATH (/sbin:/usr/sbin:/bin:/usr/bin),
#    which does not include /usr/local/bin. TAA resolves the semgrep CLI through
#    PATH, so the engine would report "executable file not found" on every audit
#    while the binary sits right next to this script. Extend PATH here, where the
#    rest of the boot environment is already being set up.
PATH="/usr/local/bin:$PATH"
export PATH

#    Tell TAA how it was started. This script is measured code that only ever
#    runs as the initrd's first userspace process, and environment does not
#    cross namespaces into a container, so the value cannot leak into the
#    container deployment's own process. It decides where model work executes,
#    never a security verdict.
TAA_DEPLOYMENT=initrd
export TAA_DEPLOYMENT

if [ -r "$TAA_CONFIG" ]; then
  "$TAA_BIN" -config "$TAA_CONFIG" -addr "$TAA_ADDR" >"$TAA_LOG" 2>&1 &
  taa_pid="$!"
  # Liveness probe. A live process is not a working service; this only proves it
  # did not exit immediately, and it is reported rather than acted on.
  sleep 2
  kill -0 "$taa_pid" >/dev/null 2>&1 || log "WARNING: TAA exited immediately; see $TAA_LOG"
else
  log "WARNING: missing $TAA_CONFIG; not starting TAA"
fi

exec /sbin/init "$@"
