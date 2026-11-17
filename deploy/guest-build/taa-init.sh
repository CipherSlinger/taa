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
# The key is the environment variable's own name in lower case, so no table is
# needed here: `taa.platform_ip` becomes PLATFORM_IP, `taa.taa_llm_endpoint`
# becomes TAA_LLM_ENDPOINT and `taa.taasecretkey` becomes TAASECRETKEY. A
# setting TAA starts reading therefore needs no change to this script.
#
# Every well-formed name is exported; there is no allow-list. The command line
# is host-provided input, so this does hand the host the wrapper's and TAA's
# environment -- but the host already chooses the kernel, the initrd and the
# boot parameters, so a shorter list only hid that fact while making each new
# setting a code change here. Names must match [a-z][a-z0-9_]*; anything else
# (empty key, upper case, punctuation) is skipped rather than exported.
cmdline_env_name() {
  case "$1" in
    [!a-z]*|*[!a-z0-9_]*) return 1 ;;
  esac
  printf '%s' "$1" | sed 'y/abcdefghijklmnopqrstuvwxyz/ABCDEFGHIJKLMNOPQRSTUVWXYZ/'
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

# ---- TAA restart supervision ----------------------------------------------
#
# The initrd has no init system that could restart a dead daemon, and this
# script becomes /sbin/init (kata-agent) after starting TAA. A backgrounded TAA
# that exits would therefore leave the guest with no TAA at all: the VM and
# kata-agent stay up, so the Pod can still look Running while registration,
# heartbeats and /v1/taa/* are gone. The supervisor is a subshell precisely so
# it survives that exec; PID 1 must never wait on it, or kata-agent would never
# start.
#
# Backoff: a quick exit doubles the delay up to TAA_RESTART_MAX_DELAY, and a run
# that stayed up for TAA_RESTART_STABLE_SECONDS resets it. That keeps a
# persistently broken config from spinning, while a one-off crash recovers
# immediately.
TAA_RESTART_DELAY="${TAA_RESTART_DELAY:-5}"
TAA_RESTART_MAX_DELAY="${TAA_RESTART_MAX_DELAY:-60}"
TAA_RESTART_STABLE_SECONDS="${TAA_RESTART_STABLE_SECONDS:-60}"
# Keep at most this much of /tmp/taa.log, plus one previous generation: /tmp is
# tmpfs here, so an unrotated log is guest RAM. Overridable so the rotation can
# be tested without writing a megabyte.
TAA_LOG_MAX_BYTES="${TAA_LOG_MAX_BYTES:-1048576}"
# Overridable only so the helpers can be tested locally, like CSV_MISC_FILE.
UPTIME_FILE="${UPTIME_FILE:-/proc/uptime}"

# These knobs are baked into the measured script rather than read from the host,
# so a bad value can only come from a mistake here. It still has to be caught: a
# non-numeric delay reaches `$(( delay * 2 ))`, and dash treats an arithmetic
# error as fatal to the shell. The supervisor would die silently and TAA would
# never be restarted again, which is exactly the failure this loop exists to
# prevent. Fall back to the documented default and say so on the console.
sanitize_restart_settings() {
  case "$TAA_RESTART_DELAY" in
    ''|*[!0-9]*)
      log "WARNING: TAA_RESTART_DELAY='$TAA_RESTART_DELAY' is not a non-negative integer; using 5"
      TAA_RESTART_DELAY=5 ;;
  esac
  case "$TAA_RESTART_MAX_DELAY" in
    ''|*[!0-9]*)
      log "WARNING: TAA_RESTART_MAX_DELAY='$TAA_RESTART_MAX_DELAY' is not a non-negative integer; using 60"
      TAA_RESTART_MAX_DELAY=60 ;;
  esac
  case "$TAA_RESTART_STABLE_SECONDS" in
    ''|*[!0-9]*)
      log "WARNING: TAA_RESTART_STABLE_SECONDS='$TAA_RESTART_STABLE_SECONDS' is not a non-negative integer; using 60"
      TAA_RESTART_STABLE_SECONDS=60 ;;
  esac
  case "$TAA_LOG_MAX_BYTES" in
    ''|*[!0-9]*)
      log "WARNING: TAA_LOG_MAX_BYTES='$TAA_LOG_MAX_BYTES' is not a non-negative integer; using 1048576"
      TAA_LOG_MAX_BYTES=1048576 ;;
  esac
}
sanitize_restart_settings

# Seconds since boot, as an integer. /proc/uptime is mounted before the
# supervisor starts; a missing or malformed file reads as 0, which only makes
# the backoff more conservative.
uptime_seconds() {
  local up=0
  if [ -r "$UPTIME_FILE" ]; then
    read -r up _ 2>/dev/null <"$UPTIME_FILE" || up=0
  fi
  case "$up" in
    *.*) up="${up%%.*}" ;;
  esac
  case "$up" in
    ''|*[!0-9]*) up=0 ;;
  esac
  printf '%s\n' "$up"
}

# The delay to wait after an exit: reset when the daemon had been stable,
# otherwise keep the current (already backed-off) delay.
restart_delay_after() {
  local current="$1" ran="$2"
  if [ "$ran" -ge "$TAA_RESTART_STABLE_SECONDS" ]; then
    printf '%s\n' "$TAA_RESTART_DELAY"
  else
    printf '%s\n' "$current"
  fi
}

# Double the delay for the next failure, capped.
double_restart_delay() {
  local next=$(( $1 * 2 ))
  if [ "$next" -gt "$TAA_RESTART_MAX_DELAY" ]; then
    next="$TAA_RESTART_MAX_DELAY"
  fi
  printf '%s\n' "$next"
}

# Bound the daemon log before each launch. One previous generation is kept so
# the crash that preceded a restart is still readable; without the check a crash
# loop would append a startup log every few seconds for the life of the VM.
rotate_taa_log() {
  local size
  [ -f "$TAA_LOG" ] || return 0
  size="$(wc -c <"$TAA_LOG" 2>/dev/null || echo 0)"
  case "$size" in
    ''|*[!0-9]*) size=0 ;;
  esac
  if [ "$size" -le "$TAA_LOG_MAX_BYTES" ]; then
    return 0
  fi
  if ! mv -f "$TAA_LOG" "$TAA_LOG.1" 2>/dev/null; then
    : >"$TAA_LOG" 2>/dev/null || true
  fi
  return 0
}

supervise_taa() {
  local delay started ran rc taa_pid
  # If this loop dies, nothing restarts TAA and the guest keeps looking healthy.
  # There is no logger to escalate to, so make the exit itself visible.
  trap 'log "WARNING: TAA supervisor exited; TAA will not be restarted"' EXIT
  delay="$TAA_RESTART_DELAY"
  while :; do
    rotate_taa_log
    started="$(uptime_seconds)"
    "$TAA_BIN" -config "$TAA_CONFIG" -addr "$TAA_ADDR" >>"$TAA_LOG" 2>&1 &
    taa_pid="$!"
    wait "$taa_pid"
    rc=$?
    ran=$(( $(uptime_seconds) - started ))
    delay="$(restart_delay_after "$delay" "$ran")"
    log "WARNING: TAA exited (code $rc) after ${ran}s; restarting in ${delay}s"
    sleep "$delay"
    delay="$(double_restart_delay "$delay")"
  done
}

# ---- Hygon DCU compute manager --------------------------------------------
#
# /dev/mkfd alone lets hy-smi read temperatures and power: that path only needs
# CREATE_HYUDS_CONN, and the driver answers it. HIP/ROCR is different: libhsa's
# hsaKmtOpenKFD() also creates a hyuds connection, and the driver refuses with
# -EBADF ("MKFD file descriptor not valid in this process") until some process
# has registered a hyuds space. Only the vendor's hymgr issues that ioctl
# (MKFD_IOC_REGISTER_HYUDS_SPACE). The registration is a single global slot in
# the driver and the socket is created inside the registering process's netns,
# while the returned connection works from any netns -- so one manager here in
# the guest serves containers in every network namespace.
#
# The driver is loaded by the prestart CDI hook, not by this script, so the loop
# waits for /dev/kfd rather than loading anything. It is backgrounded before the
# final exec so it outlives this script; PID 1 must never wait for it. If the
# manager exits, the loop restarts it: a dead hymgr unregisters the space and
# every later HIP call in the guest fails until a new one registers.
HYCU_HYHAL_DIR="${HYCU_HYHAL_DIR:-/opt/hyhal}"
HYCU_MANAGER_BIN="${HYCU_MANAGER_BIN:-$HYCU_HYHAL_DIR/bin/hymgr}"
HYCU_KFD_DEV="${HYCU_KFD_DEV:-/dev/kfd}"
HYCU_MANAGER_LOG="${HYCU_MANAGER_LOG:-/tmp/hymgr.log}"
# Seconds between checks once the manager is up, and the grace period after a
# launch before the next check (hymgr takes a moment to appear in /proc).
HYCU_MANAGER_POLL="${HYCU_MANAGER_POLL:-2}"
HYCU_MANAGER_START_WAIT="${HYCU_MANAGER_START_WAIT:-10}"
# One previous generation is kept, as for TAA's own log. /tmp is the guest's
# tmpfs, so an unbounded log from a crash loop is guest RAM.
HYCU_MANAGER_LOG_MAX_BYTES="${HYCU_MANAGER_LOG_MAX_BYTES:-1048576}"
# Overridable for the same reason as CSV_MISC_FILE: the helper is tested with a
# fixture directory instead of the live /proc.
HYCU_PROC_DIR="${HYCU_PROC_DIR:-/proc}"

# The same arithmetic trap as in sanitize_restart_settings, checked here because
# these variables are defined after that function has already run: a non-numeric
# value reaches `[ "$size" -gt ... ]` in rotate_manager_log, which dash treats as
# fatal.
case "$HYCU_MANAGER_LOG_MAX_BYTES" in
  ''|*[!0-9]*)
    log "WARNING: HYCU_MANAGER_LOG_MAX_BYTES='$HYCU_MANAGER_LOG_MAX_BYTES' is not a non-negative integer; using 1048576"
    HYCU_MANAGER_LOG_MAX_BYTES=1048576 ;;
esac

# True when a process named hymgr exists. comm, not cmdline: the kernel sets it
# to the executable's basename, which is what the driver logs too.
hycu_manager_running() {
  local comm
  for comm in "$HYCU_PROC_DIR"/[0-9]*/comm; do
    [ -r "$comm" ] || continue
    case "$(cat "$comm" 2>/dev/null)" in
      hymgr) return 0 ;;
    esac
  done
  return 1
}

# True while the last launch still exists (init running, or not yet reaped).
# /proc/<pid>/stat's third field is the state; Z means the process exited and
# only the parent's wait is missing. Without this, a manager slower to appear
# than HYCU_MANAGER_START_WAIT would be started a second time while the first
# was still initialising, and two managers would fight over the driver's single
# hyuds slot.
hycu_manager_launch_alive() {
  local stat
  [ -n "${manager_pid:-}" ] || return 1
  stat="$HYCU_PROC_DIR/$manager_pid/stat"
  [ -r "$stat" ] || return 1
  case "$(cut -d' ' -f3 "$stat" 2>/dev/null)" in
    ''|Z) return 1 ;;
  esac
  return 0
}

# Same shape as rotate_taa_log, for the manager's own log.
rotate_manager_log() {
  local size
  [ -f "$HYCU_MANAGER_LOG" ] || return 0
  size="$(wc -c <"$HYCU_MANAGER_LOG" 2>/dev/null || echo 0)"
  case "$size" in
    ''|*[!0-9]*) size=0 ;;
  esac
  [ "$size" -gt "$HYCU_MANAGER_LOG_MAX_BYTES" ] || return 0
  if ! mv -f "$HYCU_MANAGER_LOG" "$HYCU_MANAGER_LOG.1" 2>/dev/null; then
    : >"$HYCU_MANAGER_LOG" 2>/dev/null || true
  fi
  return 0
}

supervise_hycu_manager() {
  local waited
  # Initrd builds for non-DCU roles carry no vendor userland; nothing to do.
  [ -x "$HYCU_MANAGER_BIN" ] || return 0
  trap 'log "WARNING: hymgr supervisor exited; the DCU will stay unusable"' EXIT
  # The vendor unit mounts empty tmpfs over both directories. Empty ordinary
  # directories are equivalent here and survive the manager's writes.
  mkdir -p /etc/hymgr /var/log/hymgr 2>/dev/null || true
  manager_pid=""
  while :; do
    if ! hycu_manager_running && [ -e "$HYCU_KFD_DEV" ]; then
      if hycu_manager_launch_alive; then
        log "hymgr ($manager_pid) is still starting; not launching another"
      else
        rotate_manager_log
        log "starting $HYCU_MANAGER_BIN (registers the hyuds space HIP needs)"
        (
          export LD_LIBRARY_PATH="$HYCU_HYHAL_DIR/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
          # hymgr refuses to start where it detects a container unless this is 0.
          # The check exists to keep it out of docker; in this guest it is the
          # only manager and has to run.
          export HYCONTAINER_ENV=0
          exec "$HYCU_MANAGER_BIN"
        ) >>"$HYCU_MANAGER_LOG" 2>&1 </dev/null &
        manager_pid="$!"
        waited=0
        while [ "$waited" -lt "$HYCU_MANAGER_START_WAIT" ] &&
              ! hycu_manager_running && hycu_manager_launch_alive; do
          sleep 1
          waited=$((waited + 1))
        done
        if hycu_manager_running; then
          log "hymgr is up; hyuds registration follows"
        elif hycu_manager_launch_alive; then
          # Slow, not failed: the next iteration must not start a second one.
          log "WARNING: hymgr ($manager_pid) has not appeared after ${HYCU_MANAGER_START_WAIT}s; leaving it to finish"
        else
          log "WARNING: hymgr did not stay up; see $HYCU_MANAGER_LOG (the DCU will not compute)"
          # Without this the console only says "did not stay up" and the reason
          # (a missing library, a refused container check) stays on tmpfs.
          tail -n 3 "$HYCU_MANAGER_LOG" 2>/dev/null | while IFS= read -r line; do
            log "hymgr: $line"
          done
          # Reap it, so the next launch replaces a dead child instead of
          # accumulating zombies and leaving a stale pid to test.
          wait "$manager_pid" 2>/dev/null || true
          manager_pid=""
        fi
      fi
    fi
    sleep "$HYCU_MANAGER_POLL"
  done
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
#
#    debugfs is mounted here too, not only by the poststop reset hook: the hook
#    is a fallback that has to work on its own, but mounting it once at boot
#    means the reset path exists for the whole life of the guest, and a failure
#    to mount is logged at a point where the boot log is still readable. It is
#    also what makes the driver's gpu_recover entry inspectable during a run,
#    which is how "does this guest have a reset path at all?" gets answered
#    without speculating.
mkdir -p /proc /sys /sys/kernel/debug 2>/dev/null || true
mount -t proc  proc  /proc >/dev/null 2>&1 || true
mount -t sysfs sysfs /sys  >/dev/null 2>&1 || true
if mount -t debugfs debugfs /sys/kernel/debug >/dev/null 2>&1; then
  log "mounted debugfs at /sys/kernel/debug"
else
  log "WARNING: mount -t debugfs failed; the DCU reset path will be unavailable"
fi

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
  # Run the supervisor in a subshell: the exec below would otherwise replace it,
  # and PID 1 must not wait for it. The loop keeps TAA alive for the rest of the
  # VM's life, including after this script is gone.
  supervise_taa &
else
  log "WARNING: missing $TAA_CONFIG; not starting TAA"
fi

# 3b) Start the Hygon DCU compute manager. The guest cannot compute on the card
#     without it (see supervise_hycu_manager), and it is the only process that
#     registers the hyuds space. Non-DCU initrds have no hymgr and the function
#     returns immediately. Like the TAA supervisor it has to be backgrounded
#     before the final exec, and it waits for the prestart hook to load the
#     driver rather than loading anything itself.
supervise_hycu_manager &

# 4) Record whether this guest can power itself off in order. Nothing here acts
#    on it; the line exists so the question can be answered from the boot log
#    instead of guessed at after a card turns up dirty.
#
#    The teardown path that matters for the DCU is not the guest's own shutdown
#    call, though. The card is reset by the poststop hook
#    (usr/share/oci/hooks/poststop/guest-hycu-dcu-reset.sh), which runs when the
#    container stops and before the VM is destroyed. An earlier version of this
#    comment claimed kata-agent powers the guest off by writing 'o' to
#    /proc/sysrq-trigger; that is wrong. The path does appear in the agent
#    binary, but only inside its /proc masking list, and the kernel is built
#    without CONFIG_MAGIC_SYSRQ (verified from the config embedded in
#    vmlinuz-hycu-confidential-csv.container), so the file does not exist and no
#    userspace action can create it. The shim's `system_powerdown` QMP command
#    is not an ACPI path this guest subscribes to either.
if [ -e /proc/sysrq-trigger ]; then
  log "shutdown path: /proc/sysrq-trigger present"
else
  log "shutdown path: /proc/sysrq-trigger absent (kernel has no CONFIG_MAGIC_SYSRQ)"
fi

exec /sbin/init "$@"
