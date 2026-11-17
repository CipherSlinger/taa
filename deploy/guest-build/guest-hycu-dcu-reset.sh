#!/bin/sh
# Reset the Hygon DCU before the guest is torn down.
#
# Why this exists: the card is handed between guests through vfio, and the host
# has no reset path for it (`/sys/bus/pci/devices/.../reset_method` is empty, the
# device does not advertise FLReset, and QEMU logs "Cannot reset device, no
# available reset mechanism" at both attach and detach). Every guest therefore
# inherits whatever state the previous one left in the chip. When a guest that
# was computing is destroyed without the driver having reset the card first, the
# next guest's probe fails -- `gfx_v9_0_hw_init`, `RLC ucode load fail`, `ring
# kiq test failed`, `probe failed with error -110` -- and no /dev/dri appears, so
# the CDI hook writes no spec and container creation dies in the 100-second CDI
# timeout. The only recovery from that state is a host reboot.
#
# The guest side does have a reset path: `reset_method` is `bus` on the guest's
# PCI device, and the driver exposes its recovery entry at
# /sys/kernel/debug/dri/<N>/gpu_recover, which is what `hy-smi --hcureset` writes
# to. Writing it runs the driver's GPU recovery: it kills every process holding
# the device (`kfd_kill_all_process_on!`, `kill process(pid:name)`), waits for
# them to leave (`wait all process gone ...`), and then performs a BACO reset.
#
# A poststop hook is the right place for it because it runs after the container
# process is already gone and before the VM is destroyed. That ordering is what
# makes the "kill every user first" behaviour harmless instead of destructive:
# by the time this runs there is nothing left to kill. It still matters that the
# reset is deliberate -- if a process is somehow still holding the card, the
# driver will kill it, and that is the intended semantics of a teardown reset.
#
# Limits, stated here so nobody reads more into a green log line than it means:
#   * This fires when the *container* stops, which is the normal delete path
#     (terminationGracePeriodSeconds -> SIGTERM -> SIGKILL -> poststop ->
#     DestroySandbox). A force-deleted Pod, a crashed shim, or a killed
#     hypervisor skips it entirely.
#   * The reset is asynchronous in effect: it returns when the driver has
#     finished, but whether the card is clean enough for the next guest has not
#     been proven on hardware. Treat a successful write as "the guest asked for a
#     reset", not "the card is guaranteed clean".
#   * debugfs is not mounted by taa-init (it mounts proc and sysfs only), so this
#     script mounts it. That is also why the reset through the driver cannot be
#     replaced by touching sysfs alone.
#
# The script always exits 0. A poststop hook cannot abort anything -- the
# container is already gone -- and a non-zero exit would only bury the log line
# that says what actually happened.
#
# Delivered to the DCU roles' initrd at usr/share/oci/hooks/poststop/.

set -u

LOG_TAG=hycu-dcu-reset

DEBUGFS_DIR=${DEBUGFS_DIR:-/sys/kernel/debug}
DEBUGFS_MOUNT_POINT=${DEBUGFS_MOUNT_POINT:-$DEBUGFS_DIR}
PCI_DIR=${PCI_DIR:-/sys/bus/pci/devices}
MOUNT_BIN=${MOUNT_BIN:-/bin/mount}
# Mainline mount lives in /usr/bin on this image; keep the fallback explicit
# rather than relying on PATH, which a hook process does not necessarily inherit.
[ -x "$MOUNT_BIN" ] || MOUNT_BIN=/usr/bin/mount
HYCU_VENDOR_ID=${HYCU_VENDOR_ID:-0x1d94}
# Fallback entry point. Kept next to the paths the prestart CDI hook uses, so a
# change to the payload layout has one place to land.
HYCU_SMI=${HYCU_SMI:-/opt/hyhal/bin/hy-smi}
# Upper bound on how long one reset attempt may spend. A teardown reset that
# hangs is worse than no reset: the VM stays alive and the Pod never leaves
# Terminating. Applied only when the `timeout` applet exists.
HYCU_RESET_TIMEOUT=${HYCU_RESET_TIMEOUT:-120}

log() {
  printf '%s: %s\n' "$LOG_TAG" "$*"
}

# --- 1. debugfs -------------------------------------------------------------
#
# taa-init mounts debugfs at boot, so in a guest that booted normally this hook
# finds it already there and does nothing. The mount is repeated here because
# this hook is the last chance to reset the card: if the boot-time mount failed
# (logged then as a warning), or something unmounted it, the recovery entry is
# missing for a reason that has a fix, and that fix belongs here rather than in
# a boot log nobody reads after the Pod is gone.
ensure_debugfs() {
  if [ -e "$DEBUGFS_DIR/dri" ]; then
    return 0
  fi
  mkdir -p "$DEBUGFS_MOUNT_POINT" 2>/dev/null || true
  if [ ! -d "$DEBUGFS_MOUNT_POINT" ]; then
    log "cannot create $DEBUGFS_MOUNT_POINT; debugfs unavailable"
    return 1
  fi
  if "$MOUNT_BIN" -t debugfs debugfs "$DEBUGFS_MOUNT_POINT" >/dev/null 2>&1; then
    log "mounted debugfs at $DEBUGFS_MOUNT_POINT"
  else
    # Mounting over an already-mounted debugfs, or without the capability, both
    # land here. The existence check below is the real test.
    log "WARNING: mount -t debugfs $DEBUGFS_MOUNT_POINT failed"
  fi
  [ -e "$DEBUGFS_DIR/dri" ]
}

# --- 2. which devices to reset ---------------------------------------------
#
# Only the PCI devices this guest actually owns are reset. The vendor id is the
# primary filter (our card is 1d94:6211); the PCI class then confirms it is a
# display or co-processor function, the same pair the prestart CDI generator
# uses. A guest that never received the card matches nothing and exits quietly.
#
# The device has to be bound to the driver for a reset entry to exist: after a
# driver-level hang the device may be unbound, and there is nothing to write to.
hycu_bdfs() {
  for dev in "$PCI_DIR"/*; do
    [ -r "$dev/vendor" ] || continue
    vendor=$(cat "$dev/vendor" 2>/dev/null) || continue
    [ "$vendor" = "$HYCU_VENDOR_ID" ] || continue
    class=$(cat "$dev/class" 2>/dev/null) || continue
    case "$class" in
      0x03* | 0x0b40*) ;;
      *) continue ;;
    esac
    printf '%s\n' "${dev##*/}"
  done
}

# The recovery entry lives under the DRM minor, not the card name, so the minor
# is read from the device's own DRM node rather than guessed from "card0" ->
# "0". Every step is allowed to fail: a device with no DRM node has no minor and
# simply is not reset here.
drm_minor_for() {
  bdf=$1
  node="$PCI_DIR/$bdf/drm"
  [ -d "$node" ] || return 1
  for entry in "$node"/*; do
    [ -e "$entry" ] || continue
    base=${entry##*/}
    # Connector entries (card0-DP-1) share the prefix and are not the card.
    case "$base" in
      *-*) continue ;;
    esac
    case "$base" in
      card[0-9]*) printf '%s\n' "${base#card}"; return 0 ;;
    esac
  done
  return 1
}

# --- 3. the reset -----------------------------------------------------------
#
# Two ways to ask the driver, in the order of how directly they hit it:
#
#   1. write the debugfs recovery entry. This is what `hy-smi --hcureset` ends up
#      doing (its binary carries `/sys/kernel/debug/dri/` and `gpu_recover`), and
#      it is one write with no process of our own in the way.
#   2. fall back to `hy-smi --hcureset <n>` if that entry is absent. The payload
#      ships the binary, and it may reach the driver through a path this script
#      does not know about.
#
# Neither is wrapped in `timeout`: this initrd carries a small coreutils set and
# a missing binary inside a poststop hook would leave the reset silently unrun.
# The guarantee that matters (no process left holding the card) comes from
# poststop's own ordering, and the driver bounds its own kill-and-wait
# (queue_preemption_timeout_ms). HYCU_RESET_TIMEOUT is applied only when the
# `timeout` applet happens to exist.
reset_one() {
  index=$1
  bdf=$2
  minor=$(drm_minor_for "$bdf") || {
    log "$bdf has no DRM card node; nothing to reset"
    return 0
  }
  recover="$DEBUGFS_DIR/dri/$minor/gpu_recover"
  if [ -e "$recover" ]; then
    log "$bdf (minor $minor): resetting the HCU via $recover"
    # The subshell keeps a failed redirect (EPERM, read-only debugfs) from
    # killing the hook before it can log why, and keeps the fallback reachable.
    if (printf '1\n' >"$recover") 2>/dev/null; then
      log "$bdf: reset request accepted by the driver"
      return 0
    fi
    log "WARNING: $bdf: writing $recover failed"
  else
    log "$bdf (minor $minor): $recover is absent"
  fi
  if [ -x "$HYCU_SMI" ]; then
    log "$bdf: falling back to $HYCU_SMI --hcureset $index"
    if run_bounded "$HYCU_SMI" --hcureset "$index" >/dev/null 2>&1; then
      log "$bdf: hy-smi reported a successful reset"
      return 0
    fi
    log "WARNING: $bdf: hy-smi --hcureset $index failed"
  else
    log "WARNING: $bdf: no recovery entry and $HYCU_SMI is absent; the card was not reset"
  fi
  return 0
}

run_bounded() {
  if command -v timeout >/dev/null 2>&1; then
    timeout "$HYCU_RESET_TIMEOUT" "$@"
  else
    "$@"
  fi
}

main() {
  bdfs=$(hycu_bdfs | LC_ALL=C sort)
  if [ -z "$bdfs" ]; then
    log "no Hygon co-processor/display PCI device in this guest; nothing to reset"
    return 0
  fi
  if ! ensure_debugfs; then
    log "WARNING: debugfs is unavailable; the DCU cannot be reset from the guest"
    return 0
  fi
  # hy-smi addresses the card by its index in the driver's device list, which is
  # the same BDF-sorted order the prestart hook used to name CDI devices.
  index=0
  for bdf in $bdfs; do
    reset_one "$index" "$bdf"
    index=$((index + 1))
  done
  return 0
}

main
exit 0