#!/bin/sh
# Reset the Hygon DCU before the guest is torn down.
#
# Why this exists: the host has no reset path for the card. Its
# /sys/bus/pci/devices/.../reset_method is empty, the device does not advertise
# FLReset, and QEMU logs "vfio: Cannot reset device 0000:c3:00.0, no available
# reset mechanism" at both attach and detach. Every guest therefore inherits
# whatever state the previous one left in the chip. A guest that was computing
# and is destroyed without a driver-level reset leaves the card in a state the
# next guest's probe cannot recover from -- RLC ucode load fail, ring kiq test
# failed (-110), probe failed with error -110 -- and with no /dev/dri the CDI
# hook writes no spec and creation dies in the 100-second CDI timeout. The only
# recovery from that state is a host reboot.
#
# The guest side does have a reset path, and hy-smi is the supported way to use
# it: `hy-smi --hcureset -d <n>` reads
# /sys/kernel/debug/dri/<n>/gpu_recover through Device::readDevInfo, and that
# read runs the driver's GPU recovery -- it kills every process holding the card
# (kfd_kill_all_process_on!, kill process(pid:name)), waits for them to leave
# (wait all process gone ...), then performs a BACO reset.
#
# A poststop hook is the right place because it runs after the container's own
# process is already gone and before the VM is destroyed. That ordering is what
# makes the kill-every-user behaviour harmless instead of destructive: by the
# time this runs there is normally nothing left to kill.
#
# This script is deliberately thin. hy-smi does the work; the only thing here is
# the step hy-smi cannot do itself -- mounting debugfs, which taa-init does not
# mount (it mounts proc and sysfs only) and without which the recovery entry
# does not exist at all.
#
# Limits, stated so nobody reads more into a green log line than it means:
#   * This fires when the *container* stops, which is the normal delete path
#     (terminationGracePeriodSeconds -> SIGTERM -> SIGKILL -> poststop ->
#     DestroySandbox). A force-deleted Pod, a crashed shim, or a killed
#     hypervisor skips it.
#   * A successful hy-smi exit means the driver says it reset the card. Whether
#     that leaves it clean enough for the next guest has not been proven on
#     hardware.
#
# The script always exits 0. A poststop hook cannot abort anything -- the
# container is already gone -- and a non-zero exit would only bury the log line
# that says what actually happened.
#
# Delivered to the DCU roles' initrd at usr/share/oci/hooks/poststop/.

set -u

LOG_TAG=hycu-dcu-reset

DEBUGFS_DIR=${DEBUGFS_DIR:-/sys/kernel/debug}
PCI_DIR=${PCI_DIR:-/sys/bus/pci/devices}
HYCU_SMI=${HYCU_SMI:-/opt/hyhal/bin/hy-smi}
# The index hy-smi addresses a card by. A DCU Pod gets one card, so 0; a guest
# that has more than one can override this.
HYCU_SMI_DEVICE=${HYCU_SMI_DEVICE:-0}

log() {
  printf '%s: %s\n' "$LOG_TAG" "$*"
}

# taa-init mounts debugfs at boot; this repeats it only if that did not happen.
# hy-smi reads the recovery entry through debugfs, so without the mount it
# reports a failure that looks like a driver problem.
ensure_debugfs() {
  [ -e "$DEBUGFS_DIR/dri" ] && return 0
  mkdir -p "$DEBUGFS_DIR" 2>/dev/null || true
  mount -t debugfs debugfs "$DEBUGFS_DIR" >/dev/null 2>&1 ||
    log "WARNING: mount -t debugfs $DEBUGFS_DIR failed"
  [ -e "$DEBUGFS_DIR/dri" ]
}

main() {
  if [ ! -x "$HYCU_SMI" ]; then
    log "$HYCU_SMI is absent; this guest has no DCU to reset"
    return 0
  fi
  # A guest that never received the card has nothing to reset, and running the
  # reset anyway would report a failure on every teardown of a non-DCU guest.
  found=0
  for dev in "$PCI_DIR"/*; do
    [ -r "$dev/vendor" ] || continue
    [ "$(cat "$dev/vendor" 2>/dev/null)" = "0x1d94" ] || continue
    case "$(cat "$dev/class" 2>/dev/null)" in
      0x03* | 0x0b40*) found=1; break ;;
    esac
  done
  if [ "$found" != 1 ]; then
    log "no Hygon co-processor/display PCI device in this guest; nothing to reset"
    return 0
  fi
  if ! ensure_debugfs; then
    log "WARNING: debugfs is unavailable; hy-smi cannot reach the driver's reset entry"
    return 0
  fi
  log "resetting HCU $HYCU_SMI_DEVICE with $HYCU_SMI --hcureset"
  if "$HYCU_SMI" --hcureset -d "$HYCU_SMI_DEVICE"; then
    log "hy-smi reported a successful reset"
  else
    log "WARNING: hy-smi --hcureset -d $HYCU_SMI_DEVICE failed"
  fi
  return 0
}

main
exit 0