#!/bin/sh
# Generate the guest-side CDI spec for a Hygon DCU.
#
# Kata attaches the card to the guest as a vfio root port. The shim then names
# the device to the guest kata-agent as a container annotation
# (`cdi.k8s.io/vfio<N>: hygon.cn/hycu=0`), and the agent resolves that name from
# a CDI spec *inside* the guest. The official DCU image ships the vendor's
# generator under /usr/share/oci/hooks/prestart/, which the agent runs because
# the runtime config's `guest_hook_path` points there. This initrd is built from
# the plain Kata image, so it carries no generator: without this script every
# DCU Pod fails with `failed to inject devices after CDI timeout of 100
# seconds` even though the card itself is healthy.
#
# Difference from the vendor script: it derives BDFs with `lspci`, which this
# initrd does not ship (no pciutils, no libpci). A /sys scan replaces it. The
# vendor id is the primary filter (our card is 1d94:6211) because a guest may
# also expose a virtio/bochs display; the PCI class then confirms it is a
# display or co-processor device. The DRM nodes are the authoritative pairing
# between a PCI device and /dev/dri/cardN, so a vendor match without DRM nodes
# is simply not yet bound and is waited for.
#
# The script always exits 0. It runs as a prestart hook, where a non-zero exit
# aborts container creation; leaving no spec instead lets the agent's own CDI
# timeout report the failure, which is the message operators already know.
#
# Delivered to the DCU roles' initrd at usr/share/oci/hooks/prestart/.

set -u

LOG_TAG=hycu-cdi-generator

CDI_DIR=${CDI_DIR:-/var/run/cdi}
CDI_SPEC_PATH=${CDI_SPEC_PATH:-$CDI_DIR/hygon.cn-hycu.json}
CDI_VERSION=${CDI_VERSION:-0.6.0}
CDI_KIND=${CDI_KIND:-hygon.cn/hycu}

PCI_DIR=${PCI_DIR:-/sys/bus/pci/devices}
DRM_DIR=${DRM_DIR:-/sys/class/drm}
DEV_DIR=${DEV_DIR:-/dev}
HYHAL_DIR=${HYHAL_DIR:-/opt/hyhal}
HYCU_VENDOR_ID=${HYCU_VENDOR_ID:-0x1d94}
CMDLINE_FILE=${CMDLINE_FILE:-/proc/cmdline}
MODPROBE_BIN=${MODPROBE_BIN:-/usr/sbin/modprobe}
DEPMOD_BIN=${DEPMOD_BIN:-/usr/sbin/depmod}
MODULES_DIR=${MODULES_DIR:-/lib/modules}
HYCU_MANAGER=${HYCU_MANAGER:-/opt/hyhal/bin/hymgr}
# The vendor waits up to 240 s for the card's DRM nodes; its hook runs beside a
# driver that udev loads on device discovery. Here the same hook is what loads
# the driver (see load_kernel_modules), so the wait has to cover firmware load
# and probe as well, not just node creation.
WAIT_SECONDS_MAX=${HYCU_CDI_WAIT_SECONDS:-240}
# taa-init starts hymgr as soon as /dev/kfd exists; this wait only closes the
# gap before the container that needs the card is created.
HYCU_MANAGER_WAIT_SECONDS=${HYCU_MANAGER_WAIT_SECONDS:-20}
# Being in /proc is not the same as having registered. hymgr creates its
# listening socket first and issues MKFD_IOC_REGISTER_HYUDS_SPACE a few steps
# later, so a short settle keeps the container's first HIP call from landing in
# between and getting -EBADF.
HYCU_MANAGER_SETTLE_SECONDS=${HYCU_MANAGER_SETTLE_SECONDS:-3}

log() {
  printf '%s: %s\n' "$LOG_TAG" "$*"
}

# A non-numeric override makes dash's `[` exit 2 ("Illegal number"), and a test
# that errors is false: the wait's timeout branch would never fire and container
# creation would hang instead of proceeding. Fall back to the documented default
# and say so, the same way taa-init does for its numeric knobs.
sanitize_seconds() {
  local name="$1" value="$2" fallback="$3"
  case "$value" in
    ''|*[!0-9]*)
      # stderr, not log(): the caller captures stdout, and a warning inside the
      # capture would become the variable's value.
      printf '%s: WARNING: %s=%s is not a non-negative integer; using %s\n' \
        "$LOG_TAG" "$name" "'$value'" "$fallback" >&2
      printf '%s\n' "$fallback" ;;
    *) printf '%s\n' "$value" ;;
  esac
}

HYCU_MANAGER_WAIT_SECONDS="$(sanitize_seconds HYCU_MANAGER_WAIT_SECONDS "$HYCU_MANAGER_WAIT_SECONDS" 20)"
HYCU_MANAGER_SETTLE_SECONDS="$(sanitize_seconds HYCU_MANAGER_SETTLE_SECONDS "$HYCU_MANAGER_SETTLE_SECONDS" 3)"

# Print the value of taa.taa_modules= from the kernel command line, which is
# also what build-initrd renders and what taa-init used to consume itself.
cmdline_modules() {
  [ -r "$CMDLINE_FILE" ] || return 0
  for token in $(cat "$CMDLINE_FILE" 2>/dev/null); do
    case "$token" in
      taa.taa_modules=*) printf '%s\n' "${token#taa.taa_modules=}"; return 0 ;;
    esac
  done
  return 0
}

# Load the modules the command line names (comma-separated), then let the DRM
# wait below cover the probe.
#
# This load used to happen in taa-init, before kata-agent even started. The
# vendor guest does not load the driver that early: its systemd/udev loads it on
# device discovery, after the agent is up. That load timing was the one
# remaining difference between the two guest shapes, so it moves here -- the
# last userspace point before the container that needs the card, which is the
# same lifecycle position as the vendor's udev. The driver itself, the module
# tree and the kmod applet links are unchanged; both guest shapes now hand the
# card to the driver after the guest is fully up.
#
# Failures are logged and never fatal: a non-zero exit aborts container
# creation, and leaving no spec instead lets the agent's own CDI timeout
# report the failure, which is the message operators already know.
load_kernel_modules() {
  modules=$(cmdline_modules)
  [ -n "$modules" ] || return 0
  if [ ! -x "$MODPROBE_BIN" ]; then
    log "WARNING: taa.taa_modules=$modules but $MODPROBE_BIN is absent; not loading them"
    return 0
  fi
  release=$(uname -r 2>/dev/null || true)
  if [ -n "$release" ] && [ ! -f "$MODULES_DIR/$release/modules.dep" ] && [ -x "$DEPMOD_BIN" ]; then
    # The payload normally ships modules.dep. Regenerating it writes only into
    # the guest's ramfs and is cheap compared with a module the kernel cannot
    # resolve at all.
    "$DEPMOD_BIN" -b / "$release" >/dev/null 2>&1 ||
      log "WARNING: depmod $release failed"
  fi
  saved_ifs=$IFS
  IFS=,
  for name in $modules; do
    [ -n "$name" ] || continue
    if "$MODPROBE_BIN" "$name" >/dev/null 2>&1; then
      log "module loaded: $name"
    else
      log "WARNING: modprobe $name failed; the card will stay unbound"
    fi
  done
  IFS=$saved_ifs
  return 0
}

# True when taa-init's supervisor has hymgr up. The supervisor owns the start;
# this hook only waits, so there is exactly one launch point and no duplicate
# instance race.
hycu_manager_running() {
  for comm in /proc/[0-9]*/comm; do
    [ -r "$comm" ] || continue
    case "$(cat "$comm" 2>/dev/null)" in
      hymgr) return 0 ;;
    esac
  done
  return 1
}

# hymgr must be up before the first container starts, because the first HIP call
# inside it fails with -EBADF until the hyuds space is registered. The manager
# is launched by taa-init once the driver above has created /dev/kfd; waiting
# here keeps the container's first second from racing that launch without
# adding a second starter.
#
# Only the call that creates the spec needs this: the registration is guest-wide
# and does not go away with the spec, so later containers in the same guest skip
# both this wait and its settle delay.
wait_for_hycu_manager() {
  [ -x "$HYCU_MANAGER" ] || return 0
  waited=0
  while ! hycu_manager_running; do
    if [ "$waited" -ge "$HYCU_MANAGER_WAIT_SECONDS" ]; then
      log "WARNING: hymgr is not running after ${waited}s; HIP in the container will not find the GPU"
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done
  log "hymgr is up; allowing ${HYCU_MANAGER_SETTLE_SECONDS}s for the hyuds registration"
  sleep "$HYCU_MANAGER_SETTLE_SECONDS"
  return 0
}

# Print the DRM node name (card0, renderD128) whose sysfs entry resolves to the
# given BDF. Connector entries (card0-DP-1) are skipped; they share the card's
# prefix but are not device nodes.
drm_node_for() {
  bdf=$1
  prefix=$2
  for node in "$DRM_DIR/$prefix"*; do
    [ -L "$node" ] || continue
    base=${node##*/}
    case "$base" in
      *-*) continue ;;
    esac
    case "$(readlink "$node" 2>/dev/null)" in
      *"$bdf"*) printf '%s\n' "$base"; return 0 ;;
    esac
  done
  return 1
}

# Load the driver before the scan: the device is visible in sysfs either way,
# but its DRM nodes only exist after the probe.
load_kernel_modules

# CDI device names are indices ("0", "1", ...), not BDFs: the shim asks for
# hygon.cn/hycu=0 in the order it cold-plugs the devices, so the spec has to
# name them in a stable order. Sorting the BDFs keeps that order independent of
# sysfs enumeration.
candidates=
for dev in "$PCI_DIR"/*; do
  [ -r "$dev/vendor" ] || continue
  vendor=$(cat "$dev/vendor" 2>/dev/null) || continue
  class=$(cat "$dev/class" 2>/dev/null) || continue
  [ "$vendor" = "$HYCU_VENDOR_ID" ] || continue
  case "$class" in
    0x03* | 0x0b40*) ;;
    *) continue ;;
  esac
  candidates="$candidates ${dev##*/}"
done
candidates=$(printf '%s\n' $candidates | LC_ALL=C sort)

if [ -z "$candidates" ]; then
  log "no Hygon co-processor/display PCI device; leaving no CDI spec"
  exit 0
fi

if [ -e "$CDI_SPEC_PATH" ]; then
  log "spec already exists at $CDI_SPEC_PATH; nothing to do"
  exit 0
fi

# The card is present and the spec is about to be created for the first
# container of this guest. taa-init starts hymgr as soon as the driver creates
# /dev/kfd; make sure it is up before that container runs its first HIP call.
wait_for_hycu_manager

mkdir -p "$CDI_DIR" || {
  log "cannot create $CDI_DIR; leaving no CDI spec"
  exit 0
}

devices_file=$CDI_DIR/.hygon.cn-hycu.devices.$$
: >"$devices_file" || exit 0

index=0
for bdf in $candidates; do
  card=
  render=
  waited=0
  # The driver is loaded just above and its probe runs asynchronously, so the
  # nodes may not exist yet even on a healthy card. This waits for them, as the
  # vendor does, for up to WAIT_SECONDS_MAX.
  while [ -z "$card" ] || [ -z "$render" ]; do
    card=$(drm_node_for "$bdf" card) || card=
    render=$(drm_node_for "$bdf" renderD) || render=
    [ -n "$card" ] && [ -n "$render" ] && break
    [ "$waited" -ge "$WAIT_SECONDS_MAX" ] && break
    sleep 1
    waited=$((waited + 1))
  done
  if [ -z "$card" ] || [ -z "$render" ]; then
    log "$bdf has no DRM nodes after ${waited}s (card='${card}' render='${render}'); skipped"
    continue
  fi

  if [ -e "$DEV_DIR/dri/$card" ] && [ -e "$DEV_DIR/dri/$render" ]; then
    # The vendor's udev rule makes the DRM nodes 0666. This guest has no udev,
    # and a container may run as a non-root user, so apply the same mode here.
    chmod 0666 "$DEV_DIR/dri/$card" "$DEV_DIR/dri/$render" 2>/dev/null || true
    if [ "$index" -gt 0 ]; then
      printf ',\n' >>"$devices_file"
    fi
    printf '    {"name": "%d", "containerEdits": {"deviceNodes": [{"path": "%s/dri/%s"}, {"path": "%s/dri/%s"}]}}' \
      "$index" "$DEV_DIR" "$card" "$DEV_DIR" "$render" >>"$devices_file"
    log "$bdf -> device \"$index\" ($card, $render)"
    index=$((index + 1))
  else
    log "$bdf has DRM sysfs nodes but no $DEV_DIR/dri node; skipped"
  fi
done

if [ "$index" -eq 0 ]; then
  log "no usable DRM device node; leaving no CDI spec"
  rm -f "$devices_file"
  exit 0
fi

# Spec-wide nodes shared by every container. Each is included only when the
# guest actually has it: a deviceNode path that is missing makes CDI injection
# fail the container with an unrelated error, which hides the real problem.
nodes=
for node in kfd mkfd; do
  if [ -e "$DEV_DIR/$node" ]; then
    # Same vendor parity as the DRM nodes above.
    chmod 0666 "$DEV_DIR/$node" 2>/dev/null || true
    [ -n "$nodes" ] && nodes="$nodes, "
    nodes="$nodes{\"path\": \"$DEV_DIR/$node\"}"
  else
    log "skip $DEV_DIR/$node (absent in guest)"
  fi
done

# The vendor spec bind-mounts the HYCU userland from the guest. The DCU payload
# ships it at /usr/local/hyhal with the same /opt/hyhal symlink the vendor guest
# has; the mount is still emitted only when the path exists, because a container
# that gets an empty directory over its own runtime tree fails with an unrelated
# error.
mounts=
if [ -d "$HYHAL_DIR" ]; then
  mounts="[{\"hostPath\": \"$HYHAL_DIR\", \"containerPath\": \"$HYHAL_DIR\", \"type\": \"bind\", \"options\": [\"rbind\", \"ro\", \"rprivate\"]}]"
else
  log "skip $HYHAL_DIR bind mount (absent in guest)"
fi

tmp=$CDI_SPEC_PATH.$$
{
  printf '{\n'
  printf '  "cdiVersion": "%s",\n' "$CDI_VERSION"
  printf '  "kind": "%s",\n' "$CDI_KIND"
  printf '  "devices": [\n'
  cat "$devices_file"
  printf '\n  ]'
  if [ -n "$nodes" ] || [ -n "$mounts" ]; then
    printf ',\n  "containerEdits": {\n'
    if [ -n "$nodes" ]; then
      printf '    "deviceNodes": [%s]' "$nodes"
      [ -n "$mounts" ] && printf ','
      printf '\n'
    fi
    if [ -n "$mounts" ]; then
      printf '    "mounts": %s\n' "$mounts"
    fi
    printf '  }'
  fi
  printf '\n}\n'
} >"$tmp" || {
  log "cannot write $tmp; leaving no CDI spec"
  rm -f "$tmp" "$devices_file"
  exit 0
}

# One rename so a concurrently starting container never reads a partial file.
mv "$tmp" "$CDI_SPEC_PATH" || {
  log "cannot install $CDI_SPEC_PATH"
  rm -f "$tmp" "$devices_file"
  exit 0
}
rm -f "$devices_file"
log "wrote $CDI_SPEC_PATH with $index device(s)"
exit 0
