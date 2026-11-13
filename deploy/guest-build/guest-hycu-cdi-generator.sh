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
WAIT_SECONDS_MAX=${HYCU_CDI_WAIT_SECONDS:-10}

log() {
  printf '%s: %s\n' "$LOG_TAG" "$*"
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
  # The module is loaded by taa-init before the agent starts, so by the time a
  # container is created the DRM nodes either exist or never will. The wait is
  # a short safety margin, not the vendor's 240 s.
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
    [ -n "$nodes" ] && nodes="$nodes, "
    nodes="$nodes{\"path\": \"$DEV_DIR/$node\"}"
  else
    log "skip $DEV_DIR/$node (absent in guest)"
  fi
done

# The vendor spec bind-mounts the DTK tree from the guest. This initrd has no
# /opt/hyhal (the container image carries its own stack), so the mount is
# emitted only when the guest path exists; otherwise the container would get an
# empty directory over its own runtime tree.
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
