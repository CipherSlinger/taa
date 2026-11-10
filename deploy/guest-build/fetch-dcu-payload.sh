#!/bin/bash
# Host-side half of `build-initrd.sh fetch-base` for a DCU role.
#
# The hycu driver modules and their firmware are not installed on the host as
# files: they exist only inside the DCU guest image's rootfs. This script mounts
# that image read-only, resolves the module release that carries hycu, and writes
# the module tree, the matching firmware tree and kmod to stdout as a
# zstd-compressed tar. Nothing is written to the host: the loop device and the
# mount are torn down by the EXIT trap.
#
# Every progress line goes to stderr, because stdout is the archive.
#
# Usage: fetch-dcu-payload.sh <guest-image>
set -euo pipefail

image="${1:?usage: fetch-dcu-payload.sh <guest-image>}"
[[ -r "$image" ]] || { echo "error: cannot read $image" >&2; exit 1; }

mount_point="$(mktemp -d)"
loop_device=""
cleanup() {
    if mountpoint -q "$mount_point" 2>/dev/null; then
        umount "$mount_point" || true
    fi
    if [[ -n "$loop_device" ]]; then
        losetup -d "$loop_device" 2>/dev/null || true
    fi
    rmdir "$mount_point" 2>/dev/null || true
}
trap cleanup EXIT

# The image is a DOS-partitioned rootfs. Read the first partition's start from
# the image instead of trusting a constant; the measured Kata layout is 6144
# sectors, which is also the fallback when sfdisk is unavailable.
part_start=""
if command -v sfdisk >/dev/null 2>&1; then
    part_start="$(sfdisk -d "$image" 2>/dev/null |
        sed -n 's/.*start=[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n 1)"
fi
if [[ -z "$part_start" ]]; then
    part_start=6144
    echo "warning: sfdisk could not read the partition table of $image; assuming ${part_start} sectors" >&2
fi

loop_device="$(losetup --read-only --find --show --offset $((part_start * 512)) "$image")"
mount -o ro "$loop_device" "$mount_point"

# The release is the module tree that carries hycu. A DCU image also has no
# other release unless a debug image was built with several.
release=""
for candidate in "$mount_point"/usr/lib/modules/*; do
    [[ -d "$candidate" ]] || continue
    case "$(basename "$candidate")" in
        *hycu*) release="$(basename "$candidate")" && break ;;
    esac
done
if [[ -z "$release" ]]; then
    echo "error: no hycu module tree under /usr/lib/modules in $image" >&2
    exit 1
fi

modules="$mount_point/usr/lib/modules/$release"
firmware="$mount_point/usr/lib/firmware/$release"
kmod="$mount_point/usr/bin/kmod"

[[ -x "$kmod" ]] || { echo "error: no executable /usr/bin/kmod in $image" >&2; exit 1; }
[[ -f "$modules/modules.dep" ]] || \
    echo "warning: $modules/modules.dep is missing; the guest will run depmod at boot" >&2

paths=("usr/lib/modules/$release" "usr/bin/kmod")
[[ -d "$firmware" ]] && paths+=("usr/lib/firmware/$release")

echo "release=$release" >&2
echo "packing ${paths[*]}" >&2
tar --zstd -C "$mount_point" -cf - "${paths[@]}"
