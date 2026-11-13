#!/usr/bin/env bash
# Offline tests for guest-hycu-cdi-generator.sh.
#
# The generator is the only thing that makes `hygon.cn/hycu=0` resolvable inside
# a DCU guest; getting it wrong shows up as a 100-second CDI timeout in a Pod
# that cannot then be inspected. Every case below runs the real script against a
# fake sysfs and /dev tree, so the file it writes can be parsed and compared.
#
#   ./test-hycu-cdi-generator.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GENERATOR="$SCRIPT_DIR/guest-hycu-cdi-generator.sh"

tmp_dir="$(mktemp -d /tmp/test-hycu-cdi.XXXXXX)"
trap 'rm -rf "$tmp_dir"' EXIT

failures=0
check() {
  local name="$1" expected="$2" actual="$3"
  if [[ "$actual" == "$expected" ]]; then
    echo "ok   $name"
  else
    echo "FAIL $name" >&2
    echo "  expected: $expected" >&2
    echo "  actual:   $actual" >&2
    failures=$((failures + 1))
  fi
}

check_contains() {
  local name="$1" needle="$2" haystack="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    echo "ok   $name"
  else
    echo "FAIL $name (missing: $needle)" >&2
    failures=$((failures + 1))
  fi
}

check_absent() {
  local name="$1" needle="$2" haystack="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    echo "ok   $name"
  else
    echo "FAIL $name (unexpected: $needle)" >&2
    failures=$((failures + 1))
  fi
}

# One fixture per case: PCI devices, DRM symlinks and a /dev tree. `with_dcu=0`
# makes a guest where the vendor device never bound a driver.
make_fixture() {
  local root="$1" with_dcu="$2" with_display="$3"
  mkdir -p "$root/sys/bus/pci/devices" "$root/sys/class/drm" "$root/dev/dri" "$root/cdi"

  # The card: vendor 1d94, class 0x0b4000 (co-processor).
  mkdir -p "$root/sys/bus/pci/devices/0000:02:00.0"
  echo 0x1d94 >"$root/sys/bus/pci/devices/0000:02:00.0/vendor"
  echo 0x0b4000 >"$root/sys/bus/pci/devices/0000:02:00.0/class"

  # A virtio display: same class shape, different vendor, must be ignored.
  mkdir -p "$root/sys/bus/pci/devices/0000:00:01.0"
  echo 0x1af4 >"$root/sys/bus/pci/devices/0000:00:01.0/vendor"
  echo 0x030000 >"$root/sys/bus/pci/devices/0000:00:01.0/class"
  ln -s ../../devices/pci0000:00/0000:00:01.0/drm/card1 "$root/sys/class/drm/card1"

  if [[ "$with_dcu" == 1 ]]; then
    ln -s ../../devices/pci0000:00/0000:02:00.0/drm/card0 "$root/sys/class/drm/card0"
    # A connector entry shares the card's prefix and must not be mistaken for it.
    ln -s ../../devices/pci0000:00/0000:02:00.0/drm/card0/card0-DP-1 \
      "$root/sys/class/drm/card0-DP-1"
    ln -s ../../devices/pci0000:00/0000:02:00.0/drm/renderD128 "$root/sys/class/drm/renderD128"
    : >"$root/dev/dri/card0"
    : >"$root/dev/dri/renderD128"
  fi

  if [[ "$with_display" == 1 ]]; then
    # A Hygon display-class function (0x030000) pairs like the card does.
    mkdir -p "$root/sys/bus/pci/devices/0000:03:00.0"
    echo 0x1d94 >"$root/sys/bus/pci/devices/0000:03:00.0/vendor"
    echo 0x030000 >"$root/sys/bus/pci/devices/0000:03:00.0/class"
    ln -s ../../devices/pci0000:00/0000:03:00.0/drm/card2 "$root/sys/class/drm/card2"
    ln -s ../../devices/pci0000:00/0000:03:00.0/drm/renderD129 "$root/sys/class/drm/renderD129"
    : >"$root/dev/dri/card2"
    : >"$root/dev/dri/renderD129"
  fi
}

run_generator() {
  local root="$1"
  shift
  env \
    PCI_DIR="$root/sys/bus/pci/devices" \
    DRM_DIR="$root/sys/class/drm" \
    DEV_DIR="$root/dev" \
    CDI_DIR="$root/cdi" \
    HYHAL_DIR="${HYHAL_DIR:-$root/opt/hyhal}" \
    HYCU_CDI_WAIT_SECONDS="${WAIT:-0}" \
    "$@" \
    sh "$GENERATOR"
}

echo "== syntax =="
if sh -n "$GENERATOR"; then
  echo "ok   sh -n"
else
  echo "FAIL sh -n" >&2
  failures=$((failures + 1))
fi

echo "== spec shape =="
root="$tmp_dir/happy"
make_fixture "$root" 1 0
mkdir -p "$root/opt/hyhal"
: >"$root/dev/kfd"
out="$(run_generator "$root" 2>&1)"
spec="$(cat "$root/cdi/hygon.cn-hycu.json")"
check_contains "the spec is written" '"cdiVersion": "0.6.0"' "$spec"
check_contains "the kind is the one the shim asks for" '"kind": "hygon.cn/hycu"' "$spec"
check_contains "device 0 pairs card0" '"name": "0", "containerEdits": {"deviceNodes": [{"path": "'"$root"'/dev/dri/card0"}, {"path": "'"$root"'/dev/dri/renderD128"}]}' "$spec"
check_absent "the virtio display is not a device" 'card1' "$spec"
check_absent "a connector entry is not a device" 'card0-DP-1' "$spec"
check_contains "kfd is a spec-wide node" '"path": "'"$root"'/dev/kfd"' "$spec"
check_absent "mkfd is omitted when absent" 'mkfd' "$spec"
check_contains "the DTK tree is bind-mounted when present" '"hostPath": "'"$root"'/opt/hyhal"' "$spec"
check_contains "the mount is read-only rbind" '"options": ["rbind", "ro", "rprivate"]' "$spec"
check_contains "the log names the pairing" '0000:02:00.0 -> device "0"' "$out"
if python3 -I - "$root/cdi/hygon.cn-hycu.json" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    json.load(f)
PY
then
  echo "ok   the spec is valid JSON"
else
  echo "FAIL the spec is valid JSON" >&2
  failures=$((failures + 1))
fi

echo "== no /opt/hyhal, no /dev/mkfd =="
root="$tmp_dir/minimal"
make_fixture "$root" 1 0
out="$(run_generator "$root" 2>&1)"
spec="$(cat "$root/cdi/hygon.cn-hycu.json")"
check_absent "no DTK mount when the guest has none" '"mounts"' "$spec"
check_contains "device 0 survives without the mount" '"name": "0"' "$spec"
check_contains "the skip is logged" 'skip '"$root"'/opt/hyhal bind mount' "$out"

echo "== existing spec is left alone =="
root="$tmp_dir/existing"
make_fixture "$root" 1 0
echo '{"sentinel": true}' >"$root/cdi/hygon.cn-hycu.json"
out="$(run_generator "$root" 2>&1)"
check "the existing spec is not rewritten" '{"sentinel": true}' "$(cat "$root/cdi/hygon.cn-hycu.json")"
check_contains "the skip is logged" 'spec already exists' "$out"

echo "== device never bound =="
root="$tmp_dir/unbound"
make_fixture "$root" 0 0
set +e
out="$(run_generator "$root" 2>&1)"
status=$?
set -e
check "a failed pairing still exits 0" 0 "$status"
check "no spec is written" no "$([[ -e "$root/cdi/hygon.cn-hycu.json" ]] && echo yes || echo no)"
check_contains "the unbound BDF is logged" '0000:02:00.0 has no DRM nodes' "$out"

echo "== two Hygon devices are indexed in BDF order =="
root="$tmp_dir/two"
make_fixture "$root" 1 1
out="$(run_generator "$root" 2>&1)"
spec="$(cat "$root/cdi/hygon.cn-hycu.json")"
check_contains "the co-processor stays device 0" '0000:02:00.0 -> device "0"' "$out"
check_contains "the display function becomes device 1" '0000:03:00.0 -> device "1"' "$out"
check_contains "both devices are in the spec" '"name": "1"' "$spec"

echo "== a non-Hygon vendor is ignored =="
root="$tmp_dir/vendor"
make_fixture "$root" 0 0
# Drop the Hygon co-processor so the fixture holds only foreign adapters.
rm -rf "$root/sys/bus/pci/devices/0000:02:00.0"
mkdir -p "$root/sys/bus/pci/devices/0000:04:00.0"
echo 0x1002 >"$root/sys/bus/pci/devices/0000:04:00.0/vendor"
echo 0x030000 >"$root/sys/bus/pci/devices/0000:04:00.0/class"
out="$(run_generator "$root" 2>&1)"
check "no spec for a foreign display adapter" no "$([[ -e "$root/cdi/hygon.cn-hycu.json" ]] && echo yes || echo no)"
check_contains "the log says there is nothing to do" 'no Hygon co-processor/display PCI device' "$out"

echo "== build integration =="
# The hook is only useful if the DCU roles' initrd actually carries it at the
# path the runtime config's guest_hook_path points at.
check_contains "build-initrd installs the hook for DCU roles" \
  'usr/share/oci/hooks/prestart/guest-hycu-cdi-generator.sh' \
  "$(cat "$SCRIPT_DIR/build-initrd.sh")"

if [[ "$failures" -ne 0 ]]; then
  echo "$failures test(s) failed" >&2
  exit 1
fi
echo "all tests passed"
