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
    HYCU_MANAGER="${HYCU_MANAGER:-$root/opt/hyhal/bin/hymgr}" \
    HYCU_MANAGER_WAIT_SECONDS="${HYCU_MANAGER_WAIT_SECONDS:-20}" \
    HYCU_CDI_WAIT_SECONDS="${WAIT:-0}" \
    CMDLINE_FILE="${CMDLINE_FILE:-$root/proc/cmdline}" \
    MODPROBE_BIN="${MODPROBE_BIN:-/usr/sbin/modprobe}" \
    DEPMOD_BIN="${DEPMOD_BIN:-/usr/sbin/depmod}" \
    MODULES_DIR="${MODULES_DIR:-/lib/modules}" \
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
check "the card node is open to every container user" "666" "$(stat -c %a "$root/dev/dri/card0")"
check "the render node is open to every container user" "666" "$(stat -c %a "$root/dev/dri/renderD128")"
check "kfd is open to every container user" "666" "$(stat -c %a "$root/dev/kfd")"
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

echo "== hycu manager wait =="
# taa-init owns the manager's lifecycle; the hook only waits, so a second
# instance cannot race the supervisor. The wait still has to be bounded: a
# missing manager must not hold container creation until the CDI timeout.
# Only the run that creates the spec waits: the registration is guest-wide and
# outlives the spec, so a later container in the same guest must not pay the
# wait and settle delay at every start.
manager_wait_line="$(grep -n '^wait_for_hycu_manager$' "$GENERATOR" | cut -d: -f1 | head -1)"
spec_exit_line="$(grep -n 'spec already exists' "$GENERATOR" | cut -d: -f1 | head -1)"
check "waits for the manager only on the spec-creating path" "yes" \
  "$([[ -n "$manager_wait_line" && -n "$spec_exit_line" && "$manager_wait_line" -gt "$spec_exit_line" ]] && echo yes || echo no)"
check_absent "does not launch the manager itself" 'bin/hymgr" &' "$(cat "$GENERATOR")"
check_contains "the wait is bounded and reports the timeout" \
  'hymgr is not running after' "$(cat "$GENERATOR")"
check_contains "a short settle covers the registration ioctl" \
  'HYCU_MANAGER_SETTLE_SECONDS' "$(cat "$GENERATOR")"

# Functional timeout path: the manager binary exists but no process by that
# name does, so the hook must give up after the configured second and continue
# writing the spec instead of failing.
root="$tmp_dir/manager-missing"
make_fixture "$root" 1 0
mkdir -p "$root/opt/hyhal/bin"
: >"$root/opt/hyhal/bin/hymgr"
chmod +x "$root/opt/hyhal/bin/hymgr"
out="$(run_generator "$root" HYCU_MANAGER="$root/opt/hyhal/bin/hymgr" \
  HYCU_MANAGER_WAIT_SECONDS=1 HYCU_MANAGER_SETTLE_SECONDS=0 2>&1)"
check "a manager that never appears still yields a spec" "yes" \
  "$([[ -e "$root/cdi/hygon.cn-hycu.json" ]] && echo yes || echo no)"
check_contains "the timeout is logged, not fatal" 'hymgr is not running after 1s' "$out"

echo "== existing spec is left alone =="
root="$tmp_dir/existing"
make_fixture "$root" 1 0
echo '{"sentinel": true}' >"$root/cdi/hygon.cn-hycu.json"
# The manager binary exists but no process by that name does. If the hook waited
# on this path it would log the timeout after a second; skipping the wait is the
# observable difference.
mkdir -p "$root/opt/hyhal/bin"
: >"$root/opt/hyhal/bin/hymgr"
chmod +x "$root/opt/hyhal/bin/hymgr"
out="$(run_generator "$root" HYCU_MANAGER="$root/opt/hyhal/bin/hymgr" \
  HYCU_MANAGER_WAIT_SECONDS=1 2>&1)"
check "the existing spec is not rewritten" '{"sentinel": true}' "$(cat "$root/cdi/hygon.cn-hycu.json")"
check_contains "the skip is logged" 'spec already exists' "$out"
check_absent "does not wait for the manager once the spec exists" \
  'hymgr is not running' "$out"

echo "== manager wait knobs are validated =="
# A non-numeric override would make dash's `[` error, and an erroring test is
# false: the wait would never time out and container creation would hang. The
# hook has to fall back to its defaults and say so.
root="$tmp_dir/manager-bad-knobs"
make_fixture "$root" 1 0
out="$(run_generator "$root" HYCU_MANAGER="$root/missing/hymgr" \
  HYCU_MANAGER_WAIT_SECONDS=abc HYCU_MANAGER_SETTLE_SECONDS=3s 2>&1)"
check "a non-numeric wait still yields a spec" "yes" \
  "$([[ -e "$root/cdi/hygon.cn-hycu.json" ]] && echo yes || echo no)"
check_contains "the bad wait is logged" \
  "HYCU_MANAGER_WAIT_SECONDS='abc' is not a non-negative integer; using 20" "$out"
check_contains "the bad settle is logged" \
  "HYCU_MANAGER_SETTLE_SECONDS='3s' is not a non-negative integer; using 3" "$out"

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

echo "== driver loading =="

# The hook loads the driver itself, at the same point in the guest's life as the
# vendor's udev. The stub selects its applet from argv[0] (that is how the real
# kmod binary dispatches), records the call, and on `modprobe hycu` emulates the
# probe: the DRM sysfs entries and /dev nodes appear only then. A spec can
# therefore only be written if the wait actually spans the probe.
make_modprobe_stub() {
  local root="$1"
  mkdir -p "$root/bin"
  cat >"$root/bin/stub" <<'EOF'
#!/bin/sh
printf '%s %s\n' "${0##*/}" "$*" >>"${STUB_LOG:?}"
if [ "${0##*/}" = modprobe ] && [ "$1" = hycu ] && [ "${STUB_RC:-0}" = 0 ]; then
  ln -sfn ../../devices/pci0000:00/0000:02:00.0/drm/card0 "$FIXTURE/sys/class/drm/card0"
  ln -sfn ../../devices/pci0000:00/0000:02:00.0/drm/renderD128 "$FIXTURE/sys/class/drm/renderD128"
  : >"$FIXTURE/dev/dri/card0"
  : >"$FIXTURE/dev/dri/renderD128"
  chmod 0600 "$FIXTURE/dev/dri/card0" "$FIXTURE/dev/dri/renderD128"
fi
exit "${STUB_RC:-0}"
EOF
  chmod +x "$root/bin/stub"
  ln -sf stub "$root/bin/modprobe"
  ln -sf stub "$root/bin/depmod"
}

release="$(uname -r)"
root="$tmp_dir/driver"
make_fixture "$root" 0 0
make_modprobe_stub "$root"
mkdir -p "$root/proc" "$root/modules/$release"
printf 'taa.taa_modules=hycu,hycu-sched\n' >"$root/proc/cmdline"
: >"$root/modules/$release/modules.dep"
stub_log="$root/modprobe.log"
out="$(run_generator "$root" \
  FIXTURE="$root" STUB_LOG="$stub_log" \
  MODPROBE_BIN="$root/bin/modprobe" DEPMOD_BIN="$root/bin/depmod" \
  MODULES_DIR="$root/modules" HYCU_CDI_WAIT_SECONDS=5 2>&1)"
check "loads each named module in order" 'modprobe hycu
modprobe hycu-sched' "$(cat "$stub_log")"
check_contains "the load is logged" 'module loaded: hycu' "$out"
check_contains "the spec waits for the probe's DRM nodes" '0000:02:00.0 -> device "0"' "$out"
check "the probe's node modes are fixed as well" "666" "$(stat -c %a "$root/dev/dri/card0")"

# No module list: nothing to load, and that is every non-DCU role.
root="$tmp_dir/driver-none"
make_fixture "$root" 0 0
make_modprobe_stub "$root"
rm -f "$root/modprobe.log"
out="$(run_generator "$root" FIXTURE="$root" STUB_LOG="$root/modprobe.log" \
  MODPROBE_BIN="$root/bin/modprobe" DEPMOD_BIN="$root/bin/depmod" 2>&1)"
check "an empty module list is a no-op" "absent" \
  "$([[ -e "$root/modprobe.log" ]] && echo present || echo absent)"

# modules.dep is shipped by the payload, so the normal path must not pay for a
# depmod. Without it the kernel cannot resolve dependencies, so it runs first.
root="$tmp_dir/driver-depmod"
make_fixture "$root" 0 0
make_modprobe_stub "$root"
mkdir -p "$root/proc"
printf 'taa.taa_modules=hycu\n' >"$root/proc/cmdline"
run_generator "$root" FIXTURE="$root" STUB_LOG="$root/modprobe.log" \
  MODPROBE_BIN="$root/bin/modprobe" DEPMOD_BIN="$root/bin/depmod" \
  MODULES_DIR="$root/modules" >/dev/null 2>&1
check "runs depmod before loading when modules.dep is missing" "depmod -b / $release" \
  "$(head -1 "$root/modprobe.log")"

# depmod is only a repair step: a missing depmod or a failed modprobe must not
# stop the generator, which has to exit 0 and leave the CDI timeout to report.
root="$tmp_dir/driver-no-depmod"
make_fixture "$root" 0 0
make_modprobe_stub "$root"
mkdir -p "$root/proc"
printf 'taa.taa_modules=hycu\n' >"$root/proc/cmdline"
set +e
out="$(run_generator "$root" FIXTURE="$root" STUB_LOG="$root/modprobe.log" \
  MODPROBE_BIN="$root/bin/modprobe" DEPMOD_BIN="$root/no-such-depmod" \
  MODULES_DIR="$root/modules" 2>&1)"
status=$?
set -e
check "a missing depmod still loads the module" "modprobe hycu" "$(cat "$root/modprobe.log")"
check "a missing depmod is not fatal" "0" "$status"

root="$tmp_dir/driver-fail"
make_fixture "$root" 0 0
make_modprobe_stub "$root"
mkdir -p "$root/proc"
printf 'taa.taa_modules=hycu\n' >"$root/proc/cmdline"
set +e
out="$(run_generator "$root" FIXTURE="$root" STUB_LOG="$root/modprobe.log" STUB_RC=1 \
  MODPROBE_BIN="$root/bin/modprobe" DEPMOD_BIN="$root/bin/depmod" \
  MODULES_DIR="$root/modules" 2>&1)"
status=$?
set -e
check "a failed modprobe is not fatal" "0" "$status"
check_contains "a failed modprobe is reported" 'modprobe hycu failed' "$out"

root="$tmp_dir/driver-no-modprobe"
make_fixture "$root" 0 0
mkdir -p "$root/proc"
printf 'taa.taa_modules=hycu\n' >"$root/proc/cmdline"
set +e
out="$(run_generator "$root" MODPROBE_BIN="$root/no-such-modprobe" 2>&1)"
status=$?
set -e
check "a missing modprobe is not fatal" "0" "$status"
check_contains "a missing modprobe is reported" 'no-such-modprobe is absent' "$out"

echo "== wait default =="
check_contains "the DRM wait defaults to the vendor's 240 s" 'HYCU_CDI_WAIT_SECONDS:-240' \
  "$(cat "$GENERATOR")"

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
