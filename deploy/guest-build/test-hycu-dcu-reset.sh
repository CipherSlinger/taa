#!/usr/bin/env bash
# Offline tests for guest-hycu-dcu-reset.sh.
#
# The hook does one thing: call `hy-smi --hcureset`. Everything worth testing is
# therefore about *when* it is called and what it is called with -- a guest with
# no card must not call it, a missing debugfs must be mounted first, and the
# device index must reach the command line. The reset itself is hy-smi's job and
# is not simulated beyond a stub that records its argv.
#
#   ./test-hycu-dcu-reset.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK="$SCRIPT_DIR/guest-hycu-dcu-reset.sh"

if [[ ! -r "$HOOK" ]]; then
  echo "error: cannot read $HOOK" >&2
  exit 1
fi

tmp_dir="$(mktemp -d /tmp/test-hycu-reset.XXXXXX)"
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
    echo "  output: $haystack" >&2
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

# A guest with the card in sysfs and a hy-smi stub that records its argv and the
# exit status the test wants it to return.
make_fixture() {
  local root="$1" with_dcu="$2" smi_rc="${3:-0}"
  mkdir -p "$root/sys/bus/pci/devices" "$root/sys/kernel/debug" "$root/hyhal/bin"

  mkdir -p "$root/sys/bus/pci/devices/0000:00:01.0"
  echo 0x1af4 >"$root/sys/bus/pci/devices/0000:00:01.0/vendor"
  echo 0x030000 >"$root/sys/bus/pci/devices/0000:00:01.0/class"

  if [[ "$with_dcu" == 1 ]]; then
    local dev="$root/sys/bus/pci/devices/0000:02:00.0"
    mkdir -p "$dev"
    echo 0x1d94 >"$dev/vendor"
    echo 0x0b4000 >"$dev/class"
    # hy-smi reads the recovery entry through debugfs; the hook only checks that
    # the mount is there, so an empty dri/ is the right stub.
    mkdir -p "$root/sys/kernel/debug/dri"
  fi

  cat >"$root/hyhal/bin/hy-smi" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >"$root/smi.argv"
printf 'stub hy-smi ran\n'
exit $smi_rc
EOF
  chmod +x "$root/hyhal/bin/hy-smi"
}

run_hook() {
  local root="$1"; shift
  DEBUGFS_DIR="$root/sys/kernel/debug" \
  PCI_DIR="$root/sys/bus/pci/devices" \
  HYCU_SMI="$root/hyhal/bin/hy-smi" \
  "$@" sh "$HOOK" 2>&1
}

echo "== no DCU in the guest =="

root="$tmp_dir/no-dcu"
make_fixture "$root" 0
out="$(run_hook "$root" env)"
check_contains "a guest without the card says so" \
  "no Hygon co-processor/display PCI device" "$out"
check "hy-smi was not invoked" "absent" \
  "$([[ -e "$root/smi.argv" ]] && echo present || echo absent)"

echo "== no hy-smi in the guest =="

root="$tmp_dir/no-smi"
make_fixture "$root" 1
rm -f "$root/hyhal/bin/hy-smi"
out="$(run_hook "$root" env)"
check_contains "the missing tool is reported" "is absent" "$out"

echo "== the card is reset through hy-smi =="

root="$tmp_dir/basic"
make_fixture "$root" 1
out="$(run_hook "$root" env)"
check "hy-smi is called with --hcureset and the device" \
  "--hcureset -d 0" "$(cat "$root/smi.argv" 2>/dev/null)"
check_contains "the call is logged" "resetting HCU 0" "$out"
check_contains "success is reported" "hy-smi reported a successful reset" "$out"

echo "== the device index can be overridden =="

root="$tmp_dir/device"
make_fixture "$root" 1
out="$(run_hook "$root" env HYCU_SMI_DEVICE=1)"
check "the override reaches the command line" \
  "--hcureset -d 1" "$(cat "$root/smi.argv" 2>/dev/null)"

echo "== a failing hy-smi does not stop the teardown =="

root="$tmp_dir/smi-fails"
make_fixture "$root" 1 1
out="$(run_hook "$root" env)"
check_contains "the failure is reported" "WARNING" "$out"
check_absent "no success is claimed" "successful reset" "$out"

echo "== debugfs is mounted when it is missing =="

root="$tmp_dir/no-debugfs"
make_fixture "$root" 1
rm -rf "$root/sys/kernel/debug"
out="$(run_hook "$root" env)"
# The mount is attempted against the fixture path, which a real mount cannot
# populate; what matters is that the hook notices and does not call hy-smi
# against a filesystem that is not there.
check_contains "the unavailable debugfs is reported" "debugfs" "$out"
check_absent "no reset is claimed" "successful reset" "$out"

echo "== the hook never fails the teardown =="

root="$tmp_dir/exit-code"
make_fixture "$root" 1
set +e
DEBUGFS_DIR="$root/sys/kernel/debug" \
PCI_DIR="$root/sys/bus/pci/devices" \
HYCU_SMI="$root/hyhal/bin/hy-smi" \
sh "$HOOK" >/dev/null 2>&1
rc=$?
set -e
check "exits 0" "0" "$rc"

root="$tmp_dir/exit-code-fail"
make_fixture "$root" 1 1
set +e
DEBUGFS_DIR="$root/sys/kernel/debug" \
PCI_DIR="$root/sys/bus/pci/devices" \
HYCU_SMI="$root/hyhal/bin/hy-smi" \
sh "$HOOK" >/dev/null 2>&1
rc=$?
set -e
check "exits 0 even when hy-smi fails" "0" "$rc"

if (( failures > 0 )); then
  echo "FAILED: $failures check(s)" >&2
  exit 1
fi
echo "all checks passed"