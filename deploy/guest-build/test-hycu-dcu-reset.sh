#!/usr/bin/env bash
# Offline tests for guest-hycu-dcu-reset.sh.
#
# The hook is the only thing that asks the driver to reset the DCU before the
# guest is destroyed, and the failure it exists to prevent (a card the host
# cannot reset, handed to the next guest dirty) is only visible one Pod later.
# There is no way to notice from the hook's own exit code that it did nothing:
# it always exits 0 by design. So every branch that decides *whether* a write
# happens is tested here against a fake sysfs, /dev and debugfs tree.
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

# A guest with the card, its DRM node and the driver's recovery entry. `minor`
# picks the debugfs directory name so the card-name-to-minor mapping is
# exercised rather than assumed: card0 and minor 0 are the usual case, card1 and
# minor 1 are what a guest with a display function in front of the DCU sees.
make_fixture() {
  local root="$1" with_dcu="$2" card="$3" minor="$4" class="${5:-0x0b4000}"
  mkdir -p "$root/sys/bus/pci/devices" "$root/sys/kernel/debug/dri" "$root/dev/dri" "$root/hyhal/bin"

  # A virtio display, always present, never the card.
  mkdir -p "$root/sys/bus/pci/devices/0000:00:01.0"
  echo 0x1af4 >"$root/sys/bus/pci/devices/0000:00:01.0/vendor"
  echo 0x030000 >"$root/sys/bus/pci/devices/0000:00:01.0/class"

  if [[ "$with_dcu" == 1 ]]; then
    local dev="$root/sys/bus/pci/devices/0000:02:00.0"
    mkdir -p "$dev/drm/$card"
    echo 0x1d94 >"$dev/vendor"
    echo "$class" >"$dev/class"
    : >"$root/dev/dri/$card"

    mkdir -p "$root/sys/kernel/debug/dri/$minor"
    : >"$root/sys/kernel/debug/dri/$minor/gpu_recover"
  fi

  # Reading the recovery entry is what asks the driver for a reset; writing does
  # nothing (the entry has no write method). A plain file accepts both, so the
  # difference is invisible without help: this `cat` records that the entry was
  # read and passes everything else through to the real one. A hook that writes
  # leaves the log empty and fails the assertion.
  mkdir -p "$root/fakebin"
  cat >"$root/fakebin/cat" <<EOF
#!/bin/sh
case "\$*" in
  *gpu_recover*) printf '%s\n' "\$*" >>"$root/readlog"; exit 0 ;;
esac
exec $(command -v cat) "\$@"
EOF
  chmod +x "$root/fakebin/cat"
}

# Run the hook against a fixture. The mount binary is stubbed so a test never
# touches the real filesystem: the fixture already provides the debugfs tree, so
# ensure_debugfs takes its "already there" branch. DEBUGFS_MOUNT_POINT is pointed
# at the fixture too -- left at its /sys/kernel/debug default, a case without a
# debugfs tree would try to create the real one.
run_hook() {
  local root="$1"; shift
  PATH="$root/fakebin:$PATH" \
  MOUNT_BIN=/nonexistent/mount \
  DEBUGFS_DIR="$root/sys/kernel/debug" \
  DEBUGFS_MOUNT_POINT="$root/sys/kernel/debug" \
  PCI_DIR="$root/sys/bus/pci/devices" \
  HYCU_SMI="$root/hyhal/bin/hy-smi" \
  "$@" sh "$HOOK" 2>&1
}

echo "== no DCU in the guest =="

root="$tmp_dir/no-dcu"
make_fixture "$root" 0 card0 0
out="$(run_hook "$root" env)"
check_contains "a guest without the card says so" \
  "no Hygon co-processor/display PCI device" "$out"
check_absent "nothing was reset" "resetting the HCU" "$out"

echo "== reset through the debugfs recovery entry =="

root="$tmp_dir/basic"
make_fixture "$root" 1 card0 0
out="$(run_hook "$root" env)"
check_contains "the reset is attempted" \
  "resetting the HCU by reading $root/sys/kernel/debug/dri/0/gpu_recover" "$out"
# The load-bearing assertion. The driver registers this entry with seq_read and
# no write method, so a write is a no-op that also fails: the hook has to read
# it. If someone "fixes" this back to `echo 1 >`, this check goes red while the
# hook still logs a successful reset -- which is exactly the trap this bug was.
check "the hook reads the entry rather than writing to it" "1" \
  "$(wc -l <"$root/readlog" 2>/dev/null | tr -d ' ')"
check_contains "the completed reset is reported" \
  "the driver completed the reset" "$out"

echo "== the minor comes from the card node =="

root="$tmp_dir/minor"
make_fixture "$root" 1 card1 1
out="$(run_hook "$root" env)"
check_contains "card1 maps to debugfs dri/1" \
  "resetting the HCU by reading $root/sys/kernel/debug/dri/1/gpu_recover" "$out"

# A device that is present in sysfs but never bound a driver has no DRM node, so
# there is no index to write to. The hook has to skip it and say so rather than
# write to some other device's recovery entry.
root="$tmp_dir/unbound"
make_fixture "$root" 1 card0 0
rm -rf "$root/sys/bus/pci/devices/0000:02:00.0/drm"
out="$(run_hook "$root" env)"
check_contains "the unbound device is reported" "has no DRM card node" "$out"
check_absent "nothing was written" "reset request accepted" "$out"

echo "== connector entries are not mistaken for the card =="

root="$tmp_dir/connector"
make_fixture "$root" 1 card0 0
mkdir -p "$root/sys/bus/pci/devices/0000:02:00.0/drm/card0-DP-1"
out="$(run_hook "$root" env)"
check_contains "the connector does not change the minor" \
  "resetting the HCU by reading $root/sys/kernel/debug/dri/0/gpu_recover" "$out"

echo "== no recovery entry: fall back to hy-smi =="

root="$tmp_dir/fallback"
make_fixture "$root" 1 card0 0
rm -f "$root/sys/kernel/debug/dri/0/gpu_recover"
# The hook discards hy-smi's own output, so the stub records its argv in a file
# instead. That is the only way to prove the fallback passes the right device
# index -- one card, one index, and a wrong one resets the wrong device.
cat >"$root/hyhal/bin/hy-smi" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >"$root/hy-smi.argv"
exit 0
EOF
chmod +x "$root/hyhal/bin/hy-smi"
out="$(run_hook "$root" env)"
check_contains "the absent entry is reported" "gpu_recover is absent" "$out"
check "hy-smi is called with the index and --hcureset" \
  "--hcureset 0" "$(cat "$root/hy-smi.argv" 2>/dev/null)"
check_contains "the fallback success is reported" \
  "hy-smi reported a successful reset" "$out"

echo "== no recovery entry and no hy-smi =="

root="$tmp_dir/no-tools"
make_fixture "$root" 1 card0 0
rm -f "$root/sys/kernel/debug/dri/0/gpu_recover"
out="$(run_hook "$root" env)"
check_contains "the missing tool is reported, not silent" \
  "no recovery entry and" "$out"

echo "== debugfs missing: mount is attempted, failure is loud =="

root="$tmp_dir/no-debugfs"
make_fixture "$root" 1 card0 0
rm -rf "$root/sys/kernel/debug"
out="$(run_hook "$root" env)"
check_contains "the unavailable mount point is reported" \
  "debugfs" "$out"
check_absent "no reset is claimed" "reset request accepted" "$out"

echo "== a failed read does not stop the hook =="

root="$tmp_dir/read-fails"
make_fixture "$root" 1 card0 0
# A fake `cat` that fails on the entry stands in for a driver that refuses the
# reset (already in reset, recovery disabled). The hook has to log it and keep
# going rather than abort the teardown.
cat >"$root/fakebin/cat" <<'EOF'
#!/bin/sh
case "$*" in
  *gpu_recover*) echo "simulated driver refusal" >&2; exit 1 ;;
esac
exec /bin/cat "$@"
EOF
chmod +x "$root/fakebin/cat"
out="$(run_hook "$root" env)"
check_contains "the failed read is reported" "reading" "$out"
check_contains "the failure is a warning" "WARNING" "$out"
check_absent "no completed reset is claimed" "the driver completed the reset" "$out"

echo "== the hook never fails the teardown =="

root="$tmp_dir/exit-code"
make_fixture "$root" 1 card0 0
set +e
MOUNT_BIN=/nonexistent/mount \
DEBUGFS_DIR="$root/sys/kernel/debug" \
PCI_DIR="$root/sys/bus/pci/devices" \
HYCU_SMI="$root/hyhal/bin/hy-smi" \
sh "$HOOK" >/dev/null 2>&1
rc=$?
set -e
check "exits 0" "0" "$rc"

if (( failures > 0 )); then
  echo "FAILED: $failures check(s)" >&2
  exit 1
fi
echo "all checks passed"