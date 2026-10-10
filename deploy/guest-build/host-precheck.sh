#!/usr/bin/env bash
# Read-only host precondition check for the CSV2 initrd work (spec section 0).
#
# It answers three questions that decide how the rest of the work is interpreted,
# and it changes nothing on the host:
#
#   1. Does the real base initrd have a root-level `init` entry, and is it the
#      `-> /sbin/init` symlink? That explains why the earlier `init=` injection
#      never started TAA (the kernel tries rdinit=/init first and never looks at
#      init= once it succeeds).
#   2. What are the real base's size, sha256 and cpio entry count? Those are the
#      expected values for `build-initrd.sh fetch-base`.
#   3. What is `kernel_params` in the shipped kata config? That is where the
#      rdinit= patch has to land.
#
# Usage (one ssh, one shot -- the account has pam_faillock, so never retry):
#
#   ssh root@172.16.10.178 'bash -s' < host-precheck.sh
#
# Everything is quoted for a non-interactive `bash -s` over stdin; nothing here
# writes to the host.
set -u

B="${BASE_INITRD:-/opt/kata/share/kata-containers/kata-containers-initrd-confidential-csv.img}"
C="${KATA_CONFIG:-/opt/kata/share/defaults/kata-containers/configuration-qemu-csv2.toml}"
M="${MEASURE_TOOL:-/opt/hygon/csv/confidential-containers/scripts/csv-measure.py}"

echo "== 1. base initrd =="
if [[ -r "$B" ]]; then
  ls -l "$B"
  sha256sum "$B"
  if gzip -t "$B" 2>/dev/null; then
    echo "gzip: OK"
  else
    echo "gzip: BROKEN (truncated stream -- this is what the committed copy looked like)"
  fi
  echo -n "entries: "
  gzip -dc "$B" 2>/dev/null | cpio -t --quiet 2>/dev/null | wc -l
else
  echo "MISSING: $B"
fi

echo
echo "== 2. root-level init and rdinit= target =="
if [[ -r "$B" ]]; then
  # Long listing of the root-level entries that the kernel's init selection
  # looks at: /init (the rdinit= default) and /sbin/init.
  gzip -dc "$B" 2>/dev/null | cpio -tv --quiet 2>/dev/null |
    awk '$NF == "init" || $NF == "sbin/init" || $NF == "usr/sbin/init"' ||
    echo "(no root-level init entry found)"
fi

echo
echo "== 3. kata config for the CSV2 runtime =="
if [[ -r "$C" ]]; then
  grep -nE '^[[:space:]]*(kernel|initrd|image|firmware|kernel_params)[[:space:]]*=' "$C" ||
    echo "(no kernel/initrd/image/firmware/kernel_params lines found)"
else
  echo "MISSING: $C"
fi

echo
echo "== 4. host context =="
echo -n "running kata-qemu-csv2 pods: "
# pgrep -f with a bracketed pattern so this diagnostic does not match itself.
ps -eo args= 2>/dev/null | grep -c 'qemu-system-x86_6[4]' || true
ls -l "$M" 2>/dev/null || echo "measure tool MISSING: $M"
echo -n "kernel: "; uname -r
echo -n "csv-guest in /proc/misc: "
awk '$2 == "csv-guest" {print $1; found=1} END {if (!found) print "(absent)"}' /proc/misc 2>/dev/null ||
  echo "(/proc/misc unreadable)"
