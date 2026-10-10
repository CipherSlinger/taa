#!/usr/bin/env bash
# Second read-only host check: settle what the earlier attempt actually deployed,
# and identify who is running before the deploy step restarts containerd.
#
# Questions:
#   1. Does the real base initrd have a root-level `init`? (First check matched
#      nothing, but its awk pattern could not tell a symlink from a file, so this
#      one prints the raw listings.)
#   2. Was the TAA bundle / kata config / runtime handler ever actually installed?
#      If a bundle initramfs exists, its sha256 against the base decides whether
#      TAA was ever really in a deployed image.
#   3. Which QEMU processes are running, and which initrd does each use? That is
#      both the blast-radius question for `systemctl restart containerd` and the
#      acceptance evidence for "QEMU really used the new initrd".
set -u

B="${BASE_INITRD:-/opt/kata/share/kata-containers/kata-containers-initrd-confidential-csv.img}"
BUNDLE="${BUNDLE:-/opt/kata/share/kata-containers/taa-csv-20260901}"
TAA_CONFIG="${TAA_CONFIG:-/etc/kata-containers/configuration-qemu-csv2-taa.toml}"

echo "== 1. root-level entries of the real base initrd =="
gzip -dc "$B" 2>/dev/null | cpio -t --quiet 2>/dev/null | awk '!/\// {print}' | sort

echo
echo "== 1b. raw cpio -tv lines for init-like paths =="
gzip -dc "$B" 2>/dev/null | cpio -tv --quiet 2>/dev/null |
  grep -E '(^| )(init|sbin/init|usr/sbin/init|rdinit)$| init ->| sbin/init ->' || echo "(none)"

echo
echo "== 1c. any entry literally named init, at any depth =="
gzip -dc "$B" 2>/dev/null | cpio -t --quiet 2>/dev/null | grep -E '(^|/)init$' || echo "(none)"

echo
echo "== 2. was the TAA side ever installed? =="
if [[ -e "$BUNDLE" ]]; then
  echo "bundle dir exists:"
  ls -l "$BUNDLE"
  if [[ -r "$BUNDLE/initramfs.img" ]]; then
    echo -n "bundle initramfs.img sha256: "
    sha256sum "$BUNDLE/initramfs.img" | awk '{print $1}'
    echo -n "base initrd sha256:           "
    sha256sum "$B" | awk '{print $1}'
    if cmp -s "$BUNDLE/initramfs.img" "$B"; then
      echo "=> IDENTICAL to base: no TAA payload was ever deployed in this bundle"
    else
      echo "=> differs from base: this bundle does carry an injected payload"
      echo -n "   entries: "
      gzip -dc "$BUNDLE/initramfs.img" 2>/dev/null | cpio -t --quiet 2>/dev/null | wc -l
      gzip -dc "$BUNDLE/initramfs.img" 2>/dev/null | cpio -t --quiet 2>/dev/null |
        grep -E 'taa|init$' || echo "   (no taa/init entries)"
    fi
  else
    echo "no readable $BUNDLE/initramfs.img"
  fi
else
  echo "bundle dir ABSENT: $BUNDLE  (=> the earlier launch never ran, or it was cleaned up)"
fi

echo
echo "== 2b. TAA kata config / runtime handler / RuntimeClass =="
if [[ -e "$TAA_CONFIG" ]]; then
  echo "TAA kata config EXISTS: $TAA_CONFIG"
  grep -nE '^[[:space:]]*(kernel|initrd|image|firmware|kernel_params)[[:space:]]*=' "$TAA_CONFIG"
else
  echo "TAA kata config ABSENT: $TAA_CONFIG"
fi
echo "-- containerd runtimes mentioning kata --"
grep -nE 'kata[a-z0-9._-]*' /etc/containerd/config.toml 2>/dev/null | head -20 || echo "(no containerd config readable)"
echo "-- RuntimeClass listing --"
kubectl get runtimeclass 2>/dev/null || echo "(kubectl unavailable or not permitted)"

echo
echo "== 3. running QEMU processes and their initrd =="
if pgrep -f 'qemu-system-x86_6[4]' >/dev/null 2>&1; then
  ps -eo pid,etime,args= | grep 'qemu-system-x86_6[4]' | sed -E 's/(-initrd|-kernel|-append) /\n    \1 /g'
else
  echo "(no qemu-system-x86_64 running)"
fi

echo
echo "== 3b. pods on this node =="
kubectl get pods -A -o wide 2>/dev/null | grep -Ei 'NAME|kata|taa' | head -30 ||
  echo "(kubectl unavailable or not permitted)"
